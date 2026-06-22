# Plan: WG MSS clamp + WG MTU SSOT + tunnel DSCP/ECN copy (#2299, #2300, #2303)

Three related WireGuard/encap correctness fixes that share the encap
sites and the tunnel-MTU model.

## #2299 — wire `wg_tcp_mss()` into the WG SYN MSS-clamp path

### Problem
`build_forwarded_frame_into_from_frame` (frame/build/mod.rs) computes
the tunnel MSS clamp via `native_gre_tcp_mss(...)`, which subtracts only
outer-IP(20/40) + GRE(4/8). For a `mode == "wireguard"` endpoint the WG
overhead (outer IP + UDP(8) + WG data header(16) + Poly1305 tag(16) +
§5.4.6 padding(≤15)) is ~36-60 bytes larger, so the advertised inner MSS
is too high. The peer sends full-MSS data segments that exceed the WG
encap MTU guard and are silently dropped at `encap_mtu_drops`.
`wg_tcp_mss()` (wg/mss.rs) computes the correct value but has ZERO
production callers.

### Fix
Add a dispatcher `tunnel_tcp_mss(forwarding, decision, addr_family)` in
forwarding/mod.rs that looks up the endpoint mode:
- `mode == "wireguard"` → `wg::mss::wg_tcp_mss(outer_family,
  inner_family, outer_mtu)` where `outer_family` = endpoint.outer_family
  (or peer-endpoint family), `inner_family` = the inner packet's family
  (addr_family), `outer_mtu` = the egress interface MTU (same resolution
  as `native_gre_inner_mtu`'s transport-mtu chain).
- otherwise → `native_gre_tcp_mss(...)` (unchanged).

The build orchestrator calls `tunnel_tcp_mss` instead of
`native_gre_tcp_mss`. No new branch on the plain-forward fast path —
`tunnel_endpoint_id == 0` short-circuits to 0 exactly as today.

The `forwarding.tcp_mss_gre_out` operator override applies only to GRE
(it is the GRE-specific knob); for WG we always derive from the WG
overhead so the clamp matches the encap guard. (Operator MSS overrides
for WG are out of scope — there is no WG-specific MSS config leaf today.)

### Test
- WG endpoint: SYN MSS clamped to the WG value (e.g. 1385 for v4/v4 @
  1500), NOT the GRE value (1460).
- Fail-on-revert: GRE endpoint still gets the GRE value (1460), proving
  the dispatcher did not break GRE.

## #2300 — single MTU model for WG (drop the WG_OUTER_MTU constant)

### Problem
Three divergent MTU sources:
1. Transit WG encap (frame/wg.rs) reads the real egress interface MTU.
2. The TUN/control path (wg_control.rs) hardcodes
   `const WG_OUTER_MTU: usize = 1500`.
3. The Go wgN TUN MTU defaults to literal 1500
   (tunnel.go `reconcileAnchorMTULocked`, `adopting` branch).

### Fix
- Rust control thread: thread the resolved outer MTU from the spawn
  site (`spawn_one_wg_control_thread` has `self.forwarding`, which holds
  the egress MTU map) through `wg_control_loop` → `run_wg_control_loop`
  → `encap_and_send`. Replace the `WG_OUTER_MTU` constant usage with the
  per-thread value. Resolve the MTU the same way the transit path does:
  egress map keyed by the endpoint's transport/logical ifindex,
  `unwrap_or(1500)` fallback only when unknown. The constant becomes the
  documented fallback default, not the hardcode.
- Go side: in `reconcileAnchorMTULocked`, the `adopting` branch should
  derive the wgN MTU from the underlay/route MTU toward the peer
  endpoint minus the WG overhead, not a literal 1500. But the Go side
  does NOT resolve the underlay egress at this layer (the tunnel manager
  has only linkOps). Scope decision: keep the 1500 normalization as the
  *adopt-repair* default (its documented purpose is repairing the
  wireguard→gre same-name flip leftover), but make the WG-overhead model
  explicit and shared. The real per-underlay MTU derivation belongs to
  the snapshot/egress path; the Rust transit + control thread now both
  read the real egress MTU, which is the authoritative guard. Document
  that `tc.MTU > 0` (operator-set) is the supported sub-1500 path and the
  Rust guard is the backstop. (Honest scope: the Go default stays 1500
  but the Rust guards now both use the REAL egress MTU, closing the
  divergence that caused topology-dependent bugs.)

### Test
- Rust: `encap_and_send` MTU guard uses the threaded outer MTU (1450 /
  1492 / 1500 / 9000), v4 + v6, NOT a constant 1500. Fail-on-revert: a
  1409-byte inner at a 1450 outer MTU is dropped (would pass under 1500).
- Rust: transit + control thread compute the SAME encapped size for the
  same inner/outer (SSOT helper).

## #2303 — copy inner DSCP + ECN onto the outer header (RFC 6040 / 2983)

### Problem
GRE encap (gre.rs) and WG encap (frame/wg.rs) both hardcode the outer
TOS / IPv6 Traffic-Class to 0, stripping inner DSCP (QoS) and ECN
(congestion signalling, RFC 6040).

### Fix
Add `inner_tos_byte(inner_packet, addr_family) -> u8` that reads the
full 8-bit TOS/TC byte (DSCP 6 bits + ECN 2 bits) from the inner IP
packet:
- IPv4: byte 1.
- IPv6: `(b[0] << 4) | (b[1] >> 4)` (TC spans the low nibble of byte 0
  and the high nibble of byte 1).
Pass that byte as the `tos` / `traffic_class` arg at both encap sites
(GRE v4+v6, WG v4+v6). This is the uniform model for DSCP and the
RFC-6040 normal-mode ingress copy for ECN (inner ECN → outer ECN). The
existing `wg/dscp.rs::tos_from_dscp` (clears ECN) is left in place but
is not the encap reader — the encap copies the full byte so ECN
propagates.

### Test
- GRE + WG, v4 + v6: inner TOS = EF DSCP (46<<2=0xB8) + ECT(0) → outer
  TOS == inner TOS. Fail-on-revert: a non-zero inner TOS produces a
  non-zero outer TOS (the pre-fix hardcoded 0 would fail).

## Files touched
- userspace-dp/src/afxdp/forwarding/mod.rs — `tunnel_tcp_mss` dispatcher.
- userspace-dp/src/afxdp/frame/build/mod.rs — call dispatcher.
- userspace-dp/src/afxdp/wg/mss.rs — (no change; already correct).
- userspace-dp/src/afxdp/gre.rs — inner TOS copy + helper.
- userspace-dp/src/afxdp/frame/wg.rs — inner TOS copy.
- userspace-dp/src/afxdp/coordinator/wg_control.rs — thread outer MTU.
- userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs — resolve +
  pass outer MTU at spawn.
- pkg/routing/tunnel.go — document/clarify the adopt-default MTU model.
- docs: tunnel/wireguard module docs, _Log.md.

## Validation
- cargo build --release clean; new cargo tests pass.
- go build ./... + go test ./pkg/routing/... green.
- No cluster smoke (parent batches).
