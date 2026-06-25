# WireGuard interop — status and validation

Tracking doc for the #1703 WireGuard interop umbrella (interop with kernel
WireGuard, UniFi Network 10.4+, EdgeOS/EdgeRouter, UDM/UDM-Pro — all of which
run reference-compliant kernel WireGuard).

WireGuard is a fixed protocol: a byte-compliant implementation interoperates
with any other compliant implementation regardless of vendor. The work is
therefore staged by capability, not by vendor.

## Status by stage

| Stage | Scope | State |
|-------|-------|-------|
| S1 (#1709) | Wire-protocol compliance: TAI64N + handshake framing (msg type 1/2, MAC1) on build + parse, both roles | **DONE (this PR)** — validated by spec known-answer vectors + an xpf↔xpf framed-handshake regression. **NOT yet validated against an independent peer** (see "honesty note" below). |
| S2 | Dataplane activation (AF_XDP hot-path encap/decap) **+ the live kernel-WireGuard-on-a-VM interop test** | pending |
| S4 | Non-zero pre-shared key (PSK) plumbing | **plumbing DONE (#1434 B2)** — per-peer `preshared-key` on `WgPeerConfig` (Go config + wire + engine `WgPeerConfig.preshared_key` + `Peer.preshared_key`), wired into both handshake builders: the initiator sets the peer's PSK at `build_initiator_handshake` time, the responder reads msg1, identifies the peer via `get_remote_static`, then `set_psk(2, …)` before `write_message(msg2)` (snow 0.10.0 mid-handshake API). Secret hygiene: `Secret`/`Zeroizing`/`skip_serializing` on every surface (config `String()`, wire DTO, runtime peer, status). Unit-tested (`per_peer_psk_handshake_roundtrip`); the LIVE kernel-WG PSK interop validation stays #1703. |
| #1434 | Multi-PEER per WG interface (N peers on one listen port) | **DONE (#1434 B1a+B1b)** — Go config `TunnelConfig.WgPeers []WgPeerConfig` (named-instance `peer <pubkey>` schema + dual-AST compiler + commit gate), wire slice `wg_peers`, Rust engine fed N peers (RX/decap already multi-peer), egress generalized: encap LPM-selects the peer by inner-dst AllowedIPs (`frame/wg.rs` + `engine.peer_for_dest`), the WG control thread keeps per-peer effective-endpoint + per-peer handshake attempt + per-peer keepalive/rekey timers (`timer_pass_for_peer`), and per-peer status rows. The LIVE multi-peer handshake / Ubiquiti interop validation is #1703. KNOWN LIMITATION: the worker-driven NoSession/rekey REQUEST edges are still engine-wide (single edge), not per-peer — the per-peer T6/T7/T8 timers ARE per-peer; per-peer request edges ride #1703. |
| S5 | Persistent-keepalive + REKEY/REJECT-AFTER timers + endpoint roaming + empty-record (keepalive/key-confirm) handling + TAI64N disk persistence | **timers + keepalives DONE (#1888/#1889)** — full whitepaper §6.1 timer machine (REKEY_AFTER_TIME 120s initiator-only, 165s receive horizon, REJECT_AFTER_TIME 180s per-use + expiry teardown, 5s/90s retry discipline, 10s passive + configured persistent keepalives, post-msg2 key-confirmation keepalive) on a blocking-poll(2) control loop; design of record `docs/research/1888-wg-timers/plan.md`. Authenticated-datagram endpoint LEARNING shipped in S2a/#1888 (keepalives now count); engine-level roam API + TAI64N disk persistence remain pending |
| S6 | Junos config surface (grammar + compiler + snapshot population, base64↔hex keys) | pending |
| S7 | Type-3 CookieReply + MAC2 generation/verification + IPv6 outer encap + DSCP/ECN | **DSCP/ECN encap DONE (#2303)** — inner DSCP+ECN copied onto the outer header (uniform DSCP + RFC 6040 ECN ingress copy). RFC 6040 §4.2 decap-side ECN *combine* shipped for GRE (#2315) AND WG (#2317) — WG captures the outer ECN via `recvmsg` + `IP_RECVTOS`/`IPV6_RECVTCLASS` cmsg and folds it into the decrypted inner via the shared `apply_decap_ecn_combine` (live ECN-propagation verification lab-deferred to #1703-class interop). CookieReply/MAC2 still pending |
| S8 | HA RG WG-session migration | pending |

## Tunnel MTU + MSS + DSCP/ECN model (#2299 / #2300 / #2303 / #2329)

These correctness fixes share the encap sites and the tunnel-MTU
model. They apply to BOTH WireGuard and (for DSCP/ECN) GRE.

### MSS clamp (#2299)
A WG-bound TCP SYN's MSS is clamped via the WireGuard overhead, not the
GRE formula. `forwarding::tunnel_tcp_mss` dispatches by endpoint mode:
`wireguard` → `wg::mss::wg_tcp_mss(outer_family, inner_family,
outer_mtu)` (accounts for outer IP + UDP(8) + WG data header(16) +
Poly1305 tag(16) + §5.4.6 padding(≤15)); everything else keeps
`native_gre_tcp_mss` bit-for-bit. Before #2299 a WG SYN was clamped with
the GRE value (~36–60 bytes too high), so the peer sent full-MSS data
segments that the WG encap MTU guard then silently dropped at
`encap_mtu_drops` — the classic "handshake + ping pass, bulk TCP stalls
at zero bytes" failure.

### TCP-segmentation egress is mode-aware on BOTH axes (#2329)
The fallback TCP-segmentation egress builder
(`frame/tcp_segmentation.rs::segment_forwarded_tcp_frames_from_frame`)
re-segments an oversized forwarded TCP flow when the sender ignores the
advertised MSS, the session predates the clamp, or a middlebox injects
larger segments. Before #2329 it was tunnel-mode-BLIND in two places —
both effectively hardcoded to GRE:

1. **Inner-L3 MTU math.** It sized every tunnel's segments with the GRE
   inner-MTU formula (`native_gre_inner_mtu`). For a WireGuard endpoint
   that budget is ~36–60 bytes too large, so the oversized WG-bound
   segments were built and then dropped at the WG encap MTU guard
   (`encap_mtu_drops`) — the same blackhole #2299 closed for the SYN
   path, re-opened for the segmentation fallback.
2. **Encap dispatch.** It unconditionally called
   `encapsulate_native_gre_frame` for any `tunnel_endpoint_id != 0`, so a
   WireGuard tunnel's segmented TCP went out **GRE-encapsulated** (wrong
   protocol on the wire; for an inet WG endpoint it even built a
   degenerate `0.0.0.0→0.0.0.0` outer) — a mis-encapsulation, worse than
   the MTU drop.

Both axes now dispatch on the typed `TunnelKind` (the #2327 classifier,
`forwarding_build/tunnels.rs::tunnel_mode_kind`) and reuse the existing
SSOT helpers — no parallel overhead math:

- MTU: `Gre` → `native_gre_inner_mtu`; `WireGuard` →
  `wg::mss::wg_inner_mtu(outer_family, outer_mtu)` (the pad-aware inverse
  of `wg_encapped_size`, the same helper #2330's post-transform PMTUD
  uses); `Unknown`/missing → 0 budget → drop. A tunnel budget is NOT
  floored to 1280 (that floor stays on the plain-forward path only): a
  small-outer-MTU tunnel has a genuinely smaller inner budget, and
  flooring it would re-introduce the oversized-then-dropped blackhole.
- Encap: `Gre` → `encapsulate_native_gre_frame`; `WireGuard` →
  `frame/wg.rs::wg_encap_frame` (the same builder the normal egress path
  uses — it pulls the live noise session from `forwarding.wg_engines`
  itself, so the segmentation site needs no extra keystate); `Unknown`/
  missing → drop (fail closed, mirroring the #2327 build-egress
  dispatch in `frame/mod.rs`).

After #2329 the segmentation path, the normal egress path (#2327), the
SYN MSS clamp (#2299, `tunnel_tcp_mss`), the encap MTU guards
(#2331/#1865), and the post-transform PMTUD (#2330) are ALL mode-aware
and share `native_gre_inner_mtu` / `wg::mss::wg_inner_mtu` /
`TunnelKind`.

### Transit-egress encap is no-alloc beyond the owned return (#2792)
`frame/wg.rs::wg_encap_frame` previously allocated TWO heap `Vec`s per
packet on the encrypt/transmit path: an intermediate `wg_record` scratch
that `try_encap` wrote into, then a copy of that scratch into the output
frame `Vec`. Both the intermediate buffer and the copy are gone. The
function now sizes the output frame ONCE to the pad-aware maximum WG
record length (the same `WG_DATA_HEADER_LEN + pad_to_16(inner) +
POLY1305_TAG_LEN` arithmetic the #2680 MTU guard already validated) and
hands `try_encap` a `&mut [u8]` over the output frame's UDP-payload slot
directly — the WG transport record (data header + ciphertext + Poly1305
tag) is encrypted into its final wire position. The frame is then
truncated to the actual encapped length reported by `EncapOutcome::len`.
This is sound because `try_encap` stages the padded plaintext on the
stack (MaybeUninit), so snow's non-overlapping plaintext/ciphertext
requirement is satisfied without a separate output buffer. The single
remaining allocation is the function's OWNED `Vec<u8>` return value,
which is structurally identical to the GRE sibling
(`encapsulate_native_gre_frame`) and is required because the
TCP-segmentation caller accumulates one owned frame per segment in a
`Vec<Vec<u8>>`. The wire bytes are unchanged: same header bytes, same
ciphertext+tag, same outer framing — locked by the round-trip
byte-identity test `wg_encap_in_place_matches_separate_buffer`, which
decrypts the in-place-written record under the paired peer's transport
and asserts the recovered plaintext equals the original inner IP packet
(fails on a wrong encrypt offset / mis-sized buffer / bad truncation).

### Outer MTU SSOT (#2300 / #2680 / #2517)
There is now ONE outer-MTU model. The transit-egress encap
(`frame/wg.rs`) and the control-thread egress (`coordinator/wg_control.rs`)
both gate the OUTER encapped datagram against the REAL underlay-egress
interface MTU, not a hardcoded 1500. The control thread is handed the
resolved underlay MTU at spawn (`Coordinator::resolve_wg_outer_mtu`
route-looks-up the peer endpoint in the endpoint's transport table).
`WG_DEFAULT_OUTER_MTU` (1500) is now ONLY the last-resort fallback for an
unconfigured/unroutable endpoint.

**#2517 (GRE inner-MTU shares the same fallback).** The native-GRE
inner-MTU resolver `native_gre_inner_mtu` now resolves its outer/transport
MTU through the SAME `tunnel_outer_mtu` SSOT helper the WG MSS clamp uses,
instead of an independent egress-lookup chain. The two paths had drifted on
the miss case: `tunnel_outer_mtu` falls back to 1500 (`.filter(|m| *m > 0)
.unwrap_or(1500)`), but `native_gre_inner_mtu` used `unwrap_or_default()` →
0, which made `native_gre_tcp_mss` return 0 and silently DISABLE a
configured GRE outbound TCP MSS clamp during a transient egress-map miss
(re-reconciliation / interface bringup) — the clamp came back only on the
next reconcile. After #2517 a GRE egress-map miss falls back to the 1500
underlay MTU and `native_gre_tcp_mss` keeps computing a real clamp, exactly
like the WG path. Both tunnel MSS-clamp paths now read one resolver and
cannot drift again.

**#2680 (transit-egress site).** The `frame/wg.rs` guard previously read
the MTU of `decision.resolution.egress_ifindex`, which for a tunnel-resolved
flow is the tunnel LOGICAL ifindex (the WG interface, MTU ~1420), NOT the
physical underlay. Comparing the full OUTER encapped size against the
LOGICAL MTU silently dropped inner packets whose outer datagram fit the
1500-byte underlay (`encap_mtu_drops`) — broken PMTUD / tunnel transit. The
guard now resolves the PHYSICAL egress MTU via `outer_physical_egress_mtu`,
which route-looks-up the SELECTED peer endpoint (`engine.peer_for_dest`, the
real outer hop — the endpoint-level `destination` is zeroed to `0.0.0.0` for
WG, so `resolve_tunnel_outer` cannot be reused here) in the endpoint's
transport table and gates against that underlay interface's MTU.
Distinctions kept separate: OUTER encapped size vs PHYSICAL underlay MTU is
THIS guard; the INNER packet's own logical/PMTUD budget is the inner-MTU
clamp / post-transform PMTUD (#2299/#2330/#2457). Conservative fallback: an
unresolvable outer route falls back to the resolution's `egress_ifindex` MTU
(the pre-#2680 behaviour) then 1500 — never tighter than before.
On the Go side, `wgTunMTUForEndpoint` honors an operator-set `mtu` on the
tunnel interface (the supported sub-1500 / jumbo override — PPPoE 1492,
cloud overlays ~1450); with no operator MTU it derives the wgN inner MTU
from `wgDefaultOuterMTU` minus the family overhead. The pre-#2300 code
ignored `tc.MTU` entirely and always derived from 1500, so a
lowered-underlay deployment could not set a smaller wgN MTU.

**#2684 (PTB advertisement — the #2680 sibling on the same SSOT).** The
post-transform PMTUD path (`post_transform_inner_mtu`, the TX dispatcher's
inner-MTU derivation that turns an oversized DF-IPv4 / IPv6 inner into a
Frag-Needed / Packet-Too-Big) computed the WG arm's outer MTU via
`tunnel_outer_mtu` (the #2300 transport-MTU SSOT). For a WG transit flow
`endpoint.destination` is zeroed (the peer carries the real outer hop), so
`tunnel_outer_mtu`'s `tx_ifindex` resolution NoRoutes and the chain falls
through to the tunnel LOGICAL `egress_ifindex` MTU (~1420 = underlay −
encap). Feeding that already-reduced MTU to `wg_inner_mtu` subtracts the WG
outer overhead a SECOND time, so the PTB advertised
`wg_inner_mtu(1420)` ≈ 1345 (v4) / 1325 (v6) — ~80-100B SMALLER than the
underlay actually permits. The encap drop guard (#2680) admits inner packets
up to `wg_inner_mtu(physical=1500)` ≈ 1425 (v4) / 1405 (v6), so a DF-IPv4 /
IPv6 inner in the band `(wg_inner_mtu(logical), wg_inner_mtu(physical)]` got
a PTB clamping the sender ~100B too low (over-conservative — safe, no drops,
but unnecessary fragmentation pressure / throughput loss).

The WG arm now derives the outer MTU from the PHYSICAL underlay via
`frame::wg_endpoint_physical_outer_mtu`, a thin wrapper over the same #2680
`outer_physical_egress_mtu` SSOT the encap guard uses. The PTB path runs
before the per-packet peer LPM (it has no inner frame), but the WG underlay
is per-tunnel-endpoint, not per-inner-flow (#2734) — so it route-resolves
the physical egress via the FIRST peer that carries an endpoint address.
Corrected formula: advertised inner MTU = `wg_inner_mtu(outer_family,
physical_underlay_mtu)` = `physical_mtu − WG_OVERHEAD_{V4,V6} −
WG_MAX_PADDING` — EXACTLY the inverse of `wg_encapped_size` the encap guard
admits against, so the PTB and the guard now agree. Conservative fallback
(no peer endpoint to route to / unresolvable outer) reverts to the logical
`egress_ifindex` MTU — the pre-#2684 value, never worse. GRE is unaffected:
its `endpoint.destination` is the real outer hop, so `tunnel_outer_mtu`
already resolves to the physical underlay for `native_gre_inner_mtu`.

**#2701 (transit-egress OUTER SOURCE).** The #2680 MTU fix resolved the
physical underlay egress for the MTU guard but left the OUTER IP SOURCE
still read from `decision.resolution.egress_ifindex` (the LOGICAL tunnel
ifindex). When the logical WG interface carries no WAN primary the
`primary_v4?`/`primary_v6?` lookup returned `None` → dropped transit; when
it carried a tunnel address the outer UDP was sourced from that tunnel
address (breaking source-dependent policy/NAT/upstream anti-spoofing). The
MTU helper is now factored into `outer_physical_egress_ifindex` (returns the
physical underlay ifindex via the same route-to-selected-peer lookup), used
for BOTH the MTU guard (`outer_physical_egress_mtu` wraps it) AND the outer
source primary. So the outer UDP is always sourced from the physical WAN
primary, not the tunnel-logical address. Same conservative fallback: an
unresolvable outer falls back to `egress_ifindex` (no worse than pre-#2701).

**#2703 (outer TTL default).** A tunnel TTL of `0` is the "use the default
64" sentinel in the Go config (`schema_interfaces.go`, `types_routing.go`),
and the netlink GRE path applies it (`pkg/routing/tunnel.go: if ttl == 0 {
ttl = 64 }`). The AF_XDP transit path passed `tunnel.TTL` raw into the
snapshot, and the Rust frame builders (`frame/wg.rs`, `gre.rs`) write the
snapshot TTL straight into the outer IP header — so a default-config tunnel
emitted outer TTL/hop-limit 0 → deterministic first-hop blackhole. The 0→64
default is now applied Go-side in `pkg/dataplane/userspace/tunnels.go` (the
SSOT, mirroring the netlink precedent) before the value reaches the
snapshot; an explicit non-zero TTL is preserved. As a fail-closed backstop,
`TunnelTtl::try_from_snapshot` now maps a NEGATIVE snapshot TTL (corrupt /
mixed-version) to the documented default 64 rather than 0 (an out-of-range
value > 255 still fails the snapshot CLOSED via `TunnelTtlOutOfRange`).

Residual / follow-up: the per-peer LEARNED-endpoint roam case still uses
the spawn-time outer MTU on the control thread (the transit-egress path
already reads the real per-packet egress MTU); the Go default cannot see
the route at the tunnel-manager layer, so a non-1500 underlay relies on
either the operator `mtu` statement or the Rust egress guard as the
authoritative backstop.

### DSCP/ECN propagation (#2303 encap, #2315 GRE decap)

**Encap (#2303).** GRE and WG encap copy the inner packet's full TOS /
IPv6 Traffic-Class byte (DSCP 6 bits + ECN 2 bits) onto the outer header
via `gre::inner_tos_byte`, instead of hardcoding 0. This is the uniform
DSCP model (RFC 2983) — per-hop QoS classification survives the tunnel —
plus the RFC 6040 normal-mode ECN ingress COPY (inner ECN → outer ECN).
`wg::dscp::tos_from_dscp` (which clears ECN) is retained for the
DSCP-only case but is NOT the encap reader.

**Decap (#2315 GRE / #2317 WG).** The RFC 6040 §4.2 decap-side ECN
*combine* (outer ECN → inner ECN) — the half that actually reflects a CE
mark applied by a congested router on the outer path back to the inner
endpoints — is implemented for **both tunnel paths** via the shared
`gre::apply_decap_ecn_combine`: an outer CE upgrades an ECN-capable inner
to CE; the illegal outer-CE / inner-Not-ECT combination is dropped; the
inner DSCP is authoritative at decap and is never copied from the outer.
DSCP is not copied back at decap.

- **GRE (#2315)** reads the outer ECN from the still-present outer IP
  header in the frame (`outer_ecn_bits`, wired into
  `try_native_gre_decap_from_frame`). Illegal-combination drops surface as
  `xpf_userspace_gre_decap_ecn_illegal_drops_total`.

- **WireGuard (#2317)** captures the outer ECN out-of-band. The WG control
  thread reads transport records from a kernel `UdpSocket`, which strips
  the outer IP header (and its ECN) before the datagram reaches
  userspace, so the recv loop uses `recvmsg` with the `IP_RECVTOS` (v4 /
  v4-mapped) and `IPV6_RECVTCLASS` (v6) socket options enabled at bind;
  the outer DS byte arrives as ancillary data (`IP_TOS` / `IPV6_TCLASS`
  cmsg), and its low 2 bits are folded into the freshly-decrypted inner IP
  packet — before `tun.write_all` — through the same combine. Illegal-
  combination drops surface as
  `xpf_userspace_wg_decap_ecn_illegal_drops_total` (a sibling counter, so
  the two families are independently observable). The combine is skipped
  best-effort when no TOS cmsg arrives (a kernel that did not honor the
  sockopt) — never fatal to the tunnel. Live end-to-end verification (a
  real WG peer CE-marking the outer → CE on the inner) is lab-bound,
  deferred to the #1703-class interop validation; the code path and unit
  tests (cmsg parse for v4/v6, the §4.2 combine reuse, CE upgrade + IPv4
  checksum, illegal-combo drop+count) are in tree. The `recvmsg` control
  buffer is the 8-byte-aligned `CmsgBuf([u8; 256])` newtype (#2334) so the
  `cmsghdr` header-field reads the `CMSG_*` macros perform are naturally
  aligned (a bare `[u8; N]` is align-1; reading `cmsg_len`/`cmsg_level`/
  `cmsg_type` through an under-aligned `*const cmsghdr` is UB and a SIGBUS
  risk on strict-alignment targets such as ARMv8). A compile-time
  `align_of::<CmsgBuf>() >= align_of::<cmsghdr>()` assertion is the
  fail-on-revert sentinel.

## What S1 delivers

S1 makes xpf's WireGuard **handshake bytes** standards-compliant:

- **TAI64N timestamp** (`userspace-dp/src/afxdp/wg/tai64n.rs`): a 12-byte
  big-endian `0x400000000000000a + unix_secs` (the `+10` is the 1970-epoch
  TAI−UTC leap offset, matching kernel WireGuard and wireguard-go) followed by
  whitened nanoseconds (`& 0xFF000000`). The clock is strictly monotonic
  in-process so xpf never DoSes its own re-handshakes with a backwards
  timestamp. Carried as the encrypted Noise payload of message 1.
- **Handshake framing** (`userspace-dp/src/afxdp/wg/handshake.rs`): the WG
  type-1 MessageInitiation (148 bytes) and type-2 MessageResponse (92 bytes)
  on-wire framing — type byte, reserved, sender/receiver index, and
  `MAC1 = keyed-BLAKE2s-128(BLAKE2s-256("mac1----" || recipient_static_pub),
  msg[0..offsetof(mac1)])`. MAC2 is emitted as zeros (cookie handling is S7)
  and skip-verified on parse.
- **Engine orchestration**
  (`userspace-dp/src/afxdp/wg/handshake_session.rs`): `create_initiation`,
  `consume_response`, and `consume_initiation_create_response` compose snow +
  the framing + the TAI64N clock into the full handshake in both roles, with a
  two-phase index reservation (reserve before send, at most one pending per
  peer) so a completed handshake's session is never blackholed by an index
  collision. Handshake construction runs on the control thread only — never
  the AF_XDP poll worker.

## Honesty note (S1/S2 boundary)

**S1 is NOT yet proven to interoperate with an independent WireGuard peer.**
Its in-tree gate is spec known-answer vectors (the WG construction hashes, the
MAC1 keyed-BLAKE2s-128 construction, the TAI64N encoding, and full byte-exact
msg1/msg2 wire images) plus an xpf-against-xpf framed-handshake round-trip.
Those pin every framing/MAC1/TAI64N byte to the canonical construction, but a
symmetric build/parse bug shared by both xpf roles would pass them. The
independent-peer proof — a live handshake against the **Linux kernel
WireGuard** module — lands in S2 alongside the dataplane/UDP wiring it shares.
Do not claim "xpf interoperates with WireGuard / UniFi" on the basis of S1
alone.

## S2 live kernel-WireGuard interop recipe (reference; built in S2)

The independent reference is the Linux kernel WireGuard module running on a
real incus **virtual machine** (never a container — containers share the host
kernel and cannot use the WG module or create `type wireguard` links). This is
byte-identical to what UniFi / EdgeOS / UDM run.

```sh
# On a Debian-13 VM peer (root; install wireguard-tools if absent):
ip link add wgref type wireguard
wg set wgref private-key <ref.priv> listen-port <P> \
   peer <xpf.pub> allowed-ips 0.0.0.0/0 endpoint <xpf_vm_ip>:<Q>
ip addr add <wg-overlay>/24 dev wgref
ip link set wgref up

# Direction A: xpf create_initiation -> UDP <peer_vm_ip>:<P>; kernel wg
#   verifies MAC1 + decrypts the TAI64N + replies type-2; xpf
#   consume_response derives the session. Assert via `wg show wgref`
#   (peer-side cross-check) and `show security wireguard` on xpf
#   (#1865 — local handshake counters are the primary oracle).
# Direction B: kernel wg initiates (persistent-keepalive 1); xpf
#   consume_initiation_create_response replies; assert `wg show` completes.
```

The peer VM attaches to the same SR-IOV LAN segment as the cluster host
(`mlx1` / VLAN 3667 on the loss userspace cluster); S2 must verify a free VF
exists before launching the peer, or reuse an existing real VM on that segment.

## Operator CLI surface (key handling)

These operational commands support bringing a tunnel up against a peer.
They are read-only / stateless (`request` prints, it does not mutate
config), so both work on a standalone box and through the remote `cli`.

- **`show security wireguard public-key`** (#1434 Increment 1) — prints
  the **local** static public key per configured WG tunnel, in
  WireGuard-canonical base64 (the form a peer pastes into its
  `[Peer] PublicKey =`). The key is derived once by the helper from the
  local private key at engine construction and surfaced on the per-tunnel
  status row (`local_pubkey_hex`, hex on the wire; the CLI re-renders it
  as base64). A tunnel whose helper has not yet surfaced a key renders
  `(unavailable)` rather than being dropped. Complements
  `show security wireguard [detail]` (#1865 telemetry), which already
  shows the **peer** public key and handshake/transfer counters.

- **`request security wireguard generate-private-key`** (#1434
  Increment 1) — generates a fresh Curve25519/X25519 private key and
  prints it with its derived public key, both in WireGuard-canonical
  base64 — equivalent to `wg genkey` + `wg pubkey`. The key is generated
  locally in pure Go (`pkg/wgkey`, stdlib `crypto/ecdh`); it needs no
  dataplane and issues no control-socket / gRPC round-trip. The printed
  private key is clamped per the Curve25519 convention
  (`priv[0]&=248; priv[31]&=127; priv[31]|=64`) so it is byte-identical
  to what `wg genkey` emits. Paste the private key under the tunnel's
  `tunnel wireguard local-private-key`; hand the public key to the peer.

### Multi-tunnel status (#1434 scope note)

The dataplane is already multi-engine: one `Arc<WgEngine>` and one
control thread per configured WG tunnel-endpoint id (`wg_engines`,
`spawn_wg_control_threads`), per-tunnel telemetry rows, and
engine-by-id encap. **Increment 1** (this change) adds the local-key
telemetry + the two CLI commands above; it is additive and does not
touch the hot path or the AF_XDP shim. **Increment 2 — generalizing the
shim's single-port WG-RX steering so a *second* WG tunnel on a different
listen port has its inbound transport UDP steered to the kernel — is
DEFERRED and lab-gated** (it is a verifier-gated `userspace-xdp` shim
edit with a documented v6-line-rate sensitivity, and must pass the loss
cluster + perf + `make test-failover` before merge). Until Increment 2
lands, only the first configured WG listen port is steered, so a second
tunnel on a different port will not receive inbound transport packets.
Design of record: `docs/research/1434-multi-tunnel-wireguard/plan.md`.
