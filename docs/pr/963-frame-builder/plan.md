# #963: decompose rewrite_forwarded_frame_in_place (the slow-path
# god function) into v4/v6 specialized helpers + extracted subroutines

Plan v3 — 2026-04-29. Addresses Codex round-2 (task-mok8khp9-0jm235):

a. Stale Risk section still claimed "compiler's lowering options
   identical" via `#[inline]`. Rewrote to say `#[inline]` is a hint,
   not a guarantee; perf parity is validated by the smoke gate.

b. "Improves I-cache locality" deterministic claim softened to a
   *possible* side-benefit, since `#[inline]` doesn't guarantee
   the v6 helper is kept out-of-line.

c. Removed the phantom `debug_log_inplace_eth(...)` 4th helper
   from the body sketch. The cfg(debug-log) block stays inline
   (it captures local prep state; extracting it would just widen
   the helper signature with no benefit).

Plus: TTL sentinel test extended to be table-driven over IPv4
TTL and IPv6 hop-limit so it validates the skip_ttl gate in
both rewrite_apply_v4 and rewrite_apply_v6.

v2 — Addresses Codex round-1 (task-mok8bo19-r2vheq):
five blocking findings, all fixed.

1. Payload-shift / eth-header ordering corrected. Plan v1 prose
   said "write Ethernet header, shift payload" — backwards. Current
   code correctly does `copy_within` BEFORE `write_eth_header_slice`
   (else VLAN push corrupts the IP header). Helper docstring now
   pins the order explicitly.

2. Two sentinel tests added: `_skips_nat_for_fabric_redirect_when_disabled`
   (inverse of the existing `_when_enabled` test) and
   `_skips_ttl_when_fabric_ingress_flag_set`. These guard the
   apply_nat and skip_ttl booleans through the extraction.

3. Port-enforcement decision pinned: keep `enforce_expected_ports`
   (reparsing variant) in the helpers; switching to
   `enforce_expected_ports_at` is a separate optimization.

4. `#[inline]` codegen claim weakened. Plan v1 said "compiler
   lowering options identical" — false; `#[inline]` is a hint, not
   a guarantee. Now framed as "perf parity is the gate, not perf
   improvement".

5. Acceptance commands corrected: `--manifest-path
   userspace-dp/Cargo.toml`. Honesty caveat added that the iperf3
   CoS smoke exercises the warmed flow-cache HOT path, not the
   slow-path fallback this PR refactors; slow-path coverage comes
   from unit tests + first-sight packets in the smoke + post-
   failover sessions.

## Investigation findings (Claude, on commit 430b3d93)

`userspace-dp/src/afxdp/frame.rs:1560` defines
`rewrite_forwarded_frame_in_place` — the issue's "god function". It's
~170 lines and handles every permutation of:

- L3 offset trust vs reparse (lines 1573–1576).
- FabricRedirect vs ForwardCandidate disposition (1581–1593).
- VLAN presence (vlan_id > 0 → eth_len = 18, else 14) (1595).
- IPv4 vs IPv6 (matched on `meta.addr_family as i32`) (1619–1695).
- TTL skip flag (`meta.meta_flags & 0x80`) (1618, 1628, 1650, 1670, 1684).
- NAT apply gate (1647, 1681).
- Port enforcement (`enforce_expected_ports`) and conditional
  L4-checksum recompute (1659–1664, 1687–1692).
- Debug logging (1696–1726).
- Cfg-gated checksum verification (1728–1730).

### What's already in place (don't re-build)

The codebase already covers the cases #963's title would address
with a builder/state pattern:

- `RewriteDescriptor` (`flow_cache.rs:34`) — a precomputed packet
  rewrite plan baked at flow-cache insertion time. This is NOT
  technically a builder for the slow path; it is the reason the
  slow path doesn't need a new state-pattern abstraction (the
  decisions for cached flows are made elsewhere and passed in).
- `apply_rewrite_descriptor` (`frame.rs:1792`) — the straight-line
  fast path that consumes `RewriteDescriptor`. Comments explicitly
  call out: "Eliminates per-packet branches for address family,
  VLAN presence, NAT type, and checksum recomputation — all
  decisions are baked into the descriptor at session/flow-cache
  insertion time. Scope: IPv4/IPv6 TCP and UDP only."
  (frame.rs:1779–1790)

`rewrite_forwarded_frame_in_place` is the **fallback** for cases the
descriptor doesn't cover — NAT64 (header-size change), NPTv6
(checksum-neutral but address rewrite differs), ICMP identifier
repair, and packets without a flow-cache entry on first sight.

So #963's "god function" complaint is about the *slow path*. The
fix is to decompose the slow path along its existing branch axes
for readability, not to introduce a new abstraction layer.

## Approach

**Decision**: extract the slow path into specialized v4 / v6
sub-functions plus a small set of named extracted helpers. No new
struct, no builder, no trait. Just function decomposition along the
existing branch axes.

This is the minimal scope that addresses the issue:
- Reduces the body of `rewrite_forwarded_frame_in_place` to a
  small dispatch on address family.
- Keeps every existing call site identical (no API change).
- Preserves all existing tests (no behavioral change).
- *May* improve I-cache locality for the v4-only branch in
  bindings that see only IPv4 traffic — but this depends on
  whether the compiler keeps the v6 helper out-of-line, which
  `#[inline]` does not guarantee. Treat as a possible
  side-benefit, NOT a deterministic outcome (Codex round-2 #2).

### Decomposition

Extract into three private `#[inline]` helpers in `frame.rs`:

```rust
/// Common preamble: validate L3 offset, compute payload_len,
/// resolve src_mac/vlan_id/apply_nat, **shift the payload to its
/// new position FIRST**, then write the Ethernet header.
///
/// Order matters: when VLAN tag is added (eth_len 14 → 18) the
/// payload shifts forward by 4 bytes. If we wrote the new
/// Ethernet header first, the `copy_within(14.., 18)` payload
/// shift would read from bytes that have just been overwritten
/// by the VLAN tag and corrupt the IP header. The current
/// implementation at `frame.rs:1605-1614` correctly orders
/// `copy_within` BEFORE `write_eth_header_slice`; the helper
/// must preserve that order (Codex round-1 #1 caught a wording
/// flip in plan v1).
///
/// Returns RewritePrep on success, None on validation failure.
#[inline]
fn rewrite_prepare_eth(
    frame: &mut [u8],
    desc: XdpDesc,
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    apply_nat_on_fabric: bool,
) -> Option<RewritePrep> { ... }

struct RewritePrep {
    eth_len: usize,
    ip_start: usize,
    frame_len: usize,
    apply_nat: bool,
    skip_ttl: bool,
    vlan_id: u16, // for the cfg-gated debug-log block
}

/// Apply NAT + TTL + checksum to the IPv4 portion of `packet`.
/// Returns Some(()) on success, None on validation failure.
#[inline]
fn rewrite_apply_v4(
    packet: &mut [u8],
    ip_start: usize,
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    apply_nat: bool,
    skip_ttl: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<()> { ... }

#[inline]
fn rewrite_apply_v6(
    packet: &mut [u8],
    ip_start: usize,
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    apply_nat: bool,
    skip_ttl: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<()> { ... }
```

`rewrite_forwarded_frame_in_place` becomes:

```rust
pub(super) fn rewrite_forwarded_frame_in_place(
    area: &MmapArea,
    desc: XdpDesc,
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<u32> {
    let meta = meta.into();
    let frame = unsafe { area.slice_mut_unchecked(desc.addr as usize, UMEM_FRAME_SIZE as usize)? };
    let prep = rewrite_prepare_eth(frame, desc, meta, decision, apply_nat_on_fabric)?;
    let packet = &mut frame[..prep.frame_len];
    match meta.addr_family as i32 {
        libc::AF_INET => rewrite_apply_v4(
            packet, prep.ip_start, meta, decision,
            prep.apply_nat, prep.skip_ttl, expected_ports,
        )?,
        libc::AF_INET6 => rewrite_apply_v6(
            packet, prep.ip_start, meta, decision,
            prep.apply_nat, prep.skip_ttl, expected_ports,
        )?,
        _ => return None,
    }
    // The cfg(feature = "debug-log") header-dump block and the
    // verify_built_frame_checksums call stay INLINE here (not
    // extracted into a 4th helper). They reference local state
    // (vlan_id from prep, frame_len, ip_start, addr_family) and
    // moving them into a helper would either widen the helper's
    // signature with all those params or require a captured
    // state struct — either way more code, no benefit. Keep the
    // existing inline block under the new dispatch.
    #[cfg(feature = "debug-log")]
    {
        // Same thread_local INPLACE_FWD_DBG_COUNT block as today's
        // body, lines 1696-1726, just relocated below the dispatch.
    }
    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(packet);
    }
    Some(prep.frame_len as u32)
}
```

### What this is NOT

- Not a new `PacketEditor` or `FrameBuilder` struct. The hot path
  already has `RewriteDescriptor`; adding another abstraction layer
  duplicates intent and breaks the principle "don't add abstractions
  beyond what the task requires" (CLAUDE.md).
- Not a behavior change. The helpers carry `#[inline]` as a hint to
  the compiler, but `#[inline]` is **only a hint** — it does not
  guarantee that codegen is identical to today's monolithic body.
  The compiler may inline some, none, or all of them, and code
  size / register allocation may shift either direction. If a
  noticeable codegen change occurs it should show up as a perf
  delta in the smoke gate (Codex round-1 #4 corrected an
  overstated claim in plan v1).
- Not a perf claim. The win is readability/maintainability —
  swapping the v4 branch for a future change becomes editing a
  named function instead of finding the right `match` arm in a
  170-line body. Perf parity is the gate, not perf improvement.

## Files touched

- `userspace-dp/src/afxdp/frame.rs`: extract three helpers, rewrite
  the body of `rewrite_forwarded_frame_in_place`. ~120 LOC moved,
  ~30 LOC added (new helper signatures + the dispatch). No public
  API change.

## Tests

All existing tests must continue to pass:
- `rewrite_forwarded_frame_in_place_keeps_icmpv6_checksum_valid_after_snat`
- `rewrite_forwarded_frame_in_place_keeps_icmpv6_echo_identifier_and_sequence`
- `rewrite_forwarded_frame_in_place_keeps_ipv6_tcp_ports_after_vlan_snat`
- `rewrite_forwarded_frame_in_place_keeps_tcp_checksum_valid_after_vlan_snat`
- `rewrite_forwarded_frame_in_place_keeps_tcp_checksum_valid_after_vlan_dnat`
- `rewrite_forwarded_frame_in_place_applies_nat_for_fabric_redirect_when_enabled`
  (the existing fabric-redirect-with-NAT test at `frame.rs:6664`)
- `rewrite_forwarded_frame_in_place_reuses_rx_frame` (in tests.rs)
- All `apply_rewrite_descriptor_*` tests (the hot-path specialized
  function is unchanged).

### New sentinel tests (Codex round-1 #2)

Two cross-cutting boolean axes are not fully covered today and are
exactly the kind of subtle invariant that can be severed during a
function extraction. Add:

1. `rewrite_forwarded_frame_in_place_skips_nat_for_fabric_redirect_when_disabled`:
   the inverse of the existing `_when_enabled` test. Set
   `disposition = FabricRedirect`, `apply_nat_on_fabric = false`,
   `decision.nat = SNAT to 198.51.100.99`. After the rewrite,
   assert the source IP in the frame is the ORIGINAL (not the
   SNAT'd) — confirms the `apply_nat` gate at the dispatch point
   correctly suppresses NAT.

2. `rewrite_forwarded_frame_in_place_skips_ttl_when_fabric_ingress_flag_set`:
   table-driven over IPv4 TTL (offset 8) and IPv6 hop-limit
   (offset 7). For each address family, set
   `meta.meta_flags = FABRIC_INGRESS_FLAG (0x80)` so the sending
   peer is treated as having already decremented TTL. Capture the
   relevant byte before and after the rewrite; assert pre == post
   (no decrement). Covering both families validates the skip_ttl
   gate in both extracted helpers (rewrite_apply_v4 and
   rewrite_apply_v6) — Codex round-2 suggestion.

These guard the `apply_nat` and `skip_ttl` booleans through the
extraction across both families.

### Port-enforcement behavior (Codex round-1 #3)

The current `rewrite_forwarded_frame_in_place` calls
`enforce_expected_ports` (`frame.rs:1659`, `1687`), which reparses
L4 offset from the packet. There is also an
`enforce_expected_ports_at` variant (`frame.rs:2301`) that takes a
precomputed L4 offset.

**Decision**: keep `enforce_expected_ports` (the reparsing variant)
in the extracted v4/v6 helpers. Switching to `_at` is a separate
optimization with its own metadata-vs-parsed offset semantics
question; mixing it into a structure-only refactor would mask any
behavioral change behind the move. If `_at` becomes desirable
later, file a follow-up.

## Acceptance gates

The repo has no root `Cargo.toml`; cargo commands must run with
`--manifest-path userspace-dp/Cargo.toml` (Codex round-1 #5).

1. `cargo build --release --manifest-path userspace-dp/Cargo.toml`
   clean (no new warnings beyond baseline).
2. `cargo test --release --manifest-path userspace-dp/Cargo.toml`
   ≥ baseline (863 post-#965) + 2 new sentinel tests = 865, 0 failed.
3. Cluster smoke (HARD): no regression on the warmed-flow-cache
   forwarding path. Run on `loss:xpf-userspace-fw0/fw1` (the
   userspace-dp HA cluster that is the default deploy target) AND
   with CoS configured on every iperf3 forwarding-class via
   `test/incus/cos-iperf-config.set`. CoS state is wiped by
   `cluster-deploy`, so the smoke runner must re-apply that fixture
   before measurement.

   | Class       | Port  | Shaped rate | P=12 gate     |
   |-------------|-------|-------------|---------------|
   | iperf-c     | 5203  | 25 g exact  | ≥ 22 Gb/s     |
   | iperf-f     | 5206  | 19 g exact  | ≥ 17.1 Gb/s   |
   | iperf-e     | 5205  | 16 g exact  | ≥ 14.4 Gb/s   |
   | iperf-d     | 5204  | 13 g exact  | ≥ 11.7 Gb/s   |
   | iperf-b     | 5202  | 10 g exact  | ≥ 9.0 Gb/s    |
   | iperf-a     | 5201  | 1 g exact   | ≥ 0.9 Gb/s    |
   | best-effort | 5207  | 100 m exact | ≥ 90 Mb/s     |

   Every P=12 row is a blocking gate. iperf-c also keeps the P=1 ≥
   6 Gb/s historical gate.

   **Important honesty caveat** (Codex round-1 #5): the iperf3 CoS
   smoke exercises the WARMED descriptor flow-cache path (i.e.
   `apply_rewrite_descriptor` for steady-state TCP/UDP), NOT the
   `rewrite_forwarded_frame_in_place` slow-path fallback this PR
   refactors. The smoke validates that the hot path stays at line-
   rate (no regression) but does not directly hit the changed code.
   The slow path is exercised by:
   - First-sight TCP/UDP packets before the flow cache warms up
     (every connection's first few packets).
   - ICMP echo / ICMPv6 Neighbor Discovery / ICMP Time Exceeded —
     all of which the cluster smoke generates incidentally during
     warm-up + iperf3 control plane chatter.
   - The unit-test suite, which directly hits the slow path on
     every relevant branch axis.

   For NAT64 / NPTv6 coverage the unit tests are the primary
   guarantee since the cluster smoke fixture does not configure
   either feature.

4. Failover smoke: 90-s iperf3 -P 12 through fw0, force-reboot fw0
   at +20s, fw1 takes over within 10s, iperf3 average ≥ 1 Gb/s and
   ≥ 5 GB received. (The failover window forces the freshly-
   installed sessions on fw1 to traverse the slow path until their
   flow-cache entries warm up — provides incidental coverage of the
   refactored code under realistic load.)
5. Codex hostile review (plan + impl): AGREE-TO-MERGE.
6. Gemini adversarial review (plan + impl): AGREE-TO-MERGE.
7. Copilot review on PR: all valid findings addressed.

## Risk

**Low.** Pure structural refactor with no behavior change.
`#[inline]` is a hint to the compiler, not a guarantee — codegen
may shift either direction (size, register allocation, layout).
Perf parity is validated by the cluster smoke gate, not asserted
by the inline attribute. Existing test coverage is dense (~30
tests exercising every branch axis in the function).

The only realistic risk is an off-by-one or borrow-checker mistake
during the cut — caught by the test suite.

## Out of scope

- Adding a new `PacketEditor` / `FrameBuilder` struct (the issue's
  title floats this; investigation found `RewriteDescriptor` already
  fills that role for the hot path).
- Refactoring `apply_rewrite_descriptor` (it's already specialized).
- Decomposing other long functions in `frame.rs` (e.g.
  `parse_session_flow_from_bytes`, `decode_frame_summary`) — out of
  scope for this PR; tracked under separate issues if needed.
- Performance work — this is a readability refactor; perf parity is
  the gate, not perf improvement.
