# #963: decompose rewrite_forwarded_frame_in_place (the slow-path
# god function) into v4/v6 specialized helpers + extracted subroutines

Plan v1 — 2026-04-29.

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

The codebase already has the hot-path specialization #963 asks for:

- `RewriteDescriptor` (`flow_cache.rs:34`) — a precomputed packet
  rewrite plan baked at flow-cache insertion time.
- `apply_rewrite_descriptor` (`frame.rs:1792`) — the straight-line
  fast path that uses it. Comments explicitly call out: "Eliminates
  per-packet branches for address family, VLAN presence, NAT type,
  and checksum recomputation — all decisions are baked into the
  descriptor at session/flow-cache insertion time. Scope: IPv4/IPv6
  TCP and UDP only." (frame.rs:1779–1790)

`rewrite_forwarded_frame_in_place` is the **fallback** for cases the
descriptor doesn't cover — NAT64 (header-size change), NPTv6
(checksum-neutral but address rewrite differs), ICMP identifier
repair, and packets without a flow-cache entry on first sight.

So #963's "god function" complaint is about the *slow path* — the
hot path is already specialized. The fix is to decompose the slow
path for readability and maintainability, not to add another layer
of builder/state abstraction (that's already what the descriptor
is).

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
- Improves I-cache locality for the v4 hot path: when a binding only
  sees IPv4 traffic, the v6 code is cold and gets evicted from
  I-cache instead of being interleaved.

### Decomposition

Extract into three private `#[inline]` helpers in `frame.rs`:

```rust
/// Common preamble: validate L3 offset, compute payload_len,
/// resolve src_mac/vlan_id/apply_nat, write Ethernet header,
/// shift payload to its new position.
///
/// Returns (eth_len, ip_start, frame_len, apply_nat, skip_ttl)
/// or None on validation failure.
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
    // Debug log block + checksum verification (unchanged shape, just
    // moved to live next to the dispatch).
    debug_log_inplace_eth(packet, &prep, meta);
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
- Not a behavior change. Every helper inlines into the same
  generated code as today's body (verified by `cargo bench` /
  `cargo asm` if needed; the `#[inline]` attribute keeps the
  compiler's options identical).
- Not a perf claim. The win is readability/maintainability —
  swapping the v4 branch for a future change becomes editing a
  named function instead of finding the right `match` arm in a
  170-line body.

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
- `rewrite_forwarded_frame_in_place_reuses_rx_frame` (in tests.rs)
- All `apply_rewrite_descriptor_*` tests (the hot-path specialized
  function is unchanged).

No new tests required — the refactor is structure-only. A new test
to demonstrate the refactor's behavior would necessarily duplicate
an existing one.

## Acceptance gates

1. `cargo build --release` clean (no new warnings beyond baseline).
2. `cargo test --release` ≥ baseline (863 post-#965), 0 failed.
3. Cluster smoke (HARD): no regression on the unloaded-session path.
   Run on `loss:xpf-userspace-fw0/fw1` (the userspace-dp HA cluster
   that is the default deploy target) AND with CoS configured on
   every iperf3 forwarding-class via `test/incus/cos-iperf-config.set`.
   CoS state is wiped by `cluster-deploy`, so the smoke runner must
   re-apply that fixture before measurement.

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
4. Failover smoke: 90-s iperf3 -P 12 through fw0, force-reboot fw0
   at +20s, fw1 takes over within 10s, iperf3 average ≥ 1 Gb/s and
   ≥ 5 GB received.
5. Codex hostile review (plan + impl): AGREE-TO-MERGE.
6. Gemini adversarial review (plan + impl): AGREE-TO-MERGE.
7. Copilot review on PR: all valid findings addressed.

## Risk

**Low.** Pure structural refactor with no behavior change. The
helpers all `#[inline]`, so the compiler's lowering options are
identical to today. Existing test coverage is dense (~30 tests
exercising every branch axis in the function).

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
