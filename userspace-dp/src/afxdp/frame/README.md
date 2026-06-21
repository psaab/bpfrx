# userspace-dp/src/afxdp/frame/

Packet parsing + L3/L4 byte-level mutation + checksum recomputation.
The bottom layer that the rest of the pipeline reaches into to
inspect or rewrite a packet sitting in a UMEM frame.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Re-export hub + cross-module helpers (`apply_dscp_rewrite_to_frame`, `decode_frame_summary`, `frame_has_tcp_rst`, etc.). |
| `byte_writes.rs` | In-place IP and L4 port rewrites (`write_ipv4_dst`, `write_ipv4_src`, `write_ipv6_dst`, `write_ipv6_src`, `write_l4_dst_port`, `write_l4_src_port`). |
| `checksum.rs` | IPv4 header + L4 checksum incremental adjust + recompute. Owns the `checksum16_*` family, the `ChecksumFamily` enum, and the two zero-checksum predicates (`l4_udp_checksum_optional` — RFC 768 received-0 skip, IPv4 UDP only (#1840); `adjust_zero_checksum_illegal` — computed-0 → 0xFFFF canonicalization, v4 UDP / v6 UDP+ICMPv6 (#1839)). The v6 adjusters/recompute take a caller-supplied `rel_l4` (ext-aware offset, #1838). |
| `inspect.rs` | Read-only parsers / matchers used by screen, policy, conntrack hot paths. |
| `tcp.rs` | TCP-specific inspection + mutation kernels (#989) — flags, MSS clamp, header munging. |
| `tcp_segmentation.rs` | TCP segmentation kernels for forwarded over-MSS frames; re-exported from `mod.rs`. The `#[cold]` annotation is on the TX-side wrapper in `tx/tcp_segmentation.rs` that calls into these kernels, not on the kernels themselves. |
| `tests.rs` | Co-located unit tests; relocated out of `mod.rs` in #1046 Phase 1. |
| `prop_tests/` | #1824 proptest property harness — parse no-panic/bounds/round-trip, NAT round-trip + descriptor-vs-generic differential, TSO reassembly. `cfg(all(test, not(miri)))`. See "Property tests" below. |

## Where it sits

- Read by every stage that inspects a packet (screen, policy,
  conntrack, NAT, forwarding).
- Mutated by NAT / NAT64 / NPTv6 to rewrite addresses + ports +
  checksums.
- Mutated by CoS for ECN CE-marking and DSCP rewrite.

## Notable invariants

- Visibility is tight: `adjust_l4_checksum_ipv6_addr_bytes` is
  file-private to `checksum.rs` (only the local SNAT/DNAT rewrites
  use it) and is pulled into `mod.rs` via a non-pub `use` so it
  doesn't leak via a glob re-export.
- All byte-level helpers assume the caller has already validated the
  packet bounds. The validation lives in `inspect.rs` and the worker
  hot path; do not call a `byte_writes` fn on an unvalidated frame.
- IPv4 checksum is incrementally adjusted (`adjust_*`) on each
  per-field rewrite. The `recompute_*` helpers exist for the rare
  case where the previous checksum is unknown (e.g. NAT64 from
  scratch in generic XDP — the BPF-side handling of this case is
  documented in `bpf/headers/` and the `xdp_nat64.c` source).
- **IPv6 L4 offset is caller-threaded (#1838)**: `apply_nat_ipv6`,
  the v6 checksum adjusters, and `recompute_l4_checksum_ipv6` take a
  `rel_l4` parameter instead of assuming the fixed 40-byte base
  header. The single source of offset truth is `v6_rel_l4_offset` in
  `mod.rs` (meta-led when `meta_rel >= 40 && l4 > l3`, else the
  extension-chain walk) — shared by the descriptor fast path, the
  generic in-place rewrite, the copy builder, the slow path, and the
  ICMPv6-error NAT reversal builder, so the offset precedence rule
  cannot drift between paths. Every adjuster call within one
  `apply_nat_ipv6` invocation uses the SAME threaded `rel_l4` as the
  byte writes it balances — never re-derive mid-function.
- **Zero-checksum rules are predicate-routed (#1839/#1840)**: the
  RFC 768 received-0 skip (`l4_udp_checksum_optional`) is IPv4-UDP
  only; the computed-0 → 0xFFFF canonicalization
  (`adjust_zero_checksum_illegal`) covers v4 UDP and v6 UDP+ICMPv6
  (NOT TCP — a computed TCP 0x0000 is wire-valid in both families).
  Both rewrite paths route through the same predicates;
  `apply_nat_port_rewrite` additionally applies the no-op-port parity
  rule (v6 UDP stored 0x0000 + any port-NAT decision → 0xFFFF, even
  when the port value is identical) so the descriptor's ≡0-delta
  behavior matches byte-for-byte.
- **Non-first fragments skip all L4 byte ops (#1852)**: a non-first IP
  fragment has no L4 header at the post-IP offset — those bytes are
  payload. The orchestrators compute the predicate ONCE
  (`is_non_first_fragment` / `ipv4_is_non_first_fragment` /
  `ipv6_is_non_first_fragment` in `inspect.rs`) and thread a
  `non_first_fragment: bool` into `apply_nat_ipv4`/`apply_nat_ipv6`,
  `enforce_expected_ports`/`_at`, and `restore_l4_tuple_from_meta`. On a
  non-first fragment the IP address is still rewritten (every fragment
  carries the IP header and must stay consistent for reassembly), but the
  L4-checksum adjust, port rewrite, port enforcement and ICMP ident
  restore are SKIPPED — the address-change delta is folded into the first
  fragment's L4 checksum, which covers the whole datagram and is correct.
  The descriptor fast path returns `None` for non-first fragments so the
  caller falls back to the generic path (preserving the #1838 P-N3
  byte parity). The pre-rewrite dynamic pool SNAT allocation
  (`nat/source.rs`) is gated separately — a non-first fragment that would
  need a pool allocation is dropped (`SourceNatFailureReason::NonFirstFragment`)
  rather than leaking a pool port; static / interface (address-only) SNAT
  is unaffected. `clamp_tcp_mss` self-gates the fragment case (both
  families) AND derives the v6 L4 offset via the ext-aware
  `packet_rel_l4_offset_and_protocol` so MSS clamping reaches
  ext-headered v6 SYNs (the shared helper is left unchanged — GRE decap
  and tunnel local-origin read it to forward fragmented inner packets).
- **TCP inspection helpers are ext-header-aware (#2148)**: the read-only
  diagnostic/telemetry helpers `frame_has_tcp_rst`,
  `extract_tcp_flags_and_window`, and `extract_tcp_window` (`tcp.rs`) all
  derive the IPv6 L4 offset via the shared `packet_rel_l4_offset_and_protocol`
  ext-header walker, NOT a fixed L3+40. Before #2148 they hard-coded the
  TCP header at L3+40, so an IPv6 flow carrying any extension header
  (hop-by-hop, routing, fragment, dest-opts) had its RST/flags/window read
  from inside the extension header — operator-visible RST and zero-window
  diagnostics (cos queue service, rx telemetry, tx transmit, frame build
  corruption check, tunnel inner inspection) were false on those flows.
  The walker is bounded (≤6 iterations), allocation-free (no per-packet
  heap), and fails safe — a truncated/malformed/looping chain yields
  "no RST" / "flags unknown" (false / None) rather than panicking or
  reading OOB. Today these helpers are diagnostics-only, but routing them
  through the shared walker means the next caller cannot reintroduce the
  fixed-40 bug. IPv4 and plain (no-ext-header) IPv6 behavior is unchanged.
- **Canonical L2 / IPv6 parse contract + drift canaries (#2150)**: the
  userspace dataplane still has FIVE distinct Ethernet-L2 offset parsers
  (`afxdp/parser.rs::parse_eth_offsets` [learning], `inspect.rs::frame_l3_offset`
  [forwarding], `cos/ecn.rs::ethernet_l3` [CoS ECN], `nat64.rs::frame_l3_offset`
  [NAT64], `afxdp/icmp.rs::ingress_reply_l2` [ICMP reply VID]) and THREE IPv6
  extension-header walkers (`inspect.rs::packet_rel_l4_offset_and_protocol`
  [#2148, forwarding/GRE], `screen/extract.rs` [#2189, fail-closed], and
  `icmp_embed/parse.rs::parse_embedded_v6_l4` [#1838, embedded]). The
  CANONICAL CONTRACT they MUST agree on:
  - **L2**: untagged → l3 = 14; a single 0x8100 (802.1Q) OR 0x88a8 (802.1ad)
    tag → l3 = 18 (the inner ethertype, possibly still a VLAN TPID for a
    QinQ double tag, is returned as-is). A QinQ DOUBLE tag is NOT unwound in
    userspace — the upstream XDP shim (`userspace-xdp/src/lib.rs::parse_l2`)
    drops double-tagged frames before they reach the XSK, so there is no
    reachable divergence. Adding double-tag transit would require changing
    BOTH the shim and the userspace parsers and is out of scope.
  - **IPv6 ext-headers**: walk the chain (shared #2148 engine, 6-iteration
    bound) to the terminal L4 offset + protocol; do NOT assume L4 at a fixed
    L3+40.
  PR-1 of #2150 fixed the three parsers that DISAGREED on a single 0x88a8
  tag / ext-headered NDP (`parse_eth_offsets` treated 0x88a8 as the inner
  ethertype → l3=14; `nat64::frame_l3_offset` treated it as untagged →
  l3=14; `parse_ndp_neighbor_advert` read a fixed L3+40 and missed an NA
  behind a hop-by-hop header) and added drift-guard CANARIES
  (`parser_tests.rs::l2_offset_canary_all_parsers_agree`,
  `ipv6_walk_canary_learning_agrees_with_forwarding`,
  `nat64_tests.rs::nat64_l2_offset_canary`) that FAIL the instant any parser
  drifts from the contract. These bugs were LATENT not live: the shim
  XDP_PASSes ARP / diverts NDP control / drops QinQ-double, so the buggy
  learning/NAT64 parsers never received the trap frames — the fix closes the
  trap before a future steering change springs it. **PR-2 (deferred
  follow-up)** is the full unification: collapse all five L2 parsers + three
  IPv6 walkers onto one canonical `parse_l2` + one `walk_ipv6_ext` (the
  issue's `afxdp/frame/parse/` tree), gated on these PR-1 canaries staying
  green so the refactor is provably behavior-preserving. Two parallel
  implementations stay DELIBERATELY separate and are NOT part of either PR:
  the XDP shim `parse_l2`/`parse_ipv6` (kernel/no_std/verifier; authority for
  `meta.l3_offset`) and the Go `pkg/vrrp::walkIPv6ExtHeaders` (different
  language + socket).

## Property tests (`prop_tests/`, #1824)

In-tree proptest harness (plan:
`docs/research/1824-fuzz-harness/plan.md`) covering three surfaces:

- **S1 parse** (`prop_tests/inspect.rs`): no input of length 0..2048
  with arbitrary metadata can panic the inspect parsers; offsets stay
  in bounds; the frame-level and packet-relative ext-header walks
  agree; synthesized valid packets (incl. structured IPv6
  extension-header chains) round-trip to the exact built tuple.
- **S2 NAT rewrite** (`prop_tests/rewrite.rs`): NAT apply/undo
  round-trip identity on non-checksum bytes; a full-recompute
  checksum validity oracle (`prop_tests/oracle.rs` — NOT the
  v4-TCP-only `verify_built_frame_checksums`); randomized
  descriptor-vs-generic differential proving the flow-cache fast
  path's byte-equivalence claim with FULL byte equality (empty
  exclusion mask since the #1838/#1839/#1840 trio fix); payload
  immutability.
- **S4 TSO splitter** (`prop_tests/segment.rs`): reassembly identity,
  per-segment wellformedness (seq arithmetic incl. u32 wrap, PSH
  handling, length fields incl. the ext-chain bytes in the v6
  payload-length field, oracle checksums, segment count), NAT
  composition.

The #1838/#1839/#1840 defect trio is fixed and the domain gates that
encoded it are lifted: NAT-applying and segmentation generators emit
v6 extension-header chains, and the differential runs unmasked. The
former defect pins are flipped to positive regression pins
(`pin_1838_*_rewrites_real_l4`, `pin_1839_*_parity`,
`pin_1840_*_family_gated` + the v4-skip counterpart and the
same-port stored-zero parity pin). Valid-packet generators still
never emit v6 UDP 0x0000 checksums — malformed per RFC 8200 §8.1 —
so that encoding lives only in the deterministic pins.

Conventions:

- Passing runs use a fresh random seed per run; the committed
  `userspace-dp/proptest-regressions/**` corpus is replayed first on
  every run and is the actual regression-pinning mechanism. Never
  hand-edit or delete those files; review them like code.
- Case counts are explicit per property (512 parse / 256 rewrite+TSO
  / 128 differential); the whole harness adds well under the 10s
  `cargo test --release` budget. Soak:
  `PROPTEST_CASES=100000 cargo test --release prop_tests::`.
- `cfg(all(test, not(miri)))` — proptest case loops are intractable
  under the targeted miri passes; the deterministic pins and the
  existing `tests.rs` examples keep miri coverage of the same fns.
