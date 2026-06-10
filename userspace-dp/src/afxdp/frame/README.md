# userspace-dp/src/afxdp/frame/

Packet parsing + L3/L4 byte-level mutation + checksum recomputation.
The bottom layer that the rest of the pipeline reaches into to
inspect or rewrite a packet sitting in a UMEM frame.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Re-export hub + cross-module helpers (`apply_dscp_rewrite_to_frame`, `decode_frame_summary`, `frame_has_tcp_rst`, etc.). |
| `byte_writes.rs` | In-place IP and L4 port rewrites (`write_ipv4_dst`, `write_ipv4_src`, `write_ipv6_dst`, `write_ipv6_src`, `write_l4_dst_port`, `write_l4_src_port`). |
| `checksum.rs` | IPv4 header + L4 checksum incremental adjust + recompute. Owns the `checksum16_*` family. |
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
  path's byte-equivalence claim (checksum fields excluded — see
  below); payload immutability.
- **S4 TSO splitter** (`prop_tests/segment.rs`): reassembly identity,
  per-segment wellformedness (seq arithmetic incl. u32 wrap, PSH
  handling, length fields, oracle checksums, segment count), NAT
  composition.

Domain restrictions encode documented production divergences (each
pinned by a deterministic example test in `prop_tests/rewrite.rs`,
NOT hidden): #1838 (generic v6 NAT path assumes L4 at fixed offset
40 — NAT generators are v6-ext-free), #1839 (0x0000/0xFFFF L4
zero-checksum canonicalization scope mismatch — byte comparisons
mask checksum fields; the oracle accepts both encodings), #1840
(family-ungated UDP zero-checksum skip — generators never emit v6
UDP zero checksums). Flip the pins when those issues are fixed.

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
