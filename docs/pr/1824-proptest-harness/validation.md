# #1824 proptest harness — validation evidence

Plan: `docs/research/1824-fuzz-harness/plan.md` (PLAN-READY v3.1 @
`fe0ac6240ba1` on `research/1824-fuzz-harness`). Base:
`origin/master` @ `618648b1f`.

## Filed defect issues (plan §10-D, filed before the pins landed)

| Plan ID | Issue | Title |
|---|---|---|
| D3 | #1838 | generic IPv6 NAT path assumes L4 at fixed offset 40 — corrupts valid ext-header traffic |
| D1 | #1839 | IPv6 L4 zero-checksum canonicalization scope mismatch (descriptor all-protocols vs generic UDP/ICMPv6) |
| D2 | #1840 | `adjust_l4_checksum_port` UDP zero-checksum skip not family-gated |

Each is pinned by a deterministic example in
`userspace-dp/src/afxdp/frame/prop_tests/rewrite.rs`
(`pin_1838_*`, `pin_1839_*`, `pin_1840_*`) asserting CURRENT behavior
and referencing the issue; the property generators exclude the
divergent domains (v6 ext × NAT; v6 UDP zero checksum; checksum-byte
equality).

## Plan §9 gates

1. **Release binary unaffected** (§9.1): with the proptest
   dev-dependency + Cargo.lock additions and otherwise-original
   sources, `cargo build --release` reproduces the baseline binary
   **bit-for-bit** (sha256 `cf24d706c5e8…` both sides) — the dev-dep
   is proven byte-neutral. The 8-line `cfg(all(test, not(miri)))`
   module include in `frame/mod.rs` perturbs only
   `.note.gnu.build-id`, `.symtab`, `.strtab` (non-loadable
   metadata); every loadable ELF section (`.text`, `.rodata`,
   `.data`, `.eh_frame`, GOT) verified bit-identical by per-section
   sha256, `size` identical (text 5171640 / data 65184 / bss 17136),
   zero proptest symbols (`nm | grep -ci proptest` = 0).
   `cargo tree -e normal` contains zero proptest crates (the bare
   `grep -c proptest` gate string matches the worktree *path*
   `eng-1824-proptest` in cargo-tree's root line; the crate-level
   count is 0). Release warning count unchanged: 140 == 140.
   Cargo.lock diff is additions-only (proptest 1.11.0 + its dev
   graph); no existing crate changed version.
2. **Full `cargo test --release`** (§9.2): green — 1876 passed /
   0 failed / 2 ignored across all test targets, warm wall-clock
   1.57s (baseline warm execution of the main binary: 1.21s for 1781
   tests; with the harness: 1.47s for 1807 — the 26 prop-harness
   tests add ~0.2-0.3s at the configured counts (512/256/128 cases),
   well inside the ≤10s budget). The one-time proptest dev-graph
   compile cost (~70s cold for the full test build, vs 85.5s cold
   baseline — dominated by the unrelated test-binary build either
   way) is separate and acknowledged by plan §8. One unrelated
   known-flaky failed once under full-suite load
   (`worker_queue::concurrent_recovery_processes_each_command_exactly_once`,
   a scheduling-race assert listed in the known-flakies set; its
   source is untouched by this branch, it passes 5/5 standalone, and
   the full-suite re-run is green).
3. **debug-log feature arm** (§9.3): `cargo test --release
   --features debug-log --bin xpf-userspace-dp prop_tests::` green
   (26/26 — exercises the `verify_built_frame_checksums` debug arms
   inside both rewrite paths).
4. **Mutation spot-check** (§9.4) — the oracles bite:
   - dropping the `0xFEFF` TTL term from the descriptor IPv4
     checksum fold (`frame/rewrite/ipv4.rs:85`) →
     `descriptor_generic_differential` FAILS with "descriptor output
     invalid: v4 IP header checksum invalid". Reverted.
   - dropping the `ihl < 20` floor in `packet_rel_l4_offset`
     (`frame/inspect.rs:93`) → `parse_offsets_in_bounds` AND both
     offset-consistency properties FAIL. Reverted.
   The shrunk mutation-killing seeds are committed in
   `proptest-regressions/` so both mutations stay deterministically
   re-detected.
5. **Coverage spot-check** (§9.4b): `cargo llvm-cov test --release
   --bin xpf-userspace-dp -- prop_tests::` region counts for the v6
   extension-header walk in `frame/inspect.rs` (`frame_l4_offset`,
   lines 44-80), prop harness only:
   - options arm `0 | 43 | 60` — 2.22k executions
   - AH arm `51` ((len+2)*4 arithmetic) — 678
   - fragment arm `44` (fixed 8-byte advance) — 665
   - no-next-header arm `59 => return None` — 4
   - post-loop `Some(offset)` (>6-header bound) — 194
   - `_ => return Some(offset)` (L4 found) — 1.77k
   All four required arms (43/51/44/59) executed. Additionally,
   `pin_ext_walk_mixed_chain_exact_offset` guarantees
   routing+AH+fragment+dest-opts arm execution deterministically on
   every run (not just statistically).
6. **Determinism / flake** (5× repeat of the `prop_tests::` filter):
   26/26 green on all five repetitions (0.14-0.19s each); the
   committed corpus replays first on every run.

## Property list

| ID | Test | Status |
|----|------|--------|
| P-I1 | `inspect::parse_no_panic_on_garbage`, `parse_no_panic_on_mangled_ext_chains` | pass |
| P-I2 | `inspect::parse_offsets_in_bounds` | pass |
| P-I3 | `inspect::parse_offset_consistency_garbage`, `_mangled_ext` | pass |
| P-I4 | `inspect::parse_valid_round_trip` | pass |
| P-I5 | `inspect::parse_meta_independence` + `pin_meta_frame_protocol_arbitration_divergence` | pass (constrained generator + pin) |
| — | `inspect::pin_ext_walk_six_header_bound`, `pin_ext_walk_mixed_chain_exact_offset`, `pin_ext_walk_no_next_header_is_none`, `pin_af_constants` | pass (pins) |
| P-N1 | `rewrite::nat_round_trip_identity` | pass |
| P-N2 | `rewrite::oracle_accepts_generator_output` + oracle asserts inside P-N1/P-N3/P-T3 | pass |
| P-N3 | `rewrite::descriptor_generic_differential` | pass (checksum bytes masked per #1839) |
| P-N3b | `rewrite::pin_ttl_expired_declines_l3_untouched`, `pin_descriptor_port_mismatch_declines`, `pin_descriptor_nat64_nptv6_decline_frame_untouched`, `pin_1838_*`, `pin_1839_*`, `pin_1840_*` | pass (defect pins assert CURRENT behavior — flip on fix) |
| P-N4 | `rewrite::nat_payload_immutable` + in-place assert inside P-N3 | pass |
| P-T1 | `segment::segmentation_no_panic_on_garbage` | pass |
| P-T2 | `segment::segmentation_reassembles_identically` | pass |
| P-T3 | (same test — wellformedness asserts) + `segmentation_declines_syn_fin_rst` | pass |
| P-T4 | `segment::segmentation_composes_with_nat` | pass |

S3 (state encode) is DESCOPED per plan §5.3-S3 (state_writer.rs is a
persister, no Rust decoder, `ConfigSnapshot` has no `PartialEq`; the
schema is pinned by Go-side contract tests).

## Harness defect found and fixed during implementation

The first P-N1 draft oracled bare `apply_nat_ipv4` output and failed:
`apply_nat_ipv4` owns only the L4 checksum — the IPv4 HEADER checksum
belongs to the caller (`rewrite_apply_v4` calls
`adjust_ipv4_header_checksum` after NAT, fused with the TTL
decrement, frame/mod.rs:514-525). The harness now composes the hop
exactly as production does (`apply_nat_family` in
`prop_tests/rewrite.rs`); the shrunk counterexample is committed in
the corpus.
