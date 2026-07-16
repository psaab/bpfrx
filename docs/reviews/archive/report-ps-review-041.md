# Final Report — ps-review-041 (HFT-Grade Refactor / Modularity Audit — Rust AF_XDP hot path)

**Triaged:** 2026-07-09 · **Base:** `95b33d49` (advanced; triaged against current `origin/master 0b5e9cb4c`) · **Reviewer:** ps · **Class:** refactor/modularity (hot-path preservation) · **Fork tell:** run in the `avacado-xpf` checkout, which shares history — every cited Rust/Go file verified present on bpfrx master (0 confabulated). Final report file was truncated to a 36-line stub; findings were read from the 10 intermediate batch files.

## Headline
- **Majority already-tracked -> 2 novel-and-material filed**, plus 1 watch-list graduation flagged. The hot-path monolith findings (poll_descriptor, TX dispatch, waterfill, SessionTable, ForwardingState, NAT, policy.rs, protocol.go) all map to existing issues.

## Issues filed (2)
| Issue | Title | Why it's genuine |
|---|---|---|
| **#4845** | refactor: `pkg/config/compiler_validate_warn.go` — 3,600-LOC warn-validator monolith, split per-domain | Over 2,000 LOC; the strict side is already split (#4405) but the warn side is untracked; pure per-domain code-motion. |
| **#4846** | refactor: `pkg/config/compiler_nat.go` — 2,565-LOC tri-fused (helpers + 5 strict validators + per-family compile) | Over 2,000 LOC; split by concern and move strict validators into the existing `compiler_validate_strict_nat.go`; untracked. |

## Note surfaced (not re-filed)
- `userspace-dp/src/afxdp/forwarding/mod.rs` grew **1,761 -> 2,795 LOC** and has graduated from the #2158 watch-list to hard-exceed the ~2,000-LOC threshold. Recommended for re-actioning under the existing **#2158** rather than opening a duplicate issue.

## Disposition buckets
- **CONFABULATED -> 0** — fork shares history; all cited files present on bpfrx master (only drift is size, base vs now)
- **ALREADY-TRACKED (majority)** — poll_descriptor -> #4404; TX dispatch + waterfill -> #4408; SessionTable / ForwardingState-struct / neighbor.rs / policy.rs -> #4421; NAT Rust -> #4409; protocol.go -> #4839; applyConfigLocked -> #4407; compiler.go already split -> #4406; forwarding/mod.rs + queue_service/mod.rs watch-listed -> #2158
- **NOT-MATERIAL (large tail)** — under the ~2,000 prod-LOC bar (cos_classify 1,335; session_glue 1,277; screen 1,540; frame 1,710; sync_conn 1,858; tunnel 1,889; metrics_descriptors 2,013 borderline-declarative), DRY/testability nits, and `wg_control.rs` already reduced 2,280 -> 1,579 on current master
- **DELIBERATE** — worker/loop_body inline hot-path guard; a1g/a4 crypto / fail-closed / wire-compat do-not-touch negatives

## Verdict
Two mechanical splits worth scheduling + one watch-list re-action (#2158); no security or correctness exposure. Detailed per-finding reasoning: `/tmp/result-ps-review-041.md`.
