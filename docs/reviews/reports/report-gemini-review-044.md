# Final Report — gemini-review-044 (Defensive Code Refactoring Audit)

**Triaged:** 2026-07-09 · **Base:** `03a92b49c` (FRESH — == current `origin/master` at triage) · **Reviewer:** Gemini · **Class:** refactor/modularity · **Fork tell:** none (all cited paths are real bpfrx files).

## Headline
- **191 findings parsed -> 2 novel-and-material.** The audit's "40 verified, 0 dropped" headline is inflated: 9 duplicate the tracked backlog, 1 is an explicit do-not-split guard, 3 are perf/bug claims mis-filed under a refactor audit, and the rest sit under the ~2,000-production-LOC modularity bar. Low signal, as expected for Gemini + refactor.

## Issues filed (2)
| Issue | Title | Why it's genuine |
|---|---|---|
| **#4839** | refactor: `pkg/dataplane/userspace/protocol.go` — 3,064-LOC / 78-struct wire god file, split per domain | Over 2,000 LOC; single file touched by every subsystem's wire change; pure mechanical per-domain split; untracked. |
| **#4840** | refactor: split the two largest test catch-alls — `afxdp/tests.rs` (14,038 LOC) + `frame/tests.rs` (8,342 LOC) | Two largest files in the repo; catch-all test dumping grounds; recognized code-motion class (precedent #4409); untracked. |

## Disposition buckets
- **GENUINE -> 2** (#4839, #4840)
- **ALREADY-TRACKED -> 9** — #4404 (poll_descriptor), #4407 (daemon.go), #4408 (tx/dispatch + waterfill), #4409 (nat), #4421 (umbrella: policy.rs, nat64.rs, neighbor.rs, SessionTable, ForwardingState, SessionEntry Arc-clone, Surface-A DDNS)
- **DELIBERATE (do-not-split) -> 1** — `predefined.go` (finding's own advice is "keep as-is")
- **NOT-MATERIAL -> 28** — under the ~2,000-LOC bar (dhcp.go 1,800; relay.go 1,545; policymatch 1,714; manager_ha 1,440; maps_sync 1,763; eventstream 1,169; ...), the 805-LOC neighbor_resolver.rs (conflated with tracked neighbor.rs), a partially-decomposed worker_loop, an out-of-scope dev bench tool, and 3 perf/bug claims out of class for a refactor audit
- **CONFABULATED -> 0** — all 40 cited paths exist on master
- **151 low-confidence** -> one bulk NOT-MATERIAL cohort (every item `File: unknown`, no evidence)

## Verdict
Two mechanical, well-bounded splits worth scheduling; no security or correctness exposure. Detailed per-finding reasoning: `/tmp/result-gemini-review-044.md`.
