# #1636 reviewer task IDs

Tracks task IDs across rounds for long-running session resumption.

## Round 1 (plan v1 @ ee82b880b)

| Reviewer | Task ID | Verdict |
|----------|---------|--------|
| Codex | task-mpprvkz5-63418a | PLAN-NEEDS-MAJOR |
| AGY (adversarial) | adversarial-review-mpprwcvt-6ptuq6 | PLAN-NEEDS-MAJOR |
| Claude SMR | (claude-smr-plan-r1.md) | PLAN-NEEDS-MAJOR |

## Round 2 (plan v2 @ 913af5d31b41)

| Reviewer | Task ID | Verdict |
|----------|---------|--------|
| Codex | task-mppsidkk-vifkld | PLAN-NEEDS-MINOR |
| AGY (adversarial) | adversarial-review-mppsizqg-9swuak | PLAN-NEEDS-MINOR |
| Claude SMR | (claude-smr-plan-r2.md) | PLAN-NEEDS-MINOR |

## Round 3 (plan v3 @ a43fd6f9cb6d) — convergence check

| Reviewer | Task ID | Verdict |
|----------|---------|--------|
| Codex | task-mppssk54-u12emq | REVIEW-BLOCKED (tooling) |
| AGY (adversarial) | adversarial-review-mppssucj-nhfik0 | PLAN-NEEDS-MINOR |
| Claude SMR | (skipped; addressed by AGY r3 findings only) | n/a |

## Round 4 (plan v4 @ d5a4a5eb87b5)

| Reviewer | Task ID | Verdict |
|----------|---------|--------|
| Codex | task-mppsygv9-n0gwuq (retry with inlined sections) | PLAN-NEEDS-MINOR |
| AGY (adversarial) | adversarial-review-mppsyvbf-55nkt6 | PLAN-NEEDS-MINOR |
| Claude SMR | (claude-smr-plan-r4.md) | PLAN-READY (pending r4 fold-in confirmation) |

## Round 5 (plan v5 @ 1016ccfca89f)

| Reviewer | Task ID | Verdict |
|----------|---------|--------|
| Codex | task-mppt4xl4-tf0zaj | PLAN-NEEDS-MINOR |
| AGY (adversarial) | adversarial-review-mppt55mr-9htu20 | PLAN-READY (with 3 findings to fold for full convergence) |
| Claude SMR | (deferred to r6 cycle) | n/a |

## Round 6 (plan v6 @ 268fb607243a)

| Reviewer | Task ID | Verdict |
|----------|---------|--------|
| Codex | task-mpptb9hy-236nc7 | PLAN-READY |
| AGY (adversarial) | adversarial-review-mpptbh1g-iqbqdj | PLAN-NEEDS-MINOR (4 findings folded into v7) |
| Claude SMR | (claude-smr-plan-r6.md) | PLAN-READY contingent on v7 fold-in |

## Round 7 (plan v7 @ 3f9aecc700c9) — CONVERGED PLAN-READY

| Reviewer | Task ID | Verdict |
|----------|---------|--------|
| Codex | (not re-dispatched; r6 PLAN-READY stands; v7 only touches AGY r6 findings) | PLAN-READY (r6) |
| AGY (adversarial) | adversarial-review-mpptjf39-5ajzfe | **PLAN-READY** |
| Claude SMR | (claude-smr-plan-r7.md) | **PLAN-READY** |

**3-of-3 convergence achieved.** Proceeding to issue comment + final return.

## CODE review (PR impl phase, branch fix/1636-cold-connect-mitigation)

| Reviewer | Task ID | Verdict |
|----------|---------|--------|
| Claude SMR | (claude-smr-code-r1.md) | MERGE-READY |
| Codex | (codex-companion task, session a8c1b014) | 6 findings (2 High, 3 Med, 1 Low) — addressed in r2 |
| AGY (adversarial) r1 | adversarial-review-mpq1z20f-7yc7mu | 5 findings (no KILL, wire clean) — addressed in r2 |
| AGY (adversarial) r2 | adversarial-review-mpq2jl5d-sqd223 | **MERGE-READY** — all 4 fixes verified correct/complete, no new defect, ran Go+Rust suites clean |
| Copilot | PR #1640 copilot-pull-request-reviewer | 4 findings — addressed in r2 |

### Round-2 fix disposition (commit after review)
- Codex High #1 (tunnel route wrong-RG): FIX — skip routes with tunnel_endpoint_id != 0 (+ test).
- Codex High #2 (forced warm lost when queue full of 4096 stale items): REJECT — requires 4096 in-flight; warmer drains in µs, queue realistically holds <100; force path stores last_warm_sweep_ns so a later sweep recovers.
- Codex Med #3 / (warms all active RGs not just activated): REJECT — already-resolved neighbors are skipped (no-op); broader-than-needed but not a defect.
- Codex Med #4 (one stale probe after stop): FIX — re-check stop after recv before any side effect.
- Codex Med #5 / AGY #3 (Go: not restored on runtime userspaceDP→false): FIX — restore neigh retrans + clear captures in the runtime-disable branch (+ test).
- Codex Low #6 / Copilot #2 / AGY #4 (log storm): FIX — transition-gated AtomicBool, re-arms on recovery.
- Copilot #1 (on_link_up dead code): FIX — removed the unwired helper + test, documented deferral (no link-state monitor to call it).
- Copilot #3/#4 (doc ≤250 vs 300 threshold): FIX — docstrings aligned to NEIGH_RETRANS_FAST_THRESHOLD_MS.
- AGY #1 (coordinator silent poison skip): REJECT — poison is surfaced via the worker's .expect() → channel break → warm_disconnected; a coordinator-side panic is a worse failure mode and inconsistent with the coordinator's established if-let-Ok mutex discipline.
- AGY #2 (generation/rate-limit race): REJECT — key is (ifindex,hop); a changed next-hop is a different key (not rate-limited); same-key re-warm is correct and the 5s window self-heals.
- AGY #3 post-start iface leak: documented as benign known limitation (250ms is a strict improvement on any iface; matches netdev_budget observed-value-only restore).
- AGY #5 transient drop on manual sysctl revert: accept — one-snapshot window on manual admin revert, inherent to per-snapshot recompute.
