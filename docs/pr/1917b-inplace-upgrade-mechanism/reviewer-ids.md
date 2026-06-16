# #1917 increment B — code-review reviewer ledger

PR: https://github.com/psaab/xpf/pull/1933
Branch: engineer/1917b-inplace-upgrade

## Plan-review (research phase, already converged PLAN-READY v4)
See docs/research/1917b-inplace-upgrade-mechanism/ for plan-review ids.

## Code-review (this PR — 4-way: Codex + AGY + Claude SMR + Copilot)

| Reviewer | Task ID | Round | Verdict |
|---|---|---|---|
| Codex | 019ed12a-9a64-7800-86b6-aeea042e3f7a | r1 | NEEDS-REVISION (3 Critical + 2 High + 1 Medium) |
| AGY | adversarial-review-mqgtwgjy-7dc77o | r1 | NEEDS-REVISION (1 Critical + 2 High) |
| Claude SMR | in-conversation | r1 | NEEDS-REVISION (concurred with Codex/AGY) |
| Copilot | (formal PR review) | r1 | (pending) |

### Round-1 findings + resolution (commit 6fc77fba9)
- Codex Critical#1 (rollback leaves stale FLIPPED journal) — FIXED: rollback journals ROLLINGBACK + clears on success; resume handler.
- Codex Critical#2 (restoreDBSnapshot crash window destroys DB) — FIXED: stage+fsync before move-aside + recovery branch.
- Codex Critical#7 / AGY Critical (drain parser keyed on text FormatStatus never emits — dead on live cluster) — FIXED: rewrote to gRPC + chassis-cluster-information topic, real-format-validated parsers.
- Codex High#2 (stale FLIPPED not recovered) — FIXED: stale-target recovery starts a half-cut FLIPPED/STARTED.
- Codex High#5 (interactive ISSU hard-errors non-TTY) — FIXED: gRPC SystemAction.
- Codex High#6 / AGY (HA proto not actually compared) — FIXED: compare local vs peer HA protocol version lines.
- Codex Medium / AGY (LocalPrimary/DrainComplete substring bugs) — FIXED by the per-RG Local-state rewrite.
- Codex Medium (HelperHealthy ignores --unit) — FIXED: NewSystem(unit).
- AGY Critical (cluster-setup secondary grep never matches) — FIXED: grep real "Local state: Secondary".

### Round 2 (verify fixes)
| Reviewer | Task ID | Round | Verdict |
|---|---|---|---|
| Codex | 019ed139-daee-7692-b2cc-89365fbb7472 | r2 | NEEDS-REVISION (r1 Criticals verified fixed; new: peer-ownership, sync-down, stale-flip) |
| AGY | adversarial-review-mqguhxi4-ob1gq1 | r2 | NEEDS-REVISION (same class + orphan dbsnap + proto-bump doc) |

r2 findings resolved in commit 17df1edb (peer-primary drain, Status:Up sync gate, finish-stale-half-cut, orphan dbsnap gc, proto-bump documented).

### Round 3 (verify r2 fixes)
| Reviewer | Task ID | Round | Verdict |
|---|---|---|---|
| Codex | 019ed142-d414-7b90-a2c6-76b57c09f52f | r3 | NEEDS-REVISION (all prior FIXED; new High: per-RG drain pairing) |
| AGY | adversarial-review-mqguunjw-2g2wpy | r3 | NEEDS-REVISION (same per-RG; new Medium: StartUnit-failure rollback) |

r3 findings resolved: per-RG drain pairing (commit 9fa7c23a), StartUnit-failure auto-rollback (commit 500e2776).

### Round 4 (verify r3 fixes)
| Reviewer | Task ID | Round | Verdict |
|---|---|---|---|
| Codex | 019ed148-6fcf-7df0-ba39-711da9ffb71d | r4 | NEEDS-REVISION (r3 verified; new: PeerTakeoverReady fail-open, curRG bleed) |
| AGY | adversarial-review-mqgv2sxu-morswk | r4 | MERGE-READY |

r4 findings resolved: PeerTakeoverReady not-ready tokens + curRG reset (commit 0b8d0666).

### Round 5 (verify r4 fixes)
| Reviewer | Task ID | Round | Verdict |
|---|---|---|---|
| Codex | 019ed14d-fc32-71a3-852f-db2aac66419a | r5 | r4 fixes correct; Low test-gap (YES-reason-with-"no") |
| Codex (full re-read) | 019ed14d... cont | r5 | ResetFailover all-RGs + PeerTakeoverReady local-view doc |

r5 findings resolved: token-match (not substring) for takeover-ready (commit 7d489933); ResetFailover enumerates all RGs + peer-ready doc (commit ebb8b5fd).

### Copilot (formal PR review)
COMMENTED — 16 inline comments. Overlapped r1-r5 (DrainComplete strong predicate, ResetFailover all-RGs, LocalPrimary, PeerTakeoverReady, deploy grep, --unit health — ALL already fixed). Net-new Copilot items fixed in commit 8b222491: fail-closed msg path (.configdb/active.json), postinst restart safety-net, cutover Options doc.

## Convergence summary
Codex: 5 rounds, each narrowing; final findings were a doc-only Low + two pre-existing design points (ResetFailover RG-scope FIXED; PeerTakeoverReady local-view DOCUMENTED with DrainComplete as the authoritative guard). AGY: r4 MERGE-READY. Copilot: net-new items all addressed. Claude SMR: concurred each round, drove the fixes.

## Residual gates (require the serialized live cluster — NOT run here)
- Live `xpfd upgrade --rolling` on loss:xpf-userspace-fw0/fw1 + MEASURED client gap.
- `make test-failover` (mandatory for cluster/VRRP/sync changes).
- Live validation of the cluster_cli status-text parsers against real output.
