# Triage result — ps-review-040-a5-b1.md

**Cohort:** ps defensive review, Area A5 Batch 1 (`pkg/cluster`, `pkg/conntrack`, `pkg/ra`, `pkg/vrrp`) — 2 Medium Go-concurrency findings + 84 negative-result modules.
**Base reviewed:** `0ebdb74b2e8` — **STALE** (ancestor of current master, ~425 commits behind).
**Triaged against:** current `origin/master` = **`cae466c7b`** (`git show origin/master:<path>` + `git grep`; not the review's own text, not the working tree).

## Outcome counts
| Disposition | Count | Findings |
| :-- | :-- | :-- |
| **Genuine — filed** | 2 | F1, F2 |
| **Already-fixed** | 0 | — |
| **Not-material / refuted** | 0 | — |
| **Confabulated** | 0 | — |
| **Negative (review's own)** | 84 | modules swept, no defect — accepted as-is |
| **Total findings** | 2 | |

> No HIGH/security items. Both findings are the SAME two cluster bugs independently reported by gemini-review-041 (Med-11 / Med-12); each filed once with dual provenance.

---

## Genuine — filed (per-finding WHY)

| # | Finding | Issue | Sev | file:line (master) | Why genuine + fix |
| :-- | :-- | :-- | :-- | :-- | :-- |
| F1 | Data race on `cachedNlHandle` in `Monitor.getNlHandle()` | **#4715** | Low-Med | cluster/monitor.go:543-558 | Confirmed on master: `getNlHandle` lazily inits `mon.cachedNlHandle` via `netlink.NewHandle()` with NO `mon.mu`/`sync.Once`. Two production callers reach it lock-free from different goroutines — `pollInterfaceMonitors` (:260, `poll()` released mon.mu at :230) and `RGInterfaceReady` (:506, unlocks mon.mu at :504; from daemon_ha.go:627). Both observe `cachedNlHandle==nil` → both `NewHandle()` → one netlink FD leaks; the write (:556) races `Stop()`'s write (:189, under mon.mu). Fix: lock the read-modify-write / `sync.Once`. Also gemini Med-11. |
| F2 | `rg.holdTimer` leak + spurious wakeup on stopped Manager | **#4716** | Low | cluster/manager.go:388-406 + readiness.go:38-50 | Confirmed on master: `Manager.Stop()` stops monitor/hbSender/hbReceiver but never iterates `m.groups` to cancel `rg.holdTimer`. The `time.AfterFunc` closure guards only `if !rg.Ready { return }` — no `m.stopped` flag exists. A timer armed while `rg.Ready` fires post-Stop, takes `m.mu`, runs `runElection`/`electSingleNode`, and pins the `Manager` until `takeoverHoldTime` elapses → goleak/test-teardown flakiness (prod `Stop()` is process teardown at daemon_run.go:1823, so the election itself is moot). Fix: range groups under m.mu, Stop()+nil each holdTimer. Also gemini Med-12. |

## Negative results
The review's 84 module-by-module negatives (`pkg/cluster` election/heartbeat/sync/garp, `pkg/conntrack` gc, `pkg/ra`, `pkg/vrrp` state machine/packet/track) were not independently re-audited beyond the two flagged findings; no counter-evidence surfaced and they are accepted as swept. The two flagged findings are the only defects claimed and both are genuine.
