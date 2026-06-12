1. **BLOCKER** Stale timer actions can resurrect an attempt immediately after T5 give-up, violating the v9 boundary.
   Evidence: [timers.rs](/home/ps/git/bpfrx/.claude/worktrees/1888-engineer/userspace-dp/src/afxdp/wg/timers.rs:261) computes `actions.initiate = Some(InitiateReason::DeadPeer)` from T7 before cleanup. [wg_control.rs](/home/ps/git/bpfrx/.claude/worktrees/1888-engineer/userspace-dp/src/afxdp/coordinator/wg_control.rs:641) then gives up, aborts pending state, clears T7, drains edges, and comments that only traffic after this boundary may re-trigger. But the same function falls through to [wg_control.rs](/home/ps/git/bpfrx/.claude/worktrees/1888-engineer/userspace-dp/src/afxdp/coordinator/wg_control.rs:680), consumes the already-computed `actions.initiate`, and starts a fresh attempt at [wg_control.rs](/home/ps/git/bpfrx/.claude/worktrees/1888-engineer/userspace-dp/src/afxdp/coordinator/wg_control.rs:699).
   Fix direction: after give-up, either return without considering the pre-cleanup `TimerActions`, or recompute timer actions after clearing T7/draining edges if same-pass T8 behavior is intentionally required.

2. **MINOR** Prometheus help text omits the new `expired` drop reason.
   Evidence: [metrics_userspace.go](/home/ps/git/bpfrx/.claude/worktrees/1888-engineer/pkg/api/metrics_userspace.go:101) emits `reason="expired"` for decap and [metrics_userspace.go](/home/ps/git/bpfrx/.claude/worktrees/1888-engineer/pkg/api/metrics_userspace.go:117) emits it for encap, but [metrics_descriptors.go](/home/ps/git/bpfrx/.claude/worktrees/1888-engineer/pkg/api/metrics_descriptors.go:1195) lists the allowed reasons without `expired`.
   Fix direction: update the descriptor help string so operators do not see undocumented label values.

3. **NIT** The diff contains trailing whitespace in research docs.
   Evidence: `git diff --check 93c3da7ea..HEAD` reports trailing whitespace in `docs/research/1888-wg-timers/agy-plan-r3.md`, `agy-plan-r5.md`, `codex-plan-r1.md`, and `codex-plan-r2.md`.
   Fix direction: strip trailing whitespace before landing.

The mandatory traces otherwise matched the plan: authenticated msg2/msg1 completion-site cleanup preserves post-completion edges, T3 encap gates before counter/header mutation, worker transit follows the same `NoSession` contract, poll wakeup is capped at 100 ms, `expire_sessions` is serialized by `reconcile_lock`, and malformed authenticated inner endpoint-learning is post-AEAD/replay-accepted.

NEEDS-REVISION: The attempt machine can immediately bypass the reviewed give-up boundary using stale pre-cleanup timer actions, which is a core timer correctness regression. The rest of the implementation is close, but that retry-window bug must be fixed before merge.