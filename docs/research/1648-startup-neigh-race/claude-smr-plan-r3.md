# Claude SMR plan-review r3 — #1648 (on plan v3.1 → v4)

**Verdict r3: PLAN-NEEDS-REVISION (I concur with AGY r3; my v3 was wrong).**

## Self-correction: I missed Window-3.
In v3 I wrote and verified "no third window … config-reload does NOT respawn the
monitor". That was a verification ERROR. AGY r3's trace is correct and I
re-confirmed it against the worktree:
- `reconcile/mod.rs:98` → `teardown::tear_down`
- `teardown.rs:28` → `coord.stop_inner(false)`
- `coordinator/mod.rs:199` → `self.neighbors.monitor_stop.take()` (→ None)
- `bringup.rs:330` → `if monitor_stop.is_none()` → respawn → fresh
  `initial_neighbor_dump` (`neighbor.rs:514`).

I checked `stop_inner` and saw it only called from full shutdown WITHOUT
following the `tear_down` → `reconcile` caller chain up. That is exactly the
class of miss the hostile-SMR mandate exists to catch, and AGY caught it. The
consequence is material: **config-reload (every `commit`) re-opens the H-0
window**, which is far more frequent than daemon restart and makes 5.A.2
production-relevant independent of the failover question. This is the strongest
single argument for the fix and I had argued it away.

## Concurrence on AGY r3's other findings
- #2 persistent-errno busy loop: valid; any 5.E touching the loop must add a
  break/recreate on persistent error.
- #3 5.E socket-recreation: valid and important — re-dumping on a congested
  socket re-introduces the seq-mix and may keep hitting ENOBUFS. v4 mandates
  recreation.
- #4 CAP_NET_RAW silent failure: valid latent ops hazard; out-of-scope for the
  cluster repro (daemon has the cap) but worth logging. v4 notes it as OQ-7.
- #5 zero-tolerance kill bar: AGY endorses; I agree (the >1000ms RTO spike is
  cleanly separable from the 0.6-3.7ms band).

## Concurrence on Codex r3
- CRITICAL-2 (ordering): correct — "process seq=0 inline" is unsafe; v4 mandates
  staging-then-replay-after-NLMSG_DONE (or 5.A.3 dual-socket). This is the right
  implementation contract.
- HIGH-3 (5.C.2 test contradiction): my bug; removed in v4.

## Forward
v4 adds Window-3, the staging-replay ordering, 5.E socket-recreation, the test
contradiction fix, and the busy-loop/CAP_NET_RAW/staging-bound hardening. I
assess v4 as PLAN-READY pending r4 external confirmation that no further window
or ordering hazard remains. The plan's measurement-first discipline is intact;
the fix shape (5.A.2 staging-replay for the restart/config-reload windows; 5.E
conditional on H-D.1) is verified-grounded.
