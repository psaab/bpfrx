# Codex plan-review r4 — #1648 (on plan v4, `b66991feb`)

Task ID: `task-mpr1hywo-cxrf47`
Codex session: `019e7437-d377-73d2-adc9-2cab72178301`

**Verdict: PLAN-NEEDS-MINOR.**

v4 resolves my r3 criticals, but I would not stamp PLAN-READY until three
wording/contracts are fixed.

## Findings

1. **Window-3 is real, but "every commit" is overclaimed.** `reconcile()`
   teardown is unconditional once called (`reconcile/mod.rs:98`), but same-plan
   snapshot applies bypass reconcile and call `refresh_runtime_snapshot()`
   instead (`server/handlers/snapshot.rs:84`, `coordinator/mod.rs:457`). So
   Window-3 is "every accepted binding reconcile / worker rebuild," not every
   policy-only commit.

2. **Claude NIT-2's "stop staging, finish dump, let steady-state converge"
   fallback is not safe.** The dump loop has already consumed those seq=0
   messages (`neighbor.rs:406`, `neighbor.rs:434`); the steady-state loop only
   sees later messages (`neighbor.rs:526`). A consumed-but-unstaged REACHABLE
   advert may never be replayed. Use a bounded resync contract: finish dump,
   then at most one clean re-dump/socket-recreate attempt, then log/metric
   degraded state. Avoid unbounded re-dump livelock, but do not call
   steady-state-only deterministic.

3. **R3's clean-failover cell is still stale.** It says R2 ~1s means "ship
   on-link warm-at-promote and/or dump-before-admit" (`plan.md:376`), but v4
   elsewhere correctly says clean failover can only justify 5.E if ENOBUFS is
   actually observed (`plan.md:648`). Add the missing branch: clean-failover RTO
   with cold target and ENOBUFS=0 means unknown H-D/first-packet path, not 5.A.2
   or 5.E.

## Six Checks

1. **Yes:** stage-then-replay after dump rows resolves CRITICAL-2 if replay is
   FIFO/arrival-order. A HashMap with arbitrary collapse/iteration is not
   acceptable. DONE/ERROR must remain seq-matched; only seq=0 type 28/29 are
   staged.
2. **No fourth monitor-respawn window found.** `bring_up_workers()` has one
   caller (`reconcile/mod.rs:112`); respawn is gated by `monitor_stop.is_none()`
   (`bringup.rs:330`); `monitor_stop` is taken in `stop_inner()`
   (`coordinator/mod.rs:199`). Clean RG promote only calls warm logic, no dump.
3. **Yes:** 5.A.2 has standalone value as a prerequisite for 5.E. Any ENOBUFS
   resync dump on a subscribed netlink socket reopens the seq=0 mix unless the
   dump parser is fixed or 5.A.3 is used.
4. **No:** the steady-state-only overflow fallback is unsound for
   already-consumed deltas. Bound the re-dump, do not remove it entirely.
5. **Gate-R mostly covers the matrix:** R1 counter A covers H-0; R2 aged target
   covers warm/cold failover; ENOBUFS counting covers H-D.1. The unbacked
   disposition is clean-failover RTO with ENOBUFS absent.
6. **Per-scope kill discipline is crisp in the recommendation** (`plan.md:654`),
   but stale matrix/World-1 wording should be updated so nobody ships "any fix"
   after a scoped kill.
