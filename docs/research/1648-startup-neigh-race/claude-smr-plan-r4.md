# Claude SMR plan-review r4 — #1648 (on plan v4, `b66991feb`)

**Verdict r4: PLAN-READY for Gate-R (with two implementation-contract NITs for
/engineer, neither a blocker).**

Framed as netlink / AF_XDP-startup / HA-failover / neighbor-cache domain SMR.
Hostile posture: I went hunting for a fourth window or an ordering hazard the
staging-replay design still leaves open. I found none that blocks the plan.

## 1. Window-3 (config-reload) independently re-verified — UNCONDITIONAL
AGY r3 claimed every config-reload re-opens H-0. I re-verified the *frequency*
qualifier hostilely (the strongest production-relevance lever depends on it):
is `tear_down` conditional? Could a policy-only / filter-only commit skip the
teardown→respawn→dump path, narrowing Window-3 to topology commits only?

**It cannot.** `reconcile()` (`coordinator/reconcile/mod.rs:64`) has exactly one
early-return before `tear_down` — the #1606 policy-integrity preflight rejection
(`:95`). On any *accepted* snapshot, `let preserved = teardown::tear_down(self);`
(`:98`) runs unconditionally; there is no "topology unchanged → skip teardown"
fast-path. `tear_down` → `stop_inner` → `monitor_stop.take()` → `bring_up_workers`
respawn → fresh `initial_neighbor_dump` therefore fires on **every successful
commit**. Window-3 is real and unconditional. v4's claim stands; if anything it
was understated (I had argued the opposite in v3 — my error, now doubly refuted).

Refinement (not a blocker, belongs in Gate-R framing): the daemon-side path is
unconditional, but whether the Go control plane sends a reconcile RPC on *every*
`commit` vs only on snapshot-delta is a separate (control-plane) question. Either
way the daemon-side H-0 window opens whenever reconcile *is* called, which is
frequent. Gate-R R-config (OQ-5) already reproduces commit-during-cold-connect.

## 2. 5.A.2 staging-replay ordering — correct, with one precision NIT
Codex r3 CRITICAL-2's hazard (live DEL interleaved with dump rows) is resolved by
"stage seq=0 NEW/DEL, replay after NLMSG_DONE, dump rows first." I worked the
four interleavings:
- dump-row(X=STALE/absent) then staged NEW(X=REACHABLE) → REACHABLE ✓ (the bug)
- dump-row(X=REACHABLE) then staged DEL(X) → removed ✓ (DEL is newer; a DEL can
  only be staged for an entry the walk already passed or never had)
- staged DEL(X) then staged NEW(X) → final NEW ✓ — **iff replay is FIFO**
- staged NEW(X) then staged DEL(X) → final removed ✓ — **iff replay is FIFO**

**NIT-1 (implementation contract):** the plan says "replay after NLMSG_DONE" but
must state explicitly that staged deltas replay in **arrival (FIFO) order**. Two
staged events for the same key are only last-writer-wins-correct if replay
preserves arrival order. A HashMap-keyed staging buffer would silently collapse
NEW-then-DEL into whichever the map iteration yields. §5.A.2 + §8 unit test
should pin "FIFO replay; NEW-then-DEL on same key ⇒ removed; DEL-then-NEW ⇒
present." This is the precise gating contract — add it so /engineer can't ship a
map-based stage that breaks it.

## 3. OQ-9 staging bound fallback — guard against re-dump livelock
The cap + "fall back to a post-dump full re-dump" (OQ-9) is right, but a naive
re-dump under sustained churn can livelock: the re-dump sees the same churn,
overflows again, re-dumps again. **NIT-2:** the fallback needs a bounded retry
(e.g. ≤1 re-dump), after which accept eventual consistency — which is *safe*
because once NLMSG_DONE returns, the socket drops into the steady-state loop
(`neighbor.rs:526-556`) that processes seq=0 with no filter and will converge the
dropped-during-overflow deltas anyway. So the fallback can simply be: on staging
overflow, stop staging, finish the dump, and let the steady-state loop catch up
— no re-dump needed at all. State the safe fallback explicitly so /engineer
doesn't build an unbounded re-dump loop.

## 4. 5.E ↔ 5.A.2 dependency + socket-recreation — correct
5.E recreating the socket (AGY r3 #3) rather than re-dumping on the congested fd
is the right call, and gating the resync dump on the 5.A.2-fixed/staged parser is
consistent. Gating 5.E construction on Gate-R confirming ENOBUFS (H-D.1) actually
occurs is honest — don't build the theoretical fix. No issue.

## 5. Kill-bar + per-scope disposition — disciplined
Zero-tolerance-on-RTO-signature against an aged/never-seen target B, ≥10 trials
per mode/family, per-scope kill (failover scope vs restart/config-reload scope
decided independently) is methodologically sound and resists both false-negative
(prelearned target) and false-positive (background load) failure modes. The
"ship 5.A.2 for Window-1/Window-3 even if failover is World 2" is NOT
"ship-after-kill" — it is a distinct independently-justified scope, correctly
framed (Codex r3 MEDIUM-2 satisfied).

## 6. Things I tried to break and could not
- A 4th respawn window beyond {restart, crash-promote, config-reload}: ISSU is a
  config-reload (Window-3); manual `request chassis cluster failover` is clean
  (Window-2/H-D); I found no other path that calls `bring_up_workers` with a
  None `monitor_stop`. The three windows are exhaustive for the H-0 mechanism.
- A correctness hole in "DONE/ERROR stay seq-matched while NEW/DEL process at
  seq=0": a malicious/!buggy kernel sending a seq=0 NLMSG_DONE can't terminate
  the dump (guard at `neighbor.rs:438-444` stays). Sound.

## Forward
v4 is PLAN-READY for Gate-R. The two NITs (FIFO-replay contract, bounded/safe
staging-overflow fallback) are /engineer implementation-contract precision, not
plan blockers — fold them into §5.A.2 + §8 wording. Awaiting Codex r4 + AGY r4
confirmation that no further window/ordering hazard remains.
