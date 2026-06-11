# #1866 plan review — Claude SMR (hostile), round 1

Reviewer: Claude (domain SMR: dataplane lifecycle, CPU/OS, SW design).
Target: docs/research/1866-wg-teardown/plan.md @ v1 (6ea7cb37f).
Method: re-derived every load-bearing claim from source, then attacked
the design with worked traces. Whole-function reads per
`feedback_verify_whole_function_body`.

## Verification of plan claims

- **D1 verified REAL** (mod.rs:496-585 + wg_control.rs:93-127). Early
  thread exit leaves `wg_control_threads[id] = (handle, engine_ptr)`;
  unchanged identity ⇒ `populate_wg_engines` (forwarding_build/wg.rs:58-63)
  reuses the engine Arc from the helper's previous forwarding ⇒
  `desired.get(id) == Some(engine_ptr)` ⇒ not stale; spawn loop hits
  `contains_key` (mod.rs:530) ⇒ skip. No liveness check exists. Confirmed.
- **V1/V2/V3 reproduced**: I re-ran the scratch tests (coordinator prune
  + group-delete compile) — both pass. V3's same-plan claim checked
  against `userspaceSkipsIngressInterface` (`iface.Tunnel ⇒ skip`) and
  `include_userspace_binding_interface` (`iface.tunnel ⇒ false`). Correct.
- **V5 (ABA cleared)**: ordering argument holds — the previous engine Arc
  is alive in `self.forwarding` while the new forwarding is built
  (`build_forwarding_state_with_policy_counters_and_previous(snapshot, …,
  Some(&self.forwarding))`), so address reuse across one refresh is
  impossible. Agreed.

## Findings (hostile)

**F1 (MAJOR, design correction) — Change 2 as written can respawn WG
threads while the dataplane is intentionally STOPPED.**
`reconcile_status_bindings` (server/helpers.rs:381-392) calls
`state.afxdp.stop()` when `should_run_afxdp()` is false (disarmed /
forwarding-unsupported); `stop_inner` stops+joins+clears the WG threads
(mod.rs:254-262) — that is current, intended behavior. But
`refresh_status` → `refresh_bindings` keeps firing at 1/s after a stop,
and the coordinator's `self.forwarding.wg_engines` is NOT cleared by
`stop_inner`. A liveness sweep hooked inside
`Coordinator::refresh_bindings` would see desired-but-absent endpoints
and re-bind the UDP port on a disarmed node — a behavioral regression
(port held while forwarding is disarmed, e.g. across RG transitions).
**Required fix**: hoist the call to the SERVER layer —
`refresh_status` calls `state.afxdp.reconcile_wg_control_liveness()`
ONLY under `if should_run_afxdp(&state.status)`. This preserves the
existing stop semantics exactly.

**F2 (MINOR, accuracy) — D1's "permanent until identity change or daemon
restart" overstates.** A binding-plan-changing commit takes the full
reconcile path (tear_down → stop_inner joins+clears → bringup respawns),
which also heals a dead entry. The permanence claim should read "until an
identity change, a binding-plan-changing commit, or a daemon restart" —
still operator-hostile (none of those normally happen), but the plan must
not overstate.

**F3 (MAJOR, fills §4c) — the plan misses the cheapest diagnosis lever
for the residual unknown.** The live ambiguity was "snapshot retained the
endpoint" vs "prune skipped". One rare, state-transition-only log line in
`refresh_runtime_snapshot`/`apply_snapshot`: whenever the WG endpoint id
set CHANGES between consecutive snapshots, print old⇒new (ids + listen
ports). Combined with Change 3's stop/spawn logs, ONE journal capture of
a recurrence pins the layer. Add to Change 3. Without it, §4c's promise
("a recurrence pins the layer in one capture") is not actually delivered.

**F4 (MINOR, implementation precision) — backoff stamp semantics
unspecified.** `last_spawn_attempt_ns` must be written at every ATTEMPT
(success or failure), inside `spawn_one_wg_control_thread`, before the
outcome is known — otherwise a failing bind loop at apply-time (Change 1
path, not backoff-gated) could attempt on every FIB-refresh apply during
route churn. Decide: Change-1 apply-time respawns also respect the 3s
backoff (recommended — applies can arrive in bursts).

**F5 (CLARIFICATION, must be stated as invariant) — single-threaded
lifecycle.** Join-before-bind across "BOTH call sites" is only sound
because every lifecycle mutation (apply handlers, reconcile, the new
sweep) runs under the single `ServerState` guard on the control thread.
State this explicitly in §7; it is the actual reason two live threads
can never race one port in-process.

**F6 (note, no change) — Q4 answer.** I traced `wg_control_loop` for
blocking sites: socket is nonblocking (set at :104), TUN fd nonblocking
(:122), sends are on the nonblocking socket, loop ticks at 1ms idle.
`is_finished()` false ⇒ thread is genuinely looping ⇒ it observes `stop`
within ~1ms. No wedge scenario found. (The >10min test-wedge precedent
was an unrelated futex issue.)

## Answers to §11 questions

1. Tick placement: acceptable ONLY with the F1 hoist; respawn work is
   rare + bounded and the status poll already does heavier work.
2. Residual-unknown stance: ACCEPT with F3 added — self-heal + a capture
   that can pin a recurrence is strictly better than diagnose-first on a
   shared cluster with an active sibling lane.
3. Retry-forever with 3s backoff: correct; a config that collides with a
   kernel wgX is operator error and should keep surfacing, not give up.
4. See F6.
5. See F5 — the guard serialization is the answer; no tombstone needed.
6. Sequencing after #1868: correct; its wg_control.rs changes
   (wg_send_to/canonicalize_endpoint) don't touch the spawn/teardown
   region; trivial rebase expected.

## Verdict

**PLAN-NEEDS-CHANGES** — F1 (stop-semantics gate) and F3 (endpoint-set
transition logging) are required; F2/F4/F5 are wording/precision. No
kill-class flaw: the defect inventory is verified and the design,
corrected per F1, preserves all stated invariants.
