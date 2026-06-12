# Claude SMR hostile code review — PR #1907 round 1

Scope: full diff 93c3da7ea..HEAD against plan v9. Worked the three
mandated traces end-to-end against the source (not the plan prose).

## Worked trace 1 — rekey race vs inbound msg2 at the 120s boundary

t=120s: egress encap on initiator-role session arms the rekey edge
(engine.rs T1 arm, after the confirmed gate, before counter consume).
Timer arm (≤1s later): `drive_attempt_machine` consumes the edge →
`start_attempt(RekeyEdge)` → clears t7 arm, records
`baseline_session=Some(idx_A)`, sends msg1. Race A (our msg2 returns
first): socket burst → `consume_response` Ok → engine stamps
`last_recv_any` + clears t7 (handshake_session.rs completion site),
installs initiator session idx_B; loop drains both edges inline
(InboundOutcome::CompletedInitiator) and sends ONE passive keepalive →
peer's responder session confirms. Next pass: `current=Some(idx_B) !=
baseline` ∧ `is_some` → attempt cleared, nothing else mutated. Race B
(peer's own msg1 lands mid-attempt): `consume_initiation` installs
responder idx_C (unconfirmed); same-iteration TUN egress hits the
unconfirmed gate → NoSession → `request_handshake` edge AFTER the
completion-site drain → preserved; next pass ends the attempt on
identity change; if egress continues, the NoSession edge starts a
gated attempt only while unconfirmed — and the peer's data confirms
idx_C within ~1 RTT, after which `peer_has_confirmed_session` blocks
it. No erasure, no loop. PASS.

## Worked trace 2 — REJECT_AFTER_TIME mid-burst

Continuous egress, session crosses 180s between packets i and i+1 of a
64-packet burst: packet i+1.. each take the T3 gate
(`encap_drops_expired`+1 per packet, `rekey_request` store — idempotent
relaxed store, NOT an unbounded queue), `Err(NoSession)` per the caller
contract; the on-Err invariant holds per packet (gate sits before
`next_tx_counter` and the header write; verified the whole body).
Control loop: same iteration's timer arm consumes the edge once →
ungated attempt → msg1 → msg2 → fresh session; next burst resumes.
Worker transit encap (frame/wg.rs): identical engine path; its
NoSession arm additionally calls `request_handshake` (rate-limited
1/s) — harmless duplication with the rekey edge. Expiry pass tears the
carcass out of demux ≤1s later under `reconcile_lock`. Drop window ≈
edge-consume latency ≤ tick + cap ≈ 1.1s worst case, matching the plan.
PASS.

## Worked trace 3 — poll timeout vs stop signal

`stop` set while blocked in `wg_poll_wait`: poll returns ≤100ms
(timeout clamp — `poll_timeout_ms` caps at WG_POLL_CAP_MS regardless of
deadline), falls through to loop top, `stop.load` exits, run fn
returns, `wg_control_loop` logs and exits, join completes. The timer
arm cannot extend this: `expire_sessions` takes `reconcile_lock`, whose
other holders (`install_session`/`reconcile_peers`/`abort_pending`) are
all sub-millisecond slow-path critical sections in the SAME process —
no cross-thread shutdown inversion (the coordinator joins WITHOUT
holding any engine lock; verified `stop_remove_wg_control_entries`).
Bulk stop: flags first, joins after — N entries bounded ≈ one cap.
PASS (and pinned by the stop-join <500ms test).

## Findings

**F1 (BLOCKER, = Codex code-r1 #1, independently confirmed):**
`drive_attempt_machine`'s give-up arm fell through to trigger
evaluation with the pre-cleanup `actions`; a captured DeadPeer trigger
resurrects a fresh window in the same pass, defeating the boundary.
FIXED: give-up now returns `WG_NO_DEADLINE_NS` immediately; next-tick
actions are recomputed post-cleanup (T8-due still starts its fresh
window then — AGY F4 preserved). Regression test
`attempt_give_up_ignores_same_pass_stale_actions`.

**F2 (checked, no finding) — keepalive priority overwrite.** When T6
and T8 are simultaneously due, `timer_pass` returns only `Persistent`;
the single keepalive satisfies both semantics (any authenticated send
clears the T6 arm at `encap_inner`), and the counters attribute it to
persistent — acceptable, documented in timers.rs.

**F3 (checked, no finding) — `encap_buf` sharing.** The post-msg2
keepalive (socket burst) and attempt initiations (timer arm) reuse
`encap_buf` strictly sequentially within one thread; each send
completes (`wg_send_to`) before the buffer is reused.

**F4 (checked, no finding) — `now.max(1)` CAS sentinels.** 0 is the
unarmed sentinel; a (test-only) now of 0 must not store an "armed at
never" value. Wrap is impossible (CLOCK_MONOTONIC ns < 2^63 for ~292y).

**F5 (MINOR, fixed) — Prometheus help text** omitted the new `expired`
reason values (Codex #2). **F6 (NIT, fixed)** — trailing whitespace in
four verbatim research-review docs (Codex #3).

## Verdict

**MERGE-READY** (with F1/F5/F6 fixed in the follow-up commit) — the
implementation matches plan v9's section of record; all three mandated
traces terminate correctly; the single real defect found by the round
is fixed with a pinned regression test.
