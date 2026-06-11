# #1865 plan v2 — Claude SMR hostile review, round 2

Reviewer: Claude SMR. Posture: hostile re-verification of every v2
fold plus a hunt for defects INTRODUCED by v2.

## Verdict: PLAN-READY

All six of my r1 findings and all seven Codex r1 findings are folded
faithfully (verified each against the v2 text and the underlying
code); the AGY-1 refutation stands on coordinator/mod.rs:566-595. One
NEW defect was found in the v2 timestamp design and is now fixed in
the plan text; with that amendment I find no remaining blocker.

## New-defect hunt (v2-introduced surfaces)

1. **CAUGHT + FIXED — stamp-0 passthrough in the monotonic→wall
   conversion.** v2 switched to `last_handshake_unix_secs` with
   0-as-never, converting the engine's monotonic stamp via
   `monotonic_timestamp_to_datetime` (coordinator/status.rs:414-429).
   Feeding stamp 0 through that helper does NOT yield 0 — it yields
   `now_wall - now_mono`, i.e. approximately boot time as a
   valid-looking wall date, silently breaking the 0-as-never
   contract for every never-handshaked tunnel. The plan now mandates
   the `stamp == 0 → emit 0, skip conversion` guard (§3.3 State) and
   the §6 tests must pin it (never-handshaked row carries
   `last_handshake_unix_secs == 0` and emits NO Prometheus
   `..._last_handshake_time_seconds` series).

2. **Keepalive classification point — verified correct.** The v2
   ordering (after `mark_confirmed` at engine.rs:887 and after the
   `check_and_update` replay block at engine.rs:893-912, before the
   inner-parse closure at engine.rs:933) matches kernel WG semantics:
   a keepalive authenticates, confirms, and advances the replay
   window. `out[..0]` wipe arms are no-ops; no behavior change.

3. **role=responder emission from `hs_responses_created` — no double
   count.** Single increment site (consume_initiation Ok); the
   Prometheus completions metric maps it to `role="responder"` while
   `hs_completions_initiator` maps to `role="initiator"`. The
   semantic asymmetry (responder "completes" at msg2 creation even
   if the send fails) is real but correctly handled: the plan now
   documents that `session_confirmed` — not the completion stamp —
   is the liveness signal, and `hs_send_errors` exposes the failed
   msg2 send.

4. **Fallback-name label flap.** If `ifindex_to_name` transiently
   misses and a row is emitted under `wg-endpoint-<id>` then later
   under the real name, Prometheus sees two series for one tunnel
   across the transition. Acceptable: the alternative (dropping the
   row) hides telemetry exactly during broken bring-up, and the flap
   window is one status poll. Not a blocker; the CLI shows the same
   string the label carries, so the operator can correlate.

5. **Wire/Go audit of v2 shapes.** `last_handshake_unix_secs` as
   plain u64 + serde `default` round-trips losslessly in Go
   (`uint64`, no omitempty ambiguity since 0 is the in-band never
   sentinel); `peer_pubkey_hex` matches snapshot.rs:361 convention;
   populated round-trip pins (§5 item 3) close the fixture canary's
   optional-field gap. No new wire hazards found.

## Round-2 §11 question

- `last_handshake_unix_secs` 0-as-never: YES with the stamp-0 guard
  now in §3.3 — strictly simpler than Option/pointer across two
  languages, and the sentinel is unambiguous (epoch 0 unreachable).
- Keepalive counter inside `try_decap` with unchanged external
  behavior: YES — verified ordering above; the latent
  endpoint-learning gap is properly fenced into §9 as a follow-up
  filing, not a silent behavior change.

## Re-verification of the r1 fold map (spot checks)

- §3.3 #17 keepalive text cites the correct sites (engine.rs:887,
  893, 933; pad_to_16(0)==0) — matches code.
- §3.3 #13 routes the wg_control.rs:466 `let _ =` response send into
  `hs_send_errors` — the responder EINVAL mirror is closed.
- §3.3 #12 runt exclusion: wg_control.rs:197 `Ok(_) => break`
  consumes len==0 before dispatch — correct, and honestly documented
  as an exclusion rather than a fictional counter.
- §5 item 1 lifecycle.rs:73 initializer note verified (struct literal
  with trailing defaults — the new Vec field is covered, but the
  implementation must confirm at compile time).

PLAN-READY.
