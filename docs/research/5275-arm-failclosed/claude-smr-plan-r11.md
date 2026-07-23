# Claude SMR — hostile plan review r11 (#5275)

Reviewing `plan.md` @ r12. Codex r10 confirmed the crash-restart gate SOUND and
isolated one asymmetry (sender-silent-on-failure is unsafe for the LIVE re-arm path)
+ two doc-consistency nits. r12 applies Codex's exact prescription.

## Codex r10 confirmed-sound (unchanged in r12)
- D5(a) crash-restart first-zero gate: SOUND ("verified VIP/stable-link-local removal
  and Kea stop precede weight-zero, while failure remains silent instead of triggering
  immediate zero-weight election"). Plus D1–D4, D5(b), §5 facade — all prior-accepted.

## The one Codex r10 defect and r12's fix
Codex r10: silencing a still-running primary on scrub failure lets the peer time out
and activate VIP/Kea while the old owner still holds them (dual ownership) — an episode
#5275 causes by silencing a previously-healthy sender. Its fix: "scope sender-silent
failure fallback to crash restart. Live `fencing` must remain pre-hold and retain an
incumbent-heartbeat/takeover interlock until scrub succeeds; only then atomically enter
`effectiveHold`/`armFailed` and publish zero."

r12 applies exactly this — the scrub-FAILURE fallback is now PATH-SPECIFIC (§13-D5(c)):
- **Crash-restart:** scrub-fail ⇒ sender-silent ⇒ pre-existing timeout window. ✓
- **Live re-arm:** scrub-fail ⇒ KEEP the incumbent heartbeat (peer stays backup) until
  the scrub SUCCEEDS, then atomically hold+yield; while holding-but-unscrubbed it is
  fail-CLOSED (barrier drops transit — a blackhole, the security-correct default over
  dual-ownership) until scrub succeeds or a verified service/host fence (STONITH)
  resolves it; NEVER silent-while-holding. ✓
The shared invariant (never publish the first weight-zero before the synchronous
verified VIP+link-local+Kea scrub) is retained. FRR de-dup async.

## Doc-consistency fixes (Codex r10)
- §12 HA test line updated: no longer says "proved-down/service-fenced fallback before
  the peer takes over"; now states the path-specific handling (crash silent; live keeps
  incumbent until scrub). Consistent with §3/D5(c). ✓
- §3 "orderly shutdown scrubs" overbroad claim corrected: even orderly shutdown does not
  stop Kea or clear persisted FRR (daemon_run_shutdown.go), so the scrub must cover
  Kea/FRR regardless of how the prior daemon exited. ✓

## Assessment
r12 closes the last Codex-identified safety asymmetry with the reviewer's exact
prescription and resolves the two doc nits. Every prior contract (D1–D4, D5(a) crash
gate, D5(b) live gate, §5 facade, the barrier, delayed promotion, the arm-state machine)
is Codex-accepted; the live-path fail-closed-blackhole-over-dual-ownership is the
security-correct default. The one irreducible operations tradeoff (a truly-dead node's
pre-existing timeout window: accept vs STONITH) remains the flagged human sign-off.

## Verdict
r12 applies Codex r10's exact path-scoping fix and the two doc-consistency corrections;
the live-re-arm dual-ownership hole is closed by keeping the incumbent heartbeat until
scrub. This is a complete, viable, source-consistent design contract with the single
operations tradeoff flagged for human sign-off — the `/research` deliverable.

VERDICT: PLAN-READY
