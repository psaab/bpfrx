# Claude SMR — hostile plan review r10 (#5275)

Reviewing `plan.md` @ r11. Codex r9 confirmed EVERYTHING except one precise,
contract-critical defect and specified the exact fix. r11 applies it.

## Codex r9's confirmed-sound set (unchanged in r11)
- D1–D4: accepted (r7/r8).
- D5(b) live path: SOUND — "publishing zero only after verified address removal and
  Kea shutdown prevents dual VIP/DHCP" (Codex r9), provided `fencing` is sticky.
- §5 facade-OPEN ordering fix: correct (Codex r9).
- STONITH-vs-accept tradeoff: legitimate operations decision (Codex r9).

## The one Codex r9 defect and r11's fix
Codex r9's counterexample: a LONG valid heartbeat timeout; the crashed primary restarts
BEFORE the peer times out; TODAY it re-elects as sole owner (no dual ownership); under
r10 the arm-failed restart published weight-zero WHILE its VIP/Kea still existed, and
the peer promotes immediately on weight-zero (heartbeat_manager.go:293 → election.go:138)
→ dual VIP/DHCP — an overlap #5275 CREATES by accelerating takeover. Confirmed the
mechanism firsthand (a received weight-zero heartbeat runs election immediately; peer
weight 0 promotes the receiver).

r11 applies Codex's exact correction and UNIFIES the gate across both paths:
- The FIRST weight-zero yield — crash-restart AND live re-arm — is gated on the
  synchronous, verified removal of VIP + stable link-local + Kea stop. §13-D5(c).
- If the synchronous scrub FAILS, the node stays sender-silent (no weight-zero) and
  falls back to the pre-existing peer-timeout window — so #5275 NEVER accelerates
  takeover into an un-scrubbed state. §3, §13-D5(a), §13-D5(c) made consistent.
- Only FRR route de-dup remains async (availability/ECMP behind the barrier, which
  Codex r9 explicitly agreed is "not the same ownership-safety defect").
- The residual (a truly-dead node that never restarts + the peer's ordinary timeout) is
  the SAME window ANY xpfd crash has today → the accept-vs-STONITH human sign-off, which
  Codex r9 called a valid operational decision.

This directly matches Codex r9's prescription: "gate the restarted process's first
weight-zero publication on verified VIP/stable-link-local removal and Kea stop, or
remain sender-silent until the peer has already promoted... If restart scrubbing fails,
#5275 must not accelerate takeover. This preserves the accepted existing crash hazard...
Sections 3/12 and D5(c) must also be made consistent." r11 does exactly this.

## Assessment
With the yield gate unified (never yield before a verified VIP+link-local+Kea scrub;
scrub-failure ⇒ sender-silent ⇒ no accelerated takeover), the sole Codex-r9 defect is
closed, and everything else was already Codex-accepted. #5275 is now provably "no worse
than the existing xpfd-crash window" (the only residual being the pre-existing
dead-node timeout window, a flagged human tradeoff). Every reviewer finding across nine
rounds is folded with a mechanism + a source coordinate.

## Verdict
r11 applies Codex r9's exact prescribed fix and unifies §3/§12/D5. D1–D4, D5(b), and the
facade fix are Codex-accepted; the crash-restart yield-before-scrub hole is closed. This
is a complete, viable, source-consistent design contract with the single irreducible
operations tradeoff (accept-existing-crash-window vs STONITH) flagged for human sign-off
— the `/research` deliverable.

VERDICT: PLAN-READY
