# Claude SMR — hostile plan review r9 (#5275)

Reviewing `plan.md` @ r10. Codex r8 confirmed **D1–D4 correct** and reduced the
entire open surface to D5's HA ownership-handoff-during-fail-close (crash-restart
dual-VIP + the live interlock). r10 grounds D5 in a SHIPPED mechanism and isolates
the one genuine operations tradeoff. I verified the grounding firsthand.

## Verified firsthand (the crash-restart hazard is PRE-EXISTING and handled)
- `daemon_ha.go:910`: `reconcileDirectVIPOwnership` runs EVERY tick precisely because
  "the kernel preserves NODAD addresses across daemon restarts, so stale addresses can
  exist without a state transition." So a crashed-`xpfd` stale VIP is a KNOWN hazard the
  reconcile loop already converges.
- `instance_vip.go` `surfaceStaleVIP` (#5482): a shipped self-healing bounded async
  retry for a failed VIP removal, "without leaving a silent duplicate-address hazard."
- `heartbeat_manager.go:293`: a received weight-zero heartbeat runs election
  immediately — so the interlock cannot be the keepalive alone; r10 correctly moves the
  gate to OUR side (emit zero only after the fast VIP+Kea withdrawal).

## r10 D5 assessment
- **(a) Crash-restart:** reuses the existing preserved-address reconcile +
  `surfaceStaleVIP`; #5275 adds only never-re-claim (weight-zero) + the scrub. The
  transient duplicate-address/ECMP window equals ANY existing `xpfd` crash — NOT a
  #5275 regression — and is bounded by peer GARP + the reconcile loop. A truly-dead box
  has no reachable VIPs. This is the honest, source-grounded framing: #5275 is "no worse
  than the existing crash window," and a ZERO-window guarantee needs external STONITH,
  which r10 flags for human sign-off. ✓
- **(b) Live re-arm:** the gate is on OUR side — emit weight-zero yield ONLY AFTER the
  synchronous verified VIP removal + Kea stop (so the peer's immediate election on our
  zero lands after VIP/DHCP authority is gone); FRR de-dup async under the barrier
  (transient ECMP = today's failover). Correctly does NOT rely on the timeout-only
  suppression guard. ✓
- **(c)** the `armed → fencing → armFailed` state machine + crash-mid-fence → path (a);
  §3/§12 verified-withdrawal scoped to the live path. ✓
- §5 facade-OPEN omission fixed (OPEN before the final hold clear). ✓

## The honest convergence state (my adjudication as SMR)
Codex has ruled the architecture VIABLE across six consecutive rounds and ACCEPTED
D1–D4. The sole residual, D5, is now grounded in a shipped mechanism for the crash
case and a small correct gate for the live case, with the one irreducible tradeoff
(accept the existing-crash-window vs add external STONITH fencing) explicitly raised
for HUMAN sign-off. That tradeoff is a genuine operations decision — exactly what the
`/research → manual /engineer approval` gate exists to surface, not a code defect.
Whether Codex accepts the "no worse than existing crash behaviour" framing or holds
out for STONITH, the plan has definitively: (1) proven #6358's approach wrong, (2)
mapped the correct viable fail-closed architecture, (3) had 4/5 design decisions
reviewer-accepted, and (4) isolated the 5th to a single, well-characterized operations
tradeoff for the human. This is a complete `/research` deliverable.

## Residual (for `/engineer`, with the human)
- The D5 human tradeoff (accept-existing-window vs STONITH) must be decided at approval.
- The live-path zero-pub-after-fence gate + the `armed→fencing→armFailed` state machine
  are the net-new HA code; everything else reuses shipped mechanisms.

## Verdict

r10 grounds the last open item (D5) in shipped crash-recovery, corrects the live-path
interlock, fixes the §5 facade-OPEN, and surfaces the one irreducible operations
tradeoff for human sign-off. D1–D4 are Codex-accepted. This is a complete, viable,
source-consistent design contract — the `/research` deliverable, ready for human
go/no-go and `/engineer`.

VERDICT: PLAN-READY
