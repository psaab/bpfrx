# Claude SMR — hostile plan review r3 (#5275)

Reviewing `plan.md` @ r4 (re-architected after Codex r1+r2 PLAN-NEEDS-MAJOR).
Posture: adversarial. r4 replaces the "gate every publisher + advertise an
arm-failed HA signal" model (which Codex shredded across two rounds) with the
#1960 "do not start the takeover machinery" model.

## Why r4 is the right architecture (verified firsthand)

The pivotal claim — every ownership publisher and dataplane consumer is started in
one goroutine section AFTER the boot phase `dataplane-setup` — is TRUE
(daemon_run.go: `startClusterComms`:384, `runUserspaceEventStream`:356, relay
`SetMasterGate`:463, `proxyARPReassertLoop`:532, DDNS loops:545+, `watchVRRPEvents`
:565, reconcile loop:569). And the "silent node" claim is airtight:
`startClusterComms` (daemon_ha_sync.go:692) is the SOLE heartbeat starter
(`startHeartbeatWithRetry → StartHeartbeat`, :771/:1318) — gating it off ⇒ no
heartbeat ⇒ the peer's normal masterDownTimer/peer-loss election owns all RGs.

This dissolves, by construction, the bulk of the round-1/2 MAJOR findings:
- **Codex §2 (HA peer-yield / StateSecondaryHold auto-confirm / effective-ownership
  view / mixed-version wire signal / handoff ACK):** gone — a failed node is
  silent, the peer takes over via the EXISTING election. No new HA mechanism.
- **Codex §3 (publisher completeness / TOCTOU / façade / epoch / circular
  canary):** gone — the publishers never start.
- **Codex §4 (dataplane-lifetime ref-guard / consumer race on `d.dp=nil`):**
  largely gone — the consumers (GC, session sync, event stream, watchdog) never
  start, so nothing captures `d.dp`. Real `Teardown()` of the partial attach is
  still required and r4 hardens it (aggregate errors + readback + retain-on-fail,
  Codex D18).

r4 also fixes the specific corrections: per-generation coverage instead of the
historical `everArmed` boolean (Codex D3), the UNCONDITIONAL FORWARD drop
(management is INPUT not FORWARD — the r3 exemption was a routed bypass, Codex D1),
the barrier not covering relay (D2, relay handled by not-starting it), and the
`armPending → coverage → forwarding → armed` ordering (D4). The day-2
binding-expansion partial-attach (D3) and config-sync completeness (D9) are
correctly SCOPED as a bounded fold (option a) or a follow-up (option b), not
folded into a giant re-architecture.

## Residual concerns (MINOR — flag for `/engineer`, not PLAN-READY blockers)

- **N1 — ip-monitoring actuator starts EARLIER than the gated section.**
  `d.ipmon.Start()` is in `setupDataplaneAndInitialConfig` (bringup:161 region),
  before the after-`dataplane-setup` startup section, and its
  `actuateRouteOverlayLocked` reads `d.store.ActiveConfig()` + re-renders FRR
  (only an `isResetting` gate today). So it is the ONE publisher not covered by
  "don't start the section". Add an `armedOK`/`dataplaneArmFailed` check to the
  actuator (trivial — it already has the `isResetting` early-return). Called out in
  r4 §5 implicitly (consumer list) but should be explicit at impl.
- **N2 — `RestartHeartbeat` (daemon_apply_dataplane.go:436).** A live-apply RETH-MAC
  path can restart the heartbeat. It runs only inside an apply we ABORT on the boot
  first-arm (so it does not fire), and only on an already-running (day-2) node
  otherwise. Confirm the abort short-circuits before it; not a hole, but name it in
  the test matrix.
- **N3 — cold-boot ~1 s no-owner window.** When both nodes boot together and one's
  arm fails, the healthy node waits one heartbeat-timeout before claiming primary
  (election.go:119 non-preempt fresh-boot guard). That ~1 s is the EXISTING
  cold-boot behaviour, not a #5275 regression — but state it so a reviewer does not
  read it as a new gap.
- **N4 — day-2 option (a) vs (b) is a genuine user decision.** Folding the
  interface-down for a binding-expansion partial attach (a) closes the narrow
  residual within #5275; deferring (b) keeps #5275 to the boot case. Recommend (a)
  as small and complete, but the user should choose at `/engineer`.
- **N5 — quarantine vs reactive `enableForwarding`.** Moving the bringup:214 enable
  to after arm-proof (quarantine) is cleaner than disable-on-failure; either is
  acceptable, quarantine recommended. A `/engineer` decision.

## Verdict

r4 is a genuine architectural simplification that is MORE correct than r1–r3: it
reuses the reviewed #1960 fail-closed posture, makes the HA story "silent node →
existing peer election" (eliminating the entire class of both-secondary/dual-VIP/
handoff/wire-signal problems), and scopes the day-2 residual honestly. The
remaining items are implementation-completeness notes, not architecture gaps. The
design space and the two real decisions (day-2 fold vs defer; quarantine vs
reactive) are surfaced for the human — the `/research` deliverable.

VERDICT: PLAN-READY
