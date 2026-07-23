# Claude SMR — hostile plan review r4 (#5275)

Reviewing `plan.md` @ r5. Posture: adversarial. r5 abandons the "no-start
premise" of r4 (which Codex r3 correctly falsified — election + `watchClusterEvents`
+ `enableForwarding` + VRRP run in `initManagers` BEFORE the arm) and instead
GENERALIZES the shipped #1930 pre-election dataplane-arm hold.

## Verified firsthand (the pivot is real)

- `initManagers` (daemon_run_bringup.go:47) runs `holdSecondaryIfKernelCandidateArmed()`
  at :179 **before** `UpdateConfig`(=election) at :181, exactly to stop an
  unverified-dataplane node from advertising primary and preempting the healthy
  peer. `watchClusterEvents` :203, `enableForwarding` :215, `vrrpMgr.Start` :223 all
  in `initManagers`, before `setupDataplaneAndInitialConfig` (:414, the arm). So the
  #1930 hold is the exact, shipped precedent #5275 needs, and Codex r3 §1/§2 (pre-arm
  ownership publication → dual-owner) is correct. r5's generalization is sound.

## Why r5 answers the Codex r3 findings

- §1/§2 (pre-arm ownership / dual-owner): the generalized hold precedes election →
  the node never becomes Primary → no direct-VIP/RA/Kea/VRRP-master published; the
  peer owns via the #1930 non-preempt property. The higher-priority-held-node
  both-secondary case is honestly called out as the one new wire behaviour (yield
  posture), layered on the shipped hold. ✓
- §3 (flag insufficient / bootstrap-exit half-start): replaced by an idempotent
  `startTakeoverMachinery()` called from both arm-proof sites. ✓
- §4 (coverage / pin-deletion / quarantine reactive): per-generation coverage with
  post-attach program-identity kernel readback (not the global probe), and a
  MANDATORY verified FORWARD barrier installed before the compile's pin-deletion /
  interface bring-up, released only on proof. ✓
- §5 (teardown retention / apply-admission): quarantined `d.dpCleanup` field
  (operational `d.dp=nil`), per-handle teardown retention, and a single
  apply-admission gate so a day-2 commit while held publishes nothing. ✓
- §6 (day-2 scoping): folded with a PRE-mutation quarantine of B (not reactive
  bring-down), keeping A continuously protected. committed-empty→first and
  remove-all→add are handled in-scope by per-generation re-proof; config-less-HA
  runtime is correctly noted as not-a-current-path. ✓

## Residual concerns (MINOR — flag for `/engineer`)

- **N1 — standalone vs cluster mechanism split.** The generalized #1930 hold is a
  CLUSTER mechanism (the hold block is under `if cfg.Chassis.Cluster != nil`,
  bringup:163). PR1 (standalone) must fail closed via the barrier + deferred
  `enableForwarding` + `startTakeoverMachinery` gate + apply-admission ALONE (no
  cluster). r5's phasing already puts the HA yield in PR2; make explicit that PR1's
  standalone fail-closed does not depend on the cluster hold.
- **N2 — normal-boot ownership timing.** Deferring election/forwarding until
  arm-proof means a normal HA boot claims ownership a few steps later than today
  (after the arm, not before). #1930 already accepts this for candidate boots; it is
  arguably MORE correct (don't own what you can't forward). Note it so a reviewer
  doesn't read it as a failover-timing regression (the ~60ms figure is runtime
  failover, unaffected).
- **N3 — barrier atomicity on release.** The barrier removal must be atomic with
  opening forwarding and verified; a crash between "coverage proven" and "barrier
  removed" stays closed (safe). State the ordering `coverage → open-forwarding+remove-barrier(verified) → clear-hold → startTakeoverMachinery`.
- **N4 — the yield posture (PR2) is the one genuinely-new HA design.** weight-0
  advertisement is the no-new-field option but needs the advertised copy protected
  from `recalcWeight`; an explicit cannot-own bit is cleaner but a wire addition.
  This is a real `/engineer`-time decision; both are specified.
- **N5 — apply-admission must not block config PERSISTENCE.** The gate withholds
  PUBLICATION (FRR/VRRP/services) but must still persist+validate the candidate so
  an operator can fix-forward and a restart re-arms against the corrected config.
  r5 says this; keep it explicit.

## Verdict

r5 stops fighting the boot structure and reuses the shipped, reviewed #1930
arm-proof hold — which is exactly the mechanism the problem calls for — plus the
barrier, quarantine, apply-admission, and per-generation coverage that Codex r3
enumerated. The architecture is now correct and precedented; the residuals are
implementation-sequencing notes. The plan is honest that this is a real multi-PR
architecture, and it surfaces the two genuine design decisions (yield mechanism;
barrier vs deferred-forwarding) for the human. This is the `/research` deliverable.

VERDICT: PLAN-READY
