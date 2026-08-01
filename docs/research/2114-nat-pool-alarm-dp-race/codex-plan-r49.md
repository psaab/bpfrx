# Codex hostile plan-review — round 49 (plan v49 @ 6a6401af0)

Task: task-msa1rryg-ve7lj1 (session 019fbc37-11c6-7ba3-b36a-8ca4c089effe).
Verdict: NEEDS-REVISION (3 MAJOR, 2 MINOR; fold verification 2 FOLDED / 4 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:

1. FOLDED — All normative sites advance the node-lifetime epoch with the provisional pre-enqueue reservation, never roll it back, and let nil/full attempts move only the epoch (plan.md:4267-4287,4391-4397,5620-5626,6754-6767); JOIN leg (h) tests permanent nil/full advancement (plan.md:6973-6984). “Successful reservation” survives only in superseded history.

2. PARTIAL — The live runbook now states process lifetime, pre-boot initialization, central full-apply instrumentation, and `failure-count == 0 && last-outcome-success` (plan.md:4615-4629). However, the claimed daemon inventory omits the state and hook (plan.md:5509-5514,5637-5646), and §9 contains narrative rather than the claimed sticky same-text regression (plan.md:6883-6899).

3. PARTIAL — Successful deactivation does empty the engine: inactive configuration is pruned (pkg/config/compiler.go:2257-2268), tail step 17 reconciles it (pkg/daemon/daemon_apply_tail.go:194-202,463-478), and `Engine.Apply` replaces the policy/runtime sets (pkg/eventengine/engine.go:405-427). Both copies require two-node deactivation and contain reactivation (plan.md:4105-4139,4635-4644,6691-6711,6906-6913), but restoration is neither per-node nor fully verified, and pre-quiesce recapture remains incomplete.

4. PARTIAL — Intended-holder-first appears in both copies and `Load` precedes cluster communications (plan.md:4526-4539,6824-6831; pkg/daemon/daemon_run.go:157-177,393-398). It conflicts with the standing local-first rule and does not prevent later priority-based preemption.

5. FOLDED — Both copies start residual (iii) at the peer preflight’s FIRST sub-read (plan.md:4422-4437,6795-6807), correctly covering promotion and fallible persistence between the split reads (pkg/configstore/store.go:687-746).

6. PARTIAL — The live runbook bounds retries and declares stopped remediation unavailable after the second failed re-baseline (plan.md:4297-4309), matching continuous unkeyed ingress behavior (pkg/cluster/sync_admission.go:58-83; pkg/cluster/sync_auth.go:321-334). Formal acceptance omits that retry/termination branch (plan.md:6754-6772).

New findings:

MAJOR 1 — The apply-health state machine remains underspecified and can report false green in flight. The plan claims §5.1 and §9 artifacts that are absent (plan.md:4623-4632,5509-5514,5637-5646,6883-6899). More seriously, after boot success a DHCP/feed reapply can enter while `ActiveApplied()` remains true (pkg/daemon/daemon_dhcp.go:73-90; pkg/daemon/daemon_feeds.go:26-42; pkg/configstore/store.go:797-809); until `applyConfigLocked` returns failure, the count is still zero and a conventional last-outcome flag still says success (pkg/daemon/daemon_apply.go:141-355). Pin `success=false` at common-callee entry and true only after nil return, or expose and require apply-in-flight zero; inventory that hook and add both sticky-failure and parked-mid-apply regressions.

MAJOR 2 — Reactivation does not restore the two-node invariant it temporarily removed. Deactivation explicitly requires successful application on both nodes (plan.md:4105-4126,6692-6706), but both endings prescribe one singular commit followed only by a digest check (plan.md:4635-4644,6906-6913). With `ConfigSync=false`, the commit cannot update the peer (pkg/daemon/daemon_ha_sync.go:336-364). Independently, the Store is already promoted before apply (pkg/daemon/daemon_apply_commit.go:225-246), so a reactivation apply can abort before event-engine reconciliation (pkg/daemon/daemon_apply_tail.go:194-202), leaving the digest restored while automation remains empty. Reactivation must succeed independently on both nodes and be followed by the complete health/apply predicate, not merely digest equality.

MAJOR 3 — The encrypted-fallback restart choreography is contradictory and does not hold authority. The standing rule requires local-first (plan.md:4410-4414), the exception requires intended-holder-first (plan.md:4526-4538), and subsequent text still assumes “local-then-peer” (plan.md:4551-4553). Starting first only grants temporary incumbency: a higher-effective-priority peer can preempt after joining (pkg/cluster/election.go:172-193), while config reconciliation is authority-gated and delayed by the stability threshold (pkg/daemon/daemon_ha_sync.go:447-465). The plan needs an explicit precedence rule and an authority hold/manual-failover or priority condition lasting until the older peer has received and durably applied the intended configuration.

MINOR 1 — The termination fold was added only to the live runbook. Formal acceptance requires an unchanged epoch and then proceeds toward stopping (plan.md:6754-6772), but never specifies re-baselining, the second-attempt limit, ingress fencing, or the live-removal fallback stated at plan.md:4297-4309.

MINOR 2 — “Any commit forces re-capture” does not cover the pre-quiesce baseline unambiguously. That digest is captured separately before deactivation (plan.md:4135-4139), while the recapture clause is attached to the later fence-time capture (plan.md:4140-4152); final verification consumes the earlier value (plan.md:4640-4644). The formal copy only mentions the pre-quiesce digest retrospectively (plan.md:6691-6716,6906-6913). An unrelated intervening commit therefore causes a terminal false mismatch with no prescribed restart/re-capture of both baselines.

Structure confirmation: §4.7 stands—PR-1 remains A1/core and the follow-up keeps G+H+H2 together (plan.md:5460-5495), with matching §9 partitioning (plan.md:6177-6182); origin/master…HEAD contains research documentation only.

NEEDS-REVISION

Codex session ID: 019fbc37-11c6-7ba3-b36a-8ca4c089effe
Resume in Codex: codex resume 019fbc37-11c6-7ba3-b36a-8ca4c089effe
