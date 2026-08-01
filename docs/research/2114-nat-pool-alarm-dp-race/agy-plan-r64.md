# AGY adversarial plan-review — round 64 (plan v64 @ 6488af4ac)

Direct agy print-mode invocation from the trusted workspace with --add-dir at a 12m timeout (see reviewer-ids.md infra notes). Verdict: PLAN-READY (5/5 folds FOLDED; 2 fresh attacks FAILED; no new findings). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. FOLDED — pkg/daemon/daemon_run_shutdown.go:50-58, pkg/daemon/daemon_run_naming.go:230-235, test/incus/xpfd.service:11: Gate is daemon-scope state on Daemon (surviving d.dp=nil); callback holds applySem through body, so existing 5s apply drain covers in-flight callbacks with no new sequential wait added.
2. FOLDED — pkg/dataplane/userspace/manager.go:421-433,478-482, pkg/daemon/daemon_apply_interfaces.go:57-77,98-109: Reusable Teardown resets xskBoundNotified and clears OnXSKBound, and callback carries manager lifecycle generation to abandon on mismatch.
3. FOLDED — manager_worker_arm_5134.go:42-54, docs/research/2114-nat-pool-alarm-dp-race/plan.md:6895-6901,8756-8762: Every retirement path (completion, terminal failure, neutral/cancellation exits) purges reverse aliases, and §9 carries (h2n) ARM-ID-REUSE leg.
4. FOLDED — docs/research/2114-nat-pool-alarm-dp-race/plan.md:5595,5666,6916,8536,8594: All predicate-construction sites, post-reactivation summaries, and rendering inventory entries carry the "no QUEUED reservation outstanding" term.
5. FOLDED — docs/research/2114-nat-pool-alarm-dp-race/plan.md:2913,7196-7198: Wording rewritten to "teardown waits up to the five-second bound and may overlap ONE already-entered mutation".

(B) Fresh attacks:
- Callback holding applySem through body vs work-item-G stopping fence: FAILED — drain publishes stopping=true before acquiring applySem; if callback acquired applySem before stopping was published, drain waits for callback to finish under applySem with zero teardown overlap; subsequent callback fence checks read stopping=true and abandon.
- Manager-epoch reset re-registration: FAILED — epoch B's applyConfigLocked executes applyInterfaces, which observes XSKBoundNotified()==false (reset by Teardown), recalculating deferredOverlays and re-registering epoch B's callback via SetOnXSKBound.

(C) New findings:
None.

(D) Structure confirmation:
Confirmed — §4.7 delivery structure stands (A1 core + complete site conversion + canaries + sampler narrowing in PR-1; G+H+H2 in follow-up unit; r28 (A) dissent recorded).

(E) Verdict line:
PLAN-READY
