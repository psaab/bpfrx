# Codex hostile plan-review — round 62 (plan v62 @ fbe9369a8)

Task: task-msafqf0u-36x842 (session 019fbd9c-ee1f-7172-8563-91c01d83a9f9).
Verdict: NEEDS-REVISION (3 MAJOR, 2 MINOR; fold verification 2 FOLDED / 3 PARTIAL / 1 NOT-FOLDED). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:

1. PARTIAL — The four actuated terms agree at plan.md:5527-5533 and plan.md:8369-8378, but the formal copy drops the runbook’s separate “election SETTLED with EXACTLY ONE primary” term at plan.md:5506-5509. Existing per-node surfaces are `show chassis cluster data-plane statistics` for `rgN active=` (cmd/cli/show.go:462-477; pkg/dataplane/userspace/format/status_sections.go:329-335) and `show security vrrp` for runtime mastership (cmd/cli/show_security.go:601-625; pkg/grpcapi/server_nat.go:341-367); no new renderer is required.

2. PARTIAL — The gate under the debt-ledger lock plus the single `m.mu → ledger` decision/reservation/launch section closes Add-versus-Wait: the same ledger mutex supplies the happens-before edge, so shutdown either closes first or observes the reservation (plan.md:6737-6746,6997-7002). The disposition remains false, however: after five seconds an already-entered non-contextual netlink call cannot reach another fence before teardown proceeds (plan.md:7002-7009; pkg/daemon/daemon_ha_fabric.go:23-93,102-148; pkg/daemon/daemon_run_shutdown.go:214-230), and §9 lacks timeout-inside-mutation coverage (plan.md:8498-8507).

3. NOT-FOLDED — QUEUED-empty and token inheritance exist only in revision history at plan.md:2789-2794. Live normative text still declares separate non-aliasing identities and uses undefined “lower-identity” ordering (plan.md:6641-6662), while the runbook, normative predicate, renderer inventory, and formal acceptance mention only pending arms (plan.md:5491-5494,6779-6785,6921-6927,8343-8347). Therefore no executable queued-empty term or total cross-namespace order was added.

4. PARTIAL — Ledger serialization prevents aliases from being created mid-supersession, and rebasing every extant alias gives one-step A→C resolution (plan.md:6723-6748,6753-6767). Nothing defines alias deletion when its target registration retires, bounds cleanup, or tests A→B→C collapse plus retirement (plan.md:8508-8517,8548-8553; pkg/dataplane/userspace/manager_worker_arm_5134.go:38-96).

5. FOLDED — The plan now permits only `m.mu → ledger`, forbids the reverse, excludes ledger holds across IPC, and makes readiness decision, flag, registration, and launch one section (plan.md:6723-6748). Existing relevant paths already operate under `m.mu` (pkg/dataplane/userspace/process_status.go:160-173; maps_sync.go:353,451-456; manager_ha.go:106-112,139-150); the ledger is new, so no existing reverse acquisition remains, and the decision-to-launch gap is closed.

6. PARTIAL — LinkDel is now explicitly inventoried and aggregated (plan.md:6941-6944,7016-7030), and pendingHAStateClear receives registration/supersession/alias/serialization acceptance legs (plan.md:8548-8553). The live §5.1 inventory still says “up to a 120s round trip” at plan.md:6953-6955, contradicting plan.md:6728-6732 and the actual 3s small-request/~67s maximum-request calculation at pkg/dataplane/userspace/process_control.go:31-56,85-103,129-142.

New findings:

MAJOR 1 — v62 regressed formal acceptance by replacing rather than augmenting the settled-election requirement. The normative runbook requires both election settlement and actuated authority (plan.md:5506-5533), whereas formal acceptance contains only actuated authority (plan.md:8369-8379). Election state is published before daemon side effects run (pkg/cluster/election.go:337-395), so a singleton rg_active/VRRP snapshot can coexist with unsettled or dual-primary control state whose later processing changes actuation. Formal acceptance can therefore declare completion before authority is stable.

MAJOR 2 — The admission gate has no concrete shutdown owner or API. The inventory mentions startup/stopping publication and the userspace ledger but no close-admission/join call (plan.md:6805-6808,6945-6955). Today the only generic dataplane lifecycle hooks are Close and Teardown (pkg/dataplane/apply.go:18-23); process shutdown chooses either at pkg/daemon/daemon_run_shutdown.go:214-230, while bootstrap calls reusable Teardown and retains the object for re-arm (pkg/daemon/bootstrap.go:470-475). A monotonic gate cannot simply be buried in both hooks: the plan must specify a shutdown-only close/join API before subsystem teardown, or explicit reopen semantics.

MAJOR 3 — Missing alias retirement is a correctness failure, not merely unbounded memory. Arm IDs are reusable and duplicate completions must be ignored (plan.md:6561-6585,6603-6607), yet surviving aliases are blindly rebased at every supersession (plan.md:6753-6767). If A/X→B/X survives after B/X retires, a later C/X registration can rebase it to C/X; a delayed duplicate A/X completion then retires the new live arm and false-greens convergence. All reverse aliases targeting a registration must be removed atomically on completion or terminal retirement, with an arm-ID-reuse/stale-duplicate regression.

MINOR 1 — §9 still does not inject a LinkDel error. Normative text requires every mismatched-link deletion error to fail the arm (plan.md:7016-7030), but acceptance tests only “the type+mode mismatch” generically (plan.md:8498-8507). An implementation could preserve today’s discarded LinkDel error at pkg/daemon/daemon_ha_fabric.go:52-53 and still satisfy that test.

MINOR 2 — The runbook says only “each node’s own status surface” (plan.md:5530-5532,8373-8374), while its nearby named `show chassis cluster status` command exposes election state only (plan.md:5270-5272; pkg/cluster/status.go:10-25,91-104). The existing actuated commands identified above should be named explicitly; this needs no rendering change.

Structure confirmation: §4.7’s PR-1 core plus G+H+H2 follow-up split stands (plan.md:6403-6438), and §9’s JOIN-COHERENCE reservation, retirement, publication-order, reader-wins, and stop-wins legs remain coherent (plan.md:8410-8459).

NEEDS-REVISION

Codex session ID: 019fbd9c-ee1f-7172-8563-91c01d83a9f9
Resume in Codex: codex resume 019fbd9c-ee1f-7172-8563-91c01d83a9f9
