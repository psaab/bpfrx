# Codex hostile plan-review — round 63 (plan v63 @ 5d9ab6ebb)

Task: task-msah5x3c-r3esl0 (session 019fbdc1-92e5-7262-98a3-b4d77f11e437).
Verdict: NEEDS-REVISION (5 MAJOR, 1 MINOR; fold verification 3 FOLDED / 3 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. FOLDED — Both copies retain election settlement and add the multi-term actuated predicate: docs/research/2114-nat-pool-alarm-dp-race/plan.md:5566-5602 and :8470-8485. The sequencing claim holds at pkg/cluster/election.go:337-395.
2. PARTIAL — Shutdown-only closure and “Teardown never closes it” are present at plan.md:7081-7095, but the supposedly “named” call has no name, receiver, signature, or reachable interface; RuntimeDataPlane still exposes only Close/Teardown at pkg/dataplane/apply.go:18-23. Reusable re-arm also remains epoch-unsafe.
3. PARTIAL — Atomic reverse-alias retirement is specified at plan.md:6838-6848, and completion-versus-terminal-retirement is safe in either ledger-lock order under :6675-6677, :6766-6769, and :6793-6795. Cancellation/neutral retirement is not explicitly connected to cleanup, and the promised reuse regression is absent from §9; :8664-8678 only covers generic alias/token cases.
4. FOLDED — The literal two-copy target is present: QUEUED-empty plus identity ordering at plan.md:5544-5553 and QUEUED-empty in formal acceptance at :8443-8448. Other copies have regressed; see MAJOR 4.
5. PARTIAL — The one-in-flight-call disposition and timeout test exist at plan.md:7095-7104 and :8605-8609, but :7104-7108 immediately contradicts them by claiming teardown waits and the callback is “never mutating live state during teardown.”
6. FOLDED — Named commands are at plan.md:5593-5600 and backed by pkg/dataplane/userspace/format/status_sections.go:329-335, pkg/grpcapi/server_show_cluster_text.go:138-147, cmd/cli/show.go:462-477, cmd/cli/show_security.go:601-625, and pkg/grpcapi/server_nat.go:341-367. LinkDel injection is at plan.md:8601-8604; the second live timing is corrected to 3s/~67s at :7034-7039, matching pkg/dataplane/userspace/process_control.go:31-56,85-103,129-142.

New findings:

MAJOR 1 — The shutdown API remains unimplementably unspecified. The text literally says “via a named close-admission/join call” without providing a name or owner at plan.md:7084-7094; the daemon, shutdown, and userspace inventories at :6522-6534, :6884-6889, and :7026-7043 add no gate field, adapter method, or narrow interface. Worse, re-arm failure clears d.dp at pkg/daemon/daemon_run_naming.go:230-235, potentially making a manager-owned gate unreachable while reserved work survives. An implementor must invent both plumbing and ownership.

MAJOR 2 — Exact bootstrap interleaving breaks epoch safety. Epoch A reserves and launches the detached callback at pkg/dataplane/userspace/maps_sync.go:451-456, then stalls before applySem; bootstrap Teardown retains the manager at pkg/daemon/bootstrap.go:470-475; Teardown/stopLocked resets neither xskBoundNotified nor OnXSKBound at pkg/dataplane/userspace/manager.go:421-433,478-482 and process.go:197-267; epoch B restarts the same object at pkg/daemon/daemon_run_naming.go:228-235. A then resumes with admission and shutdown fences open, and identical current configuration passes the fire-time check at plan.md:7044-7058. Because xskBoundNotified also survived, B may never produce its own readiness callback and can treat XSK as already bound at pkg/daemon/daemon_apply_interfaces.go:57-77. A lifecycle-generation rejection or reusable Teardown cancel/join/reset protocol is required.

MAJOR 3 — Alias retirement remains incomplete and untested. Current neutral/cancellation exits drop debt when the helper is absent or a later apply already armed it at pkg/dataplane/userspace/manager_worker_arm_5134.go:42-54, but plan.md:6845-6848 never says these exits invoke the reverse-alias purge. The promised A/X→B/X retirement, X reuse by C/X, then delayed duplicate A/X regression does not exist; §9 only lists broader alias/token tests at plan.md:8624-8639 and :8664-8678. The specified completion/terminal race is sound, but that does not cover the omitted retirement class.

MAJOR 4 — QUEUED-empty is still missing from executable design and final rechecks. Section 5.1 defines convergence as count==0/no-pending/lastOK at plan.md:6859-6866 and inventories only token/pending rendering at :7000-7008. Both post-reactivation summaries likewise enumerate no-pending without no-QUEUED at :5612-5617 and :8498-8503. Implementation or operations following these copies can still declare green while an apply reservation is queued.

MAJOR 5 — The new five-second join overruns the existing shutdown budget. Existing sequential worst-case waits are 5s apply drain at pkg/daemon/daemon_run_shutdown.go:10-15,50-58, 3s aggregator at pkg/daemon/daemon_system.go:323-336,379-384, 3s IPsec join at pkg/daemon/daemon_ipsec_rebind.go:91-107,147-153, 2s HA clear at pkg/daemon/daemon_run_shutdown.go:159-178, and 5s session-sync stop at pkg/cluster/sync_conn.go:376-384. Adding plan.md:7095-7107’s 5s join reaches at least 23s against test/incus/xpfd.service:11’s TimeoutStopSec=20, permitting SIGKILL before dataplane Close/Teardown.

MINOR — Rewrite plan.md:7104-7108 to say teardown waits up to five seconds and may overlap one already-entered mutation. Its current absolute wording contradicts the precise disposition and test immediately surrounding it.

Structure confirmation: §4.7’s PR-1 core plus inseparable G+H+H2 follow-up structure stands at plan.md:6473-6516.

NEEDS-REVISION

Codex session ID: 019fbdc1-92e5-7262-98a3-b4d77f11e437
Resume in Codex: codex resume 019fbdc1-92e5-7262-98a3-b4d77f11e437
