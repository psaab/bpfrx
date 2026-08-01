# Codex hostile plan-review — round 64 (plan v64 @ 6488af4ac)

Task: task-msaihk2z-9k4yjc (session 019fbde3-8144-7d72-8f24-f3748bdaf79b).
Verdict: NEEDS-REVISION (3 MAJOR, 1 MINOR; fold verification 2 FOLDED / 3 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. PARTIAL — Daemon ownership and the normal semaphore ordering are sound at docs/research/2114-nat-pool-alarm-dp-race/plan.md:7169-7179, but the promised “CONCRETELY-NAMED” gate still has no field/API and is absent from the daemon inventory at :6572-6577; worse, the drain is conditional at pkg/daemon/daemon_run_shutdown.go:35-60 and its five-second bound is defeated by the later uncapped semaphore acquisition at pkg/daemon/daemon_scheduler.go:170-183.
2. PARTIAL — Reset and generation are both necessary, and a successful bootstrap re-arm does reach fresh registration—pkg/daemon/daemon_apply.go:221-224,280,287—but docs/research/2114-nat-pool-alarm-dp-race/plan.md:7125-7130 neither scopes reset safely nor pins the generation bump/post-semaphore comparison.
3. FOLDED — Every retirement class now purges reverse aliases at docs/research/2114-nat-pool-alarm-dp-race/plan.md:6895-6903, covering the neutral exits at pkg/dataplane/userspace/manager_worker_arm_5134.go:42-54 and completion at :84-101; ARM-ID-REUSE exists at plan.md:8756-8762.
4. PARTIAL — QUEUED-empty appears in the runbook, normative predicate, and formal acceptance at docs/research/2114-nat-pool-alarm-dp-race/plan.md:5593-5602,5661-5667,6915-6917,8534-8539,8589-8595, but the §5.1 rendering inventory still exposes only token/pending at :7055-7068.
5. FOLDED — The bounded wording is present at docs/research/2114-nat-pool-alarm-dp-race/plan.md:7195-7199 and reflected by the timeout-inside-mutation leg at :8697-8701.

New findings:

MAJOR 1 — The claimed five-second callback disposition does not hold. In the ordinary interleaving, a callback that owns `applySem` may read the fence clear, enter one operation, and make shutdown wait; if the drain wins first, it releases immediately and the callback later sees the fence—neither ordering deadlocks. But after the drain times out at pkg/daemon/daemon_run_shutdown.go:50-58, shutdown calls `stopPolicySchedulerLoop` at :78, which reacquires `applySem` with `context.Background()` at pkg/daemon/daemon_scheduler.go:170-183. A callback still holding the semaphore therefore stalls shutdown uncapped before the HA fence. Startup abort also invokes shutdown before `applyCancel` initialization at pkg/daemon/daemon_run.go:157-197, skipping the drain despite phase four being able to launch the callback at pkg/daemon/daemon_run_bringup.go:493-520 and pkg/dataplane/userspace/maps_sync.go:451-456. If that downstream reacquisition is capped, another uncovered race remains: preemption after the callback’s fence check but before the netlink call allows the call to begin after timeout/teardown; §9 tests only an operation already entered at plan.md:8697-8701.

MAJOR 2 — The manager-epoch reset scope is unsafe. The plan directs “Teardown/stopLocked” reset at docs/research/2114-nat-pool-alarm-dp-race/plan.md:7125-7130, but `stopLocked` also runs during ordinary helper restarts at pkg/dataplane/userspace/process.go:18-33,133, pkg/dataplane/userspace/manager_compile.go:242-249, and pkg/dataplane/userspace/process_status.go:61-70. The compile restart occurs after the daemon installed the callback and has no later registration in that apply, so clearing it strands epoch readiness. Reset/generation bump must be Teardown-specific and precede `stopLocked`’s early return at pkg/dataplane/userspace/process.go:210-216; the generation comparison must occur after callback `applySem` acquisition. Section 9 has no Teardown→reset→B-registration→A-generation-rejection regression at plan.md:8706-8720.

MAJOR 3 — The operator acceptance predicate remains unexecutable. The runbook and formal acceptance require the queued set beside pending at docs/research/2114-nat-pool-alarm-dp-race/plan.md:5593-5602 and :8534-8539, while §5.1’s exhaustive status/rendering inventory at :7055-7068 omits that field. An implementation following the inventory cannot verify QUEUED-empty.

MINOR 1 — The budget arithmetic is false: docs/research/2114-nat-pool-alarm-dp-race/plan.md:7165-7168 lists 5+3+3+2+5 as “at least 23s”; it is 18s. Persistent aggregator/IPsec stalls can add six more seconds through Run’s defers at pkg/daemon/daemon_run.go:100-112, while pkg/daemon/daemon_run_shutdown.go:62-64 already contains an unbounded `wg.Wait`.

Structure confirmation: §4.7’s PR-1 core plus inseparable G+H+H2 follow-up stands at docs/research/2114-nat-pool-alarm-dp-race/plan.md:6523-6566; §9 JOIN-COHERENCE remains intact at :8609-8658.

NEEDS-REVISION

Codex session ID: 019fbde3-8144-7d72-8f24-f3748bdaf79b
Resume in Codex: codex resume 019fbde3-8144-7d72-8f24-f3748bdaf79b
