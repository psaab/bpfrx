# Codex hostile plan-review — round 66 (plan v66 @ bbbb6078b)

Task: task-msal9j1i-71m6yh (session 019fbe2a-a979-7762-917f-c2581fb7be0f).
Verdict: NEEDS-REVISION (3 MAJOR, 1 MINOR; fold verification 2 FOLDED / 2 PARTIAL / 1 NOT-FOLDED). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. PARTIAL — Pre-launch reservation closes the unscheduled-goroutine blind spot (docs/research/2114-nat-pool-alarm-dp-race/plan.md:7296-7306; pkg/dataplane/userspace/maps_sync.go:451-456), but a callback blocked in non-contextual netlink work cannot retire before the five-second timeout, after which teardown proceeds with it live (plan.md:7341-7356; pkg/daemon/daemon_ha_fabric.go:23-93,102-148; pkg/daemon/daemon_run_shutdown.go:214-230).
2. NOT-FOLDED — The claimed shared fence and process-local terminal state at plan.md:7323-7329 do not exist: publishPolicyScheduleState checks only epoch before dataplane mutation (pkg/daemon/daemon_scheduler.go:192-217,229-241), §5.1 inventories no scheduler change (plan.md:7024-7029), and the unconditional Run defer can invoke the supposedly abandoned stop again (pkg/daemon/daemon_run.go:89-100; pkg/daemon/daemon_scheduler.go:170-183).
3. PARTIAL — resetting is latched under applySem before the wipe and remains set through release (pkg/daemon/daemon_apply_reset.go:59-89); ActiveConfig remains the retained pre-wipe compiled config (pkg/configstore/store_format.go:55-60), and the sole callback path gains the three-term fence normatively (plan.md:7242-7256; pkg/daemon/daemon_apply_interfaces.go:98-109; pkg/dataplane/userspace/maps_sync.go:451-456). But later normative and formal copies regress to only runCtx.Err() OR stopping (plan.md:7341-7344,8875-8881).
4. FOLDED — The taxonomy is complete: reusable and terminal Teardown both reset, helper-restart stopLocked paths do not, and terminal Close needs no reset (plan.md:7221-7237; pkg/dataplane/userspace/manager.go:471-482; pkg/daemon/bootstrap.go:470-475; pkg/daemon/daemon_run_shutdown.go:214-230; pkg/dataplane/userspace/process.go:18-33,133).
5. FOLDED — All three h2o legs exist: preemption-between-check-and-call, Teardown→reset→B-registration→A-generation-rejection, and reserved-set-drain (plan.md:8851-8861).

New findings:

MAJOR — The reserved-set “join” has no safe timeout disposition. The general arm ledger retires arm registrations on completion (plan.md:6797-6811), while v66 explicitly retires the shutdown reservation only on the unscheduled closed-gate path (plan.md:7301-7306); it never binds that reservation to a defer covering every callback exit. Even if it did, a callback hung in LinkAdd, LinkSetUp, AddrReplace, or another non-contextual call cannot run the defer (pkg/daemon/daemon_ha_fabric.go:23-93,102-148). At five seconds the plan proceeds into dataplane Close/Teardown (plan.md:7340-7356; pkg/daemon/daemon_run_shutdown.go:214-230), leaving both the reservation and callback live. “The reserved set always drains” is therefore false.

MAJOR — The new preemption-between-check-and-call acceptance leg is impossible under the proposed repeated-load mechanism. The plan itself concedes that a signal can arrive after any check and that atomic loads cannot establish never-mutating (plan.md:7256-7262), yet requires a callback preempted after its check until after timeout not to start the netlink call (plan.md:8851-8855). Once the bounded join has returned, that callback can resume and enter the uncontextual call. This requires an operation-entry transition serialized with gate closure, a cancellable bounded operation, or process exit at the timeout—not another fence load.

MAJOR — Scheduler abandonment is neither safe nor terminal. The scheduler acquires applySem with the uncancelled daemonCtx, checks no runCtx/stopping/resetting fence, and invokes the dataplane (pkg/daemon/daemon_scheduler.go:192-217,229-241). The userspace path holds m.mu while issuing apply_snapshot and applying helper status (pkg/dataplane/userspace/manager_compile.go:447-453,526-564), potentially for approximately 67 seconds (pkg/dataplane/userspace/process_control.go:31-56,129-142), while Close/Teardown require the same mutex (pkg/dataplane/userspace/manager.go:471-482). It can therefore mutate external dataplane/BPF state and re-block teardown after the five-second abandonment; it can also republish the retained pre-wipe config after zeroize. Finally, Run’s unconditional defer calls stopPolicySchedulerLoop again, whose current implementation always reacquires and waits (pkg/daemon/daemon_run.go:89-100; pkg/daemon/daemon_scheduler.go:170-183). No abandoned-state latch, fast path, or scheduler fence is specified in §5.1 (plan.md:6654-6668,7024-7029).

MINOR — The zeroize fold is not regression-pinned consistently. The canonical fence includes resetting (plan.md:7242-7255), but both the timeout disposition and §9 call the two-term runCtx.Err() OR stopping predicate “full” (plan.md:7341-7344,8875-8881), and h2o contains no zeroize callback leg (plan.md:8851-8861). An implementation omitting resetting could satisfy the listed callback tests.

Structure confirmation: §4.7 stands—PR-1 remains the A1/accessor core, with G+H+H2 together in the follow-up (plan.md:6607-6650,9000-9009).

NEEDS-REVISION

Codex session ID: 019fbe2a-a979-7762-917f-c2581fb7be0f
Resume in Codex: codex resume 019fbe2a-a979-7762-917f-c2581fb7be0f
