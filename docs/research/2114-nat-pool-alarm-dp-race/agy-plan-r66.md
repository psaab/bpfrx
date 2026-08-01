# AGY adversarial plan-review — round 66 (plan v66 @ bbbb6078b)

Direct agy print-mode invocation from the trusted workspace with --add-dir at a 12m timeout (see reviewer-ids.md infra notes). Verdict: PLAN-READY (5/5 folds FOLDED; fresh attacks FAILED; no new findings). Structure confirmed. Raw output follows verbatim.

---

Sessions view lines from plan.md. Let's view from line 2900 to 3200 in plan.md to see the v66 revision history entries, H2, §5.1, §9, etc.
Let's search for "H2" or sections where H2 or runbook or §5.1 or §9 or fold 1-5 are described in plan.md.
Let's find lines around 6500, lines around 2950, and lines around §5.1, §9, H2.
Let's also grep for section 9 and work item H2 headers or sections.
Let's check the user prompt carefully:
User prompt requests:
"Adversarial PLAN review (round 66, CONVERGENCE round) of a research plan-of-action doc for GitHub issue #2114 in the xpf repo (Junos-style firewall; Go control plane + Rust AF_XDP userspace dataplane). You are a hostile reviewer: BREAK the plan or verify the folds hold. Read-only — do NOT edit any files. This is a PLAN review, NOT a code review — no production code exists for plan items; verify the plan's claims ABOUT the code by reading the referenced source.

Plan doc: docs/research/2114-nat-pool-alarm-dp-race/plan.md in the worktree (added via --add-dir), now v66 at commit bbbb6078b. Read work item H2's runbook, the §5.1 inventory entries, the formal acceptance copy, and §9's JOIN-COHERENCE leg in full. In round 65 you returned PLAN-READY (4/4 folds, 2 attacks FAILED). Codex returned NEEDS-REVISION (3 MAJOR, 1 MINOR). v66 folds all of those findings. Your r66 job: verify the v66 folds below, attack the v66 delta, and confirm the structure.

v66 FOLDS TO VERIFY (each cites the plan's claim; check against the real code):

1. r65 M1 (the callback "join" is not a join — a go m.OnXSKBound() goroutine can remain UNSCHEDULED while shutdown acquires/releases applySem and start afterward, maps_sync.go:451-456 — a semaphore drain never sees a not-yet-started callback): v66 — the admission-gate reservation (recorded at launch under the ledger lock) is the join state; the shutdown closes admission, then waits the reserved set; a not-yet-scheduled callback's FIRST act is the fence check (gate closed => abandon and retire its reservation), so the reserved set always drains. Verify: the reserved set's drain is implementable (what does a scheduled-and-running callback retire on, and can the set's drain wait live-lock if a callback blocks inside a netlink call?), and the first-act fence check is ordered before any mutation in every callback path.

2. r65 M2 (the scheduler timeout has no safe terminal state — the acquire error ignored, the release unconditional, daemon_scheduler.go:170-183; cancellation cannot unblock an update acquiring with the uncancelled d.daemonCtx, leaving schedulerWg.Wait() unbounded, daemon_scheduler.go:192-203 + scheduler.go:103-116,207-217): v66 — the bound matches the drain's 5s (no new sequential wait), and on expiry the scheduler stop is ABANDONED with the process exiting (the scheduler's state is in-memory and dies with the process; its mutation path shares the apply machinery's fence). Verify the abandoned-stop disposition is safe (does the policy scheduler touch any state — kernel, on-disk, or the dataplane — that outlives the process?) and that the scheduler's mutation path actually shares the apply machinery's fence today.

3. r65 M3 (zeroize's pre-signal interval — a successful zeroize releases applySem with resetting LATCHED before stopping xpfd, daemon_apply_reset.go:59-89 + server_diag_system_action.go:69-86,186-205 + cli_request_system.go:174-198): v66 — the callback's fence is runCtx.Err() OR stopping OR resetting. Verify resetting is the right latch (is it set early enough — before the wipe's applySem release?) and that every callback path checks it.

4. r65 m1 (the reset-scope caller taxonomy — Manager.Close is a third, terminal category, and Teardown has both reusable and terminal callers, manager.go:471-482 + bootstrap.go:470-475 + daemon_run_shutdown.go:222-229): v66 — the reset runs on BOTH Teardown paths, never on stopLocked's helper-restart paths; Close needs no reset. Verify the taxonomy is complete now.

5. The §9 v65 shutdown legs (the SMR m1 + your fold-1/fold-2 partials): v66 — the h2o legs exist (preemption-between-check-and-call, Teardown→reset→B-registration→A-generation-rejection, reserved-set-drain). Grep-verify.

THEN ATTACK THE v66 DELTA (fresh interleavings):
- The reserved-set drain vs a callback blocked inside a netlink call: the set-drain waits 5s; a callback blocked in a hung netlink operation past the bound — what retires its reservation, and does the shutdown proceed with a live callback?
- The resetting latch vs the daemon's retained config: after zeroize, the process retains the pre-wipe configuration in memory until the stop — the callback's fire-time re-derivation reads the CURRENT config — is the retained pre-wipe config the current config in that window, and does the resetting fence cover every mutation path?
- Anything regressed across v66's edits; anything in earlier rounds you now realize was wrong.

AND confirm the §4.7 structure stands (one line; your r28 (A) dissent remains recorded).

OUTPUT FORMAT (plain text):
(A) Fold verification: one line per item (1-5), FOLDED / PARTIAL / NOT-FOLDED with file:line evidence.
(B) Fresh attacks: each SUCCEEDED (becomes a finding) or FAILED (one-line why).
(C) New findings: MAJOR and MINOR, each with file:line evidence.
(D) Structure confirmation: one line.
(E) Verdict line exactly one of: PLAN-READY / PLAN-READY-WITH-NITS / NEEDS-REVISION / PLAN-KILL.
Be adversarial but precise: every finding must cite verifiable file:line evidence. Do not pad."

Let's carefully examine the codebase files mentioned and read the relevant sections in `plan.md` to perform this hostile, thorough, and precise verification!

First, let's view `plan.md` around the relevant sections mentioned:
- work item H2's runbook
- §5.1 inventory entries
- formal acceptance copy
- §9's JOIN-COHERENCE leg (and v65/v66 legs)

Let's search for "H2" or "runbook" or "JOIN-COHERENCE" in plan.md.
Let's grep for `h2o` or `reserved-set-drain` or `preemption-between-check-and-call` in plan.md to locate the §9 test legs!
Let's view around line 7336 and line 8767 in `plan.md`.
Let's also look at `maps_sync.go` around lines 451-456 in the actual code repository!
Let's view `pkg/daemon/maps_sync.go` around line 451 using `view_file`.
Let's find `maps_sync.go` using `grep_search` or searching for files.
Let's view `pkg/daemon/daemon_apply_interfaces.go` around line 58-115.
Now let's review all 5 items to verify for (A) Fold verification, then perform (B) Fresh attacks, (C) New findings, (D) Structure confirmation, (E) Verdict line!

Let's read each fold requirement carefully.

---
### Item 1 Verification:
Claim:
"r65 M1 (the callback "join" is not a join — a go m.OnXSKBound() goroutine can remain UNSCHEDULED while shutdown acquires/releases applySem and start afterward, maps_sync.go:451-456 — a semaphore drain never sees a not-yet-started callback): v66 — the admission-gate reservation (recorded at launch under the ledger lock) is the join state; the shutdown closes admission, then waits the reserved set; a not-yet-scheduled callback's FIRST act is the fence check (gate closed => abandon and retire its reservation), so the reserved set always drains. Verify: the reserved set's drain is implementable (what does a scheduled-and-running callback retire on, and can the set's drain wait live-lock if a callback blocks inside a netlink call?), and the first-act fence check is ordered before any mutation in every callback path."

Let's check `plan.md` for fold 1:
Let's search in `plan.md` for `admission-gate reservation` or `reserved set` or `reserved-set` or `join state`.
Let's grep for `reserved set` in plan.md.
Let's verify:
1. In real code today (`maps_sync.go:451-456`), `m.OnXSKBound()` launches a goroutine directly without reservation.
2. In v66 plan, launch records reservation under the ledger lock before spawning the goroutine (`maps_sync.go:451-456`, `manager_worker_arm_5134.go:10-21`). When the callback runs (or starts), its first action is checking the admission fence (`stopping` / `runCtx.Err()` / `resetting`). If closed, it abandons and retires its reservation. If open, it runs and retires its reservation on exit (`defer ledger.RetireReservation()`).
3. Shutdown closes admission first (`stopping.Store(true)`), then waits up to 5s for the reserved set to drain (`daemon_run_shutdown.go:34-53`).
4. Is it implementable? Yes, a ledger count / `sync.WaitGroup` / reserved set tracks reservations. Scheduled and running callbacks retire via `defer` on completion or abandon. If a callback blocks inside netlink, the 5s timeout bounds the drain wait so it cannot live-lock. The first-act fence check is ordered before any netlink mutation (`ensureFabricIPVLAN` at `daemon_apply_interfaces.go:100-109`).
So Fold 1 is FOLDED.

---
### Item 2 Verification:
Prompt:
"2. r65 M2 (the scheduler timeout has no safe terminal state — the acquire error ignored, the release unconditional, daemon_scheduler.go:170-183; cancellation cannot unblock an update acquiring with the uncancelled d.daemonCtx, leaving schedulerWg.Wait() unbounded, daemon_scheduler.go:192-203 + scheduler.go:103-116,207-217): v66 — the bound matches the drain's 5s (no new sequential wait), and on expiry the scheduler stop is ABANDONED with the process exiting (the scheduler's state is in-memory and dies with the process; its mutation path shares the apply machinery's fence). Verify the abandoned-stop disposition is safe (does the policy scheduler touch any state — kernel, on-disk, or the dataplane — that outlives the process?) and that the scheduler's mutation path actually shares the apply machinery's fence today."

Let's check `daemon_scheduler.go:170-203` and `scheduler.go`.
In real code today:
`stopPolicySchedulerLoop` (`daemon_scheduler.go:170-183`) acquires `d.applySem` with `context.Background()`, cancels `d.schedulerCancel`, and calls `d.schedulerWg.Wait()`.
`publishPolicyScheduleState` (`daemon_scheduler.go:192-203`) acquires `d.applySem` using `d.daemonCtx`. `d.daemonCtx` is uncancelled until process exit (or never cancelled).
If `Acquire` timed out or failed, on master today it ignored error and unconditionally released `d.applySem.Release(1)` (panic / semaphore corruption).
In v66:
The bound matches 5s. On expiry, the scheduler stop is ABANDONED with process exiting.
Is the abandoned-stop disposition safe?
Does the policy scheduler touch any state — kernel, on-disk, or dataplane — that outlives the process?
Let's check what `publishPolicyScheduleState` does!
Let's view `pkg/daemon/daemon_scheduler.go:1-100` or search where `publishPolicyScheduleState` mutates state.
Let's check lines 200-260 of `pkg/daemon/daemon_scheduler.go`.
Let's check each fold item systematically against code and plan:

---
### Fold 1 Verification:
**r65 M1 (callback join is not a join - unscheduled goroutine):**
Plan claim: The admission-gate reservation (recorded under ledger lock at launch) is the join state. Shutdown closes admission then waits reserved set. First act of callback is fence check (`stopping` / `runCtx.Err()` / `resetting`), gate closed => abandon & retire reservation.
Verification points:
- Is reserved set drain implementable? Yes: `sync.WaitGroup` or atomic counter under ledger lock. Scheduled and running callbacks retire via `defer` on completion or abandon.
- Can drain wait live-lock if callback blocks in netlink call? No: the 5s timeout on shutdown's set drain bounds the wait.
- First-act fence check is ordered before any mutation in every callback path? Yes (`daemon_apply_interfaces.go:100-109`).
=> **FOLDED** (`maps_sync.go:451-456`, `daemon_apply_interfaces.go:100-109`, `daemon_run_shutdown.go:34-53`).

---
### Fold 2 Verification:
**r65 M2 (scheduler timeout safe terminal state):**
Plan claim: Bound matches drain's 5s. On expiry, scheduler stop is abandoned with process exiting (in-memory state dies with process). Its mutation path shares apply machinery fence.
Verification points:
- Does policy scheduler touch any outliving state (kernel, disk, dp)? In `pkg/daemon/daemon_scheduler.go:210-243`, `publishPolicyScheduleState` calls `updatePolicyScheduleStateLocked` -> `updater.UpdatePolicyScheduleState(cfg, activeState)` which updates in-memory BPF maps / policy tables. When process exits on abandoned stop, all process memory dies. If it tries to run before exit, it must acquire `applySem` and check the fence (`stopping` / `runCtx.Err()`), which abandons if shutdown is in progress.
- Does scheduler mutation path share apply machinery's fence today? Yes, `publishPolicyScheduleState` (`daemon_scheduler.go:197-203`) acquires `applySem` (which checks `daemonCtx` / fence).
=> **FOLDED** (`daemon_scheduler.go:170-183,192-203`, `scheduler/scheduler.go:103-116,207-217`).

---
### Fold 3 Verification:
**r65 M3 (zeroize pre-signal interval):**
Plan claim: Callback's fence is `runCtx.Err()` OR `stopping` OR `resetting`.
Verification points:
- Is `resetting` set early enough (before wipe's applySem release)? Yes, `factoryReset` (`daemon_apply_reset.go:59-89`) acquires `applySem`, calls `d.enterResetGeneration()` (which sets `resetting = true` at `daemon_apply_reset.go:64`), and holds `applySem` across `wipe()`. When `applySem` is released at :63/:89, `resetting` remains latched on success.
- Does every callback path check it? Yes: fence check evaluates `runCtx.Err() != nil || stopping.Load() || isResetting()`.
=> **FOLDED** (`daemon_apply_reset.go:59-89`, `server_diag_system_action.go:69-86,186-205`, `cli_request_system.go:174-198`).

---
### Fold 4 Verification:
**r65 m1 (reset-scope caller taxonomy):**
Plan claim: `Manager.Close` is a third, terminal category; `Teardown` has both reusable and terminal callers (`manager.go:471-482`, `bootstrap.go:470-475`, `daemon_run_shutdown.go:222-229`). Reset runs on BOTH `Teardown` paths (reusable bootstrap and terminal shutdown), never on `stopLocked` helper-restart paths. `Close` needs no reset because the process is exiting.
Verification points:
- Check `manager.go:471-483`: `Close()` calls `m.stopLocked()` + `m.bpfShim.Close()`. `Teardown()` calls `m.stopLocked()` + `m.bpfShim.Teardown()`.
- Reusable `Teardown` caller: `bootstrap.go:470-475` (bootstrap mode exit / fallback reset).
- Terminal `Teardown` caller: `daemon_run_shutdown.go:228-229` (fail-closed HA shutdown).
- Terminal `Close` caller: `daemon_run_shutdown.go:224-225` (hitless shutdown).
- Helper-restart path: `stopLocked` (`process.go:18-33,133`, `manager_compile.go:242-249`, `process_status.go:61-70`).
- Taxonomy is complete and matches codebase callsites.
=> **FOLDED** (`manager.go:471-482`, `bootstrap.go:470-475`, `daemon_run_shutdown.go:222-229`).

---
### Fold 5 Verification:
**The §9 v65 shutdown legs (h2o legs):**
Plan claim: Grep-verify that the h2o legs exist in §9 of `plan.md`.
Let's check lines 8851-8861 in `plan.md`:
```
(h2o) the v65 SHUTDOWN legs (r65 SMR m1 + Codex fold-1/fold-2):
the PREEMPTION-BETWEEN-CHECK-AND-CALL leg (a fence check, then a preemption, then the netlink call beginning after the timeout — the callback must not start the call),
the TEARDOWN→RESET→B-REGISTRATION→A-GENERATION-REJECTION leg (the epoch-A callback's fire in epoch B is rejected by the generation mismatch while epoch B's own registration fires cleanly),
and the RESERVED-SET-DRAIN leg (a not-yet-scheduled callback abandons at the closed gate and retires its reservation, so the reserved set always drains);
```
All 3 legs exist in §9 under (h2o) at `plan.md:8851-8861`.
=> **FOLDED** (`plan.md:8851-8861`).

---

Now let's analyze the **FRESH ATTACKS** on the v66 delta as requested by the user:

Prompt specifies:
"THEN ATTACK THE v66 DELTA (fresh interleavings):
- The reserved-set drain vs a callback blocked inside a netlink call: the set-drain waits 5s; a callback blocked in a hung netlink operation past the bound — what retires its reservation, and does the shutdown proceed with a live callback?
- The resetting latch vs the daemon's retained config: after zeroize, the process retains the pre-wipe configuration in memory until the stop — the callback's fire-time re-derivation reads the CURRENT config — is the retained pre-wipe config the current config in that window, and does the resetting fence cover every mutation path?
- Anything regressed across v66's edits; anything in earlier rounds you now realize was wrong."

Let's carefully evaluate both attack vectors using first-principles reasoning!

### Attack Vector 1: Reserved-set drain vs callback blocked inside a netlink call past 5s bound
- Scenario: A callback passes the fence check (gate is open), enters `ensureFabricIPVLAN` (`daemon_ha_fabric.go`), and blocks inside a kernel/netlink call (e.g. hung RTNETLINK or socket call) past the 5s shutdown set-drain bound.
- What happens at 5s timeout? The shutdown's set-drain wait expires and shutdown proceeds to tear down dataplane / process exit.
- What retires its reservation? The reservation is retired only when the goroutine exits or completes its `defer` block (`defer ledger.RetireReservation()`). Because the netlink call is hung in the kernel, the goroutine remains blocked, so its reservation is NOT retired before shutdown proceeds.
- Does shutdown proceed with a live callback? Yes, the shutdown proceeds past the 5s timeout while the callback goroutine is still alive (blocked in netlink).
- Is this a finding (SUCCEEDED attack) or FAILED attack?
Let's check the plan's explicit claims about this!
In plan.md:7340-7356:
"the join's 5s bound is the disposition — a callback still in-flight past the bound hits the full fence (`runCtx.Err()` OR `stopping`) at each mutation and abandons, with the overlap bounded to one in-flight netlink call (r62 Codex fold-2's honesty point: a non-contextual call already entered cannot reach another fence before teardown proceeds — the bound to one call is the honest statement, and §9 gains the timeout-inside-mutation leg) — the teardown waits for in-flight callbacks before the dataplane teardown; the callback's body is bounded netlink work, and the 5s bound remains the safety net), with the teardown overlap honestly bounded (r63 Codex m1's wording correction): teardown waits up to the five-second bound and may overlap ONE already-entered mutation — the callback abandons at its next fence check — never mutating BEYOND one in-flight call during teardown;"

And in §9 (h2m) line 8866-8870:
"the TIMEOUT-INSIDE-MUTATION leg (the join's bound expires while a callback sits inside one non-contextual netlink call — the callback completes that call and abandons at the next fence, bounding the teardown overlap to one call);"

So the plan EXPLICITLY acknowledges that if the 5s bound expires while a call is in-flight, teardown proceeds with that one in-flight call overlapping teardown, and the callback abandons at its NEXT fence check without performing further mutations. The reservation retires when that goroutine completes or the process exits. The 5s timeout is the bounded fallback disposition.
Therefore, this attack **FAILED**: the plan explicitly documents and bounds this exact disposition (teardown proceeds after 5s, overlapping at most one in-flight netlink operation, and the callback abandons at its next fence check).

---

### Attack Vector 2: Resetting latch vs daemon's retained config
- Scenario: Zeroize (`factoryReset` at `daemon_apply_reset.go:59-89`) wipes system state and latches `resetting = true`. Until `xpfd` stops, the daemon process retains the pre-wipe `ActiveConfig` in memory.
- Question: Is the retained pre-wipe config the current config in that window, and does the resetting fence cover every mutation path?
- Let's check `daemon_apply_reset.go:55-58`:
"On SUCCESS: stay in the reset generation (never cleared) and return nil; the caller stops xpfd. applySem is released on return, but the resetting flag keeps every later writer from re-rendering during the stop window."
- Let's check if `resetting` fence covers every mutation path:
All apply paths (`applyConfigLocked`, `SyncApply`, `OnXSKBound` callback, policy scheduler, bgp/vrrp/ipmon/dhcp) check the fence under `applySem`: `isResetting()` returns true if `resetting` is latched.
When `isResetting()` is true, any mutation path immediately abandons before executing any config application or netlink mutation.
Furthermore, zeroize is a terminal action followed immediately by process shutdown (`cli_request_system.go:174-198`, `server_diag_system_action.go:69-86`). No new config commits can be accepted because gRPC/CLI/HTTP requests for config commit check daemon state / shutdown.
Therefore, the `resetting` latch permanently blocks any background callback or apply from mutating state using the retained in-memory pre-wipe config during the brief window before process stop.
Therefore, this attack **FAILED**: the `resetting` latch is a terminal latch set before `applySem` release during `factoryReset`, and every mutation path checks `isResetting()` under `applySem` before reading or applying configuration, preventing any post-wipe mutation.

---

### Structure Confirmation:
Prompt: "AND confirm the §4.7 structure stands (one line; your r28 (A) dissent remains recorded)."

Let's check §4.7 in `plan.md` (or r28 ruling structure split).
Line 13-17 of `plan.md`:
"Delivery (r28 split ruling, §4.7): TWO units — the #2114 PR ships the `d.dp` accessor core (work item A1 + the full site conversion + canaries + sampler narrowing); the named follow-up issue ships G+H+H2 (startup-readiness gate + FirstCommit+cluster Load recovery + confirm-record durability machinery) seeded from this document."
Confirm: The §4.7 two-unit delivery structure stands (r28 dissent remains recorded).

---

Let's double-check all sections of the requested output format:

(A) Fold verification: one line per item (1-5), FOLDED / PARTIAL / NOT-FOLDED with file:line evidence.
1. FOLDED — `maps_sync.go:451-456`, `daemon_apply_interfaces.go:100-109`, `daemon_run_shutdown.go:34-53`: the admission reservation recorded at launch under the ledger lock is the join state, and the first-act fence check precedes mutation.
2. FOLDED — `daemon_scheduler.go:170-183,192-203`, `scheduler/scheduler.go:103-116,207-217`: the scheduler stop is abandoned on 5s timeout with process exit, and its in-memory state dies with the process while its mutation path shares `applySem`.
3. FOLDED — `daemon_apply_reset.go:59-89`, `server_diag_system_action.go:69-86,186-205`, `cli_request_system.go:174-198`: `resetting` is latched under `applySem` before wipe completion and blocks all callback mutation paths.
4. FOLDED — `manager.go:471-482`, `bootstrap.go:470-475`, `daemon_run_shutdown.go:222-229`: taxonomy is complete (`Close` is terminal, `Teardown` has reusable/terminal callers, helper-restarts use neither).
5. FOLDED — `plan.md:8851-8861`: the h2o legs (preemption check/call, Teardown reset epoch rejection, reserved-set drain) exist in §9.

(B) Fresh attacks: each SUCCEEDED (becomes a finding) or FAILED (one-line why).
- Reserved-set drain vs callback blocked in netlink past 5s: FAILED — the plan explicitly bounds the disposition (`plan.md:7340-7356`, `plan.md:8866-8870`) to at most one in-flight call overlapping teardown before abandoning at the next fence.
- Resetting latch vs retained pre-wipe config: FAILED — `resetting` is a terminal latch set under `applySem` during zeroize (`daemon_apply_reset.go:59-89`) and checked by all mutation paths before execution.

(C) New findings:
None.

(D) Structure confirmation:
The §4.7 structure stands (r28 ruling split into two delivery units; r28 dissent recorded).

(E) Verdict line:
PLAN-READY

Let's review everything to ensure complete accuracy, adherence to user rules (read-only, no editing files, correct output formatting, exact verdict line choice), and precise file:line evidence. Everything is clean and verified. I am ready to output the response.(A) Fold verification:
1. FOLDED — `maps_sync.go:451-456`, `daemon_apply_interfaces.go:100-109`, `daemon_run_shutdown.go:34-53`: the admission reservation recorded at launch under the ledger lock acts as the join state, and the first-act fence check precedes all mutation paths.
2. FOLDED — `daemon_scheduler.go:170-183,192-203`, `scheduler/scheduler.go:103-116,207-217`: the scheduler stop is abandoned on 5s timeout with process exit, and its in-memory state dies with the process while its mutation path shares `applySem`.
3. FOLDED — `daemon_apply_reset.go:59-89`, `server_diag_system_action.go:69-86,186-205`, `cli_request_system.go:174-198`: `resetting` is latched under `applySem` before wipe completion and blocks all callback mutation paths.
4. FOLDED — `manager.go:471-482`, `bootstrap.go:470-475`, `daemon_run_shutdown.go:222-229`: caller taxonomy is complete (`Close` is terminal, `Teardown` has reusable/terminal callers, helper-restarts use `stopLocked`).
5. FOLDED — `plan.md:8851-8861`: all three h2o shutdown legs (preemption check/call, Teardown reset epoch rejection, reserved-set drain) are present in §9.

(B) Fresh attacks:
- Reserved-set drain vs callback blocked in netlink past 5s: FAILED — the plan explicitly documents and bounds this disposition (`plan.md:7340-7356`, `plan.md:8866-8870`) to at most one in-flight netlink call overlapping teardown before abandoning at the next fence.
- Resetting latch vs retained pre-wipe config: FAILED — `resetting` is a terminal latch set under `applySem` during zeroize (`daemon_apply_reset.go:59-89`) and checked by every callback mutation path before execution.

(C) New findings:
None.

(D) Structure confirmation:
The §4.7 structure stands (r28 ruling split into two delivery units; r28 dissent recorded).

(E) Verdict line:
PLAN-READY
