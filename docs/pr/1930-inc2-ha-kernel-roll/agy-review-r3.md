# #1930 INC-2 (PR #1941) — AGY adversarial review r3 (convergence)

Verdict: CONVERGED — all 3 r2 findings resolved, no new CRITICAL/HIGH.
Task: adversarial-review-mqhh81or-79tk7t

# Adversarial Review: Convergence Check

I have performed a read-only pressure test on the implementation changes between `origin/master` and `HEAD` located in the worktree [1930-eng](file:///home/ps/git/bpfrx/.claude/worktrees/1930-eng). Below is the verification of the three prior findings and their potential side-effects.

---

### (1) F2 Marker-Based Release and Race-Free Tracing
**Predicate Verdict: Race-free & Safe**

The marker-based hold release in [reconcileKernelUpgradeHold](file:///home/ps/git/bpfrx/.claude/worktrees/1930-eng/pkg/daemon/kernel_selfrecover.go#L77-L97) uses the predicate `ReadPromotionMarker() == RunningKernel()`. Let's trace it across all scenarios:

*   **Successful Promote (Happy Path):** The oneshot service runs `Promote()`, which calls [WritePromotionMarker](file:///home/ps/git/bpfrx/.claude/worktrees/1930-eng/pkg/upgrade/kernel_run.go#L415-L421) before clearing the journal. Once booted into the candidate kernel, the 5-second tick in `reconcileKernelUpgradeHold` reads the marker, verifies it matches the running kernel, and drops the hold.
*   **Marker-Write Failure on Successful Promote:** If `WritePromotionMarker` fails (e.g. read-only filesystem or disk full on `/var/lib/xpf`), the promotion still succeeds locally, but the marker is not written.
    *   *System State:* The daemon does not release `kernelUpgradeHold` (fails safe toward holding the candidate `SECONDARY` in memory).
    *   *Orchestrator Behavior:* The external roll manager [xpf-deploy.py:L774-L793](file:///home/ps/git/bpfrx/.claude/worktrees/1930-eng/scripts/deploy/xpf-deploy.py#L774-L793) polls the guest status and times out after 600s because it expects `promoted == version`. The orchestrator aborts the roll and does not issue the `rejoin` command.
    *   *Fail-Safe Evaluation:* This is the correct fail-safe behavior. Under a write failure on `/var/lib/xpf` (which also breaks journal persistence), the node is degraded. Blockading local takeover and leaving the peer primary is the safest outcome. If the operator rectifies the disk issue, the hold can be cleared by rebooting or restarting `xpfd`, which will boot with a cleared journal (`IsArmed() == false`) and not set the hold.
*   **Revert Path:** `xpfd upgrade kernel promote` fails the verification gate, writes no marker, and boots back to the known-good slot. On boot, the journal is already cleared, `IsArmed()` is false, and the hold is never set. No window exists for the reverted slot to temporarily claim primary.
*   **Timeout (Hang) Path:** If the gate hangs, `OnFailure` reboots the node back to the known-good slot. Just like the revert path, no marker matches the running kernel during the boot, and the next boot on known-good does not set the hold.

---

### (2) OnFailure Unit and Loop-Safety
**Predicate Verdict: Loop-Safe & No Double-Reboot**

*   **Loop-Safety:**
    The candidate boot uses the firmware-cleared `BootNext` option. The persistent `BootOrder` is never modified unless promotion succeeds. When [xpf-kernel-promote-failed.service](file:///home/ps/git/bpfrx/.claude/worktrees/1930-eng/scripts/image/xpf-kernel-promote-failed.service) reboots the machine, the firmware has already consumed and cleared `BootNext`. The boot falls back to the known-good slot at the front of `BootOrder`. The system is now on the known-good kernel, where the promotion gate exits immediately with code `0`, preventing any loop.
*   **Double-Reboot on Revert:**
    If the promotion gate fails verification, the script [scripts/image/xpf-kernel-promote#L42-L54](file:///home/ps/git/bpfrx/.claude/worktrees/1930-eng/scripts/image/xpf-kernel-promote#L42-L54) triggers a revert reboot (`systemctl reboot --no-wall`) and **exits with status 0**. Because it exits successfully, the systemd unit `xpf-kernel-promote.service` transitions to a successful exit rather than a failed state. The `OnFailure` handler is not triggered, avoiding a double reboot.

---

### (3) Demote-on-Arm under Lock (`sendEvent`)
**Predicate Verdict: Deadlock-Safe**

[SetKernelUpgradeHold](file:///home/ps/git/bpfrx/.claude/worktrees/1930-eng/pkg/cluster/kernel_selfrecover.go#L52-L67) acquires `m.mu.Lock()` and demotes any active primary groups, calling [sendEvent](file:///home/ps/git/bpfrx/.claude/worktrees/1930-eng/pkg/cluster/manager.go#L305-L322) under the lock. This is safe:

1.  **Reentrancy:** `sendEvent` does not acquire `m.mu`. It writes to `m.eventCh` and logs to history.
2.  **Channel Blocking:** The send to `eventCh` (which has buffer size 64) is wrapped in a `select-default` block. If the channel is full, the event is dropped (notifying the non-blocking `onEventDrop` callback `triggerReconcile`), ensuring it never blocks or deadlocks.
3.  **Bootstrap Ordering:** In `daemon_run.go`, `holdSecondaryIfKernelCandidateArmed` runs before `UpdateConfig`. Because the manager's `groups` map is empty at this stage, no loops execute, and no events are written to the channel.

---

### (4) New Issues Analysis
No new CRITICAL or HIGH severity issues have been introduced by these commits. 

#### Low-Risk Implementation Discrepancy:
*   **Lease-Expiration / Rejoin Hold-Clear Gap:**
    The comments in `ClearKernelUpgradeHold` state that hold clearing is *"Also implied by ResetAllFailover so the rejoin path clears it."* However, when the orchestrator calls rejoin, the client `grpcCluster` calls [ResetFailover](file:///home/ps/git/bpfrx/.claude/worktrees/1930-eng/pkg/upgrade/cluster_cli.go#L459-L475), which loops and sends a `cluster-failover-reset:<rgID>` action for each RG. The daemon handler executes `Manager.ResetFailover(rgID)` for individual groups, which does **not** call `ClearKernelUpgradeHold()`.
    *   *Risk:* Low. On a successful roll, `reconcileKernelUpgradeHold` has already cleared the hold 5 seconds post-boot. If the roll fails, keeping the hold is the correct fail-safe behavior. The only minor side effect is that if an operator manually triggers `rejoin` on a node where the marker write failed, the hold is not cleared through gRPC and requires a daemon restart (`systemctl restart xpfd`) to resolve.

---

### Conclusion
**Status: CONVERGED**

All three prior findings (**F1**, **F2**, and **F3**) are successfully resolved, and no new CRITICAL or HIGH issues exist.
