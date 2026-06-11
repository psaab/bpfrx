# AGY Adversarial Plan Review (Round 3)

This report presents the adversarial review and ratification of the **v3 serialization plan** for the shared `loss` userspace cluster ([plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1875-research/docs/research/1875-cluster-ownership/plan.md)).

---

## 1. Soundness Assessment of v3 Deltas

We reviewed the seven v3 deltas folded from Round 2 findings and verified their safety and execution semantics:

### Delta 1: Lock-Boundary Rule
* **Change**: Moved `suppress_host_parent_ipv6_ra` from pre-lock into the reentrant locked continuation of `cmd_deploy`.
* **Evaluation**: **Sound.** The helper mutates host parent interfaces (using `sysctl`, address flushes, and route flushes). Interleaving these host mutations across concurrent deploy loops would lead to race conditions. Serializing them within the lock boundaries protects shared host network integrity.

### Delta 2: Re-exec Target absolute path
* **Change**: Executing `"$SCRIPT_DIR/cluster-setup.sh"` instead of `"$0"`.
* **Evaluation**: **Sound.** `"$0"` can be unstable or relative depending on symlinks, `PATH` lookups, or context changes during GID transitions. Sourcing `SCRIPT_DIR` guarantees absolute execution safety.

### Delta 3: `sg` Environment Forwarding
* **Change**: Dynamic forwarding of all exported `XPF_*` and `BPFRX_*` variables in `local_env` via prefix expansion (`${!BPFRX_@} ${!XPF_@}`) and `printf %q`.
* **Evaluation**: **Sound.** Standard shadow-utils `sg` sanitizes environments. Dynamically serializing and prepending the matching variables prevents cell deadlocks (marker loss) and duplicate builds (`XPF_CLUSTER_SKIP_BUILD` loss). Bash prefix expansion is `set -u` safe and behaves cleanly when no matching variables exist.

### Delta 4: `dev:ino` Revalidation and Split-Mutex Assertion
* **Change**: Revalidating `dev:ino` pairs to survive unlinks and failing closed if a live PID has a lock file with a different `dev:ino`.
* **Evaluation**: **Sound.** Kernel-level `flock` locks are associated with the open file description (inode), not the path. Comparing `dev:ino` rather than bare inodes handles multi-device environments correctly. The split-mutex assertion handles the unlink-while-held edge case by refusing to run when a split occurs.

### Delta 5: Invariant 7.2 Restatement
* **Change**: Restating that `with-cluster.sh` is the only long-lived/self-locking script holder exporting the marker, whereas standalone per-command `flock` invocations do not export it.
* **Evaluation**: **Sound.** Resolves the asymmetry while preventing nested deadlocks during standalone operations.

### Delta 6: Standalone `apply-cos-config.sh` self-lock
* **Change**: Adding a self-locking header to `apply-cos-config.sh`.
* **Evaluation**: **Sound.** CoS mutation is a frequent operation that alters active traffic behavior. Serializing it under `with-cluster.sh` ensures it does not run concurrently with active deployments or benchmarks.

### Delta 7: Blocking-Default + Optional Timeout
* **Change**: Blocking by default with periodic updates, allowing timeout customization via `XPF_CLUSTER_LOCK_TIMEOUT`.
* **Evaluation**: **Sound.** Long-running benchmarking cells (25–40 minutes) would frequently time out under a brief fail-fast default, encouraging agents to bypass the lock mechanism. Periodic status reports provide console feedback, keeping the LLM engine informed.

---

## 2. §13 Split-Mutex Abort & PID Recycling Analysis

### The False-Positive Surface
A false-positive split-mutex abort can only occur if:
1. The lock file `/tmp/xpf-cluster.lock` is deleted and recreated (inode changes from `I` to `J`).
2. The active lock holder is terminated abruptly (e.g., `SIGKILL`), bypassing the `EXIT` trap and leaving a stale owner file.
3. The old holder's PID is recycled by the kernel.
4. The recycled PID happens to be active at the exact moment of the next lock acquisition.

Because the failure mode is **refuse-and-diagnose** (fail-closed) rather than clobbering the cluster, this extremely rare false-positive surface is highly acceptable for cooperating agents.

### Recommended Cheap Robustness Improvement
We can completely eliminate the recycled PID false-positive risk under cooperating agent conditions by leveraging the fact that `with-cluster.sh` always holds the lock on **fd 9**.

When the PID is found to be alive, we can verify if it actually holds the target lock by checking `/proc/<recorded_pid>/fd/9`.
```bash
if kill -0 "$recorded_pid" 2>/dev/null; then
    # Verify if the live process actually holds the recorded lock
    local actual_dev_ino
    actual_dev_ino=$(stat -L -c %d:%i "/proc/$recorded_pid/fd/9" 2>/dev/null || true)
    if [[ "$actual_dev_ino" == "$recorded_dev_ino" && "$actual_dev_ino" != "$my_dev_ino" ]]; then
        # The mutex has indeed been split
        echo "Error: Split mutex detected!" >&2
        exit 1
    fi
fi
```

* **Why this works**: If the PID has been recycled to an unrelated process, that process will either not have fd 9 open, or fd 9 will point to a different resource. `stat` will fail or return a different `dev:ino`, bypassing the abort condition.
* **Permissions**: Since all cooperating agents run as the same user (`ps`), the `/proc` filesystem is fully readable. If the PID is recycled to a different user, `stat` fails with permission denied, causing `actual_dev_ino` to be empty, which also safely bypasses the abort.
