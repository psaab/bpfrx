# #1875 Round-2 Adversarial Plan Review

This document presents a hostile, pressure-tested adversarial review of the proposed **v2 serialization plan** for the shared `loss` userspace cluster ([plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1875-research/docs/research/1875-cluster-ownership/plan.md)).

---

## 1. Script Re-verification Analysis

We pressure-tested the v2 design against the actual codebase implementations of the target scripts:

### A. GID Re-exec in `cluster-setup.sh` (lines 41-50)
The script currently checks if GID permissions for `incus` are present. If not, it executes:
```bash
local_env=""
if [[ -n "${BPFRX_CLUSTER_ENV:-}" ]]; then
    local_env="BPFRX_CLUSTER_ENV=$(printf '%q' "$BPFRX_CLUSTER_ENV") "
fi
exec sg incus-admin -c "${local_env}$(printf '%q ' "$0" "$@")"
```
* **Findings:** The use of `printf '%q '` to escape the arguments is highly robust and avoids argument corruption when passing the command string through the `sg -c` shell. However, the manual reconstruction of the environment via `local_env` is **incomplete** under the new re-exec architecture (see Section 3).

### B. `cmd_deploy` (~580) and `deploy_vm` (630-760)
* **Findings:** `cmd_deploy` performs local compilation of `xpfd`, `cli`, and `xpf-userspace-dp` before pushing them. The proposed re-exec happens *after* the compilation. 
* **Mechanics:** The re-exec is:
  `exec "$SCRIPT_DIR/with-cluster.sh" ... -- env XPF_CLUSTER_SKIP_BUILD=1 "$0" deploy "$target"`
  Because `with-cluster.sh` invokes the child with `"$@" 9>&-`, the file descriptor 9 (which holds the lock) is closed at the process boundary. The many children spawned by `deploy_vm` (`incus file push`, `incus exec`, and their remote ssh/systemd invocations) will not inherit the lock fd.
  This completely resolves the zombie-holder issue where a terminated deploy leaves a child holding the inherited fd.

### C. `wg-interop.sh` `inc()` (64-71)
* **Findings:** The current implementation uses:
  `flock "${WG_CLUSTER_LOCK}" sg incus-admin -c "$q"`
  The v2 design proposes:
  ```bash
  if xpf_cluster_lock_held; then
      sg incus-admin -c "$q"
  else
      flock "${WG_CLUSTER_LOCK}" sg incus-admin -c "$q"
  fi
  ```
  This is correct. Sourcing `cluster-lock.sh` allows the `inc()` helper to inspect the `XPF_CLUSTER_LOCK_HELD` marker. If present and valid, it bypasses the nested `flock`, preventing the inner-lock deadlock while preserving standalone serialization when called directly.

---

## 2. Answers to §12's Open Questions

### Q1: Is post-acquire inode revalidation (A2 step 3) worth its ~6 lines?
* **Recommendation:** **Yes, it is absolutely worth keeping.**
* **Rationale:** In Linux, `flock` locks are bound to the **open file description** (which points to an inode), not the filesystem path. If another process or an automated cleanup script (like `systemd-tmpfiles`) deletes `/tmp/xpf-cluster.lock` while a process has the file open (or between `open` and `flock`), the path is unlinked. 
  A subsequent process opening `/tmp/xpf-cluster.lock` will create a *new* file with a *different* inode. Both processes will successfully acquire locks on their respective inodes, creating a **split-lock / mutex split** and running concurrently.
  Checking:
  `[[ "$(stat -c %i "$LOCK")" == "$(stat -L -c %i /proc/$$/fd/9)" ]]`
  takes exactly 4 lines of shell and completely immunizes the harness against silent split-lock races.

### Q2: Does the `cmd_deploy` re-exec have a hole?
* **Recommendation:** **Yes, a critical environment propagation hole exists in the GID re-exec path.**
* **Rationale:** As analyzed in Section 3, when `cluster-setup.sh` re-executes through `sg incus-admin -c`, it sanitizes the environment. Since the `sg` re-exec command string only serializes `BPFRX_CLUSTER_ENV`, other vital variables (`XPF_CLUSTER_LOCK_HELD`, `XPF_CLUSTER_SKIP_BUILD`, and overridden lock paths/timeouts) are **lost**.
* **Argument Re-quoting & Build Avoidance:** If the environment propagation hole is closed, the argument re-quoting through `with-cluster.sh` is safe because `with-cluster.sh` invokes the array `"$@"` directly without shell parsing, preserving exact arguments. Double-build avoidance is also fully preserved by checking `XPF_CLUSTER_SKIP_BUILD=1`.

### Q3: Is deprecating raw outer-flock of self-locking verbs acceptable?
* **Recommendation:** **Acceptable; no compatibility shim is needed.**
* **Rationale:** There is no reliable way to verify if a raw `flock` is held by our ancestor because the utility sets `FD_CLOEXEC` on the lock fd, meaning we do not inherit the fd. A `flock -n` probe cannot distinguish between a lock held by our ancestor (which we should bypass) and a lock held by a concurrent competitor (which we must block on). 
  Deprecating the raw pattern is the only clean path. Deadlocks caused by manual muscle-memory usage of `flock` will print the owner report and `fuser -v` output to stderr every 30 seconds, allowing the operator to immediately diagnose the block.

### Q4: Can two cooperating processes both end up holding the canonical lock under v2?
* **Recommendation:** **Refute.**
* **Rationale:** Under the cooperating agent assumption, two processes can never both hold the canonical lock. The exclusive nature of `flock`, the explicit closing of fd 9 for children (`9>&-`), the ancestor PPid walk (which prevents stale/forged marker bypasses), and the inode revalidation (which prevents unlinked split-locks) provide a complete guarantee of mutual exclusion.

---

## 3. New Holes Introduced by v2

We identified **one critical hole** and **one minor optimization opportunity** in the v2 design:

### Hole 1: Marker and Build-Skip Loss Across `sg` Boundary (CRITICAL)
In `cluster-setup.sh:41-50`, the GID re-exec command string only serializes `BPFRX_CLUSTER_ENV`:
`exec sg incus-admin -c "BPFRX_CLUSTER_ENV=$(printf '%q' "$BPFRX_CLUSTER_ENV") $0 $@"`

If the script runs inside a `with-cluster.sh` cell wrapper:
1. `with-cluster.sh` exports `XPF_CLUSTER_LOCK_HELD="<lockpath>:<pid>"`.
2. It executes `cluster-setup.sh deploy`.
3. `cluster-setup.sh` detects it needs the `incus-admin` GID, and runs `exec sg incus-admin -c ...`.
4. On systems where `sg` or PAM scrubs the environment, `XPF_CLUSTER_LOCK_HELD` is **wiped**.
5. The re-exec'ed script starts. `cmd_deploy` runs, compiles the code, and checks `xpf_cluster_lock_held`.
6. Because the env marker was wiped, it thinks the lock is **not** held.
7. It calls `with-cluster.sh`, which attempts to acquire the lock.
8. The lock is already held by the outer `with-cluster.sh` (from Step 1).
9. **Deadlock:** The inner `with-cluster.sh` blocks forever.

Similarly, if `cmd_deploy` runs `with-cluster.sh` inside the GID-transitioned shell:
1. `with-cluster.sh` runs, sets `XPF_CLUSTER_LOCK_HELD`, and runs `env XPF_CLUSTER_SKIP_BUILD=1 ./cluster-setup.sh`.
2. If the user invokes this with GID elevation, `cluster-setup.sh` does not GID-re-exec, so it works. But if any other GID re-exec happens, `XPF_CLUSTER_SKIP_BUILD` is wiped, causing a **double build**.

#### The Fix:
Dynamically serialize all `BPFRX_` and `XPF_` prefixed environment variables when constructing `local_env` for the `sg` re-exec:
```bash
local_env=""
for var in ${!BPFRX_@} ${!XPF_@}; do
    if [[ -n "${!var:-}" ]]; then
        local_env="${local_env}${var}=$(printf '%q' "${!var}") "
    fi
done
exec sg incus-admin -c "${local_env}$(printf '%q ' "$0" "$@")"
```
This is fully compatible with Bash 3.0+ and guarantees that all markers, custom lock paths, and configuration overrides survive the GID transition.

### Hole 2: Standalone `apply-cos-config.sh` Runs Lock-Free
While retrofitting all scripts is out of scope, `apply-cos-config.sh` directly mutates the active cluster (specifically Class of Service shaping). If run standalone, it can overwrite active CoS configurations mid-measurement.
#### The Fix:
Add a quick self-locking block at the beginning of `apply-cos-config.sh`:
```bash
if ! xpf_cluster_lock_held; then
    exec "$SCRIPT_DIR/with-cluster.sh" "apply-cos-config $*" -- "$0" "$@"
fi
```
This guarantees that manual CoS applications serialize behind active deploys, while safely bypassing the lock when called inside a `with-cluster.sh` cell wrapper.

---

## 4. Re-Judging Blocking vs. Fail-Fast (AGY Preference)

In Round 1, AGY recommended a `flock -w 300` (5-minute) fail-fast timeout. 
In v2, the plan opts for **blocking by default with 30-second periodic status updates** on stderr, plus an optional `XPF_CLUSTER_LOCK_TIMEOUT` override.

We explicitly re-judged this trade-off:
* **The Case for Blocking:** Legitimate measurement cells take 25–40 minutes. If concurrent runs default to a 5-minute fail-fast, automated agents will repeatedly fail their deploys. Impatient agents will then attempt to write custom scripts to bypass the tools entirely.
* **The Affordance:** The 30-second stderr progress report prints the holder's PID, user, git branch, purpose, and timestamp. Because this output goes to stderr, the calling agent's LLM engine receives this context live in its console. The agent can parse the output, understand that a legitimate benchmark is running, and choose to wait or reschedule rather than hanging blindly.
* **Verdict:** The **v2 design (blocking by default + periodic diagnostics report + optional timeout override) is superior to the v1 fail-fast default.** It prevents false failures during long-duration runs while providing the necessary observability for autonomous agents.

---

## Verdict: PLAN-READY

With the addition of the **Prefix-based Environment Propagation** fix for the `sg` GID transition, the v2 design is robust, complete, and ready for implementation.

**VERDICT: PLAN-READY**
