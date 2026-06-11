# Adversarial Plan Review: xpf Issue #1875 (Cluster Ownership Serialization)

This document provides a hostile, pressure-tested review of the proposed serialization plan for the shared loss userspace cluster.

---

## 1. The flock Mechanics & Deadlock Proof

### A. Inner flock Deadlock
The plan's claim that outer-wrapping `wg-interop.sh` in `flock /tmp/xpf-cluster.lock` causes a deadlock is **100% technically correct**. 

In Linux/Unix, `flock` locks are associated with the **open file description** (created via `open()`), not the file path or the process ID.
1. When the parent/caller runs `flock /tmp/xpf-cluster.lock ...`, it opens the file, gets an open file description, and locks it.
2. When the child script calls `inc()`, it executes `flock "${WG_CLUSTER_LOCK}" sg incus-admin -c "$q"`. This spawns a new `flock` process which opens the same path `/tmp/xpf-cluster.lock` anew.
3. Because the new `flock` process opens the file independently, it gets a **new open file description**. It then attempts to acquire an exclusive lock and is blocked by the parent's lock on the first open file description, resulting in an indefinite deadlock.

### B. Child inheritance and fd 9 closure (`"$@" 9>&-`)
The plan proposes running the cell command with fd 9 closed: `"$@" 9>&-`.
* **Does it prevent inheritance?** Yes. Redirection `9>&-` closes fd 9 at the child process boundary. Consequently, neither the child nor any grandchildren spawned by it will have fd 9 open.
* **Why this is superior to the CLI `flock` tool:** The standard `flock` command-line tool (e.g., `flock /tmp/xpf-cluster.lock cmd`) executes the command as a child while keeping its lock fd open. If `cmd` backgrounds a long-running process (like a daemon or tunnel), that background process inherits the open lock fd. Even if `flock` and `cmd` both exit, the lock remains held by the background process. By managing the file descriptor ourselves in the shell (`exec 9>>file; flock 9`) and explicitly closing it for children (`9>&-`), any backgrounded child processes are stripped of the fd. If the wrapper script is killed, the kernel automatically closes the wrapper's copy of fd 9, immediately releasing the lock.
* **Subshell edge cases:** In Bash, subshells (`(...)`) inherit all file descriptors from the parent. However, since the wrapper closes fd 9 at the boundary of `"$@"`, no subshell spawned *inside* the child command will ever receive fd 9 in the first place.

---

## 2. The Deadlock and Double-Release Matrix

Let's evaluate every combination of **A2** (cell wrapper), **A3** (deploy self-lock), and **A4** (`inc()` locking):

| Outer Context | Inner Command | Reentrancy State | Result |
| :--- | :--- | :--- | :--- |
| **A2** (`with-cluster.sh`) | **A3** (`cluster-setup.sh deploy`) | `XPF_CLUSTER_LOCK_HELD` is set to parent PID. A3 sources A1, sees the env marker, and NO-OPs the lock. | **Safe / Lock-Free Bypass** (No deadlock). |
| **A2** (`with-cluster.sh`) | **A4** (`wg-interop.sh` `inc()`) | `XPF_CLUSTER_LOCK_HELD` is set. A4's `inc()` bypasses flock and runs `sg` directly. | **Safe / Lock-Free Bypass** (No deadlock). |
| **A3** (`cluster-setup.sh deploy`) | **A4** (`wg-interop.sh` `inc()`) | `XPF_CLUSTER_LOCK_HELD` is set to A3's PID. Since A3 does not call A4 directly, this is a non-issue. But if it did, A4 would skip locking. | **Safe**. |
| **A4** (`wg-interop.sh`) | **A3** (`cluster-setup.sh deploy`) | Standalone A4 does not call A3. | **N/A**. |

### Double-Release / Stale Metadata Wipe Vulnerability
If a nested process (like `cluster-setup.sh deploy` called inside a `with-cluster.sh` cell) sources `cluster-lock.sh` and exits, we must ensure it does **not** run any cleanup traps.
* **Risk:** If the sourced library blindly installs an `EXIT` trap to delete `/tmp/xpf-cluster.owner`, then when the nested `cluster-setup.sh` exits, its trap will execute and delete the owner file, even though the parent cell still holds the lock!
* **Correction:** The `EXIT` trap to clean up `/tmp/xpf-cluster.owner` must **only** be registered by the process that *successfully acquired* the lock (i.e., when `XPF_CLUSTER_LOCK_HELD` was not previously set). If the lock acquisition is bypassed, the trap registration must be skipped.

---

## 3. Reentrancy-by-Env (`XPF_CLUSTER_LOCK_HELD`) Leak Analysis

The environment variable `XPF_CLUSTER_LOCK_HELD` is highly susceptible to leakage:
* **The Leak Scenario:** A cell wrapper `with-cluster.sh` runs a test suite. The test suite backgrounds a persistent helper process (e.g., a logging daemon, proxy, or tunnel). This daemon inherits the environment, including `XPF_CLUSTER_LOCK_HELD=12345`.
* **The Stale-Marker Failure:** The test suite finishes and `with-cluster.sh` exits, releasing the lock. Hours later, the background daemon (still running) executes a script that calls `cluster-setup.sh` or `wg-interop.sh`. These scripts see `XPF_CLUSTER_LOCK_HELD=12345` and **NO-OP the lock**, running completely unprotected while not actually holding the lock!

### Solution: Ancestor Liveness Check
To make the reentrancy marker robust, the check must verify that the lock holder PID is both **alive** and is an **ancestor** of the current process.

We should define an ancestry check function that traverses parent PIDs via `/proc/$PID/status` (immune to spaces/parentheses in process names):

```bash
is_lock_holder_ancestor() {
    local target_pid="${XPF_CLUSTER_LOCK_HELD:-}"
    [[ -z "$target_pid" || ! "$target_pid" =~ ^[0-9]+$ ]] && return 1
    
    # Verify the target process is actually alive
    kill -0 "$target_pid" 2>/dev/null || return 1
    
    local curr_pid=$$
    while [[ "$curr_pid" -gt 1 ]]; do
        if [[ "$curr_pid" -eq "$target_pid" ]]; then
            return 0
        fi
        local ppid=""
        if [[ -r "/proc/${curr_pid}/status" ]]; then
            ppid=$(awk '/^PPid:/ {print $2}' "/proc/${curr_pid}/status" 2>/dev/null)
        fi
        if [[ -z "$ppid" || ! "$ppid" =~ ^[0-9]+$ ]]; then
            break
        fi
        curr_pid="$ppid"
    done
    return 1
}
```

Then, the check becomes:
```bash
if is_lock_holder_ancestor; then
    # Reentrant case: skip lock acquisition
    return 0
fi
```
This is **not YAGNI**; it is a critical process-hardening requirement to prevent silent lock bypasses.

---

## 4. `set -euo pipefail` Pitfalls

Writing shell lock libraries under `set -euo pipefail` introduces several subtle failure modes:

### A. Redirection Race Condition
The planned owner file read:
`read pid ts user branch purpose < "$XPF_CLUSTER_OWNER"`
* **The Bug:** If another process releases the lock and deletes `$XPF_CLUSTER_OWNER` in the split-second between the waiter's file-existence check and the redirection, the redirection `<` will fail. Under `set -e`, a redirection failure on a non-existent file terminates the script immediately!
* **The Fix:** Read the content safely using `cat` and a Here-String:
  ```bash
  local owner_content
  owner_content=$(cat "$XPF_CLUSTER_OWNER" 2>/dev/null || true)
  if [[ -n "$owner_content" ]]; then
      read -r holder_pid holder_time holder_user holder_branch holder_purpose <<< "$owner_content"
  fi
  ```

### B. Trap Clobbering
Sourcing `cluster-lock.sh` directly in scripts like `cluster-setup.sh` risks overwriting existing traps.
* **The Bug:** If a caller script has its own `EXIT` trap, sourcing `cluster-lock.sh` and executing `trap 'rm -f $XPF_CLUSTER_OWNER' EXIT` will clobber the caller's trap.
* **The Fix:** Use a trap-appending helper in the sourced library:
  ```bash
  append_exit_trap() {
      local cmd="$1"
      local existing
      existing=$(trap -p EXIT)
      if [[ -z "$existing" ]]; then
          trap "$cmd" EXIT
      else
          local existing_cmd
          existing_cmd=$(echo "$existing" | sed -e "s/^trap -- '//" -e "s/' EXIT$//")
          trap "${existing_cmd}; ${cmd}" EXIT
      fi
  }
  ```

### C. `kill -0` on invalid PIDs
If the owner file is empty or corrupted, checking `kill -0 "$pid"` will return a non-zero status or syntax error. Under `set -e`, this must be strictly guarded:
`[[ "$holder_pid" =~ ^[0-9]+$ ]] && kill -0 "$holder_pid" 2>/dev/null`

---

## 5. Adoption Realism

* **Does hooking `cmd_deploy` capture all paths?** Yes. `Makefile` targets `cluster-deploy` and `userspace-cluster-deploy` expand to:
  `BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/cluster-setup.sh deploy $(NODE)`
  Since `cluster-setup.sh` handles all mutating command dispatches, hooking `cmd_deploy`, `cmd_create`, `cmd_destroy`, `cmd_start`, `cmd_stop`, and `cmd_restart` inside `cluster-setup.sh` covers 100% of automated and manual deploy vectors.
* **Bypasses:** Standard operations like direct `incus file push` by an operator bypass this harness. This is acceptable under the *cooperating same-host agents* assumption, provided CLAUDE.md is updated to direct agents to use the standard tools.

---

## 6. Answers to §11 Open Questions

### Q1: Is Path C (docs-only) sufficient?
**No.** Relying entirely on conventions has already failed because the default `make cluster-deploy` path does not enforce it. A convention that is not enforced by the default tooling is not a convention. We need the mechanism to backstop LLM errors.

### Q2: Blocking vs fail-fast default for deploy
**Fail-fast with a reasonable timeout.** Unattended agents should not block indefinitely (e.g. `flock` without timeout), nor should they immediately abort on transient 1-second contention. 
* **Recommendation:** Use a 5-minute timeout: `flock -w 300 9`. If the lock is held beyond 5 minutes (indicating an active measurement cell), abort loudly with a clear stderr diagnostic so the agent can reschedule.

### Q3: fd-close tradeoff (A2)
**Keep `9>&-` (close-fd) for the child.** The risk of a stuck daemon permanently holding the lock (3-hour diagnose cycle) is worse than releasing the lock early when a wrapper is SIGKILLed. 
* **Recommendation:** Keep the `9>&-` close redirection. To prevent early release, ensure `with-cluster.sh` runs the child in a new process group and registers a `TERM` trap to clean up the process group on normal termination:
  ```bash
  trap 'kill -TERM -$$ 2>/dev/null' EXIT INT TERM
  ```

### Q4: Reentrancy via env leak
**Mandatory PID + ancestor check.** As analyzed in Section 3, simple env checking is highly vulnerable to stale markers from background processes. The ancestor liveness check is required.

### Q5: Should `create`/`destroy` lock?
**Yes.** Raced network or VM creation/deletion will corrupt the global Incus profile and bridges. 
* **Recommendation:** Lock them by default, but provide an escape hatch environment variable `XPF_CLUSTER_FORCE=1` to bypass the lock check during manual operator disaster recovery.

### Q6: Owner-file location/permissions
**Use `/tmp` with `chmod 0666` hygiene.** While the Sticky Bit on `/tmp` prevents deletion of files by other users, it does not prevent reading or writing if permissions are permissive.
* **Recommendation:** Initialize `/tmp/xpf-cluster.owner` and `/tmp/xpf-cluster.lock` with `chmod 0666` (or `umask 000` during creation) so that different user accounts (e.g., human `ps` vs automated CI/test runners) can contend on the same lock and update the diagnostics file.

---

## Verdict: PLAN-NEEDS-REVISION

The general direction of the plan is correct, but it requires critical revisions to address reentrancy env leakage, trap clobbering, redirection race conditions under `set -e`, and multi-user permissions.
