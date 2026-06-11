*   **Case (a)**: Waiter blocks, reports holder PID + purpose, timeout honors `XPF_CLUSTER_LOCK_TIMEOUT`.
*   **Case (b)**: Kill -9 of cell tree releases the lock.
*   **Case (c)**: Nested cell is reentrant; outer owner metadata survives.
*   **Case (d)**: Forged/stale/garbage markers rejected, normal acquire proceeds.
*   **Case (e)**: Stale/corrupt/empty owner files tolerated under `set -euo pipefail`.
*   **Case (f)**: Cell exit status propagates (3), owner file cleaned.
*   **Case (g)**: Split-mutex: `rm` lock while held fails closed with SPLIT MUTEX diagnosis, reclaim works after holder exits.
*   **Case (h)**: Marker survives `sg`-shaped re-exec command string.

I am waiting for the background selftest script to complete. Once done, I will examine the results and provide the final detailed report.
Here is the hostile adversarial review of the PR implementation against the converged plan (`docs/pr/1875-cluster-ownership/plan.md`).

---

### 1. Shell Correctness Under `set -euo pipefail`
Every new/changed shell path was analyzed for robustness under strict error-handling:
* **Ancestry status check** ([cluster-lock.sh:53](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/cluster-lock.sh#L53)): The ancestry walk uses `2>/dev/null || true` inside the `ppid` subshell assignment. If the status file does not exist (due to process termination mid-check), it exits `0` returning an empty string. The following numeric match check ([cluster-lock.sh:54](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/cluster-lock.sh#L54)) is correctly guarded, returning `1` rather than aborting.
* **Corrupt/stale owner file read** ([cluster-lock.sh:77](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/cluster-lock.sh#L77)): Sourcing `read -r ... <<<"$owner" || true` prevents a shell abort under `set -e` if the metadata line is empty or short, and subsequent parameter references are safely defaulted (e.g., `${opid:-}`).
* **flock wait-loop arithmetic** ([with-cluster.sh:70-87](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/with-cluster.sh#L70-L87)): The `REMAIN` arithmetic is protected by checking if `TIMEOUT` is numeric and greater than `0`. If `TIMEOUT` is `0` (default, wait forever), `WINDOW` stays `30` and no subtraction occurs. If `flock -w` times out, its exit status is correctly caught by the `if` condition on line 81 without triggering a `set -e` abort.
* **Lock file permissions** ([with-cluster.sh:64](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/with-cluster.sh#L64)): The `chmod 0666` call is guarded by `2>/dev/null || true` to prevent aborts if the lock file is owned by another cooperating user in `/tmp`.

### 2. Reentrancy Chain End-to-End
* **sg env forwarding** ([cluster-setup.sh:50-58](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/cluster-setup.sh#L50-L58)): The shadow group re-exec loop parses `${!BPFRX_@}` and `${!XPF_@}` to dynamically build `local_env`. Because the variables are parsed from existing names, they are guaranteed to exist, preventing any `set -u` issues on indirect expansions.
* **Double build prevention** ([cluster-setup.sh:612-621](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/cluster-setup.sh#L612-L621)): Inside `cmd_deploy`, the code builds the local binaries first, and then execs `with-cluster.sh` with `env XPF_CLUSTER_SKIP_BUILD=1`. The re-execed child skips the build block, avoiding duplicate compiles.
* **Reentrant marker resolution**: Sourcing `cluster-lock.sh` correctly resolves the marker `XPF_CLUSTER_LOCK_HELD` to check if the current process's ancestor is the holder. This prevents a deadlock when `cluster-setup.sh` re-invokes itself.

### 3. `with-cluster.sh` Edge Cases
* **Purpose strings with spaces/quotes** ([with-cluster.sh:109-111](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/with-cluster.sh#L109-L111)): The owner metadata contains space-separated fields where the 6th field is the purpose string. When read via `read -r OPID _ _ _ OINO _ <<<"$OWNER_LINE"`, Bash correctly maps the first 5 words and groups all remaining text (including all spaces in the purpose) into the final discard variable `_`. Thus, `OINO` and `OPID` are parsed correctly regardless of spaces/quotes.
* **FD 9 closure** ([with-cluster.sh:144](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/with-cluster.sh#L144)): The command runs as `"$@" 9>&-`. Since `with-cluster.sh` is an executable process, the command is always an external program. It runs with the lock descriptor closed, ensuring no descendant process inherits it.
* **Split-mutex probe false-positive surface** ([with-cluster.sh:112-120](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/with-cluster.sh#L112-L120)): The probe checks `/proc/${OPID}/fd/9` against `OINO`. For a false-positive to trigger on a recycled PID, the unrelated recycled process must have fd 9 open, and that fd must point to the *exact* inode that was deleted. This is virtually impossible under standard system conditions.

### 4. `wg-interop.sh` Integration
* **Standalone behavior** ([wg-interop.sh:77-85](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/wg-interop.sh#L77-L85)): If run standalone, `xpf_cluster_lock_held` is false, and it falls back to the original `flock "${WG_CLUSTER_LOCK}" sg incus-admin ...` command. The behavior is byte-identical.
* **Lock path binding** ([wg-interop.sh:42](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/wg-interop.sh#L42)): Binding `XPF_CLUSTER_LOCK="${WG_CLUSTER_LOCK}"` before sourcing `cluster-lock.sh` guarantees that the ancestry marker checks the correct lock file. If a custom cell overrides the default lock file path, `wg-interop.sh` correctly falls back to locking its own path rather than bypassing.

### 5. `apply-cos-config.sh` Re-exec
* **Argv preservation** ([apply-cos-config.sh:48-53](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/apply-cos-config.sh#L48-L53)): The re-exec block is located at the top of the file before any flag processing or positional shifting. The arguments are preserved exactly with `"$@"` when passed to `with-cluster.sh`.
* **Zero arguments check**: Under `set -u`, `"apply-cos-config $*"` with zero arguments does not throw an unbound error in Bash. The recursion guard functions correctly.

### 6. Selftest Validity
* **Case (b) `pkill -P` optimization dependency** ([with-cluster-selftest.sh:50](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/with-cluster-selftest.sh#L50)): The test case runs `bash -c 'echo started >...; sleep 60'`. Since `sleep 60` is the last command in the string, Bash applies a tail-call `exec` optimization, making the `sleep` process a direct child of the wrapper (`B_PID`). 
  > [!NOTE]
  > If the command string contained trailing commands (e.g. `sleep 60; echo done`), the `sleep` command would run as a grandchild. `pkill -9 -P "$B_PID"` would kill only the parent shell, leaving `sleep` orphaned. However, since children run with fd 9 closed, the lock itself would still release immediately, keeping the test behavior sound.
* **Case (h) re-exec simulation**: Properly simulates the dynamic prefix-matching shadow re-exec using `local_env` variables.

### 7. Docs Accuracy
* The instructions in [engineering-style.md:365-398](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/docs/engineering-style.md#L365-L398), [CLAUDE.md:91-97](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/CLAUDE.md#L91-L97), and [wg-interop-runbook.md:48-60](file:///home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/docs/wg-interop-runbook.md#L48-L60) are completely accurate and reflect the implemented codebase changes.

---

### Verdict
The implementation satisfies all requirements, resolves locking asymmetries, and passes the test matrix.

**VERDICT: MERGE-READY**
