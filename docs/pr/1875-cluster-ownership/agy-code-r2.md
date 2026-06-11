I will start by listing my permissions to understand what directories I can read.
I will run a git command to view the diff between `280e73a6f16c` and `b24f28a3fc44` in the target worktree directory to see the exact changes that need to be reviewed.
I will view the `test/incus/with-cluster.sh` file to see the implementation of the wrapper script.
I will view the `with-cluster.sh` file inside the worktree path `/home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/with-cluster.sh`.
I will view `cluster-lock.sh` to see the helper function definitions, in particular `xpf_cluster_lock_held`.
I will list the files in the repository using `git ls-files` to locate `cluster-setup.sh`, `apply-cos`, etc.
I will search for the relevant cluster setup and config files in the repository.
I will view the contents of `apply-cos-config.sh` to understand how it uses the locking mechanism.
I will view `cluster-setup.sh` to see how it locks/runs with-cluster.sh.
I will run a quick verification command to confirm how `env --` behaves when nesting another `env` with variable definitions.
I will run a quick verification command to confirm that exit status propagation with `|| rc=$?` behaves correctly under `set -euo pipefail`.
I will search for all references to `with-cluster.sh` in the repository to check if there are other callers.
I will view `wg-interop.sh` to check if and how it calls `with-cluster.sh`.
I will view the `reverse-key-collision-probe.sh` script to verify how it uses the locking mechanism.
I will view lines 61-120 of `reverse-key-collision-probe.sh`.
I will run the selftests for `with-cluster.sh` to confirm that all 10 cases pass successfully in the local worktree environment.
I will pause and wait for the background selftest task to complete.
I will run a command to verify the process tree structure when using `env --` to show that the `env` process replaces itself and does not remain in the tree as an intermediate parent of the target command.
I will run a command using `ps` to inspect the parent-child relationship and see if `env` stays in the process tree.
### Adversarial Review Delta Confirmation

We have verified the delta between commits `280e73a6f16c` and `b24f28a3fc44` in the target worktree at `/home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock`. The analysis indicates that the modifications are robust, address the targeted failure modes successfully, and do not regress the locking protocol or process mechanics.

---

### Key Areas Investigated

#### 1. Command Pinning with `env --` (Codex F1)
* **Reentrant & Acquiring Path Execution**: Running the target cell via `env -- "$@"` guarantees that the target is resolved and executed as an external binary. 
* **Builtin Rejection (Case i)**: Shell builtins (like `exec`, `eval`, etc.) are successfully rejected with exit status `127` because `env` cannot execute them. This prevents a command like `exec some-long-running-command` from replacing the wrapper shell process directly, which would have closed the lock file descriptor early and bypassed the `EXIT` cleanup trap.
* **Process Image Replacement (No Parent Bloat)**: Since `env` performs an `execve(2)` system call to launch the target command, it replaces its own process image rather than remaining in the process tree as a child. Our verification confirms that the target command runs as a **direct child** of the `with-cluster.sh` wrapper (PID-wise), preserving standard signal propagation and exit-status mapping exactly as if the command were executed directly.
* **Signal/Kill Behavior**: Because there is no intermediate `env` process left alive during execution, signals (e.g. `SIGINT`, `SIGTERM`, `SIGKILL`) sent to the child PID target the cell process directly.

#### 2. Composition with Script-Path Cells and Nested `env` Calls
* **`env -- env ...` Composition (Case h)**: In `cluster-setup.sh`, the re-exec boundary prepends an extra environment assignment `env XPF_CLUSTER_SKIP_BUILD=1`.
  * The outer `with-cluster.sh` executes: `env -- env XPF_CLUSTER_SKIP_BUILD=1 ...`
  * The first `env` treats the second `env` as the target command.
  * The second `env` parses the `XPF_CLUSTER_SKIP_BUILD=1` argument as an environment assignment, sets it, and executes the script.
  * This nested composition is standard, POSIX-compliant, and behaves correctly (verified in Case h).
* **Script-Path Cells**: For `apply-cos-config.sh`, `env --` resolves the script path, reads the shebang (`#!/usr/bin/env bash`), and spawns the shell interpreter as expected.

#### 3. Timeout Normalization (Codex F2)
* **The Octal Trap**: Restricting the `XPF_CLUSTER_LOCK_TIMEOUT` input to `^[0-9]{1,7}$` and prepending `10#` base-10 conversion prevents bash from interpreting values with leading zeros (like `08` or `09`) as invalid octal numbers.
* **Safe Degradation (Case j)**: Garbage inputs or absurdly large numbers (which could otherwise cause integer overflow in bash) fail the regex check and degrade cleanly to `0` (wait forever), which is the safest failure direction.

#### 4. Live Selftest Execution
We executed `./test/incus/with-cluster-selftest.sh` in the local worktree, and all 10 test cases passed successfully, confirming the live behavior of the new tests:
* **Case h**: Verifies marker + skip-build propagation across the `sg` re-exec boundary.
* **Case i**: Verifies shell builtins are rejected (127) without leaking owner metadata.
* **Case j**: Verifies timeout normalization (base-10 forcing and huge value degradation).

---

### Verdict

**VERDICT: MERGE-READY**
