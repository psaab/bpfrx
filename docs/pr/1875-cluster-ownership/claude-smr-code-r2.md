# Claude SMR hostile code review — PR #1878 r2 (delta over b24f28a3fc44)

Reviewer: Claude (in-conversation SMR). Scope: the Codex code-r1 fix
commit. Honest note first: SMR r1 passed both paths Codex F1/F2
flagged — the builtin-cell escape and the octal timeout — which is
exactly the SMR-soft-pass pattern this project documents. The r2 walk
below was done against that bias.

## Verdict: MERGE-READY

- **`env --` pinning (F1)**: checked every in-tree cell producer for
  regression: cluster-setup's re-exec cell becomes `env -- env
  XPF_CLUSTER_SKIP_BUILD=1 cluster-setup.sh deploy <t>` (nested env is
  well-defined); apply-cos passes an absolute script path; the
  selftest passes `bash -c`/`sg`/`true`/`sleep`; the runbook examples
  pass `env`/`bash -c`. No caller relied on builtin/function
  execution (impossible by design — a cell is a process). The
  reentrant path's `exec env -- "$@"` keeps reentrant and acquiring
  semantics identical. Selftest (i) pins the 127-with-lock-intact
  contract, including post-rejection reclaim.
- **Timeout normalization (F2)**: `^[0-9]{1,7}$` then `10#` — "08"
  becomes 8 (case j proves acquire succeeds at the 4s holder exit and
  no arithmetic error text leaks); a 20-digit value degrades to
  wait-forever and case j proves it cannot block a free lock. The
  degrade direction (wait, never skip/crash) matches invariant §7.3.
- **Selftest h (F3)**: the inner block is a verbatim transplant of
  cluster-setup.sh's forwarding loop, and on this host it crossed a
  REAL `sg incus-admin -c` boundary (verified in the live run — the
  host has the group, so the sg branch executed). Asserts all three
  classes of forwarded state: the marker, the skip-build flag, and a
  BPFRX_* variable.
- **Case b comment (F4)**: now states exactly what is proven
  (wrapper death = lock release; deep orphans cannot hold).
- Full selftest re-ran live post-fix: ALL 10 CASES PASS. bash -n +
  shellcheck -x clean.

No new findings. The live-cluster validation from r1 (self-locking
deploy, build identity g280e73a6f, CoS re-apply, shaped/uncapped
iperf3) predates the fix commit but the fix touches only with-cluster
internals + selftest, both re-proven by the matrix; the deploy path's
behavior is unchanged (env-- composes transparently).
