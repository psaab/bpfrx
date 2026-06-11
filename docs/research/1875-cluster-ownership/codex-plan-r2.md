**Findings**

1. **Revision needed: deploy has a pre-build shared-host mutation that v2 would leave outside the lock.**  
   The plan says the `cmd_deploy` re-exec happens after the local build: [plan.md:189](/home/ps/git/bpfrx/.claude/worktrees/1875-research/docs/research/1875-cluster-ownership/plan.md:189) and [plan.md:306](/home/ps/git/bpfrx/.claude/worktrees/1875-research/docs/research/1875-cluster-ownership/plan.md:306). But current `cmd_deploy` runs `suppress_host_parent_ipv6_ra` before the build at [cluster-setup.sh:583](/home/ps/git/bpfrx/.claude/worktrees/1875-research/test/incus/cluster-setup.sh:583), and that helper mutates host network state via `sysctl`, address flush, and route flush at [cluster-setup.sh:126](/home/ps/git/bpfrx/.claude/worktrees/1875-research/test/incus/cluster-setup.sh:126), [cluster-setup.sh:130](/home/ps/git/bpfrx/.claude/worktrees/1875-research/test/incus/cluster-setup.sh:130), and [cluster-setup.sh:135](/home/ps/git/bpfrx/.claude/worktrees/1875-research/test/incus/cluster-setup.sh:135).  
   Recommendation: make `cmd_deploy` do only target validation and local build before lock acquisition; after the reentrant continuation, run `suppress_host_parent_ipv6_ra` and all deploy mutations under the marker.

2. **The “exactly one process ever holds the lock fd” invariant is overstated.**  
   v2 says only `with-cluster.sh` ever holds the lock at [plan.md:108](/home/ps/git/bpfrx/.claude/worktrees/1875-research/docs/research/1875-cluster-ownership/plan.md:108) and [plan.md:310](/home/ps/git/bpfrx/.claude/worktrees/1875-research/docs/research/1875-cluster-ownership/plan.md:310). But A4 intentionally keeps standalone `wg-interop.sh` as `flock "${WG_CLUSTER_LOCK}" sg ...` at [plan.md:222](/home/ps/git/bpfrx/.claude/worktrees/1875-research/docs/research/1875-cluster-ownership/plan.md:222), matching current code at [wg-interop.sh:67](/home/ps/git/bpfrx/.claude/worktrees/1875-research/test/incus/wg-interop.sh:67). The plan also says raw per-command flock remains valid at [plan.md:249](/home/ps/git/bpfrx/.claude/worktrees/1875-research/docs/research/1875-cluster-ownership/plan.md:249).  
   Recommendation: restate this as “`with-cluster.sh` is the only long-lived/self-locking script holder and the only holder that exports the marker.” Standalone per-command `flock` holders still exist and must never set the marker.

3. **The test matrix should pin the exact `sg` re-exec, not just a generic env-preserving boundary.**  
   The plan relies on marker survival through `sg` at [plan.md:209](/home/ps/git/bpfrx/.claude/worktrees/1875-research/docs/research/1875-cluster-ownership/plan.md:209), while the actual script rebuilds the command string and only explicitly prepends `BPFRX_CLUSTER_ENV` at [cluster-setup.sh:42](/home/ps/git/bpfrx/.claude/worktrees/1875-research/test/incus/cluster-setup.sh:42) through [cluster-setup.sh:46](/home/ps/git/bpfrx/.claude/worktrees/1875-research/test/incus/cluster-setup.sh:46). I tested util-linux `sg` 2.41.3 here and it does preserve exported `XPF_CLUSTER_LOCK_HELD` and `XPF_CLUSTER_SKIP_BUILD`, so I do not see a functional hole. But §9.2d should explicitly exercise the actual `sg incus-admin -c "${local_env}$(printf '%q ' "$0" "$@")"` shape and verify both marker survival and skip-build/double-build avoidance.

**§12 Answers**

1. Keep post-acquire inode revalidation. It is cheap and directly addresses the unlink/split-lock class. I would compare `dev:ino`, not just inode, but the design direction is right.

2. The `exec with-cluster.sh ... -- env XPF_CLUSTER_SKIP_BUILD=1 "$0" deploy "$target"` shape is mostly sound: array argv avoids re-quoting issues, `BPFRX_CLUSTER_ENV` passes through, and `sg` preserves exported env on this host. Prefer `"$SCRIPT_DIR/cluster-setup.sh"` over `"$0"` for the re-exec to avoid PATH/symlink oddities.

3. Deprecating raw outer-flock for self-locking verbs is acceptable. A compat `flock -n` probe is unreliable because it cannot distinguish “my caller holds it” from “someone else holds it,” and a free-at-probe instant proves nothing. Update the two current teachers; at this commit they still show raw flock at [reverse-key-collision-probe.sh:47](/home/ps/git/bpfrx/.claude/worktrees/1875-research/test/incus/reverse-key-collision-probe.sh:47) and [wg-interop-runbook.md:48](/home/ps/git/bpfrx/.claude/worktrees/1875-research/docs/wg-interop-runbook.md:48).

4. I do not have a counterexample where two cooperating processes both hold the same canonical flock, assuming no cooperating process removes/recreates the lock file and all acquirers use the same path. Kernel exclusive `flock` prevents that. The weaker residual is early release if only the wrapper dies while children continue, but v2 explicitly accepts no process-group management at [plan.md:387](/home/ps/git/bpfrx/.claude/worktrees/1875-research/docs/research/1875-cluster-ownership/plan.md:387); that is concurrent mutation by a non-holder, not two lock holders.

I also re-judge AGY’s timeout objection in favor of v2: block-by-default is the right default with 25-40 minute legitimate measurement cells. A default 300s abort would make false failures routine and would push agents toward bypass attempts. Periodic holder reports plus optional `XPF_CLUSTER_LOCK_TIMEOUT` is the better operator/agent affordance.

VERDICT: PLAN-NEEDS-REVISION

Codex session ID: 019eb8ab-7fb8-71c2-8e2c-9255767e746c
Resume in Codex: codex resume 019eb8ab-7fb8-71c2-8e2c-9255767e746c
