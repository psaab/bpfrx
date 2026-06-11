**Findings**

1. `Codex r2 F2` is only partially folded. §7.2 is corrected, but the earlier Path A summary still says: “v2 therefore has exactly ONE process that ever holds the lock: `with-cluster.sh`” at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1875-research/docs/research/1875-cluster-ownership/plan.md:108). That directly contradicts the intended v3 invariant at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1875-research/docs/research/1875-cluster-ownership/plan.md:345), which correctly allows standalone per-command `flock` holders that never export the marker. This is a small text fix, not a design rejection, but it leaves the exact r2 overstatement alive in §5.

**§13 Answer**

The A2-3b false-positive surface is acceptable under the stated cooperating-agent, single-host model. It requires stale owner metadata from wrapper SIGKILL, pid reuse before the next acquire, and a still-live recycled pid at acquire time; the failure direction is refuse-and-diagnose, not silent concurrent mutation.

Cheap optional hardening: before aborting on live pid + mismatched recorded dev:ino, verify `/proc/<pid>/fd/9` still resolves to the recorded dev:ino. That directly proves the recorded holder still has the old lock fd and cheaply defeats most pid-reuse false positives. I would treat this as optional, not blocking.

Other v3 deltas look sound: lock-boundary movement, `$SCRIPT_DIR/cluster-setup.sh`, sg env forwarding plus §9.2d, dev:ino split detection, `apply-cos-config.sh` self-locking, and blocking-default resolution all match the r2 findings.

VERDICT: PLAN-NEEDS-REVISION

Codex session ID: 019eb8b2-dfe2-7602-b453-3479ae2711a4
Resume in Codex: codex resume 019eb8b2-dfe2-7602-b453-3479ae2711a4
