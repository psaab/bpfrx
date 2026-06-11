No blocking findings.

Confirmed the requested v4 deltas in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1875-research/docs/research/1875-cluster-ownership/plan.md:110):

- The Path A summary now matches §7.2: exactly one long-lived, self-locking, marker-exporting holder, while standalone per-command `flock` holders remain valid and never export the marker.
- A2 step 3b now includes the `/proc/<recorded-pid>/fd/9` dev:ino probe and only aborts when that fd still resolves to the recorded lock inode.

I also checked the requested diff, searched for residual “exactly ONE”/fd wording conflicts, and ran `git diff --check`; no plan-design regression found. Minor non-blocking note: §1 still says `DRAFT v3`, but the v4 status header is clear and this does not affect the reviewed invariants.

VERDICT: PLAN-READY

Codex session ID: 019eb8ba-0ee9-7dd2-af3f-0008a2b7cc00
Resume in Codex: codex resume 019eb8ba-0ee9-7dd2-af3f-0008a2b7cc00
