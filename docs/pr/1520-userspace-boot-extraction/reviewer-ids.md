# #1520 Reviewer IDs

Per-round reviewer task / job IDs for the triple-review skill.

## Plan review

### Round 1

- Codex task ID: _pending dispatch_
- Antigravity job ID: _pending dispatch_

### Round 2

- Codex task ID: _n/a_
- Antigravity job ID: _n/a_

## Code review (post-PR)

### Round 1

- Codex task ID: _pending_
- Antigravity job ID: _pending_
- Copilot review: _pending_

## Notes

- Worktree: `/home/ps/git/bpfrx/.claude/worktrees/1520-userspace-boot-extraction`
- Branch: `refactor/1520-userspace-boot-extraction` (off `origin/master`)
- Sibling agents in flight: #1516, #1517, #1518, #1519, #1521.
  #1520 touches `pkg/dataplane/userspace/manager.go` (init + new
  Boot constructor) and `pkg/daemon/daemon_run.go` (wrapper).
  #1521 touches `pkg/dataplane/userspace/maps_sync.go`. No file
  overlap expected; reviewers should verify by walking the diff.
