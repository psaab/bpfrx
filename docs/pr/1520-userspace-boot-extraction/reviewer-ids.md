# #1520 Reviewer IDs

Per-round reviewer task / job IDs for the triple-review skill.

## Plan review

### Round 1

- Codex task ID: `task-mpkuoz5b-87r2ey`
- Antigravity job ID: `adversarial-review-mpkuphrt-q6d0tm`

### Round 2 (fresh dispatch on c9d54271)

- Codex task ID: _bg task bf381q00x (codex exec, default model)_ — VERDICT PLAN-NEEDS-MAJOR, 9 findings; addressed in plan v3
- Antigravity job ID: `adversarial-review-mplbs7le-wwyo78` — VERDICT PLAN-NEEDS-MINOR (1 CRITICAL: existing AST canary collision); addressed in plan v4

### Round 3 (re-review on plan v3)

- Codex task ID: _bg task bwio39fci (codex exec)_ — VERDICT PLAN-NEEDS-MINOR (2 stale string findings); addressed in plan v4

## Code review (post-PR)

### Round 1 (PR #1550, HEAD e0a694ca)

- Codex task ID: _bg task bq4nf4oer (codex exec)_ — output empty (Codex CLI errored); re-dispatched as bqz009mtr (also empty); will re-dispatch round-2 on new HEAD
- Antigravity job ID: `adversarial-review-mplc57vw-e6chtv` — VERDICT MERGE-READY (8 findings clean, 1 minor coverage gap)
- Copilot review: COMMENTED — 2 inline wording nits (Boot() doc + buildRuntimeDataPlane doc); both addressed in round-2 commit

### Round 2 (after wording + coverage gap fixes, HEAD 9c532b05)

- Codex task ID: _bg task bodqke6ph (codex exec)_ — VERDICT MERGE-READY (no findings; all wording fixes confirmed; 3 quoted-line evidence items; all targeted tests pass)
- Antigravity job ID: `adversarial-review-mplcf05h-abqou8` — VERDICT MERGE-READY (8/8 invariants verified; clean rebase assessment)
- Copilot review: COMMENTED — 3 doc nits (stale legacy-caller list in Boot() doc + canary test docstring; README "only" wording); all addressed in round-3 commit

### Round 3 (after Copilot round-2 doc nits, HEAD 444a1959)

- Codex task ID: _bg task bzjreb3hv (codex exec)_ — VERDICT MERGE-READY (no findings; only docs/comments changed; targeted tests pass)
- Antigravity job ID: `adversarial-review-mplcpbnz-5avtoo` — VERDICT MERGE-READY (3 Copilot round-2 nits resolved; 8/8 invariants intact; doc-only change scope)
- Copilot review: COMMENTED with no new comments — implicit MERGE-READY

## Smoke matrix outcome

PASS — per-class v4/v6 × push/-R matrix on loss userspace cluster
on HEAD 444a1959. Best-effort 5201 at ~80 Mbps push (expected
low-priority CoS surplus floor); per-class shaping consistent
across v4/v6; reverse direction 6-8 Gbps across all classes. No
data-path regression observable.

## Notes

- Worktree: `/home/ps/git/bpfrx/.claude/worktrees/1520-userspace-boot-extraction`
- Branch: `refactor/1520-userspace-boot-extraction` (off `origin/master`)
- Sibling agents in flight: #1516, #1517, #1518, #1519, #1521.
  #1520 touches `pkg/dataplane/userspace/manager.go` (init + new
  Boot constructor) and `pkg/daemon/daemon_run.go` (wrapper).
  #1521 touches `pkg/dataplane/userspace/maps_sync.go`. No file
  overlap expected; reviewers should verify by walking the diff.
