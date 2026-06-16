# PR #1937 — reviewer task IDs

DOCS-ONLY: README getting-started restructure + move reference content to docs/.

- **AGY adversarial-review**:
  - round 1: `adversarial-review-mqh8v4z5-l38w5l`
  - round 2 (re-review after fixes): `adversarial-review-mqh96ku5-9qlg7o`
  - (background, base origin/master, cwd = worktree readme-gs). Results
    under `~/.claude/plugins/data/agy-claude-code-agy/state/jobs/<id>.result.md`.
- **Codex**: run non-interactively via the `codex` CLI (`codex exec
  --skip-git-repo-check -C <worktree> < prompt`); the run is not a
  codex-review-plugin workflow, so it has no plugin task id. Round-1
  verdict and findings are recorded in the PR review-response comment.
- **Copilot**: requested via `gh pr edit 1937 --add-reviewer Copilot`
  (rounds 1 and 2).
