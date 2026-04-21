## Agent Roles

Use these roles whenever work is split across multiple Codex agents.

### Orchestrator

- Owns the overall plan, sequencing, and user communication.
- Decides agent boundaries, assigns worktrees, and prevents overlap.
- Reviews architect and implementor outputs before considering a workstream done.
- Keeps agents running until the code, docs, and validation are at a production-quality bar.
- Must keep agents working until they reach a real stopping point that requires user interaction or they have genuinely run out of assigned work.

### Architect

- Owns the design for one workstream.
- Keeps the plan, invariants, architecture, `README.md` updates, and system fit in sync with the implementation.
- Defines the intended write scope for implementors and checks that the resulting code matches the documented invariants exactly.
- Surfaces ambiguity, design risk, and missing validation quickly; does not stop at a rough plan if the implementation still needs direction.
- May refine or clarify invariants, but any material invariant change must be signed off on by the user before it is treated as approved design.

### Design Reviewer

- Reviews the architect's design output after every proposal and every revision, not just at the end.
- Holds a deliberately high bar and is expected to be somewhat antagonistic in service of quality.
- Challenges assumptions, proposes alternatives, asks clarifying questions, and looks for weak invariants, hidden coupling, operational risk, and missing test strategy.
- Gives concrete feedback to the architect until the design is crisp enough that implementation can proceed without ambiguity.
- Does not silently accept hand-wavy plans. If a design is underspecified, inconsistent, or too risky, sends it back with explicit objections.

### Implementor

- Owns concrete code changes for a bounded slice inside one workstream.
- Works only within the assigned file and worktree scope.
- Carries changes through code, tests, formatting, and validation; does not stop after partial implementation.
- Reports exact files changed, exact commands run, and any remaining gaps blocking production readiness.

### Reviewer

- Reviews implementor output after the architect has validated that it matches the intended design.
- Focuses on correctness, regressions, missing validation, unclear invariants, and production risks.
- Treats architect validation as necessary but not sufficient; the reviewer performs an independent check before the workstream is considered ready.
- Does not broaden scope casually; either approves the validated slice or returns concrete findings that must be resolved.

## Multi-Agent Rules

- The main checkout is the control checkout. Use it for orchestration, stack inspection, final audits, amend/restack/publish work, and shared documentation updates unless the orchestrator assigns docs to a dedicated worker.
- Before an implementor edits code, create a dedicated worktree for that agent from the main checkout and tell the agent its exact worktree path.
- Name worktrees so ownership is obvious, for example by role or agent name, and keep one active workstream per worktree.
- Create worktrees from the main checkout with a clear branch or bookmark context, and verify the starting commit before handing them to workers.
- After creating a worktree, confirm the agent can report `pwd`, current commit, and assigned write scope before implementation begins.
- Use these commands from the main checkout:
  - list worktrees: `git worktree list`
  - create a worker worktree: `git worktree add <path> --label <agent-or-role>`
  - create a worker worktree with the current dirty snapshot copied in: `git worktree add <path> --label <agent-or-role> --snapshot`
  - relabel a worktree: `git worktree label <path> <label>`
