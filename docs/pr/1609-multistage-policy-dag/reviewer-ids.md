# Reviewer task IDs — #1609 multi-stage policy DAG

Track Codex + AGY task IDs per round so continuations can fetch
results by ID if the Companion CLI session state is lost
(per `feedback_codex_session_loss_continuation`).

## Plan reviews

### Round 1 (v1 of plan.md)

- **Codex**: `task-mpovhqw1-mcdu2a` (session lost — retried as `task-mpow930q-op3gid`, PLAN-NEEDS-MAJOR delivered as source-availability-limited review per sandbox infra failure)
- **AGY**: `adversarial-review-mpoviaz0-v46siz` — PLAN-NEEDS-MAJOR
- **Claude SMR**: `docs/pr/1609-multistage-policy-dag/claude-smr-plan-r1.md` — PLAN-NEEDS-MAJOR
- **Copilot**: posts on PR creation; not applicable to plan reviews

### Round 2 (convergence + BLOCKED determination)

- **Claude SMR**: `docs/pr/1609-multistage-policy-dag/claude-smr-plan-r2.md` — PLAN-NEEDS-MAJOR + BLOCKED-on-#1612 for production framing
