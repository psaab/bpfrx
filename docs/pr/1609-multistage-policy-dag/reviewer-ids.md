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

### Round 3 (v2 round 1 — Multi-Book LPM + staged delivery, user override)

- **Codex**: `task-mpp07r70-gr5xtw` — PLAN-NEEDS-MAJOR (10 numbered findings F1-F10)
- **AGY**: `adversarial-review-mpp08612-zcapi3` — PLAN-NEEDS-MAJOR (4 Class-A fatals F1.1-F1.4 + 2 Class-B nits)
- **Claude SMR r3**: `docs/pr/1609-multistage-policy-dag/claude-smr-plan-r3.md` — PLAN-READY-WITH-NITS (soft-pass, REVERSED in r4)
- **Claude SMR r4**: `docs/pr/1609-multistage-policy-dag/claude-smr-plan-r4.md` — PLAN-NEEDS-MAJOR (3-of-3 convergence with Codex + AGY)
- **Copilot**: posts on PR creation; not applicable to plan reviews

**Verdict**: 3-of-3 PLAN-NEEDS-MAJOR convergent. 6 fatals + 6 majors enumerated in r4. Architectural axis (Multi-Book LPM + sorted postings + galloping merge) remains sound; v2 concrete design has fatal patchable issues. Deferred to future planning session (ideally after #1612 lands measurement).

### Round 5 (v3 round 1 — Multi-Book LPM 5-fix, memory budget RELAXED per user override)

- **Codex**: pending (will dispatch with v3 SHA)
- **AGY**: pending (will dispatch with v3 SHA)
- **Claude SMR r5**: `docs/pr/1609-multistage-policy-dag/claude-smr-plan-r5.md` — PLAN-NEEDS-MINOR (4 residual issues F-r5-1 through F-r5-4 enumerated; hostile self-review to avoid r3-style soft-pass)
- **Copilot**: posts on PR creation; not applicable to plan reviews
