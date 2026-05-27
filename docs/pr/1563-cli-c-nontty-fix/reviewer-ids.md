# Reviewer task IDs for #1563

Recorded so any future continuation can fetch results by ID rather
than re-dispatching.

## Plan review

| Round | Reviewer | Task ID | Verdict |
|-------|----------|---------|---------|
| 1 | Codex | task-mpnhw9dl-x9ci3c | PLAN-NEEDS-MAJOR |
| 1 | AGY | review-mpnhwj5s-pec4dp | PLAN-NEEDS-MINOR |
| 2 | Codex | task-mpni2ff9-799vbw | PLAN-NEEDS-MAJOR |
| 2 | AGY | review-mpni2nbc-yosv1u | PLAN-NEEDS-MINOR |
| 3 | Codex | task-mpni9hhz-88hm9u | PLAN-NEEDS-MINOR |
| 3 | AGY | review-mpni9pux-rhf7u6 | PLAN-NEEDS-MINOR |

## Code review (round 1 — post-PR-open)

Pending PR creation.

## Notes

- Round-2 critical finding (both reviewers): configLockInterceptor
  is a Unary Interceptor and doesn't fire on connection close, so
  `cli -c configure` would leak the daemon-side config lock unless
  we hard-error before issuing EnterConfigure.
- Round-2 Codex bonus finding: EnterConfigureExclusive sets
  `exclusiveHolder` not `configHolder`; ExitConfigureSession
  refuses to release exclusive locks. Pre-existing daemon bug,
  out-of-scope for #1563.
- Round-2 Codex bonus finding: `load` is not in operational
  dispatch, so `cli -c "load merge terminal"` is unreachable
  today. Bufio fallback dropped from plan.
- Round-3 AGY finding: confirmYes prompt-restoration must be
  configMode-aware (else `run request system reboot` from config
  mode would restore the wrong prompt).
- Plan v3 converged design: hard-error `configure` when c.rl==nil,
  factor confirmYes helper for destructive prompts, defensive
  nil-guards in dispatchConfig SetPrompt sites.
