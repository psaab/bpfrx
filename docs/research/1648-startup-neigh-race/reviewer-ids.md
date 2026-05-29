# #1648 reviewer task-id ledger

Per `feedback_codex_session_loss_continuation`: record every reviewer task-id
here so a continuation can re-fetch by id rather than re-dispatch.

## Round 1

| Reviewer | Task ID | Verdict | Doc |
|---|---|---|---|
| Codex | workflow 20260529-074550-6bad9c (plan r1) | Not-PLAN-READY r1; 2C/4H/3M/1L all ACCEPTED | codex-plan-r1.md |
| AGY | adversarial-review-mpqmaa6j-2dgeki | READY for Gate-R; seq=0 drop = root cause | agy-plan-r1.md |
| Claude SMR | n/a (in-conversation) | PLAN-NEEDS-REVISION r1 → addressed in v2 | claude-smr-plan-r1.md |

## Round 2 (v2)
| Reviewer | Task ID | Verdict | Doc |
|---|---|---|---|
| Codex | workflow 20260529-074550-6bad9c (plan r2) | Not-PLAN-READY; 1C/4H/2M/1L ACCEPTED | codex-plan-r2.md |
| AGY | adversarial-review-mpqmob0t-c2m30p | PLAN-NEEDS-REVISION (startup-only finding) | agy-plan-r2.md |
| Claude SMR | n/a | PLAN-READY on v2 scope (superseded by AGY r2) | claude-smr-plan-r2.md |

## Round 3 (v3.1)
| Reviewer | Task ID | Verdict | Doc |
|---|---|---|---|
| Codex | workflow 20260529-074550-6bad9c (plan r3) | Not-PLAN-READY; 2C/3H/2M ACCEPTED | codex-plan-r3.md |
| AGY | adversarial-review-mpqn25qc-6ejm3r | PLAN-NEEDS-REVISION (Window-3 counter-example) | agy-plan-r3.md |
| Claude SMR | n/a | PLAN-NEEDS-REVISION (concur; missed Window-3) | claude-smr-plan-r3.md |

## Round 4 (v4)
| Reviewer | Task ID | Verdict | Doc |
|---|---|---|---|
| Codex | task-mpr1hywo-cxrf47 | PLAN-NEEDS-MINOR (Window-3 narrowing, NIT-2 unsound, stale R3 cell) | codex-plan-r4.md |
| AGY | adversarial-review-mpr1hhma-hbycu7 | PLAN-NEEDS-REVISION (stale-entry leak, key-collapsed staging, respawn, both-signal bar) | agy-plan-r4.md |
| Claude SMR | n/a (in-conversation) | PLAN-READY (2 NITs; NIT-2 self-corrected as unsound) | claude-smr-plan-r4.md |

## Round 5 (v5)
| Reviewer | Task ID | Verdict | Doc |
|---|---|---|---|
| Codex | (pending dispatch) | (pending) | codex-plan-r5.md |
| AGY | (pending dispatch) | (pending) | agy-plan-r5.md |
| Claude SMR | n/a (in-conversation) | PLAN-READY | claude-smr-plan-r5.md |

## Notes
- Gate-R is a CLUSTER measurement (loss:xpf-userspace-fw0/fw1), FIFO with the
  in-flight bug-fix agent. Research stops at PLAN-READY/KILL; Gate-R runs at
  /engineer time (no cluster code ships from /research).
