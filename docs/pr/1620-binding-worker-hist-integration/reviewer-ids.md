# #1620 reviewer task IDs

Persistent record per `feedback_codex_session_loss_continuation`.

## Round 1 (plan v1 @ 5b43a44d5)

- **Codex**: task-mppk7c5e-bppfn9 (PLAN-NEEDS-MAJOR; 3 HIGH, 3 MED, 3 LOW)
- **AGY**: adversarial-review-mppk87jl-1qsqek (PLAN-NEEDS-MAJOR; 2 HIGH,
  4 MED, 1 LOW)
- **Claude SMR**: claude-smr-plan-r1.md (PLAN-NEEDS-MINOR; F1-F7)

## Round 2 (plan v2 @ 31556cfe7)

- **Codex**: task-mppl7scr-w2unwz (PLAN-NEEDS-MINOR; sandbox-broken,
  conceptual: 3 findings — repr(C), CLI overflow, baseline subtract)
- **AGY**: adversarial-review-mppl8c0b-ofyy0y (PLAN-NEEDS-MINOR;
  Amendment A repr(C), Amendment B wrapper_baseline subtract)
- **Claude SMR**: claude-smr-plan-r2.md (PLAN-READY; F8-F10 NITs)

## Round 3 (plan v3 @ 191a92445)

- **Codex**: task-mpplze6q-dheeud (PLAN-NEEDS-MINOR; 3 findings — all
  caught by AGY r3 independently: HIGH-1 sample_phase publish, MED-1
  ClockSource repr(u8), MED-2 Go CLI loophole. Earlier dispatch
  task-mpplr90m-wwhp8i failed to register; re-dispatched.)
- **AGY**: adversarial-review-mpplrk9n-p3pjm0 (PLAN-NEEDS-MINOR; same
  3 findings + AXIS-6 diagnostic counter recommendation)
- **Claude SMR**: claude-smr-plan-r3.md (PLAN-READY — missed
  sample_phase publish gap; self-corrected in r4)

## Round 4 (plan v4 @ efeac19f9)

- **Codex**: task-mppm70jl-1zhg3q (PLAN-NEEDS-MINOR; substantive v4
  design approved, blocked only on §4.1 doc-consistency stale text)
- **AGY**: adversarial-review-mppm7cic-qw93ab (PLAN-READY)
- **Claude SMR**: claude-smr-plan-r4.md (PLAN-READY on v4)

## Round 5 (plan v4 + doc cleanup)

- **Claude SMR**: claude-smr-plan-r5.md (PLAN-READY post doc cleanup)
- Codex r4 doc findings addressed in-line; no further reviewer
  dispatch needed because Codex r4 stated "Patch the stale
  snippets/layout/store-count/test-count comments to the v4 layout
  you pasted, and my verdict becomes PLAN-READY". This round's
  edits are exactly that.
