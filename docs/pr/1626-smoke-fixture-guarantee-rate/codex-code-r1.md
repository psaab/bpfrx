# Codex code review r1 — PR #1629 (closes #1626)

## Findings

FINDING 1 (none): No blocking code-review findings. The two-file diff
matches plan v2 §6+§7: fixture enables `guarantee-rate 0.7` on `reth0
unit 80`, and Phase-3.5 dynamically checks every fixture
`oversubscription-policy` set line against `show configuration
class-of-service | display set`.

FINDING 2 (none): Bash structure looks sound. `done < <(grep ...)` is
valid process substitution, quoted variables are safe, `grep -Fxq
"$want"` avoids regex/substring false passes, and CRLF trimming is
scoped to the expected fixture line.

FINDING 3 (none): Failure handling is not silent. A missing
round-trip line prints the expected line, dumps the flat running CoS
config, attempts `rollback 1` + `commit`, warns loudly if rollback
fails, and exits `7`.

FINDING 4 (none): Phase-3.5 is placed after Phase 3's existing
CoS-live verification and its `exit 6` failure path, so it only runs
after the prior live CoS check has passed.

FINDING 5 (none): Smoke evidence shows the scheduler still behaves
proportionally under the now-active knob, but that is explicitly
documented as out of scope for this surgical PR and is the point of
making the fixture exercise the branch.

## VERDICT: MERGE-READY
