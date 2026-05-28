# AGY code review r1 — PR #1629 (closes #1626)

Job: review-mppmmo99-vhww42

## Verdict: MERGE-READY

## Verification

### Plan v2 match
- F1 (flat-set): line 260 uses `show configuration class-of-service |
  display set`. Match.
- F2/F6 (single failure path): `MISSING` accumulator; single
  `if [[ "$MISSING" -ne 0 ]]` → rollback + exit 7. Match.
- F3 (no warning grep): compiler-warning grep removed; assertion
  rests on durable config state. Match.
- F5 (fixture-content gate): line 256 `grep -qE '^set
  .*oversubscription-policy' "$CONFIG_FILE"`. Match.
- AGY CRLF nit: line 265 `want="${want%$'\r'}"`. Match.

### Shell discipline
- All expansions quoted (`"$CONFIG_FILE"`, `"$OVERSUB_OUT"`,
  `"$TARGET"`, `"$want"`, `"$ROLLBACK_OUT"`).
- Process substitution `< <(...)` correctly keeps `MISSING` in
  parent shell.
- Trap chain cumulative; cleanup fires on any exit.
- Rollback heredoc uses `<<'EOF'` (single-quoted) so commands aren't
  shell-expanded before reaching the target CLI.

## Residual risk

CLI output drift: `grep -Fxq` is strict exact-string. If a future
Junos CLI adds whitespace/indentation to flat-set rendering, the
assertion could false-fail. Minor; flat-set is highly standardized.

## Conclusion

**MERGE-READY**.
