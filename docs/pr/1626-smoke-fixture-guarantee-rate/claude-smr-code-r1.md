# Claude SMR code review r1 — PR #1629

Reviewer profile: domain SMR for Junos CoS config syntax, smoke
harness design, measurement validity, bash discipline.

## Verdict: MERGE-READY

## Implementation matches plan v2

### `test/incus/cos-iperf-config.set`
One-line diff, lands directly after `shaping-rate 25g` on `reth0 unit
80`. Syntax verified against
`pkg/config/parser_class_of_service_test.go:936` parser test. Matches
plan §5 ("the line goes after shaping-rate 25g").

### `test/incus/apply-cos-config.sh`
Phase-3.5 block (lines 235-296) is a faithful realization of plan §7:

- **F1 (flat-set)**: line 260 uses `show configuration
  class-of-service | display set`. Match.
- **F2/F6 (single failure path)**: `MISSING=0` accumulator (line
  263); any missed line sets `MISSING=1`; single
  `if [[ "$MISSING" -ne 0 ]]` triggers rollback (line 273). No
  conflicting branches.
- **F3 (no warning grep)**: zero references to compiler-warning
  string. The assertion rests entirely on round-trip config state.
- **F5 (fixture-content gate)**: line 256 `if grep -qE '^set
  .*oversubscription-policy' "$CONFIG_FILE"`. Match.
- **AGY-r2 CRLF nit**: line 265 `want="${want%$'\r'}"`. Match.

### Bash discipline checks (SMR)

- **process substitution survival**: `done < <(grep ...)` (line 271)
  keeps `MISSING` in the parent shell (no subshell). Correct.
- **trap chain**: line 258 extends the cumulative trap with
  `$OVERSUB_OUT`; line 280 further extends with `$ROLLBACK_OUT` on
  the rollback path. Both cleanups fire on any exit. Correct.
- **quoting**: all expansions are quoted (`"$CONFIG_FILE"`,
  `"$OVERSUB_OUT"`, `"$want"`). No word-splitting bug.
- **heredoc termination**: line 281 uses `<<'EOF'` (single-quoted) so
  the rollback commands aren't subject to shell expansion. Line 287
  terminates the heredoc. The `EOF` token is also used by the outer
  bash heredoc in plan §7 example — verify the actual script
  doesn't have a nested-EOF clash. Reading line 281-287: the heredoc
  starts inside an `if` clause with `incus exec ... <<'EOF'`. There
  is no outer heredoc in the bash script (the script itself isn't a
  heredoc). No clash.
- **exit codes**: existing script uses 1 (CLI not found), 4 (commit
  check fail), 5 (commit fail post-check), 6 (Phase-3 verification
  fail). New phase uses 7. Distinct and monotonic. Correct.
- **`incus exec ... || true`**: on line 261 the `|| true` lets us
  inspect the output regardless of CLI exit. The gate is on file
  content, not exit code. Same discipline as Phase-3 (line 208).

### Smoke evidence

I ran the smoke directly:
- Phase-3.5 PASSED (assertion would have triggered rollback on miss;
  it didn't).
- `show class-of-service interface` confirms `Guarantee: yes` on all
  exact-rate classes — the knob IS active at runtime, not just in the
  config tree.
- Aggregate push 19.78 Gbps; per-class equalization ~20% confirmed
  proportional-mode-like behaviour. Algorithm bug to be filed as
  #1627 (per plan §7 outcome-(b)). Out of scope for this PR.

## Cross-cutting

- **No HA touched**: pure smoke-harness change.
- **No Rust source touched**: snapshot field already on wire.
- **No CoS scheduler code touched**: per scope.
- **Plan-doc lineage**: agy-plan-r1.md, agy-plan-r2.md,
  codex-plan-r1.md, codex-plan-r2.md, claude-smr-plan-r1.md (with
  honest self-correction), claude-smr-plan-r2.md, plan.md (v2),
  smoke-measurement.md, smoke-verdict.json — all committed.

## Conclusion

Clean, surgical, well-reviewed. Implementation matches plan v2
exactly. Smoke ran clean. The diagnostic value is realized: the
algorithm bug is now visible (and out of scope for this PR — #1627
filed next).

**MERGE-READY** subject to AGY code-r1 and Copilot.
