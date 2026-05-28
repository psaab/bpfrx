# Claude SMR plan review r2 — #1626

Plan v2 review. Verify each of the 7 r1 findings is actually
addressed by v2 design, not just declared addressed.

## Verdict: PLAN-READY pending AGY+Codex r2 concur

## Per-finding verification

### F1 (hierarchical vs flat) — addressed
v2 §7 explicitly uses `show configuration class-of-service | display
set` (line 11 of the bash block) and a `grep -Fxq` fixed-string
exact-line match. The CLI in this repo recognizes `| display set`
because the same idiom is used by the existing tooling (verified
earlier: `pkg/configstore/...ShowActivePathSet` etc.). Match.

### F2 (rollback contradiction) — addressed
v2 §7 has a SINGLE failure path: any line in the fixture matching
`^set .*oversubscription-policy` that does not also appear in the
running config triggers `MISSING=1` → rollback. §9 risk section
matches this. No contradiction.

### F3 (compiler warning grep coupling) — addressed
v2 §7 contains no `grep` of the compiler warning string. The §6
discussion of v1 has been dropped from v2 design; verification rests
entirely on round-trip flat-set output. Match.

### F4 (math wrong) — addressed
v2 §6 explicitly distinguishes:
- `shaping-rate 25g` (configured shaper),
- `pass1_budget = 0.7 × 25g = 17.5g` (correct),
- ~18 G NIC ceiling under simul-load (an OBSERVATIONAL bound, not
  algorithm input).
This is the right framing. The smoke gate-1 outcome
(small classes honoured) is preserved qualitatively.

### F5 (hard-coded flag skip) — addressed
v2 §7 gates by:
```bash
if grep -qE '^set .*oversubscription-policy' "$CONFIG_FILE"; then
  FIXTURE_HAS_OVERSUB=1
fi
```
This is fixture-content driven. `--same-class`/`--symmetric` skip
automatically; future fixtures that add the knob get gated unchanged.
Match.

### F6 (belt-and-suspenders backwards) — addressed
Same root as F2. v2 §7's single failure path solves both. Match.

### F7 (go vet/go test inconsistency) — addressed
v2 §8 first bullet now lists `go vet ./pkg/config/...`; §11 first
bullet says `go vet ./pkg/config/... && go test ./pkg/config/...`.
Same command, both sections. Match.

## Cross-cutting verification (new SMR checks)

### SMR-1: heredoc pattern correctness
The bash `done < <(grep ...)` process-substitution-with-while pattern
in §7 is the canonical way to iterate command output without
subshelling (so MISSING survives the loop). Correct.

### SMR-2: trap chain
§7 extends the trap chain with `OVERSUB_OUT`. Existing trap chain in
apply-cos-config.sh already uses cumulative `trap "rm -f $A $B $C
..."` — implementer must follow that pattern. Plan says "Phase 3.5"
which fits between existing Phase-3 and the final success echo.

### SMR-3: `incus exec ... -c "show configuration..."` exit code
The `|| true` after the incus invocation is correct because the CLI
may return non-zero on some edge cases (e.g., empty section). The
gate is on output content, not exit code, which is the right
discipline.

### SMR-4: surplus-sharing interaction
v2 §9 calls out that surplus-sharing awk pass appends NEW lines
(scheduler-level) and doesn't transform the oversubscription line
(unit-level). The two knobs live on different config subtrees
(`schedulers.<name>` vs `interfaces.<if>.units.<u>`). Compiler
accepts both independently (verified via
parser_class_of_service_test.go). No interaction.

### SMR-5: `display set` output format includes the leading `set`
The flat-set form of a config tree starts with `set` per Junos
convention. `grep -Fxq` (fixed-string exact-line) will match the
fixture line verbatim. Implementer should also ensure the fixture
line doesn't have trailing whitespace.

### SMR-6: parser interface name normalization
Junos accepts `ge-0/0/2` in display syntax but the fixture uses
`reth0`. `show configuration | display set` always emits the form
the operator typed (verified by reading
`pkg/configstore/ShowCandidatePathSet` chain: returns the
canonical-set representation of the AST). Round-trip identical.

## Conclusion

Plan v2 addresses all 7 r1 findings cleanly. The §7 design is
considerably more robust than v1: durable contract (round-trip
flat-set), single failure path, dynamic gating, no compiler-message
coupling. The math in §6 is now correct.

**PLAN-READY** subject to AGY+Codex r2 concur.
