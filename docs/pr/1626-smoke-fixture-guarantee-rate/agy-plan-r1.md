# AGY plan review r1 — #1626

Job: review-mppm1lhv-1kkpmo

## Verdict: PLAN-NEEDS-MAJOR

## Findings

### F1. Hierarchical vs. Flat CLI Output Grep Failure (Syntax / Correctness)

- Plan citation: section 6 "Grep `show configuration
  class-of-service`" + "A literal `oversubscription-policy
  guarantee-rate 0.7` grep against `show configuration` is trivially
  correct."
- `cli` outputs standard hierarchical curly-brace by default. The
  configured line serializes as:
  ```
  interfaces { reth0 { unit 80 { oversubscription-policy {
    guarantee-rate 0.7; } } } }
  ```
- A literal single-line grep for `oversubscription-policy
  guarantee-rate 0.7` will fail (exit 1) and trigger false-positive
  rollback.
- **Correction**: use `show configuration class-of-service | display
  set` for flat-set form, or a multi-line regex.

### F2. Rollback Logic Contradiction (Assertion Fail-Safe)

- Plan section 6 says rollback if either fails; section 9 says only
  if both fail.
- Either-AND lets compiler regressions pass silently (Check B fails
  but Check A passes → no rollback).
- **Correction**: OR semantics; both must pass.

### F3. Tight Coupling to Compiler Diagnostics

- Grep-asserting the exact English warning string couples harness to
  Go source wording.
- Future phrasing change silently breaks harness or triggers cluster
  rollbacks.
- **Correction**: verify via durable state (`show configuration |
  display set`); use generic regex if checking warnings at all.

### F4. Shaping Rate and Bandwidth Calculation Discrepancy

- Plan section 4 cites `pass1_budget = 0.7 × 18 = 12.6 G` from v5
  worked example.
- Fixture sets `shaping-rate 25g` on `reth0 unit 80`.
- True budget at 0.7 × 25g = 17.5 Gbps, not 12.6 G.
- **Correction**: re-do the residual-bandwidth math against actual
  fixture parameters before declaring smoke gate expectations.

### F5. Fragile Hardcoded Skip Rules

- Plan section 6 skips assertion for `--same-class` and `--symmetric`
  by flag.
- Adding guarantee-rate to one of those fixtures later would silently
  skip the gate.
- **Correction**: gate by fixture content:
  ```
  if grep -q "oversubscription-policy" "$CONFIG_FILE"; then ...
  ```

### Residual: surplus-sharing compatibility

- `--surplus-sharing` appends `surplus-sharing` to exact schedulers.
- Combined with new `oversubscription-policy guarantee-rate` needs
  explicit verification (compiler must accept both; runtime must
  not panic).
