# AGY plan review r2 — #1626

Job: review-mppmady0-3jml3p

## Verdict: PLAN-READY

All 7 r1 findings verified FIXED in v2. AGY ran `show configuration
class-of-service | display set` on a live cluster VM (bpfrx-fw1) to
confirm the flat-set output format matches the fixture line format
that `grep -Fxq` will receive. Also ran `go vet ./pkg/config/...` +
`go test ./pkg/config/...` — both green.

## Per-finding verification

- **F1** FIXED — live VM check confirms `| display set` produces
  exact-line matchable output (no trailing `;` or `\r`).
- **F2/F6** FIXED — single `MISSING=1` failure path → unified
  rollback.
- **F3** FIXED — warning-string grep dropped; validation anchored to
  running config state.
- **F4** FIXED — 0.7 × 25g = 17.5G; 10.1G of small-class rates fits
  inside.
- **F5** FIXED — fixture-content gate via
  `grep -qE '^set .*oversubscription-policy' "$CONFIG_FILE"`.
- **F7** FIXED — both §8 and §11 consistent on `pkg/config/...`.

## Residual hostile checks

- **A. CRLF risk**: implementer should strip `\r` from `$want` before
  grep (`want="${want%$'\r'}"`) as a safety measure. Files on cluster
  currently use Unix LF.
- **B. --surplus-sharing**: the awk pass only adds scheduler-level
  lines; the §7 grep filters source-fixture content for
  oversubscription-policy lines and doesn't overlap. Safe.
- **C. Trap chain**: cumulative `$OVERSUB_OUT` registration works
  whether success or rollback path fires.

## Conclusion

Plan v2 is robust, mathematically consistent, and technically correct.
**PLAN-READY**.
