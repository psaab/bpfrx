# Codex plan review r1 — #1626

Codex was given the AGY findings inline and asked to concur/dispute
each, plus add anything missed.

## Findings

F1: concur — the plan says the line should appear verbatim in `show
configuration class-of-service`, but if that command emits hierarchical
config, the literal flat-set grep is not robust.

F2: concur — section 6 says rollback if either assertion fails, while
section 9 says only if both fail; for a required Phase-3.5 gate this
must be OR.

F3: concur — requiring the compiler warning text makes the harness
depend on diagnostic wording rather than durable behavior.

F4: concur — the plan's cited worked example uses 18G, but this
fixture's stated shaping-rate is 25g, so `0.7` implies 17.5G.

F5: concur — skipping by `--same-class`/`--symmetric` bakes fixture
names into logic; the assertion should key off whether the applied
fixture actually contains the guarantee-rate line.

NEW F6 (major): section 9's "belt-and-suspenders" mitigation is
backwards: requiring both A and B to fail would let parser/config or
compiler acceptance regressions pass silently when only one assertion
fails.

NEW F7 (minor): test plan includes `go vet ./...`, but section 8 only
lists `go test ./pkg/config/...`; validation scope is inconsistent and
should be made explicit.

## VERDICT: PLAN-NEEDS-MAJOR
