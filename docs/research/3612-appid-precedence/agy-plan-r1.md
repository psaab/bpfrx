# AGY — hostile adversarial plan review r1 (#3612)

Verdict: **PLAN-READY** (PATH A). Reviewed against worktree @ f1d00ffeb.

Summary of independently-verified findings (all confirm the plan):

1. **Reachability (no KILL).** `pkg/config/compiler_applications_collision.go:79`
   (`validateApplicationNameCollisionsAST`) rejects only duplicate NAME
   definitions, NOT distinct-named apps overlapping on protocol/port. Overlaps
   are valid + catalogued → divergence reachable.
2. **Target symbol correct.** `AppCatalog::lookup_directional`
   (`userspace-dp/src/policy.rs:1607`) + wrappers `lookup_forward` (:1658),
   `lookup_admitted` (:1683) are the ONLY Rust-side label resolution path.
3. **Specificity corner cases hold.** exact-vs-range and source-port-only both
   land in the same "port-constrained" tier in BOTH languages under PATH A.
   Reverse-direction (S2): Go `resolveTupleFallback` treats dst as service port
   and mislabels reverse-keyed flows when AppID off; AppID-on stamps at session
   create on both directions. Correctly deferred as S2.
4. **Display-only holds.** app_id is published to conntrack for telemetry
   (show / RT_FLOW) only; enforcement uses `CompiledApplications::matches`
   (`policy.rs:1452`), a separate boolean matcher. Tiebreak change cannot alter
   permit/deny.
5. **Set-membership gap (S1) does not defeat the parity test** as scoped — the
   shared fixture feeds the SAME user-app list to both paths.
   (`runtime.go:21 builtinFallbacks` vs `pkg/config/predefined.go:11
   PredefinedApplications`.)
6. **Specificity is the correct unifying rule** — lowest-id/name-first is
   arbitrary and shadows specific services with broad ones.

Required engineer actions (PATH A): tag `AppScanEntry` with `port_constrained`
(policy.rs:1545), update `lookup_directional` tier resolution (min(exact,
first_port_constrained) then protocol-only fallback), add the cross-language
JSON parity fixture under `userspace-dp/tests/fixtures/`.
