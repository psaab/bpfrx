# r1 reviewer verdicts (verbatim verdict lines + convergent findings)

Three hostile reviewers ran on plan r1 (`491106500`). Companions (Codex/AGY)
were infra-degraded for plan-prose review (AGY's adversarial-review tool diffs a
code worktree, not a docs-only branch); substituted two independent hostile
Claude plan-reviewers + the hostile Claude SMR per the research-skip rule.

## Claude SMR (claude-smr-plan-r1.md)
VERDICT: PLAN-CHANGES-REQUIRED
- F1 (MAJOR): partial-fix framing must be sharpened; double-export deferral
  honest but must commit to a concrete follow-up issue and not imply #2129
  fully resolved.
- F2 (MINOR): 5.2-keep coherent + better-justified than written (cite
  gre_acceleration/power_mode_disable precedent).
- F3 (MINOR): add explicit grep gate to §7.
- F4 (NIT): presence-not-non-empty gating semantic — state it.

## Hostile reviewer A
VERDICT: PLAN-CHANGES-REQUIRED
- BLOCKING: the §5.1 guard breaks ~8 existing tests whose helpers/assertions
  encode the current buggy behavior (3 `BuildExportConfig(nil, fo)` in
  exporter_test.go asserting non-nil; ~6 in
  daemon_flowexport_reconcile_test.go via the `Version9`-less
  `flowSamplingConfig` helper). Plan frames test work as additive — wrong; must
  enumerate + prescribe (add `Version9` to the helper + the 3 svc args).
- NITs: "~490-line module" is 352 (flowexport.rs) + 137 (tests); §5.2
  builder.go:59 is a struct-literal field line + protocol.go:69 Snapshot field
  under 5.2-remove.
- Confirmed all four central claims (live Go v9 emitter; dead Rust exporter;
  gating asymmetry; per-server selector). Double-export deferral DEFENSIBLE;
  unrequested-stream is the broader harm and IS fixed. Not a kill/split.

## Hostile reviewer B
VERDICT: PLAN-CHANGES-REQUIRED
- BLOCKING (D): 9 existing tests break — precisely confirmed: base
  `flowSamplingConfig` (lines 19-35) sets NO FlowMonitoring (only
  `ipfixSamplingConfig` adds VersionIPFIX); 3 `BuildExportConfig(nil,..)` cases
  at exporter_test.go:30/166/198. Must be in-scope.
- SHOULD-FIX (C): under 5.2-keep, `snapshot.flow_export` becomes test-only-read
  after the writer is removed → new dead_code warning; no `-D warnings` so build
  passes, but add `#[allow(dead_code)]` (precedent forwarding.rs:78/85). Plan's
  "cargo build is the gate" is weaker than implied.
- NITs: base-commit count (two commits, not one); §B risk-weighting (the fixed
  presence-gate is the broader defect; deferred double-export needs deliberate
  dual-config).
- Confirmed all claims; skew-safety real (omitempty + serde default); Rust
  removal list complete; one PR acceptable; no PLAN-KILL/split.

## Convergence
All three independently converged on PLAN-CHANGES-REQUIRED over the SAME
blocking finding (the gate fix breaks existing tests). r2 folds: full
9-test enumeration (§6), `#[allow(dead_code)]` on snapshot.flow_export (§5.2),
sharpened partial-fix framing + concrete follow-up commitment (§3/§8), grep
gate (§7), and the NIT corrections.
