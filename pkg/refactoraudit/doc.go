// Package refactoraudit hosts the enforcement canary for the committed
// modularity heatmap (docs/refactoring-audit-current.txt).
//
// It contains no runtime code. Its sole purpose is to give `go test
// ./...` — the required pre-commit aggregate (`make test`) — a home for
// the drift gate that keeps the committed heatmap honest: if a
// production file enters the audit (crosses 1500 LOC), leaves it, or is
// promoted/demoted across the 2000 LOC [REFACTOR] boundary without the
// artifact being regenerated, TestHeatmapNotStale fails.
//
// The gate is on audit CONTENT — the file set and each file's tier —
// not on the artifact's exact bytes. The LOC column is a repo-global
// quantity that no gate can hold byte-exact under parallel merges, and
// #6617 records what happened when one tried: master was red in 26 of
// 40 consecutive commits, including PRs that regenerated the artifact
// correctly and still landed stale on a file they never touched. The
// count is reproducible by regenerating at each first-parent commit;
// docs/refactoring-audit.md carries the method.
//
// The companion tests pin the artifact's internal coherence
// (TestHeatmapArtifactWellFormed), generator determinism
// (TestGeneratorDeterministic), the Rust test-only filename classifier
// (#6232), and the raw-LOC measurement so the gate cannot silently
// start counting test warehouses as production again.
//
// See audit_canary_test.go, docs/refactoring-audit.md,
// scripts/refactoring-audit.sh, and scripts/refactoring-audit-lib.sh.
package refactoraudit
