// Package refactoraudit hosts the enforcement canary for the committed
// modularity heatmap (docs/refactoring-audit-current.txt).
//
// It contains no runtime code. Its sole purpose is to give `go test
// ./...` — the required pre-commit aggregate (`make test`) — a home for
// the drift gate that keeps the committed heatmap honest: if a refactor
// adds, deletes, or resizes a >=1500 LOC production file without
// regenerating the artifact, TestHeatmapNotStale fails. The companion
// tests pin the Rust test-only filename classifier (#6232) and the
// raw-LOC measurement so the gate cannot silently start counting test
// warehouses as production again.
//
// See audit_canary_test.go, scripts/refactoring-audit.sh, and
// scripts/refactoring-audit-lib.sh.
package refactoraudit
