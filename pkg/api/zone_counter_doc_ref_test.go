package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #3651: the #3643 HIDE surfaces document the deferred POPULATE design by
// pointing at docs/research/3643-dead-counters/plan.md §5A/§5B. Four production
// files cite that path (pkg/api/README.md, pkg/api/metrics_counters.go,
// pkg/api/types.go, pkg/dataplane/loader.go), so the doc must actually exist on
// master with those section anchors — otherwise every one of those references
// dangles.
//
// FAIL-ON-REVERT: deleting the design doc (as happened once — it lived only on
// the unmerged research/3643-dead-counters branch) or dropping its §5A / §5B
// POPULATE/HIDE anchors re-dangles the in-code references and makes this test
// go RED. It is the guard that the deferred-POPULATE design of record stays on
// master until the Rust per-zone counter-publish (#3651) ships.
func TestZoneCounterDeferredDesignDocExists(t *testing.T) {
	// pkg/api -> repo root is ../.. (matches the retirement boundary canary).
	path := filepath.Join("..", "..", "docs", "research", "3643-dead-counters", "plan.md")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("deferred per-zone-counter design doc missing: %v "+
			"(pkg/api/README.md, pkg/api/metrics_counters.go, pkg/api/types.go, and "+
			"pkg/dataplane/loader.go all cite %s §5A/§5B)", err, path)
	}
	doc := string(b)
	for _, anchor := range []string{"§5A", "§5B", "#3651"} {
		if !strings.Contains(doc, anchor) {
			t.Errorf("design doc %s missing anchor %q that the in-code #3643/#3651 "+
				"references rely on", path, anchor)
		}
	}
}
