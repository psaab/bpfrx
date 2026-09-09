package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #9392: `recycle_scan_pops` was a Rust `#[cfg(test)]` seam, so the
// non-amortizing recycled phase #9327 measured had NO operator-visible signal.
// A counter with no production reader is the same as no counter, so the
// promotion is worth nothing unless something an operator looks at reads it.
//
// This binds the READER. The Rust cells prove the counters move and the wire
// cell proves the keys agree; neither says anything about whether `show
// security nat source pool` prints them, and that is the mutant this campaign
// has repeatedly watched survive — severing a daemon-side consumer leaves every
// producer-side cell green because those cells only ever prove the producer
// handles what it is GIVEN.
//
// FAIL-ON-REVERT: delete the "Recycled-scan pops" block from
// `showNATSourcePool` and the first leg reds.
type recycleScanCLIDP struct {
	*dataplane.Manager
	poolIDs map[string]uint8
	status  dpuserspace.ProcessStatus
}

func (d *recycleScanCLIDP) IsLoaded() bool { return true }
func (d *recycleScanCLIDP) LastApplyResult() *dataplane.ApplyResult {
	return &dataplane.ApplyResult{PoolIDs: d.poolIDs}
}
func (d *recycleScanCLIDP) ReadNATPortCounter(uint32) (uint64, error) { return 0, nil }
func (d *recycleScanCLIDP) Status() (dpuserspace.ProcessStatus, error) {
	return d.status, nil
}

func recycleScanCLI(pool dpuserspace.SourceNATPoolStatus) *CLI {
	return &CLI{
		dp: &recycleScanCLIDP{
			Manager: dataplane.New(),
			poolIDs: map[string]uint8{"p1": 0},
			status: dpuserspace.ProcessStatus{
				SourceNATPools: []dpuserspace.SourceNATPoolStatus{pool},
			},
		},
	}
}

func TestShowSourceNATPoolReportsTheRecycleScanRatio9392(t *testing.T) {
	// THE CLIFF. 15 occupied tokens ahead of 1 free one is the #9327 shape:
	// 16 pops per scan, forever. Distinct, non-round numbers so a renderer that
	// printed the wrong field, or the same field twice, cannot match.
	cliff := captureStdout(t, func() {
		c := recycleScanCLI(dpuserspace.SourceNATPoolStatus{
			PoolName:              "p1",
			UsedPorts:             15,
			RecycleScanPopsTotal:  128,
			RecycleScanWalksTotal: 8,
		})
		if err := c.showNATSourcePool(armedSourceCfg(), ""); err != nil {
			t.Fatalf("cliff: %v", err)
		}
	})
	// PREMISE: the ports block must have rendered at all, or the assertion
	// below is about a view that never reached the counters.
	if !strings.Contains(cliff, "Ports allocated:") {
		t.Fatalf("the armed fixture did not render the ports block, so the "+
			"recycle-scan assertion is not about the reader:\n%s", cliff)
	}
	if !strings.Contains(cliff, "Recycled-scan pops: 128 over 8 scans (16.00 per scan)") {
		t.Errorf("show security nat source pool did not report the recycled-scan "+
			"cost. #9327 measured that the recycled phase pays (K+F)/F pops per "+
			"claim — 16 per claim at K=15,F=1 — and could not say whether "+
			"production reaches that shape because the counter was a test seam. "+
			"Promoting it without a reader would be the same as not promoting it "+
			"(#9392).\ngot:\n%s", cliff)
	}

	// CONTROL 1: a HEALTHY pool must still render the line, with a ~1 ratio.
	// Without this leg the fix could be "print the line whenever pops is large",
	// which reports the cliff and hides the baseline an operator needs to
	// recognise it as a cliff.
	healthy := captureStdout(t, func() {
		c := recycleScanCLI(dpuserspace.SourceNATPoolStatus{
			PoolName:              "p1",
			UsedPorts:             3,
			RecycleScanPopsTotal:  9,
			RecycleScanWalksTotal: 9,
		})
		if err := c.showNATSourcePool(armedSourceCfg(), ""); err != nil {
			t.Fatalf("healthy: %v", err)
		}
	})
	if !strings.Contains(healthy, "Recycled-scan pops: 9 over 9 scans (1.00 per scan)") {
		t.Errorf("a HEALTHY pool must still report the pair — the baseline is what "+
			"makes the cliff reading interpretable.\ngot:\n%s", healthy)
	}

	// CONTROL 2: zero WALKS must print NOTHING. That is the reading an older
	// helper produces (both keys absent, both decode 0) and also the reading a
	// pool whose recycled phase never ran produces. Printing "0 over 0" — or a
	// 1.00 ratio computed from a zero denominator — would be the fabricated
	// healthy zero #7473 and #8606 already refused twice on this very view.
	silent := captureStdout(t, func() {
		c := recycleScanCLI(dpuserspace.SourceNATPoolStatus{
			PoolName:  "p1",
			UsedPorts: 3,
		})
		if err := c.showNATSourcePool(armedSourceCfg(), ""); err != nil {
			t.Fatalf("silent: %v", err)
		}
	})
	if !strings.Contains(silent, "Ports allocated:") {
		t.Fatalf("the zero-walk fixture did not render the ports block, so its "+
			"silence below is not attributable to the walk gate:\n%s", silent)
	}
	if strings.Contains(silent, "Recycled-scan") {
		t.Errorf("a helper reporting ZERO recycled-phase scans must produce no "+
			"recycled-scan line. An old helper omits both keys and they decode 0; "+
			"printing a ratio from a zero denominator states a measurement nobody "+
			"made (#9392).\ngot:\n%s", silent)
	}
}
