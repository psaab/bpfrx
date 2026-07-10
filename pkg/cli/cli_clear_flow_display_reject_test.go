// #5066: `clear security flow session summary|brief|sort-by ...` must be
// rejected, NOT silently accepted. The shared show/clear filter parser
// recognized those presentation tokens but hasFilter() excluded all
// three, so on the clear path they produced an empty selector that fell
// through to ClearAllSessions() plus an unfiltered peer clear — the most
// destructive path, on both HA nodes. These tests assert each modifier is
// rejected with an error and that NEITHER clear method (ClearAllSessions
// nor the filtered IterateSessions path) is invoked.
//
// Fail-on-revert: restore the old `c.parseSessionFilter(args[2:])` call on
// the clear path (or drop the clearMode rejection) and the display
// modifiers again parse clean → hasFilter() false → ClearAllSessions runs,
// so callErr goes nil and clearAllCalls goes 1 → these tests go RED.
package cli

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// clearCountDP is a cliRuntime that reports IsLoaded()==true and counts
// invocations of the two clear entry points so a test can assert a
// rejected command touches NEITHER.
type clearCountDP struct {
	*dataplane.Manager
	clearAllCalls int
	iterateCalls  int
}

func (d *clearCountDP) IsLoaded() bool { return true }

func (d *clearCountDP) ClearAllSessions() (int, int, error) {
	d.clearAllCalls++
	return 0, 0, nil
}

func (d *clearCountDP) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	d.iterateCalls++
	return nil
}

func (d *clearCountDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	d.iterateCalls++
	return nil
}

func TestClearFlowSessionRejectsDisplayModifiers(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"summary", []string{"flow", "session", "summary"}},
		{"brief", []string{"flow", "session", "brief"}},
		{"sort-by bytes", []string{"flow", "session", "sort-by", "bytes"}},
		{"sort-by packets", []string{"flow", "session", "sort-by", "packets"}},
		{"filter plus summary", []string{"flow", "session", "protocol", "tcp", "summary"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := &clearCountDP{Manager: dataplane.New()}
			c := newClearCLI(t, dp)
			var callErr error
			out := captureStdout(t, func() {
				callErr = c.handleClearSecurity(tc.args)
			})
			if callErr == nil {
				t.Fatalf("%s: expected an error rejecting the display modifier, got nil (output: %q)", tc.name, out)
			}
			if dp.clearAllCalls != 0 {
				t.Fatalf("%s: invoked ClearAllSessions (%d) — a display modifier wiped the whole table", tc.name, dp.clearAllCalls)
			}
			if dp.iterateCalls != 0 {
				t.Fatalf("%s: invoked the filtered clear (IterateSessions %d) — must reject before clearing", tc.name, dp.iterateCalls)
			}
		})
	}
}

// Positive control: an exactly-empty selector is still the clear-all path,
// so the #5066 fix does not disturb the legitimate `clear security flow
// session` (no args) semantics.
func TestClearFlowSessionEmptyStillClearsAll(t *testing.T) {
	dp := &clearCountDP{Manager: dataplane.New()}
	c := newClearCLI(t, dp)
	var callErr error
	captureStdout(t, func() {
		callErr = c.handleClearSecurity([]string{"flow", "session"})
	})
	if callErr != nil {
		t.Fatalf("empty clear should succeed, got %v", callErr)
	}
	if dp.clearAllCalls != 1 {
		t.Fatalf("empty clear should invoke ClearAllSessions exactly once, got %d", dp.clearAllCalls)
	}
	if dp.iterateCalls != 0 {
		t.Fatalf("empty clear should not take the filtered path, IterateSessions=%d", dp.iterateCalls)
	}
}

// Parser-level assertions: the clear parser rejects presentation tokens
// (surfacing through both parseErr and validate so the clear path cannot
// fall through to ClearAllSessions), while the show parser still accepts
// them and now validates the sort-by value.
func TestParseClearSessionFilterRejectsDisplayTokens(t *testing.T) {
	c := &CLI{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}

	for _, args := range [][]string{
		{"summary"},
		{"brief"},
		{"sort-by", "bytes"},
		{"sort-by", "packets"},
	} {
		f := c.parseClearSessionFilter(args)
		if f.parseErr == nil {
			t.Errorf("clear parse of %v: parseErr nil, want display-modifier rejection", args)
		}
		if !f.hasFilter() {
			t.Errorf("clear parse of %v: hasFilter() false — would fall through to clear-all", args)
		}
		if err := f.validate(); err == nil {
			t.Errorf("clear parse of %v: validate() nil, want error", args)
		}
	}

	// Show path still accepts the display modifiers.
	for _, args := range [][]string{{"summary"}, {"brief"}, {"sort-by", "bytes"}, {"sort-by", "packets"}} {
		f := c.parseSessionFilter(args)
		if f.parseErr != nil {
			t.Errorf("show parse of %v: unexpected parseErr %v", args, f.parseErr)
		}
	}
	if f := c.parseSessionFilter([]string{"summary"}); !f.summary {
		t.Errorf("show parse of summary: summary flag not set")
	}
	if f := c.parseSessionFilter([]string{"sort-by", "packets"}); f.sortBy != "packets" {
		t.Errorf("show parse of sort-by packets: sortBy=%q, want packets", f.sortBy)
	}

	// Show path now validates the sort-by value.
	if f := c.parseSessionFilter([]string{"sort-by", "garbage"}); f.parseErr == nil {
		t.Errorf("show parse of sort-by garbage: parseErr nil, want invalid-sort-by error")
	}
}
