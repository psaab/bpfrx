// #2468: session clear must surface — not silently discard — failures
// from the iterator, reverse/companion deletes, and (covered in the
// grpcapi package) the HA peer-clear RPC. These tests inject failures
// via a cliRuntime that embeds *dataplane.Manager and overrides the
// session methods, then assert the CLI prints a WARNING tail. They are
// fail-on-revert: restoring the old `_ =`/fire-and-forget discards makes
// the failures invisible and the WARNING assertions go RED.
package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// clearFaultCLIDP is a cliRuntime that reports IsLoaded()==true and lets
// a test seed one matching v4 session plus per-operation error
// injection. It embeds *dataplane.Manager so it satisfies the full
// cliRuntime surface; only the session methods are overridden.
type clearFaultCLIDP struct {
	*dataplane.Manager

	v4Sessions map[dataplane.SessionKey]dataplane.SessionValue

	iterErr    error // returned by IterateSessions
	iterV6Err  error // returned by IterateSessionsV6
	delErr     error // returned by DeleteSession (forward + reverse)
	delDNATErr error // returned by DeleteDNATEntry
}

func (d *clearFaultCLIDP) IsLoaded() bool { return true }

func (d *clearFaultCLIDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for k, v := range d.v4Sessions {
		if !fn(k, v) {
			break
		}
	}
	return d.iterErr
}

func (d *clearFaultCLIDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return d.iterV6Err
}

func (d *clearFaultCLIDP) DeleteSession(key dataplane.SessionKey) error { return d.delErr }
func (d *clearFaultCLIDP) DeleteSessionV6(dataplane.SessionKeyV6) error { return nil }
func (d *clearFaultCLIDP) DeleteDNATEntry(dataplane.DNATKey) error      { return d.delDNATErr }
func (d *clearFaultCLIDP) DeleteDNATEntryV6(dataplane.DNATKeyV6) error  { return nil }
func (d *clearFaultCLIDP) ClearAllSessions() (int, int, error)          { return 0, 0, nil }

// one matching TCP session (proto-only filter), optionally SNAT.
func seedV4(snat bool) map[dataplane.SessionKey]dataplane.SessionValue {
	key := dataplane.SessionKey{Protocol: 6, SrcPort: 0x3930} // network-order, irrelevant to proto filter
	val := dataplane.SessionValue{}
	if snat {
		val.Flags = dataplane.SessFlagSNAT
	}
	return map[dataplane.SessionKey]dataplane.SessionValue{key: val}
}

func newClearCLI(t *testing.T, dp cliRuntime) *CLI {
	t.Helper()
	return &CLI{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    dp,
		// cluster intentionally nil — standalone, so the peer-clear path
		// is a clean no-op and these tests isolate the dataplane-side
		// failure surfacing.
	}
}

func TestClearFilteredSessionsReportsIteratorFailure(t *testing.T) {
	dp := &clearFaultCLIDP{
		Manager:    dataplane.New(),
		v4Sessions: seedV4(false),
		iterErr:    fmt.Errorf("map dump truncated"),
	}
	c := newClearCLI(t, dp)
	var callErr error
	out := captureStdout(t, func() {
		// proto-only filter -> hasFilter() true -> clearFilteredSessions
		callErr = c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"})
	})
	if callErr != nil {
		t.Fatalf("handleClearSecurity error = %v", callErr)
	}
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "v4 iterate") {
		t.Fatalf("iterator failure not surfaced in output:\n%s", out)
	}
}

func TestClearFilteredSessionsReportsReverseDeleteFailure(t *testing.T) {
	dp := &clearFaultCLIDP{
		Manager:    dataplane.New(),
		v4Sessions: seedV4(false),
		delErr:     fmt.Errorf("kernel map delete EBUSY"),
	}
	c := newClearCLI(t, dp)
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"})
	})
	if callErr != nil {
		t.Fatalf("handleClearSecurity error = %v", callErr)
	}
	// delErr hits both the forward delete and the reverse delete.
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "delete") {
		t.Fatalf("reverse/forward delete failure not surfaced:\n%s", out)
	}
}

func TestClearFilteredSessionsReportsDNATCompanionFailure(t *testing.T) {
	dp := &clearFaultCLIDP{
		Manager:    dataplane.New(),
		v4Sessions: seedV4(true), // SNAT -> a DNAT companion entry is deleted
		delDNATErr: fmt.Errorf("dnat map delete failed"),
	}
	c := newClearCLI(t, dp)
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"})
	})
	if callErr != nil {
		t.Fatalf("handleClearSecurity error = %v", callErr)
	}
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "DNAT companion") {
		t.Fatalf("DNAT companion failure not surfaced:\n%s", out)
	}
}

// Happy path: every sub-operation succeeds -> clean cleared line, no
// WARNING. Guards against a regression that warns spuriously.
func TestClearFilteredSessionsHappyPathNoWarning(t *testing.T) {
	dp := &clearFaultCLIDP{
		Manager:    dataplane.New(),
		v4Sessions: seedV4(true),
	}
	c := newClearCLI(t, dp)
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"})
	})
	if callErr != nil {
		t.Fatalf("handleClearSecurity error = %v", callErr)
	}
	if strings.Contains(out, "WARNING") {
		t.Fatalf("happy path emitted a spurious WARNING:\n%s", out)
	}
	if !strings.Contains(out, "matching sessions cleared") {
		t.Fatalf("happy path missing cleared line:\n%s", out)
	}
}
