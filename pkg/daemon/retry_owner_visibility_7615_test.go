package daemon

import (
	"strings"
	"testing"
)

// TestDaemonWiresRetryOwnerMetrics7615 binds the WIRING.
//
// The pkg/api cells prove the gauges track their fn. They prove nothing about
// whether the DAEMON supplies one — all three stay green against a build where
// every assignment below is missing, because a nil fn is a legal server. An
// exported accessor with no production caller satisfies nothing: it is the
// #6852 shape, and it leaves the operator exactly as blind as before.
//
// startHTTPServer builds the api.Config inline and launches a goroutine, so it
// cannot be driven from a unit test; the assignments are asserted at the source
// with comments stripped, the same instrument the loop-start and #6800/#6802
// metric cells use. Comments are stripped because the block introducing these
// names them, and a gate satisfiable by its own documentation proves nothing.
//
// FAIL-ON-REVERT: drop any one assignment and this reds, while every
// behavioural cell in pkg/api stays green.
func TestDaemonWiresRetryOwnerMetrics7615(t *testing.T) {
	src := stripLineComments6791(readDaemonSource(t, "daemon_run_servers.go"))

	for _, want := range []string{
		"RADeadSenderPendingFn:    d.RADeadSenderPending",
		"FabricOverlayMissingFn:   d.FabricOverlayMissing",
		"ManagementListenerDownFn: d.ManagementListenerDown",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("daemon does not wire %q into the REST/metrics server; the "+
				"retry owner re-drives a failed repair with nothing an operator "+
				"can see (#7615, and the #6852 no-production-caller shape)", want)
		}
	}
}

// TestRetryOwnerAccessorsReadTheLoopsOwnGate7615 binds each accessor to the
// SAME predicate its loop gates on.
//
// This is the property that keeps the gauge honest. An accessor derived from a
// second, parallel predicate would be a new way to be wrong: the loop could be
// re-driving while the gauge read 0, or the reverse, and both would look
// correct in isolation. Driving the loop's own seam and reading the accessor is
// what proves they cannot disagree.
func TestRetryOwnerAccessorsReadTheLoopsOwnGate7615(t *testing.T) {
	// RA: the loop gates on d.raHasDeadSenders(), which the #6793 seam
	// overrides. The accessor must follow it in BOTH directions — a one-way
	// check passes against an accessor hardwired to either constant.
	d := &Daemon{}
	for _, dead := range []bool{true, false} {
		d.raHasDeadSendersFn = func() bool { return dead }
		if got := d.RADeadSenderPending(); got != dead {
			t.Errorf("RADeadSenderPending() = %v while the loop's own gate says %v — "+
				"the gauge and the retry owner would disagree about whether an "+
				"interface is advertising nothing (#7615)", got, dead)
		}
	}

	// Fabric and management-listener accessors must be scrape-safe on a daemon
	// with no store: a Prometheus scrape can land before bring-up, and a panic
	// there takes down the endpoint an operator is using to diagnose the very
	// node that is unhealthy.
	bare := &Daemon{}
	if bare.FabricOverlayMissing() {
		t.Error("FabricOverlayMissing() must report false with no active config, " +
			"not invent a missing overlay for a node that has configured none")
	}
	if got := bare.ManagementListenerDown(); got != bare.mgmtListenerDown() {
		t.Errorf("ManagementListenerDown() = %v but the loop's gate says %v — the "+
			"accessor must read the loop's own predicate, not a parallel one", got,
			bare.mgmtListenerDown())
	}
}
