package vrrp

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestArrivalIfindexDetector binds the VRRP fail-open warning (#7171).
//
// Fresh instance rather than the package global: a process-lifetime sync.Once
// fires on test ORDER rather than on the input, so asserting the global's log
// would make this cell's result depend on what ran before it.
//
// The negative control carries as much weight as the positive one here. This
// guard sits on a path where the NORMAL case -- a platform that does report an
// arrival ifindex -- must stay silent; an implementation that warned on every
// advert would satisfy a positive-only cell while flooding journald at 30ms
// intervals, which is the failure CLAUDE.md's logging rules exist to prevent.
func TestArrivalIfindexDetector(t *testing.T) {
	var d arrivalIfindexDetector
	buf := captureSlog(t)

	// --- negative control: the platform DID report an interface ---
	if d.observe(7, 7) {
		t.Error("observe(7,7) reported an unreported arrival ifindex")
	}
	if d.observe(9, 7) {
		t.Error("observe(9,7) reported unreported; that is a genuine MISMATCH, not a missing cmsg")
	}
	// An instance with no resolved index is a test construction, not an
	// operator-actionable platform fault, and must stay silent too.
	if d.observe(0, 0) {
		t.Error("observe(0,0) reported; expectedIfindex <= 0 is not the reportable case")
	}
	if got := d.count(); got != 0 {
		t.Errorf("count after non-reportable observations = %d, want 0", got)
	}
	if buf.Len() != 0 {
		t.Errorf("non-reportable state emitted a warning: %q", buf.String())
	}

	// --- positive: real instance, platform omitted the cmsg ---
	if !d.observe(0, 7) {
		t.Fatal("observe(0,7) did not report an unreported arrival ifindex")
	}
	if got := d.count(); got != 1 {
		t.Errorf("count = %d, want 1", got)
	}
	logged := buf.String()
	for _, want := range []string{
		"did not report an arrival interface",
		"expected_ifindex=7",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("warning does not contain %q; got %q", want, logged)
		}
	}

	// --- every occurrence detected, log still fires once ---
	// This condition is not a one-off: on an affected platform it is EVERY
	// advert. A bare Once reports one occurrence and a million identically.
	sizeAfterFirst := buf.Len()
	if !d.observe(0, 7) {
		t.Fatal("second occurrence not reported")
	}
	if got := d.count(); got != 2 {
		t.Errorf("count after second occurrence = %d, want 2 (detection must advance every time)", got)
	}
	if buf.Len() != sizeAfterFirst {
		t.Error("warning re-emitted on the second occurrence; the once-guard should suppress it")
	}
}

// TestAcceptArrivalIfindexWiresDetector binds the detector TO THE PRODUCTION
// PATH. The cells above prove the detector behaves; deleting the observe call
// from acceptArrivalIfindex leaves all of them green. Delta-based, so it does
// not care whether an earlier test in this binary already tripped the global.
func TestAcceptArrivalIfindexWiresDetector(t *testing.T) {
	// Negative control through the real function: a reported, matching
	// interface is the healthy path and must register nothing.
	before := unreportedArrivalIfindex.count()
	if !acceptArrivalIfindex(7, 7) {
		t.Fatal("acceptArrivalIfindex(7,7) rejected a matching arrival interface")
	}
	if acceptArrivalIfindex(9, 7) {
		t.Fatal("acceptArrivalIfindex(9,7) accepted a mismatched arrival interface")
	}
	if got := unreportedArrivalIfindex.count(); got != before {
		t.Errorf("healthy path registered %d occurrence(s)", got-before)
	}

	// Positive through the real function: fails OPEN (still true) and is now
	// recorded rather than silent -- both halves matter, since the fix must not
	// change the fail-open behaviour it exists to make visible.
	if !acceptArrivalIfindex(0, 7) {
		t.Fatal("acceptArrivalIfindex(0,7) must still fail OPEN")
	}
	if got := unreportedArrivalIfindex.count(); got != before+1 {
		t.Fatalf("acceptArrivalIfindex did not register the unreported arrival (delta %d, want 1)", got-before)
	}
}
