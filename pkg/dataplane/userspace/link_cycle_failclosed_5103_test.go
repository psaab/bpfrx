package userspace

import (
	"path/filepath"
	"strings"
	"testing"
)

// #5103: PrepareLinkCycle used to return nothing, so a failed worker join was
// indistinguishable from a successful one and the caller cycled the link
// regardless. The stop_workers failure path was a slog.Warn followed by a bare
// return — visible in the journal, invisible to the code that had to decide
// whether it was safe to take the NIC down.
//
// These bind the error return itself. Without them the signature could carry an
// error that is never non-nil, which is the same fail-open wearing a type.

// TestPrepareLinkCycleErrorsWhenStopWorkersFails_5103 is the fail-closed guard.
// The control server is given NO responses, so the stop_workers request fails,
// and PrepareLinkCycle must report it.
func TestPrepareLinkCycleErrorsWhenStopWorkersFails_5103(t *testing.T) {
	skipLinkCycleRebindSleep(t)

	controlSock := filepath.Join(t.TempDir(), "control.sock")
	m := newLinkCycleProcessOnlyManager(t, controlSock)
	// No control server is started at all: the helper socket does not accept,
	// so the stop_workers request cannot complete. That is exactly the
	// condition under which the workers have NOT been joined.

	err := m.PrepareLinkCycle()
	if err == nil {
		t.Fatal("PrepareLinkCycle returned nil after the stop_workers request failed. The " +
			"workers were not joined, so the caller would take the NIC down while threads " +
			"may still be touching UMEM (#5103)")
	}
	if !strings.Contains(err.Error(), "stop_workers") {
		t.Errorf("error should name the failed step so the journal and the return agree; "+
			"got %v", err)
	}
}

// TestPrepareLinkCycleSucceedsWhenWorkersJoin_5103 is the over-rejection guard.
// An implementation that always returned an error would satisfy the test above
// and block every legitimate RETH MAC link cycle, which is a forwarding outage
// of its own. A healthy helper that answers stop_workers must return nil.
func TestPrepareLinkCycleSucceedsWhenWorkersJoin_5103(t *testing.T) {
	skipLinkCycleRebindSleep(t)

	controlSock := filepath.Join(t.TempDir(), "control.sock")
	m := newLinkCycleProcessOnlyManager(t, controlSock)
	events := startLinkCycleControlServer(t, controlSock, nil, []ProcessStatus{
		{PID: 4242, Bindings: []BindingStatus{{Slot: 1, Ifindex: 2, QueueID: 0, Ready: true}}},
	})

	if err := m.PrepareLinkCycle(); err != nil {
		t.Fatalf("PrepareLinkCycle must return nil when the workers join cleanly; got %v", err)
	}
	first := nextLinkCycleControlEvent(t, events)
	if first.Request.Type != "stop_workers" {
		t.Fatalf("first request type = %q, want stop_workers", first.Request.Type)
	}
}

// TestPrepareLinkCycleNoHelperIsNotAnError_5103 pins the one case that is a
// genuine success rather than a swallowed failure: with no helper process there
// are no workers to join, so a link cycle cannot race one. Reporting an error
// here would block RETH MAC programming on every non-userspace deployment.
func TestPrepareLinkCycleNoHelperIsNotAnError_5103(t *testing.T) {
	m := New()
	if err := m.PrepareLinkCycle(); err != nil {
		t.Errorf("no running helper means no workers to join; got %v", err)
	}
}
