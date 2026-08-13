package userspace

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// #6871: NotifyLinkCycle used to be a slog.Warn and a bare return on a void
// function, so a rebind that did not land left every worker stopped WHILE THE
// COMMIT REPORTED SUCCESS — a silent total dataplane outage on that node,
// indistinguishable from a clean cycle to the one caller that reports the
// commit. The error return is what makes the daemon's "this path owns its own
// rollback" claim true rather than attempted.
//
// These are the NotifyLinkCycle half of the mirror suite in
// link_cycle_failclosed_5103_test.go, and they exist for the same reason and
// with the same structure. Read that file's header first — everything it says
// about PrepareLinkCycle applies verbatim here.
//
// They call through m.Link() — the userspaceLinkController adapter — rather than
// m.NotifyLinkCycle() directly, because that adapter is the ONLY production path
// from the daemon down to the manager (daemon_apply_dataplane.go ->
// dataplane.LinkController.NotifyLinkCycle -> Manager.NotifyLinkCycle), on BOTH
// of the daemon's uses of it: step 2.6b2 completing a cycle, and
// programRethMACWithWorkerJoin rolling an aborted one back.
//
// That distinction is not theoretical. Before these tests the production line
// could be severed TWO independent ways with the whole suite still green:
//
//   - the producer: replace process_linkcycle.go's
//     `return fmt.Errorf("userspace: rebind after link cycle: %w", err)` with the
//     pre-#6871 bare `return nil`; or
//   - the transport: change this adapter to
//     `_ = c.manager.NotifyLinkCycle(); return nil`.
//
// Neither was caught, because the daemon-side tests
// (reth_rollback_failure_6871_test.go, reth_prepare_abort_recovery_5103_test.go)
// drive abortRecoveryLinkController.notifyErr — a FAKE — and so bind the
// daemon's CONSUMPTION of the error, never the manager's PRODUCTION of it; and
// link_cycle_test.go calls the real m.NotifyLinkCycle() as a bare statement,
// discarding the return. No daemon test constructs a real userspace.Manager.
//
// The DISCRIMINATOR (cell 1, TestNotifyLinkCycleErrorsWhenRebindFails_6871) goes
// RED on BOTH reverts — that is the property that matters, since a cell catching
// only one of two independent severances leaves the other live. The other three
// cells are CONTROLS and stay GREEN under both, which is what makes them
// controls: they assert that a LANDED rebind, a helperless manager and a nil
// manager adapter each still report success, and neither revert can break that
// (both only ever turn an error into a nil). An earlier revision of this comment
// said "each cell below goes RED on BOTH reverts", which would have made the
// controls restatements of the discriminator rather than guards against
// over-reach (#6871 round 6).
//
// Deliberately NO BPF maps: none of these cells needs one, so they RUN
// unprivileged rather than SKIP. A cell that skips is not a cell that passed.

// startOneShotLinkCycleServer answers exactly one control request with an OK
// status and then CLOSES the listener, so the next request fails at dial.
//
// That is what makes cell 1 a rebind failure specifically: PrepareLinkCycle's
// stop_workers is served normally (the workers really are joined, which is the
// state the daemon is in when it calls NotifyLinkCycle), and only the rebind
// finds nothing listening. Reusing startLinkCycleControlServer with one response
// would leave the listener open with nobody accepting, so the rebind would hang
// to its round-trip deadline instead — a timeout rather than the refusal a dead
// helper actually produces.
func startOneShotLinkCycleServer(t *testing.T, sock string, status ProcessStatus) {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() {
			_ = conn.Close()
			// The helper is gone from here on: no listener, so the rebind's
			// dial is refused rather than left to time out.
			_ = ln.Close()
		}()
		var req ControlRequest
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}
		resp := status
		_ = json.NewEncoder(conn).Encode(ControlResponse{OK: true, Status: &resp})
	}()
}

// TestNotifyLinkCycleErrorsWhenRebindFails_6871 is the fail-closed guard.
//
// The helper serves stop_workers and then stops, which is exactly the state that
// makes the silent outage possible: the workers ARE joined, ctrl IS off, and the
// rebind that would bring them back cannot be delivered. NotifyLinkCycle must
// report that, because the caller folds it into the commit error.
func TestNotifyLinkCycleErrorsWhenRebindFails_6871(t *testing.T) {
	skipLinkCycleRebindSleep(t)

	controlSock := filepath.Join(t.TempDir(), "control.sock")
	m := newLinkCycleProcessOnlyManager(t, controlSock)
	startOneShotLinkCycleServer(t, controlSock, ProcessStatus{
		PID:      4242,
		Bindings: []BindingStatus{{Slot: 1, Ifindex: 2, QueueID: 0, Ready: true}},
	})

	link := m.Link()
	if err := link.PrepareLinkCycle(); err != nil {
		t.Fatalf("PrepareLinkCycle must succeed against the one served response; got %v", err)
	}

	err := link.NotifyLinkCycle()
	if err == nil {
		t.Fatal("NotifyLinkCycle returned nil after the rebind request failed. The workers " +
			"stop_workers joined are still stopped and ctrl is still off, so this node is " +
			"forwarding NOTHING — and the caller (step 2.6b2, and the abort rollback in " +
			"programRethMACWithWorkerJoin) just reported the commit SUCCEEDED (#6871)")
	}
	if !strings.Contains(err.Error(), "rebind") {
		t.Errorf("error should name the failed step so the journal and the return agree; "+
			"got %v", err)
	}
}

// TestNotifyLinkCycleSucceedsWhenRebindLands_6871 is the over-rejection guard.
// An implementation that always returned an error would satisfy the test above
// and fail EVERY RETH MAC commit — including the ones whose dataplane is
// perfectly healthy — which is an outage of its own wearing the fix's clothes.
// A helper that answers both requests must yield nil from both calls.
func TestNotifyLinkCycleSucceedsWhenRebindLands_6871(t *testing.T) {
	skipLinkCycleRebindSleep(t)

	controlSock := filepath.Join(t.TempDir(), "control.sock")
	m := newLinkCycleProcessOnlyManager(t, controlSock)
	events := startLinkCycleControlServer(t, controlSock, nil, []ProcessStatus{
		{PID: 7001, Bindings: []BindingStatus{{Slot: 1, Ifindex: 2, QueueID: 0, Ready: true}}},
		{PID: 7002, Workers: 2, Bindings: []BindingStatus{{Slot: 1, Ifindex: 2, QueueID: 0, Ready: true}}},
	})

	link := m.Link()
	if err := link.PrepareLinkCycle(); err != nil {
		t.Fatalf("PrepareLinkCycle must return nil when the workers join cleanly; got %v", err)
	}
	first := nextLinkCycleControlEvent(t, events)
	if first.Request.Type != "stop_workers" {
		t.Fatalf("first request type = %q, want stop_workers", first.Request.Type)
	}

	if err := link.NotifyLinkCycle(); err != nil {
		t.Fatalf("NotifyLinkCycle must return nil when the rebind lands; got %v", err)
	}
	second := nextLinkCycleControlEvent(t, events)
	if second.Request.Type != "rebind" {
		t.Fatalf("second request type = %q, want rebind", second.Request.Type)
	}
}

// TestNotifyLinkCycleNoHelperIsNotAnError_6871 pins the one case that is a
// genuine success rather than a swallowed failure: with no helper process there
// are no workers to rebind. Reporting an error here would fail RETH MAC
// programming on every non-userspace deployment.
func TestNotifyLinkCycleNoHelperIsNotAnError_6871(t *testing.T) {
	skipLinkCycleRebindSleep(t)

	m := New()
	if err := m.Link().NotifyLinkCycle(); err != nil {
		t.Errorf("no running helper means no workers to rebind; got %v", err)
	}
}

// TestNotifyLinkCycleNilManagerAdapterIsNotAnError_6871 pins the adapter's own
// nil-manager branch — the one place it may answer nil without consulting a
// manager, and it must stay that way: an adapter that reported an error here
// would abort RETH MAC programming on every deployment with no userspace manager
// wired. Together with the two guards above this is the negative control: an
// adapter that always returned an error would satisfy the fail-closed assertion
// and fail these two.
func TestNotifyLinkCycleNilManagerAdapterIsNotAnError_6871(t *testing.T) {
	var c userspaceLinkController // manager == nil
	if err := c.NotifyLinkCycle(); err != nil {
		t.Errorf("a nil manager means no workers to rebind; got %v", err)
	}
}
