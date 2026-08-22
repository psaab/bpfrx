package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// #6566 member 2: `clear security policies hit-count` must reach the HELPER,
// not the retired-eBPF array.
//
// `LegacyDataPlaneAdapter` had no ClearPolicyCounters method, so the embedded
// dataplane.DataPlane (= bpfShim) was PROMOTED and its ClearPolicyCounters
// zeroed the retired `policy_counters` per-CPU array — 4096 slots nothing has
// incremented since the eBPF dataplane was retired (#1373/#1476). It returned
// nil, so both operator surfaces printed "policy hit counters cleared" while
// the counters the display actually READS (the helper's live
// PolicyCounterStore, reached via the ReadAllPolicyCounters override) were
// untouched.
//
// The operator-visible symptom is an asymmetry on ONE box: `clear security
// counters` DOES reset policy hit counts (it routes through the
// ClearAllCounters override), while `clear security policies hit-count` does
// NOT. Same counters, two commands, opposite outcomes, both reporting success.
//
// NOTE on the issue text: the READ half of that cohort row ("per-policy hit
// counts read the retired eBPF array on all 5 surfaces") was already FIXED by
// the ReadAllPolicyCounters adapter override before this sweep, and canary
// tests enforce the bulk reader on every display site. The CLEAR half is the
// live defect, and it is the one this test binds.
//
// FAIL-ON-REVERT: delete the adapter's ClearPolicyCounters method and the call
// promotes to bpfShim again — no clear_policy_counters IPC is sent and the
// assertion below fails. That is the WIRING, not the function it calls:
// Manager.ClearPolicyCounters is unchanged and keeps working either way, which
// is exactly why the defect survived.

func TestAdapterClearPolicyCountersReachesTheHelper(t *testing.T) {
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	reqCh := make(chan string, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				conn.Close()
				return
			}
			reqCh <- req.Type
			_ = json.NewEncoder(conn).Encode(ControlResponse{
				OK:     true,
				Status: &ProcessStatus{},
			})
			conn.Close()
		}
	}()

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock

	// Drive the ADAPTER, which is what the operator surfaces hold
	// (pkg/cli/cli_clear.go and pkg/grpcapi/server_diag_system_action.go both
	// call ClearPolicyCounters on the dataplane.DataPlane interface).
	adapter := &LegacyDataPlaneAdapter{manager: m}
	// The returned error is IGNORED on purpose. Manager.ClearPolicyCounters
	// calls the bpfShim leg first and JOINS its error, and in a unit test no
	// BPF map is loaded, so it always reports "dataplane not armed:
	// policy_counters". That leg is not the property under test — the helper
	// IPC is, and it is sent unconditionally afterwards. Asserting err == nil
	// here would make the test fail for a reason unrelated to the defect.
	_ = adapter.ClearPolicyCounters()

	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-reqCh:
			if got == "clear_policy_counters" {
				return // the property
			}
		case <-deadline:
			t.Fatal("the helper never received a clear_policy_counters IPC — " +
				"the clear was promoted to the retired-eBPF bpfShim array, so " +
				"the live PolicyCounterStore the display reads is untouched " +
				"while the operator is told the counters were cleared")
		}
	}
}

// TestAdapterClearAllCountersAlsoClearsPolicyCounters pins the OTHER half of
// the asymmetry, so a future change cannot fix one command by breaking the
// other. Both commands must reach the helper.
func TestAdapterClearAllCountersAlsoClearsPolicyCounters(t *testing.T) {
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	reqCh := make(chan string, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				conn.Close()
				return
			}
			reqCh <- req.Type
			_ = json.NewEncoder(conn).Encode(ControlResponse{
				OK:     true,
				Status: &ProcessStatus{},
			})
			conn.Close()
		}
	}()

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock

	adapter := &LegacyDataPlaneAdapter{manager: m}
	// Ignored for the same reason as above: the unarmed bpfShim leg is joined
	// into the error and is not the property under test.
	_ = adapter.ClearAllCounters()

	seen := map[string]bool{}
	deadline := time.After(5 * time.Second)
	for !seen["clear_policy_counters"] {
		select {
		case got := <-reqCh:
			seen[got] = true
		case <-deadline:
			t.Fatalf("clear-all never sent clear_policy_counters; saw %v", seen)
		}
	}
}
