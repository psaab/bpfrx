package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestNeighborReplaceEnvelopeCarriesGenerationAndRetainsRetryDebt is the #6034
// fail-on-revert guard for the manager-neighbor replace-generation envelope.
//
// It binds BOTH halves of the mechanism:
//
//   - ENVELOPE CARRY: an authoritative update_neighbors replace must stamp the
//     monotonic Manager.neighborReplaceGen onto ControlRequest.NeighborGeneration
//     so the helper can fence a stale/reordered replace and ACK the applied
//     generation. Reverting the NeighborGeneration stamp makes the captured
//     request carry generation 0 and fails the carry assertion.
//
//   - RETRY DEBT: when the helper's ACK (ProcessStatus.ManagerNeighborGeneration)
//     is BELOW the sent generation — i.e. the replace was fenced as stale — the
//     manager must NOT advance its cached neighbor view, so the next
//     regeneration re-diffs and retries. Reverting the ACK check makes the
//     manager advance m.lastSnapshot.Neighbors even on a non-ack and fails the
//     debt assertion. The complementary sub-case proves a matching ACK DOES
//     advance the cached view (so the guard cannot be satisfied by never
//     advancing).
//
// The publish path is driven deterministically without kernel neighbor state:
// a config with no interfaces makes buildNeighborSnapshots return nil, so a
// seeded non-empty lastSnapshot.Neighbors always diffs and triggers the replace.
func TestNeighborReplaceEnvelopeCarriesGenerationAndRetainsRetryDebt(t *testing.T) {
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	var (
		mu       sync.Mutex
		requests []ControlRequest
		ackGen   uint64 // ManagerNeighborGeneration the fake helper reports
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				conn.Close()
				continue
			}
			mu.Lock()
			requests = append(requests, req)
			reply := ackGen
			mu.Unlock()
			_ = json.NewEncoder(conn).Encode(ControlResponse{
				OK:     true,
				Status: &ProcessStatus{PID: 4321, ManagerNeighborGeneration: reply},
			})
			conn.Close()
		}
	}()

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}

	seeded := NeighborSnapshot{
		Ifindex: 13,
		Family:  "inet",
		IP:      "172.16.80.200",
		MAC:     "02:aa:bb:cc:dd:ee",
		State:   "reachable",
	}

	newManager := func(ack uint64) *Manager {
		m := New()
		m.proc = &exec.Cmd{Process: proc}
		m.cfg.ControlSocket = controlSock
		// Empty config -> buildNeighborSnapshots returns nil, so the seeded
		// (publishable) neighbor always diffs and triggers the replace.
		m.lastSnapshot = &ConfigSnapshot{
			Version:    ProtocolVersion,
			Generation: 1,
			Config:     &config.Config{},
			Neighbors:  []NeighborSnapshot{seeded},
		}
		m.generation = 1
		// Pre-seed so the next allocated replace generation is 5 (lets the
		// debt case report a non-zero ACK of 4 that is strictly below it).
		m.neighborReplaceGen = 4
		mu.Lock()
		ackGen = ack
		mu.Unlock()
		return m
	}

	lastRequestGen := func() uint64 {
		mu.Lock()
		defer mu.Unlock()
		if len(requests) == 0 {
			t.Fatalf("no update_neighbors request was sent")
		}
		return requests[len(requests)-1].NeighborGeneration
	}

	// --- Sub-case 1: helper fences the replace (ACK below sent gen) ---------
	// Manager must retain retry debt: cached neighbor view stays seeded.
	debtMgr := newManager(4)
	debtMgr.RegenerateNeighborSnapshot()

	if got := lastRequestGen(); got != 5 {
		t.Fatalf("ENVELOPE CARRY revert: update_neighbors NeighborGeneration = %d, want 5", got)
	}
	debtMgr.mu.Lock()
	debtNeighbors := append([]NeighborSnapshot(nil), debtMgr.lastSnapshot.Neighbors...)
	debtMgr.mu.Unlock()
	if len(debtNeighbors) != 1 || debtNeighbors[0] != seeded {
		t.Fatalf("RETRY DEBT revert: after a fenced replace (ACK 4 < sent 5) lastSnapshot.Neighbors = %+v, "+
			"want the seeded entry retained so the next regeneration retries", debtNeighbors)
	}

	// --- Sub-case 2: helper acknowledges the applied generation ------------
	// Manager must advance its cached view to the new (empty) set.
	okMgr := newManager(5)
	okMgr.RegenerateNeighborSnapshot()

	if got := lastRequestGen(); got != 5 {
		t.Fatalf("ENVELOPE CARRY: update_neighbors NeighborGeneration = %d, want 5", got)
	}
	okMgr.mu.Lock()
	okNeighbors := append([]NeighborSnapshot(nil), okMgr.lastSnapshot.Neighbors...)
	okMgr.mu.Unlock()
	if len(okNeighbors) != 0 {
		t.Fatalf("acknowledged replace (ACK 5 >= sent 5) must advance the cached neighbor view to empty, "+
			"got %+v", okNeighbors)
	}
}
