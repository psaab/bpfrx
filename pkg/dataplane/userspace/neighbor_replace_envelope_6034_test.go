package userspace

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

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
	var (
		mu       sync.Mutex
		requests []ControlRequest
		ackGen   uint64 // ManagerNeighborGeneration the fake helper reports
	)
	requestHook := func(req ControlRequest, status *ProcessStatus) error {
		mu.Lock()
		requests = append(requests, req)
		reply := ackGen
		mu.Unlock()
		if status != nil {
			*status = ProcessStatus{PID: 4321, ManagerNeighborGeneration: reply}
		}
		return nil
	}

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
		m.controlRequestHook = requestHook
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

// TestNeighborReplaceGenerationSeedsFromFirstStatus is the restart guard for
// #6034. A new Manager starts its in-memory replace counter at zero, while a
// surviving helper can retain a much higher applied-generation fence. The
// first status poll must seed the manager from that fence before the next
// replace is allocated, so the helper accepts generation 101 rather than
// fencing generation 1.
func TestNeighborReplaceGenerationSeedsFromFirstStatus(t *testing.T) {
	var (
		helperMu   sync.Mutex
		appliedGen uint64 = 100
	)
	statusSeen := make(chan struct{}, 1)
	neighborReq := make(chan ControlRequest, 1)
	requestHook := func(req ControlRequest, status *ProcessStatus) error {
		helperMu.Lock()
		switch req.Type {
		case "status":
			select {
			case statusSeen <- struct{}{}:
			default:
			}
		case "update_neighbors":
			// Model the helper's strict fence: only a generation above the
			// persisted high-water mark is applied.
			if req.NeighborGeneration > appliedGen {
				appliedGen = req.NeighborGeneration
			}
			select {
			case neighborReq <- req:
			default:
			}
		}
		reply := appliedGen
		helperMu.Unlock()
		if status != nil {
			*status = ProcessStatus{PID: 4321, ManagerNeighborGeneration: reply}
		}
		return nil
	}

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.controlRequestHook = requestHook
	if m.neighborReplaceGen != 0 {
		t.Fatalf("new manager neighborReplaceGen = %d, want reset value 0", m.neighborReplaceGen)
	}

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		m.statusLoop(ctx)
		close(loopDone)
	}()
	select {
	case <-statusSeen:
	case <-time.After(3 * time.Second):
		cancel()
		<-loopDone
		t.Fatal("timed out waiting for first helper status poll")
	}

	deadline := time.Now().Add(time.Second)
	for {
		m.mu.Lock()
		seededGen := m.neighborReplaceGen
		m.mu.Unlock()
		if seededGen == 100 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-loopDone
			t.Fatalf("neighborReplaceGen after first status = %d, want seeded helper generation 100", seededGen)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-loopDone

	seededNeighbor := NeighborSnapshot{
		Ifindex: 13,
		Family:  "inet",
		IP:      "172.16.80.200",
		MAC:     "02:aa:bb:cc:dd:ee",
		State:   "reachable",
	}
	m.lastSnapshot = &ConfigSnapshot{
		Version:    ProtocolVersion,
		Generation: 1,
		Config:     &config.Config{},
		Neighbors:  []NeighborSnapshot{seededNeighbor},
	}
	m.generation = 1
	m.RegenerateNeighborSnapshot()

	select {
	case req := <-neighborReq:
		if req.NeighborGeneration != 101 {
			t.Fatalf("first neighbor replace generation = %d, want 101 (helper fence 100 + 1)", req.NeighborGeneration)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for neighbor replace")
	}
	helperMu.Lock()
	gotApplied := appliedGen
	helperMu.Unlock()
	if gotApplied != 101 {
		t.Fatalf("helper applied generation = %d, want 101", gotApplied)
	}
}
