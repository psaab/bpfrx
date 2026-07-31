package cluster

import (
	"encoding/binary"
	"sync"
	"testing"
)

// #5718 (codex-182 C-HA C01b): the syncMsgBulkEnd mismatch-epoch handler read
// s.bulkRecvEpoch in its slog.Warn arguments AFTER releasing s.bulkMu. That
// field is written under s.bulkMu by the BulkStart handler (and by disconnect
// teardown), so a BulkEnd on one fabric receive loop racing a BulkStart on
// another produces an unsynchronized concurrent read/write — a diagnostic-only
// data race the Go memory model forbids and go test -race flags. The fix
// snapshots the expected epoch (want := s.bulkRecvEpoch) BEFORE the Unlock and
// logs the snapshot.
//
// This is the fail-on-revert gate. A start barrier releases the writer and
// reader together, and the writer LOOPS mutating s.bulkRecvEpoch under s.bulkMu
// until the reader signals done, so every BulkEnd dispatch overlaps a live
// concurrent writer. That guaranteed overlap makes the race detector reliably
// observe the concurrent access under both the default GOMAXPROCS and
// GOMAXPROCS=1 — a fixed-count writer that can run to completion before the
// reader starts leaves no concurrent access and false-greens on revert. It
// passes cleanly with the snapshot fix and reliably reports WARNING: DATA RACE
// + FAIL if the log reverts to reading s.bulkRecvEpoch after Unlock. Must be
// run with `go test -race`.
func TestBulkEndMismatchEpochLogNoRace5718(t *testing.T) {
	s := &SessionSync{}
	// A bulk transfer is in progress so the BulkEnd handler reaches the
	// epoch-comparison branch rather than the no-transfer early-out.
	s.bulkInProgress = true
	s.bulkRecvEpoch = 1

	// The incoming BulkEnd always carries an epoch that never matches either
	// value the writer cycles bulkRecvEpoch through, so every call lands in the
	// mismatch branch that logs the protected expected epoch.
	end := make([]byte, 8)
	binary.LittleEndian.PutUint64(end, 7)

	const iters = 5000
	start := make(chan struct{})
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: a locked mutation of bulkRecvEpoch, mirroring the BulkStart
	// handler's s.bulkMu.Lock(); s.bulkRecvEpoch = epoch; s.bulkMu.Unlock()
	// discipline. It loops until the reader signals done so it stays live for
	// the whole reader window, alternating between 1 and 2 (neither equals 7).
	go func() {
		defer wg.Done()
		<-start
		for {
			select {
			case <-done:
				return
			default:
			}
			s.bulkMu.Lock()
			if s.bulkRecvEpoch == 1 {
				s.bulkRecvEpoch = 2
			} else {
				s.bulkRecvEpoch = 1
			}
			s.bulkMu.Unlock()
		}
	}()

	// Reader: the real BulkEnd dispatch path, run for a bounded window while the
	// writer is guaranteed to be concurrently mutating bulkRecvEpoch. conn is
	// nil — the mismatch branch never dereferences it.
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iters; i++ {
			s.handleMessage(nil, syncMsgBulkEnd, end)
		}
		close(done)
	}()

	close(start)
	wg.Wait()
}
