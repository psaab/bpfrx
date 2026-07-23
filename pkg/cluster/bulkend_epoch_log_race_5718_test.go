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
// This is the fail-on-revert gate: the race detector reports on the FIRST
// unsynchronized concurrent access, so a few thousand tightly interleaved
// iterations suffice and stay fast under -race. It passes cleanly with the
// snapshot fix and DETECTS the race if the log reverts to reading
// s.bulkRecvEpoch after Unlock. Must be run with `go test -race`.
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
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: a locked mutation of bulkRecvEpoch, mirroring the BulkStart
	// handler's s.bulkMu.Lock(); s.bulkRecvEpoch = epoch; s.bulkMu.Unlock()
	// discipline. It alternates between 1 and 2, neither of which equals 7.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			s.bulkMu.Lock()
			if i%2 == 0 {
				s.bulkRecvEpoch = 1
			} else {
				s.bulkRecvEpoch = 2
			}
			s.bulkMu.Unlock()
		}
	}()

	// Reader: the real BulkEnd dispatch path. conn is nil — the mismatch branch
	// never dereferences it.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			s.handleMessage(nil, syncMsgBulkEnd, end)
		}
	}()

	wg.Wait()
}
