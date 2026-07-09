package userspace

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// serialWatchConn is a net.Conn stub used to prove writeFrame serializes
// SetWriteDeadline+Write per frame (#4835).
//
// Its SetWriteDeadline and Write mutate UNSYNCHRONIZED fields (deadlineSets /
// writeCalls) on purpose: with the pre-fix writeFrame — which released the
// lock before SetWriteDeadline+Write — two goroutines execute that window
// concurrently and the Go race detector trips on those unguarded fields. The
// writeMu fix serializes the window, so the accesses are no longer concurrent
// and the test is race-clean.
//
// It also records the peak number of goroutines simultaneously inside the
// deadline+write window (via atomics, which do NOT mask the primary race on
// the unguarded fields). peakWindow > 1 means two frames interleaved — a
// deterministic failure signal that also works without the race detector.
type serialWatchConn struct {
	net.Conn // embedded; the remaining methods are never called by writeFrame

	// Unsynchronized on purpose — concurrent access is the #4835 race signal.
	deadlineSets int
	writeCalls   int

	inWindow   atomic.Int32
	peakWindow atomic.Int32
	widen      time.Duration
}

func (c *serialWatchConn) enter() {
	n := c.inWindow.Add(1)
	for {
		p := c.peakWindow.Load()
		if n <= p || c.peakWindow.CompareAndSwap(p, n) {
			return
		}
	}
}

// SetWriteDeadline opens the deadline+write window.
func (c *serialWatchConn) SetWriteDeadline(time.Time) error {
	c.enter()
	c.deadlineSets++ // UNSYNCHRONIZED
	return nil
}

// Write closes the window. A small sleep widens the window so that, absent
// serialization, two writers reliably overlap (peakWindow reaches 2).
func (c *serialWatchConn) Write(b []byte) (int, error) {
	if c.widen > 0 {
		time.Sleep(c.widen)
	}
	c.writeCalls++ // UNSYNCHRONIZED
	c.inWindow.Add(-1)
	return len(b), nil
}

// TestEventStreamWriteFrameSerializesDeadlineAndWrite spins up many concurrent
// writeFrame callers (mirroring ackLoop's ticker racing SendPause / SendResume
// / SendDrainRequest) against one conn and asserts the SetWriteDeadline+Write
// pair is atomic per frame. With the pre-fix code (es.mu released before the
// write) this fails two ways: `go test -race` reports a DATA RACE on the
// conn's unguarded fields, and peakWindow exceeds 1. The writeMu fix makes it
// pass on both.
func TestEventStreamWriteFrameSerializesDeadlineAndWrite(t *testing.T) {
	es := NewEventStream("")
	fc := &serialWatchConn{widen: 200 * time.Microsecond}
	es.mu.Lock()
	es.conn = fc
	es.mu.Unlock()

	const writers = 8
	const perWriter = 64
	payload := []byte{1, 2, 3, 4}

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				// Alternate empty and payload frames so both write
				// branches of writeFrame are exercised under contention.
				var err error
				if i%2 == 0 {
					err = es.writeFrame(EventTypeAck, uint64(i), nil)
				} else {
					err = es.writeFrame(EventTypePause, uint64(i), payload)
				}
				if err != nil {
					t.Errorf("writeFrame: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if peak := fc.peakWindow.Load(); peak > 1 {
		t.Fatalf("writeFrame allowed %d concurrent SetWriteDeadline+Write windows; "+
			"the deadline+write must be atomic per frame (want peak <= 1)", peak)
	}

	wantFrames := uint64(writers * perWriter)
	if got := es.FramesWritten.Load(); got != wantFrames {
		t.Fatalf("FramesWritten = %d, want %d", got, wantFrames)
	}
	if fc.deadlineSets != int(wantFrames) || fc.writeCalls != int(wantFrames) {
		t.Fatalf("deadlineSets=%d writeCalls=%d, want both %d",
			fc.deadlineSets, fc.writeCalls, wantFrames)
	}
}
