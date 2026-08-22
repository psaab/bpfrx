package vrrp

import (
	"errors"
	"sync"
	"sync/atomic"
)

// ErrStaleVIPOnBackup is the resign verdict for an instance that is already
// BACKUP but whose last VIP removal FAILED and has not yet been cleared by the
// #5482 async reconcile. The address may still be on the wire, so the
// resignation must not be reported as a clean release (#6177 item 1).
var ErrStaleVIPOnBackup = errors.New("vrrp: stale VIP still present on BACKUP instance")

// ResignBarrier reports when a forced RG resignation has been ACTUATED on the
// VRRP run loop — i.e. every targeted instance has physically removed its
// virtual addresses (or reported why it could not) — as opposed to merely
// having the resignation signalled.
//
// #6177 item 1. ResignRG is only half-synchronous: it drops the instance
// priority to 0 under the instance lock (synchronous, so the resigning node
// cannot win a re-election) and then does a NON-BLOCKING send on resignCh. The
// priority-0 advert burst and the becomeBackup VIP removal run later, on the
// instance's own goroutine. A caller that treats ResignRG's return as "the VIPs
// are off the wire" is wrong by the length of one run-loop hop — the sub-ms
// two-owner residual the #5640 hostile review flagged. ResignBarrier closes that
// gap by giving the caller something to wait on that is driven FROM the VIP
// removal itself.
//
// The barrier is one-shot and completes exactly once, when the last targeted
// instance reports. Err reports the first VIP-removal failure observed by any
// instance (nil when every instance released cleanly) — a failed removal means a
// stale VIP may still be answering ARP, which is precisely the two-owner hazard
// the caller is fencing against, so it must not read as a clean resignation.
//
// A barrier with no targeted instances is born complete: there is no VRRP VIP
// tenure to release, so there is nothing to wait for.
type ResignBarrier struct {
	remaining atomic.Int32
	done      chan struct{}

	mu  sync.Mutex
	err error
}

// newResignBarrier builds a barrier awaiting n instance reports. n <= 0 yields
// an already-complete barrier.
func newResignBarrier(n int) *ResignBarrier {
	b := &ResignBarrier{done: make(chan struct{})}
	if n <= 0 {
		close(b.done)
		return b
	}
	b.remaining.Store(int32(n))
	return b
}

// Done returns a channel closed once every targeted instance has reported its
// VIP-release outcome. Read Err after it closes for the verdict.
func (b *ResignBarrier) Done() <-chan struct{} {
	if b == nil {
		return nil
	}
	return b.done
}

// Err returns the first VIP-removal failure reported by any targeted instance,
// or nil when all of them released cleanly. Only meaningful once Done is closed.
func (b *ResignBarrier) Err() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

// report records one instance's VIP-release outcome. The FIRST non-nil error
// wins so the verdict names the earliest failure rather than the last reporter.
// The count is decremented after the error is recorded, so a goroutine that
// observes the close also observes the verdict.
func (b *ResignBarrier) report(err error) {
	if b == nil {
		return
	}
	if err != nil {
		b.mu.Lock()
		if b.err == nil {
			b.err = err
		}
		b.mu.Unlock()
	}
	if b.remaining.Add(-1) == 0 {
		close(b.done)
	}
}
