package daemon

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

// #4691: restoreStep0TunablesOnShutdown must serialize against an un-drained
// apply by acquiring d.applySem before touching the priorTunables snapshot.
// applyStep0TunablesWith mutates the snapshot's maps outside priorTunablesMu
// (under d.applySem, via applyConfig), so a DHCP lease apply still in flight at
// shutdown would otherwise race the restore's snapshot handoff + map ops.
//
// Lock-held assertion: hold applySem (simulating an in-flight apply), then
// launch restore. It must BLOCK until applySem is released, and complete
// promptly afterwards.
//
// RED-on-revert: dropping the d.applySem.Acquire in
// restoreStep0TunablesOnShutdown lets restore run to completion while the
// semaphore is held, so the "blocked while held" assertion below fires RED.
func TestRestoreStep0TunablesAcquiresApplySem(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}

	// Simulate an in-flight apply holding the apply lock.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("pre-acquire applySem: %v", err)
	}

	done := make(chan struct{})
	go func() {
		d.restoreStep0TunablesOnShutdown()
		close(done)
	}()

	// While the apply lock is held, restore must not finish.
	select {
	case <-done:
		t.Fatal("restoreStep0TunablesOnShutdown completed while applySem was held — " +
			"it did not serialize against the apply lock (#4691)")
	case <-time.After(150 * time.Millisecond):
		// Correctly blocked on applySem.
	}

	// Release the apply lock; restore must now proceed to completion.
	d.applySem.Release(1)
	select {
	case <-done:
		// Completed once the lock was free.
	case <-time.After(2 * time.Second):
		t.Fatal("restoreStep0TunablesOnShutdown did not complete after applySem released (#4691)")
	}

	// The lock must be free again afterwards (restore released it).
	if !d.applySem.TryAcquire(1) {
		t.Fatal("restoreStep0TunablesOnShutdown did not release applySem")
	}
	d.applySem.Release(1)
}
