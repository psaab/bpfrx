package daemon

// ra_dead_sender_retry_6793_test.go — #6793 RETRY-OWNER regression.
//
// pkg/ra's cells bind the probe and the rebuild. They stay GREEN when nothing
// ever calls Apply again — which IS the bug: standalone applies RA only from
// applyServicesReconcile (a config apply), and reconcileRGStateLoop is
// cluster-only, so a boot-time bind failure left an interface advertising
// nothing until an operator happened to commit.

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// standaloneRADaemon6793 builds a daemon with a committed standalone config
// carrying one RA interface, plus spies for the applier and the dead-sender
// probe.
func standaloneRADaemon6793(t *testing.T, dead bool) (*Daemon, *int, *sync.Mutex) {
	t.Helper()
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet6 {
                address 2001:db8:61::1/64;
            }
        }
    }
}
protocols {
    router-advertisement {
        interface ge-0/0/0.0 {
            prefix 2001:db8:61::/64;
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0.0;
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()

	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("fixture must commit a config")
	}
	if cfg.Chassis.Cluster != nil {
		t.Fatal("fixture must be STANDALONE — the cluster path has its own driver")
	}

	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	// Guard the fixture's own premise: an empty desired RA set would make the
	// applier a no-op and every assertion below vacuous.
	if got := len(d.buildRAConfigs(cfg)); got == 0 {
		t.Fatal("fixture built ZERO RA configs, so the reassert would have " +
			"nothing to apply and this test could not distinguish a working " +
			"retry owner from a missing one")
	}

	var mu sync.Mutex
	applies := 0
	d.raApplyFn = func([]*config.RAInterfaceConfig) error {
		mu.Lock()
		applies++
		mu.Unlock()
		return nil
	}
	d.raHasDeadSendersFn = func() bool { return dead }
	return d, &applies, &mu
}

// TestDeadSenderReassertAppliesOnlyWhenASenderIsDead6793 is the PAIRED wiring
// cell: the same tick, two probe answers, opposite outcomes.
//
// The healthy leg is the one that keeps the fix from being a new bug. An
// always-on loop that re-applied RA unconditionally would restart every healthy
// sender every 30s — a periodic RA gap on a working firewall, which is worse
// than the silence it is meant to cure.
func TestDeadSenderReassertAppliesOnlyWhenASenderIsDead6793(t *testing.T) {
	t.Run("dead-sender-is-re-driven", func(t *testing.T) {
		d, applies, mu := standaloneRADaemon6793(t, true)
		d.reassertDeadRASendersOnce(context.Background())
		mu.Lock()
		got := *applies
		mu.Unlock()
		if got != 1 {
			t.Fatalf("the reassert applied RA %d times for a DEAD sender, want "+
				"1 — standalone has no other driver (applyServicesReconcile runs "+
				"only on a config apply, reconcileRGStateLoop is cluster-only), "+
				"so without this the interface advertises nothing until an "+
				"operator happens to commit (#6793)", got)
		}
	})

	t.Run("no-applier-and-no-manager-is-safe", func(t *testing.T) {
		// The loop is started UNCONDITIONALLY, so it ticks on daemons that
		// never built an RA manager. It must not panic there.
		store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
		if err != nil {
			t.Fatalf("configstore.New: %v", err)
		}
		d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
		d.reassertDeadRASendersOnce(context.Background())
	})
}

// TestDeadSenderReassertIsANoOpWhenEverySenderIsHealthy6793 pins the gate
// itself, with no RA manager needed: a tick whose probe says "no dead sender"
// must not touch the applier.
//
// RED-on-revert: drop the `!d.raHasDeadSenders()` early return from
// reassertDeadRASendersOnce and this fires — an unconditional 30s RA re-apply.
func TestDeadSenderReassertIsANoOpWhenEverySenderIsHealthy6793(t *testing.T) {
	d, applies, mu := standaloneRADaemon6793(t, false)
	d.reassertDeadRASendersOnce(context.Background())
	mu.Lock()
	got := *applies
	mu.Unlock()
	if got != 0 {
		t.Fatalf("the reassert applied RA %d times with NO dead sender — an "+
			"always-on loop that re-applies unconditionally restarts every "+
			"healthy sender on its cadence, a periodic RA gap on a working "+
			"firewall (#6793)", got)
	}
}

// TestClusterReconcileBypassesTheDigestForADeadSender6793 pins the OTHER half.
// reconcileClusterRAServices runs every 2s but is digest-gated, and a dead
// sender does not move the digest — so its own doc comment's promise ("a
// transient apply error is retried on the next pass") did not hold for the one
// failure the digest cannot see.
//
// PAIRED on the same converged state: with no dead sender the digest must still
// short-circuit, or the 2s loop would re-apply RA forever.
func TestClusterReconcileBypassesTheDigestForADeadSender6793(t *testing.T) {
	newClusterDaemon := func(t *testing.T, dead bool) (*Daemon, *int, *sync.Mutex) {
		t.Helper()
		store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
		if err != nil {
			t.Fatalf("configstore.New: %v", err)
		}
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := store.LoadOverride(`
chassis {
    cluster {
        cluster-id 1;
        node 0;
        authentication-key "cyaLE6jUXcHqZBB6xSJP7CVc5S9dHRBAtF5vTBqFEss=";
    }
}
`); err != nil {
			t.Fatalf("LoadOverride: %v", err)
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		store.ExitConfigure()
		if store.ActiveConfig().Chassis.Cluster == nil {
			t.Fatal("fixture must commit a CLUSTER config")
		}

		d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
		var mu sync.Mutex
		applies := 0
		d.raApplyFn = func([]*config.RAInterfaceConfig) error {
			mu.Lock()
			applies++
			mu.Unlock()
			return nil
		}
		d.raHasDeadSendersFn = func() bool { return dead }
		return d, &applies, &mu
	}

	// Converge first: one pass applies and records the digest. With no RA
	// configured the desired set is empty, which still produces a stable digest
	// — that is the case where a dead sender is most invisible.
	t.Run("converged-then-dead-sender-re-drives", func(t *testing.T) {
		d, applies, mu := newClusterDaemon(t, false)
		d.reconcileClusterRAServices("converge")
		mu.Lock()
		afterConverge := *applies
		mu.Unlock()

		// A second pass with nothing changed must be free.
		d.reconcileClusterRAServices("idempotent")
		mu.Lock()
		afterIdempotent := *applies
		mu.Unlock()
		if afterIdempotent != afterConverge {
			t.Fatalf("the digest gate stopped short-circuiting (%d -> %d applies) "+
				"— the 2s loop would re-apply RA on every tick",
				afterConverge, afterIdempotent)
		}

		// Now a sender dies. The digest has NOT moved.
		d.raHasDeadSendersFn = func() bool { return true }
		d.reconcileClusterRAServices("dead-sender")
		mu.Lock()
		afterDead := *applies
		mu.Unlock()
		if afterDead <= afterIdempotent {
			t.Fatalf("a DEAD sender did not re-drive the cluster reconcile "+
				"(%d applies, unchanged) — the desired-set digest cannot see a "+
				"dead sender, so the interface stays silent until an unrelated "+
				"config change moves the hash (#6793)", afterDead)
		}
	})
}
