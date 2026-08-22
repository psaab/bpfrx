package daemon

import (
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #6716: the background apply callbacks must reconcile against the config that
// is ACTIVE when they get the apply semaphore, not the one they read before
// waiting for it.
//
// The inversion is a real interleaving, not a simulated one: this test HOLDS an
// apply inside the applyBodyForTest seam, lands a genuine commit of config B on
// another goroutine while that apply owns applySem, then releases. A caller that
// captured A before blocking would apply A after B was committed — silently
// reverting the operator's commit in every subsystem applyConfigLocked drives,
// with no error anywhere.
//
// The assertion reads the config the apply body actually received, because that
// is the value the whole pipeline is driven from. Asserting merely that "an
// apply happened" is what let this hide: both the correct and the inverted path
// apply exactly once and both return success.

// applyRereadHarness6716 builds a daemon whose store holds config A active, with
// the apply body replaced by a recorder that can be blocked mid-apply.
func applyRereadHarness6716(t *testing.T) (*Daemon, *configstore.Store) {
	t.Helper()
	s := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := s.LoadSet(applyRereadSets6716("A")); err != nil {
		t.Fatalf("LoadSet(A): %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit(A): %v", err)
	}
	return &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    s,
		opts:     Options{NoDataplane: true},
	}, s
}

// applyRereadSets6716 returns a config whose description carries the marker, so
// the config that reached the apply body is identifiable by value.
func applyRereadSets6716(marker string) string {
	return "set interfaces ge-0/0/0 description " + marker + "\n" +
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24\n"
}

// applyRereadMarker6716 extracts the marker from a compiled config.
func applyRereadMarker6716(t *testing.T, cfg *config.Config) string {
	t.Helper()
	if cfg == nil {
		return "<nil>"
	}
	if iface := cfg.Interfaces.Interfaces["ge-0/0/0"]; iface != nil {
		return iface.Description
	}
	return "<absent>"
}

// TestBackgroundCallbacksRereadTheActiveConfig6716 is the defect proper, driven
// through the REAL production callbacks.
//
// It deliberately does NOT call applyActiveConfig directly. That would bind the
// FUNCTION and leave the WIRING free: reverting either call site back to the
// pre-captured pointer keeps such a test green, which is exactly how the defect
// survived. Each subtest invokes the callback the daemon actually registers.
func TestBackgroundCallbacksRereadTheActiveConfig6716(t *testing.T) {
	for _, tc := range []struct {
		name string
		fire func(*Daemon)
	}{
		{"DHCP lease change", func(d *Daemon) { d.onDHCPAddressChange() }},
		{"dynamic feed update", func(d *Daemon) { _ = d.onFeedUpdate() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, s := applyRereadHarness6716(t)

			var applied []string
			d.applyBodyForTest = func(cfg *config.Config) {
				applied = append(applied, applyRereadMarker6716(t, cfg))
			}

			// The seam fires AFTER the callback has read config for its own
			// decisions and BEFORE it hands off to the apply. Committing B here
			// reproduces the real interleaving — callback reads A, operator's
			// commit lands, apply runs — without a sleep or a scheduler race.
			// Firing the callback after an already-landed commit instead would
			// let its own read see B and pass either way.
			var once sync.Once
			d.preApplyHookForTest = func() {
				once.Do(func() {
					if _, err := s.LoadSet(applyRereadSets6716("B")); err != nil {
						t.Errorf("LoadSet(B): %v", err)
						return
					}
					if _, err := s.Commit(); err != nil {
						t.Errorf("Commit(B): %v", err)
					}
				})
			}

			tc.fire(d)

			if got := applyRereadMarker6716(t, s.ActiveConfig()); got != "B" {
				t.Fatalf("test setup: active config after the commit = %q, want B", got)
			}
			if len(applied) != 1 {
				t.Fatalf("expected exactly 1 apply from the callback, got %d: %v", len(applied), applied)
			}
			if applied[0] != "B" {
				t.Errorf("the %s callback applied %q after the operator committed B — a "+
					"background apply REVERTED a newer commit across every subsystem "+
					"applyConfigLocked reconciles, with no error reported anywhere. "+
					"The callback must reconcile against the config active when it gets "+
					"applySem, not the one it read before waiting for it", tc.name, applied[0])
			}
		})
	}
}

// TestApplyConfigStillHonoursAnExplicitConfig6716 is the TIGHTENING control.
//
// A "fix" that made every apply re-read would satisfy the test above while
// destroying applyConfig's contract — the commit paths and the lenient
// boot-apply path depend on applying the EXACT config handed to them, not
// whatever happens to be active. This pins that side.
func TestApplyConfigStillHonoursAnExplicitConfig6716(t *testing.T) {
	d, s := applyRereadHarness6716(t)

	var got []string
	d.applyBodyForTest = func(cfg *config.Config) {
		got = append(got, applyRereadMarker6716(t, cfg))
	}

	// Commit B so the ACTIVE config differs from the one we pass explicitly.
	if _, err := s.LoadSet(applyRereadSets6716("B")); err != nil {
		t.Fatalf("LoadSet(B): %v", err)
	}
	explicit, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit(B): %v", err)
	}
	if _, err := s.LoadSet(applyRereadSets6716("C")); err != nil {
		t.Fatalf("LoadSet(C): %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit(C): %v", err)
	}

	d.applyConfig(explicit)

	if len(got) != 1 {
		t.Fatalf("expected exactly 1 apply, got %d: %v", len(got), got)
	}
	if got[0] != "B" {
		t.Errorf("applyConfig(cfg) applied %q, want B — an explicit-config caller must apply "+
			"the config it was handed; re-reading here would break the commit and "+
			"lenient-boot paths that depend on applying a specific compiled config", got[0])
	}
}

// TestApplyActiveConfigNilActiveIsANoOp6716 pins the pre-boot contract the feed
// path relies on: a nil active config is a vacuous success, not an error and not
// an apply of nil.
func TestApplyActiveConfigNilActiveIsANoOp6716(t *testing.T) {
	s := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s, opts: Options{NoDataplane: true}}

	applies := 0
	d.applyBodyForTest = func(*config.Config) { applies++ }

	if s.ActiveConfig() != nil {
		t.Skip("store has an active config; this test needs the pre-boot window")
	}
	d.applyActiveConfig()
	if err := d.applyActiveConfigResult(); err != nil {
		t.Errorf("applyActiveConfigResult with no active config = %v, want nil — the feed "+
			"manager records content as published on a nil return, so an error here makes "+
			"a pre-boot refetch spin forever (#5646)", err)
	}
	if applies != 0 {
		t.Errorf("applied %d times with no active config, want 0", applies)
	}
	if !d.applySem.TryAcquire(1) {
		t.Fatal("applySem not released on the nil-active path")
	}
	d.applySem.Release(1)
}
