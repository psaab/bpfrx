package daemon

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/vishvananda/netlink"

	"path/filepath"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #8372: the reassert loop only ever CREATED, so a fabric IPVLAN that the
// active config no longer names persisted for the daemon's lifetime — and past
// it.
//
// Two mechanisms look like they should reap one and neither does:
// `CleanupFabricIPVLANs` is reachable only from the `xpfd cleanup` subcommand
// (the daemon never removes these links when it exits), and the stale-overlay
// sweep inside `applyInterfaces` runs on the next COMMIT. So the end state was
// healable by an operator action rather than by a timer — while the link
// carries the fabric / session-sync address, possibly on a parent the config no
// longer designates.
//
// The route in is the deferred `OnXSKBound` closure: it iterates a
// closure-captured slice and calls the ensure unconditionally, so an overlay a
// later apply correctly tore down is recreated when the XSK binds.

// fabricCfg8372NoFabric is the SAME shape as fabricCfg6791 with the fabric
// interface removed — i.e. what the config looks like after an apply that drops
// the overlay. Deriving it from the same fixture rather than writing an empty
// config keeps the difference to the one field under test.
func fabricCfg8372NoFabric() *config.Config {
	cfg := fabricCfg6791()
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0"},
	}
	return cfg
}

// newFabricReaperDaemon8372 builds a daemon whose ACTIVE CONFIG names no fabric
// interface — the post-apply state in which a surviving fab0 is stale.
//
// It cannot reuse newFabricReassertDaemon: that helper commits a config that
// DOES name fab0, so `staleFabricOverlays` would correctly find nothing and
// every cell driving the real loop would pass for the wrong reason.
func newFabricReaperDaemon8372(t *testing.T) *Daemon {
	t.Helper()
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// The same cluster shape, with the fab0 stanza REMOVED: this is what apply
	// B leaves behind after dropping the overlay.
	if _, err := s.LoadSet(
		"set chassis cluster cluster-id 1\n" +
			"set chassis cluster authentication-key test-cluster-psk-8372\n" +
			"set interfaces ge-0/0/0 unit 0 family inet address 10.99.0.254/24\n",
	); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &Daemon{store: s, applySem: semaphore.NewWeighted(1)}
}

func ipvlan8372(name string) netlink.Link {
	return &netlink.IPVlan{LinkAttrs: netlink.LinkAttrs{Name: name, Flags: net.FlagUp}}
}

// TestAStaleFabricOverlayIsReaped8372 is the defect.
func TestAStaleFabricOverlayIsReaped8372(t *testing.T) {
	d := &Daemon{linkByNameFn: func(name string) (netlink.Link, error) {
		if name == "fab0" {
			return ipvlan8372(name), nil
		}
		return nil, netlink.LinkNotFoundError{}
	}}
	stale := d.staleFabricOverlays(fabricCfg8372NoFabric())
	if len(stale) != 1 {
		t.Fatalf("fab0 exists and the active config does not name it, so it must be "+
			"reaped; got %d stale overlays. It carries the fabric/session-sync "+
			"address on a path the operator removed.", len(stale))
	}
	if stale[0].Attrs().Name != "fab0" {
		t.Errorf("reaped the wrong link: %s", stale[0].Attrs().Name)
	}
}

// TestAConfiguredFabricOverlayIsNotReaped8372 is the control, and without it
// every other cell here passes against a reaper that deletes the fabric on a
// healthy node — which is the reaper causing the outage it exists to prevent.
func TestAConfiguredFabricOverlayIsNotReaped8372(t *testing.T) {
	d := &Daemon{linkByNameFn: func(name string) (netlink.Link, error) {
		if name == "fab0" {
			return ipvlan8372(name), nil
		}
		return nil, netlink.LinkNotFoundError{}
	}}
	if stale := d.staleFabricOverlays(fabricCfg6791()); len(stale) != 0 {
		t.Fatalf("fab0 IS in the active config and must never be reaped; got %d", len(stale))
	}
}

// TestANonIPVLANIsNeverReaped8372: a same-named device of another type is not
// ours. Deleting it would be this reaper destroying something it did not make.
func TestANonIPVLANIsNeverReaped8372(t *testing.T) {
	d := &Daemon{linkByNameFn: func(name string) (netlink.Link, error) {
		if name == "fab0" {
			return &fakeFabricLink{attrs: netlink.LinkAttrs{Name: name, Flags: net.FlagUp}}, nil
		}
		return nil, netlink.LinkNotFoundError{}
	}}
	if stale := d.staleFabricOverlays(fabricCfg8372NoFabric()); len(stale) != 0 {
		t.Errorf("a fab0 that is NOT an IPVLAN was not made by us and must not be "+
			"reaped; got %d", len(stale))
	}
}

// TestTheCheapPathGateDoesNotHideTheReaper8372 is the cell that catches the
// mistake this fix is most likely to be written with.
//
// The loop's cheap path returned early on `len(missing) == 0`. A stale overlay
// is an EXTRA device, not a missing one — so that condition is exactly the
// state a stale overlay produces, and a reaper added below that gate would be
// unreachable in the only case it exists for. It would also be invisible: every
// unit test of the reaper function itself still passes.
func TestTheCheapPathGateDoesNotHideTheReaper8372(t *testing.T) {
	var mu sync.Mutex
	var deleted []string
	withFabricEnsure(t, func(parent, name string, addrs []string) error { return nil })

	d := newFabricReaperDaemon8372(t)
	d.linkByNameFn = func(name string) (netlink.Link, error) {
		if name == "fab0" {
			return ipvlan8372(name), nil
		}
		return nil, netlink.LinkNotFoundError{}
	}
	d.linkDelFn = func(l netlink.Link) error {
		mu.Lock()
		deleted = append(deleted, l.Attrs().Name)
		mu.Unlock()
		return nil
	}

	// The active config names no fabric interface, so NOTHING is missing —
	// which is precisely the state the old cheap path returned on.
	if missing := d.missingFabricOverlays(d.store.ActiveConfig()); len(missing) != 0 {
		t.Fatalf("fixture is wrong: this cell needs len(missing)==0 to exercise the "+
			"gate; got %v", missing)
	}

	d.reassertFabricIPVLANOnce(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(deleted) != 1 || deleted[0] != "fab0" {
		t.Fatalf("the reaper did not run through reassertFabricIPVLANOnce; deleted=%v.\n"+
			"If the cheap-path gate still keys on `len(missing) == 0` alone, the "+
			"reaper is unreachable in exactly the case it exists for.", deleted)
	}
}

// TestTheReaperSurvivesARacingRecreate8372 is the interaction the issue warns
// about: a reaper racing a creator is a NEW interaction, and a fixture where
// the two never overlap passes under an implementation that deletes a link
// another path is mid-way through creating.
//
// This drives the race rather than the steady state: the delete callback
// recreates the link, modelling the deferred OnXSKBound closure firing on its
// own goroutine during the reap. The property asserted is CONVERGENCE, not
// mutual exclusion — nothing can exclude a goroutine nobody joins. The set is
// re-derived from the current config on every pass, so a stale overlay
// recreated by a racing closure is reaped again by the next pass rather than
// being permanently readmitted.
func TestTheReaperSurvivesARacingRecreate8372(t *testing.T) {
	var mu sync.Mutex
	exists := true
	deletes := 0
	withFabricEnsure(t, func(parent, name string, addrs []string) error { return nil })

	d := newFabricReaperDaemon8372(t)
	d.linkByNameFn = func(name string) (netlink.Link, error) {
		mu.Lock()
		defer mu.Unlock()
		if name == "fab0" && exists {
			return ipvlan8372(name), nil
		}
		return nil, netlink.LinkNotFoundError{}
	}
	d.linkDelFn = func(l netlink.Link) error {
		mu.Lock()
		defer mu.Unlock()
		deletes++
		exists = false
		// The race: a concurrent creator puts it straight back.
		exists = true
		return nil
	}

	for i := 0; i < 3; i++ {
		d.reassertFabricIPVLANOnce(context.Background())
	}

	mu.Lock()
	defer mu.Unlock()
	if deletes != 3 {
		t.Fatalf("a stale overlay recreated by a racing creator must be reaped again "+
			"on every pass — convergence, not one-shot; deletes=%d after 3 passes", deletes)
	}
}

// TestTheCandidateNamesAreSingleSourced8372: the reaper and CleanupFabricIPVLANs
// must enumerate the same devices. Two hardcoded copies of "which devices are
// ours" is a rule that silently stops covering a third — and the reaper's
// failure mode there is the quiet one, simply never noticing it went stale.
func TestTheCandidateNamesAreSingleSourced8372(t *testing.T) {
	names := fabricOverlayNames()
	if len(names) == 0 {
		t.Fatal("fabricOverlayNames returned nothing, so the reaper scans nothing " +
			"and every other cell here would pass vacuously")
	}
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Errorf("duplicate candidate %q", n)
		}
		seen[n] = true
	}
	for _, want := range []string{"fab0", "fab1"} {
		if !seen[want] {
			t.Errorf("%q is a fabric overlay this daemon can create and must be a "+
				"reap candidate", want)
		}
	}
}
