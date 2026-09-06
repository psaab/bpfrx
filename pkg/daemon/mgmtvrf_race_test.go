package daemon

import (
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestMgmtVRFIfaceSetPrePublish asserts a reader before any apply/publish sees
// the safe empty state (#5113): Load returns nil and every read helper treats
// that as "no mgmt VRF interfaces yet" without panicking.
func TestMgmtVRFIfaceSetPrePublish(t *testing.T) {
	d := &Daemon{}

	if got := d.mgmtVRFIfaceSet(); got != nil {
		t.Fatalf("pre-publish mgmtVRFIfaceSet() = %v, want nil", got)
	}
	if got := len(d.mgmtVRFIfaceSet()); got != 0 {
		t.Fatalf("pre-publish len(mgmtVRFIfaceSet()) = %d, want 0", got)
	}
	// The DHCP-callback classify path must be conservative (recompile) with no
	// published set, and must not deref a nil map.
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"fxp0": {
					Name:  "fxp0",
					Units: map[int]*config.InterfaceUnit{0: {DHCP: true}},
				},
			},
		},
	}
	if !d.dhcpLeaseChangeRequiresRecompile(cfg, false) {
		t.Fatal("pre-publish classification should stay conservative (recompile)")
	}
}

// TestMgmtVRFInterfacesConcurrentPublish exercises the atomic publication of
// d.mgmtVRFInterfaces against the lock-free DHCP-callback read path. It runs a
// writer that republishes a fresh immutable map (mimicking apply under
// applySem) concurrently with readers walking the classify/snapshot path.
//
// Under `go test -race` this must be clean. Reverting mgmtVRFInterfaces to a
// bare `map[string]bool` field with bare `= nil` / `= mgmtIfaces` assignments
// reintroduces the #5113 unsynchronized concurrent map-pointer read/write and
// this test fails under -race.
func TestMgmtVRFInterfacesConcurrentPublish(t *testing.T) {
	d := &Daemon{}

	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"fxp0": {
					Name:  "fxp0",
					Units: map[int]*config.InterfaceUnit{0: {DHCP: true}},
				},
			},
		},
	}

	const iters = 2000
	var wg sync.WaitGroup

	// Writer: republish a fresh map (and periodically an empty/nil set) each
	// iteration, as a commit apply would.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			var m map[string]bool
			if i%2 == 0 {
				m = map[string]bool{"fxp0": true}
			}
			d.publishMgmtVRFIfaces(m)
		}
	}()

	// Readers: the DHCP-callback classify path plus the raw snapshot accessor,
	// both of which read the published field.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				_ = d.dhcpLeaseChangeRequiresRecompile(cfg, false)
				_ = len(d.mgmtVRFIfaceSet())
			}
		}()
	}

	wg.Wait()
}
