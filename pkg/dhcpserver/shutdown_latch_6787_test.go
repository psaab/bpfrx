package dhcpserver

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// servingConfig6787 is a minimal desired state with BOTH families configured,
// so a reconcile that honours it starts kea-dhcp4 AND kea-dhcp6.
func servingConfig6787() *config.DHCPServerConfig {
	return &config.DHCPServerConfig{
		DHCPLocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{"g4": {
				Name:       "g4",
				Interfaces: []string{"reth1.0"},
				Pools: []*config.DHCPPool{{
					Name:      "p4",
					Subnet:    "10.0.61.0/24",
					RangeLow:  "10.0.61.100",
					RangeHigh: "10.0.61.200",
				}},
			}},
		},
		DHCPv6LocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{"g6": {
				Name:       "g6",
				Interfaces: []string{"reth1.0"},
				Pools: []*config.DHCPPool{{
					Name:      "p6",
					Subnet:    "2001:db8:61::/64",
					RangeLow:  "2001:db8:61::100",
					RangeHigh: "2001:db8:61::200",
				}},
			}},
		},
	}
}

// systemctlRecorder6787 records every systemctl invocation and reports the
// units it believes are active, so a test can distinguish "asked to stop" from
// "actually reconciled to stopped".
type systemctlRecorder6787 struct {
	mu     sync.Mutex
	calls  []string
	active map[string]bool
}

func newRecorder6787() *systemctlRecorder6787 {
	return &systemctlRecorder6787{active: map[string]bool{}}
}

func (r *systemctlRecorder6787) run(args ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, strings.Join(args, " "))
	if len(args) >= 2 {
		switch args[0] {
		case "restart", "start":
			r.active[args[1]] = true
		case "stop":
			r.active[args[1]] = false
		}
	}
	return nil
}

func (r *systemctlRecorder6787) isActive(unit string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active[unit]
}

func (r *systemctlRecorder6787) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.calls))
	copy(out, r.calls)
	return out
}

func (r *systemctlRecorder6787) anyActive() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, on := range r.active {
		if on {
			return true
		}
	}
	return false
}

func newManager6787(t *testing.T, r *systemctlRecorder6787) *Manager {
	t.Helper()
	dir := t.TempDir()
	return NewManagerForTesting(
		filepath.Join(dir, "kea-dhcp4.conf"),
		filepath.Join(dir, "kea-dhcp6.conf"),
		r.run,
		r.isActive,
	)
}

// TestShutdownStopsRunningKeaUnits6787 is the first half: Shutdown must
// actually reconcile a SERVING manager to stopped, synchronously.
//
// The precondition assert is load-bearing. Without it the test would pass
// against a manager that never started anything, and "no units active at the
// end" would be true for the wrong reason — the shape of a green
// indistinguishable from healthy.
func TestShutdownStopsRunningKeaUnits6787(t *testing.T) {
	r := newRecorder6787()
	m := newManager6787(t, r)

	if err := m.Apply(servingConfig6787()); err != nil {
		t.Fatalf("precondition Apply: %v", err)
	}
	if !r.anyActive() {
		t.Fatalf("precondition: no Kea unit was started, so a later "+
			"'nothing active' assertion would prove nothing; calls=%v",
			r.snapshot())
	}

	if err := m.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if r.anyActive() {
		t.Fatalf("a Kea unit is still active after Shutdown — this node keeps "+
			"answering DHCP while the peer serves the same segment (#6787); "+
			"calls=%v", r.snapshot())
	}
}

// TestShutdownLatchesAgainstALaterApply6787 is the half that matters, and it is
// PAIRED: the same Apply call, before and after Shutdown, must have opposite
// effects.
//
// Shutdown deliberately runs BEFORE the priority-0 withdrawal, so this node
// stops serving before the peer starts. That ordering leaves a window in which
// a VRRP MASTER transition can still reach the manager — and it allocates a
// NEWER generation than Shutdown's own apply, so the #1835 supersession guard
// cannot refuse it. Stopping without latching would let that window re-arm the
// units after the stop had already reported success.
//
// The "before" leg is not decoration: without it, "Apply does not start Kea"
// would be satisfied by a manager that never starts Kea at all.
func TestShutdownLatchesAgainstALaterApply6787(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(m *Manager) error
	}{
		{"Apply", func(m *Manager) error { return m.Apply(servingConfig6787()) }},
		{"ApplyClusterCommit", func(m *Manager) error {
			return m.ApplyClusterCommit(servingConfig6787())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRecorder6787()
			m := newManager6787(t, r)

			// BEFORE: the same call must genuinely serve. ApplyClusterCommit
			// only restarts an ALREADY-ACTIVE unit, so start from a serving
			// state via Apply first; that is its documented semantics, not a
			// workaround.
			if err := m.Apply(servingConfig6787()); err != nil {
				t.Fatalf("precondition Apply: %v", err)
			}
			if err := tc.apply(m); err != nil {
				t.Fatalf("precondition %s: %v", tc.name, err)
			}
			if !r.anyActive() {
				t.Fatalf("precondition: %s did not leave any unit active, so the "+
					"post-shutdown assertion below would pass vacuously; calls=%v",
					tc.name, r.snapshot())
			}

			if err := m.Shutdown(); err != nil {
				t.Fatalf("Shutdown: %v", err)
			}

			// AFTER: the identical call, with a strictly newer generation, must
			// not bring the units back.
			if err := tc.apply(m); err != nil {
				t.Fatalf("post-shutdown %s returned an error; it must converge "+
					"to stopped, not fail: %v", tc.name, err)
			}
			if r.anyActive() {
				t.Fatalf("%s restarted Kea AFTER shutdown had begun — a VRRP "+
					"MASTER transition racing the shutdown window re-arms the "+
					"units this node just stopped (#6787); calls=%v",
					tc.name, r.snapshot())
			}
		})
	}
}

// TestShutdownLatchAppliesToTheAsyncWorker6787 covers the path the VRRP event
// loop actually uses. ApplyAsync is the one every ownership transition calls,
// so a latch that only covered the synchronous appliers would leave the real
// racing caller untouched.
//
// Driven through enqueueAsync with a gen allocated up front, which is the
// interleaving the mailbox exists to model, and joined by draining the worker
// synchronously rather than sleeping.
func TestShutdownLatchAppliesToTheAsyncWorker6787(t *testing.T) {
	r := newRecorder6787()
	m := newManager6787(t, r)

	if err := m.Apply(servingConfig6787()); err != nil {
		t.Fatalf("precondition Apply: %v", err)
	}
	if !r.anyActive() {
		t.Fatal("precondition: nothing was started")
	}
	if err := m.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	m.ApplyAsync(servingConfig6787(), "vrrp MASTER racing shutdown (#6787)")
	// Join the singleton worker on an OBSERVABLE, not a sleep.
	//
	// Deliberately NOT the systemctl call log: a latched apply reconciles to
	// "stopped", the units are already stopped, so it issues NO systemctl call
	// at all — waiting for the log to grow times out even though the worker ran
	// correctly. lastAppliedGen is the right signal because it advances on every
	// apply body that runs, including a no-op one. A sleep would be worse than
	// either: a worker that never ran would pass.
	wantGen := m.applyGen.Load()
	waitForCondition(t, "the async worker to drain the post-shutdown request",
		func() bool {
			m.mu.Lock()
			defer m.mu.Unlock()
			return m.lastAppliedGen >= wantGen
		})

	if r.anyActive() {
		t.Fatalf("the async worker restarted Kea after shutdown — the VRRP "+
			"event loop's own applier is the one that races this window "+
			"(#6787); calls=%v", r.snapshot())
	}
}
