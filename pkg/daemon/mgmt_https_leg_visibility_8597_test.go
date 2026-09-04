package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/sysservices"
	"golang.org/x/sync/semaphore"
)

// #8597 K86: a dead HTTPS management leg was reported healthy on every surface
// and was never re-driven.
//
// `mgmtListenerDown` — the gate of the always-on re-assert owner — asked only
// the HTTP leg, and `sysservices.Listeners` had no HTTPS row at all. So an
// HTTPS leg that died to an unexpected serve-loop exit stayed installed-but-
// dead, `show system services` showed nothing wrong, and the repair waited for
// the operator's NEXT COMMIT — the one event a broken management plane makes
// hard to deliver.
//
// The commit path already asked the right question (#6827 round 6:
// `next.TLS && !m.srv.HTTPSServing()`). These cells pin that the steady-state
// owner and the operator view ask it too, so the three cannot disagree.

// bootMgmtTLS8597 boots a reconciler with BOTH legs serving. The HTTPS leg must
// actually be up before a cell kills it, or "down" would be the starting state
// and every assertion below would pass for the wrong reason.
func bootMgmtTLS8597(t *testing.T, reg *fakeReg, addr, httpsAddr string) (*Daemon, *managementReconciler) {
	t.Helper()
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.opts.APIAddr = addr
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	d.mgmt.Store(m)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := m.startTo(ctx, cfgFor(reg, addr, true, httpsAddr, nil)); err != nil {
		t.Fatalf("startTo with TLS: %v", err)
	}
	if !m.srv.HTTPServing() {
		t.Fatal("the boot bind left the HTTP leg down; the case starts wrong")
	}
	if !m.srv.HTTPSServing() {
		t.Fatal("the boot bind left the HTTPS leg down; the case starts wrong and " +
			"every assertion below would pass for the wrong reason")
	}
	return d, m
}

func killHTTPSLeg8597(t *testing.T, m *managementReconciler, reg *fakeReg, httpsAddr string) {
	t.Helper()
	reg.mu.Lock()
	ln := reg.byAddr[httpsAddr]
	reg.mu.Unlock()
	if ln == nil {
		t.Fatalf("no HTTPS listener was ever created at %s; the case starts wrong", httpsAddr)
	}
	ln.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !m.srv.HTTPSServing() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the HTTPS leg at %s was still reported serving after its socket died", httpsAddr)
}

// THE DEFECT: a dead HTTPS leg must make the re-assert owner fire. The HTTP leg
// is left healthy throughout, so nothing but the HTTPS question can turn the
// gate on — before the fix this returned false and nothing re-drove the leg.
func TestMgmtListenerDownSeesADeadHTTPSLeg8597K86(t *testing.T) {
	const addr, httpsAddr = "127.0.0.1:18080", "127.0.0.1:18443"
	reg := newFakeReg()
	d, m := bootMgmtTLS8597(t, reg, addr, httpsAddr)

	if d.mgmtListenerDown() {
		t.Fatal("both legs serving reported DOWN; the owner would rebind a working " +
			"management plane every tick")
	}
	killHTTPSLeg8597(t, m, reg, httpsAddr)

	if !m.srv.HTTPServing() {
		t.Fatal("killing the HTTPS leg also took down HTTP; the cell can no longer " +
			"attribute the gate to the HTTPS question")
	}
	if !d.mgmtListenerDown() {
		t.Fatal("#8597 K86: an HTTPS leg whose serve loop exited reported UP. " +
			"Nothing re-drives it, so a dead HTTPS management plane is repaired " +
			"only by the operator's next commit — the one event a broken " +
			"management plane makes hard to deliver")
	}
}

// The operator view must answer the SAME question as the gate, for the reason
// #6803 gives for the HTTP leg: if they can disagree the box either reports a
// dead listener nothing retries, or retries one it reports healthy.
func TestHTTPSOperatorViewAgreesWithTheGate8597K86(t *testing.T) {
	const addr, httpsAddr = "127.0.0.1:18081", "127.0.0.1:18444"
	reg := newFakeReg()
	d, m := bootMgmtTLS8597(t, reg, addr, httpsAddr)

	if got := m.effectiveHTTPSListener().State; got != sysservices.StateListening {
		t.Fatalf("a serving HTTPS leg renders %v, want Listening", got)
	}
	killHTTPSLeg8597(t, m, reg, httpsAddr)

	got := m.effectiveHTTPSListener().State
	if got != sysservices.StateFailed {
		t.Fatalf("a dead HTTPS leg renders %v, want Failed — `show system services` "+
			"reported a management plane that is serving nothing as healthy", got)
	}
	if !d.mgmtListenerDown() {
		t.Fatal("the operator view says Failed while the gate says up — the two must " +
			"be the same question")
	}
}

// CONTROL, and it is what keeps the new gate from firing forever on the large
// majority of deployments. TLS is NOT configured here: an absent HTTPS leg is
// not a failed one, and reporting it down would make the always-on owner
// re-drive a reconcile every tick on every box that never wanted HTTPS.
//
// This is the cell that a naive `!HTTPSServing()` gate — the obvious
// implementation — fails.
func TestUnconfiguredHTTPSIsDisabledNotFailed8597K86(t *testing.T) {
	const addr = "127.0.0.1:18082"
	reg := newFakeReg()
	d, m := bootMgmt6803(t, reg, addr) // TLS off

	if got := m.effectiveHTTPSListener().State; got != sysservices.StateDisabled {
		t.Fatalf("HTTPS with no TLS configured renders %v, want Disabled — an absent "+
			"management leg is not a failed one", got)
	}
	if d.mgmtListenerDown() {
		t.Fatal("#8597 K86: a box with no HTTPS configured reported its management " +
			"listener DOWN. The always-on re-assert owner would re-drive a " +
			"reconcile every tick, forever, on every deployment that never " +
			"enabled TLS")
	}
	// And a daemon with no reconciler at all stays UP, matching #6803.
	if (&Daemon{}).mgmtListenerDown() {
		t.Error("a daemon with no management reconciler reported a DOWN listener")
	}
}
