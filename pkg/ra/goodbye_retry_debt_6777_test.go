package ra

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

// errSimGoodbyeWrite is the injected write failure. It is NOT errGoodbyeWrite
// itself: the production code wraps this into errGoodbyeWrite at the
// sendGoodbyeStandalone boundary, and asserting on the wrapper is what proves
// the classification survives the whole path rather than being re-derived from
// a value the test planted.
var errSimGoodbyeWrite = errors.New("simulated lifetime-0 write failure")

// goodbyeProbe is the #6777 seam. Every conn BINDS successfully; a write of a
// lifetime-0 (goodbye) RA is counted and — while failing is set — rejected.
// Normal RAs are left alone, so a sender started through this probe behaves
// normally right up to its final goodbye. Counting ATTEMPTS (not conns) is the
// point: the property under test is "was another lifetime-0 emit tried at all",
// which is exactly what the pre-#6777 code could not do once it had erased the
// tombstone and dropped the sender.
type goodbyeProbe struct {
	mu       sync.Mutex
	failing  bool
	attempts map[string]int
}

func (g *goodbyeProbe) setFailing(v bool) {
	g.mu.Lock()
	g.failing = v
	g.mu.Unlock()
}

func (g *goodbyeProbe) attemptsFor(name string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.attempts[name]
}

func installGoodbyeProbe(t *testing.T, failing bool) *goodbyeProbe {
	t.Helper()
	g := &goodbyeProbe{failing: failing, attempts: map[string]int{}}
	origListen := listenFn
	origEnsure := ensureLinkLocalFn
	t.Cleanup(func() { listenFn = origListen; ensureLinkLocalFn = origEnsure })
	ensureLinkLocalFn = func(*net.Interface) error { return nil }
	listenFn = func(iface *net.Interface, _ ndp.Addr) (ndpConn, netip.Addr, error) {
		name := iface.Name
		fc := newFakeConn()
		// The hook runs BEFORE WriteTo consults writeErr, so arming it here
		// takes effect on this very write.
		fc.setBeforeWrite(func(lifetime time.Duration) {
			if lifetime != 0 {
				return
			}
			g.mu.Lock()
			g.attempts[name]++
			fail := g.failing
			g.mu.Unlock()
			if fail {
				fc.setWriteErr(errSimGoodbyeWrite)
			} else {
				fc.setWriteErr(nil)
			}
		})
		return fc, netip.MustParseAddr("fe80::1"), nil
	}
	return g
}

func requireLo(t *testing.T) {
	t.Helper()
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
}

func (m *Manager) owedCountForTest() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.goodbyeOwed)
}

// TestGracefulWithdrawSurfacesFinalGoodbyeFailure6777 is the SURFACE half of
// #6777. Manager.Withdraw returned a hard-coded nil: releaseDrain's goodbye
// outcome was logged inside finishDrainDecision and then thrown away, so all
// three production call sites — the config-removal apply, daemon shutdown, and
// the VRRP BACKUP transition — carried an `if err := d.ra.Withdraw(); err !=
// nil` branch that could never be reached. A router whose final lifetime-0 RA
// never went out was reported to operators as a clean withdrawal.
//
// NON-TAUTOLOGY: revert Withdraw to `return nil` and this fails RED.
func TestGracefulWithdrawSurfacesFinalGoodbyeFailure6777(t *testing.T) {
	requireLo(t)
	g := installGoodbyeProbe(t, false)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	g.setFailing(true)
	err := m.Withdraw()
	if err == nil {
		t.Fatal("Withdraw() returned nil after EVERY lifetime-0 write failed — " +
			"the final goodbye was discarded and reported as success (#6777)")
	}
	if g.attemptsFor("lo") == 0 {
		t.Fatal("no lifetime-0 write was even attempted; the probe did not " +
			"exercise the goodbye path, so the assertion above proves nothing")
	}
}

// TestApplyRemovalSurfacesFinalGoodbyeFailure6777 is the same surface property
// on the OTHER graceful-withdrawal entry point: Apply with an empty desired set,
// which is the cluster "this node owns no RG any more" withdrawal driven by
// reconcileClusterRAServices. That caller latches convergence on a nil return,
// so a swallowed failure there is what erases the retry.
//
// NON-TAUTOLOGY: restore the empty-config branch's `return nil` → RED.
func TestApplyRemovalSurfacesFinalGoodbyeFailure6777(t *testing.T) {
	requireLo(t)
	g := installGoodbyeProbe(t, false)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	g.setFailing(true)
	if err := m.Apply(nil); err == nil {
		t.Fatal("Apply(nil) returned nil after every lifetime-0 write failed — " +
			"reconcileClusterRAServices would latch this as converged (#6777)")
	}
	if g.attemptsFor("lo") == 0 {
		t.Fatal("no lifetime-0 write attempted; probe did not reach the goodbye")
	}
}

// TestFailedFinalGoodbyeIsRetriedByALaterApply6777 is the RETRY-DEBT half, and
// the load-bearing cell of the pair. Surfacing the error alone is not the fix:
// pre-#6777 finishDrainDecision also set goodbyeClaimed, deleted the tombstone
// and dropped the sender, so even a caller that DID see a failure had nothing
// left to retry — a later Apply found no sender and no tombstone for the
// interface and emitted nothing. The debt is what makes the daemon's existing
// every-2s driver able to act.
//
// NON-TAUTOLOGY: delete the recordGoodbyeDebtLocked call (keeping the error
// return) and the second Apply attempts NO further lifetime-0 write → RED.
func TestFailedFinalGoodbyeIsRetriedByALaterApply6777(t *testing.T) {
	requireLo(t)
	g := installGoodbyeProbe(t, false)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	g.setFailing(true)
	if err := m.Apply(nil); err == nil {
		t.Fatal("withdrawal with a failing goodbye reported success (#6777)")
	}
	afterWithdraw := g.attemptsFor("lo")
	if afterWithdraw == 0 {
		t.Fatal("no lifetime-0 write attempted during the withdrawal")
	}
	if m.owedCountForTest() != 1 {
		t.Fatalf("retry debt not retained after a failed final goodbye: owed=%d",
			m.owedCountForTest())
	}

	// A LATER pass with the interface still un-desired must try again. This is
	// the pass reconcileClusterRAServices makes only because the previous Apply
	// returned non-nil and left the convergence digest un-advanced.
	if err := m.Apply(nil); err == nil {
		t.Fatal("the second pass reported success while the goodbye was still owed")
	}
	afterRetry := g.attemptsFor("lo")
	if afterRetry <= afterWithdraw {
		t.Fatalf("no goodbye was re-attempted on the next pass "+
			"(attempts %d -> %d): the retry debt was cleared along with the "+
			"tombstone, so the withdrawal can never complete (#6777)",
			afterWithdraw, afterRetry)
	}
}

// TestFinalGoodbyeRetrySucceedsAndClearsDebt6777 closes the loop: once the
// interface accepts the write, the retry SENDS, the debt is dropped, and no
// further pass emits a stray lifetime-0 RA. The trailing no-op assertion is the
// tightening control — a debt that is reported cleared but keeps re-emitting
// would advertise a withdrawal for an interface nobody is withdrawing.
func TestFinalGoodbyeRetrySucceedsAndClearsDebt6777(t *testing.T) {
	requireLo(t)
	g := installGoodbyeProbe(t, false)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	g.setFailing(true)
	if err := m.Apply(nil); err == nil {
		t.Fatal("withdrawal with a failing goodbye reported success")
	}

	// The link recovers. The next pass must retry and succeed.
	g.setFailing(false)
	beforeRetry := g.attemptsFor("lo")
	if err := m.Apply(nil); err != nil {
		t.Fatalf("the retry pass should have SENT the goodbye and returned nil, got %v", err)
	}
	if g.attemptsFor("lo") <= beforeRetry {
		t.Fatal("the successful pass emitted no lifetime-0 RA at all — it " +
			"returned nil without doing the work")
	}
	if m.owedCountForTest() != 0 {
		t.Fatalf("debt survived a SUCCESSFUL retry: owed=%d", m.owedCountForTest())
	}

	settled := g.attemptsFor("lo")
	if err := m.Apply(nil); err != nil {
		t.Fatalf("a pass with no debt outstanding must return nil, got %v", err)
	}
	if g.attemptsFor("lo") != settled {
		t.Fatalf("a cleared debt still emitted a goodbye (attempts %d -> %d)",
			settled, g.attemptsFor("lo"))
	}
}

// TestFinalGoodbyeRetryDebtIsBounded6777 guards the other direction. Apply
// returns non-nil while debt is outstanding, and that non-nil is precisely what
// stops reconcileClusterRAServices advancing its digest — so an interface that
// can NEVER accept the goodbye would otherwise re-apply and log every 2s
// forever. After maxGoodbyeRetries the debt is dropped, Apply goes quiet, and no
// further emit is attempted.
func TestFinalGoodbyeRetryDebtIsBounded6777(t *testing.T) {
	requireLo(t)
	g := installGoodbyeProbe(t, false)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	g.setFailing(true)
	if err := m.Apply(nil); err == nil {
		t.Fatal("withdrawal with a failing goodbye reported success")
	}

	// Drive passes until Apply goes quiet. The bound must be reached in a small,
	// fixed number of passes; the loop cap is deliberately far above
	// maxGoodbyeRetries so an unbounded implementation fails on the cap rather
	// than hanging.
	quietAt := -1
	for i := 0; i < maxGoodbyeRetries+5; i++ {
		if err := m.Apply(nil); err == nil {
			quietAt = i
			break
		}
	}
	if quietAt < 0 {
		t.Fatalf("Apply(nil) still reported an outstanding goodbye after %d "+
			"passes — the retry debt is unbounded and would suppress the RA "+
			"reconcile digest forever", maxGoodbyeRetries+5)
	}
	if m.owedCountForTest() != 0 {
		t.Fatalf("debt survived the bound: owed=%d", m.owedCountForTest())
	}
	settled := g.attemptsFor("lo")
	if err := m.Apply(nil); err != nil {
		t.Fatalf("a pass after the bound must return nil, got %v", err)
	}
	if g.attemptsFor("lo") != settled {
		t.Fatalf("a dropped debt still emitted a goodbye (attempts %d -> %d)",
			settled, g.attemptsFor("lo"))
	}
}

// TestGoodbyeDebtDroppedWhenInterfaceIsAdvertisedAgain6777 asserts the debt is
// not a zombie. If the operator (or a VRRP re-promotion) brings RA back on the
// interface, the owed lifetime-0 RA must NOT be emitted — it would withdraw the
// router the sender we just started is advertising.
func TestGoodbyeDebtDroppedWhenInterfaceIsAdvertisedAgain6777(t *testing.T) {
	requireLo(t)
	g := installGoodbyeProbe(t, false)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	g.setFailing(true)
	if err := m.Apply(nil); err == nil {
		t.Fatal("withdrawal with a failing goodbye reported success")
	}
	if m.owedCountForTest() != 1 {
		t.Fatalf("precondition: expected 1 owed goodbye, got %d", m.owedCountForTest())
	}

	g.setFailing(false)
	beforeReadvertise := g.attemptsFor("lo")
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("re-advertising Apply: %v", err)
	}
	if m.owedCountForTest() != 0 {
		t.Fatalf("debt survived the interface being advertised again: owed=%d",
			m.owedCountForTest())
	}
	if g.attemptsFor("lo") != beforeReadvertise {
		t.Fatalf("a lifetime-0 goodbye was emitted on an interface that is "+
			"advertising again (attempts %d -> %d) — that withdraws the router "+
			"the new sender just announced", beforeReadvertise, g.attemptsFor("lo"))
	}
}

// TestVanishedInterfaceLeavesNoGoodbyeRetryDebt6777 is the PAIRED cell for the
// debt-classification rule: the same call site, two error shapes, opposite
// outcomes. A netdev that no longer exists can never accept a goodbye and has
// no hosts behind it left to hear one, so retaining debt for it would make a
// legitimately removed interface a permanent Apply error and suppress the RA
// reconcile digest for the whole node. A write failure IS retained.
//
// Without the negative half, "records debt on failure" would be satisfied by an
// implementation that records debt for EVERY failure — the shape that bricks
// the reconcile.
func TestVanishedInterfaceLeavesNoGoodbyeRetryDebt6777(t *testing.T) {
	m := New()
	cfg := testCfg("ge-0-0-vanished")

	// Negative: the exact wrapping sendOneGoodbye produces for a missing netdev.
	missing := fmt.Errorf("%w %s: %w", errGoodbyeIfaceMissing, cfg.Interface, os.ErrNotExist)
	m.mu.Lock()
	m.recordGoodbyeDebtLocked(cfg.Interface, cfg, missing)
	m.mu.Unlock()
	if got := m.owedCountForTest(); got != 0 {
		t.Fatalf("a vanished interface recorded retry debt (owed=%d) — every "+
			"later Apply would return non-nil forever and the node's RA "+
			"reconcile digest would never advance", got)
	}

	// Positive control: a write failure on the same call site MUST be retained,
	// so the negative above is a classification and not a dead code path.
	writeFail := fmt.Errorf("%w on %s", errGoodbyeWrite, cfg.Interface)
	m.mu.Lock()
	m.recordGoodbyeDebtLocked(cfg.Interface, cfg, writeFail)
	m.mu.Unlock()
	if got := m.owedCountForTest(); got != 1 {
		t.Fatalf("a lifetime-0 WRITE failure recorded no retry debt (owed=%d) — "+
			"recordGoodbyeDebtLocked is rejecting everything", got)
	}
}
