package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// proxyarp_unresolved_debt_7685_test.go — #7685.
//
// proxyARPReassertLoop was the one always-on retry owner with no operator
// signal, because it keeps no debt: it re-runs its reconcile unconditionally
// every tick. #7615 left it out for exactly that reason.
//
// The predicate it turned out to need was not the one #7685 first proposed.
// "The kernel drifted" (a link flap re-defaulting the proxy_arp sysctl) is
// EXPECTED and is corrected on the next tick, so a gauge for it reads false
// almost always and a counter for it reports a routine event — the metric
// operators learn to ignore.
//
// The reconcile already held a real debt, and the code already called it that:
// a CONFIGURED proxy-arp interface whose Linux netdev does not resolve is
// retained rather than torn down (#6536, retainUnresolvedProxyResponders), with
// a log line naming it debt. That condition does NOT self-heal on the next tick
// — it persists until the interface exists — and while it holds the responder
// is not answering on a node whose commit reported success.
//
// These cells bind the accessor to that value, in BOTH directions and across
// the clear, and they are hermetic: the apply seam is stubbed so no netlink or
// privilege is required.

// stubProxyARPApply7685 replaces the dataplane apply with a no-op so these cells
// exercise the RESOLUTION path only. Without it the test needs privileges and
// skips — and a skipping cell guards nothing.
func stubProxyARPApply7685(t *testing.T) {
	t.Helper()
	prevApply := proxyARPApplyFn
	proxyARPApplyFn = func(_ *config.Config, _, _ map[string]int, _ map[int]string) ([]dataplane.ProxyARPAdded, map[string]map[int]struct{}, error) {
		return nil, map[string]map[int]struct{}{}, nil
	}
	t.Cleanup(func() { proxyARPApplyFn = prevApply })

	prevDisable := proxyARPDisableFn
	proxyARPDisableFn = func(map[string]map[int]struct{}) int { return 0 }
	t.Cleanup(func() { proxyARPDisableFn = prevDisable })
}

func proxyARPCfg7685(iface string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: iface, Addresses: []string{"10.0.2.50/32"}},
	}
	return cfg
}

// BOTH DIRECTIONS. A one-way cell is satisfied by an accessor hardwired to the
// answer it happens to check: true-only passes for one stuck at true, which
// pages forever on a healthy node, and false-only passes for one stuck at
// false, which is the pre-#7685 blindness with extra steps.
func TestProxyARPUnresolvedTracksTheReconcile7685(t *testing.T) {
	stubProxyARPApply7685(t)
	d := &Daemon{}

	// The configured interface does NOT resolve → debt.
	withFakeIfaceResolver(t, map[string]int{})
	d.reconcileProxyARP(proxyARPCfg7685("ge-0-0-9"))
	if !d.ProxyARPUnresolved() {
		t.Fatalf("a configured proxy-arp interface that does not resolve must " +
			"report debt: the responder is not answering and the commit reported " +
			"success, which is the whole condition #7685 exists to surface")
	}
	if got := d.proxyARPUnresolvedNames(); len(got) != 1 {
		t.Errorf("debt does not name the interface: %v", got)
	}

	// The same interface now resolves → debt clears.
	withFakeIfaceResolver(t, map[string]int{config.LinuxIfName("ge-0-0-9"): 42})
	d.reconcileProxyARP(proxyARPCfg7685("ge-0-0-9"))
	if d.ProxyARPUnresolved() {
		t.Errorf("debt stayed latched after the interface resolved: %v — a signal "+
			"that keeps firing after the fix is one operators learn to mute",
			d.proxyARPUnresolvedNames())
	}
}

// The CLEAR-ON-UNCONFIGURE path is separate because it returns through a
// different branch: reconcileProxyARP short-circuits before resolving anything
// when nothing is configured and nothing was installed. Without an explicit
// clear there, a commit that REMOVES proxy-arp leaves the gauge latched on an
// interface nobody is asking for any more.
func TestProxyARPUnresolvedClearsWhenUnconfigured7685(t *testing.T) {
	stubProxyARPApply7685(t)
	d := &Daemon{}

	withFakeIfaceResolver(t, map[string]int{})
	d.reconcileProxyARP(proxyARPCfg7685("ge-0-0-9"))
	if !d.ProxyARPUnresolved() {
		t.Fatalf("precondition: the fixture must first enter the debt state")
	}

	// proxy-arp removed from the config entirely.
	d.reconcileProxyARP(&config.Config{})
	if d.ProxyARPUnresolved() {
		t.Errorf("debt survived proxy-arp being unconfigured: %v",
			d.proxyARPUnresolvedNames())
	}
}

// COST. The loop's current virtue is being free when nothing is configured, and
// #7685's acceptance criteria require whatever this costs there to be stated
// and measured. It costs nothing: with no proxy-arp configured and nothing
// installed, the reconcile returns before calling the resolver at all, so the
// added debt-tracking performs zero interface lookups.
//
// Measured rather than asserted — the resolver counts its own calls.
func TestProxyARPUnresolvedCostsNothingWhenUnconfigured7685(t *testing.T) {
	stubProxyARPApply7685(t)

	calls := 0
	prev := ifaceIndexByName
	ifaceIndexByName = func(string) (int, error) { calls++; return 0, nil }
	t.Cleanup(func() { ifaceIndexByName = prev })

	d := &Daemon{}
	d.reconcileProxyARP(&config.Config{})
	if calls != 0 {
		t.Errorf("unconfigured reconcile performed %d interface lookups, want 0 — "+
			"the always-on loop's no-op-when-unconfigured property is the thing "+
			"#7685 was required not to spend", calls)
	}
	if d.ProxyARPUnresolved() {
		t.Errorf("unconfigured node reports proxy-arp debt")
	}

	// POSITIVE CONTROL: the counter can move, so the zero above is a fact about
	// the short-circuit and not about a resolver that is never consulted.
	withFakeIfaceResolver(t, map[string]int{})
	d.reconcileProxyARP(proxyARPCfg7685("ge-0-0-9"))
	if !d.ProxyARPUnresolved() {
		t.Errorf("control: a configured interface must reach the resolver")
	}
}

// WIRING (#6852 shape). An exported accessor nothing calls satisfies nothing:
// every cell above stays green against a build where the daemon never hands it
// to the metrics server, and the operator stays exactly as blind.
func TestDaemonWiresProxyARPUnresolvedMetric7685(t *testing.T) {
	src := stripLineComments6791(readDaemonSource(t, "daemon_run_servers.go"))
	const want = "ProxyARPUnresolvedFn:     d.ProxyARPUnresolved"
	if !strings.Contains(src, want) {
		t.Errorf("daemon does not wire %q into the REST/metrics server; the "+
			"accessor has no production caller, so a proxy-arp responder that is "+
			"silently not answering stays invisible (#7685, and the #6852 "+
			"no-production-caller shape)", want)
	}
}
