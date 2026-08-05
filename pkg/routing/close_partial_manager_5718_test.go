package routing

import (
	"testing"

	"github.com/vishvananda/netlink"
)

// closeGuardRuleOps is a do-nothing ruleOps: this test only drives Close, so
// no rule call is expected to run.
type closeGuardRuleOps struct{}

func (closeGuardRuleOps) RuleAdd(*netlink.Rule) error { return nil }
func (closeGuardRuleOps) RuleDel(*netlink.Rule) error { return nil }
func (closeGuardRuleOps) RuleList(int) ([]netlink.Rule, error) {
	return nil, nil
}

// closeGuardRouteLister is a do-nothing routeLister, same rationale.
type closeGuardRouteLister struct{}

func (closeGuardRouteLister) RouteListFiltered(int, *netlink.Route, uint64) ([]netlink.Route, error) {
	return nil, nil
}
func (closeGuardRouteLister) RouteList(netlink.Link, int) ([]netlink.Route, error) { return nil, nil }
func (closeGuardRouteLister) LinkByIndex(int) (netlink.Link, error)                { return nil, nil }
func (closeGuardRouteLister) LinkByName(string) (netlink.Link, error)              { return nil, nil }

// TestClosePartialTestManagersDoesNotPanic_5718 is the #5718 A7-b02-C01
// fail-on-revert.
//
// The partial test-manager constructors in test_seams.go wire only the domains
// their callers exercise and leave the rest nil. Their doc comments told
// callers that Close nil-guards the unwired state, but Close guarded only
// nlHandle and called m.tunnel.stopAll() unconditionally. stopAll immediately
// takes t.mu (tunnel_keepalive_runner.go), which dereferences the nil
// *tunnelManager, so the documented `defer m.Close()` panicked the caller's
// test rather than cleaning up.
//
// A constructor this package exports must produce a Manager that is safe to
// Close, so this test drives Close on every partial constructor.
func TestClosePartialTestManagersDoesNotPanic_5718(t *testing.T) {
	t.Run("rule ops manager", func(t *testing.T) {
		m := NewManagerWithRuleOpsForTest(closeGuardRuleOps{})
		if m.tunnel != nil {
			t.Fatal("setup: NewManagerWithRuleOpsForTest is expected to leave the " +
				"tunnel domain nil — that unwired domain is what Close must guard")
		}
		// Panics with a nil-pointer dereference in tunnelManager.stopAll
		// without the Close guard.
		if err := m.Close(); err != nil {
			t.Fatalf("Close on a rule-ops test manager: %v", err)
		}
	})

	t.Run("route lister manager", func(t *testing.T) {
		m := NewManagerWithRouteListerForTest(closeGuardRouteLister{})
		if m.tunnel != nil {
			t.Fatal("setup: NewManagerWithRouteListerForTest is expected to leave " +
				"the tunnel domain nil")
		}
		if err := m.Close(); err != nil {
			t.Fatalf("Close on a route-lister test manager: %v", err)
		}
	})

	t.Run("link ops manager still drains keepalives", func(t *testing.T) {
		// The fully-wired link-ops constructor DOES populate tunnel, so the
		// guard must not turn Close into a no-op there: stopAll still has to
		// run and drain keepalive goroutines (#848).
		m := NewManagerWithLinkOpsForTest(nil)
		if m.tunnel == nil {
			t.Fatal("setup: NewManagerWithLinkOpsForTest must wire the tunnel domain")
		}
		if err := m.Close(); err != nil {
			t.Fatalf("Close on a link-ops test manager: %v", err)
		}
	})
}
