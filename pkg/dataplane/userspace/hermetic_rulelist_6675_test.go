package userspace

import (
	"os"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #6675 — this package's tests were not hermetic with respect to the kernel
// ip-rule table, and the failure mode was a nil dereference rather than a
// diagnostic.
//
// buildSnapshot fails CLOSED on a netlink RuleList error (#3772 M9): the
// synthetic rib-group / next-table leak routes are derived from the live
// ip-rule table, so a snapshot missing them must not ship. Thirty-six call
// sites across fifteen test files write `snap, _ := buildSnapshot(...)` and then
// dereference `snap`. On a host where the dump is permitted — including this
// one, unprivileged — that is invisible. In a restricted sandbox the dump
// returns `operation not permitted`, every one of those sites panics on a nil
// pointer, and the panic carries no trace of the real cause. It surfaced as a
// phantom regression in a review run of an unrelated PR (#6670).
//
// WHY THIS IS A TestMain AND NOT THIRTY-SIX ERROR CHECKS. Handling the error at
// each site — skip on EPERM, fail otherwise — is right for one test and wrong
// as a shape: it is thirty-six copies of one policy decision, and the
// thirty-seventh call site added next month will not have it. The package
// already owns the seam that fixes it once. `ruleListFn` (routes.go) is
// indirected precisely so tests can replace it, and thirteen files already
// stub it by hand. Installing the stub as the package DEFAULT makes every test
// hermetic, and the tests that care about enumeration keep overriding it
// exactly as they do today — `routes_rulelist_3772_test.go` injects a failure
// and asserts it is surfaced, and must keep working.
//
// WHAT THIS DOES NOT COVER, stated rather than implied. buildSnapshot has three
// other error returns (an address-book content-ID collision #2514, an app
// catalog fault #3438, and a policy build failure), and a discarded error from
// any of them still nil-derefs. Those are config-shaped: they depend on the
// fixture, not the host, so they fail deterministically everywhere rather than
// only in a sandbox. The environment-dependent one — the only one that turns a
// capability difference into a phantom regression — is the one closed here.
//
// MEASURED BEFORE LANDING, because a package-wide default stub changes what
// every test sees: a test passing because the real RuleList returned actual
// rules would start seeing an empty list. The full package was run at
// -count=1 -v on this host with and without this file; the pass/skip set is
// identical (1161 test results, same names, same outcomes). No test in the
// package depends on the host's real ip-rule table.

// hermeticRuleList is the enumerator installed for the whole package: an empty
// rule table, never an error. Empty rather than an error because a snapshot
// build is expected to SUCCEED in a unit test; a test that wants the failure
// path injects it (routes_rulelist_3772_test.go).
func hermeticRuleList(int) ([]netlink.Rule, error) { return nil, nil }

// TestMain installs the hermetic ip-rule enumerator before any test runs.
//
// It is the package's only TestMain, and it deliberately does nothing else: a
// TestMain that grows setup becomes a place where tests acquire hidden
// dependencies on each other's state.
func TestMain(m *testing.M) {
	ruleListFn = hermeticRuleList
	os.Exit(m.Run())
}

// TestPackageDefaultsToAHermeticRuleEnumerator_6675 binds the WIRING, not the
// stub. `hermeticRuleList` being correct proves nothing if TestMain stops
// installing it — and nothing else in the package would notice on a host where
// the real dump happens to work, which is precisely how this defect stayed
// invisible in the first place.
func TestPackageDefaultsToAHermeticRuleEnumerator_6675(t *testing.T) {
	realFn := reflect.ValueOf(netlink.RuleList).Pointer()
	if reflect.ValueOf(ruleListFn).Pointer() == realFn {
		t.Fatalf("ruleListFn is still netlink.RuleList — TestMain did not install " +
			"the hermetic enumerator, so every buildSnapshot call site in this " +
			"package depends on the host's ip-rule table again")
	}
	if got := reflect.ValueOf(ruleListFn).Pointer(); got != reflect.ValueOf(hermeticRuleList).Pointer() {
		t.Errorf("ruleListFn is neither the real enumerator nor the hermetic one; " +
			"a leaked per-test override would make later tests depend on run order")
	}
}

// TestBuildSnapshotSucceedsWithoutTheHostRuleTable_6675 is the property the
// thirty-six discarding call sites actually rely on: under the package default,
// buildSnapshot returns a usable snapshot and no error, so `snap, _ := ...`
// followed by a dereference cannot panic for an environmental reason.
//
// It also asserts buildSnapshot never returns (nil, nil), which is what makes
// the discard survivable at all rather than merely lucky.
func TestBuildSnapshotSucceedsWithoutTheHostRuleTable_6675(t *testing.T) {
	cfg := &config.Config{}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{Workers: 1}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot failed under the hermetic enumerator: %v", err)
	}
	if snap == nil {
		t.Fatalf("buildSnapshot returned (nil, nil) — every `snap, _ :=` call site " +
			"in this package would nil-deref")
	}
}

// TestPermissionDeniedRuleListStillFailsClosed_6675 pins the half the hermetic
// default must NOT erase. The product behaviour under #3772 M9 is to fail the
// snapshot closed on an enumeration error, and a package default that made a
// test pass under a REAL EPERM would be worse than the panic it replaces: it
// would report coverage for a path it never took.
//
// The override here is the same mechanism every enumeration-sensitive test in
// the package already uses, which is what keeps this change compatible with
// them: the default is a starting value, not a lock.
func TestPermissionDeniedRuleListStillFailsClosed_6675(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, os.ErrPermission }

	cfg := &config.Config{
		RoutingOptions: config.RoutingOptionsConfig{
			StaticRoutes: []*config.StaticRoute{{
				Destination: "10.9.0.0/24",
				NextHops:    []config.NextHopEntry{{Address: "10.0.1.254"}},
			}},
		},
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{Workers: 1}, 1, 0)
	if err == nil {
		t.Fatalf("a permission-denied ip-rule enumeration was swallowed; #3772 M9 " +
			"requires the snapshot build to fail closed")
	}
	if snap != nil {
		t.Errorf("buildSnapshot returned a snapshot alongside an error; the apply " +
			"path must have nothing to ship")
	}
}
