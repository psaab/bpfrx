package userspace

import (
	"os"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #7446: buildSnapshot returns (*ConfigSnapshot, error) and, on ANY failure,
// returns a NIL pointer. Test call sites that discarded the error dereferenced
// it, and a nil dereference is a SIGSEGV that aborts the whole test binary —
// so one bad fixture took every remaining test in the package down with it and
// reported a crash with no diagnostic instead of naming the failing build step.
//
// These helpers make the safe form the SHORT form. A call site gets shorter by
// adopting them, which is what keeps the population from growing back: the
// discarding spelling is now strictly more typing than the checked one.
//
// Scope, stated because the site count depends entirely on how you count it
// (#7446 says ~45; a narrower regex counts 36; both are right about different
// populations): these cover the THREE builders that return a POINTER and can
// therefore nil-dereference — buildSnapshot, buildSnapshotWithSchedulerState
// and buildSnapshotWithSchedulerStateAndNATCounters. The sibling builders
// (buildPolicySnapshots, buildAddressBookTable*, ...) return slices and maps,
// where a nil result reads back safely; discarding their error is a vacuity
// smell rather than this crash, and is deliberately NOT swept in here.

func mustBuildSnapshot(t *testing.T, cfg *config.Config, ucfg config.UserspaceConfig,
	generation uint64, fibGeneration uint32) *ConfigSnapshot {
	t.Helper()
	snap, err := buildSnapshot(cfg, ucfg, generation, fibGeneration)
	return checkedSnapshot7446(t, "buildSnapshot", snap, err)
}

func mustBuildSnapshotWithSchedulerState(t *testing.T, cfg *config.Config, ucfg config.UserspaceConfig,
	generation uint64, fibGeneration uint32, activeState map[string]bool,
	routeOverlay []config.RouteOverlayEntry, feedOverlay map[string][]string) *ConfigSnapshot {
	t.Helper()
	snap, err := buildSnapshotWithSchedulerState(cfg, ucfg, generation, fibGeneration,
		activeState, routeOverlay, feedOverlay)
	return checkedSnapshot7446(t, "buildSnapshotWithSchedulerState", snap, err)
}

// checkedSnapshot7446 fails the test rather than returning something a caller
// can dereference. The nil-with-nil-error arm is not redundant defensiveness:
// it is the ONLY thing standing between a future builder that forgets to set
// its error and the exact SIGSEGV this issue exists to remove.
func checkedSnapshot7446(t *testing.T, who string, snap *ConfigSnapshot, err error) *ConfigSnapshot {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", who, err)
	}
	if snap == nil {
		t.Fatalf("%s returned a nil snapshot with a nil error", who)
	}
	return snap
}

// TestPermissionDeniedRuleListStillFailsClosed_6675 is the propagation link
// #6675 left unpinned, contributed on the #7446 issue thread by the lane that
// independently fixed the same defect (PR #7453, closed as a duplicate of the
// merged #7445). It belongs with this work rather than as its own PR.
//
// routes_rulelist_3772_test.go pins that buildRouteSnapshots SURFACES a
// RuleList failure. What was not pinned is that buildSnapshot PROPAGATES it and
// returns nothing shippable — and that link matters precisely BECAUSE the
// package now installs a stub that can never fail. A future change making
// buildSnapshot tolerant of a route-snapshot error, or returning a partial
// snapshot alongside one, would go unnoticed: every call site converted above
// would then hand the apply path a snapshot #3772 M9 says must not ship.
//
// A hermetic default that made a test pass under a real EPERM would be worse
// than the panic it replaced — it would report coverage for a path never taken.
//
// The override restores to the hermetic TestMain stub rather than to
// netlink.RuleList, so it composes with it.
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
