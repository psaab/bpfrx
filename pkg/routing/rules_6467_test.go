package routing

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sys/unix"
)

// TestNextTableApplyCapAggregatesDegradedError is the #6467 fail-on-revert
// guard. When the next-table leak set exceeds the hard cap
// (config.NextTableRuleWindow), nextTableManager.Apply MUST aggregate a
// degraded error naming how many leaks were dropped — NOT a bare slog.Warn.
//
// Before #6467 the cap did `slog.Warn(...); break` with no `errs = append(...)`,
// so Apply returned nil and reported SUCCESS while silently truncating the leak
// set. That diverged the kernel (which drops leak #101+) from the userspace FIB
// (which mirrored ALL config next-table leaks uncapped), so a slow-path packet
// matching leak #101+ resolved in the target VRF in userspace but the main
// table in the kernel — a security-relevant kernel/dataplane verdict split with
// no operator signal. This mirrors the rib-group (TestRibGroupRulesPriorityCap)
// and PBR (TestPBRApplyCapBoundary) over-limit guards.
//
// RED-on-revert: reverting the cap block to the pre-#6467 `slog.Warn(...); break`
// (dropping the `errs = append(...)`) makes Apply return nil, so the first
// assertion fails with a clean t.Fatal (not a compile error — keep the loop
// index and drop-count feeding the Warn if neutralizing to reproduce master).
func TestNextTableApplyCapAggregatesDegradedError(t *testing.T) {
	mkRoutes := func(n int) []*config.StaticRoute {
		routes := make([]*config.StaticRoute, n)
		for i := 0; i < n; i++ {
			routes[i] = &config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
				NextTable:   "dmz-vr",
			}
		}
		return routes
	}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	const over = 50 // 50 next-table routes past the cap must be reported.
	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	err := nt.Apply(mkRoutes(config.NextTableRuleWindow+over), instances)
	if err == nil {
		t.Fatal("over-cap Apply must return a degraded error naming the dropped " +
			"next-table leaks, not a bare Warn (#6467)")
	}
	// The error must name the cap so the degraded result is self-describing.
	if !strings.Contains(err.Error(), "next-table rule limit") {
		t.Errorf("degraded error must name the next-table cap, got %v", err)
	}
	// The error must name HOW MANY leaks were dropped (the routes past the cap).
	if !strings.Contains(err.Error(), fmt.Sprintf("%d next-table route", over)) {
		t.Errorf("degraded error must name the %d dropped leaks, got %v", over, err)
	}
	// The cap still holds: exactly NextTableRuleWindow rules install, none beyond.
	if total := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); total != config.NextTableRuleWindow {
		t.Errorf("expected the cap to hold at %d installed rules, got %d",
			config.NextTableRuleWindow, total)
	}
	assertAllRulesInRange(t, ops, nextTableRulePriority, nextTableRulePriority+maxNextTableRules)
}

// TestNextTableApplyUnderCapNoError is the companion no-false-positive guard:
// exactly at the cap (and below) Apply returns nil and installs every leak, so
// the #6467 degraded error only fires on genuine over-subscription.
func TestNextTableApplyUnderCapNoError(t *testing.T) {
	mkRoutes := func(n int) []*config.StaticRoute {
		routes := make([]*config.StaticRoute, n)
		for i := 0; i < n; i++ {
			routes[i] = &config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
				NextTable:   "dmz-vr",
			}
		}
		return routes
	}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	if err := nt.Apply(mkRoutes(config.NextTableRuleWindow), instances); err != nil {
		t.Fatalf("exactly %d next-table routes must apply without a degraded error, got %v",
			config.NextTableRuleWindow, err)
	}
	if total := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); total != config.NextTableRuleWindow {
		t.Fatalf("expected all %d routes programmed at the limit, got %d",
			config.NextTableRuleWindow, total)
	}
}

// TestNextTableApplyDroppedCountCountsOnlyEligible is the #6467-fold guard for
// the degraded-error drop count. The applier skips a next-table route with an
// unknown target instance (no prio++), so such a route never consumes a window
// slot and is NOT a "dropped leak". The "N not leaked" figure must therefore
// count only ELIGIBLE routes past the cap (known instance + parseable CIDR), not
// every next-table route in the tail.
//
// Layout: the window's worth of valid routes fill the window, then the tail
// carries 50 valid + 30 dangling routes. The cap fires with 50 eligible +
// 30 ineligible past it, so the accurate drop count is 50, not 80.
//
// RED-on-revert: reverting the dropped-count scan to `if rem.NextTable != ""`
// (counting all next-table routes in the tail) makes the error say "80", so the
// "50" assertion fails and the "not 80" assertion fails.
func TestNextTableApplyDroppedCountCountsOnlyEligible(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	var routes []*config.StaticRoute
	// Fill the window with valid routes.
	for i := 0; i < config.NextTableRuleWindow; i++ {
		routes = append(routes, &config.StaticRoute{
			Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
			NextTable:   "dmz-vr",
		})
	}
	// Tail: 50 eligible (valid) next-table routes past the cap...
	for i := 0; i < 50; i++ {
		routes = append(routes, &config.StaticRoute{
			Destination: fmt.Sprintf("172.16.%d.0/24", i),
			NextTable:   "dmz-vr",
		})
	}
	// ...plus 30 dangling (unknown-instance) routes that would never install.
	for i := 0; i < 30; i++ {
		routes = append(routes, &config.StaticRoute{
			Destination: fmt.Sprintf("192.168.%d.0/24", i),
			NextTable:   "ghost-vr", // not a defined instance
		})
	}

	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	err := nt.Apply(routes, instances)
	if err == nil {
		t.Fatal("over-cap Apply must return a degraded error (#6467)")
	}
	if !strings.Contains(err.Error(), "50 next-table route") {
		t.Errorf("drop count must name only the 50 ELIGIBLE routes past the cap, got %v", err)
	}
	if strings.Contains(err.Error(), "80 next-table route") {
		t.Errorf("drop count must NOT include the 30 dangling routes that never install, got %v", err)
	}
	// Only the window's worth of valid rules installed.
	if total := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); total != config.NextTableRuleWindow {
		t.Errorf("expected the cap to hold at %d installed rules, got %d", config.NextTableRuleWindow, total)
	}
}
