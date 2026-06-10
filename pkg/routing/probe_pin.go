// probe_pin.go implements the RPM probe next-hop pin reconciler
// (#1827 PR-1a §4.2.4).
//
// Each RPM test with a `next-hop` gets a deterministic per-test fwmark +
// per-test kernel routing table (mark config.ProbeFwmarkBase+idx, table
// config.ProbeTableBase+idx, idx assigned in sorted probe/test order),
// one `ip rule fwmark <mark> lookup <table>` in the reserved priority
// band 50-99, and the pinned /32 (/128) host route installed with an
// explicit `dev` + `onlink` in the per-test table. Probe sockets set
// SO_MARK with the same mark (pkg/rpm), so ONLY probe traffic follows
// the pin: the rules and tables are invisible to transit traffic (fast
// path AND kernel slow path), are NOT rendered into FRR, and are NOT
// part of the dataplane snapshot.
//
// Per-test tables make "same target via two uplinks" (the normal
// dual-WAN probe pattern) first-class. Startup runs a clear() pass over
// the band and flushes the probe tables so a crashed daemon never leaks
// stale pins (AGY r2-3). Pin state follows the prober lifecycle, not
// config lifecycle.
package routing

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ProbePin describes one RPM test's next-hop pin: the fwmark rule plus
// the pinned host route in the per-test probe table.
type ProbePin struct {
	TestKey   string // "probe/test" — matches the pkg/rpm results key
	Index     int    // deterministic index in sorted probe/test order
	Mark      uint32 // fwmark (config.ProbeFwmarkBase + Index)
	Table     int    // kernel routing table (config.ProbeTableBase + Index)
	Priority  int    // ip-rule priority (config.ProbeRulePriorityBase + Index)
	Target    string // probe target IP literal
	NextHop   string // pinned next-hop IP
	Interface string // Linux egress interface name (resolved)
}

// BuildProbePins computes the deterministic pin assignment for every
// RPM test that configures a next-hop. The assignment is in sorted
// probe-name then test-name order so both the rule programmer (this
// package) and the SO_MARK socket option (pkg/rpm) derive identical
// marks from the same config. rethMap translates Junos RETH interface
// names to physical member names (e.g. "reth0.50" → "ge-0-0-2.50").
func BuildProbePins(rpmCfg *config.RPMConfig, rethMap map[string]string) []ProbePin {
	if rpmCfg == nil || len(rpmCfg.Probes) == 0 {
		return nil
	}
	probeNames := make([]string, 0, len(rpmCfg.Probes))
	for name := range rpmCfg.Probes {
		probeNames = append(probeNames, name)
	}
	sort.Strings(probeNames)

	var pins []ProbePin
	idx := 0
	for _, pn := range probeNames {
		probe := rpmCfg.Probes[pn]
		if probe == nil {
			continue
		}
		testNames := make([]string, 0, len(probe.Tests))
		for name := range probe.Tests {
			testNames = append(testNames, name)
		}
		sort.Strings(testNames)
		for _, tn := range testNames {
			test := probe.Tests[tn]
			if test == nil || test.NextHop == "" {
				continue
			}
			if idx >= config.ProbeTableCount {
				// Commit validation caps this; defensive guard so a
				// non-strict-path config can never program outside the
				// reserved band.
				slog.Warn("probe pin band exhausted; ignoring further next-hop pins",
					"probe", pn, "test", tn, "limit", config.ProbeTableCount)
				return pins
			}
			pins = append(pins, ProbePin{
				TestKey:   pn + "/" + tn,
				Index:     idx,
				Mark:      uint32(config.ProbeFwmarkBase + idx),
				Table:     config.ProbeTableBase + idx,
				Priority:  config.ProbeRulePriorityBase + idx,
				Target:    test.Target,
				NextHop:   test.NextHop,
				Interface: ResolveProbeInterface(test.DestinationInterface, rethMap),
			})
			idx++
		}
	}
	return pins
}

// ResolveProbeInterface translates a Junos interface/unit name into the
// Linux kernel interface name used for SO_BINDTODEVICE and the pinned
// route's `dev`: RETH base names resolve through rethMap to the local
// physical member, slashes become dashes, and the default ".0" unit
// suffix is stripped (VLAN units like ".50" are real kernel names and
// are preserved). Mirrors the FRR static-route name translation.
func ResolveProbeInterface(name string, rethMap map[string]string) string {
	if name == "" {
		return ""
	}
	parts := strings.SplitN(name, ".", 2)
	base := parts[0]
	if phys, ok := rethMap[base]; ok && phys != "" {
		base = phys
	}
	base = config.LinuxIfName(base)
	if len(parts) == 2 && parts[1] != "0" {
		return base + "." + parts[1]
	}
	return base
}

// probePinOps is the narrow netlink surface the probe-pin reconciler
// uses. Satisfied by *netlink.Handle; tests substitute a fake.
type probePinOps interface {
	RuleAdd(*netlink.Rule) error
	RuleDel(*netlink.Rule) error
	RuleList(family int) ([]netlink.Rule, error)
	RouteAdd(*netlink.Route) error
	RouteDel(*netlink.Route) error
	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)
	LinkByName(name string) (netlink.Link, error)
}

// probePinManager reconciles probe pin rules + routes. Stateless apart
// from the borrowed probePinOps; it reconciles against live kernel
// state (clear-then-program, like the rules.go reconcilers).
type probePinManager struct {
	ops probePinOps
}

// Apply clears the probe-pin band and programs one fwmark rule + one
// pinned host route per pin. Pins whose egress interface does not exist
// are skipped with a warning (the probe will simply fail unpinned-time
// resolution until the interface appears and the next apply runs).
func (p *probePinManager) Apply(pins []ProbePin) error {
	if err := p.clear(); err != nil {
		slog.Warn("failed to clear probe pin band", "err", err)
	}
	for _, pin := range pins {
		target := net.ParseIP(pin.Target)
		nextHop := net.ParseIP(pin.NextHop)
		if target == nil || nextHop == nil {
			slog.Warn("probe pin: invalid target/next-hop",
				"test", pin.TestKey, "target", pin.Target, "next_hop", pin.NextHop)
			continue
		}
		family := unix.AF_INET
		hostBits := 32
		if target.To4() == nil {
			family = unix.AF_INET6
			hostBits = 128
		}

		link, err := p.ops.LinkByName(pin.Interface)
		if err != nil {
			slog.Warn("probe pin: egress interface not found",
				"test", pin.TestKey, "interface", pin.Interface, "err", err)
			continue
		}

		rule := netlink.NewRule()
		rule.Family = family
		rule.Mark = pin.Mark
		rule.Table = pin.Table
		rule.Priority = pin.Priority
		if err := p.ops.RuleAdd(rule); err != nil {
			slog.Warn("probe pin: failed to add fwmark rule",
				"test", pin.TestKey, "mark", pin.Mark, "table", pin.Table, "err", err)
			continue
		}

		route := &netlink.Route{
			Dst:       &net.IPNet{IP: target, Mask: net.CIDRMask(hostBits, hostBits)},
			Gw:        nextHop,
			LinkIndex: link.Attrs().Index,
			Table:     pin.Table,
			Flags:     int(netlink.FLAG_ONLINK),
		}
		if err := p.ops.RouteAdd(route); err != nil {
			slog.Warn("probe pin: failed to add pinned route",
				"test", pin.TestKey, "target", pin.Target,
				"next_hop", pin.NextHop, "table", pin.Table, "err", err)
			continue
		}
		slog.Info("probe pin programmed",
			"test", pin.TestKey, "target", pin.Target, "next_hop", pin.NextHop,
			"interface", pin.Interface, "mark", fmt.Sprintf("%#x", pin.Mark),
			"table", pin.Table)
	}
	return nil
}

// clear removes all ip rules in the probe-pin priority band and flushes
// every route in the reserved probe tables (both families). Run at
// daemon startup as well so a crashed daemon never leaks stale pins.
func (p *probePinManager) clear() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := p.ops.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if r.Priority >= config.ProbeRulePriorityBase &&
				r.Priority < config.ProbeRulePriorityBase+config.ProbeTableCount {
				if err := p.ops.RuleDel(&r); err != nil {
					slog.Debug("failed to delete stale probe pin rule",
						"priority", r.Priority, "err", err)
				}
			}
		}
		for table := config.ProbeTableBase; table < config.ProbeTableBase+config.ProbeTableCount; table++ {
			routes, err := p.ops.RouteListFiltered(family,
				&netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
			if err != nil {
				continue
			}
			for i := range routes {
				if err := p.ops.RouteDel(&routes[i]); err != nil {
					slog.Debug("failed to delete stale probe pin route",
						"table", table, "err", err)
				}
			}
		}
	}
	return nil
}
