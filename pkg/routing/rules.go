package routing

import (
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ruleOps is the narrow netlink policy-routing surface the three rule
// reconcilers (next-table, rib-group, PBR) use. Satisfied by
// *netlink.Handle in production; tests substitute a fake. This is the
// interface that makes the rule domains unit-testable without netlink.
type ruleOps interface {
	RuleAdd(*netlink.Rule) error
	RuleDel(*netlink.Rule) error
	RuleList(family int) ([]netlink.Rule, error)
}

// nextTableRulePriority is the base priority for next-table ip rules.
// Lower values = higher priority. We use 100-199 range for next-table rules.
const nextTableRulePriority = 100

// ribGroupRulePriority is the base priority for rib-group ip rules.
// Must be AFTER the main table (32766) so VRF routes supplement rather
// than override main table routing. We use 33000-33099 range.
const ribGroupRulePriority = 33000

// pbrRulePriority is the base priority for policy-based routing ip rules.
// BEFORE the main table (32766) so the kernel also honors PBR for XDP_PASS'd
// packets (e.g. SNAT'd traffic destined for a VRF/GRE tunnel).
// We use 31000-31999 range.
const pbrRulePriority = 31000

// nextTableManager reconciles next-table inter-VRF route-leak ip rules.
// Stateless apart from the borrowed ruleOps; it reconciles against live
// kernel ip-rule state.
type nextTableManager struct {
	ops ruleOps
}

// Apply creates Linux policy routing rules (ip rule) for static routes
// with next-table directives. This implements inter-VRF route leaking:
// "route X/Y next-table Instance.inet.0" means traffic to X/Y should be
// looked up in Instance's routing table.
func (n *nextTableManager) Apply(routes []*config.StaticRoute, instances []*config.RoutingInstanceConfig) error {
	// Build instance name → table ID map
	tableIDs := make(map[string]int)
	for _, inst := range instances {
		tableIDs[inst.Name] = inst.TableID
	}

	// Clean up old next-table rules (priority range 100-199)
	if err := n.clear(); err != nil {
		slog.Warn("failed to clear old next-table rules", "err", err)
	}

	prio := nextTableRulePriority
	for _, sr := range routes {
		if sr.NextTable == "" {
			continue
		}
		tableID, ok := tableIDs[sr.NextTable]
		if !ok {
			slog.Warn("next-table references unknown routing instance",
				"destination", sr.Destination, "instance", sr.NextTable)
			continue
		}

		_, dst, err := net.ParseCIDR(sr.Destination)
		if err != nil {
			slog.Warn("invalid next-table destination", "destination", sr.Destination, "err", err)
			continue
		}

		family := unix.AF_INET
		if dst.IP.To4() == nil {
			family = unix.AF_INET6
		}

		// Hard-cap the priority inside the window that clear() scans
		// (nextTableRulePriority .. nextTableRulePriority+100). A rule
		// programmed at or beyond the upper bound would never be removed
		// on a later apply and would leak permanently. Stop programming
		// further next-table routes once the window is exhausted, matching
		// the pbrManager cap pattern below. ValidateConfig emits a
		// commit-time warning before this point is ever reached.
		if prio >= nextTableRulePriority+100 {
			slog.Warn("next-table rule limit reached; ignoring further next-table routes",
				"limit", 100, "destination", sr.Destination, "instance", sr.NextTable)
			break
		}

		rule := netlink.NewRule()
		rule.Dst = dst
		rule.Table = tableID
		rule.Priority = prio
		rule.Family = family

		if err := n.ops.RuleAdd(rule); err != nil {
			slog.Warn("failed to add next-table rule",
				"destination", sr.Destination, "instance", sr.NextTable,
				"table", tableID, "err", err)
			continue
		}
		slog.Info("next-table rule added",
			"destination", sr.Destination, "instance", sr.NextTable, "table", tableID)
		prio++
	}
	return nil
}

// clear removes all ip rules in the next-table priority range.
func (n *nextTableManager) clear() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := n.ops.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if r.Priority >= nextTableRulePriority && r.Priority < nextTableRulePriority+100 {
				if err := n.ops.RuleDel(&r); err != nil {
					slog.Debug("failed to delete stale next-table rule",
						"priority", r.Priority, "err", err)
				}
			}
		}
	}
	return nil
}

// ribGroupManager reconciles rib-group route-leak ip rules. Stateless
// apart from the borrowed ruleOps.
type ribGroupManager struct {
	ops ruleOps
}

// Apply creates Linux policy routing rules (ip rule) for rib-group route
// leaking. When a routing instance has interface-routes with a rib-group
// reference, the instance's routes are leaked to other tables listed in
// the rib-group's import-rib list.
//
// Both IPv4 (InterfaceRoutesRibGroup) and IPv6 (InterfaceRoutesRibGroupV6)
// rib-groups are handled. For each source table that needs leaking, both
// IPv4 and IPv6 ip rules are created.
//
// For example, if dmz-vr (table 101) has interface-routes rib-group "dmz-leak",
// and dmz-leak has import-rib [ dmz-vr.inet.0 inet.0 ], then an ip rule is
// created to make table 101 visible to main table lookups:
//
//	ip rule add from all lookup 101 pref 33000
func (rg *ribGroupManager) Apply(ribGroups map[string]*config.RibGroup, instances []*config.RoutingInstanceConfig) error {
	// Clean up old rib-group rules
	if err := rg.clear(); err != nil {
		slog.Warn("failed to clear old rib-group rules", "err", err)
	}

	if len(ribGroups) == 0 || len(instances) == 0 {
		return nil
	}

	// Build instance name → table ID map
	tableIDs := make(map[string]int)
	for _, inst := range instances {
		tableIDs[inst.Name] = inst.TableID
	}

	// Track which source tables we've already added rules for
	// (avoid duplicate rules if multiple rib-groups reference the same table)
	leakedTables := make(map[int]bool)

	prio := ribGroupRulePriority
	for _, inst := range instances {
		// Collect all rib-group names referenced by this instance (inet + inet6)
		rgNames := []string{inst.InterfaceRoutesRibGroup, inst.InterfaceRoutesRibGroupV6}

		sourceTable := inst.TableID
		needsLeak := false
		for _, rgName := range rgNames {
			if rgName == "" {
				continue
			}
			rgDef, ok := ribGroups[rgName]
			if !ok {
				slog.Warn("interface-routes references unknown rib-group",
					"instance", inst.Name, "rib-group", rgName)
				continue
			}
			for _, ribName := range rgDef.ImportRibs {
				targetTable := resolveRibTable(ribName, tableIDs)
				if targetTable != sourceTable {
					needsLeak = true
					break
				}
			}
			if needsLeak {
				break
			}
		}
		if !needsLeak {
			continue
		}

		if leakedTables[sourceTable] {
			continue
		}

		// Each leaked table consumes TWO priorities (IPv4 then IPv6).
		// clear() only scans [ribGroupRulePriority, ribGroupRulePriority+100),
		// so a pair that would place the IPv6 rule (prio+1) at or beyond the
		// upper bound must be rejected as a unit — otherwise it leaks
		// permanently across applies. Stop before marking the table leaked
		// so a capped table is not recorded as done. ValidateConfig emits a
		// commit-time warning before this point is ever reached.
		if prio+1 >= ribGroupRulePriority+100 {
			slog.Warn("rib-group rule limit reached; ignoring further leaking tables",
				"limit", 100, "instance", inst.Name, "table", sourceTable)
			break
		}
		leakedTables[sourceTable] = true

		// Add IPv4 rule
		rule := netlink.NewRule()
		rule.Table = sourceTable
		rule.Priority = prio
		rule.Family = unix.AF_INET

		if err := rg.ops.RuleAdd(rule); err != nil {
			slog.Warn("failed to add rib-group IPv4 rule",
				"instance", inst.Name, "table", sourceTable, "err", err)
		} else {
			slog.Info("rib-group rule added",
				"instance", inst.Name, "table", sourceTable,
				"family", "inet", "pref", prio)
		}
		prio++

		// Add IPv6 rule
		rule6 := netlink.NewRule()
		rule6.Table = sourceTable
		rule6.Priority = prio
		rule6.Family = unix.AF_INET6

		if err := rg.ops.RuleAdd(rule6); err != nil {
			slog.Warn("failed to add rib-group IPv6 rule",
				"instance", inst.Name, "table", sourceTable, "err", err)
		} else {
			slog.Info("rib-group rule added",
				"instance", inst.Name, "table", sourceTable,
				"family", "inet6", "pref", prio)
		}
		prio++
	}
	return nil
}

// clear removes all ip rules in the rib-group priority range. Also
// cleans up legacy rules from the old 200-299 range.
func (rg *ribGroupManager) clear() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := rg.ops.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			inCurrent := r.Priority >= ribGroupRulePriority && r.Priority < ribGroupRulePriority+100
			inLegacy := r.Priority >= 200 && r.Priority < 300
			if inCurrent || inLegacy {
				if err := rg.ops.RuleDel(&r); err != nil {
					slog.Debug("failed to delete stale rib-group rule",
						"priority", r.Priority, "err", err)
				}
			}
		}
	}
	return nil
}

// PBRRule describes a single policy-based routing rule derived from a
// firewall filter term with a routing-instance action.
type PBRRule struct {
	Family   int    // unix.AF_INET or unix.AF_INET6
	TOS      uint8  // TOS byte (DSCP << 2), 0 = no TOS match
	Src      string // source CIDR, "" = any
	Dst      string // destination CIDR, "" = any
	TableID  int    // target routing table
	Instance string // routing instance name (for logging)
}

// pbrManager reconciles policy-based routing ip rules. Stateless apart
// from the borrowed ruleOps.
type pbrManager struct {
	ops ruleOps
}

// Apply creates Linux policy routing rules (ip rule) for firewall filter
// terms that use a routing-instance action. This implements
// policy-based routing: traffic matching DSCP/source/destination
// criteria is routed via the specified VRF's routing table.
func (p *pbrManager) Apply(rules []PBRRule) error {
	// Clean up old PBR rules first
	if err := p.clear(); err != nil {
		slog.Warn("failed to clear old PBR rules", "err", err)
	}

	if len(rules) == 0 {
		return nil
	}

	prio := pbrRulePriority
	for _, pbr := range rules {
		rule := netlink.NewRule()
		rule.Table = pbr.TableID
		rule.Priority = prio
		rule.Family = pbr.Family

		if pbr.TOS != 0 {
			rule.Tos = uint(pbr.TOS)
		}
		if pbr.Src != "" {
			_, src, err := net.ParseCIDR(pbr.Src)
			if err != nil {
				slog.Warn("invalid PBR source", "src", pbr.Src, "err", err)
				continue
			}
			rule.Src = src
		}
		if pbr.Dst != "" {
			_, dst, err := net.ParseCIDR(pbr.Dst)
			if err != nil {
				slog.Warn("invalid PBR destination", "dst", pbr.Dst, "err", err)
				continue
			}
			rule.Dst = dst
		}

		if err := p.ops.RuleAdd(rule); err != nil {
			slog.Warn("failed to add PBR rule",
				"instance", pbr.Instance, "tos", pbr.TOS,
				"src", pbr.Src, "dst", pbr.Dst,
				"table", pbr.TableID, "err", err)
			continue
		}
		slog.Info("PBR rule added",
			"instance", pbr.Instance, "tos", pbr.TOS,
			"src", pbr.Src, "dst", pbr.Dst, "table", pbr.TableID)
		prio++
		if prio >= pbrRulePriority+1000 {
			slog.Warn("PBR rule limit reached")
			break
		}
	}
	return nil
}

// clear removes all ip rules in the PBR priority range.
func (p *pbrManager) clear() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := p.ops.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if r.Priority >= pbrRulePriority && r.Priority < pbrRulePriority+1000 {
				if err := p.ops.RuleDel(&r); err != nil {
					slog.Debug("failed to delete stale PBR rule",
						"priority", r.Priority, "err", err)
				}
			}
		}
	}
	return nil
}

// BuildPBRRules extracts policy-based routing rules from firewall filter
// configuration. Each filter term with a routing-instance action produces
// one or more PBR rules depending on the match criteria.
func BuildPBRRules(fw *config.FirewallConfig, instances []*config.RoutingInstanceConfig) []PBRRule {
	if fw == nil {
		return nil
	}

	// Build instance name → table ID map
	tableIDs := make(map[string]int)
	for _, inst := range instances {
		tableIDs[inst.Name] = inst.TableID
	}

	var rules []PBRRule
	// Process inet filters
	for _, filter := range fw.FiltersInet {
		rules = append(rules, buildPBRFromFilter(filter, unix.AF_INET, tableIDs)...)
	}
	// Process inet6 filters
	for _, filter := range fw.FiltersInet6 {
		rules = append(rules, buildPBRFromFilter(filter, unix.AF_INET6, tableIDs)...)
	}
	return rules
}

// buildPBRFromFilter extracts PBR rules from a single firewall filter.
func buildPBRFromFilter(filter *config.FirewallFilter, family int, tableIDs map[string]int) []PBRRule {
	var rules []PBRRule
	for _, term := range filter.Terms {
		if term.RoutingInstance == "" {
			continue
		}
		tableID, ok := tableIDs[term.RoutingInstance]
		if !ok {
			slog.Warn("PBR: routing-instance not found",
				"filter", filter.Name, "term", term.Name,
				"instance", term.RoutingInstance)
			continue
		}

		// Determine TOS byte from DSCP value
		var tos uint8
		if term.DSCP != "" {
			tos = dscpToTOS(term.DSCP)
		}

		// If the term has source/dest addresses, create a rule per address.
		// If it has neither addresses nor DSCP, we can't express it as ip rule.
		srcs := term.SourceAddresses
		dsts := term.DestAddresses
		if len(srcs) == 0 {
			srcs = []string{""}
		}
		if len(dsts) == 0 {
			dsts = []string{""}
		}

		// Check if we have anything ip rule can match on
		hasCriteria := tos != 0 || term.SourceAddresses != nil || term.DestAddresses != nil
		if !hasCriteria {
			slog.Warn("PBR: filter term has routing-instance but no ip-rule-compatible criteria (dscp, source-address, destination-address)",
				"filter", filter.Name, "term", term.Name)
			continue
		}

		for _, src := range srcs {
			for _, dst := range dsts {
				rules = append(rules, PBRRule{
					Family:   family,
					TOS:      tos,
					Src:      src,
					Dst:      dst,
					TableID:  tableID,
					Instance: term.RoutingInstance,
				})
			}
		}
	}
	return rules
}

// dscpToTOS converts a DSCP name or numeric value to a TOS byte.
// TOS byte = DSCP value << 2 (DSCP occupies the upper 6 bits of the TOS byte).
func dscpToTOS(dscp string) uint8 {
	// DSCP name → numeric value mapping (same values as dataplane.DSCPValues)
	dscpValues := map[string]uint8{
		"ef":   46,
		"af11": 10, "af12": 12, "af13": 14,
		"af21": 18, "af22": 20, "af23": 22,
		"af31": 26, "af32": 28, "af33": 30,
		"af41": 34, "af42": 36, "af43": 38,
		"cs0": 0, "cs1": 8, "cs2": 16, "cs3": 24,
		"cs4": 32, "cs5": 40, "cs6": 48, "cs7": 56,
		"be": 0,
	}

	name := strings.ToLower(dscp)
	if val, ok := dscpValues[name]; ok {
		return val << 2
	}
	if v, err := strconv.Atoi(dscp); err == nil && v >= 0 && v <= 63 {
		return uint8(v) << 2
	}
	return 0
}

// resolveRibTable maps a Junos rib name to its kernel routing table ID.
// "<instance>.inet.0" or "<instance>.inet6.0" maps to the instance's table.
func resolveRibTable(ribName string, tableIDs map[string]int) int {
	if ribName == "inet.0" || ribName == "inet6.0" {
		return 254 // main table
	}
	// Parse "instance-name.inet.0" or "instance-name.inet6.0"
	if idx := strings.Index(ribName, ".inet"); idx > 0 {
		instanceName := ribName[:idx]
		if tableID, ok := tableIDs[instanceName]; ok {
			return tableID
		}
	}
	return 0
}
