package routing

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
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

	// Clean up old next-table rules (priority range 100-199). A failed
	// per-family list does NOT abort the apply — we still re-add every
	// desired rule below so forward progress is preserved on the common
	// path. The clear error is captured and returned at the end so the
	// caller can observe (and a future caller retry) instead of leaving
	// orphaned rules in an unobservable window (#2273).
	clearErr := n.clear()
	if clearErr != nil {
		slog.Warn("failed to clear old next-table rules", "err", clearErr)
	}

	// Aggregate every failure (clear + per-rule add) and return it so the
	// commit/apply outcome reflects a half-installed leak instead of
	// reporting success after the up-front clear already removed the
	// previously-working next-table rules (#3731). A per-rule RuleAdd error
	// used to be logged and swallowed (Apply returned clearErr only), so a
	// transient netlink failure after clear() left inter-VRF leaking DOWN
	// with no signal to the daemon apply loop. This mirrors the #3430 PBR
	// pattern (aggregate + errors.Join) already used below. The clear error,
	// if any, is the first aggregated entry.
	var errs []error
	if clearErr != nil {
		errs = append(errs, clearErr)
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
			errs = append(errs, fmt.Errorf(
				"add next-table rule destination %s instance %s table %d: %w",
				sr.Destination, sr.NextTable, tableID, err))
			continue
		}
		slog.Info("next-table rule added",
			"destination", sr.Destination, "instance", sr.NextTable, "table", tableID)
		prio++
	}
	// Desired rules are re-added; surface any clear/add failure so a dropped
	// leak rule (or the orphaned-rule window) is observable rather than
	// silently nil (#3731 / #2273).
	return errors.Join(errs...)
}

// clear removes all ip rules in the next-table priority range.
//
// A per-family RuleList dump that fails transiently must NOT be silently
// swallowed: continuing past it means the rules in that family's window
// are left in place (orphaned) for this pass while the other family is
// cleaned, and the caller never learns it happened. We still best-effort
// delete every family whose dump DID succeed, but we aggregate the dump
// failures and return them so Apply (and ultimately the daemon apply
// loop) can observe — and a future caller could retry — instead of the
// brief, unobservable self-healing-orphan window described in #2273.
func (n *nextTableManager) clear() error {
	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := n.ops.RuleList(family)
		if err != nil {
			errs = append(errs, fmt.Errorf("list next-table rules family %d: %w", family, err))
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
	return errors.Join(errs...)
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
	// Clean up old rib-group rules. As with next-table, a failed per-family
	// list does not abort the apply; the clear error is captured and
	// returned at the end (or at the early-return below) so the caller can
	// observe it (#2273).
	clearErr := rg.clear()
	if clearErr != nil {
		slog.Warn("failed to clear old rib-group rules", "err", clearErr)
	}

	// Aggregate every failure (clear + per-rule add) and return it so a
	// dropped leak rule is surfaced instead of reporting success after the
	// up-front clear already removed the previously-working rules (#3731).
	// A per-rule RuleAdd error used to be logged and swallowed (Apply
	// returned clearErr only), so a transient netlink failure after clear()
	// left inter-VRF leaking DOWN with no signal. This mirrors the #3430 PBR
	// pattern (aggregate + errors.Join) already used below. The clear error,
	// if any, is the first aggregated entry.
	var errs []error
	if clearErr != nil {
		errs = append(errs, clearErr)
	}

	if len(ribGroups) == 0 || len(instances) == 0 {
		return errors.Join(errs...)
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
				targetTable, ok := resolveRibTable(ribName, tableIDs)
				if !ok {
					// Unknown / undefined rib name: do NOT treat it as
					// a (non-source) target table — that would set
					// needsLeak and install an `ip rule from all lookup
					// <sourceTable>` for a rib that does not exist,
					// silently leaking the source table into the main
					// lookup (#2226). Skip it; warn for visibility. The
					// strict commit-time gate normally rejects this
					// before apply, but a tolerantly-loaded / peer-synced
					// config can still reach here.
					slog.Warn("rib-group import-rib references unknown rib; skipping (not leaking)",
						"instance", inst.Name, "rib-group", rgName, "import-rib", ribName)
					continue
				}
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
			errs = append(errs, fmt.Errorf(
				"add rib-group IPv4 rule instance %s table %d: %w",
				inst.Name, sourceTable, err))
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
			errs = append(errs, fmt.Errorf(
				"add rib-group IPv6 rule instance %s table %d: %w",
				inst.Name, sourceTable, err))
		} else {
			slog.Info("rib-group rule added",
				"instance", inst.Name, "table", sourceTable,
				"family", "inet6", "pref", prio)
		}
		prio++
	}
	// Desired rules are re-added; surface any clear/add failure so a dropped
	// leak rule (or the orphaned-rule window) is observable rather than
	// silently nil (#3731 / #2273).
	return errors.Join(errs...)
}

// clear removes all ip rules in the rib-group priority range. Also
// cleans up legacy rules from the old 200-299 range.
//
// Per-family RuleList dump failures are aggregated and returned rather
// than swallowed; see the rationale on nextTableManager.clear (#2273).
func (rg *ribGroupManager) clear() error {
	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := rg.ops.RuleList(family)
		if err != nil {
			errs = append(errs, fmt.Errorf("list rib-group rules family %d: %w", family, err))
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
	return errors.Join(errs...)
}

// PBRRule describes a single policy-based routing rule derived from a
// firewall filter term with a routing-instance action.
type PBRRule struct {
	Family int   // unix.AF_INET or unix.AF_INET6
	TOS    uint8 // TOS byte (DSCP << 2); only meaningful when TOSSet
	// TOSSet distinguishes "match DSCP 0" (be / cs0 / numeric 0) from
	// "no DSCP match" (#3430 H2). TOS==0 is a perfectly valid DSCP
	// (best-effort / class-selector 0); without an explicit presence flag
	// the applier either skipped the rule (no address predicate) or widened
	// it to ALL DSCP values (address predicate present). The rule emits a
	// `tos` selector iff TOSSet is true.
	TOSSet bool
	Src    string // source CIDR, "" = any (no `from` selector)
	Dst    string // destination CIDR, "" = any (no `to` selector)
	// IPProto, Sport and Dport mirror the L4 predicates a kernel `ip rule` CAN
	// express (#3730): FRA_IP_PROTO, FRA_SPORT_RANGE and FRA_DPORT_RANGE. Before
	// #3730 the FBF mirror emitted only the address/DSCP selectors and silently
	// dropped every L4 predicate, so a port/protocol-constrained
	// `then routing-instance` term either over-steered ALL address-matching
	// traffic to the target VRF or no-opped — with no degraded signal. The
	// builder now honors these; predicates an ip rule cannot represent
	// (port-except, tcp-flags, icmp-type/code, is-fragment, flexible-match-range)
	// fail closed (the whole term is dropped and the build is marked degraded)
	// rather than widening the match.
	IPProto  int           // IP protocol number, 0 = no protocol selector
	Sport    *PBRPortRange // source-port range, nil = no source-port selector
	Dport    *PBRPortRange // destination-port range, nil = no dest-port selector
	TableID  int           // target routing table
	Instance string        // routing instance name (for logging)
}

// PBRPortRange is a numeric [Lo,Hi] port range for the kernel FBF ip-rule
// mirror. A single port has Lo==Hi. It maps 1:1 onto netlink's RulePortRange
// (FRA_SPORT_RANGE / FRA_DPORT_RANGE) but stays netlink-free so the builder is
// unit-testable without the kernel.
type PBRPortRange struct {
	Lo uint16
	Hi uint16
}

// String renders the range as a single port ("443") or a low-high span
// ("1024-2048"). A nil receiver renders as "" so it is safe to log an unset
// selector directly.
func (r *PBRPortRange) String() string {
	if r == nil {
		return ""
	}
	if r.Lo == r.Hi {
		return strconv.Itoa(int(r.Lo))
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// maxPBRRules bounds the number of ip rules the PBR builder/applier will
// install, matching the pbrRulePriority window (clear() scans
// [pbrRulePriority, pbrRulePriority+1000)). A larger DSCP×src×dst expansion
// is truncated and reported as a degraded build (#3430 M3) rather than
// silently dropping later terms' steering.
const maxPBRRules = 1000

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
	// Clean up old PBR rules first. As with next-table, a failed per-family
	// list does not abort the apply; the clear error is captured and
	// returned at the end (or at the early-return below) so the caller can
	// observe it (#2273).
	clearErr := p.clear()
	if clearErr != nil {
		slog.Warn("failed to clear old PBR rules", "err", clearErr)
	}

	// Aggregate every failure (clear, parse, add, overflow) and return it so
	// the commit/apply outcome reflects a half-installed policy instead of
	// reporting success after the up-front clear already removed the
	// previously-working steering (#3430 H3). The clear error, if any, is the
	// first aggregated entry.
	var errs []error
	if clearErr != nil {
		errs = append(errs, clearErr)
	}

	if len(rules) == 0 {
		return errors.Join(errs...)
	}

	prio := pbrRulePriority
	for _, pbr := range rules {
		// Cap at the priority window (defense-in-depth; BuildPBRRules already
		// truncates). Checked at the top so exactly maxPBRRules rules install
		// without a spurious overflow error (#3430 M3 apply leg).
		if prio >= pbrRulePriority+maxPBRRules {
			errs = append(errs, fmt.Errorf("PBR rule limit (%d) reached; remaining rules dropped", maxPBRRules))
			break
		}
		rule := netlink.NewRule()
		rule.Table = pbr.TableID
		rule.Priority = prio
		rule.Family = pbr.Family

		// Emit a tos selector iff the term actually matched a DSCP (#3430 H2).
		if pbr.TOSSet {
			rule.Tos = uint(pbr.TOS)
		}
		if pbr.Src != "" {
			_, src, err := net.ParseCIDR(pbr.Src)
			if err != nil {
				errs = append(errs, fmt.Errorf("PBR source %q (instance %s): %w", pbr.Src, pbr.Instance, err))
				continue
			}
			rule.Src = src
		}
		if pbr.Dst != "" {
			_, dst, err := net.ParseCIDR(pbr.Dst)
			if err != nil {
				errs = append(errs, fmt.Errorf("PBR destination %q (instance %s): %w", pbr.Dst, pbr.Instance, err))
				continue
			}
			rule.Dst = dst
		}

		// Emit the L4 selectors the kernel ip rule supports (#3730). IPProto is
		// written only when > 0 (the netlink FRA_IP_PROTO emit condition; 0 =
		// "match any"). Sport/Dport map onto FRA_SPORT_RANGE / FRA_DPORT_RANGE.
		if pbr.IPProto > 0 {
			rule.IPProto = pbr.IPProto
		}
		if pbr.Sport != nil {
			rule.Sport = netlink.NewRulePortRange(pbr.Sport.Lo, pbr.Sport.Hi)
		}
		if pbr.Dport != nil {
			rule.Dport = netlink.NewRulePortRange(pbr.Dport.Lo, pbr.Dport.Hi)
		}

		if err := p.ops.RuleAdd(rule); err != nil {
			errs = append(errs, fmt.Errorf("add PBR rule instance %s table %d: %w", pbr.Instance, pbr.TableID, err))
			continue
		}
		slog.Info("PBR rule added",
			"instance", pbr.Instance, "tos", pbr.TOS, "tos_set", pbr.TOSSet,
			"src", pbr.Src, "dst", pbr.Dst, "ipproto", pbr.IPProto,
			"sport", pbr.Sport.String(), "dport", pbr.Dport.String(),
			"table", pbr.TableID)
		prio++
	}
	// Desired rules are re-added; surface any clear/parse/add/overflow failure.
	return errors.Join(errs...)
}

// clear removes all ip rules in the PBR priority range.
//
// Per-family RuleList dump failures are aggregated and returned rather
// than swallowed; see the rationale on nextTableManager.clear (#2273).
func (p *pbrManager) clear() error {
	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := p.ops.RuleList(family)
		if err != nil {
			errs = append(errs, fmt.Errorf("list PBR rules family %d: %w", family, err))
			continue
		}
		for _, r := range rules {
			if r.Priority >= pbrRulePriority && r.Priority < pbrRulePriority+1000 {
				if err := p.ops.RuleDel(&r); err != nil {
					// #3430 H3: a RuleDel failure leaves a STALE PBR rule in the
					// kernel. Join it into the returned error so Apply does not
					// report success after the up-front clear could not remove a
					// stale (now-divergent) rule — the operator must see that the
					// installed steering may still carry leftover rules.
					errs = append(errs, fmt.Errorf("delete stale PBR rule prio %d: %w", r.Priority, err))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// BuildPBRRules extracts policy-based routing (filter-based-forwarding) ip
// rules from the firewall configuration, matching Junos FBF semantics.
//
// Junos FBF is realized by an INPUT firewall filter attached to an interface;
// a `then routing-instance <vr>` term steers matching ingress traffic to that
// instance's routing table. The builder therefore derives rules ONLY from
// filters actually attached as an interface-unit input filter (#3430 H1) — a
// defined-but-unattached filter has no dataplane effect in Junos and must not
// program a global ip rule. Output-attached filters are not FBF and are
// ignored.
//
// Each attached filter is expanded once regardless of how many interfaces
// reference it: the resulting ip rules carry no incoming-interface selector
// (a documented widening relative to per-interface Junos FBF — adding an iif
// selector requires the kernel ifname mapping and is a separate change), so a
// duplicate per attachment would be redundant.
//
// Kernel-mirror support matrix (#3730). An `ip rule` can only express a subset
// of a firewall-filter term's `from` predicates, so the mirror is exact for the
// representable ones and FAILS CLOSED for the rest:
//
//   - REPRESENTABLE (honored): source/destination address + prefix-list (FRA_SRC/
//     FRA_DST), DSCP (rtmsg tos, DSCP-0 excepted — see below), `protocol`
//     (FRA_IP_PROTO), `source-port` (FRA_SPORT_RANGE) and `destination-port`
//     (FRA_DPORT_RANGE). Multi-value protocol/port sets expand to one ip rule per
//     value; a port range maps to a single [lo,hi] rule range.
//   - UNREPRESENTABLE (fail-closed, whole term dropped + degraded): a non-empty
//     address `except` set, a DSCP-0 match (the netlink layer writes tos only when
//     non-zero and a zero tos matches ANY DSCP), `source-port-except` /
//     `destination-port-except` (no negated port selector), `tcp-flags`,
//     `icmp-type` / `icmp-code`, `is-fragment`, `flexible-match-range`, and any
//     unresolved / unenforceable `from` leaf. Emitting the address/protocol/port
//     half while silently dropping these would WIDEN the match and steer traffic
//     the operator constrained away (the #3730 over-steer); dropping the term is
//     the fail-safe under-steer (steered traffic falls back to the main table),
//     and the userspace filter path still enforces the term exactly.
//
// The returned error is non-nil when the build is DEGRADED: a term carries an
// ip-rule-unrepresentable predicate (per the matrix above) or the expansion
// exceeds maxPBRRules. The successfully-built rules are still returned so the
// caller can install them and surface the degradation.
func BuildPBRRules(cfg *config.Config) ([]PBRRule, error) {
	if cfg == nil {
		return nil, nil
	}
	fw := &cfg.Firewall

	// Build instance name → table ID map
	tableIDs := make(map[string]int)
	for _, inst := range cfg.RoutingInstances {
		tableIDs[inst.Name] = inst.TableID
	}

	inetAttached, inet6Attached := collectAttachedInputFilters(&cfg.Interfaces)
	pls := cfg.PolicyOptions.PrefixLists

	var rules []PBRRule
	var errs []error
	build := func(names []string, filters map[string]*config.FirewallFilter, family int) {
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				// Dangling attachment (filter named on an interface but not
				// defined). The strict commit gate rejects this
				// (validateFilterAttachmentReferences / warn path); skip here.
				continue
			}
			r, e := buildPBRFromFilter(filter, family, tableIDs, pls)
			rules = append(rules, r...)
			errs = append(errs, e...)
		}
	}
	build(sortedKeys(inetAttached), fw.FiltersInet, unix.AF_INET)
	build(sortedKeys(inet6Attached), fw.FiltersInet6, unix.AF_INET6)

	// M3: truncate to the priority window and report the overflow rather than
	// silently dropping later terms' steering.
	if len(rules) > maxPBRRules {
		errs = append(errs, fmt.Errorf(
			"PBR expansion produced %d ip rules, exceeding the limit of %d; "+
				"steering for the %d rule(s) beyond the limit is dropped — reduce the "+
				"DSCP×source×destination cross-product in the routing-instance filter terms",
			len(rules), maxPBRRules, len(rules)-maxPBRRules))
		rules = rules[:maxPBRRules]
	}
	return rules, errors.Join(errs...)
}

// collectAttachedInputFilters returns the set of filter names attached as an
// interface-unit INPUT filter, split by family. These are the only filters
// whose `then routing-instance` terms take effect as Junos FBF (#3430 H1).
func collectAttachedInputFilters(ifs *config.InterfacesConfig) (inet, inet6 map[string]struct{}) {
	inet = make(map[string]struct{})
	inet6 = make(map[string]struct{})
	if ifs == nil {
		return inet, inet6
	}
	for _, ifc := range ifs.Interfaces {
		if ifc == nil {
			continue
		}
		for _, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			if unit.FilterInputV4 != "" {
				inet[unit.FilterInputV4] = struct{}{}
			}
			if unit.FilterInputV6 != "" {
				inet6[unit.FilterInputV6] = struct{}{}
			}
		}
	}
	return inet, inet6
}

// sortedKeys returns the map keys in deterministic (sorted) order so the
// emitted ip-rule priorities are stable across applies.
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// buildPBRFromFilter extracts PBR rules from a single firewall filter.
// The returned error slice carries per-term DEGRADED conditions (an
// unrepresentable except set, a DSCP-0 match, or an ip-rule-unrepresentable
// L4/per-packet predicate — #3730); the buildable rules are still returned.
func buildPBRFromFilter(filter *config.FirewallFilter, family int, tableIDs map[string]int, pls map[string]*config.PrefixList) ([]PBRRule, []error) {
	var rules []PBRRule
	var errs []error
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

		// Classify the term's L4/per-packet predicates against what a kernel ip
		// rule can express (#3730). A predicate an ip rule cannot represent
		// (port-except / tcp-flags / icmp / is-fragment / flex / unresolved from
		// leaf, or an unknown protocol / unparseable port) fails CLOSED: the whole
		// term is dropped so the mirror never widens a constrained steer to
		// address-only. The representable predicates (protocol, source/destination
		// port) are honored below via the cross-product.
		protos, sports, dports, unrep := pbrTermL4(term)
		if len(unrep) > 0 {
			errs = append(errs, fmt.Errorf(
				"PBR filter %s term %s carries filter predicate(s) [%s] that a kernel "+
					"ip rule cannot represent (the FBF mirror steers on address / DSCP / "+
					"protocol / port only); steering for this term is dropped (fail-safe "+
					"under-steer to the main table) rather than widening the match — enforce "+
					"it on the userspace filter path",
				filter.Name, term.Name, strings.Join(unrep, ", ")))
			continue
		}

		// DSCP → TOS presence-tracked values (#2545 multi-value, #3430 H2).
		// An ip rule carries a SINGLE tos, so a term with several `from dscp`
		// values expands to one rule per DSCP (× the src/dst cross-product).
		//
		// DSCP 0 (be / cs0 / numeric 0) is NOT representable as an ip rule: the
		// netlink layer (vishvananda/netlink) writes the rtmsg tos field only
		// when non-zero (ruleHandle, rule_linux.go) and exposes no FRA_DSCP
		// escape hatch, and the kernel treats a zero tos in a fib rule as
		// "match ANY tos". Emitting a TOS=0 rule would therefore OVER-MATCH
		// every DSCP — the exact #3430 H2 bug. So a DSCP-0 match value is
		// DROPPED with a degraded build error (fail-safe under-steer), mirroring
		// the non-empty `except` handling in resolvePBRDirection. Within a
		// multi-value set (e.g. `from dscp [ be ef ]`) only the DSCP-0 value is
		// dropped; the representable values still emit exact rules.
		type tosEntry struct {
			tos uint8
			set bool
		}
		var toses []tosEntry
		hadDSCP := false
		for _, d := range term.DSCPs {
			if d == "" {
				continue
			}
			hadDSCP = true
			tos := dscpToTOS(d)
			if tos == 0 {
				errs = append(errs, fmt.Errorf(
					"PBR filter %s term %s matches DSCP 0 (%q), which an ip rule "+
						"cannot represent (the netlink layer has no FRA_DSCP and a zero "+
						"tos matches ANY DSCP); steering for this DSCP-0 match is dropped",
					filter.Name, term.Name, d))
				continue
			}
			toses = append(toses, tosEntry{tos: tos, set: true})
		}
		if hadDSCP {
			if len(toses) == 0 {
				// Every DSCP this term matched was DSCP-0 (all dropped above).
				// Emitting an address-only sentinel rule here would over-match
				// ALL DSCP, so skip the term entirely — the degraded error is
				// already recorded.
				continue
			}
		} else {
			// No DSCP constraint: a single unset entry so the address-only case
			// still emits one rule (no tos selector).
			toses = []tosEntry{{tos: 0, set: false}}
		}

		// Resolve source / destination scope, expanding prefix-lists and
		// normalizing any/bare-host tokens (#3430 M1, M2). A direction that
		// matches NOTHING (constrained-but-empty positive set) skips the whole
		// term; an unrepresentable except set degrades the build.
		srcs, srcSkip, srcErr := resolvePBRDirection(
			term.SourceAddresses, term.SourcePrefixLists, pls, filter.Name, term.Name, "source")
		dsts, dstSkip, dstErr := resolvePBRDirection(
			term.DestAddresses, term.DestPrefixLists, pls, filter.Name, term.Name, "destination")
		if srcErr != nil {
			errs = append(errs, srcErr)
		}
		if dstErr != nil {
			errs = append(errs, dstErr)
		}
		if srcErr != nil || dstErr != nil || srcSkip || dstSkip {
			// Either unrepresentable (already recorded) or matches nothing —
			// emit no rule for this term in both cases (fail-safe: never widen).
			continue
		}

		hasDSCP := false
		for _, t := range toses {
			if t.set {
				hasDSCP = true
				break
			}
		}
		srcConstrained := !(len(srcs) == 1 && srcs[0] == "")
		dstConstrained := !(len(dsts) == 1 && dsts[0] == "")
		// A protocol / source-port / destination-port constraint is now an
		// ip-rule-compatible criterion (#3730), so a term carrying only an L4
		// predicate is no longer a no-op under-steer — it emits an ip rule with
		// the L4 selector.
		hasL4 := len(protos) > 0 || len(sports) > 0 || len(dports) > 0
		if !hasDSCP && !srcConstrained && !dstConstrained && !hasL4 {
			// A truly unconstrained `then routing-instance` term (no dscp, no
			// address, no L4) would program `from all to all lookup <vr>`, which —
			// the mirror has no iif selector (H03) — steers ALL traffic globally.
			// Skip it (fail-safe under-steer), matching the pre-#3730 behavior.
			slog.Warn("PBR: filter term has routing-instance but no ip-rule-compatible criteria (dscp, address, protocol, port)",
				"filter", filter.Name, "term", term.Name)
			continue
		}

		// Normalize each L4 dimension to a single "unset" entry when the term did
		// not constrain it, so the cross-product still emits one rule per
		// dscp × src × dst combination (IPProto 0 / nil port = no selector).
		if len(protos) == 0 {
			protos = []int{0}
		}
		if len(sports) == 0 {
			sports = []*PBRPortRange{nil}
		}
		if len(dports) == 0 {
			dports = []*PBRPortRange{nil}
		}

		for _, t := range toses {
			for _, proto := range protos {
				for _, sp := range sports {
					for _, dp := range dports {
						for _, src := range srcs {
							for _, dst := range dsts {
								rules = append(rules, PBRRule{
									Family:   family,
									TOS:      t.tos,
									TOSSet:   t.set,
									IPProto:  proto,
									Sport:    sp,
									Dport:    dp,
									Src:      src,
									Dst:      dst,
									TableID:  tableID,
									Instance: term.RoutingInstance,
								})
							}
						}
					}
				}
			}
		}
	}
	return rules, errs
}

// pbrTermL4 classifies a routing-instance term's L4 / per-packet `from`
// predicates against what a kernel `ip rule` can express (#3730).
//
// It returns the REPRESENTABLE dimensions the caller folds into the ip-rule
// cross-product — protos (FRA_IP_PROTO values), sports and dports
// (FRA_SPORT_RANGE / FRA_DPORT_RANGE) — plus unrep, the list of predicates the
// term carries that an ip rule CANNOT represent. A non-empty unrep means the
// caller must FAIL CLOSED (drop the whole term + degrade); honoring the
// representable half while dropping the rest would widen the steer beyond what
// the operator authored (the #3730 over-steer). Unknown protocol names,
// protocol 0 (HOPOPT, which the netlink FRA_IP_PROTO>0 emit condition cannot
// express), and unparseable ports are also reported as unrep so they fail
// closed rather than silently narrowing/widening the match.
func pbrTermL4(term *config.FirewallFilterTerm) (protos []int, sports, dports []*PBRPortRange, unrep []string) {
	// Predicates an ip rule has no selector for at all.
	if hasRealString(term.SourcePortsExcept) {
		unrep = append(unrep, "source-port-except")
	}
	if hasRealString(term.DestPortsExcept) {
		unrep = append(unrep, "destination-port-except")
	}
	if len(term.TCPFlags) > 0 {
		unrep = append(unrep, "tcp-flags")
	}
	if term.IsFragment {
		unrep = append(unrep, "is-fragment")
	}
	if len(term.ICMPTypes) > 0 || len(term.UnknownICMPTypes) > 0 {
		unrep = append(unrep, "icmp-type")
	}
	if len(term.ICMPCodes) > 0 || len(term.UnknownICMPCodes) > 0 {
		unrep = append(unrep, "icmp-code")
	}
	if term.FlexMatch != nil || len(term.UnknownFlexMatch) > 0 {
		unrep = append(unrep, "flexible-match-range")
	}
	for _, f := range term.UnknownFrom {
		unrep = append(unrep, "unsupported from-match "+f)
	}

	// Representable: `from protocol` → one FRA_IP_PROTO value per protocol.
	for _, p := range term.Protocols {
		if strings.TrimSpace(p) == "" {
			continue
		}
		n, ok := appid.ProtocolNumber(p)
		if !ok || n == 0 {
			unrep = append(unrep, fmt.Sprintf("protocol %q", p))
			continue
		}
		protos = append(protos, int(n))
	}

	// Representable: `from source-port` / `from destination-port` → one
	// FRA_SPORT_RANGE / FRA_DPORT_RANGE per port spec (a range maps to [lo,hi]).
	for _, spec := range term.SourcePorts {
		if strings.TrimSpace(spec) == "" {
			continue
		}
		lo, hi, ok := config.ResolveFilterPortRange(spec)
		if !ok {
			unrep = append(unrep, fmt.Sprintf("source-port %q", spec))
			continue
		}
		sports = append(sports, &PBRPortRange{Lo: lo, Hi: hi})
	}
	for _, spec := range term.DestinationPorts {
		if strings.TrimSpace(spec) == "" {
			continue
		}
		lo, hi, ok := config.ResolveFilterPortRange(spec)
		if !ok {
			unrep = append(unrep, fmt.Sprintf("destination-port %q", spec))
			continue
		}
		dports = append(dports, &PBRPortRange{Lo: lo, Hi: hi})
	}
	return protos, sports, dports, unrep
}

// hasRealString reports whether the slice carries at least one non-empty
// (trimmed) entry — the "constrained" test for a firewall-filter match list.
func hasRealString(vals []string) bool {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// resolvePBRDirection resolves one direction (source or destination) of a
// firewall-filter term into the CIDR match strings for ip-rule generation,
// applying the same prefix-list + empty-set + except semantics as the
// userspace snapshot builder (resolvePrefixListAddrs) and then mapping them
// onto what an `ip rule from/to` selector can express (#3430 M1, M2).
//
// Returns:
//   - matches: the CIDRs to emit, one rule each. The single element "" means
//     "no selector" (match any).
//   - skip: the direction matches NOTHING (a constrained-but-empty positive
//     set, e.g. an empty / unresolved positive prefix-list). The caller emits
//     no rule for the term — omitting the rule is the correct realization of
//     "steer nothing" for FBF (an omitted rule cannot steer).
//   - err: the direction cannot be represented as an ip rule (a non-empty
//     address `except` set; ip rule has no negated from/to). The caller skips
//     the term (fail-safe: never steer the wrong traffic) and reports degraded.
func resolvePBRDirection(
	literal []string,
	refs []config.PrefixListRef,
	pls map[string]*config.PrefixList,
	filterName, termName, direction string,
) (matches []string, skip bool, err error) {
	constrained := len(literal) > 0 || len(refs) > 0
	if !constrained {
		return []string{""}, false, nil
	}

	var positive []string
	hasPositiveRef := false
	hasExcept := false
	exceptCount := 0
	unconstrainedSeen := false

	addNorm := func(tok string) error {
		cidr, unc, e := normalizePBRAddr(tok)
		if e != nil {
			return e
		}
		if unc {
			unconstrainedSeen = true
			return nil
		}
		positive = append(positive, cidr)
		return nil
	}

	for _, tok := range literal {
		if e := addNorm(tok); e != nil {
			return nil, false, fmt.Errorf("PBR %s address %q (filter %s term %s): %w",
				direction, tok, filterName, termName, e)
		}
	}
	for _, ref := range refs {
		pl := pls[ref.Name]
		if pl == nil {
			// Unresolved reference. The strict gate rejects this at commit; on
			// the tolerant/peer-sync path it contributes no prefixes, but the
			// direction stays constrained so we fail closed (positive) /
			// match-all (except) per the empty-set semantics below.
			slog.Warn("PBR: filter prefix-list reference unresolved",
				"filter", filterName, "term", termName, "direction", direction,
				"prefix-list", ref.Name)
			if ref.Except {
				hasExcept = true
			} else {
				hasPositiveRef = true
			}
			continue
		}
		if ref.Except {
			hasExcept = true
			exceptCount += len(pl.Prefixes)
		} else {
			hasPositiveRef = true
			for _, p := range pl.Prefixes {
				if e := addNorm(p); e != nil {
					slog.Warn("PBR: skipping unparseable prefix-list entry",
						"filter", filterName, "term", termName, "direction", direction,
						"prefix-list", ref.Name, "prefix", p, "err", e)
				}
			}
		}
	}

	// Pure-except: an `except` set is the SOLE scope for this direction.
	if hasExcept && len(positive) == 0 && !hasPositiveRef && !unconstrainedSeen {
		if exceptCount == 0 {
			// "match every source NOT in {}" = match ALL.
			return []string{""}, false, nil
		}
		// "match every source NOT in <set>" — ip rule has no negated selector.
		return nil, false, fmt.Errorf(
			"PBR %s scope of filter %s term %s uses a non-empty `except` prefix-list, "+
				"which an ip rule cannot represent (no negated from/to); steering for "+
				"this term is dropped — express the complement explicitly or use the "+
				"userspace filter path", direction, filterName, termName)
	}

	if hasExcept {
		// Mixed positive + except in one direction: commit-rejected
		// (validateFilterAddressExceptStrict, #3359); reaches here only on the
		// tolerant/peer-sync path. POSITIVE-WINS — ignore the except prefixes
		// (mirrors resolvePrefixListAddrs); fail-safe (never widen the steer).
		slog.Warn("PBR: filter term mixes positive addresses with an except "+
			"prefix-list in one direction; the except modifier is ignored "+
			"(positive-wins)",
			"filter", filterName, "term", termName, "direction", direction)
	}

	if unconstrainedSeen {
		// An `any` / 0.0.0.0/0 / ::/0 token widens the direction to match all.
		return []string{""}, false, nil
	}
	if len(positive) == 0 {
		// Constrained but resolved to no prefixes — matches nothing. For FBF
		// "steer nothing" is realized by emitting no rule (skip the term).
		return nil, true, nil
	}
	return positive, false, nil
}

// normalizePBRAddr maps a firewall-filter address token onto an ip-rule CIDR,
// mirroring the userspace filter compiler (#3430 M1):
//   - "any" (and 0.0.0.0/0 / ::/0) → unconstrained (no from/to selector).
//   - a bare host IP → /32 (IPv4) or /128 (IPv6).
//   - a literal CIDR → passed through unchanged.
//   - anything else → error (the caller fails closed instead of widening).
func normalizePBRAddr(tok string) (cidr string, unconstrained bool, err error) {
	t := strings.TrimSpace(tok)
	if t == "" || strings.EqualFold(t, "any") {
		return "", true, nil
	}
	if ip := net.ParseIP(t); ip != nil {
		if ip.To4() != nil {
			return ip.String() + "/32", false, nil
		}
		return ip.String() + "/128", false, nil
	}
	if _, n, e := net.ParseCIDR(t); e == nil {
		if ones, _ := n.Mask.Size(); ones == 0 {
			return "", true, nil // 0.0.0.0/0 or ::/0 — match all
		}
		return t, false, nil
	}
	return "", false, fmt.Errorf("unparseable address %q", tok)
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
//
// The boolean return distinguishes "resolved to a real table" (ok=true)
// from "unresolvable rib name" (ok=false) — a name that is neither
// inet.0/inet6.0 nor "<known-instance>.inet[6].0". Callers MUST treat
// ok=false as "unknown rib": never fall back to table 0 (#2226). Before
// this split the unresolvable case returned a bare 0, which the Apply
// needsLeak loop read as a real (non-source) table and spuriously
// installed an `ip rule from all lookup <sourceTable>` for a typo'd /
// non-existent import-rib — a silent mis-leak of the source table into
// the main lookup. Commit-time validation
// (validateRibGroupImportRibReferencesStrict) now also rejects the
// dangling reference; this guard is defense in depth for any reference
// that reaches apply via the tolerant load / peer-sync path.
func resolveRibTable(ribName string, tableIDs map[string]int) (int, bool) {
	if ribName == "inet.0" || ribName == "inet6.0" {
		return 254, true // main table
	}
	// Parse "<instance>.inet.0" or "<instance>.inet6.0" with an EXACT family
	// suffix — a loose ".inet" substring match would accept malformed names
	// like "<instance>.inetX.0" or "<instance>.inet.0.garbage" and resolve
	// them to the instance table (#2253). ribInstanceFromName returns the
	// instance only for the two valid unicast families.
	if instanceName, ok := ribInstanceFromName(ribName); ok {
		if tableID, ok := tableIDs[instanceName]; ok {
			return tableID, true
		}
	}
	return 0, false
}

// ribInstanceFromName extracts the routing-instance prefix from a non-default
// rib name of the EXACT form "<instance>.inet.0" or "<instance>.inet6.0",
// returning ok=false for any other shape. The instance prefix must be
// non-empty. Junos rib names are exactly "<table>.inet.0" (IPv4 unicast) or
// "<table>.inet6.0" (IPv6 unicast); bare "inet.0" / "inet6.0" (the main
// table) are handled by the caller and are NOT treated as instance ribs here.
// Malformed family tokens (".inetX.0", ".inetfoo.0", ".inet60.0") and trailing
// garbage (".inet.0.x") return ok=false so the caller rejects them rather than
// silently mapping a typo'd rib onto the instance table (#2253). This mirrors
// pkg/config.ribInstanceFromName — the two MUST stay in lockstep so the
// commit-time gate and the runtime applier agree on what resolves (#2226).
func ribInstanceFromName(ribName string) (string, bool) {
	for _, suffix := range []string{".inet.0", ".inet6.0"} {
		if instance, ok := strings.CutSuffix(ribName, suffix); ok && instance != "" {
			return instance, true
		}
	}
	return "", false
}
