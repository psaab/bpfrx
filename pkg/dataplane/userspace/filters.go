package userspace

import (
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func buildFirewallFilterSnapshots(cfg *config.Config) []FirewallFilterSnapshot {
	if cfg == nil {
		return nil
	}
	var out []FirewallFilterSnapshot
	// inet filters
	inetNames := make([]string, 0, len(cfg.Firewall.FiltersInet))
	for name := range cfg.Firewall.FiltersInet {
		inetNames = append(inetNames, name)
	}
	sort.Strings(inetNames)
	for _, name := range inetNames {
		filter := cfg.Firewall.FiltersInet[name]
		if filter == nil {
			continue
		}
		snap := FirewallFilterSnapshot{
			Name:   name,
			Family: "inet",
			Terms:  buildFilterTermSnapshots(name, filter, cfg),
		}
		out = append(out, snap)
	}
	// inet6 filters
	inet6Names := make([]string, 0, len(cfg.Firewall.FiltersInet6))
	for name := range cfg.Firewall.FiltersInet6 {
		inet6Names = append(inet6Names, name)
	}
	sort.Strings(inet6Names)
	for _, name := range inet6Names {
		filter := cfg.Firewall.FiltersInet6[name]
		if filter == nil {
			continue
		}
		snap := FirewallFilterSnapshot{
			Name:   name,
			Family: "inet6",
			Terms:  buildFilterTermSnapshots(name, filter, cfg),
		}
		out = append(out, snap)
	}
	return out
}

func buildFilterTermSnapshots(filterName string, filter *config.FirewallFilter, cfg *config.Config) []FirewallTermSnapshot {
	// #2214: return a non-nil empty slice (never nil) so the enclosing
	// FirewallFilterSnapshot.Terms marshals as `[]`, never JSON `null`. The
	// Terms field has no `,omitempty` (the compiler can store a filter with
	// zero terms — see compileFirewall) and the Rust `Vec<FirewallTermSnapshot>`
	// rejects an explicit null, which aborts the whole snapshot decode and
	// kills ALL transit (#1961 no-transit signature).
	if filter == nil || len(filter.Terms) == 0 {
		return []FirewallTermSnapshot{}
	}
	terms := make([]FirewallTermSnapshot, 0, len(filter.Terms))
	for _, term := range filter.Terms {
		if term == nil {
			continue
		}
		snap := FirewallTermSnapshot{
			Name:            term.Name,
			Action:          term.Action,
			Count:           term.Count,
			Log:             term.Log,
			PolicerName:     term.Policer,
			RoutingInstance: term.RoutingInstance,
			ForwardingClass: term.ForwardingClass,
		}
		// Source / destination addresses: literal CIDRs PLUS the prefixes
		// resolved from any `from source-prefix-list` / `destination-prefix-list`
		// reference (#2506). The legacy eBPF compiler expanded these
		// (pkg/dataplane/compiler_filter.go); the userspace snapshot builder
		// dropped them entirely, so a term scoped by a prefix-list reached the
		// dataplane with NO address constraint (fail-open for accept/PBR,
		// fail-closed for discard/reject — either way wrong).
		srcAddrs, srcExcept := resolvePrefixListAddrs(
			term.SourceAddresses, term.SourcePrefixLists, cfg, filterName, term.Name, "source")
		dstAddrs, dstExcept := resolvePrefixListAddrs(
			term.DestAddresses, term.DestPrefixLists, cfg, filterName, term.Name, "destination")
		snap.SourceAddresses = srcAddrs
		snap.DestAddresses = dstAddrs
		snap.SourceExcept = srcExcept
		snap.DestExcept = dstExcept
		// Protocols
		if term.Protocol != "" {
			snap.Protocols = []string{term.Protocol}
		}
		// Source ports
		snap.SourcePorts = append(snap.SourcePorts, term.SourcePorts...)
		// Destination ports
		snap.DestPorts = append(snap.DestPorts, term.DestinationPorts...)
		// DSCP
		if term.DSCP != "" {
			if val, ok := dataplane.DSCPValues[strings.ToLower(term.DSCP)]; ok {
				snap.DSCPValues = []uint8{val}
			} else if v, err := strconv.Atoi(term.DSCP); err == nil && v >= 0 && v <= 63 {
				snap.DSCPValues = []uint8{uint8(v)}
			}
		}
		// DSCP rewrite
		if term.DSCPRewrite != "" {
			if val, ok := dataplane.DSCPValues[strings.ToLower(term.DSCPRewrite)]; ok {
				rewrite := val
				snap.DSCPRewrite = &rewrite
			} else if v, err := strconv.Atoi(term.DSCPRewrite); err == nil && v >= 0 && v <= 63 {
				rewrite := uint8(v)
				snap.DSCPRewrite = &rewrite
			}
		}
		// Per-packet L4 match conditions (#2362). Previously parsed but
		// dropped on the wire — wire them through so the dataplane matches
		// exactly what the operator authored.
		if mask, ok := tcpFlagsMask(term.TCPFlags); ok {
			m := mask
			snap.TCPFlags = &m
		}
		snap.IsFragment = term.IsFragment
		// The typed config uses -1 for "not set"; only serialize a valid
		// in-range byte. Junos icmp-type/icmp-code are 0..255.
		if term.ICMPType >= 0 && term.ICMPType <= 255 {
			t := uint8(term.ICMPType)
			snap.ICMPType = &t
		}
		if term.ICMPCode >= 0 && term.ICMPCode <= 255 {
			c := uint8(term.ICMPCode)
			snap.ICMPCode = &c
		}
		terms = append(terms, snap)
	}
	return terms
}

// resolvePrefixListAddrs merges a firewall-filter term's literal source/dest
// address CIDRs with the prefixes resolved from its source/destination
// prefix-list references (#2506). It returns the combined CIDR list and a
// per-direction `except` (inversion) flag.
//
// Semantics (Junos):
//   - A plain `source-prefix-list NAME` reference contributes NAME's prefixes
//     to the term's positive match set, OR'd with any literal source-address
//     entries — a packet matches the direction if its address falls in ANY of
//     them.
//   - `source-prefix-list NAME except` means "match every source EXCEPT those
//     in NAME". It is represented as the expanded prefixes plus `except=true`;
//     the Rust matcher evaluates `(addr ∈ prefixes) XOR except`.
//
// Scope (this PR): the two clean, common cases are wired through —
//  1. positive prefix-lists (with or without literal addresses), and
//  2. an `except` prefix-list as the SOLE address source for the direction.
//
// The MIXED case — literal/positive addresses AND an `except` prefix-list in
// the SAME direction of ONE term — has no single boolean-inversion
// representation (one direction would need both a positive set and a negated
// set). Rather than silently pick a wrong interpretation, the except modifier
// is dropped (the prefixes fold into the positive set, i.e. the under-broad,
// fail-safe reading) and a warning is emitted. The structured mixed case is a
// documented follow-up.
//
// An undefined prefix-list reference is NOT silently dropped here — it is a
// strict commit-time error (validateFirewallPrefixListReferencesStrict, #1960
// strict/lenient pattern). On the tolerant load / peer-sync path that gate
// downgrades to a warning and an unresolved reference contributes no prefixes
// (so a constrained term fails closed in the matcher rather than matching all).
func resolvePrefixListAddrs(
	literal []string,
	refs []config.PrefixListRef,
	cfg *config.Config,
	filterName, termName, direction string,
) ([]string, bool) {
	if len(refs) == 0 {
		// No prefix-lists: copy the literal addresses verbatim (never share the
		// term's backing slice).
		if len(literal) == 0 {
			return nil, false
		}
		out := make([]string, len(literal))
		copy(out, literal)
		return out, false
	}

	var positive []string
	positive = append(positive, literal...)
	var exceptPrefixes []string
	hasExcept := false
	hasPositiveRef := false

	for _, ref := range refs {
		pl := cfg.PolicyOptions.PrefixLists[ref.Name]
		if pl == nil {
			// Undefined reference. The strict gate rejects this at commit; on
			// the tolerant path it is a warning and we simply contribute no
			// prefixes for it.
			slog.Warn("firewall filter prefix-list reference unresolved",
				"filter", filterName, "term", termName, "direction", direction,
				"prefix-list", ref.Name)
			continue
		}
		if ref.Except {
			hasExcept = true
			exceptPrefixes = append(exceptPrefixes, pl.Prefixes...)
		} else {
			hasPositiveRef = true
			positive = append(positive, pl.Prefixes...)
		}
	}

	// Clean except case: an `except` prefix-list is the sole address source for
	// this direction (no literal addresses, no positive prefix-lists).
	if hasExcept && len(positive) == 0 && !hasPositiveRef {
		return exceptPrefixes, true
	}

	if hasExcept {
		// Mixed positive + except in one direction — out of scope for the
		// boolean-inversion model. Fold the except prefixes into the positive
		// set (under-broad, fail-safe) and warn so the operator can split the
		// term. Documented follow-up.
		slog.Warn("firewall filter term mixes literal/positive addresses with an "+
			"except prefix-list in one direction; the except modifier is ignored "+
			"(prefixes treated as a positive match). Split into separate terms.",
			"filter", filterName, "term", termName, "direction", direction)
		positive = append(positive, exceptPrefixes...)
	}

	if len(positive) == 0 {
		return nil, false
	}
	return positive, false
}

// tcpFlagsBits maps Junos TCP-flag names to their bit value in the TCP flags
// byte. Junos also accepts aliases (e.g. `syn`, `ack`); only the literal flag
// names the firewall-filter compiler emits as a flat list are supported here —
// the parser does not produce the richer `(syn & !ack)` expression grammar, so
// no negation/disjunction is representable (a parser limitation, tracked
// separately). Bit order matches userspace-dp/src/tcp_flags.rs.
var tcpFlagsBits = map[string]uint8{
	"fin": 0x01,
	"syn": 0x02,
	"rst": 0x04,
	"psh": 0x08,
	"ack": 0x10,
	"urg": 0x20,
}

// tcpFlagsMask folds a parsed flag-name list into a required-bits mask. A TCP
// packet matches the term when (flags & mask) == mask (all listed flags set).
// Returns ok=false when the list is empty or contains no recognized flag name,
// so the wire field stays nil (no tcp-flags constraint) rather than a 0 mask
// that would match every packet.
func tcpFlagsMask(flags []string) (uint8, bool) {
	var mask uint8
	matched := false
	for _, f := range flags {
		if bit, ok := tcpFlagsBits[strings.ToLower(strings.TrimSpace(f))]; ok {
			mask |= bit
			matched = true
		}
	}
	if !matched {
		return 0, false
	}
	return mask, true
}

func buildPolicerSnapshots(cfg *config.Config) []PolicerSnapshot {
	if cfg == nil || len(cfg.Firewall.Policers) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Firewall.Policers))
	for name := range cfg.Firewall.Policers {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]PolicerSnapshot, 0, len(names))
	for _, name := range names {
		pol := cfg.Firewall.Policers[name]
		if pol == nil {
			continue
		}
		snap := PolicerSnapshot{
			Name:         name,
			BandwidthBps: pol.BandwidthLimit,
			BurstBytes:   pol.BurstSizeLimit,
		}
		if pol.ThenAction == "discard" {
			snap.DiscardExcess = true
		}
		out = append(out, snap)
	}
	return out
}

func buildThreeColorPolicerSnapshots(cfg *config.Config) []ThreeColorPolicerSnapshot {
	if cfg == nil || len(cfg.Firewall.ThreeColorPolicers) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Firewall.ThreeColorPolicers))
	for name := range cfg.Firewall.ThreeColorPolicers {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]ThreeColorPolicerSnapshot, 0, len(names))
	for _, name := range names {
		pol := cfg.Firewall.ThreeColorPolicers[name]
		if pol == nil {
			continue
		}
		mode := "single-rate"
		peakOrExcessRate := uint64(0)
		if pol.TwoRate {
			mode = "two-rate"
			peakOrExcessRate = pol.PIR
		}
		out = append(out, ThreeColorPolicerSnapshot{
			Name:                   name,
			Mode:                   mode,
			ColorBlind:             pol.ColorBlind,
			CommittedRateBytes:     pol.CIR,
			CommittedBurstBytes:    pol.CBS,
			PeakOrExcessRateBytes:  peakOrExcessRate,
			PeakOrExcessBurstBytes: pol.PBS,
			ThenAction:             pol.ThenAction,
		})
	}
	return out
}
