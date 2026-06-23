package userspace

import (
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
			Terms:  buildFilterTermSnapshots(filter, cfg),
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
			Terms:  buildFilterTermSnapshots(filter, cfg),
		}
		out = append(out, snap)
	}
	return out
}

func buildFilterTermSnapshots(filter *config.FirewallFilter, cfg *config.Config) []FirewallTermSnapshot {
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
		// Source addresses (CIDRs)
		snap.SourceAddresses = append(snap.SourceAddresses, term.SourceAddresses...)
		// Destination addresses (CIDRs)
		snap.DestAddresses = append(snap.DestAddresses, term.DestAddresses...)
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
