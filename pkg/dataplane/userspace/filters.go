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
			// #2544: fall-through. A term whose `then` carries NO terminating
			// action must apply its modifiers and FALL THROUGH to the next term
			// (Junos). This covers BOTH the explicit `then next term`
			// (term.NextTerm set by compileFilterThen) AND a modifier-only term
			// (Action=="" with only count/log/forwarding-class/policer/dscp).
			// Junos treats a modifier-only term as an implicit fall-through, so
			// the signal is uniformly "no terminating action" == fall-through.
			// A routing-instance (PBR) term is terminating-wise its own decision
			// and is NOT a fall-through even with an empty Action — leave it.
			NextTerm: (term.NextTerm || term.Action == "") && term.RoutingInstance == "",
		}
		// Source / destination addresses: literal CIDRs PLUS the prefixes
		// resolved from any `from source-prefix-list` / `destination-prefix-list`
		// reference (#2506). The legacy eBPF compiler expanded these
		// (pkg/dataplane/compiler_filter.go); the userspace snapshot builder
		// dropped them entirely, so a term scoped by a prefix-list reached the
		// dataplane with NO address constraint (fail-open for accept/PBR,
		// fail-closed for discard/reject — either way wrong).
		srcAddrs, srcExcept, srcConstrained := resolvePrefixListAddrs(
			term.SourceAddresses, term.SourcePrefixLists, cfg, filterName, term.Name, "source")
		dstAddrs, dstExcept, dstConstrained := resolvePrefixListAddrs(
			term.DestAddresses, term.DestPrefixLists, cfg, filterName, term.Name, "destination")
		snap.SourceAddresses = srcAddrs
		snap.DestAddresses = dstAddrs
		snap.SourceExcept = srcExcept
		snap.DestExcept = dstExcept
		snap.SourceConstrained = srcConstrained
		snap.DestConstrained = dstConstrained
		// Protocols (#2545: a term may carry several `from protocol` values;
		// emit ALL of them into the wire vector — the Rust matcher does set
		// membership).
		for _, p := range term.Protocols {
			if p != "" {
				snap.Protocols = append(snap.Protocols, p)
			}
		}
		// Source ports
		snap.SourcePorts = append(snap.SourcePorts, term.SourcePorts...)
		// Destination ports
		snap.DestPorts = append(snap.DestPorts, term.DestinationPorts...)
		// Negated port sets (#2622): match all ports EXCEPT these. Emitted as
		// separate wire fields; the Rust matcher inverts membership.
		snap.SourcePortsExcept = append(snap.SourcePortsExcept, term.SourcePortsExcept...)
		snap.DestPortsExcept = append(snap.DestPortsExcept, term.DestPortsExcept...)
		// DSCP (#2545: multi-value — emit every resolved code point).
		for _, d := range term.DSCPs {
			if d == "" {
				continue
			}
			if val, ok := dataplane.DSCPValues[strings.ToLower(d)]; ok {
				snap.DSCPValues = append(snap.DSCPValues, val)
			} else if v, err := strconv.Atoi(d); err == nil && v >= 0 && v <= 63 {
				snap.DSCPValues = append(snap.DSCPValues, uint8(v))
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
		// #3076: parse the full Junos tcp-flags expression (`syn & !ack`,
		// `(syn & !ack)`, plain lists) into a required-bits mask AND a
		// forbidden-bits mask. A TCP segment matches when
		// (flags & required) == required && (flags & forbidden) == 0.
		// Unrepresentable expressions (disjunction, negated groups, unknown
		// flags) are rejected at commit by compileFirewall, so a parse error
		// here is unreachable for a committed config; if one slips through
		// (e.g. a hand-built snapshot) log it and leave the masks nil rather
		// than emit a 0 mask that would match every packet (the pre-#3076
		// fail-open).
		if required, forbidden, ok, err := config.ParseTCPFlagsExpression(term.TCPFlags); err != nil {
			slog.Warn("dropping unparseable tcp-flags expression from filter term",
				"filter", filterName, "term", term.Name, "tcp_flags", term.TCPFlags, "error", err)
		} else if ok {
			if required != 0 {
				r := required
				snap.TCPFlags = &r
			}
			if forbidden != 0 {
				f := forbidden
				snap.TCPFlagsForbidden = &f
			}
		}
		snap.IsFragment = term.IsFragment
		// icmp-type / icmp-code are multi-value (#2545): emit every in-range
		// byte into the wire vector. Junos icmp-type/icmp-code are 0..255; an
		// empty vector means the criterion is unconstrained. The Rust matcher
		// does set membership (match-ANY within the field).
		for _, t := range term.ICMPTypes {
			if t >= 0 && t <= 255 {
				snap.ICMPTypes = append(snap.ICMPTypes, uint8(t))
			}
		}
		for _, c := range term.ICMPCodes {
			if c >= 0 && c <= 255 {
				snap.ICMPCodes = append(snap.ICMPCodes, uint8(c))
			}
		}
		// Flexible-match-range (#3077). Previously parsed + compiled for the
		// retired legacy dataplane (pkg/dataplane/compiler_filter.go) but
		// silently dropped here, so the byte-offset constraint never reached the
		// sole runtime dataplane and the term matched too broadly (fail-open).
		// Mirror the legacy lowering: FlexLength is the match width in BYTES
		// (BitLength/8, defaulted to 4 == 32-bit when unset, capped at 4 since
		// the wire value is a u32), and the compared value is pre-masked. The
		// byte offset is L3-relative (match-start layer-3, the only start point
		// the compiler emits). A zero effective length is dropped (no
		// constraint) rather than emitted as a degenerate always-fail match.
		if fm := term.FlexMatch; fm != nil {
			// #3203: round UP to whole bytes so a non-multiple-of-8 bit length
			// (e.g. 12 bits -> 2 bytes) reads enough bytes to cover the field.
			// Integer truncation (BitLength/8) gave 1 byte for 12 bits, dropping
			// the partial trailing byte so the match always failed closed. The
			// Go compiler's default mask zeroes the extra bits within the ceil
			// byte, so the matcher's (read & mask) == value comparison stays
			// correct for a sub-byte field.
			length := (int(fm.BitLength) + 7) / 8
			if length == 0 {
				length = 4 // default 32-bit, matching compiler_filter.go
			}
			if length > 4 {
				length = 4 // the wire value is a u32; cap defensively
			}
			// #3232: carry the match-start base. layer-3 (default) maps to ""
			// so the wire stays byte-identical for every pre-#3232 term
			// (omitempty); only an explicit layer-4 emits a value. The compiler
			// has already rejected payload/unknown at commit, so MatchStart is
			// only ever "layer-3" or "layer-4" here.
			matchStart := ""
			if fm.MatchStart == "layer-4" {
				matchStart = "layer-4"
			}
			snap.FlexMatch = &FlexMatchSnapshot{
				Offset:     fm.ByteOffset,
				Length:     uint8(length),
				Value:      fm.Value & fm.Mask,
				Mask:       fm.Mask,
				MatchStart: matchStart,
			}
		}
		terms = append(terms, snap)
	}
	return terms
}

// resolvePrefixListAddrs merges a firewall-filter term's literal source/dest
// address CIDRs with the prefixes resolved from its source/destination
// prefix-list references (#2506). It returns the combined CIDR list, a
// per-direction `except` (inversion) flag, and a `constrained` flag.
//
// `constrained` is TRUE whenever the term SPECIFIED any scope for this
// direction — at least one literal address OR at least one prefix-list
// reference — INDEPENDENT of whether resolution yielded any prefixes. This is
// the load-bearing signal for the empty-resolution case (Copilot, this PR): a
// `source-prefix-list X` whose X is defined-but-empty (passes the strict gate)
// OR unresolved on the lenient/peer-sync path resolves to ZERO prefixes. If the
// matcher derived "constrained" from the list length alone, an empty list would
// collapse to match-ANY and silently drop the operator's scope (fail-open for
// `accept`/PBR, wrong scope for `discard`). Carrying `constrained` explicitly
// lets the matcher distinguish "no scope specified -> match any" from "scope
// specified but resolved empty -> match per Junos empty-set semantics".
//
// Semantics (Junos), realized in the Rust matcher (nets_match_v4/v6):
//   - A plain `source-prefix-list NAME` reference contributes NAME's prefixes
//     to the term's positive match set, OR'd with any literal source-address
//     entries — a packet matches the direction if its address falls in ANY of
//     them. NAME empty -> "match sources in {}" = match NOTHING (fail-closed).
//   - `source-prefix-list NAME except` means "match every source EXCEPT those
//     in NAME". Represented as the expanded prefixes plus `except=true`; the
//     matcher evaluates `(addr ∈ prefixes) XOR except`. NAME empty -> "match
//     sources NOT in {}" = match ALL.
//
// Scope (this PR): the two clean, common cases are wired through —
//  1. positive prefix-lists (with or without literal addresses), and
//  2. an `except` prefix-list as the SOLE address source for the direction.
//
// The MIXED case — literal/positive addresses AND an `except` prefix-list in
// the SAME direction of ONE term — has no single boolean-inversion
// representation (one direction would need both a positive set and a negated
// set). Rather than silently pick a wrong interpretation, the except modifier
// is dropped (the prefixes fold into the positive set) and a warning is
// emitted. This fold is ACTION-DEPENDENT in safety: it under-broadens the match
// (the listed prefixes are matched positively instead of excluded), which is
// fail-safe for `accept`/permit terms but fail-OPEN for a `discard`/`reject`
// term (traffic the operator meant to drop via `except` is no longer dropped).
// The structured mixed case is a documented follow-up.
//
// An undefined prefix-list reference is NOT silently dropped here — it is a
// strict commit-time error (validateFirewallPrefixListReferencesStrict, #1960
// strict/lenient pattern). On the tolerant load / peer-sync path that gate
// downgrades to a warning and an unresolved reference contributes no prefixes;
// because the reference still makes the direction `constrained`, the matcher
// fails closed (positive) / match-all (except) per the empty-set semantics
// above rather than collapsing to match-any.
func resolvePrefixListAddrs(
	literal []string,
	refs []config.PrefixListRef,
	cfg *config.Config,
	filterName, termName, direction string,
) (addrs []string, except bool, constrained bool) {
	// The direction is constrained iff the operator wrote ANY scope for it —
	// literal addresses or prefix-list references — regardless of resolution.
	constrained = len(literal) > 0 || len(refs) > 0

	if len(refs) == 0 {
		// No prefix-lists: copy the literal addresses verbatim (never share the
		// term's backing slice).
		if len(literal) == 0 {
			return nil, false, false
		}
		out := make([]string, len(literal))
		copy(out, literal)
		return out, false, true
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
			// the tolerant path it is a warning and we contribute no prefixes
			// for it — but the direction stays `constrained` (set above), so the
			// matcher fails closed rather than matching any.
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
	// this direction (no literal addresses, no positive prefix-lists). Note this
	// holds even when the except list resolved EMPTY — the direction is
	// constrained and except is set, so the matcher's empty guard returns
	// `except` (= match ALL), the Junos "not in {}" semantic.
	if hasExcept && len(positive) == 0 && !hasPositiveRef {
		return exceptPrefixes, true, true
	}

	if hasExcept {
		// Mixed positive + except in one direction — out of scope for the
		// boolean-inversion model. Fold the except prefixes into the positive
		// set and warn so the operator can split the term. Documented
		// follow-up. (Action-dependent safety — see the doc comment above.)
		slog.Warn("firewall filter term mixes literal/positive addresses with an "+
			"except prefix-list in one direction; the except modifier is ignored "+
			"(prefixes treated as a positive match). Split into separate terms.",
			"filter", filterName, "term", termName, "direction", direction)
		positive = append(positive, exceptPrefixes...)
	}

	// `positive` may be empty here (e.g. a positive prefix-list that resolved to
	// no prefixes, or an unresolved positive ref). The direction is still
	// constrained, so the matcher fails closed (matches nothing) rather than
	// matching any.
	return positive, false, true
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
