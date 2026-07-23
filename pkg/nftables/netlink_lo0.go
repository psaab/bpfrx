package nftables

// netlink_lo0.go builds the `inet xpf_lo0` loopback input-filter chain via
// netlink, mirroring buildLo0FilterPayload / nftRulesFromTerm in
// pkg/daemon/daemon_nft.go (the parity ORACLE). Source/destination scopes arrive
// pre-resolved (prefix-lists already expanded by the daemon converter); this
// builder re-applies the family-filter / empty-set / match-nothing semantics
// (mirroring nftFamilyAddrs / nftAddrPredicate) and the term disposition
// (fall-through, reject pair, tcp-flags fail-closed, verdict mapping) that
// nftRulesFromTerm encodes, so a term lowers to the SAME 0/1/2 kernel rules.

import (
	"log/slog"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/nftables/expr"
	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// buildLo0FilterNetlink queues the lo0 filter table (counters + chain + rules)
// into the plan, mirroring buildLo0FilterPayload. The caller has created the
// table + `input` chain (priority nftLo0FilterPriority, policy accept).
func buildLo0FilterNetlink(p *nlPlan, spec Lo0FilterSpec) {
	seen := map[string]bool{}
	declareCounters := func(terms []Lo0FilterTerm) {
		for _, t := range terms {
			if t.Count == "" {
				continue
			}
			cn := Lo0CounterName(t.Count)
			if !seen[cn] {
				seen[cn] = true
				p.counterObj(cn)
			}
		}
	}
	declareCounters(spec.V4Terms)
	declareCounters(spec.V6Terms)

	for _, t := range spec.V4Terms {
		buildLo0TermNetlink(p, t, famV4)
	}
	for _, t := range spec.V6Terms {
		buildLo0TermNetlink(p, t, famV6)
	}
}

// buildLo0TermNetlink lowers one filter term to 0, 1, or 2 kernel rules,
// mirroring nftRulesFromTerm.
func buildLo0TermNetlink(p *nlPlan, t Lo0FilterTerm, f nlFamily) {
	// Resolve the address predicates first: a positive scope that resolves to no
	// prefix of this family is a Junos match-nothing term (skip entirely).
	srcAddrs, srcSkip := lo0AddrScope(f, t.SrcAddrs, t.SrcExcept, t.SrcConstrained)
	if srcSkip {
		return
	}
	dstAddrs, dstSkip := lo0AddrScope(f, t.DstAddrs, t.DstExcept, t.DstConstrained)
	if dstSkip {
		return
	}

	// applyMatches appends every match predicate (in oracle order) to a rule
	// assembler; it does NOT append the tcp-flags predicate when fail-closed.
	tcpFailClosed := false
	if len(t.TCPFlags) > 0 {
		if _, _, _, err := config.ParseTCPFlagsExpression(t.TCPFlags); err != nil {
			slog.Warn("lo0 netlink mirror: unrepresentable tcp-flags expression, failing term CLOSED (drop) to match userspace",
				"term", t.Name, "tcp_flags", strings.Join(t.TCPFlags, " "), "error", err)
			tcpFailClosed = true
		}
	}
	applyMatches := func(a *ruleAsm) {
		if len(srcAddrs) > 0 {
			a.saddr(f, srcAddrs, t.SrcExcept)
		}
		if len(dstAddrs) > 0 {
			a.daddr(f, dstAddrs, t.DstExcept)
		}
		if protos := lo0Protocols(t.Protocols); len(protos) > 0 {
			a.l4protoSet(protos)
		}
		if ports, ok := parsePortTokens(t.SourcePorts); ok && len(ports) > 0 {
			a.thPort("sport", ports, false)
		}
		if ports, ok := parsePortTokens(t.DestinationPorts); ok && len(ports) > 0 {
			a.thPort("dport", ports, false)
		}
		if ports, ok := parsePortTokens(t.SourcePortsExcept); ok && len(ports) > 0 {
			a.thPort("sport", ports, true)
		}
		if ports, ok := parsePortTokens(t.DestPortsExcept); ok && len(ports) > 0 {
			a.thPort("dport", ports, true)
		}
		if dscps := lo0DSCPs(t.DSCPs); len(dscps) > 0 {
			a.dscp(f, dscps)
		}
		if len(t.ICMPTypes) > 0 {
			a.icmpType(f, intsToU8(t.ICMPTypes))
		}
		if len(t.ICMPCodes) > 0 {
			a.icmpCode(f, intsToU8(t.ICMPCodes))
		}
		if !tcpFailClosed && len(t.TCPFlags) > 0 {
			if required, forbidden, ok, _ := config.ParseTCPFlagsExpression(t.TCPFlags); ok {
				a.tcpFlags(required, forbidden)
			}
		}
		if t.IsFragment {
			if f.v6 {
				a.exthdrFragV6()
			} else {
				a.fragV4()
			}
		}
	}
	applyMods := func(a *ruleAsm) {
		if t.Log {
			a.logPrefix(nftLo0LogPrefix(t.Name))
		}
		if t.Count != "" {
			a.counterRef(Lo0CounterName(t.Count))
		}
	}

	// #5512: fail-closed override for an unrepresentable tcp-flags expression —
	// a TCP-scoped drop instead of the term's widened verdict.
	if tcpFailClosed {
		a := p.rule()
		applyMatches(a)
		a.needL4proto(protoTCP) // literal `meta l4proto 6` guard
		applyMods(a)
		a.emit(verdictDrop()...)
		return
	}

	// Fall-through (#3427): a term with no terminating action applies its honored
	// modifiers and continues. Emit a non-terminating rule (no verdict) only when
	// there is a modifier to honor; otherwise emit no rule.
	if (t.NextTerm || t.Action == "") && t.RoutingInstance == "" {
		if !t.Log && t.Count == "" {
			return
		}
		a := p.rule()
		applyMatches(a)
		applyMods(a)
		a.emit()
		return
	}

	// reject (#3445 H10): a TCP RST plus a family-agnostic ICMP/ICMPv6
	// admin-prohibited reply — two mutually-exclusive rules.
	if t.Action == "reject" {
		a1 := p.rule()
		applyMatches(a1)
		a1.needL4proto(protoTCP)
		applyMods(a1)
		a1.emit(rejectTCPReset()...)

		a2 := p.rule()
		applyMatches(a2)
		applyMods(a2)
		a2.emit(rejectICMPXAdminProhibited()...)
		return
	}

	// Terminating verdict (mirrors the Rust compiler's action mapping).
	var verdict []expr.Any
	switch t.Action {
	case "discard":
		verdict = verdictDrop()
	case "accept", "":
		verdict = verdictAccept()
	default:
		slog.Warn("lo0 netlink mirror: unknown terminating action, failing closed to drop",
			"term", t.Name, "action", t.Action)
		verdict = verdictDrop()
	}
	a := p.rule()
	applyMatches(a)
	applyMods(a)
	a.emit(verdict...)
}

// lo0AddrScope mirrors nftFamilyAddrs + nftAddrPredicate's family-filter and
// match-nothing decision. It returns the family-filtered address list to feed
// the address match, and skip==true when the term matches nothing (a positive
// scope constrained to no prefix of this family) — the caller drops the rule.
func lo0AddrScope(f nlFamily, addrs []string, except, constrained bool) (out []string, skip bool) {
	if !constrained {
		return nil, false
	}
	fam := filterFamilyAddrs(f, addrs)
	if len(fam) == 0 {
		if except {
			// Empty except set -> match ALL -> no predicate.
			return nil, false
		}
		// Empty positive set -> match NOTHING -> skip the rule.
		return nil, true
	}
	return fam, false
}

// filterFamilyAddrs mirrors nftFamilyAddrs: keep only this family's literals,
// dropping empty/"any"/malformed and wrong-family tokens, canonicalizing each.
func filterFamilyAddrs(f nlFamily, addrs []string) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a == "" || a == "any" {
			continue
		}
		if pfx, err := netip.ParsePrefix(a); err == nil {
			if pfx.Addr().Is6() == f.v6 {
				out = append(out, pfx.String())
			}
			continue
		}
		if ip, err := netip.ParseAddr(a); err == nil {
			if ip.Is6() == f.v6 {
				out = append(out, ip.String())
			}
			continue
		}
	}
	return out
}

// lo0Protocols mirrors the #3436 numeric protocol lowering: resolve each Junos
// protocol token through appid.ProtocolNumber, dropping unresolvable tokens.
func lo0Protocols(tokens []string) []uint8 {
	out := make([]uint8, 0, len(tokens))
	for _, tok := range tokens {
		if n, ok := appid.ProtocolNumber(tok); ok {
			out = append(out, n)
		} else {
			slog.Warn("dropping unresolvable protocol from lo0 netlink term", "protocol", tok)
		}
	}
	return out
}

// lo0DSCPs mirrors nftDSCPValue: resolve each DSCP token to a numeric codepoint
// via the shared dataplane.DSCPValues SSOT, or a bare numeric 0..63.
func lo0DSCPs(tokens []string) []uint8 {
	out := make([]uint8, 0, len(tokens))
	for _, tok := range tokens {
		key := strings.ToLower(strings.TrimSpace(tok))
		if v, ok := dataplane.DSCPValues[key]; ok {
			out = append(out, v)
			continue
		}
		if v, err := strconv.Atoi(key); err == nil && v >= 0 && v <= 63 {
			out = append(out, uint8(v))
			continue
		}
		slog.Warn("dropping unresolvable dscp from lo0 netlink term", "dscp", tok)
	}
	return out
}

// parsePortTokens parses lo0 filter port strings ("22", "1024-2048") into
// nlPort. ok is false if any token is unparseable (mirrors the oracle emitting
// the raw token; the netlink path cannot render a named port, so it drops the
// whole port predicate rather than a partial one).
func parsePortTokens(tokens []string) ([]nlPort, bool) {
	if len(tokens) == 0 {
		return nil, true
	}
	out := make([]nlPort, 0, len(tokens))
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if lo, hi, ok := strings.Cut(tok, "-"); ok {
			l, err1 := strconv.Atoi(lo)
			h, err2 := strconv.Atoi(hi)
			if err1 != nil || err2 != nil || l < 0 || h > 0xffff || l > h {
				slog.Warn("dropping unparseable lo0 port range", "token", tok)
				return nil, false
			}
			out = append(out, nlPort{lo: uint16(l), hi: uint16(h)})
			continue
		}
		v, err := strconv.Atoi(tok)
		if err != nil || v < 0 || v > 0xffff {
			slog.Warn("dropping unparseable lo0 port", "token", tok)
			return nil, false
		}
		out = append(out, nlPort{lo: uint16(v), hi: uint16(v)})
	}
	return out, true
}

// nftLo0LogPrefix mirrors nftLo0LogPrefix in the oracle: `xpf-lo0 <term>: `,
// quote/backslash stripped, bounded to 64 bytes.
func nftLo0LogPrefix(term string) string {
	const maxLen = 64
	safe := strings.NewReplacer(`"`, "", `\`, "").Replace(term)
	p := "xpf-lo0 " + safe + ": "
	if len(p) > maxLen {
		p = p[:maxLen]
	}
	return p
}

func intsToU8(vals []int) []uint8 {
	out := make([]uint8, 0, len(vals))
	for _, v := range vals {
		out = append(out, uint8(v))
	}
	return out
}
