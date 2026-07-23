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
	"fmt"
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
	// addPorts resolves one port-token list and appends its transport-port match.
	// An unrepresentable token FAILS the plan CLOSED (a.p.fail), exactly as the
	// nft oracle does: the oracle emits the raw token and `nft -f -` REJECTS it,
	// retaining the prior ruleset — so the netlink build must abort the install
	// rather than DROP the predicate and widen a port-constrained rule to
	// match-all (the #6405 fail-open).
	addPorts := func(a *ruleAsm, tokens []string, dir string, except bool) {
		ports, err := parsePortTokens(tokens)
		if err != nil {
			a.p.fail(fmt.Errorf("lo0 filter term %q %s (except=%t): %w", t.Name, dir, except, err))
			return
		}
		if len(ports) > 0 {
			a.thPort(dir, ports, except)
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
		addPorts(a, t.SourcePorts, "sport", false)
		addPorts(a, t.DestinationPorts, "dport", false)
		addPorts(a, t.SourcePortsExcept, "sport", true)
		addPorts(a, t.DestPortsExcept, "dport", true)
		if len(t.DSCPs) > 0 {
			// DSCP mirrors the port path: nftDSCPValue emits the raw token on an
			// unresolvable name (nft then rejects -> fail closed), so dropping the
			// predicate here would widen the match. Fail the plan closed instead.
			dscps, err := lo0DSCPs(t.DSCPs)
			if err != nil {
				a.p.fail(fmt.Errorf("lo0 filter term %q dscp: %w", t.Name, err))
			} else if len(dscps) > 0 {
				a.dscp(f, dscps)
			}
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
// via the shared dataplane.DSCPValues SSOT, or a bare numeric 0..63. An
// unresolvable token returns a non-nil error so the caller FAILS CLOSED — the
// oracle's nftDSCPValue emits the raw token, which `nft -f -` then rejects
// (prior ruleset retained), so silently dropping the predicate here would widen
// the match (a fail-open, the same class as the #6405 port bug).
func lo0DSCPs(tokens []string) ([]uint8, error) {
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
		return nil, fmt.Errorf("unrepresentable dscp token %q (fail closed to match the nft oracle, which rejects it)", tok)
	}
	return out, nil
}

// parsePortTokens resolves lo0 filter port tokens ("22", "ssh", "1024-2048")
// into numeric [lo,hi] ranges via config.ResolveFilterPortRange — the SAME SSOT
// the compile path and the kernel filter-based-forwarding mirror use, and the
// same numeric resolution nft applies to the raw token the oracle emits (a
// /etc/services-style name like `ssh` -> 22).
//
// A token that cannot be represented numerically (an unknown service name, a
// malformed range) returns a non-nil error so the caller FAILS CLOSED: the
// oracle emits the raw token and `nft -f -` REJECTS it, so the prior ruleset is
// retained. The netlink build MUST likewise abort the install rather than DROP
// the whole port predicate and widen a port-constrained rule to match ALL ports
// (the #6405 host-inbound fail-open). An empty token list yields no predicate.
func parsePortTokens(tokens []string) ([]nlPort, error) {
	if len(tokens) == 0 {
		return nil, nil
	}
	out := make([]nlPort, 0, len(tokens))
	for _, tok := range tokens {
		lo, hi, ok := config.ResolveFilterPortRange(strings.TrimSpace(tok))
		if !ok {
			return nil, fmt.Errorf("unrepresentable port token %q (fail closed to match the nft oracle, which rejects it)", tok)
		}
		out = append(out, nlPort{lo: lo, hi: hi})
	}
	return out, nil
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
