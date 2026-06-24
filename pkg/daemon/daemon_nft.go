// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// applyLo0Filter applies loopback filter rules for host-bound traffic.
// Implements "interfaces lo0 unit 0 family inet filter input <name>" by
// generating nftables rules from the named firewall filter.
func (d *Daemon) applyLo0Filter(cfg *config.Config) {
	filterV4 := cfg.System.Lo0FilterInputV4
	filterV6 := cfg.System.Lo0FilterInputV6
	if filterV4 == "" && filterV6 == "" {
		// No lo0 filter configured — clean up any stale nftables rules.
		// The error stays discarded: delete fails normally when the
		// table doesn't exist (the common case). Timeout-bounded so a
		// wedged nft cannot stall the apply path (#1794).
		_, _ = runCommandTimeout("nft", "delete", "table", "inet", "xpf_lo0")
		return
	}

	nftConf := buildLo0FilterPayload(cfg, filterV4, filterV6)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	// WaitDelay caps the post-SIGKILL pipe-drain window (#1794).
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdin = strings.NewReader(nftConf)
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("failed to apply lo0 filter", "err", err, "output", string(out))
	} else {
		slog.Info("lo0 filter applied", "v4", filterV4, "v6", filterV6)
	}
}

// buildLo0FilterPayload assembles the exact nft ruleset payload that
// applyLo0Filter feeds to `nft -f -`. It is split out as a pure function so
// tests can capture and parse-check the full payload (#2069) without invoking
// nft or the daemon apply path. Callers pass the already-resolved v4/v6 filter
// names so the payload reflects exactly what applyLo0Filter would send.
//
// The leading three lines are the atomic flush idiom: create the table if it
// does not yet exist (`table inet xpf_lo0` with no body — idempotent), flush
// its contents, then redefine it. nft parses an `-f -` payload atomically, so
// a syntax error on any line rejects the ENTIRE payload. The pre-#2069
// `flush ruleset inet xpf_lo0` was NOT valid nft — `flush ruleset` takes at
// most an OPTIONAL family (`flush ruleset [<family>]`), never a table name, so
// the trailing table token was a parse error that rejected the whole ruleset
// (incl. the real filter rules) and made the lo0 filter fail OPEN.
func buildLo0FilterPayload(cfg *config.Config, filterV4, filterV6 string) string {
	var rules []string
	rules = append(rules, "table inet xpf_lo0")
	rules = append(rules, "flush table inet xpf_lo0")
	rules = append(rules, "table inet xpf_lo0 {")
	rules = append(rules, "  chain input {")
	rules = append(rules, "    type filter hook input priority 0; policy accept;")

	prefixLists := cfg.PolicyOptions.PrefixLists
	if filterV4 != "" {
		if f, ok := cfg.Firewall.FiltersInet[filterV4]; ok {
			for _, term := range f.Terms {
				r := nftRuleFromTerm(term, "ip", prefixLists)
				if r != "" {
					rules = append(rules, "    "+r)
				}
			}
		}
	}
	if filterV6 != "" {
		if f, ok := cfg.Firewall.FiltersInet6[filterV6]; ok {
			for _, term := range f.Terms {
				r := nftRuleFromTerm(term, "ip6", prefixLists)
				if r != "" {
					rules = append(rules, "    "+r)
				}
			}
		}
	}
	rules = append(rules, "  }")
	rules = append(rules, "}")

	return strings.Join(rules, "\n") + "\n"
}

// nftRuleFromTerm converts a firewall filter term to an nftables rule string.
// prefixLists is used to expand source-prefix-list and destination-prefix-list references.
func nftRuleFromTerm(term *config.FirewallFilterTerm, family string, prefixLists map[string]*config.PrefixList) string {
	var parts []string

	// Collect all source CIDRs (direct addresses + expanded prefix-lists)
	var srcCIDRs []string
	srcCIDRs = append(srcCIDRs, term.SourceAddresses...)
	var srcNegate bool
	for _, pl := range term.SourcePrefixLists {
		if resolved, ok := prefixLists[pl.Name]; ok {
			srcCIDRs = append(srcCIDRs, resolved.Prefixes...)
		}
		if pl.Except {
			srcNegate = true
		}
	}
	if len(srcCIDRs) > 0 {
		op := " saddr "
		if srcNegate {
			op = " saddr != "
		}
		if len(srcCIDRs) == 1 {
			parts = append(parts, family+op+srcCIDRs[0])
		} else {
			parts = append(parts, family+op+"{ "+strings.Join(srcCIDRs, ", ")+" }")
		}
	}

	// Collect all destination CIDRs
	var dstCIDRs []string
	dstCIDRs = append(dstCIDRs, term.DestAddresses...)
	var dstNegate bool
	for _, pl := range term.DestPrefixLists {
		if resolved, ok := prefixLists[pl.Name]; ok {
			dstCIDRs = append(dstCIDRs, resolved.Prefixes...)
		}
		if pl.Except {
			dstNegate = true
		}
	}
	if len(dstCIDRs) > 0 {
		op := " daddr "
		if dstNegate {
			op = " daddr != "
		}
		if len(dstCIDRs) == 1 {
			parts = append(parts, family+op+dstCIDRs[0])
		} else {
			parts = append(parts, family+op+"{ "+strings.Join(dstCIDRs, ", ")+" }")
		}
	}

	// Protocol matching (#2545: multi-value — emit an nft set on >1).
	if len(term.Protocols) == 1 {
		parts = append(parts, "meta l4proto "+term.Protocols[0])
	} else if len(term.Protocols) > 1 {
		parts = append(parts, "meta l4proto { "+strings.Join(term.Protocols, ", ")+" }")
	}

	// Source port matching
	if len(term.SourcePorts) == 1 {
		parts = append(parts, "th sport "+term.SourcePorts[0])
	} else if len(term.SourcePorts) > 1 {
		parts = append(parts, "th sport { "+strings.Join(term.SourcePorts, ", ")+" }")
	}

	// Destination port matching
	if len(term.DestinationPorts) == 1 {
		parts = append(parts, "th dport "+term.DestinationPorts[0])
	} else if len(term.DestinationPorts) > 1 {
		parts = append(parts, "th dport { "+strings.Join(term.DestinationPorts, ", ")+" }")
	}

	// DSCP / traffic-class matching (#2545: multi-value).
	if len(term.DSCPs) > 0 {
		dscpKey := "ip dscp "
		if family == "ip6" {
			dscpKey = "ip6 dscp "
		}
		dscps := make([]string, 0, len(term.DSCPs))
		for _, d := range term.DSCPs {
			dscps = append(dscps, nftDSCPValue(d))
		}
		if len(dscps) == 1 {
			parts = append(parts, dscpKey+dscps[0])
		} else {
			parts = append(parts, dscpKey+"{ "+strings.Join(dscps, ", ")+" }")
		}
	}

	// ICMP type/code matching (#2545: multi-value).
	if len(term.ICMPTypes) > 0 {
		icmpFamily := "icmp"
		if family == "ip6" {
			icmpFamily = "icmpv6"
		}
		parts = append(parts, icmpFamily+" type "+nftIntSet(term.ICMPTypes))
		if len(term.ICMPCodes) > 0 {
			parts = append(parts, icmpFamily+" code "+nftIntSet(term.ICMPCodes))
		}
	}

	// TCP flags matching
	if len(term.TCPFlags) > 0 {
		parts = append(parts, "tcp flags "+strings.Join(term.TCPFlags, ","))
	}

	// IP fragment matching
	if term.IsFragment {
		parts = append(parts, "ip frag-off & 0x1fff != 0")
	}

	// Action: discard → drop (silent), reject → reject (ICMP unreachable), accept → accept
	action := "accept"
	switch term.Action {
	case "discard":
		action = "drop"
	case "reject":
		action = "reject"
	case "accept", "":
		action = "accept"
	}

	if len(parts) == 0 {
		return action
	}
	return strings.Join(parts, " ") + " " + action
}

// nftDSCPValue converts a Junos DSCP name to the nftables symbolic name.
// nftables accepts: cs0-cs7, af11-af43, ef, or numeric values.
// nftIntSet renders an int slice as a single nft scalar (e.g. "8") or an nft
// anonymous set (e.g. "{ 8, 13 }") for multi-value match criteria (#2545).
func nftIntSet(vals []int) string {
	if len(vals) == 1 {
		return strconv.Itoa(vals[0])
	}
	strs := make([]string, len(vals))
	for i, v := range vals {
		strs[i] = strconv.Itoa(v)
	}
	return "{ " + strings.Join(strs, ", ") + " }"
}

func nftDSCPValue(name string) string {
	// Junos and nftables use the same naming for standard DSCP values.
	// Just pass through — nftables accepts ef, af11, af12, af13, af21,
	// af22, af23, af31, af32, af33, af41, af42, af43, cs0-cs7.
	return name
}
