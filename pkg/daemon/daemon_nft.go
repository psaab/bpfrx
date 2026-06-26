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
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
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

// applyHostInboundFilter is the KERNEL-nftables PRIMARY enforcement of
// `security zones <z> host-inbound-traffic` (#3070). Ordinary host-bound
// traffic to a firewall interface IP / VRRP VIP (SSH, ping, OSPF/BGP to the
// box — exactly what host-inbound-traffic governs) is shunted to the Linux
// kernel by the XDP shim before it reaches userspace-dp, so the userspace
// LocalDelivery check (forwarding/host_inbound.rs) only catches the narrow
// subset that actually reaches the XSK. This kernel chain enforces the
// host-inbound set for the rest, mirroring the lo0-filter precedent.
//
// Safety: only zones that DECLARED a host-inbound-traffic stanza get any rule;
// a zone with no stanza is admit-all (unchanged). Management / cluster-control
// lifeline interfaces (fxp0 / em0 / fab*) are excluded from the address sets by
// BuildZoneHostInboundViews, so a host-inbound deny can never strand management
// or break HA. Established sessions and IPv6 ND / PMTUD control messages are
// accepted before any deny.
func (d *Daemon) applyHostInboundFilter(cfg *config.Config) {
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	if !hostInboundHasEnforceableView(views) {
		// No host-inbound-configured zone with a resolvable address — nothing
		// to enforce. Remove any stale table (idempotent; delete fails benignly
		// when the table is absent). Timeout-bounded (#1794).
		_, _ = runCommandTimeout("nft", "delete", "table", "inet", "xpf_hostinbound")
		return
	}
	nftConf := buildHostInboundFilterPayload(views)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdin = strings.NewReader(nftConf)
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("failed to apply host-inbound filter", "err", err, "output", string(out))
	} else {
		slog.Info("host-inbound filter applied", "zones", len(views))
	}
}

// hostInboundHasEnforceableView reports whether at least one view carries a
// resolvable address. Static, VRRP-VIP and DHCP/DHCPv6-learned addresses all
// count: the live interface snapshot enumerates every kernel address via
// AddrList(FAMILY_ALL), so a DHCP-only interface with a live lease IS scoped
// (#3224 — see BuildZoneHostInboundViews). The only no-address case left is a
// configured zone whose interfaces have no static address AND no live address
// yet (e.g. a DHCP WAN before its first lease). That zone produces nothing; if
// NO zone is enforceable the whole table is removed (it self-heals once an
// address appears, because the lease-change / commit paths re-render).
func hostInboundHasEnforceableView(views []dpuserspace.ZoneHostInboundView) bool {
	for _, v := range views {
		if len(v.V4Addrs) > 0 || len(v.V6Addrs) > 0 {
			return true
		}
	}
	return false
}

// buildHostInboundFilterPayload assembles the exact `nft -f -` payload for the
// host-inbound kernel chain. Split out as a pure function so tests can
// parse-check the full payload without invoking nft. Uses the same atomic
// create/flush/redefine idiom as buildLo0FilterPayload (a syntax error on any
// line rejects the WHOLE payload, so the chain fails closed-as-absent rather
// than half-applied).
//
// Layout of `chain input` (type filter hook input priority 0; policy accept):
//  1. ct state established,related accept   — return/ongoing host traffic.
//  2. meta l4proto { 50, 51 } accept — raw ESP/AH exemption for host-terminated
//     IPsec (mirrors the userspace stage_ipsec_passthrough_check); the kernel
//     XFRM stack decrypts before any host-inbound deny can apply.
//  3. icmpv6 ND + error/PMTUD accept, icmp error/PMTUD accept — IPv6 Neighbor
//     Discovery and v4/v6 PMTUD/error control messages (dest-unreachable,
//     packet-too-big, time-exceeded, parameter-problem) are mandatory link
//     operation, never a "service" exposure; accepted globally so a host-inbound
//     set omitting `ping` does not black-hole PMTUD/ND/error delivery. This set
//     is mirrored by the userspace host-inbound exemption (#3171) so kernel and
//     XSK LocalDelivery agree. Echo-request stays gated on the `ping` service.
//  4. Per host-inbound-configured zone, per family with addresses:
//     - if `system-services all` / `any-service`: <fam> daddr <addrs> accept
//     (and no deny — the operator opened the zone to all services).
//     - else: one accept per listed service/protocol scoped to the zone addrs
//     (`protocols all` expands to the routing-protocol set — #3199, NOT a
//     blanket accept), then a catch-all `<fam> daddr <addrs> drop` (Junos
//     default-deny to the host is a silent drop).
func buildHostInboundFilterPayload(views []dpuserspace.ZoneHostInboundView) string {
	var rules []string
	rules = append(rules, "table inet xpf_hostinbound")
	rules = append(rules, "flush table inet xpf_hostinbound")
	rules = append(rules, "table inet xpf_hostinbound {")
	rules = append(rules, "  chain input {")
	rules = append(rules, "    type filter hook input priority 0; policy accept;")
	rules = append(rules, "    ct state established,related accept")
	// Raw ESP (50) / AH (51) are exempt from host-inbound enforcement so the
	// kernel XFRM stack can decrypt host-terminated IPsec — mirroring the
	// userspace stage_ipsec_passthrough_check, which runs BEFORE
	// host_inbound_admits (poll_descriptor mod.rs). Standard vSRX configures the
	// IPsec external zone with host-inbound `system-services { ike; }` (IKE
	// alone; ESP implicitly permitted): the `ike` token already accepts udp
	// 500/4500 (so IKE and NAT-T survive), and this exempts the raw ESP/AH data
	// plane (typical site-to-site). Without it a scoped `daddr <wan-ip> drop`
	// would black-hole the tunnel AFTER IKE succeeds — a silent upgrade
	// regression once #3070 turns a previously-no-op `ike` stanza into real
	// enforcement.
	rules = append(rules, "    meta l4proto { 50, 51 } accept")
	// IPv6 ND + v4/v6 PMTUD/error control messages — accepted regardless of the
	// host-inbound set so enforcement never breaks core L3 operation. The ICMP
	// error subtypes accepted here MUST stay in lock-step with the userspace
	// host-inbound exemption (`is_icmp_host_inbound_error` in
	// userspace-dp/.../forwarding/host_inbound.rs, #3171) so the kernel chain and
	// the XSK LocalDelivery classifier agree on a configured ping-less zone.
	// icmpv6 type 1 (destination-unreachable), 2 (packet-too-big, PMTUD), 3
	// (time-exceeded), 4 (parameter-problem) carry v6 error/PMTUD/traceroute
	// signalling; 133-137 are Neighbor Discovery. ICMPv4 destination-unreachable
	// (3, also PMTUD frag-needed code 4), time-exceeded (11, traceroute) and
	// parameter-problem (12) are the v4 error set. Echo-request is NOT here — it
	// stays gated on the per-zone `ping` system-service.
	rules = append(rules, "    icmpv6 type { 1, 2, 3, 4, 133, 134, 135, 136, 137 } accept")
	rules = append(rules, "    icmp type { destination-unreachable, time-exceeded, parameter-problem } accept")

	for _, v := range views {
		emitHostInboundZone(&rules, v, "ip", v.V4Addrs)
		emitHostInboundZone(&rules, v, "ip6", v.V6Addrs)
	}
	rules = append(rules, "  }")
	rules = append(rules, "}")
	return strings.Join(rules, "\n") + "\n"
}

// emitHostInboundZone appends the accept(+drop) rules for one zone/family to
// rules. No-op when the zone has no address in this family.
func emitHostInboundZone(rules *[]string, v dpuserspace.ZoneHostInboundView, family string, addrs []string) {
	if len(addrs) == 0 {
		return
	}
	daddr := family + " daddr " + nftAddrSet(addrs)
	// Only `system-services all` / `any-service` fully opens the zone: accept
	// everything to its addresses, emit no deny. `protocols all` is scoped to
	// the routing-protocol set (#3199) and flows through the per-match path
	// below, so it still gets a catch-all drop for non-routing traffic.
	if hostInboundAllowsAll(v) {
		*rules = append(*rules, "    "+daddr+" accept")
		return
	}
	matches := hostInboundMatchSet(v, family)
	// Zero recognized service/protocol matches for this configured zone — an
	// empty `host-inbound-traffic { }` stanza (or, on the tolerant load path,
	// a zone whose every token was an unrecognized typo that commit-time
	// validation downgraded to a warning rather than rejected). Fall through to
	// emit ONLY the catch-all drop below: a configured-but-empty stanza means
	// the operator opened nothing, so Junos denies all host-bound traffic to
	// the zone, and the Rust AF_XDP classifier already fails CLOSED for the
	// same case (host_inbound_admits returns deny when the zone is configured
	// but matches nothing). Emitting nothing here would fail OPEN and leave the
	// kernel and Rust paths in disagreement — the #3200 split-brain. Management
	// / cluster-control lifeline interfaces are excluded from v.V4Addrs /
	// v.V6Addrs by BuildZoneHostInboundViews, and the established / ESP-AH / ND
	// / PMTUD accepts precede this drop, so a zero-match zone cannot strand
	// management or break HA. The strict commit path rejects unknown tokens
	// outright (validateHostInboundTokensStrict), so this zero-match branch is
	// normally reachable only for a genuinely empty stanza.
	for _, m := range matches {
		*rules = append(*rules, "    "+daddr+" "+m+" accept")
	}
	// Catch-all deny for anything else destined to this zone's addresses
	// (Junos default-deny to the host is a silent drop).
	*rules = append(*rules, "    "+daddr+" drop")
}

// hostInboundAllowsAll reports whether the zone's system-services contains
// `all` / `any-service` (full admit). `protocols all` is deliberately NOT a
// full admit (#3199): in Junos it means all ROUTING protocols, not all
// system-services and not a blanket accept. `protocols all` is expanded to the
// concrete routing-protocol match set by hostInboundProtocolMatches instead, so
// it never opens SSH/HTTPS/SNMP/NETCONF on the box.
func hostInboundAllowsAll(v dpuserspace.ZoneHostInboundView) bool {
	for _, s := range v.SystemServices {
		if s == "all" || s == "any-service" {
			return true
		}
	}
	return false
}

// hostInboundMatchSet returns the de-duplicated nft match fragments (each a
// match clause WITHOUT the leading daddr or trailing accept) admitted by the
// zone's system-services + protocols for the given family ("ip" / "ip6").
//
// This is the Go/nftables MIRROR of the Rust classifier in
// userspace-dp/src/afxdp/forwarding/host_inbound.rs — keep the two token sets
// in sync (the recognized-token SSOT is config.KnownHostInboundSystemServices /
// config.KnownHostInboundProtocols; TestHostInboundNftMatchesKnownTokens
// asserts this matcher's domain equals that SSOT). An unrecognised token
// contributes nothing here; if it leaves the zone with zero recognized matches,
// emitHostInboundZone emits a catch-all drop (fail CLOSED, matching the Rust
// classifier). Strict commit-time rejection of unknown tokens lands in
// validateHostInboundTokensStrict (#3200), so a zero-match zone normally only
// arises from a genuinely empty `host-inbound-traffic { }` stanza.
func hostInboundMatchSet(v dpuserspace.ZoneHostInboundView, family string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(m string) {
		if m == "" || seen[m] {
			return
		}
		seen[m] = true
		out = append(out, m)
	}
	for _, s := range v.SystemServices {
		for _, m := range hostInboundServiceMatches(s, family) {
			add(m)
		}
	}
	for _, p := range v.Protocols {
		for _, m := range hostInboundProtocolMatches(p, family) {
			add(m)
		}
	}
	return out
}

// hostInboundServiceMatches maps a Junos `system-services` token to nft match
// fragments for the given family. Returns nil for `all` / `any-service`
// (handled by hostInboundAllowsAll) and for unrecognised tokens (fail-closed).
func hostInboundServiceMatches(token, family string) []string {
	// #3225: family-specific services (dhcp=v4, dhcpv6=v6) emit ONLY on their
	// own family. emitHostInboundZone calls this once per family with the same
	// token set, so a family-mismatched token must contribute no match (it would
	// otherwise be emitted under the wrong `ip`/`ip6 daddr`). The family map is
	// the SSOT shared with the Rust classifier (config.HostInboundServiceFamily).
	if fam, ok := config.HostInboundServiceFamily[token]; ok && fam != family {
		return nil
	}
	icmp := "icmp"
	if family == "ip6" {
		icmp = "icmpv6"
	}
	switch token {
	case "ssh":
		return []string{"tcp dport 22"}
	case "telnet":
		return []string{"tcp dport 23"}
	case "ftp":
		return []string{"tcp dport 21"}
	case "http", "webapi-clear-text":
		return []string{"tcp dport 80"}
	case "https", "webapi-ssl":
		return []string{"tcp dport 443"}
	case "ping":
		return []string{icmp + " type echo-request"}
	case "dns":
		return []string{"udp dport 53", "tcp dport 53"}
	case "dhcp", "bootp":
		return []string{"udp dport { 67, 68 }"}
	case "dhcpv6":
		return []string{"udp dport { 546, 547 }"}
	case "ntp":
		return []string{"udp dport 123"}
	case "snmp":
		return []string{"udp dport 161"}
	case "snmp-trap":
		return []string{"udp dport 162"}
	case "ike", "ipsec":
		// `ipsec` is the Junos system-service that permits host-terminated
		// IPsec: IKE negotiation (udp 500 / NAT-T 4500) plus the ESP/AH data
		// plane. The raw ESP (50) / AH (51) data plane is already accepted
		// globally in buildHostInboundFilterPayload (so the kernel XFRM stack
		// can decrypt), so the per-zone match only needs to open IKE — making
		// `ipsec` a superset of `ike`. Treating them as one case keeps the nft
		// mirror in parity with the Rust classifier.
		return []string{"udp dport { 500, 4500 }"}
	case "tftp":
		return []string{"udp dport 69"}
	case "netconf":
		return []string{"tcp dport 830"}
	case "ssh-netconf", "netconf-ssh":
		return []string{"tcp dport { 22, 830 }"}
	case "finger":
		return []string{"tcp dport 79"}
	case "ident-reset":
		return []string{"tcp dport 113"}
	case "lsping":
		return []string{"udp dport 3503"}
	case "sip":
		return []string{"udp dport 5060", "tcp dport 5060"}
	case "r-login", "rlogin":
		return []string{"tcp dport 513"}
	case "r-sh", "rsh":
		return []string{"tcp dport 514"}
	case "r-exec", "rexec":
		return []string{"tcp dport 512"}
	case "xnm-clear-text":
		return []string{"tcp dport 3221"}
	case "xnm-ssl":
		return []string{"tcp dport 3220"}
	case "traceroute":
		return []string{"udp dport 33434-33523"}
	case "gre":
		return []string{"meta l4proto 47"}
	default:
		return nil
	}
}

// hostInboundRoutingProtocolTokens is the routing-protocol set that
// `protocols all` expands to (#3199). One entry per unique signature
// (`ospf3` aliases `ospf`); hostInboundMatchSet dedups. Mirrors the Rust
// ROUTING_PROTOCOL_TOKENS in userspace-dp/src/afxdp/forwarding/host_inbound.rs.
// ospf3 is listed alongside ospf (#3225): both ride IP protocol 89 but on
// different families, so `protocols all` must admit proto 89 on BOTH IPv4
// (ospf) and IPv6 (ospf3). hostInboundProtocolMatches family-gates each, so the
// expansion emits proto 89 once per family without a wrong-family match.
var hostInboundRoutingProtocolTokens = []string{
	"ospf", "ospf3", "bgp", "rip", "ripng", "igmp", "pim",
	"vrrp", "bfd", "ldp", "msdp", "nhrp", "router-discovery",
}

// hostInboundProtocolMatches maps a Junos `protocols` (routing-protocol) token
// to nft match fragments. `all` expands to the full routing-protocol set
// (#3199) — NOT a blanket accept (that would open every system-service). Returns
// nil for unrecognised tokens (fail-closed).
func hostInboundProtocolMatches(token, family string) []string {
	// #3225: family-specific routing protocols (ospf=v4 / ospf3=v6, rip=v4 /
	// ripng=v6, igmp=v4) emit ONLY on their own family — the SSOT is
	// config.HostInboundProtocolFamily, shared with the Rust classifier. `all`
	// is dual-family (absent from the map) and recurses into the per-token set,
	// each of which family-gates itself here.
	if fam, ok := config.HostInboundProtocolFamily[token]; ok && fam != family {
		return nil
	}
	switch token {
	case "all":
		// `protocols all` = every routing protocol, scoped to protocol traffic.
		var out []string
		for _, p := range hostInboundRoutingProtocolTokens {
			out = append(out, hostInboundProtocolMatches(p, family)...)
		}
		return out
	case "ospf", "ospf3":
		// OSPFv2 (ospf, IPv4) and OSPFv3 (ospf3, IPv6) both ride IP protocol 89;
		// the family gate above scopes each to its own family.
		return []string{"meta l4proto 89"}
	case "bgp":
		return []string{"tcp dport 179"}
	case "rip":
		return []string{"udp dport 520"}
	case "ripng":
		return []string{"udp dport 521"}
	case "igmp":
		// v6 multicast group membership is MLD (icmpv6), reached via the ND
		// accept; the family gate restricts igmp to IPv4.
		return []string{"meta l4proto 2"}
	case "pim":
		return []string{"meta l4proto 103"}
	case "vrrp":
		return []string{"meta l4proto 112"}
	case "bfd":
		return []string{"udp dport { 3784, 3785 }"}
	case "ldp":
		return []string{"tcp dport 646", "udp dport 646"}
	case "msdp":
		return []string{"tcp dport 639"}
	case "nhrp":
		return []string{"meta l4proto 54"}
	case "router-discovery":
		if family == "ip6" {
			// v6 RS/RA are part of the always-accepted ND set above.
			return nil
		}
		return []string{"icmp type { 9, 10 }"}
	default:
		return nil
	}
}

// nftAddrSet renders a single address as a bare token or multiple as an nft
// anonymous set.
func nftAddrSet(addrs []string) string {
	if len(addrs) == 1 {
		return addrs[0]
	}
	return "{ " + strings.Join(addrs, ", ") + " }"
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

	// Negated (except) port matching (#3231). `source-port-except` /
	// `destination-port-except` (parsed since #2622/#3205) were dropped here,
	// so a `discard` term blocked the ports it should have exempted and an
	// accept-all-except-SSH term silently permitted SSH — a control-plane
	// bypass on the lo0 input filter. Emit the nft negated form mirroring the
	// positive port emission above (`th sport != ...` / `th dport != ...`).
	if len(term.SourcePortsExcept) == 1 {
		parts = append(parts, "th sport != "+term.SourcePortsExcept[0])
	} else if len(term.SourcePortsExcept) > 1 {
		parts = append(parts, "th sport != { "+strings.Join(term.SourcePortsExcept, ", ")+" }")
	}
	if len(term.DestPortsExcept) == 1 {
		parts = append(parts, "th dport != "+term.DestPortsExcept[0])
	} else if len(term.DestPortsExcept) > 1 {
		parts = append(parts, "th dport != { "+strings.Join(term.DestPortsExcept, ", ")+" }")
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

	// TCP flags matching (#3231). The Junos `tcp-flags` value is an
	// AND-conjunction with optional negation (`syn & !ack` = SYN required,
	// ACK forbidden). The pre-fix code joined the RAW tokens with commas
	// (`tcp flags syn,&,!ack`), which is invalid nft — and because nft loads
	// the lo0 ruleset atomically, that single syntax error rejected the WHOLE
	// ruleset and left the host control-plane filter fail-OPEN. Even a plain
	// list (`tcp flags syn,ack`) is wrong: nft reads a comma list as a
	// disjunctive set, not the Junos conjunction, and forbidden flags are not
	// representable that way at all. Reuse the commit-validated parser to get
	// the required/forbidden masks and emit the canonical
	// `tcp flags & (mentioned-mask) == required` form. A parse error is
	// unreachable for a committed config (compileFirewall rejects
	// unrepresentable expressions), but if one slips through we drop the
	// constraint with a warning rather than emit garbage that fails the whole
	// ruleset open — mirroring the userspace lowering in
	// pkg/dataplane/userspace/filters.go.
	if len(term.TCPFlags) > 0 {
		if required, forbidden, ok, err := config.ParseTCPFlagsExpression(term.TCPFlags); err != nil {
			slog.Warn("dropping unrepresentable tcp-flags expression from lo0 filter term",
				"term", term.Name, "tcp_flags", term.TCPFlags, "error", err)
		} else if ok {
			parts = append(parts, nftTCPFlagsMatch(required, forbidden))
		}
	}

	// IP fragment matching (#3231). `ip frag-off` is an IPv4-only header field;
	// emitting it in the inet6 chain is an nft syntax error that (atomic load)
	// rejected the whole ruleset and failed the lo0 filter open. Family-condition
	// the match: the IPv4 fragment-offset test for ip, and the IPv6 fragment
	// extension-header existence test for ip6.
	if term.IsFragment {
		if family == "ip6" {
			parts = append(parts, "exthdr frag exists")
		} else {
			parts = append(parts, "ip frag-off & 0x1fff != 0")
		}
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

// nftTCPFlagOrder lists the TCP flag bits in canonical low-to-high bit order
// with their nftables symbolic names. The bit values match config.tcpFlagBits
// (the SSOT consumed by ParseTCPFlagsExpression) and userspace-dp/src/tcp_flags.rs.
var nftTCPFlagOrder = []struct {
	bit  uint8
	name string
}{
	{0x01, "fin"},
	{0x02, "syn"},
	{0x04, "rst"},
	{0x08, "psh"},
	{0x10, "ack"},
	{0x20, "urg"},
}

// nftTCPFlagNames renders a TCP-flags bit mask as the nftables symbolic flag
// list joined with " | " (e.g. 0x12 -> "syn | ack"). An empty mask renders as
// the numeric "0x0" so it is a valid right-hand side for the `== 0` (all-clear)
// case.
func nftTCPFlagNames(mask uint8) string {
	var names []string
	for _, f := range nftTCPFlagOrder {
		if mask&f.bit != 0 {
			names = append(names, f.name)
		}
	}
	if len(names) == 0 {
		return "0x0"
	}
	return strings.Join(names, " | ")
}

// nftTCPFlagsMatch renders the canonical nftables masked-equality TCP-flags
// match for a required/forbidden mask pair, the form that expresses the Junos
// AND-conjunction semantics (a segment matches when (flags & required) ==
// required && (flags & forbidden) == 0):
//
//	tcp flags & (<required|forbidden flag names>) == <required flag names>
//
// Both sides are parenthesized when they name more than one flag so nft's `|`
// precedence cannot reassociate the right-hand side across the `==`. A single
// flag, or the all-clear "0x0" right-hand side, needs no parentheses.
func nftTCPFlagsMatch(required, forbidden uint8) string {
	mask := required | forbidden
	maskExpr := nftTCPFlagNames(mask)
	if mask&(mask-1) != 0 { // more than one bit set
		maskExpr = "(" + maskExpr + ")"
	}
	reqExpr := nftTCPFlagNames(required)
	if required&(required-1) != 0 { // more than one bit set
		reqExpr = "(" + reqExpr + ")"
	}
	return "tcp flags & " + maskExpr + " == " + reqExpr
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
