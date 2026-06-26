package config

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// validatePoolUtilizationAlarm is the #2079 strict-vs-lenient gate for the
// `security nat source pool-utilization-alarm raise-threshold/clear-threshold`
// thresholds. Junos requires raise > clear; a bare `pool-utilization-alarm;`
// compiles to raise=0/clear=0 (an always-firing alarm) and inverted/equal
// thresholds make hysteresis meaningless. Strict (commit / commit-check):
// hard-reject. Lenient (load / peer-sync, #1979 doctrine): return the message
// as a warning so a config committed before this gate existed still boots
// (#1960 fail-closed-on-compile-failure would otherwise brick the daemon on
// restart). The runtime monitor treats raise<=0 as disabled, so a leniently
// loaded bad config is inert, not always-firing.
func validatePoolUtilizationAlarm(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	a := cfg.Security.NAT.PoolUtilizationAlarm
	if a == nil {
		return nil, nil
	}
	var msg string
	switch {
	case a.RaiseThreshold <= 0 || a.RaiseThreshold > 100:
		msg = fmt.Sprintf("pool-utilization-alarm: raise-threshold must be in 1..100, got %d", a.RaiseThreshold)
	case a.ClearThreshold <= 0 || a.ClearThreshold >= a.RaiseThreshold:
		msg = fmt.Sprintf("pool-utilization-alarm: clear-threshold must be in 1..raise-threshold-1 (0 < clear < raise), got clear=%d raise=%d", a.ClearThreshold, a.RaiseThreshold)
	default:
		return nil, nil
	}
	if lenient {
		return []string{msg + " (ignored: alarm disabled until corrected)"}, nil
	}
	return nil, fmt.Errorf("%s", msg)
}

// natAddrFamily classifies an IP-part string the way the Rust parsers do,
// so the Go commit gate and the dataplane agree on every input.
//
//   - kind "v4": parses as IPv4 AND is textually a dotted-quad (no colon) —
//     i.e. exactly what Rust `Ipv4Addr::from_str` / `IpAddr::V4` accept.
//   - kind "v6": parses as IPv6 (textually colon-bearing) — what Rust
//     `IpAddr::V6` represents.
//   - kind "": does not parse as an IP at all (e.g. an address-book name);
//     NOT this validator's concern.
//
// The colon test is load-bearing: Go's net.ParseIP("::ffff:1.2.3.4").To4()
// is NON-nil (Go folds the IPv4-mapped form), but Rust `Ipv4Addr::from_str`
// REJECTS it and `IpAddr::from_str` classifies it as V6. Keying the family
// on text (no colon == v4) reproduces the Rust classification exactly, so a
// mapped form is treated as IPv6 here too — never accepted as a v4 host that
// the dataplane would then silently drop.
func natAddrFamily(ipPart string) string {
	if net.ParseIP(ipPart) == nil {
		return ""
	}
	if strings.IndexByte(ipPart, ':') >= 0 {
		return "v6"
	}
	return "v4"
}

// natCIDRIPPart returns the address portion of a CIDR string (everything before
// the first '/'), or the whole string if it carries no mask. It exists so the
// textual natAddrFamily classification can be applied to the ORIGINAL config
// text rather than a parsed net.IP — net.ParseCIDR/ParseIP folds an
// IPv4-mapped IPv6 literal (::ffff:1.2.3.4) into a 4-byte form whose .To4() is
// non-nil, which diverges from Rust's Ipv6Addr::from_str (it keeps the literal
// as V6). Keying the family on the un-parsed text preserves Go<->Rust parity.
func natCIDRIPPart(cidr string) string {
	if slash := strings.IndexByte(cidr, '/'); slash >= 0 {
		return cidr[:slash]
	}
	return cidr
}

// isHostMaskAddress reports whether addr is a host route the static-NAT
// dataplane can install: a bare IP (no mask) or the canonical host mask
// (/32 for IPv4, /128 for IPv6). It mirrors EXACTLY the Rust host-mask gate
// added in PR #2167 for static NAT (parse_nat_addr in
// userspace-dp/src/nat/static_nat.rs): static NAT is a strictly 1:1 host
// mapping, so a non-host mask carries no representable meaning. The family
// (hence the required mask) is keyed on natAddrFamily so an IPv4-mapped
// IPv6 literal is classified the SAME as Rust (V6, host_len 128). The
// second return value reports whether addr parsed as an IP at all; a non-IP
// token (e.g. an address-book name) is NOT this validator's concern and is
// left to the existing address handling.
//
// NOTE: NAT64 source-pool addresses use isNAT64PoolHostAddress, NOT this
// predicate — the Rust parse_pool_v4 (nat64.rs) is IPv4-ONLY (the pool
// translates to IPv4 source addresses), so an IPv6 pool entry that this
// predicate would accept (its /128 host form) is silently dropped there.
func isHostMaskAddress(addr string) (host bool, parsed bool) {
	slash := strings.IndexByte(addr, '/')
	ipPart := addr
	if slash >= 0 {
		ipPart = addr[:slash]
	}
	fam := natAddrFamily(ipPart)
	if fam == "" {
		return false, false
	}
	if slash < 0 {
		// Bare address — a host in both families.
		return true, true
	}
	maskPart := addr[slash+1:]
	wantMask := "128"
	if fam == "v4" {
		wantMask = "32"
	}
	return maskPart == wantMask, true
}

// natStaticPrefixInfo classifies a static-NAT address the way the Rust
// parse_nat_prefix (static_nat.rs, #3031) does: it returns the family, the
// prefix length, whether the value is a host route, and whether it parsed as
// an IP at all. A bare address is a host route (len == max). A `/N` mask is
// parsed numerically; bits < 0 flags a malformed/out-of-range mask (a
// non-numeric or `/33`/`/129` suffix) so the caller leaves the existing
// host-route rejection to fire. A non-IP token (address-book name) returns
// parsedIP == false and is not this validator's concern.
func natStaticPrefixInfo(addr string) (fam string, bits int, isHost, parsedIP bool) {
	slash := strings.IndexByte(addr, '/')
	ipPart := addr
	if slash >= 0 {
		ipPart = addr[:slash]
	}
	fam = natAddrFamily(ipPart)
	if fam == "" {
		return "", -1, false, false
	}
	max := 128
	if fam == "v4" {
		max = 32
	}
	if slash < 0 {
		return fam, max, true, true
	}
	n, err := strconv.Atoi(addr[slash+1:])
	if err != nil || n < 0 || n > max {
		return fam, -1, false, true
	}
	return fam, n, n == max, true
}

// isStaticBlockPair reports whether (match, then) is a valid block-to-block
// (subnet) static-NAT 1:1 mapping (#3031): both sides parse as IPs, both are
// non-host prefixes of the SAME family with EQUAL prefix length. The Rust
// dataplane installs exactly this case (offset-preserving remap); a
// host-vs-block, mismatched-length, mixed-family, or malformed-mask pair is
// NOT a block pair and falls through to the existing host-route rejection.
func isStaticBlockPair(match, then string) bool {
	mf, mb, mh, mp := natStaticPrefixInfo(match)
	tf, tb, th, tp := natStaticPrefixInfo(then)
	if !mp || !tp {
		return false // a non-IP token — leave to existing handling
	}
	if mh || th || mb < 0 || tb < 0 {
		return false // a host side or a malformed mask — not a block pair
	}
	return mf == tf && mb == tb
}

// isNAT64PoolHostAddress reports whether addr is an IPv4 host route the
// NAT64 source pool can install. It mirrors EXACTLY the Rust parse_pool_v4
// gate (userspace-dp/src/nat64.rs): the NAT64 pool holds IPv4 source
// addresses, so it accepts ONLY a bare IPv4 address or an IPv4 /32 — an
// IPv6 address (bare or any mask, INCLUDING the IPv4-mapped ::ffff:x.x.x.x
// form that Ipv4Addr::from_str rejects) and a non-host IPv4 mask are all
// silently dropped by parse_pool_v4, so the commit gate must reject them
// too or the gate and the dataplane disagree. Family is keyed on
// natAddrFamily (textual, colon == v6) to match Ipv4Addr::from_str. The
// second return value reports whether addr parsed as an IP at all (so a
// non-IP address-book token is left to existing handling); a parseable
// non-IPv4 address returns (host=false, parsed=true) — it parsed, but is
// not an installable pool address.
func isNAT64PoolHostAddress(addr string) (host bool, parsed bool) {
	slash := strings.IndexByte(addr, '/')
	ipPart := addr
	if slash >= 0 {
		ipPart = addr[:slash]
	}
	fam := natAddrFamily(ipPart)
	if fam == "" {
		return false, false
	}
	if fam != "v4" {
		// Parsed, but not an IPv4 pool address — reject (parse_pool_v4 drops).
		return false, true
	}
	if slash < 0 {
		return true, true
	}
	// Only an IPv4 /32 is an installable pool host address.
	return addr[slash+1:] == "32", true
}

// nptv6PrefixHasHostBits reports whether the CIDR text `cidr` carries any
// bit set beyond its prefix length — i.e. the raw address is not equal to
// its own network (masked) address. `parsed` is the *net.IPNet returned by
// net.ParseCIDR(cidr) (its .IP is already masked); the comparison parses the
// raw IP part of the original text and re-masks it under the same mask. The
// second return value is false when the raw IP cannot be parsed (the caller
// has already proven cidr parses via ParseCIDR, so this is defensive only).
// #2380: net.ParseCIDR silently masks, so this surfaces the discarded bits.
func nptv6PrefixHasHostBits(cidr string, parsed *net.IPNet) (host bool, ok bool) {
	if parsed == nil {
		return false, false
	}
	raw := net.ParseIP(natCIDRIPPart(cidr))
	if raw == nil {
		return false, false
	}
	// Mask the raw address with the prefix's mask and compare to the raw
	// address. If they differ, host/subnet bits were set beyond the prefix.
	masked := raw.Mask(parsed.Mask)
	if masked == nil {
		// Mask width does not match the address family — should not happen
		// for an IPv6 prefix that already parsed, but treat as no host bits.
		return false, true
	}
	return !masked.Equal(raw), true
}

// validateNATHostMaskStrict is the #2173 strict-vs-lenient gate that
// rejects a static-NAT match/prefix or a NAT64 source-pool address whose
// mask is not a host route (/32 for v4, /128 for v6; a bare address is a
// host too). #2132 made the Rust dataplane TOLERATE the canonical host
// mask, and PR #2167 then hardened the Rust parser to REJECT a non-host
// mask — so today a misconfigured /24 static-NAT match or pool address is
// SILENTLY DROPPED at the dataplane (the rule is parsed-out, never
// installed) with no operator feedback. This commit-time check surfaces
// the misconfiguration at `commit`/`commit check` instead.
//
// Scope mirrors what the Rust host-mask gate covers:
//   - static-NAT rules' `match destination-address` (-> ExternalIP) and
//     `then static-nat prefix` (-> InternalIP). NPTv6 (`nptv6-prefix`) and
//     NAT64 (`static-nat inet`) rules are EXEMPT: NPTv6 is a genuine prefix
//     translation (RFC 6296), and an `inet` rule's match is the NAT64
//     well-known prefix (e.g. 64:ff9b::/96) with translation driven by the
//     separate NAT64 snapshot, not the static_nat table.
//   - NAT64 source-pool addresses (the IPv4 pool referenced by a
//     `nat64 rule-set ... source-pool` — parse_pool_v4 host-mask gate).
//
// Strict (commit / commit-check): hard-reject. Lenient (load / peer-sync,
// #1960 / #1979 doctrine): return the message as a warning so a config
// committed before this gate existed still boots (fail-closed-on-compile-
// failure would otherwise brick the daemon on restart); the dataplane
// independently drops the bad entry, so a leniently-loaded config is
// already inert for that rule, not mis-installed.
func validateNATHostMaskStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	// emitSuffix returns a violation as an error (strict) or appends it to the
	// lenient warning list with a dataplane-effect suffix. The suffix differs
	// by case: a static-NAT IP failure drops the WHOLE rule (parse_nat_addr
	// returns None for the rule's match/then), whereas a NAT64 source-pool
	// entry is dropped individually by filter_map(parse_pool_v4) — the rest of
	// the pool/rule stays installed. Keep the load-path text precise so the
	// operator does not over-read the impact.
	emitSuffix := func(msg, suffix string) error {
		if lenient {
			warnings = append(warnings, msg+suffix)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	emit := func(msg string) error {
		return emitSuffix(msg, " (ignored: rule dropped by dataplane until corrected)")
	}

	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.IsNPTv6 {
				continue
			}
			// `then static-nat inet` is a NAT64 translation, not host-1:1
			// static NAT: its `match destination-address` is the NAT64
			// well-known prefix (e.g. 64:ff9b::/96, a legitimate non-host
			// prefix) and the actual translation is driven by the separate
			// NAT64 snapshot (buildNAT64Snapshots), not the static_nat table
			// (the inet rule's static_nat snapshot entry is expected to be a
			// no-op the Rust parse drops). Exempt the whole rule.
			if rule.Then == "inet" {
				continue
			}
			// #3206: a `match destination-address` / `then static-nat
			// prefix` that is not a parseable literal IP or CIDR (an
			// address-book name, or a typo'd prefix) is NOT caught by the
			// host-mask check below — that check fires only when the value
			// parses (`parsed && !host`). An unparseable value falls all the
			// way through to the Rust dataplane, where `parse_nat_prefix`
			// returns None and `from_snapshots` does `continue`, SILENTLY
			// dropping the entire static-NAT mapping with no commit error or
			// runtime feedback (the operator authored a rule that simply does
			// not exist at runtime). Static NAT takes literal IP/CIDR
			// endpoints, not address-book references, so reject an
			// unparseable value at commit. `natStaticPrefixInfo` mirrors the
			// Rust `parse_nat_prefix` classification; its `parsedIP == false`
			// is precisely the silently-dropped case. Run this BEFORE the
			// blockPair / host-mask checks so an unparseable value reports its
			// own (clearer) error rather than being skipped as "not a block
			// pair".
			if rule.Match != "" {
				if _, _, _, parsedIP := natStaticPrefixInfo(rule.Match); !parsedIP {
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q match destination-address %q is not a valid IP address or CIDR prefix (static NAT requires a literal address or prefix, not an address-book name or a typo'd value)",
						rs.Name, rule.Name, rule.Match)); err != nil {
						return nil, err
					}
				}
			}
			if rule.Then != "" {
				if _, _, _, parsedIP := natStaticPrefixInfo(rule.Then); !parsedIP {
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q then static-nat prefix %q is not a valid IP address or CIDR prefix (static NAT requires a literal address or prefix, not an address-book name or a typo'd value)",
						rs.Name, rule.Name, rule.Then)); err != nil {
						return nil, err
					}
				}
			}
			// #3031: a valid block-to-block (subnet) static-NAT rule —
			// equal-length non-host prefixes of the same family — is now
			// installed by the dataplane (offset-preserving 1:1 remap), so do
			// NOT reject it as a non-host mask. Only the genuinely-invalid
			// non-host cases (host-vs-block, mismatched length, mixed family,
			// malformed mask) fall through to the host-route rejection below.
			blockPair := isStaticBlockPair(rule.Match, rule.Then)
			// #3202: a block-to-block (subnet) static-NAT rule that ALSO
			// carries a `match destination-port` or a `then static-nat
			// mapped-port` is not representable in the dataplane. The Rust
			// `StaticNatBlock` (static_nat.rs `from_snapshots`) stores only the
			// address prefixes and performs an offset-preserving, ALL-PORT 1:1
			// remap — it has no `match_dst_port`/`mapped_port` fields. So the
			// port match/mapping is SILENTLY discarded and "NAT only port 80 of
			// this /24, remap to 8080" degrades to "NAT every port of the /24"
			// (over-broad NAT / policy bypass). This also matches Junos: a
			// `static-nat prefix` is an address-only 1:1 subnet map; per-port
			// translation is a host-scope construct (`static-nat ... mapped-port`
			// on a /32). Reject the combination at strict commit-check so the
			// operator authors a host static-NAT rule for the port forward, or
			// drops the port tokens for a whole-subnet 1:1. (#3031 added the
			// address-only block map; it did not add this rejection.)
			if blockPair && (rule.MatchDestinationPort != 0 || rule.MappedPort != 0) {
				if err := emitSuffix(fmt.Sprintf(
					"security nat static rule-set %q rule %q maps a subnet (block-to-block prefix) but also specifies a port (match destination-port / then static-nat mapped-port); subnet static NAT is address-only 1:1 and the dataplane cannot translate per-port for a block, so the port mapping is silently dropped (use a /32 host match+prefix for a port forward, or drop the port tokens for a whole-subnet 1:1)",
					rs.Name, rule.Name),
					" (ignored: port mapping dropped by dataplane until corrected)"); err != nil {
					return nil, err
				}
			}
			if rule.Match != "" && !blockPair {
				if host, parsed := isHostMaskAddress(rule.Match); parsed && !host {
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q match destination-address %q must be a host route (/32 for IPv4, /128 for IPv6); a non-host mask is silently dropped by the dataplane",
						rs.Name, rule.Name, rule.Match)); err != nil {
						return nil, err
					}
				}
			}
			if rule.Then != "" && !blockPair {
				if host, parsed := isHostMaskAddress(rule.Then); parsed && !host {
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q then static-nat prefix %q must be a host route (/32 for IPv4, /128 for IPv6); a non-host mask is silently dropped by the dataplane",
						rs.Name, rule.Name, rule.Then)); err != nil {
						return nil, err
					}
				}
			}
			// #2491: port-mapped static NAT. The `mapped-port` token rides
			// inside the children:nil static-nat leaf, so the schema's
			// value-slot validator never sees it; range-check it here. An
			// out-of-range port would truncate to a wrong u16 in the snapshot,
			// so reject it. A `mapped-port` requires a matching `match
			// destination-port`: without an external port to match, the port
			// rewrite has no inbound trigger and the reverse SNAT cannot
			// recover the original port.
			if rule.MatchDestinationPort != 0 && (rule.MatchDestinationPort < 1 || rule.MatchDestinationPort > 65535) {
				if err := emitSuffix(fmt.Sprintf(
					"security nat static rule-set %q rule %q match destination-port %d is out of range (1-65535)",
					rs.Name, rule.Name, rule.MatchDestinationPort),
					" (ignored: port match dropped by dataplane until corrected)"); err != nil {
					return nil, err
				}
			}
			// #2769: a `match destination-port` WITHOUT a `then static-nat
			// mapped-port` is a port-scoped 1:1 (no port translation). The
			// dataplane scopes the reverse SNAT to that one port — but the
			// half-config is almost always an operator mistake (the intent is
			// usually a full port-forward with mapped-port). Reject it at
			// strict commit-check, mirroring the existing mapped-port-without-
			// match-port rejection below, so the operator must either drop the
			// port match (whole-address 1:1) or add a mapped-port (port
			// forward). The dataplane backstop (static_nat.rs) keeps the
			// reverse SNAT scoped to the matched port if the rule slips through
			// the lenient load / peer-sync path.
			if rule.MatchDestinationPort != 0 && rule.MappedPort == 0 {
				if err := emitSuffix(fmt.Sprintf(
					"security nat static rule-set %q rule %q match destination-port %d requires a matching `then static-nat mapped-port` (a port match without a port translation either broadens or scopes the reverse source-NAT in a non-obvious way; drop the port match for a whole-address 1:1, or add a mapped-port for a port forward)",
					rs.Name, rule.Name, rule.MatchDestinationPort),
					" (ignored: port match dropped by dataplane until corrected)"); err != nil {
					return nil, err
				}
			}
			if rule.MappedPort != 0 {
				if rule.MappedPort < 1 || rule.MappedPort > 65535 {
					if err := emitSuffix(fmt.Sprintf(
						"security nat static rule-set %q rule %q then static-nat mapped-port %d is out of range (1-65535)",
						rs.Name, rule.Name, rule.MappedPort),
						" (ignored: port translation dropped by dataplane until corrected)"); err != nil {
						return nil, err
					}
				}
				if rule.MatchDestinationPort == 0 {
					if err := emitSuffix(fmt.Sprintf(
						"security nat static rule-set %q rule %q then static-nat mapped-port %d requires a matching `match destination-port`",
						rs.Name, rule.Name, rule.MappedPort),
						" (ignored: port translation dropped by dataplane until corrected)"); err != nil {
						return nil, err
					}
				}
			}
		}
	}

	// NAT64 source-pool addresses are discrete IPv4 host source IPs: the Rust
	// parse_pool_v4 (nat64.rs) accepts ONLY a bare IPv4 or an IPv4 /32 and
	// silently drops everything else (an IPv6 address, a non-host IPv4 mask).
	// Range-expanded pool entries are always /32 by construction
	// (expandAddressRange), so only an operator-authored single
	// `pool address <X>` can trip this.
	for _, rs := range cfg.Security.NAT.NAT64 {
		if rs == nil || rs.SourcePool == "" {
			continue
		}
		pool, ok := cfg.Security.NAT.SourcePools[rs.SourcePool]
		if !ok || pool == nil {
			continue
		}
		addrs := pool.Addresses
		if pool.Address != "" {
			addrs = append([]string{pool.Address}, addrs...)
		}
		for _, a := range addrs {
			if a == "" {
				continue
			}
			if host, parsed := isNAT64PoolHostAddress(a); parsed && !host {
				if err := emitSuffix(fmt.Sprintf(
					"security nat source pool %q address %q is referenced by nat64 rule-set %q source-pool and must be an IPv4 host route (a bare IPv4 address or /32); a non-host or IPv6 address is silently dropped by the dataplane",
					pool.Name, a, rs.Name),
					" (ignored: only this pool address is dropped by the dataplane until corrected)"); err != nil {
					return nil, err
				}
			}
		}
	}

	return warnings, nil
}

// validateNPTv6Strict is the #2240/#2241 strict-vs-lenient gate for NPTv6
// (RFC 6296) static-NAT rules (`then static-nat nptv6-prefix`).
//
// #2240 (fail-closed validation): the dataplane compiler
// (`pkg/dataplane/compiler_nat.go` compileNPTv6) historically logged a warning
// and `continue`d past any per-rule validation failure (unparseable prefix,
// mismatched /48-vs-/64 lengths, an unsupported length, a non-IPv6 prefix),
// then unconditionally called `DeleteStaleNPTv6(written)` over only the VALID
// subset — so editing one previously-good rule into an invalid one TORE DOWN
// its working translation entry with no replacement installed, silently
// disabling a working translation. The Rust helper mirrored the silent skip.
// In a retired-eBPF world (#1373) the userspace helper is the enforcement
// plane, so this is a fail-OPEN regression: a typo silently changes
// reachability and source/destination identity while the commit still reports
// success. This commit-time gate surfaces the misconfiguration loudly.
//
// #2241 (overlap rejection): NPTv6 supports both /48 and /64 rules. The runtime
// resolves a match by FIRST hit in insertion order with no longest-prefix
// match, so a broad /48 configured before a nested /64 shadows the /64 and
// reordering the same rules changes the translation identity. Reject any
// overlapping pair (in either direction) so resolution is deterministic.
//
// Strict (commit / commit-check): hard-reject. Lenient (load / peer-sync, #1960
// / #1979 doctrine): return the messages as warnings so a config committed
// before this gate existed (or peer-synced) still boots. The "previous state is
// kept" impact note in the lenient warning is scoped to the userspace
// apply/preflight, not asserted as a general validator guarantee: the Rust
// helper's own #2240/#2241 backstop (`Nptv6State::try_from_snapshots`) rejects
// the whole snapshot at apply, so the apply preflight keeps the previous live
// forwarding state and a leniently-loaded bad config never installs a
// torn-down or nondeterministic NPTv6 runtime. The validator itself only
// classifies the rule as invalid; it is the helper preflight that preserves
// the prior forwarding state.
func validateNPTv6Strict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	emit := func(msg string) error {
		if lenient {
			warnings = append(warnings,
				msg+" (this NPTv6 rule is invalid; on a userspace-dataplane apply/preflight"+
					" the helper rejects the whole NPTv6 snapshot and the previous state is kept,"+
					" so the rule will not take effect until corrected)")
			return nil
		}
		return fmt.Errorf("%s", msg)
	}

	// Track already-validated prefixes per direction to reject overlaps (#2241).
	// Outbound matches on the internal prefix; inbound matches on the external
	// (match) prefix. Each direction is checked independently.
	type seenPrefix struct {
		net         *net.IPNet
		ones        int
		ruleSetName string
		ruleName    string
	}
	var internalSeen, externalSeen []seenPrefix

	// overlaps reports whether two IPv6 prefixes overlap — i.e. one contains
	// the other's network address (the shorter prefix is a prefix of the
	// longer). This covers identical /48-/48, identical /64-/64, and a /48
	// nesting a /64 (the case that makes first-match resolution order-
	// dependent).
	overlaps := func(a, b *net.IPNet) bool {
		return a.Contains(b.IP) || b.Contains(a.IP)
	}

	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || !rule.IsNPTv6 {
				continue
			}

			// External prefix = `match destination-address`. The family is
			// classified from the original CIDR text (natCIDRIPPart +
			// natAddrFamily below), not the parsed net.IP, so the parsed IP
			// values are intentionally discarded.
			_, extNet, errExt := net.ParseCIDR(rule.Match)
			// Internal prefix = `then static-nat nptv6-prefix`.
			_, intNet, errInt := net.ParseCIDR(rule.Then)

			if errExt != nil {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q match destination-address %q is not a valid IPv6 prefix for nptv6-prefix translation",
					rs.Name, rule.Name, rule.Match)); err != nil {
					return nil, err
				}
				continue
			}
			if errInt != nil {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q then static-nat nptv6-prefix %q is not a valid IPv6 prefix",
					rs.Name, rule.Name, rule.Then)); err != nil {
					return nil, err
				}
				continue
			}

			extOnes, _ := extNet.Mask.Size()
			intOnes, _ := intNet.Mask.Size()

			if extOnes != intOnes {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q nptv6 prefix lengths must match (match %q is /%d, nptv6-prefix %q is /%d)",
					rs.Name, rule.Name, rule.Match, extOnes, rule.Then, intOnes)); err != nil {
					return nil, err
				}
				continue
			}
			if extOnes != 48 && extOnes != 64 {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q nptv6 prefix length /%d is unsupported (only /48 and /64 are allowed)",
					rs.Name, rule.Name, extOnes)); err != nil {
					return nil, err
				}
				continue
			}
			// Family classification MUST be textual (natAddrFamily), not
			// net.IP.To4(): Go folds an IPv4-mapped IPv6 literal
			// (::ffff:1.2.3.4) so its parsed .To4() is non-nil, but Rust's
			// Ipv6Addr::from_str (parse_prefix in userspace-dp/src/nptv6.rs)
			// accepts the same text as a valid IPv6 address and APPLIES the
			// rule. A To4()-based check here would warn-skip on the lenient
			// load path while the dataplane installs the rule — a Go<->Rust
			// divergence (#2247 item 2). Classifying on the original text
			// (colon == v6) matches the helper exactly, so an IPv4-mapped form
			// is treated as IPv6 here too. We split the IP part off the CIDR
			// (the same idiom as isHostMaskAddress); ParseCIDR already proved
			// these parse, so a missing slash cannot happen, but the helper is
			// robust either way.
			if natAddrFamily(natCIDRIPPart(rule.Match)) != "v6" ||
				natAddrFamily(natCIDRIPPart(rule.Then)) != "v6" {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q nptv6 prefixes must be IPv6 (match %q, nptv6-prefix %q)",
					rs.Name, rule.Name, rule.Match, rule.Then)); err != nil {
					return nil, err
				}
				continue
			}

			// #2380: host-bits-zero strictness. net.ParseCIDR masks the
			// address to the prefix length silently, so a prefix with bits
			// set beyond the prefix length (e.g. 2001:db8:1:2::/48) parses
			// as a DIFFERENT prefix (2001:db8:1::/48) than the operator
			// wrote, and the Rust parse_prefix (nptv6.rs) discards the extra
			// words identically. Both planes agree on the masked result, so
			// there is no traffic-correctness bug — but the operator gets a
			// rule that does not match what they typed, with no feedback.
			// Junos rejects host bits set on a prefix; mirror that here. This
			// is the same class as isHostMaskAddress for static-NAT host
			// masks. The masked network address is extNet.IP / intNet.IP; the
			// raw address is the IP part of the original CIDR text. A mismatch
			// means host/subnet bits were set.
			if host, ok := nptv6PrefixHasHostBits(rule.Match, extNet); ok && host {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q match destination-address %q has host bits set beyond the /%d prefix (Junos rejects this; write the masked prefix explicitly)",
					rs.Name, rule.Name, rule.Match, extOnes)); err != nil {
					return nil, err
				}
				continue
			}
			if host, ok := nptv6PrefixHasHostBits(rule.Then, intNet); ok && host {
				if err := emit(fmt.Sprintf(
					"security nat static rule-set %q rule %q then static-nat nptv6-prefix %q has host bits set beyond the /%d prefix (Junos rejects this; write the masked prefix explicitly)",
					rs.Name, rule.Name, rule.Then, intOnes)); err != nil {
					return nil, err
				}
				continue
			}

			// #2241: overlap rejection. Check the internal (outbound) and
			// external (inbound) prefixes independently against prior rules.
			overlapFound := false
			for _, prev := range internalSeen {
				if overlaps(prev.net, intNet) {
					overlapFound = true
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q nptv6-prefix %q overlaps rule-set %q rule %q (outbound/internal prefixes overlap; first-match resolution would be order-dependent)",
						rs.Name, rule.Name, rule.Then, prev.ruleSetName, prev.ruleName)); err != nil {
						return nil, err
					}
					break
				}
			}
			for _, prev := range externalSeen {
				if overlaps(prev.net, extNet) {
					overlapFound = true
					if err := emit(fmt.Sprintf(
						"security nat static rule-set %q rule %q match destination-address %q overlaps rule-set %q rule %q (inbound/external prefixes overlap; first-match resolution would be order-dependent)",
						rs.Name, rule.Name, rule.Match, prev.ruleSetName, prev.ruleName)); err != nil {
						return nil, err
					}
					break
				}
			}
			if overlapFound {
				// Do not register an overlapping rule as a baseline for
				// subsequent comparisons; the snapshot is already rejected.
				continue
			}

			internalSeen = append(internalSeen, seenPrefix{net: intNet, ones: intOnes, ruleSetName: rs.Name, ruleName: rule.Name})
			externalSeen = append(externalSeen, seenPrefix{net: extNet, ones: extOnes, ruleSetName: rs.Name, ruleName: rule.Name})
		}
	}

	return warnings, nil
}

func compileNAT(node *Node, sec *SecurityConfig) error {
	// Initialize SourcePools map
	if sec.NAT.SourcePools == nil {
		sec.NAT.SourcePools = make(map[string]*NATPool)
	}

	srcNode := node.FindChild("source")
	if srcNode != nil {
		if err := compileNATSource(srcNode, sec); err != nil {
			return fmt.Errorf("source: %w", err)
		}
	}

	dstNode := node.FindChild("destination")
	if dstNode != nil {
		if err := compileNATDestination(dstNode, sec); err != nil {
			return fmt.Errorf("destination: %w", err)
		}
	}

	staticNode := node.FindChild("static")
	if staticNode != nil {
		if err := compileNATStatic(staticNode, sec); err != nil {
			return fmt.Errorf("static: %w", err)
		}
	}

	nat64Node := node.FindChild("nat64")
	if nat64Node != nil {
		if err := compileNAT64(nat64Node, sec); err != nil {
			return fmt.Errorf("nat64: %w", err)
		}
	}

	// natv6v4 { no-v6-frag-header; }
	v6v4Node := node.FindChild("natv6v4")
	if v6v4Node != nil {
		sec.NAT.NATv6v4 = &NATv6v4Config{}
		if v6v4Node.FindChild("no-v6-frag-header") != nil {
			sec.NAT.NATv6v4.NoV6FragHeader = true
		}
	}

	// proxy-arp { interface <name> { address <addr>; } }
	proxyNode := node.FindChild("proxy-arp")
	if proxyNode != nil {
		for _, inst := range namedInstances(proxyNode.FindChildren("interface")) {
			entry := &ProxyARPEntry{Interface: inst.name}
			for _, prop := range inst.node.Children {
				if prop.Name() != "address" {
					continue
				}
				// Hierarchical range: Keys=["address","addr1","to","addr2"]
				if len(prop.Keys) >= 4 && prop.Keys[2] == "to" {
					expanded, err := expandAddressRange(prop.Keys[1], prop.Keys[3])
					if err != nil {
						return fmt.Errorf("proxy-arp interface %s: %w", inst.name, err)
					}
					entry.Addresses = append(entry.Addresses, expanded...)
					continue
				}

				// Set syntax range: Keys=["address","addr1"], child Keys=["to","addr2"]
				toChild := prop.FindChild("to")
				if toChild != nil {
					low := nodeVal(prop)
					high := nodeVal(toChild)
					if low != "" && high != "" {
						expanded, err := expandAddressRange(low, high)
						if err != nil {
							return fmt.Errorf("proxy-arp interface %s: %w", inst.name, err)
						}
						entry.Addresses = append(entry.Addresses, expanded...)
						continue
					}
				}

				// Single address
				if v := nodeVal(prop); v != "" {
					addr := v
					if !strings.Contains(addr, "/") {
						addr += "/32"
					}
					entry.Addresses = append(entry.Addresses, addr)
				}
			}
			sec.NAT.ProxyARP = append(sec.NAT.ProxyARP, entry)
		}
	}

	return nil
}

func compileNAT64(node *Node, sec *SecurityConfig) error {
	for _, inst := range namedInstances(node.FindChildren("rule-set")) {
		rs := &NAT64RuleSet{Name: inst.name}

		for _, child := range inst.node.Children {
			switch child.Name() {
			case "prefix":
				rs.Prefix = nodeVal(child)
			case "source-pool":
				rs.SourcePool = nodeVal(child)
			}
		}

		sec.NAT.NAT64 = append(sec.NAT.NAT64, rs)
	}
	return nil
}

// parseZoneList extracts zone names from a from/to node.
// Handles every AST shape the parser can produce for `from zone ...`:
//   - `from` carries the list inline: Keys=["from","zone","A","B","C"] → ["A","B","C"]
//   - Unified bracket list (#2419): one "zone" child with the whole list
//     collapsed onto its Keys — Keys=["zone","A","B","C"] → ["A","B","C"].
//     This is the shape flat-set `set ... from zone [ A B C ]` now produces;
//     before #2419 it split into a "zone" child plus orphan leaf children, and
//     reading only nodeVal here silently dropped every zone but the first
//     (FAIL-OPEN static NAT — the dropped zone's whole rule-set vanished).
//   - Hierarchical / legacy block: multiple "zone" children, each
//     Keys=["zone","A"] (from `from { zone A; zone B; }` or repeated
//     `set ... from zone A` / `from zone B` set commands).
//
// For each "zone" child we accumulate Keys[1:] AND any orphan leaf children,
// mirroring firewallMatchValues (compiler_firewall.go) — the #2419 contract for
// reading a multi-value leaf across both AST shapes.
func parseZoneList(node *Node) []string {
	// `from` carries the zone list inline on its own Keys.
	if len(node.Keys) >= 3 && node.Keys[1] == "zone" {
		return node.Keys[2:]
	}
	var zones []string
	for _, child := range node.Children {
		if child.Name() != "zone" {
			continue
		}
		// Unified bracket list / single value: every token after "zone".
		for _, k := range child.Keys[1:] {
			if k != "" {
				zones = append(zones, k)
			}
		}
		// Legacy bracket-expanded orphan leaf children (defensive — older
		// trees that still split the list into child leaves).
		for _, grandchild := range child.Children {
			if grandchild.IsLeaf && len(grandchild.Keys) >= 1 && grandchild.Keys[0] != "" {
				zones = append(zones, grandchild.Keys[0])
			}
		}
	}
	return zones
}

// expandAddressRange expands "low/mask to high/mask" into individual IP strings.
// Both low and high must be /32 CIDRs. Max 256 IPs.
func expandAddressRange(low, high string) ([]string, error) {
	lowCIDR := low
	if !strings.Contains(lowCIDR, "/") {
		lowCIDR += "/32"
	}
	highCIDR := high
	if !strings.Contains(highCIDR, "/") {
		highCIDR += "/32"
	}
	lowIP, _, err := net.ParseCIDR(lowCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid low address %q: %w", low, err)
	}
	highIP, _, err := net.ParseCIDR(highCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid high address %q: %w", high, err)
	}
	lowIP = lowIP.To4()
	highIP = highIP.To4()
	if lowIP == nil || highIP == nil {
		return nil, fmt.Errorf("address range only supports IPv4")
	}
	lowN := binary.BigEndian.Uint32(lowIP)
	highN := binary.BigEndian.Uint32(highIP)
	if lowN > highN {
		return nil, fmt.Errorf("low address %s > high address %s", low, high)
	}
	count := highN - lowN + 1
	if count > 256 {
		return nil, fmt.Errorf("address range too large: %d IPs (max 256)", count)
	}
	var result []string
	buf := make(net.IP, 4)
	for i := uint32(0); i < count; i++ {
		binary.BigEndian.PutUint32(buf, lowN+i)
		result = append(result, buf.String()+"/32")
	}
	return result, nil
}

func compileNATSource(node *Node, sec *SecurityConfig) error {
	// Global flags
	if node.FindChild("address-persistent") != nil {
		sec.NAT.AddressPersistent = true
	}

	// Parse source NAT pools
	for _, inst := range namedInstances(node.FindChildren("pool")) {
		pool := &NATPool{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "address":
				// Check for address range: "addr1 to addr2"
				if len(prop.Keys) >= 4 && prop.Keys[2] == "to" {
					expanded, err := expandAddressRange(prop.Keys[1], prop.Keys[3])
					if err != nil {
						return fmt.Errorf("pool %q address range: %w", pool.Name, err)
					}
					pool.Addresses = append(pool.Addresses, expanded...)
				} else if len(prop.Keys) >= 2 && prop.Keys[1] != "" {
					// Inline value form ("address <prefix>;" / flat set).
					// Deliberately NOT nodeVal: its Children[0] fallback
					// would double-append the block form, whose children
					// are walked below (#1808).
					pool.Addresses = append(pool.Addresses, prop.Keys[1])
				}
				// Also handle children for hierarchical syntax
				for _, addrChild := range prop.Children {
					if len(addrChild.Keys) >= 3 && addrChild.Keys[1] == "to" {
						expanded, err := expandAddressRange(addrChild.Keys[0], addrChild.Keys[2])
						if err != nil {
							return fmt.Errorf("pool %q address range: %w", pool.Name, err)
						}
						pool.Addresses = append(pool.Addresses, expanded...)
					} else if addrChild.IsLeaf && len(addrChild.Keys) >= 1 {
						pool.Addresses = append(pool.Addresses, addrChild.Keys[0])
					}
				}
			case "port":
				// "port range low N high M" or "port N"
				if len(prop.Keys) >= 6 && prop.Keys[1] == "range" &&
					prop.Keys[2] == "low" && prop.Keys[4] == "high" {
					if v, err := strconv.Atoi(prop.Keys[3]); err == nil {
						pool.PortLow = v
					}
					if v, err := strconv.Atoi(prop.Keys[5]); err == nil {
						pool.PortHigh = v
					}
				} else if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						pool.PortLow = n
						pool.PortHigh = n
					}
				}
				// Check for deterministic port config (hierarchical)
				for _, portChild := range prop.Children {
					if portChild.Name() == "deterministic" {
						detCfg := &DeterministicNATConfig{}
						for _, detProp := range portChild.Children {
							switch detProp.Name() {
							case "block-size":
								if v := nodeVal(detProp); v != "" {
									if n, err := strconv.Atoi(v); err == nil {
										detCfg.BlockSize = n
									}
								}
							case "host":
								// "host address 100.64.0.0/22"
								if len(detProp.Keys) >= 3 && detProp.Keys[1] == "address" {
									detCfg.HostAddress = detProp.Keys[2]
								} else if v := nodeVal(detProp); v != "" {
									detCfg.HostAddress = v
								}
								for _, hc := range detProp.Children {
									if hc.Name() == "address" {
										if v := nodeVal(hc); v != "" {
											detCfg.HostAddress = v
										}
									}
								}
							}
						}
						pool.Deterministic = detCfg
					}
				}
				// Flat set: "port deterministic block-size 2016"
				if len(prop.Keys) >= 2 && prop.Keys[1] == "deterministic" {
					detCfg := &DeterministicNATConfig{}
					for i := 2; i < len(prop.Keys); i++ {
						if prop.Keys[i] == "block-size" && i+1 < len(prop.Keys) {
							if n, err := strconv.Atoi(prop.Keys[i+1]); err == nil {
								detCfg.BlockSize = n
							}
						}
					}
					// host address from children
					for _, portChild := range prop.Children {
						if portChild.Name() == "host" {
							if len(portChild.Keys) >= 3 && portChild.Keys[1] == "address" {
								detCfg.HostAddress = portChild.Keys[2]
							}
							for _, hc := range portChild.Children {
								if hc.Name() == "address" {
									if v := nodeVal(hc); v != "" {
										detCfg.HostAddress = v
									}
								}
							}
						}
					}
					pool.Deterministic = detCfg
				}
			case "persistent-nat":
				// #2823: default is target-host-port (the pre-#2823
				// false-flag (dst_ip, dst_port) keying) so a config that
				// configures persistent-nat with no explicit permit keeps
				// the #2819 behavior byte-identical.
				pnat := &PersistentNATConfig{
					InactivityTimeout: 300,
					Permit:            PersistentNATPermitTargetHostPort,
				}
				parsePermit := func(v string) {
					switch v {
					case "any-remote-host":
						pnat.Permit = PersistentNATPermitAnyRemoteHost
					case "target-host":
						pnat.Permit = PersistentNATPermitTargetHost
					case "target-host-port":
						pnat.Permit = PersistentNATPermitTargetHostPort
					}
				}
				// Flat-set shape: persistent-nat collapses trailing tokens
				// onto Keys (e.g. ["persistent-nat","permit","target-host"]
				// or ["persistent-nat","inactivity-timeout","600"]).
				for i := 1; i+1 < len(prop.Keys); i++ {
					switch prop.Keys[i] {
					case "permit":
						parsePermit(prop.Keys[i+1])
					case "inactivity-timeout":
						if n, err := strconv.Atoi(prop.Keys[i+1]); err == nil {
							pnat.InactivityTimeout = n
						}
					}
				}
				// Hierarchical / schema-grouped shape: permit and
				// inactivity-timeout arrive as child leaves.
				for _, pnProp := range prop.Children {
					switch pnProp.Name() {
					case "permit":
						if v := nodeVal(pnProp); v != "" {
							parsePermit(v)
						}
					case "inactivity-timeout":
						if v := nodeVal(pnProp); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								pnat.InactivityTimeout = n
							}
						}
					}
				}
				pool.PersistentNAT = pnat
			}
		}
		if pool.PortLow == 0 {
			pool.PortLow = 1024
		}
		if pool.PortHigh == 0 {
			pool.PortHigh = 65535
		}
		sec.NAT.SourcePools[pool.Name] = pool
	}

	// Parse pool-utilization-alarm
	if alarmNode := node.FindChild("pool-utilization-alarm"); alarmNode != nil {
		alarm := &PoolUtilizationAlarmConfig{}
		for _, ap := range alarmNode.Children {
			switch ap.Name() {
			case "raise-threshold":
				if v := nodeVal(ap); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						alarm.RaiseThreshold = n
					}
				}
			case "clear-threshold":
				if v := nodeVal(ap); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						alarm.ClearThreshold = n
					}
				}
			}
		}
		// Also handle flat keys: pool-utilization-alarm raise-threshold 80 clear-threshold 70
		for i := 1; i < len(alarmNode.Keys); i++ {
			if alarmNode.Keys[i] == "raise-threshold" && i+1 < len(alarmNode.Keys) {
				if n, err := strconv.Atoi(alarmNode.Keys[i+1]); err == nil {
					alarm.RaiseThreshold = n
				}
			}
			if alarmNode.Keys[i] == "clear-threshold" && i+1 < len(alarmNode.Keys) {
				if n, err := strconv.Atoi(alarmNode.Keys[i+1]); err == nil {
					alarm.ClearThreshold = n
				}
			}
		}
		sec.NAT.PoolUtilizationAlarm = alarm
	}

	// Validate deterministic NAT pools
	for _, pool := range sec.NAT.SourcePools {
		if pool.Deterministic == nil {
			continue
		}
		det := pool.Deterministic
		if det.BlockSize <= 0 {
			return fmt.Errorf("pool %q: deterministic block-size must be > 0", pool.Name)
		}
		if det.HostAddress == "" {
			return fmt.Errorf("pool %q: deterministic host address required", pool.Name)
		}
		_, hostNet, err := net.ParseCIDR(det.HostAddress)
		if err != nil {
			return fmt.Errorf("pool %q: invalid host address %q: %w", pool.Name, det.HostAddress, err)
		}
		ones, bits := hostNet.Mask.Size()
		portLow := pool.PortLow
		if portLow == 0 {
			portLow = 1024
		}
		portHigh := pool.PortHigh
		if portHigh == 0 {
			portHigh = 65535
		}
		portRange := portHigh - portLow + 1
		if det.BlockSize > portRange {
			return fmt.Errorf("pool %q: block-size %d exceeds port range %d", pool.Name, det.BlockSize, portRange)
		}
		blocksPerIP := portRange / det.BlockSize
		totalBlocks := len(pool.Addresses) * blocksPerIP

		if bits == 128 {
			// IPv6 host address — validate word-aligned prefix
			if ones != 32 && ones != 64 {
				return fmt.Errorf("pool %q: IPv6 host prefix must be /32 or /64, got /%d", pool.Name, ones)
			}
			// For IPv6, subscriber count is capped by pool capacity
			if totalBlocks == 0 {
				return fmt.Errorf("pool %q: insufficient capacity (0 blocks) for IPv6 deterministic NAT", pool.Name)
			}
		} else {
			// IPv4 host address
			hostCount := 1 << uint(bits-ones)
			if totalBlocks < hostCount {
				return fmt.Errorf("pool %q: insufficient capacity (%d blocks) for %d subscribers", pool.Name, totalBlocks, hostCount)
			}
		}
		if pool.PersistentNAT != nil {
			return fmt.Errorf("pool %q: deterministic and persistent-nat are mutually exclusive", pool.Name)
		}
		if sec.NAT.AddressPersistent {
			return fmt.Errorf("pool %q: deterministic and address-persistent are mutually exclusive", pool.Name)
		}
	}

	// #2079: pool-utilization-alarm threshold validation is NOT performed
	// here — it is a strict-vs-lenient gate (validatePoolUtilizationAlarm,
	// compiler.go typed-config phase) so the strict commit path hard-rejects
	// while the tolerant load/peer-sync path WARNS. Doing it here would hard-
	// fail CompileConfigLenient and brick a daemon restart on a legacy config
	// that was committed before #2079 added validation (#1979 doctrine).

	// Parse source NAT rule-sets
	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
		// Parse from/to zones (bracket lists produce multiple keys)
		var fromZones, toZones []string
		for _, child := range rsInst.node.Children {
			if child.Name() == "from" {
				fromZones = append(fromZones, parseZoneList(child)...)
			}
			if child.Name() == "to" {
				toZones = append(toZones, parseZoneList(child)...)
			}
		}
		if len(fromZones) == 0 {
			fromZones = []string{""}
		}
		if len(toZones) == 0 {
			toZones = []string{""}
		}

		// Parse rules (shared across all zone-pair expansions)
		var rules []*NATRule
		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
			rule := &NATRule{Name: ruleInst.name}

			matchNode := ruleInst.node.FindChild("match")
			if matchNode != nil {
				for _, m := range matchNode.Children {
					switch m.Name() {
					case "source-address":
						// Support bracket lists: source-address [ addr1 addr2 ... ]
						if len(m.Keys) >= 2 {
							rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, child.Name())
							}
						}
						if len(rule.Match.SourceAddresses) > 0 {
							rule.Match.SourceAddress = rule.Match.SourceAddresses[0]
						}
					case "source-address-name":
						// #2416: address-book reference; resolved to prefixes at
						// snapshot-build time (appendNATSourceAddressName).
						rule.Match.SourceAddressName = nodeVal(m)
					case "destination-address":
						// Support bracket lists: destination-address [ addr1 addr2 ... ]
						if len(m.Keys) >= 2 {
							rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, child.Name())
							}
						}
						if len(rule.Match.DestinationAddresses) > 0 {
							rule.Match.DestinationAddress = rule.Match.DestinationAddresses[0]
						} else {
							rule.Match.DestinationAddress = nodeVal(m)
						}
					case "destination-port":
						if len(m.Children) > 0 {
							for _, child := range m.Children {
								if n, err := strconv.Atoi(child.Name()); err == nil {
									rule.Match.DestinationPorts = append(rule.Match.DestinationPorts, n)
									if rule.Match.DestinationPort == 0 {
										rule.Match.DestinationPort = n
									}
								}
							}
						} else if v := nodeVal(m); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								rule.Match.DestinationPort = n
								rule.Match.DestinationPorts = append(rule.Match.DestinationPorts, n)
							}
						}
					case "application":
						rule.Match.Application = nodeVal(m)
					}
				}
			}

			thenNode := ruleInst.node.FindChild("then")
			if thenNode != nil {
				for _, t := range thenNode.Children {
					if t.Name() == "source-nat" {
						if len(t.Keys) >= 2 {
							switch t.Keys[1] {
							case "interface":
								rule.Then.Type = NATSource
								rule.Then.Interface = true
							case "off":
								rule.Then.Type = NATSource
								rule.Then.Off = true
							case "pool":
								rule.Then.Type = NATSource
								if len(t.Keys) >= 3 {
									rule.Then.PoolName = t.Keys[2]
								}
							}
						} else if t.FindChild("interface") != nil {
							rule.Then.Type = NATSource
							rule.Then.Interface = true
						} else if t.FindChild("off") != nil {
							rule.Then.Type = NATSource
							rule.Then.Off = true
						} else if poolNode := t.FindChild("pool"); poolNode != nil {
							rule.Then.Type = NATSource
							rule.Then.PoolName = nodeVal(poolNode)
						}
					}
				}
			}

			rules = append(rules, rule)
		}

		// Expand Cartesian product of from-zones × to-zones
		for _, fz := range fromZones {
			for _, tz := range toZones {
				rs := &NATRuleSet{
					Name:     rsInst.name,
					FromZone: fz,
					ToZone:   tz,
					Rules:    rules,
				}
				sec.NAT.Source = append(sec.NAT.Source, rs)
			}
		}
	}
	return nil
}

func compileNATDestination(node *Node, sec *SecurityConfig) error {
	if sec.NAT.Destination == nil {
		sec.NAT.Destination = &DestinationNATConfig{
			Pools: make(map[string]*NATPool),
		}
	}

	// Parse pools
	for _, inst := range namedInstances(node.FindChildren("pool")) {
		pool := &NATPool{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "address":
				pool.Address = nodeVal(prop)
			case "port":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						pool.Port = n
					}
				}
			}
		}

		sec.NAT.Destination.Pools[pool.Name] = pool
	}

	// Parse rule-sets
	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
		// Parse from/to zones (bracket lists produce multiple keys)
		var fromZones, toZones []string
		for _, child := range rsInst.node.Children {
			if child.Name() == "from" {
				fromZones = append(fromZones, parseZoneList(child)...)
			}
			if child.Name() == "to" {
				toZones = append(toZones, parseZoneList(child)...)
			}
		}
		if len(fromZones) == 0 {
			fromZones = []string{""}
		}
		if len(toZones) == 0 {
			toZones = []string{""}
		}

		var rules []*NATRule
		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
			rule := &NATRule{Name: ruleInst.name}

			matchNode := ruleInst.node.FindChild("match")
			if matchNode != nil {
				for _, m := range matchNode.Children {
					switch m.Name() {
					case "destination-address":
						// Support bracket lists: destination-address [ addr1 addr2 ... ]
						if len(m.Keys) >= 2 {
							rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.Match.DestinationAddresses = append(rule.Match.DestinationAddresses, child.Name())
							}
						}
						if len(rule.Match.DestinationAddresses) > 0 {
							rule.Match.DestinationAddress = rule.Match.DestinationAddresses[0]
						} else {
							rule.Match.DestinationAddress = nodeVal(m)
						}
					case "destination-port":
						rule.Match.DestinationPorts = append(rule.Match.DestinationPorts, parseDNATPortList(m)...)
						if rule.Match.DestinationPort == 0 && len(rule.Match.DestinationPorts) > 0 {
							rule.Match.DestinationPort = rule.Match.DestinationPorts[0]
						}
					case "source-address":
						// Support bracket lists: source-address [ addr1 addr2 ... ]
						if len(m.Keys) >= 2 {
							rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, m.Keys[1:]...)
						} else if len(m.Children) > 0 {
							for _, child := range m.Children {
								rule.Match.SourceAddresses = append(rule.Match.SourceAddresses, child.Name())
							}
						}
						if len(rule.Match.SourceAddresses) > 0 {
							rule.Match.SourceAddress = rule.Match.SourceAddresses[0]
						}
					case "source-address-name":
						rule.Match.SourceAddressName = nodeVal(m)
					case "protocol":
						rule.Match.Protocol = nodeVal(m)
					case "application":
						rule.Match.Application = nodeVal(m)
					}
				}
			}

			thenNode := ruleInst.node.FindChild("then")
			if thenNode != nil {
				for _, t := range thenNode.Children {
					if t.Name() == "destination-nat" {
						if len(t.Keys) >= 3 && t.Keys[1] == "pool" {
							rule.Then.Type = NATDestination
							rule.Then.PoolName = t.Keys[2]
						} else if poolNode := t.FindChild("pool"); poolNode != nil {
							rule.Then.Type = NATDestination
							rule.Then.PoolName = nodeVal(poolNode)
						}
					}
				}
			}

			rules = append(rules, rule)
		}

		// Expand Cartesian product of from-zones × to-zones
		for _, fz := range fromZones {
			for _, tz := range toZones {
				rs := &NATRuleSet{
					Name:     rsInst.name,
					FromZone: fz,
					ToZone:   tz,
					Rules:    rules,
				}
				sec.NAT.Destination.RuleSets = append(sec.NAT.Destination.RuleSets, rs)
			}
		}
	}
	return nil
}

// parseDNATPortList extracts destination ports from a destination-port node.
// Handles single port, multiple ports as children, and port ranges ("20000 to 30000").
// AST shapes handled:
//   - Hierarchical multi-port: destination-port { 80; 443; 20000 to 30000; }
//   - Single port leaf: destination-port 8080;
//   - Set syntax range: destination-port 20000 { to 30000; } (args=1 consumes low, "to N" is child)
func parseDNATPortList(m *Node) []int {
	var ports []int
	// Unified single-leaf shape (#2419): both the hierarchical parser and
	// the flat-set SetPath now collapse a bracket list or a `low to high`
	// range onto the node's own keys, with NO children:
	//   destination-port [ 80 443 ]        → Keys=[destination-port 80 443]
	//   destination-port 20000 to 20003     → Keys=[destination-port 20000 to 20003]
	// Parse the trailing key tokens directly. A `to` token between two
	// numbers is a range; everything else is an individual port.
	if len(m.Children) == 0 && len(m.Keys) >= 2 {
		vals := m.Keys[1:]
		for i := 0; i < len(vals); i++ {
			low, err := strconv.Atoi(vals[i])
			if err != nil {
				continue
			}
			if i+2 < len(vals) && vals[i+1] == "to" {
				if high, err2 := strconv.Atoi(vals[i+2]); err2 == nil && high >= low {
					for p := low; p <= high; p++ {
						ports = append(ports, p)
					}
					i += 2
					continue
				}
			}
			ports = append(ports, low)
		}
		return ports
	}
	if len(m.Children) > 0 {
		// Check for set-syntax port range: Keys=["destination-port","20000"] + child "to 30000"
		if len(m.Keys) >= 2 {
			if low, err := strconv.Atoi(m.Keys[1]); err == nil {
				// Look for "to" child indicating a range
				toChild := m.FindChild("to")
				if toChild != nil {
					if high, err2 := strconv.Atoi(nodeVal(toChild)); err2 == nil && high >= low {
						for p := low; p <= high; p++ {
							ports = append(ports, p)
						}
						return ports
					}
				}
				// No range — just a port with non-range children (shouldn't happen, but be safe)
				ports = append(ports, low)
			}
		}
		// Multiple ports/ranges as children: destination-port { 80; 443; 20000 to 30000; }
		for i := 0; i < len(m.Children); i++ {
			child := m.Children[i]
			low, err := strconv.Atoi(child.Name())
			if err != nil {
				continue
			}
			// Hierarchical range: "20000 to 30000" → leaf Keys=["20000", "to", "30000"]
			if len(child.Keys) >= 3 && child.Keys[1] == "to" {
				if high, err2 := strconv.Atoi(child.Keys[2]); err2 == nil && high >= low {
					for p := low; p <= high; p++ {
						ports = append(ports, p)
					}
					continue
				}
			}
			// Sibling-node range: child[i]="20000", child[i+1]="to", child[i+2]="30000"
			if i+2 < len(m.Children) && m.Children[i+1].Name() == "to" {
				if high, err2 := strconv.Atoi(m.Children[i+2].Name()); err2 == nil && high >= low {
					for p := low; p <= high; p++ {
						ports = append(ports, p)
					}
					i += 2
					continue
				}
			}
			ports = append(ports, low)
		}
	} else if v := nodeVal(m); v != "" {
		// Single port: destination-port 8080;
		if n, err := strconv.Atoi(v); err == nil {
			ports = append(ports, n)
		}
	}
	return ports
}

// staticNATMappedPortFromKeys extracts the `mapped-port <port>` modifier
// from a flat-set static-NAT leaf's collapsed Keys (#2491). The lexer
// collapses `then static-nat prefix <ip> mapped-port <port>` onto one node
// whose Keys are `["static-nat","prefix","<ip>","mapped-port","<port>"]`
// because `static-nat` is a children:nil schema leaf. Returns 0 (no port
// translation) when the keyword is absent or its value is non-numeric;
// the schema does not yet range-check this in-leaf token, so the caller's
// dataplane parse fails closed on an out-of-range value.
func staticNATMappedPortFromKeys(keys []string) int {
	for i := 0; i+1 < len(keys); i++ {
		if keys[i] == "mapped-port" {
			if p, err := strconv.Atoi(keys[i+1]); err == nil {
				return p
			}
			return 0
		}
	}
	return 0
}

func compileNATStatic(node *Node, sec *SecurityConfig) error {
	for _, rsInst := range namedInstances(node.FindChildren("rule-set")) {
		// Parse from zones (bracket lists produce multiple keys)
		var fromZones []string
		for _, child := range rsInst.node.Children {
			if child.Name() == "from" {
				fromZones = append(fromZones, parseZoneList(child)...)
			}
		}
		if len(fromZones) == 0 {
			fromZones = []string{""}
		}

		// Parse rules (shared across all zone expansions)
		var rules []*StaticNATRule
		for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
			rule := &StaticNATRule{Name: ruleInst.name}

			matchNode := ruleInst.node.FindChild("match")
			if matchNode != nil {
				for _, m := range matchNode.Children {
					switch m.Name() {
					case "destination-address":
						rule.Match = nodeVal(m)
					case "source-address":
						rule.SourceAddress = nodeVal(m)
					case "destination-port":
						// #2491: external (pre-translation) destination
						// port the inbound packet must carry. Schema
						// already range-checks 1..65535; tolerate a
						// non-numeric value defensively (leave 0 = any).
						if p, err := strconv.Atoi(nodeVal(m)); err == nil {
							rule.MatchDestinationPort = p
						}
					}
				}
			}

			thenNode := ruleInst.node.FindChild("then")
			if thenNode != nil {
				for _, t := range thenNode.Children {
					if t.Name() == "static-nat" {
						if len(t.Keys) >= 3 && t.Keys[1] == "nptv6-prefix" {
							// set ... then static-nat nptv6-prefix PREFIX
							rule.Then = t.Keys[2]
							rule.IsNPTv6 = true
						} else if np := t.FindChild("nptv6-prefix"); np != nil {
							// static-nat { nptv6-prefix { PREFIX; } }
							rule.Then = nodeVal(np)
							rule.IsNPTv6 = true
						} else if len(t.Keys) >= 3 && t.Keys[1] == "prefix" {
							rule.Then = t.Keys[2]
							// #2491: optional trailing `mapped-port <port>`.
							// Flat-set collapses the whole `prefix <ip>
							// mapped-port <port>` onto this one leaf's Keys
							// (`static-nat` is a children:nil schema leaf), so
							// scan for the keyword + value pair.
							rule.MappedPort = staticNATMappedPortFromKeys(t.Keys)
						} else if pn := t.FindChild("prefix"); pn != nil {
							rule.Then = nodeVal(pn)
							// #2491: `then static-nat prefix <ip> mapped-port
							// <port>` collapses onto the `prefix` child's Keys
							// (`["prefix","<ip>","mapped-port","<port>"]`)
							// because `static-nat` is a children:nil schema
							// leaf, so the modifier rides on the prefix leaf,
							// not a sibling `mapped-port` node. Scan pn.Keys.
							rule.MappedPort = staticNATMappedPortFromKeys(pn.Keys)
							// Hierarchical shape `static-nat { prefix X;
							// mapped-port P; }` carries it as a sibling child.
							if rule.MappedPort == 0 {
								if mp := t.FindChild("mapped-port"); mp != nil {
									if p, err := strconv.Atoi(nodeVal(mp)); err == nil {
										rule.MappedPort = p
									}
								}
							}
						} else if t.FindChild("inet") != nil || (len(t.Keys) >= 2 && t.Keys[1] == "inet") {
							// static-nat { inet; } — NAT64 translation
							rule.Then = "inet"
						}
					}
				}
			}

			rules = append(rules, rule)
		}

		// Expand for each from-zone
		for _, fz := range fromZones {
			rs := &StaticNATRuleSet{
				Name:     rsInst.name,
				FromZone: fz,
				Rules:    rules,
			}
			sec.NAT.Static = append(sec.NAT.Static, rs)
		}
	}
	return nil
}
