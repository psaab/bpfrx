package config

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// validateNATMatchApplicationsStrict hard-rejects a source- or
// destination-NAT rule's `match application <name>` token that resolves to
// NONE of: a predefined junos-* application, a user-defined `applications
// application <name>`, or a non-empty user-defined `applications
// application-set <name>` (#3434, Codex audit 095 H07/H08). It is the NAT
// analog of validatePolicyMatchApplicationsStrict (#3144/#3146).
//
// A NAT `match application` consumes the referenced application's
// protocol/port the same way a policy match does (the SNAT/DNAT snapshot
// builders in pkg/dataplane/userspace/nat.go resolve it via
// ResolveApplication / ExpandApplicationSet). When the token is a typo /
// dangling reference (H07) or a defined-but-EMPTY application-set (H08), the
// reference resolves to ZERO application terms — and the DNAT builder then
// fell THROUGH to its explicit-match fallback (protocol="" + destination-port
// 0), publishing the pool VIP for EVERY flow to the destination (a fail-open
// wildcard translation). The dataplane backstop now substitutes a never-match
// term on that path (the source-NAT buildSourceNATAppTerms natProtoNever term,
// and the destination-NAT natNeverMatchPortRange source-port sentinel), but
// the operator still got a green commit for a NAT rule that quietly fails
// closed. Failing the unresolved reference at commit turns that silent break
// into an operator-visible error.
//
// Resolution mirrors the snapshot builders EXACTLY (ResolveApplication, which
// checks user apps then the predefined table, plus ResolveApplicationSet +
// ExpandApplicationSet) so the commit gate and the dataplane cannot diverge.
// The `any` keyword and the empty token are always accepted (they mean
// "unconstrained" and the builders short-circuit them to no terms). Static NAT
// carries no application match, so only source and destination NAT rule-sets
// are walked.
//
// Strict on commit / commit-check (hard reject naming the NAT kind, rule-set,
// rule, and the undefined app); lenient on load / peer-sync (warn — #1960; the
// dataplane independently fails the rule closed, so a leniently-loaded bad
// config is no worse off, now flagged). Same doctrine as
// lenientPolicyMatchApplications.
func validateNATMatchApplicationsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// appRefError returns nil if the token resolves, or a tailored reject.
	// Resolution mirrors the SNAT/DNAT snapshot builders: a name resolves only
	// if it is a predefined / user application OR an application-set that
	// EXPANDS to >= 1 member. A defined-but-EMPTY application-set resolves by
	// NAME but expands to zero members -> the builder produces a never-match
	// term (H08).
	appRefError := func(natKind, ruleSet, ruleName, name string) error {
		switch name {
		case "", "any":
			return nil
		}
		if _, ok := ResolveApplication(name, cfg.Applications.Applications); ok {
			return nil
		}
		if _, ok := ResolveApplicationSet(name, cfg.Applications.ApplicationSets); ok {
			expanded, err := ExpandApplicationSet(name, &cfg.Applications)
			if err == nil && len(expanded) == 0 {
				return natMatchEmptyAppSetError(natKind, ruleSet, ruleName, name)
			}
			return nil
		}
		return natMatchApplicationError(natKind, ruleSet, ruleName, name)
	}
	checkRuleSet := func(natKind string, rs *NATRuleSet) error {
		if rs == nil {
			return nil
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			// #3431: validate EVERY application in a bracket list / repeated
			// `match application [ a b ]`, not just the first. The parser used
			// to collapse the list to one value, so a trailing typo was never
			// reached by this gate.
			for _, app := range rule.Match.ApplicationList() {
				if err := appRefError(natKind, rs.Name, rule.Name, app); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, rs := range cfg.Security.NAT.Source {
		if err := checkRuleSet("source", rs); err != nil {
			return err
		}
	}
	if cfg.Security.NAT.Destination != nil {
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			if err := checkRuleSet("destination", rs); err != nil {
				return err
			}
		}
	}
	return nil
}

// natMatchApplicationError formats the #3434 H07 reject for a NAT rule whose
// `match application` names neither a predefined/user application nor an
// application-set.
func natMatchApplicationError(natKind, ruleSet, ruleName, app string) error {
	return fmt.Errorf(
		"%s NAT rule-set %q rule %q match application %q resolves to no "+
			"predefined application, user-defined application, or "+
			"application-set (a typo or undefined application disarms the NAT "+
			"match and the dataplane falls open to a wildcard translation) — "+
			"define the application or fix the reference (#3434)",
		natKind, ruleSet, ruleName, app)
}

// natMatchEmptyAppSetError formats the #3434 H08 reject for a NAT rule
// referencing a DEFINED but EMPTY application-set. The set exists by name but
// expands to zero members, so the snapshot builder produces a never-match term
// and the rule quietly matches nothing — the NAT sibling of #3146.
func natMatchEmptyAppSetError(natKind, ruleSet, ruleName, name string) error {
	return fmt.Errorf(
		"%s NAT rule-set %q rule %q match application %q is a defined but "+
			"EMPTY application-set (it expands to zero applications) — the rule "+
			"commits but the dataplane installs a never-match term so the "+
			"translation never fires — add at least one `applications "+
			"application-set %q application <name>` member or remove the "+
			"reference (#3434)",
		natKind, ruleSet, ruleName, name, name)
}

// validateDestinationNATAddressesStrict (#2396(c)) hard-rejects a
// destination-NAT rule whose `match destination-address` resolves to NO
// parseable host IP — i.e. the rule HAS a destination match (singular or
// bracket-list) but EVERY configured token fails to parse as a bare IP after
// any CIDR mask is stripped.
//
// The DNAT snapshot builder (buildDestinationNATSnapshots, #2395) strips the
// CIDR suffix from each destination and SKIPS any token where
// `net.ParseIP(stripped) == nil`; the Rust DNAT table (DnatTable::from_snapshots)
// independently `continue`s on a destination it cannot parse. So a rule whose
// destinations are all malformed emits NO table entry and silently translates
// NOTHING — it compiled and committed, but is inert, with no operator feedback.
// This is the #2396(c) silent-drop. Surfacing it at commit / commit-check turns
// a fat-fingered "the only destination is a typo" into a visible error.
//
// Acceptance MUST match the builder's exactly: a token is "good" iff, after
// stripping a trailing `/mask`, the remainder parses with net.ParseIP. A rule
// with NO destination match at all is out of scope (it never reaches the
// builder's per-destination loop). A rule with at least one good destination is
// fine even if others are malformed (the builder emits entries for the good
// ones and skips the rest — partial, but not a silent total no-op).
//
// Reported deterministically: rule-sets are walked in sorted name order and
// rules in their configured order, so the first-reported offender is stable.
// The caller downgrades the error to a warning on the tolerant load / peer-sync
// path (#1960 no-brick): a config persisted before this gate existed still
// boots, and the dataplane drops the inert rule on its own.
func validateDestinationNATAddressesStrict(cfg *Config) error {
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		return nil
	}
	rulesets := append([]*NATRuleSet(nil), cfg.Security.NAT.Destination.RuleSets...)
	sort.SliceStable(rulesets, func(i, j int) bool {
		if rulesets[i] == nil || rulesets[j] == nil {
			return rulesets[i] != nil
		}
		return rulesets[i].Name < rulesets[j].Name
	})
	for _, rs := range rulesets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			// Mirror the builder's destination-address gathering: prefer the
			// bracket-list form, fall back to the singular match value.
			destAddrs := append([]string(nil), rule.Match.DestinationAddresses...)
			if len(destAddrs) == 0 && rule.Match.DestinationAddress != "" {
				destAddrs = append(destAddrs, rule.Match.DestinationAddress)
			}
			if len(destAddrs) == 0 {
				// No destination match at all — out of scope.
				continue
			}
			// #3228: reject the rule if ANY listed destination-address is
			// unparseable, not just when they ALL are. The snapshot builder
			// (buildDestinationNATSnapshots) strips the CIDR suffix and then
			// per-entry `continue`s past any token that is empty or fails
			// net.ParseIP — silently dropping it from the installed DNAT
			// table. A mixed list such as `[ 192.0.2.1 web-server ]` would
			// otherwise commit clean (the old anyGood break) while
			// `web-server` never translates. Mirror the builder's exact skip
			// predicate (CIDR strip via natCIDRIPPart, then empty/ParseIP
			// check) so the validator rejects precisely what the builder
			// would drop: validator and dataplane view agree, and an
			// all-valid list still compiles byte-identical.
			for _, raw := range destAddrs {
				ipPart := natCIDRIPPart(raw)
				if ipPart == "" || net.ParseIP(ipPart) == nil {
					return fmt.Errorf(
						"destination-nat rule-set %q rule %q: match destination-address "+
							"%q is not a valid IP/CIDR; the rule would commit but the "+
							"dataplane silently drops the malformed entry, leaving traffic "+
							"to it untranslated (full list: %s)",
						rs.Name, rule.Name, raw, strings.Join(destAddrs, ", "))
				}
			}
			// #3164: a DNAT `match destination-address` that is a MULTI-HOST
			// prefix (a CIDR with a non-host mask, e.g. 198.51.100.0/24) is now
			// HONORED. The snapshot builder (buildDestinationNATSnapshots) carries
			// the canonical prefix to the wire (DestinationPrefix) and the Rust
			// DnatTable installs a longest-prefix-match entry so every host in the
			// block is translated to the rule's pool. The #3029 reject that
			// previously fired here (fail-closed against silent narrowing) is gone
			// — the narrowing no longer exists. Block-mapping semantics (1:1
			// offset host-N->host-N) remain out of scope: a prefix destination is
			// a many:1 match to the configured pool, matching the documented
			// scope of #3164.
		}
	}
	return nil
}

// dnatProtocolResolvable reports whether a DNAT `match protocol` token is one
// the userspace dataplane can resolve for the DNAT match path. The DNAT path
// emits the token VERBATIM (no junos-* pre-resolution); normalization (trim +
// lower-case) matches proto_number exactly.
//
// This is a deliberately-tighter SSOT than the Rust ip_proto::proto_number
// resolver — it is NOT a 1:1 mirror of it. It is tighter in TWO ways:
//
//  1. junos-* aliases: proto_number resolves them (for the filter/application
//     paths), but the raw DNAT match-protocol path never pre-resolves them, so
//     accepting a junos-* token here would re-introduce the #2396 silent drop.
//
//  2. ipv6 (IANA protocol 41): proto_number was widened in #3393 to resolve the
//     "ipv6" name (so a firewall filter's `from protocol ipv6` round-trips),
//     but DNAT match-protocol intentionally EXCLUDES it — matching on the IPv6
//     encapsulation protocol number is not a meaningful DNAT destination-rule
//     selector here. So `match protocol ipv6` is rejected at commit even though
//     proto_number would resolve it. (filterProtocolResolvable / the appid
//     SSOT accept "ipv6"; DNAT does not — that divergence is by design.)
//
// Empty ("" = any protocol) is the IP-only wildcard and is always resolvable.
func dnatProtocolResolvable(token string) bool {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "",
		"tcp", "udp",
		"icmp", "icmp6", "icmpv6",
		"gre", "ospf", "ipip",
		"egp", "igmp", "pim",
		"ah", "esp", "sctp", "vrrp":
		return true
	default:
		if n, err := strconv.Atoi(strings.TrimSpace(token)); err == nil && n >= 0 && n < 256 {
			return true
		}
		return false
	}
}

// DNATProtocolResolvable exposes dnatProtocolResolvable for a cross-package
// drift-guard test that pins this acceptance set to its documented,
// deliberately-tighter relationship to the Rust proto_number SSOT (it excludes
// the junos-* aliases and "ipv6"/41 that proto_number resolves — see
// dnatProtocolResolvable). TEST seam, not a runtime coupling.
func DNATProtocolResolvable(token string) bool {
	return dnatProtocolResolvable(token)
}

// validateDestinationNATProtocolStrict (#2396 (a)/(3)) hard-rejects a DNAT rule
// whose `match protocol <token>` is not resolvable by the dataplane
// (dnatProtocolResolvable / proto_number). The token reaches the snapshot
// verbatim and the Rust table drops an unresolvable one with no apply failure,
// so an operator typo (`match protocol grre`) or a junos-* alias the DNAT path
// does not pre-resolve committed cleanly and silently translated nothing.
//
// Only the raw `match protocol` token is gated here. A protocol that comes from
// a resolved `match application` is validated separately by
// validateApplicationSpecsStrict (the application's own `protocol` leaf), so it
// is not re-checked. Rule-sets are walked in sorted name order and rules in
// configured order for a deterministic first-reported offender. The caller
// downgrades the error to a warning on the tolerant load / peer-sync path
// (#1960 no-brick).
func validateDestinationNATProtocolStrict(cfg *Config) error {
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		return nil
	}
	rulesets := append([]*NATRuleSet(nil), cfg.Security.NAT.Destination.RuleSets...)
	sort.SliceStable(rulesets, func(i, j int) bool {
		if rulesets[i] == nil || rulesets[j] == nil {
			return rulesets[i] != nil
		}
		return rulesets[i].Name < rulesets[j].Name
	})
	for _, rs := range rulesets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			// The raw match-protocol token is only emitted when the rule has no
			// application override (the builder prefers app terms). But gating it
			// regardless is correct: an unresolvable token can never be a valid
			// DNAT protocol, application override or not.
			//
			// #3431: validate EVERY protocol of a bracket list / repeated
			// `match protocol [ tcp udp ]`. The parser used to keep only the
			// first, so a bad trailing protocol committed silently AND only the
			// first protocol was ever published.
			for _, proto := range rule.Match.ProtocolList() {
				if !dnatProtocolResolvable(proto) {
					return fmt.Errorf(
						"destination-nat rule-set %q rule %q: match protocol %q is not a "+
							"resolvable protocol (known name or 0-255 number); the rule would "+
							"commit but never translate any traffic",
						rs.Name, rule.Name, proto)
				}
			}
		}
	}
	return nil
}

// validateNATMatchDestinationPortStrict (#3446) hard-rejects a source- or
// destination-NAT rule whose `match destination-port` carries a value the
// dataplane cannot honor: 0, a negative or >65535 number, or a non-numeric
// token (`http`). Static NAT already validates its typed `destination-port`
// leaf (#2491 / validateNATHostMaskStrict 1..65535); this closes the same gap
// for the source/destination NAT match grammar, whose parser used a bare
// strconv.Atoi with no bound check and whose builders cast straight to uint16
// (so 70000 wrapped to 4464, -1 to 65535) or collapsed an unparseable list to
// the wildcard port (translating EVERY port instead of failing closed).
//
// The compiled match carries two signals: DestinationPorts (every numeric
// token, including out-of-range ones) and InvalidDestinationPorts (the raw
// tokens that did not parse as integers — preserved by parseDNATPortList for
// exactly this gate). A 0/out-of-range number or any invalid token is an
// operator error that can never become a valid L4 port match.
//
// Strict on commit / commit-check (hard reject so the bad port is
// operator-visible); the compiler downgrades this to a warning on the tolerant
// load / peer-sync path (#1960 no-brick) — the snapshot builders independently
// fail CLOSED (coalescePortRanges / sourceNATDestPortRanges emit a never-match
// sentinel; the DNAT builder drops the rule rather than wildcarding), so a
// leniently-loaded bad rule installs nothing rather than over-translating.
// Rule-sets are walked in sorted name order, rules in configured order, for a
// deterministic first-reported offender.
func validateNATMatchDestinationPortStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(kind string, rulesets []*NATRuleSet) error {
		sorted := append([]*NATRuleSet(nil), rulesets...)
		sort.SliceStable(sorted, func(i, j int) bool {
			if sorted[i] == nil || sorted[j] == nil {
				return sorted[i] != nil
			}
			return sorted[i].Name < sorted[j].Name
		})
		for _, rs := range sorted {
			if rs == nil {
				continue
			}
			for _, rule := range rs.Rules {
				if rule == nil {
					continue
				}
				for _, p := range rule.Match.DestinationPorts {
					if p < 1 || p > 65535 {
						return fmt.Errorf(
							"%s-nat rule-set %q rule %q: match destination-port %d is out "+
								"of range (1-65535); the rule would commit but the dataplane "+
								"cannot install it as an L4 port match (the value wraps on a "+
								"uint16 cast or collapses to the wildcard port, translating "+
								"the wrong port or every port)",
							kind, rs.Name, rule.Name, p)
					}
				}
				if len(rule.Match.InvalidDestinationPorts) > 0 {
					return fmt.Errorf(
						"%s-nat rule-set %q rule %q: match destination-port %q is not a "+
							"numeric port (1-65535); the rule would commit but the bad token "+
							"is dropped and the port match collapses to the wildcard port "+
							"(translating every port instead of failing closed)",
						kind, rs.Name, rule.Name, rule.Match.InvalidDestinationPorts[0])
				}
				// #4422: a reversed range (high < low, e.g. `destination-port
				// 4000 to 3000`) is malformed — the parser splits it into its two
				// discrete endpoints, silently matching only those two ports
				// instead of the contiguous range the operator wrote. Reject it so
				// the miscompile is operator-visible at commit.
				if len(rule.Match.ReversedDestinationPortRanges) > 0 {
					return fmt.Errorf(
						"%s-nat rule-set %q rule %q: match destination-port %q is a "+
							"reversed range (low is greater than high); the rule would commit "+
							"but the parser splits it into the two discrete endpoints, matching "+
							"only those ports instead of the contiguous range — swap the "+
							"endpoints so low <= high",
						kind, rs.Name, rule.Name, rule.Match.ReversedDestinationPortRanges[0])
				}
			}
		}
		return nil
	}
	if err := check("source", cfg.Security.NAT.Source); err != nil {
		return err
	}
	if cfg.Security.NAT.Destination != nil {
		if err := check("destination", cfg.Security.NAT.Destination.RuleSets); err != nil {
			return err
		}
	}
	return nil
}

// validateDNATPoolStrict (#3450) hard-rejects a destination-NAT pool whose
// translated `port` or `address` the dataplane cannot honor as configured:
//
//   - M03/M04 port: the pool `port` parser used a bare strconv.Atoi with no
//     bound check and the snapshot builder cast straight to uint16, so `port
//     70000` wrapped to 4464 and `-1` to 65535 (translating to an unintended
//     backend port), while `port 0` / `port httpp` collapsed to Port==0 — which
//     the Rust DNAT path treats as "preserve the destination port", silently
//     no-op'ing the requested rewrite. PortRaw distinguishes a configured port
//     (which must be 1..65535) from no `port` leaf at all (Port==0 = the
//     legitimate preserve-port mode, left untouched).
//
//   - M05/M06 address: the builder strips any CIDR suffix and the Rust
//     DnatTable parses the remainder as a single host IpAddr, `continue`-ing
//     past anything it cannot parse. So `address 10.0.0.0/24` was coerced to
//     the network base 10.0.0.0 (no pool/range semantics — M05) and `address
//     web-server` (an address-book name) installed NO table entry, leaving the
//     VIP silently untranslated (M06). A DNAT pool address must therefore be a
//     single host the dataplane can install: a bare IP, /32, or /128
//     (isHostMaskAddress — the same predicate static NAT uses). An empty pool
//     address is also rejected: the builder skips it, so the rule is inert.
//
// Strict on commit / commit-check (hard reject so the bad value is operator-
// visible); the compiler downgrades this to a warning on the tolerant load /
// peer-sync path (#1960 no-brick) — the snapshot builder independently fails
// CLOSED (it skips the rule rather than wrapping the port or coercing the
// address), so a leniently-loaded bad pool installs nothing rather than
// translating wrongly. Pools are walked in sorted name order for a
// deterministic first-reported offender.
func validateDNATPoolStrict(cfg *Config) error {
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		return nil
	}
	pools := cfg.Security.NAT.Destination.Pools
	names := make([]string, 0, len(pools))
	for name := range pools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		pool := pools[name]
		if pool == nil {
			continue
		}
		// Port: only validate when a `port` leaf was actually configured.
		// No leaf (PortRaw == "") leaves Port == 0 = preserve-destination-port,
		// which is legitimate and untouched.
		if pool.PortRaw != "" {
			n, err := parseCanonicalPort(pool.PortRaw)
			if err != nil {
				return fmt.Errorf(
					"destination-nat pool %q: port %q is not a numeric port (1-65535); "+
						"the rule would commit but the bad token is dropped and the pool "+
						"port collapses to 0 (preserve destination port), silently "+
						"no-op'ing the requested rewrite",
					name, pool.PortRaw)
			}
			if n < 1 || n > 65535 {
				return fmt.Errorf(
					"destination-nat pool %q: port %d is out of range (1-65535); the rule "+
						"would commit but the value wraps on a uint16 cast (e.g. 70000->4464, "+
						"-1->65535) or collapses to 0 (preserve destination port), translating "+
						"to an unintended backend port or silently no-op'ing the rewrite",
					name, n)
			}
		}
		// Address: the dataplane needs a single host (bare IP, /32, or /128).
		if pool.Address == "" {
			return fmt.Errorf(
				"destination-nat pool %q: no translated address configured; the rule "+
					"would commit but the dataplane installs no entry, leaving matching "+
					"traffic untranslated", name)
		}
		if host, _ := isHostMaskAddress(pool.Address); !host {
			return fmt.Errorf(
				"destination-nat pool %q: address %q is not a single host address "+
					"(a bare IP, /32, or /128); the rule would commit but the dataplane "+
					"coerces a non-host CIDR to its network base (no pool/range semantics) "+
					"or drops an unparseable token (e.g. an address-book name), leaving "+
					"matching traffic translated to the wrong address or untranslated",
				name, pool.Address)
		}
	}
	return nil
}

// validateSourceNATPoolStrict (#3906) hard-rejects a source-NAT pool whose
// `port range <low> to <high>` the dataplane cannot honor as configured:
//
//   - a REVERSED range (low > high) — the Rust allocator marks the pool
//     unusable (SourceNatFailureReason::InvalidPortRange) and drops the rule at
//     runtime, so the config commits green then silently stops translating; and
//   - an OUT-OF-RANGE endpoint (low < 1 or high > 65535) — a port cannot live
//     outside 1..65535, and the u16 wire slot would wrap it.
//
// Before #3906 the pool `port range <low> to <high>` was parsed with the wrong
// keyword shape and silently ignored (the pool defaulted to 1024-65535 PAT), so
// an operator narrowing the pool to a specific range got the full default range
// and a reversed range was never caught. Only an EXPLICITLY configured range is
// validated: a pool with no `port` leaf keeps PortLow==0/PortHigh==0 (defaulted
// to 1024/65535 downstream) and is left untouched. A `port no-translation` pool
// preserves the source port and ignores the range entirely, so its (defaulted)
// range is not an error.
//
// Strict on commit / commit-check (hard-reject so the bad value is operator-
// visible); the compiler downgrades this to a warning on the tolerant load /
// peer-sync path (#1960 no-brick) — the snapshot builder independently fails
// CLOSED (sourceNATPoolPortRange returns !valid, marking the pool unusable), so
// a leniently-loaded bad range installs nothing rather than translating wrongly.
// Pools are walked in sorted name order for a deterministic first-reported
// offender.
func validateSourceNATPoolStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	pools := cfg.Security.NAT.SourcePools
	names := make([]string, 0, len(pools))
	for name := range pools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		pool := pools[name]
		if pool == nil {
			continue
		}
		// Only validate an EXPLICITLY configured range. No `port` leaf leaves
		// PortLow/PortHigh at 0 (defaulted to 1024/65535 downstream) — the
		// legitimate default-PAT mode, untouched.
		low := pool.PortLow
		high := pool.PortHigh
		if low == 0 && high == 0 {
			continue
		}
		if low < 1 || low > 65535 || high < 1 || high > 65535 {
			return fmt.Errorf(
				"source-nat pool %q: port range %d to %d is out of range (1-65535); "+
					"the rule would commit but the dataplane marks the pool unusable and "+
					"drops the rule at runtime, silently stopping translation",
				name, low, high)
		}
		if low > high {
			return fmt.Errorf(
				"source-nat pool %q: port range low %d is greater than high %d "+
					"(reversed); the rule would commit but the dataplane marks the pool "+
					"unusable and drops the rule at runtime, silently stopping translation",
				name, low, high)
		}
	}
	return nil
}

// validateNATSourceAddressNameReferencesStrict hard-rejects a source or
// destination NAT rule whose `match source-address-name <name>` OR `match
// destination-address-name <name>` (#3229) names an address-book entry that
// either is not defined under `security address-book` (#2416) OR is defined
// but does not resolve to >= 1 concrete address (#3425).
//
// The name is resolved to concrete prefixes at snapshot-build time
// (appendNATSourceAddressName → resolveNATAddressNamePrefixes →
// resolveUserspaceAddressBookEntry). Two distinct failures both translate to a
// rule that matches NOTHING (fail-closed but SILENT):
//
//   - a wholly UNDEFINED name (a typo) — neither an address-book entry nor a
//     dynamic-address feed binding; and
//   - a DEFINED-but-UNRESOLVABLE name (#3425) — a defined `address` with no
//     prefix (empty Value), a defined-but-EMPTY `address-set`, or a set with a
//     dangling / member-less expansion. resolveUserspaceAddressBookEntry
//     returns ok=false for these, so the builder appends the raw (unparseable)
//     token to keep the constraint non-empty and the rule translates no
//     traffic — exactly the policy-address fail-open class #3149 closes for
//     security policies, here for NAT.
//
// This gate makes BOTH visible at commit, consistent with the policy-address
// representability gate (validatePolicyMatchAddressSetMembersStrict) and the
// NAT match-application gate (validateNATMatchApplicationsStrict).
//
// Feed carve-out (#3303 / #3294): a DIRECT `match ...-address-name <feed-name>`
// reference to a `security dynamic-address address-name <name> profile <feed>`
// binding is ACCEPTED — the static book expansion is empty but
// resolveNATAddressNamePrefixes unions the live feed overlay at runtime, so the
// rule does carry prefixes. Mirrors validatePolicyMatchAddressesStrict's
// AddressBindings carve-out; deliberately scoped to the DIRECT reference (a
// feed member NESTED in an address-set is still poisoned by the static
// resolver — the anti-Option-C guardrail, identical to the policy path).
//
// On the tolerant load / peer-sync paths the call site downgrades to a warning
// (opts.lenientFirewallRefs) so an already-persisted or peer-synced config
// still BOOTS (#1960); the dataplane then fails closed for the unresolved
// reference. Rule-sets are walked source-first then destination, in slice
// order, for a deterministic first error.
func validateNATSourceAddressNameReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ab := cfg.Security.AddressBook
	feedBinding := func(name string) bool {
		if name == "" {
			return false
		}
		_, ok := cfg.Security.DynamicAddress.AddressBindings[name]
		return ok
	}
	defined := func(name string) bool {
		if name == "" || ab == nil {
			return false
		}
		if _, ok := ab.Addresses[name]; ok {
			return true
		}
		_, ok := ab.AddressSets[name]
		return ok
	}
	// nameError returns nil when the reference is valid, or the strict
	// rejection error otherwise. field is "source-address-name" /
	// "destination-address-name" and scope is "source scope" / "destination
	// scope" for the operator-facing message.
	nameError := func(natType, ruleSet, ruleName, field, scope, name string) error {
		if name == "" || feedBinding(name) {
			return nil
		}
		if !defined(name) {
			return fmt.Errorf(
				"%s NAT rule-set %q rule %q references undefined "+
					"%s %q (define `security address-book "+
					"address %s` / `address-set %s`, or fix the name — the "+
					"%s would otherwise be silently lost and the "+
					"rule would match no traffic)",
				natType, ruleSet, ruleName, field, name, name, name, scope)
		}
		// #3425: a DEFINED name that the runtime resolver cannot expand to >= 1
		// literal address (empty address, empty/dangling set). The builder
		// appends the raw token → the rule is non-empty but unmatchable. Reject
		// it so the operator sees the dead scope at commit.
		if cause := policyMatchAddressBookResolves(ab, name); cause != nil {
			return fmt.Errorf(
				"%s NAT rule-set %q rule %q match %s %q does not resolve to "+
					"any address: %w — the rule commits but the dataplane "+
					"installs a match-nothing %s so the translation never "+
					"fires (add at least one resolvable member / a prefix to "+
					"the address, or remove the reference) (#3425)",
				natType, ruleSet, ruleName, field, name, cause, scope)
		}
		return nil
	}
	check := func(natType string, rs *NATRuleSet) error {
		if rs == nil {
			return nil
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			// #3431: validate EVERY name in a bracket list / repeated
			// `match source-address-name [ a b ]`, not just the first.
			for _, name := range rule.Match.SourceAddressNameList() {
				if err := nameError(natType, rs.Name, rule.Name,
					"source-address-name", "source scope", name); err != nil {
					return err
				}
			}
			// #3229: destination-address-name is the destination twin of
			// source-address-name and resolves through the same address-book
			// expander (appendNATDestinationAddressName). A dangling or
			// unresolvable reference installs no destination = the rule matches
			// nothing (fail-closed but silent); gate it here so the problem is
			// operator-visible at commit, exactly like the source name above.
			// #3431: validate every value of a bracket list / repeated leaf.
			for _, name := range rule.Match.DestinationAddressNameList() {
				if err := nameError(natType, rs.Name, rule.Name,
					"destination-address-name", "destination scope", name); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, rs := range cfg.Security.NAT.Source {
		if err := check("source", rs); err != nil {
			return err
		}
	}
	if cfg.Security.NAT.Destination != nil {
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			if err := check("destination", rs); err != nil {
				return err
			}
		}
	}
	return nil
}

// validatePoolUtilizationAlarm is the #2079 strict-vs-lenient gate for the
// `security nat source pool-utilization-alarm raise-threshold/clear-threshold`
// thresholds. Junos requires only raise-threshold; clear-threshold is optional
// and, when omitted, is defaulted at parse time to a hysteresis margin below
// raise (defaultPoolAlarmClearThreshold, #4077) so a raise-only alarm both
// commits and runs. This gate therefore only ever sees a zero/invalid
// clear-threshold when the operator EXPLICITLY provided one. A bare
// `pool-utilization-alarm;` compiles to raise=0/clear=0 (an always-firing
// alarm) and inverted/equal thresholds make hysteresis meaningless. Strict
// (commit / commit-check): hard-reject. Lenient (load / peer-sync, #1979
// doctrine): return the message as a warning so a config committed before this
// gate existed still boots (#1960 fail-closed-on-compile-failure would
// otherwise brick the daemon on restart). The runtime monitor treats raise<=0
// as disabled, so a leniently loaded bad config is inert, not always-firing.
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
			//
			// #4339: a rule is NEVER compared against itself. A single NPTv6
			// rule in a rule-set with MULTIPLE from-scopes (`from zone A; from
			// zone B`, or several interfaces) is scope-expanded by
			// compileNATStatic into one StaticNATRuleSet entry PER scope, all
			// sharing the rule-set name AND the rule name (they are one logical
			// rule; only the from-scope differs). The seen lists span every
			// rule-set, so the second scope-expansion's prefixes matched the
			// first's exactly and the rule was reported as overlapping ITSELF —
			// blocking ANY NPTv6 mapping whose rule-set had more than one
			// from-scope. Skip the same (rule-set, rule) identity so only
			// DISTINCT rules are compared for a genuine, order-dependent overlap.
			sameRule := func(prev seenPrefix) bool {
				return prev.ruleSetName == rs.Name && prev.ruleName == rule.Name
			}
			overlapFound := false
			for _, prev := range internalSeen {
				if sameRule(prev) {
					continue
				}
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
				if sameRule(prev) {
					continue
				}
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

// validateNAT64PrefixStrict is the #3886 strict-vs-lenient gate for a NAT64
// rule-set's `prefix` (`security nat nat64 rule-set <r> prefix <p>`).
//
// The prefix is read verbatim into NAT64RuleSnapshot.Prefix
// (compiler_nat.go:compileNAT64 -> buildNAT64Snapshots) and parsed at
// dataplane apply by Nat64State::try_from_snapshots (userspace-dp/src/nat64.rs).
// That /96-integrity check REQUIRES the prefix to be `<ipv6-address>/96`: it
// splits on '/', the token after the first '/' MUST parse as a decimal /96
// (only /96 is supported by the translator), and the address token before the
// '/' MUST parse as an IPv6 address. Anything else (a non-/96 length, a missing
// or garbage mask, a non-IPv6 / malformed address) makes try_from_snapshots
// return a SnapshotIntegrityError, which propagates via `?` out of
// build_reconcile_forwarding and ABORTS the whole forwarding rebuild WITHOUT
// publishing a snapshot. The dataplane is then frozen at the last-good state:
// every later commit (new sessions, policy, NAT) silently stops reaching the
// dataplane with no operator feedback. Without this gate a single bad NAT64
// prefix COMMITS GREEN and wedges the entire control->dataplane pipeline.
//
// This mirrors the Rust /96-integrity check EXACTLY so anything that would
// abort the rebuild at runtime is rejected at commit — no commit-accept ->
// runtime-abort gap. An empty/absent prefix is deliberately OUT OF SCOPE: the
// Go builder (buildNAT64Snapshots) skips an empty-prefix rule, so it is never
// emitted on the wire and never reaches the Rust check, so it cannot freeze the
// rebuild.
//
// Strict (commit / commit-check): hard-reject a non-/96 or malformed prefix.
// Lenient (load / peer-sync, #1960 / #1979 doctrine): return the message as a
// warning so a config committed before this gate existed (or peer-synced) still
// BOOTS — fail-closed-on-compile-failure would otherwise brick the daemon on
// restart. The Rust helper's own try_from_snapshots backstop keeps the previous
// live forwarding state on the leniently-loaded config, so the bad rule never
// installs. Same doctrine as validateNPTv6Strict.
func validateNAT64PrefixStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	emit := func(msg string) error {
		if lenient {
			warnings = append(warnings,
				msg+" (this NAT64 rule is invalid; on a userspace-dataplane apply/preflight"+
					" the helper's Nat64State::try_from_snapshots rejects the whole forwarding"+
					" snapshot and the previous live state is kept, so this rule — and every"+
					" later config change — will not reach the dataplane until it is corrected)")
			return nil
		}
		return fmt.Errorf("%s", msg)
	}

	for _, rs := range cfg.Security.NAT.NAT64 {
		if rs == nil || rs.Prefix == "" {
			continue
		}
		// Mirror Nat64State::try_from_snapshots (userspace-dp/src/nat64.rs)
		// EXACTLY. Split on '/' (Rust `split('/')`); a trailing junk field
		// after the mask is ignored by both sides, so we index [0] and [1] and
		// disregard the rest rather than SplitN'ing the mask.
		parts := strings.Split(rs.Prefix, "/")
		// The token after the first '/' must parse as a decimal /96. A missing
		// mask (no '/'), an empty mask, a non-numeric mask, or any length other
		// than 96 is rejected — only /96 is supported by the translator.
		mask96 := false
		if len(parts) >= 2 {
			if m, err := strconv.ParseUint(parts[1], 10, 8); err == nil && m == 96 {
				mask96 = true
			}
		}
		if !mask96 {
			if err := emit(fmt.Sprintf(
				"security nat nat64 rule-set %q prefix %q must be an IPv6 prefix of length /96 (RFC 6052: the well-known 64:ff9b::/96 or a /96 network-specific prefix); any other length or a missing/garbage mask is rejected by the dataplane, which aborts the entire forwarding rebuild",
				rs.Name, rs.Prefix)); err != nil {
				return nil, err
			}
			continue
		}
		// The address token before the first '/' must parse as an IPv6 address.
		// natAddrFamily keys the family on the un-parsed text (colon == v6) so
		// an IPv4-mapped literal (::ffff:1.2.3.4) is classified V6, matching
		// Rust's Ipv6Addr::from_str exactly (a dotted-quad or a non-IP token is
		// NOT V6 and is rejected).
		if natAddrFamily(parts[0]) != "v6" {
			if err := emit(fmt.Sprintf(
				"security nat nat64 rule-set %q prefix %q has an address part %q that is not a valid IPv6 address; the dataplane rejects it and aborts the entire forwarding rebuild",
				rs.Name, rs.Prefix, parts[0])); err != nil {
				return nil, err
			}
			continue
		}
	}

	return warnings, nil
}

// validateStaticNATThenTargetStrict rejects a static-NAT rule that would install
// with an EMPTY translation target (#4290). Two causes both leave Then=="":
//
//   - an unresolvable `then static-nat prefix-name <name>` (undefined /
//     multi-member / prefix-less address-book entry — resolveStaticNATThen-
//     PrefixNames could not fill Then); and
//   - a bare / misspelled `then static-nat` target keyword (a typo the free-form
//     static-nat leaf accepted — the then switch matched no case).
//
// Both previously committed cleanly and installed a static NAT with no
// translation (silent broken 1:1). NPTv6 rules are skipped (their Then holds the
// nptv6 prefix and buildStaticNATSnapshots handles them on a separate path).
// Strict on commit / commit-check (hard reject); the call site downgrades to a
// warning on the tolerant load / peer-sync path (#1960) where the dataplane then
// fails closed (the empty prefix does not parse as an IP → no translation).
// Rule-sets are walked in slice order for a deterministic first error.
func validateStaticNATThenTargetStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.IsNPTv6 || rule.Then != "" {
				continue
			}
			if rule.ThenPrefixName != "" {
				return fmt.Errorf(
					"static NAT rule-set %q rule %q references `then static-nat "+
						"prefix-name %q`, which does not resolve to a single "+
						"address-book prefix (define `security address-book "+
						"global address %s <prefix>`, or fix the name — the "+
						"translation target would otherwise be silently empty "+
						"and the 1:1 NAT would install with no target) (#4290)",
					rs.Name, rule.Name, rule.ThenPrefixName, rule.ThenPrefixName)
			}
			return fmt.Errorf(
				"static NAT rule-set %q rule %q has an empty `then static-nat` "+
					"translation target (an unhandled or misspelled target "+
					"keyword — expected prefix | prefix-name | nptv6-prefix | "+
					"inet) — the rule would otherwise install with no "+
					"translation and silently forward the packet untranslated "+
					"(#4290)",
				rs.Name, rule.Name)
		}
	}
	return nil
}
