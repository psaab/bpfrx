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
