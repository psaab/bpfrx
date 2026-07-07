package userspace

import (
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// natCounterID returns the compiler-assigned per-rule translation hit counter
// ID for the type-namespaced "natType/rulesetName/ruleName" key (#2218). The
// natType MUST match the type the compiler stamped (dataplane.NATCounterKey),
// otherwise same-named SNAT/DNAT/static rules collide. A nil map or a missing
// key yields 0 ("no counter"), preserving the legacy behavior where the
// snapshot carried no per-rule counter attribution. The ID is the stable
// key-derived hash assigned by the compiler (#2255), so it is u32-wide.
func natCounterID(ids map[string]uint32, natType, ruleSet, rule string) uint32 {
	if ids == nil {
		return 0
	}
	return ids[dataplane.NATCounterKey(natType, ruleSet, rule)]
}

// resolveNATAddressNamePrefixes resolves a NAT `match {source,destination}-
// address-name` reference into concrete prefixes, unioning the static global
// address-book expansion (resolveUserspaceAddressBookEntry) with the live
// dynamic-address feed overlay (#2049 / #3303). feedOverlay maps a
// `security dynamic-address address-name ... profile <feed>` binding to its
// live feed-backed CIDR strings (resolved by the daemon from
// feeds.Manager.SnapshotForBindings).
//
// Before #3303 the NAT snapshot builders never received feedOverlay, so a NAT
// rule scoped to a feed-backed address-name resolved STATIC-ONLY and matched
// nothing on live feed content — contradicting the docs claim that feeds are
// enforced via "policy/NAT address-name bindings". This brings NAT into line
// with the policy path (buildAddressBookTableWithFeeds), which also merges
// feedOverlay[name] into a name's content.
//
// It is NOT a byte-for-byte mirror of that path: the policy builder
// family-splits the feed CIDRs and re-sorts/dedups across the static+feed union
// (it must, to assign a content-hash ID), whereas this helper appends the feed
// strings to the prefix list directly. That difference is functionally inert —
// feeds.Manager.SnapshotForBindings already returns the overlay CIDRs sorted
// and deduped, and the NAT consumer treats the list as an unordered prefix set
// (duplicates contribute no extra table entry, ordering is irrelevant) — so no
// re-dedup or family-split is needed here.
//
// The recursive case — an address-SET whose member is feed-backed — is NOT
// resolved here (the static resolveUserspaceAddressBookEntry expander poisons
// the whole set on an unresolvable feed member and never consults the overlay).
// #3294 closed this for the SECURITY-POLICY path (the feed-aware
// expandBookNameRecursive now merges nested feed members into the policy
// address-book row), but the NAT path was deliberately left out of #3294 scope
// (the converged plan, constraint 5 / open-question 4) and remains a tracked
// residual. A DIRECT `match ...-address-name <feed-name>` reference is fully
// resolved here, which was the #3303 NAT-side gap.
func resolveNATAddressNamePrefixes(cfg *config.Config, feedOverlay map[string][]string, name string) []string {
	var out []string
	if values, ok := resolveUserspaceAddressBookEntry(cfg, name); ok {
		out = append(out, values...)
	}
	if feeds := feedOverlay[name]; len(feeds) > 0 {
		out = append(out, feeds...)
	}
	return out
}

// appendNATSourceAddressName resolves a NAT rule's `match source-address-name
// <book-entry>` into concrete source prefixes and appends them to the rule's
// source list (#2416). It reuses resolveNATAddressNamePrefixes — the same
// static-book expander the security-policy snapshot path uses, now unioned with
// the dynamic-address feed overlay (#3303) — so a name-scoped NAT rule carries
// the entry's prefixes (static AND feed-backed) into the #2394 source
// constraint instead of publishing an empty (match-any) source list.
//
// Fail-closed on an unknown / unresolvable name: the raw token is appended so
// the source list stays NON-EMPTY (source_constrained stays true on the Rust
// side) while the token itself fails IpAddr/IpNet parse and contributes no
// prefix — the rule then matches NOTHING rather than collapsing to match-any.
// This mirrors the policy path's behavior for an unresolved address reference
// and is backstopped at commit by validateNATSourceAddressNameReferencesStrict.
func appendNATSourceAddressName(cfg *config.Config, feedOverlay map[string][]string, sourceAddrs []string, name string) []string {
	if name == "" {
		return sourceAddrs
	}
	if values := resolveNATAddressNamePrefixes(cfg, feedOverlay, name); len(values) > 0 {
		return append(sourceAddrs, values...)
	}
	// Unknown / empty book entry: keep the constraint non-empty but
	// unmatchable (fail-closed). The raw name cannot parse as an IP.
	return append(sourceAddrs, name)
}

// appendNATDestinationAddressName resolves a NAT rule's `match
// destination-address-name <book-entry>` into concrete destination prefixes and
// appends them to the rule's destination list (#3229). It is the destination
// twin of appendNATSourceAddressName and shares the same expander
// (resolveNATAddressNamePrefixes) the security-policy and source-address-name
// paths use — static address book unioned with the dynamic-address feed overlay
// (#3303) — so a name-scoped destination matches the same prefixes a literal
// `match destination-address` would, including feed-backed members.
//
// Fail-closed on an unknown / unresolvable name: the raw token is appended so
// the destination list stays NON-EMPTY (the rule does not collapse to no
// destination = skip), while the token itself fails IP parse downstream and
// contributes no installed table entry — the rule then matches NOTHING rather
// than broadening. Backstopped at commit by
// validateNATSourceAddressNameReferencesStrict, which also gates
// destination-address-name.
func appendNATDestinationAddressName(cfg *config.Config, feedOverlay map[string][]string, destAddrs []string, name string) []string {
	if name == "" {
		return destAddrs
	}
	if values := resolveNATAddressNamePrefixes(cfg, feedOverlay, name); len(values) > 0 {
		return append(destAddrs, values...)
	}
	// Unknown / empty book entry: keep the list non-empty but unmatchable
	// (fail-closed). The raw name cannot parse as an IP.
	return append(destAddrs, name)
}

// natNeverMatchPortRange is an impossible inclusive range (Low > High): no L4
// port satisfies `p >= 1 && p <= 0`, so a rule carrying it matches NOTHING
// (#3429). It is the fail-CLOSED sentinel emitted when a destination-port (or an
// application's destination-port) constraint WAS configured but every value is
// unrepresentable / out of the valid 1..65535 range. Without it, coalescing to
// an EMPTY range list would be read downstream as "no port constraint" = match
// any port — re-introducing the exact fail-OPEN widening #3429 closes (AGY
// finding on PR #3471). The Rust matcher PRESERVES a Low>High range (it never
// matches) rather than dropping it, so the sentinel survives the wire. The
// strict commit gate (#3386) already rejects an out-of-range port at commit;
// this hardens the lenient / tolerant-load / peer-sync path.
var natNeverMatchPortRange = NatPortRangeWire{Low: 1, High: 0}

// coalescePortRanges collapses a list of individual L4 ports (the expanded
// output of parseDNATPortList / appPortsFromSpec) into a minimal set of
// inclusive [Low,High] wire ranges (#3429). Any value outside the valid
// 1..65535 range is skipped (a bad/wrapping value never becomes a wrong u16
// match). The result is sorted, deduplicated, and run-merged so a
// `destination-port 20000 to 20003` carries one range, not four entries.
//
// This is a pure utility: it returns an EMPTY slice both for "no ports given"
// AND for "ports given but none representable" — the two are indistinguishable
// here and an empty result means "unconstrained" downstream. Callers that must
// fail CLOSED on an all-out-of-range constraint (rather than widen to match-any)
// MUST go through sourceNATDestPortRanges / the app-term guard, which substitute
// natNeverMatchPortRange when the input was non-empty but coalesced to nothing.
func coalescePortRanges(ports []int) []NatPortRangeWire {
	if len(ports) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(ports))
	uniq := make([]int, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		uniq = append(uniq, p)
	}
	if len(uniq) == 0 {
		return nil
	}
	sort.Ints(uniq)
	var ranges []NatPortRangeWire
	lo, hi := uniq[0], uniq[0]
	for _, p := range uniq[1:] {
		if p == hi+1 {
			hi = p
			continue
		}
		ranges = append(ranges, NatPortRangeWire{Low: uint16(lo), High: uint16(hi)})
		lo, hi = p, p
	}
	ranges = append(ranges, NatPortRangeWire{Low: uint16(lo), High: uint16(hi)})
	return ranges
}

// clampPort coerces a compiler-stored port (int, 0 = unset) into the u16
// wire slot. An out-of-range value is rejected at strict commit-check
// (compiler_nat.go validateNATHostMaskStrict), but the lenient load/peer-sync
// path can still carry one; clamp it to 0 ("no port translation") so a bad
// value fails CLOSED on the wire instead of wrapping to a wrong u16. #2491.
func clampPort(p int) uint16 {
	if p < 1 || p > 65535 {
		return 0
	}
	return uint16(p)
}

func buildStaticNATSnapshots(cfg *config.Config, natCounterIDs map[string]uint32) []StaticNATRuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		return nil
	}
	out := make([]StaticNATRuleSnapshot, 0)
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.IsNPTv6 {
				continue
			}
			// #3435: carry the `match source-address` constraint into the
			// snapshot. Prefer the full bracket-list (SourceAddresses); fall
			// back to the singular SourceAddress for an older typed config.
			// Empty = match any source (unscoped, pre-#3435 behavior).
			sourceAddrs := append([]string(nil), rule.SourceAddresses...)
			if len(sourceAddrs) == 0 && rule.SourceAddress != "" {
				sourceAddrs = append(sourceAddrs, rule.SourceAddress)
			}
			out = append(out, StaticNATRuleSnapshot{
				Name:                 rule.Name,
				FromZone:             rs.FromZone,
				FromInterface:        rs.FromInterface,
				FromRoutingInstance:  rs.FromRoutingInstance,
				SourceAddresses:      sourceAddrs,
				ExternalIP:           rule.Match,
				InternalIP:           rule.Then,
				MatchDestinationPort: clampPort(rule.MatchDestinationPort),
				MappedPort:           clampPort(rule.MappedPort),
				CounterID:            natCounterID(natCounterIDs, dataplane.NATCounterTypeStatic, rs.Name, rule.Name),
			})
		}
	}
	return out
}

// appPortsFromSpec parses a port specification like "80", "1024-65535" into a
// list of port numbers. Mirrors the logic in pkg/dataplane/compiler.go.
func appPortsFromSpec(spec string) []int {
	if spec == "" {
		return nil
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		lo, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return nil
		}
		hi, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return nil
		}
		if hi > lo {
			var ports []int
			for p := lo; p <= hi; p++ {
				ports = append(ports, int(p))
			}
			return ports
		}
		if hi < lo {
			// #3726: a REVERSED range ("200-100", lo>hi) is invalid — it can
			// never match any port. Return nil (not []int{lo}) so the caller
			// treats it as "configured but unrepresentable" and fails CLOSED
			// via the never-match sentinel, rather than silently narrowing the
			// NAT rule to an exact match on the low port. Strict commit already
			// rejects lo>hi (pkg/config range validation); this hardens the
			// #1960 tolerant-load / peer-sync backstop. The hi==lo case below
			// is a legitimate single exact port.
			return nil
		}
		return []int{int(lo)}
	}
	p, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return nil
	}
	return []int{int(p)}
}

// dnatDestinationParts splits a DNAT `match destination-address` token into the
// base address the DNAT table keys on and, for a non-host prefix, the canonical
// masked CIDR (#3164). It is the single point that decides host-vs-prefix on the
// Go side so the snapshot and the Rust DnatTable agree:
//
//   - A bare IP ("198.51.100.42") or an explicit host mask ("198.51.100.42/32",
//     "2001:db8::1/128") is a HOST: base = the address, prefix = "" — the Rust
//     table keys it in the O(1) exact hash map (unchanged fast path).
//   - A non-host prefix ("198.51.100.0/24") is a BLOCK: base = the prefix
//     network address ("198.51.100.0"), prefix = the canonical masked CIDR
//     ("198.51.100.0/24") — the Rust table installs a longest-prefix-match
//     entry that translates every host in the block to the rule's pool.
//
// ok is false for a token that does not parse as an IP or CIDR (an unresolved
// address-book name reaches here verbatim on a typo); the caller skips it, so a
// rule whose destinations are all malformed installs no entry and matches
// nothing (fail-closed) — the commit-time gate makes the typo operator-visible.
func dnatDestinationParts(raw string) (base, prefix string, ok bool) {
	if raw == "" {
		return "", "", false
	}
	if strings.IndexByte(raw, '/') == -1 {
		// Bare address — always a host.
		if net.ParseIP(raw) == nil {
			return "", "", false
		}
		return raw, "", true
	}
	ip, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		return "", "", false
	}
	ones, bits := ipNet.Mask.Size()
	if ones == bits {
		// Canonical host mask (/32 or /128) — exact-host fast path.
		return ip.String(), "", true
	}
	// Non-host prefix: base = network address, prefix = canonical masked CIDR.
	return ipNet.IP.String(), ipNet.String(), true
}

// dnatPoolHostIP validates a DNAT pool's translated address and returns the
// bare host IP the wire carries. The Rust DnatTable parses the pool address as
// a single host IpAddr, so the pool must resolve to exactly one host: a bare
// IP, /32, or /128. A non-host CIDR (e.g. 10.0.0.0/24) would otherwise be
// coerced to its network base (10.0.0.0) with no pool/range semantics (#3450
// M05), and a non-IP token (e.g. an address-book name) would be dropped by the
// Rust parser, leaving the VIP untranslated (#3450 M06). ok is false for both
// so the caller fails CLOSED (skips the rule, installing no entry) rather than
// translating to the wrong address. The commit-time gate (validateDNATPoolStrict)
// makes the bad address operator-visible; this is the lenient / peer-sync
// backstop.
func dnatPoolHostIP(addr string) (string, bool) {
	if addr == "" {
		return "", false
	}
	if strings.IndexByte(addr, '/') == -1 {
		ip := net.ParseIP(addr)
		if ip == nil {
			return "", false
		}
		return ip.String(), true
	}
	ip, ipNet, err := net.ParseCIDR(addr)
	if err != nil {
		return "", false
	}
	if ones, bits := ipNet.Mask.Size(); ones != bits {
		return "", false // non-host prefix — would coerce to the network base
	}
	return ip.String(), true
}

// buildDestinationNATSnapshots is the static-only convenience wrapper retained
// for callers without a dynamic-address feed overlay (tests, legacy paths). The
// production snapshot path uses buildDestinationNATSnapshotsWithFeeds (#3303).
func buildDestinationNATSnapshots(cfg *config.Config, natCounterIDs map[string]uint32) []DestinationNATRuleSnapshot {
	return buildDestinationNATSnapshotsWithFeeds(cfg, natCounterIDs, nil)
}

func buildDestinationNATSnapshotsWithFeeds(cfg *config.Config, natCounterIDs map[string]uint32, feedOverlay map[string][]string) []DestinationNATRuleSnapshot {
	if cfg == nil || cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) == 0 {
		return nil
	}
	var out []DestinationNATRuleSnapshot
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			// #3844: `then destination-nat off` is a no-translate EXEMPTION.
			// It carries no pool, but the rule MUST still install a snapshot
			// entry so the Rust DnatTable can recognize the matched traffic as
			// exempt and SHORT-CIRCUIT later DNAT rules (the Junos "matched
			// rule wins, stop" semantic). Before #3844 the off rule compiled to
			// an empty Then, was skipped here (PoolName == ""), and the
			// "exempted" traffic fell through to be DNAT'd by a later rule
			// (fail-open). An off entry runs the SAME match expansion below
			// (destination/source addresses, protocol, ports) but with an empty
			// pool and Off=true; the pool lookup/validation is skipped.
			isOff := rule.Then.Type == config.NATDestination && rule.Then.Off
			if !isOff && rule.Then.PoolName == "" {
				continue
			}
			ruleCounterID := natCounterID(natCounterIDs, dataplane.NATCounterTypeDest, rs.Name, rule.Name)
			var pool *config.NATPool
			var poolAddr string
			if !isOff {
				var ok bool
				pool, ok = cfg.Security.NAT.Destination.Pools[rule.Then.PoolName]
				if !ok || pool == nil || pool.Address == "" {
					continue
				}
				// #3450 fail-closed (lenient / peer-sync backstop; the commit gate
				// validateDNATPoolStrict rejects these). A pool with a
				// configured-but-invalid port (0/out-of-range/non-numeric — PortRaw
				// set but Port not in 1..65535) or a non-host pool address must
				// publish NO entry, so the rule matches NOTHING rather than wrapping
				// the port on a uint16 cast, collapsing to preserve-destination-port,
				// or coercing a non-host CIDR to its network base.
				var poolAddrOK bool
				poolAddr, poolAddrOK = dnatPoolHostIP(pool.Address)
				if !poolAddrOK {
					slog.Warn("userspace snapshot: skipping DNAT rule with non-host pool address (fail-closed, #3450)",
						"ruleset", rs.Name, "rule", rule.Name, "pool", rule.Then.PoolName, "address", pool.Address)
					continue
				}
				if pool.PortRaw != "" && (pool.Port < 1 || pool.Port > 65535) {
					slog.Warn("userspace snapshot: skipping DNAT rule with out-of-range pool port (fail-closed, #3450)",
						"ruleset", rs.Name, "rule", rule.Name, "pool", rule.Then.PoolName, "port_raw", pool.PortRaw, "port", pool.Port)
					continue
				}
			}
			// #2395: a DNAT rule may publish multiple destination addresses
			// (`match destination-address [ A B C ]`). The DNAT table is keyed
			// by exact destination IP, so each configured destination needs its
			// OWN snapshot entry sharing the rule's pool/counter id. Iterating
			// only the singular `DestinationAddress` (the first list element)
			// collapsed the rule to its first destination and silently dropped
			// translation for B and C. Mirror the source-address idiom: prefer
			// the bracket-list form, fall back to the singular match value.
			destAddrs := append([]string(nil), rule.Match.DestinationAddresses...)
			if len(destAddrs) == 0 && rule.Match.DestinationAddress != "" {
				destAddrs = append(destAddrs, rule.Match.DestinationAddress)
			}
			// #3229: `match destination-address-name <book-entry>` selects the
			// translated destination by an address-book reference instead of a
			// literal prefix. It was parsed into DestinationAddressName but never
			// resolved into the destination list the DNAT table is keyed on, so a
			// name-scoped DNAT rule installed NO table entry (silently dropped).
			// Resolve the name to its concrete prefixes via the same address-book
			// expander the source path uses (appendNATDestinationAddressName).
			// Each resolved host installs its own table entry below; a non-host
			// prefix is stripped to its network address like a literal CIDR
			// destination. On an unknown name the raw token is appended: it
			// cannot parse as an IP and is skipped in the emit loop, so the rule
			// matches NOTHING (fail-closed). The commit-time strict gate
			// (validateNATSourceAddressNameReferencesStrict) makes the typo
			// operator-visible.
			// #3431: resolve EVERY name of a bracket list / repeated leaf.
			for _, name := range rule.Match.DestinationAddressNameList() {
				destAddrs = appendNATDestinationAddressName(cfg, feedOverlay, destAddrs, name)
			}
			if len(destAddrs) == 0 {
				continue
			}

			// #2394: carry the DNAT `match source-address` constraint into the
			// snapshot. Junos DNAT source-address restricts which sources the
			// destination translation fires for; dropping it published the
			// internal service to every source in the from-zone (fail-open).
			// Mirror the SNAT builder: prefer the bracket-list form, fall back
			// to the singular match value. An empty result = match any source.
			sourceAddrs := append([]string(nil), rule.Match.SourceAddresses...)
			if len(sourceAddrs) == 0 && rule.Match.SourceAddress != "" {
				sourceAddrs = append(sourceAddrs, rule.Match.SourceAddress)
			}
			// #2416: `match source-address-name <book-entry>` scopes the DNAT
			// the same way a literal `match source-address` does, but as an
			// address-book reference. It was parsed into SourceAddressName yet
			// never resolved into the source list the #2394 enforcement reads,
			// so a name-scoped DNAT published an EMPTY source list = match any
			// source = fail-open (a destination translation the operator scoped
			// to a named source set fired for everyone). Resolve the name to its
			// concrete prefixes via the same address-book expander the policy
			// path uses and append them. On an unknown name we append the raw
			// token: it cannot parse on the Rust side (IpAddr::parse fails) so it
			// contributes no prefix, but it keeps the source list NON-EMPTY so
			// source_constrained stays true and the rule matches NOTHING
			// (fail-closed) instead of collapsing back to match-any. A commit-
			// time strict gate (validateNATSourceAddressNameReferencesStrict)
			// makes the typo operator-visible; this is the dataplane backstop.
			// #3431: resolve EVERY name of a bracket list / repeated leaf.
			for _, name := range rule.Match.SourceAddressNameList() {
				sourceAddrs = appendNATSourceAddressName(cfg, feedOverlay, sourceAddrs, name)
			}

			// Resolve application match to protocol+ports if specified.
			//
			// #3437: an application also pins a `source-port` (H10) and, for an
			// ICMP/ICMPv6 application, an ICMP type[,code] (H11). The pre-#3437
			// DNAT builder reduced an app to protocol + destination-port only and
			// dropped both — a fail-open widening (any source port / every ICMP
			// type was translated to the VIP). Carry them per term:
			//   - srcPorts: the application's `source-port` spec coalesced to wire
			//     ranges, with the same fail-CLOSED never-match sentinel the SNAT
			//     path uses (#3429/#3491) when it was configured but coalesces to
			//     nothing. nil = source-port unconstrained.
			//   - icmpType / icmpCode: the application's ICMP type[,code]
			//     constraint, carried verbatim (already valid u8s). nil = no ICMP
			//     type/code constraint (match every type/code of the protocol).
			type appTerm struct {
				proto    string
				ports    []int
				srcPorts []NatPortRangeWire
				icmpType *uint8
				icmpCode *uint8
				// dstPortConfigured records that the application specified a
				// non-empty destination-port spec, even if it coalesced to no
				// representable port (all out of 1..65535, or a reversed
				// "200-100" range rejected by appPortsFromSpec, #3726). The
				// port-filtering loop below reads this so a configured-but-
				// unrepresentable app destination-port fails CLOSED (never
				// match) instead of widening to the wildcard match-any-port
				// term — the DNAT analog of the source-NAT #3429/#3491 guard.
				dstPortConfigured bool
			}
			var appTerms []appTerm

			appTermFor := func(a *config.Application) appTerm {
				srcPorts := coalescePortRanges(appPortsFromSpec(a.SourcePort))
				if a.SourcePort != "" && len(srcPorts) == 0 {
					// #3437: a configured source-port that coalesces to nothing
					// (every value out of 1..65535) fails CLOSED — match no source
					// port rather than widening to any.
					srcPorts = []NatPortRangeWire{natNeverMatchPortRange}
				}
				return appTerm{
					proto:             a.Protocol,
					ports:             appPortsFromSpec(a.DestinationPort),
					srcPorts:          srcPorts,
					icmpType:          a.ICMPType,
					icmpCode:          a.ICMPCode,
					dstPortConfigured: a.DestinationPort != "",
				}
			}

			// #3431: expand EVERY application of a bracket list / repeated
			// `match application [ a b ]` into the union of its terms (match
			// ANY). Pre-#3431 only the first application was read and the rest
			// silently dropped, narrowing the rule.
			appConfigured := len(rule.Match.ApplicationList()) > 0
			if appConfigured {
				userApps := cfg.Applications.Applications
				for _, appName := range rule.Match.ApplicationList() {
					app, found := config.ResolveApplication(appName, userApps)
					if found {
						appTerms = append(appTerms, appTermFor(app))
					} else if _, isSet := cfg.Applications.ApplicationSets[appName]; isSet {
						expanded, err := config.ExpandApplicationSet(appName, &cfg.Applications)
						if err == nil {
							for _, termName := range expanded {
								tApp, ok := config.ResolveApplication(termName, userApps)
								if !ok {
									continue
								}
								appTerms = append(appTerms, appTermFor(tApp))
							}
						}
					}
				}
			}

			// If no application terms resolved, the behavior depends on WHETHER
			// an application was configured:
			//
			//   - #3434: an application WAS configured (rule.Match.Application !=
			//     "") but resolved to ZERO terms — a typo / dangling reference or
			//     a defined-but-EMPTY application-set. Falling through to the
			//     explicit-match fallback would emit proto="" + dstPort=0 = a
			//     wildcard match-ALL term and publish the pool VIP for EVERY
			//     flow to the destination (the H07/H08 fail-open, the DNAT analog
			//     of the source-NAT buildSourceNATAppTerms natProtoNever guard).
			//     Emit a never-match term instead, reusing the #3437 source-port
			//     never-match sentinel (an impossible Low>High range): the entry
			//     installs but can never satisfy l4_extra_matches, so the rule
			//     matches NOTHING. The commit-time strict gate
			//     (validateNATMatchApplicationsStrict, #3434) rejects the
			//     typo/empty-set so this is only the lenient load / peer-sync
			//     backstop.
			//
			//   - No application configured: use the explicit match grammar
			//     (protocol + destination-port). DNAT `match` grammar has no
			//     source-port or ICMP type/code, so those axes stay unconstrained
			//     on the explicit-match fallback term. The term carries the
			//     rule's destination-port list directly; #3857 additionally
			//     resolves the rule-level destination-port below (ruleDstPorts /
			//     ruleDstPortConfigured) so the port-filtering loop can tell a
			//     configured-but-unresolved destination-port from a genuine
			//     wildcard and fail closed — for BOTH this path and the
			//     application-present path.
			if len(appTerms) == 0 {
				if appConfigured {
					appTerms = []appTerm{{srcPorts: []NatPortRangeWire{natNeverMatchPortRange}}}
				} else {
					// #3431: one explicit-match term per protocol of a bracket
					// list / repeated `match protocol [ tcp udp ]` (match ANY).
					// Pre-#3431 only the first protocol was published. With no
					// protocol configured, ProtocolList() is empty and a single
					// proto="" wildcard term is emitted (unchanged behavior).
					protos := rule.Match.ProtocolList()
					if len(protos) == 0 {
						protos = []string{""}
					}
					for _, proto := range protos {
						appTerms = append(appTerms, appTerm{proto: proto, ports: rule.Match.DestinationPorts})
					}
				}
			}

			// #3857: an explicit rule-level `match destination-port` is
			// authoritative for the DNAT destination-port axis and applies to
			// EVERY resolved application term. Before #3857 the rule-level port
			// was consulted ONLY on the no-application explicit-match path
			// (explicitFallback); with an application ALSO present the builder
			// (a) dropped a VALID rule destination-port (the application's own
			// port, or a match-any wildcard, won), (b) collapsed a multi-value
			// list to the singular first port, and (c) — for a port-less
			// application — WIDENED an invalid/unrepresentable token to the
			// wildcard [0,0] port, a fail-open that bypassed the #3446 dport
			// guard on the lenient / HA peer-sync decode path. Resolve the
			// rule's port list once here (the plural, falling back to the scalar
			// a mixed-version peer may carry alone) and, when configured, use it
			// in place of the application's own destination-port on every term.
			// The application still constrains protocol / source-port / ICMP
			// type-code; only the destination-port axis is taken from the
			// explicit rule match. A configured-but-unrepresentable value fails
			// CLOSED below (the rule is omitted), exactly like the no-application
			// path and the source-NAT builder — it never widens to [0,0].
			ruleDstPorts := rule.Match.DestinationPorts
			if len(ruleDstPorts) == 0 && rule.Match.DestinationPort != 0 {
				ruleDstPorts = []int{rule.Match.DestinationPort}
			}
			ruleDstPortConfigured := len(ruleDstPorts) > 0 || len(rule.Match.InvalidDestinationPorts) > 0

			for _, term := range appTerms {
				// #3446: a `match destination-port` that was configured but
				// resolves to NO valid 1..65535 port must match NOTHING (fail
				// closed) — never widen to the wildcard port (0 = any). Out-of-
				// range numerics are dropped here (the bare uint16 cast used to
				// wrap 70000→4464); non-numeric tokens (`http`) were dropped at
				// parse and surface via Match.InvalidDestinationPorts. The strict
				// commit gate (validateNATMatchDestinationPortStrict) rejects all
				// of these at commit; this hardens the lenient / peer-sync path.
				//
				// #3449: coalesce the term's valid 1..65535 ports into inclusive
				// [Low,High] ranges so a wide `destination-port low to high` (or
				// an application's wide destination-port) carries ONE compact
				// entry instead of (high-low+1) per-port snapshots — a
				// control-plane memory/apply-time amplification hazard. A single
				// port (Low==High) keeps the exact-port O(1) fast-path entry; a
				// multi-port range becomes a wildcard-port (DestinationPort=0)
				// entry whose MatchDestinationPorts the Rust l4_extra_matches
				// AND-checks against the flow's destination port (mirroring the
				// #3437 MatchSourcePorts handling). coalescePortRanges drops
				// out-of-range values; an all-invalid configured port therefore
				// coalesces to nothing and is failed CLOSED below.
				// #3857: the explicit rule-level `match destination-port`
				// overrides the application's own destination-port on this term.
				// term.ports (the application's destination-port) is used only
				// when the rule did NOT configure `match destination-port`. On
				// the no-application explicit-match path term.ports already IS
				// rule.Match.DestinationPorts, so the override is a no-op there.
				termPorts := term.ports
				termDstPortConfigured := term.dstPortConfigured
				if ruleDstPortConfigured {
					termPorts = ruleDstPorts
					termDstPortConfigured = true
				}
				portRanges := coalescePortRanges(termPorts)
				// Did this term CONFIGURE a destination-port at all? A configured
				// port that survived to no valid value must not become wildcard.
				// #3726: term.dstPortConfigured is true when the application named
				// a destination-port that coalesced to nothing (all out of
				// 1..65535, or a reversed "200-100" range rejected by
				// appPortsFromSpec). #3857: termDstPortConfigured is also true
				// when the rule pinned an explicit `match destination-port` (a
				// numeric out-of-range, or non-numeric token on
				// InvalidDestinationPorts). Without this the empty ports slip
				// through to the wildcard match-any-port default — a fail-open
				// that widens the DNAT rule to every port.
				portConfigured := len(termPorts) > 0 || termDstPortConfigured
				if len(portRanges) == 0 {
					switch {
					case portConfigured:
						// Configured but no valid port → fail closed: emit no
						// snapshot for this term so the rule matches nothing.
						// #3857: this now also catches an invalid/unrepresentable
						// rule-level `match destination-port` present ALONGSIDE an
						// application, which previously widened to the [0,0]
						// wildcard via the removed singular-port switch case.
						continue
					default:
						// Genuine wildcard (no port match): a [0,0] range maps to
						// DestinationPort=0 with no range constraint below.
						portRanges = []NatPortRangeWire{{Low: 0, High: 0}}
					}
				}

				for _, pr := range portRanges {
					// A single-port range (Low==High, including the [0,0]
					// wildcard) keeps the exact wire key; a multi-port range
					// uses the wildcard key (DestinationPort=0) plus a
					// MatchDestinationPorts range constraint so it is NOT
					// expanded per port.
					var dstPort uint16
					var matchDstPorts []NatPortRangeWire
					if pr.Low == pr.High {
						dstPort = pr.Low
					} else {
						dstPort = 0
						matchDstPorts = []NatPortRangeWire{pr}
					}
					poolPort := dstPort
					// #3844: an off (exemption) rule has no pool — `pool` is
					// nil, so the pool-port override is skipped. The Rust side
					// short-circuits on the Off flag before reading any pool
					// value, so poolPort/poolAddr are unused for off entries.
					if !isOff && pool.Port != 0 {
						// #3450: pool.Port is gated to 1..65535 above (an
						// invalid configured port skips the whole rule), so this
						// uint16 cast can no longer wrap. Port == 0 (no `port`
						// leaf) preserves the destination port, unchanged.
						poolPort = uint16(pool.Port)
					}

					// Determine protocol string for the snapshot. A port-based
					// rule (an exact port OR a range constraint) defaults to TCP
					// when the rule did not pin a protocol, exactly as before.
					proto := term.proto
					if proto == "" && (dstPort != 0 || len(matchDstPorts) > 0) {
						proto = "tcp" // default for port-based DNAT
					}

					// #3450: poolAddr is the validated single-host IP (CIDR
					// suffix stripped, non-host prefix / non-IP token already
					// rejected above). Computed once before the rule loop.

					// #2395: emit one snapshot per configured destination so a
					// bracket-list DNAT installs a table entry for EVERY
					// published destination, not just the first.
					//
					// #3164: a destination may now be a non-host prefix
					// (`match destination-address 198.51.100.0/24`).
					// dnatDestinationParts classifies each token: a host (bare IP,
					// /32, /128) carries an empty DestinationPrefix and keys the
					// Rust exact hash map (unchanged fast path); a non-host prefix
					// carries the canonical masked CIDR in DestinationPrefix (the
					// network base in DestinationAddress) and installs a
					// longest-prefix-match entry that translates every host in the
					// block to the rule's pool. A token that does not parse as an
					// IP or CIDR is skipped — if a rule has destinations but ALL
					// are malformed, no entry is emitted, so the rule matches
					// NOTHING (fail-closed) rather than broadening to match-any.
					for _, rawDst := range destAddrs {
						base, prefix, ok := dnatDestinationParts(rawDst)
						if !ok {
							continue
						}
						out = append(out, DestinationNATRuleSnapshot{
							Name:                rule.Name,
							FromZone:            rs.FromZone,
							FromInterface:       rs.FromInterface,
							FromRoutingInstance: rs.FromRoutingInstance,
							SourceAddresses:     sourceAddrs,
							DestinationAddress:  base,
							DestinationPrefix:   prefix,
							DestinationPort:     dstPort,
							// #3449: a multi-port range rides this field as
							// one [Low,High] constraint instead of (High-Low+1)
							// per-port entries; empty for a single/exact port.
							MatchDestinationPorts: matchDstPorts,
							Protocol:              proto,
							PoolAddress:           poolAddr,
							PoolPort:              poolPort,
							// #3437: carry the application's source-port and
							// ICMP type/code constraints so the DNAT match is no
							// wider than the referenced application.
							MatchSourcePorts: term.srcPorts,
							MatchICMPType:    term.icmpType,
							MatchICMPCode:    term.icmpCode,
							// #3844: a `then destination-nat off` exemption. When
							// set, the Rust DnatTable treats a match as
							// no-translate and short-circuits later DNAT rules;
							// the pool fields are unused. PoolAddress is empty
							// for an off entry.
							Off:       isOff,
							CounterID: ruleCounterID,
						})
					}
				}
			}
		}
	}
	return out
}

func buildNAT64Snapshots(cfg *config.Config) []NAT64RuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.NAT64) == 0 {
		return nil
	}
	// `security nat natv6v4 no-v6-frag-header` is a global option, but the
	// dataplane consumes NAT64 state per rule-set. Replicate the flag onto
	// every emitted rule so the IPv6->IPv4 translator can honor it. The option
	// is an option-gated LOCAL DF policy (not the size-driven RFC 7915 5.1
	// selection): when set the translator clears DF so the IPv4 packet stays
	// fragmentable (DF=0, non-atomic) and carries a generated non-zero,
	// non-repeating Identification (RFC 6864 4.1) rather than the default DF=1
	// atomic framing.
	noV6FragHeader := cfg.Security.NAT.NATv6v4 != nil && cfg.Security.NAT.NATv6v4.NoV6FragHeader
	out := make([]NAT64RuleSnapshot, 0, len(cfg.Security.NAT.NAT64))
	for _, rs := range cfg.Security.NAT.NAT64 {
		if rs == nil || rs.Prefix == "" {
			continue
		}
		// #2214: initialize non-nil so a rule with no resolvable source pool
		// marshals `pool_addresses` as `[]`, never JSON `null`. The field has
		// no `,omitempty` (an empty pool is still a meaningful "no source-pool
		// resolved" state the dataplane must see), and the Rust `Vec<String>`
		// rejects an explicit null — which aborts the whole snapshot decode and
		// kills ALL transit (#1961 no-transit signature).
		poolAddresses := []string{}
		if rs.SourcePool != "" {
			if pool, ok := cfg.Security.NAT.SourcePools[rs.SourcePool]; ok && pool != nil {
				if pool.Address != "" {
					poolAddresses = append(poolAddresses, pool.Address)
				}
				poolAddresses = append(poolAddresses, pool.Addresses...)
			}
		}
		out = append(out, NAT64RuleSnapshot{
			Name:           rs.Name,
			Prefix:         rs.Prefix,
			PoolAddresses:  poolAddresses,
			NoV6FragHeader: noV6FragHeader,
		})
	}
	return out
}

func buildNptv6Snapshots(cfg *config.Config) []Nptv6RuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		return nil
	}
	var out []Nptv6RuleSnapshot
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || !rule.IsNPTv6 {
				continue
			}
			out = append(out, Nptv6RuleSnapshot{
				Name:           rule.Name,
				FromZone:       rs.FromZone,
				ExternalPrefix: rule.Match,
				InternalPrefix: rule.Then,
			})
		}
	}
	return out
}

// hasNonNptv6StaticNAT returns true if the config has any static NAT rules
// that are NOT NPTv6. NPTv6 rules are supported by the userspace dataplane.
func hasNonNptv6StaticNAT(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule != nil && !rule.IsNPTv6 {
				return true
			}
		}
	}
	return false
}
