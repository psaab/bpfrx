package userspace

import (
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
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
// The recursive case — an address-SET whose member is feed-backed — remains the
// known #3294 gap (the static expander does not pull feed prefixes for nested
// set members). A DIRECT `match ...-address-name <feed-name>` reference is fully
// resolved here, which is the #3303 NAT-side gap.
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

// buildSourceNATSnapshots is the static-only convenience wrapper retained for
// callers that carry no dynamic-address feed overlay (tests, legacy paths). The
// production snapshot path uses buildSourceNATSnapshotsWithFeeds so feed-backed
// `match {source,destination}-address-name` references resolve their live feed
// prefixes (#3303).
func buildSourceNATSnapshots(cfg *config.Config, natCounterIDs map[string]uint32) []SourceNATRuleSnapshot {
	return buildSourceNATSnapshotsWithFeeds(cfg, natCounterIDs, nil)
}

func buildSourceNATSnapshotsWithFeeds(cfg *config.Config, natCounterIDs map[string]uint32, feedOverlay map[string][]string) []SourceNATRuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.Source) == 0 {
		return nil
	}
	out := make([]SourceNATRuleSnapshot, 0)
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			sourceAddrs := append([]string(nil), rule.Match.SourceAddresses...)
			if len(sourceAddrs) == 0 && rule.Match.SourceAddress != "" {
				sourceAddrs = append(sourceAddrs, rule.Match.SourceAddress)
			}
			// #2416: resolve `match source-address-name` for SNAT too — same
			// builder gap as DNAT (the source list only carried literal
			// prefixes). See appendNATSourceAddressName.
			sourceAddrs = appendNATSourceAddressName(cfg, feedOverlay, sourceAddrs, rule.Match.SourceAddressName)
			destAddrs := append([]string(nil), rule.Match.DestinationAddresses...)
			if len(destAddrs) == 0 && rule.Match.DestinationAddress != "" {
				destAddrs = append(destAddrs, rule.Match.DestinationAddress)
			}
			// #3229: resolve `match destination-address-name` the same way the
			// source path resolves source-address-name — without this a
			// name-scoped destination constraint published an EMPTY list =
			// match-any destination (fail-open).
			destAddrs = appendNATDestinationAddressName(cfg, feedOverlay, destAddrs, rule.Match.DestinationAddressName)
			var poolAddresses []string
			var portLow, portHigh uint16
			var persistentNAT bool
			var persistentNATPermitAnyRemoteHost bool
			var persistentNATPermit string
			var persistentNATInactivityTimeout int
			var poolUnusable bool
			var poolUnusableReason string
			if rule.Then.PoolName != "" {
				pool, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]
				if !ok || pool == nil {
					slog.Warn("userspace snapshot: marking source NAT rule with missing pool unusable",
						"rule", rule.Name, "pool", rule.Then.PoolName)
					poolUnusable = true
					poolUnusableReason = "missing_pool"
				} else {
					if pool.Address != "" {
						poolAddresses = append(poolAddresses, pool.Address)
					}
					poolAddresses = append(poolAddresses, pool.Addresses...)
					if len(poolAddresses) == 0 {
						slog.Warn("userspace snapshot: marking source NAT rule with empty pool unusable",
							"rule", rule.Name, "pool", rule.Then.PoolName)
						poolUnusable = true
						poolUnusableReason = "empty_pool"
					}
					var valid bool
					portLow, portHigh, valid = sourceNATPoolPortRange(pool)
					if !valid {
						slog.Warn("userspace snapshot: marking source NAT rule with invalid pool port range unusable",
							"rule", rule.Name, "pool", rule.Then.PoolName,
							"port_low", pool.PortLow, "port_high", pool.PortHigh)
						poolUnusable = true
						poolUnusableReason = "invalid_port_range"
					}
					if pool.PersistentNAT != nil {
						persistentNAT = true
						// #2823: carry the full three-way permit enum. Default
						// an unset mode to target-host-port (the pre-#2823
						// false-flag (dst_ip, dst_port) keying) so existing
						// configs stay byte-identical. The
						// PermitAnyRemoteHost bool is kept on the wire for
						// back-compat with an older helper that predates the
						// enum (#1961 wire-skew discipline).
						permit := pool.PersistentNAT.Permit
						if permit == "" {
							permit = config.PersistentNATPermitTargetHostPort
						}
						persistentNATPermit = string(permit)
						persistentNATPermitAnyRemoteHost = permit == config.PersistentNATPermitAnyRemoteHost
						persistentNATInactivityTimeout = pool.PersistentNAT.InactivityTimeout
						if persistentNATInactivityTimeout <= 0 {
							persistentNATInactivityTimeout = 300
						}
					}
				}
			}
			// #3429: carry the source-NAT L4 match constraints to the
			// dataplane. `match destination-port` becomes a set of inclusive
			// port ranges; `match application` is pre-expanded to (protocol,
			// port-range) terms (an application-set yields one term per resolved
			// member). The Rust matcher enforces these before translating AND
			// before applying a `then source-nat off` exemption, so a
			// port/app-scoped rule no longer silently widens to every port.
			matchDestPorts := sourceNATDestPortRanges(rule.Match.DestinationPorts)
			matchApps := buildSourceNATAppTerms(cfg, rule.Match.Application)

			out = append(out, SourceNATRuleSnapshot{
				Name:                             rule.Name,
				FromZone:                         rs.FromZone,
				ToZone:                           rs.ToZone,
				FromInterface:                    rs.FromInterface,
				ToInterface:                      rs.ToInterface,
				FromRoutingInstance:              rs.FromRoutingInstance,
				ToRoutingInstance:                rs.ToRoutingInstance,
				SourceAddresses:                  sourceAddrs,
				DestinationAddresses:             destAddrs,
				InterfaceMode:                    rule.Then.Interface,
				Off:                              rule.Then.Off,
				PoolName:                         rule.Then.PoolName,
				PoolAddresses:                    poolAddresses,
				PortLow:                          portLow,
				PortHigh:                         portHigh,
				AddressPersistent:                cfg.Security.NAT.AddressPersistent,
				PersistentNAT:                    persistentNAT,
				PersistentNATPermitAnyRemoteHost: persistentNATPermitAnyRemoteHost,
				PersistentNATPermit:              persistentNATPermit,
				PersistentNATInactivityTimeout:   persistentNATInactivityTimeout,
				PoolUnusable:                     poolUnusable,
				PoolUnusableReason:               poolUnusableReason,
				MatchDestinationPorts:            matchDestPorts,
				MatchApplications:                matchApps,
				CounterID:                        natCounterID(natCounterIDs, dataplane.NATCounterTypeSource, rs.Name, rule.Name),
			})
		}
	}
	return out
}

// natProtoAny is the source-NAT match-term protocol wildcard, mirroring the
// Rust SOURCE_NAT_PROTO_ANY (256): outside the 0-255 protocol range so it never
// aliases protocol 0 (HOPOPT). It denotes a GENUINELY unconstrained term and
// must never be used as a fallback for an unresolvable protocol (that is a
// fail-open widen — Codex finding on PR #3471; see natAppProtoNumber). The
// builder does not currently emit it: an application always constrains protocol,
// and an unconstrained `match application` (empty / "any") produces NO term at
// all rather than an any-protocol term. Kept defined to document the wire
// wildcard the Rust matcher honors and to keep the two sides legible. #3429.
const natProtoAny uint16 = 256

var _ = natProtoAny // reserved wire wildcard; see doc above (not emitted today)

// natProtoNever is a reserved protocol sentinel that can never equal a real
// 0-255 protocol and is not the wildcard, so a term carrying it matches no flow
// (#3429). Emitted for a `match application` that was configured but resolved to
// ZERO terms (a typo / dangling reference / empty application-set) so the rule
// fails CLOSED — it matches nothing — rather than silently widening to every
// protocol/port. The commit-time strict gate (#2187) rejects the typo so this
// is only the lenient load / peer-sync backstop.
const natProtoNever uint16 = 0xFFFF

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

// sourceNATDestPortRanges coalesces a configured source-NAT `match
// destination-port` list to wire ranges, failing CLOSED when the constraint was
// specified but nothing is representable (#3429). An empty input (no constraint
// configured) stays empty — a legitimate match-any-port wildcard. A non-empty
// input that coalesces to nothing (every port out of 1..65535) returns the
// never-match sentinel so the rule matches NOTHING instead of widening to every
// port (the AGY-found fail-open on PR #3471). NOTE: source NAT has no
// `match source-port` grammar (the SNAT parser only reads source/destination
// address(-name), destination-port, and application), so there is no
// source-port coalesce path to guard symmetrically.
func sourceNATDestPortRanges(ports []int) []NatPortRangeWire {
	ranges := coalescePortRanges(ports)
	if len(ports) > 0 && len(ranges) == 0 {
		return []NatPortRangeWire{natNeverMatchPortRange}
	}
	return ranges
}

// natAppProtoNumber resolves an application's protocol token to its IANA number
// for the source-NAT match wire (#3429). A resolvable token — including a
// numeric "0" (HOPOPT) — maps to its IANA value via the appid SSOT
// (appid.ProtocolNumber, the same resolver the policy path uses). An EMPTY or
// unresolvable protocol returns natProtoNever (0xFFFF), a never-match sentinel:
// a Junos application ALWAYS constrains protocol, so a term whose protocol
// cannot be resolved must match NOTHING. Returning natProtoAny (256, the
// wildcard) here would widen the app-scoped rule to EVERY protocol — a fail-open
// of the same class #3429 closes (Codex finding on PR #3471). natProtoAny is
// reserved for a genuinely unconstrained term, which the app path never produces
// (the "any" / empty app name short-circuits to no terms before this is called).
func natAppProtoNumber(proto string) uint16 {
	if n, ok := appid.ProtocolNumber(proto); ok {
		return uint16(n)
	}
	return natProtoNever
}

// buildSourceNATAppTerms resolves a source-NAT `match application <name>` into
// (protocol, destination-port range, source-port range) terms for the dataplane
// match (#3429, #3491). A single user/predefined application yields one term; an
// application-set yields one term per resolved member. The empty name (or "any")
// is unconstrained and yields no terms. A term's Ports are the application's
// destination-port spec coalesced to ranges and SrcPorts its source-port spec;
// an application with no destination (resp. source) port leaves that axis empty
// (unconstrained on it). A configured-but-unresolvable reference yields a single
// never-match term so the rule fails closed (see natProtoNever).
func buildSourceNATAppTerms(cfg *config.Config, appName string) []NatAppTermWire {
	if cfg == nil || appName == "" || appName == "any" {
		return nil
	}
	userApps := cfg.Applications.Applications
	var terms []NatAppTermWire
	addApp := func(a *config.Application) {
		if a == nil {
			return
		}
		ports := coalescePortRanges(appPortsFromSpec(a.DestinationPort))
		if a.DestinationPort != "" && len(ports) == 0 {
			// #3429: the application carried a destination-port spec but none of
			// it is representable (out of 1..65535) — fail CLOSED so the term
			// matches nothing rather than silently demoting to a protocol-only
			// (any-port) match. An app with NO destination-port keeps Ports empty
			// (a legitimate protocol-only match).
			ports = []NatPortRangeWire{natNeverMatchPortRange}
		}
		// #3491: the application's source-port constraint, dropped before this
		// fix. Same fail-CLOSED guard as the destination-port axis: an app that
		// configured a source-port but coalesces to nothing (all out of
		// 1..65535) gets the never-match sentinel rather than widening to any
		// source port. An app with NO source-port keeps SrcPorts empty (a
		// legitimate source-port-unconstrained match — the common case).
		srcPorts := coalescePortRanges(appPortsFromSpec(a.SourcePort))
		if a.SourcePort != "" && len(srcPorts) == 0 {
			srcPorts = []NatPortRangeWire{natNeverMatchPortRange}
		}
		terms = append(terms, NatAppTermWire{
			Protocol: natAppProtoNumber(a.Protocol),
			Ports:    ports,
			SrcPorts: srcPorts,
		})
	}
	if app, found := config.ResolveApplication(appName, userApps); found {
		addApp(app)
	} else if _, isSet := cfg.Applications.ApplicationSets[appName]; isSet {
		if expanded, err := config.ExpandApplicationSet(appName, &cfg.Applications); err == nil {
			for _, termName := range expanded {
				if a, ok := config.ResolveApplication(termName, userApps); ok {
					addApp(a)
				}
			}
		}
	}
	if len(terms) == 0 {
		// Configured app reference that resolved to nothing -> fail closed.
		terms = []NatAppTermWire{{Protocol: natProtoNever}}
	}
	return terms
}

func sourceNATPoolPortRange(pool *config.NATPool) (uint16, uint16, bool) {
	if pool == nil {
		return 0, 0, false
	}
	low := pool.PortLow
	if low == 0 {
		low = 1024
	}
	high := pool.PortHigh
	if high == 0 {
		high = 65535
	}
	if low < 1 || high < 1 || low > 65535 || high > 65535 || low > high {
		return 0, 0, false
	}
	return uint16(low), uint16(high), true
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
			if rule == nil || rule.Then.PoolName == "" {
				continue
			}
			ruleCounterID := natCounterID(natCounterIDs, dataplane.NATCounterTypeDest, rs.Name, rule.Name)
			pool, ok := cfg.Security.NAT.Destination.Pools[rule.Then.PoolName]
			if !ok || pool == nil || pool.Address == "" {
				continue
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
			destAddrs = appendNATDestinationAddressName(cfg, feedOverlay, destAddrs, rule.Match.DestinationAddressName)
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
			sourceAddrs = appendNATSourceAddressName(cfg, feedOverlay, sourceAddrs, rule.Match.SourceAddressName)

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
					proto:    a.Protocol,
					ports:    appPortsFromSpec(a.DestinationPort),
					srcPorts: srcPorts,
					icmpType: a.ICMPType,
					icmpCode: a.ICMPCode,
				}
			}

			if rule.Match.Application != "" {
				userApps := cfg.Applications.Applications
				app, found := config.ResolveApplication(rule.Match.Application, userApps)
				if found {
					appTerms = append(appTerms, appTermFor(app))
				} else if _, isSet := cfg.Applications.ApplicationSets[rule.Match.Application]; isSet {
					expanded, err := config.ExpandApplicationSet(rule.Match.Application, &cfg.Applications)
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

			// If no application terms resolved, use explicit match values. DNAT
			// `match` grammar has no source-port or ICMP type/code, so those axes
			// stay unconstrained on the explicit-match fallback term.
			if len(appTerms) == 0 {
				appTerms = []appTerm{{proto: rule.Match.Protocol, ports: rule.Match.DestinationPorts}}
			}

			for _, term := range appTerms {
				var dstPorts []uint16
				if len(term.ports) > 0 {
					for _, p := range term.ports {
						dstPorts = append(dstPorts, uint16(p))
					}
				} else if rule.Match.DestinationPort != 0 {
					dstPorts = []uint16{uint16(rule.Match.DestinationPort)}
				} else {
					dstPorts = []uint16{0}
				}

				for _, dstPort := range dstPorts {
					poolPort := dstPort
					if pool.Port != 0 {
						poolPort = uint16(pool.Port)
					}

					// Determine protocol string for the snapshot.
					proto := term.proto
					if proto == "" && dstPort != 0 {
						proto = "tcp" // default for port-based DNAT
					}

					poolAddr := pool.Address
					if idx := strings.IndexByte(poolAddr, '/'); idx != -1 {
						poolAddr = poolAddr[:idx]
					}

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
							Protocol:            proto,
							PoolAddress:         poolAddr,
							PoolPort:            poolPort,
							// #3437: carry the application's source-port and
							// ICMP type/code constraints so the DNAT match is no
							// wider than the referenced application.
							MatchSourcePorts: term.srcPorts,
							MatchICMPType:    term.icmpType,
							MatchICMPCode:    term.icmpCode,
							CounterID:        ruleCounterID,
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
