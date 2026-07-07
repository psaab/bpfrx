package userspace

import (
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
