package config

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// vrfOverlapPrefix records one L3 prefix carried by a routing-instance together
// with a human-readable origin (the interface or the PBR filter/term that put
// it there) so the overlap warning can name where each side comes from.
type vrfOverlapPrefix struct {
	prefix netip.Prefix // masked network prefix
	origin string       // e.g. `interface "ge-0/0/1.0"` or `filter "fbf" term "t1"`
}

const (
	// vrfOverlapMaxWarnings caps how many cross-routing-instance overlap
	// advisories one compile emits (#5194 A3-b3-F5). A config with a large
	// number of overlapping prefixes must not flood commit output; the (N+1)th
	// overlap collapses into a single truncation notice.
	vrfOverlapMaxWarnings = 64
	// vrfOverlapMaxComparisons bounds the total prefix-pair comparisons this
	// advisory-only scan performs (#5194 A3-b3-F5). The pairwise scan is O(P^2)
	// across every routing-instance prefix; on a pathological config (thousands
	// of prefixes per RI across many RIs) that is millions of Overlaps() calls
	// on EVERY strict AND tolerant compile, including HA peer-sync. This is a
	// cold advisory path (a warning, never a reject), so once the budget is
	// spent the scan stops and emits a truncation notice rather than letting the
	// cross-VRF advisory dominate commit latency.
	vrfOverlapMaxComparisons = 1 << 20 // ~1M
)

// validateVRFOverlap emits a commit WARNING (never a hard reject) when two
// DISTINCT routing-instances carry overlapping L3 address space. This is the
// #2387 interim mitigation (Track A.1): the userspace-dp session/flow identity
// is the bare 5-tuple (userspace-dp/src/session/key.rs) with no
// routing-instance/VRF discriminator, so two flows in different
// routing-instances that share a 5-tuple collide in the conntrack map. The
// collision is LIVE under PBR `then routing-instance` (the established-session
// fast path runs before the PBR table override, so a second flow with the same
// 5-tuple inherits the first flow's cached egress / NAT / policy decision —
// wrong-VRF forwarding). See docs/research/2387-vrf-flow-identity/plan.md and
// userspace-dp/src/afxdp/forwarding/README.md.
//
// A WARNING, not a reject: overlapping-subnet multi-tenant VRF via PBR is a
// legitimate, working forwarding design, so hard-rejecting it would break a
// valid deployment to work around a fast-path bug. The operator is told the
// topology is not session-isolated; the config still commits. Neither of the
// two candidate end-states is decided: the hard-reject variant (a "no
// overlapping subnets at all" product posture) and the VRF-aware session key
// (a symmetric routing-domain id in SessionKey, Track B) both remain open on
// #2387, which is held on a maintainer risk-appetite call rather than on
// further engineering.
//
// The warning text below therefore states the CURRENT limitation and points at
// the tracking issue; it must not promise a fix, nor rule one out. It used to
// say colliding 5-tuples may cross-forward "until the session identity is
// VRF-aware", which asserted an outcome the open decision may never produce —
// and which the #2387 plan then cited back as evidence for that same outcome.
// TestVRFOverlapWarningStatesStatusNotPromise enforces that in BOTH format
// strings below — but enforces it PARTIALLY, and the difference matters if you
// are editing this text. It pins the closing status sentence verbatim, so the
// tail cannot be reworded or dropped, and nothing can be appended after it
// EXCEPT text that itself re-terminates with the tail verbatim — a contrived
// escape, recorded so nobody reasons from "appends are impossible". Wording
// spliced into the
// MIDDLE of the message is caught only if it uses a spelling on that test's
// token lists, which are blocklists and incomplete by construction. A forecast
// in either direction, phrased in a way nobody listed, will commit green. The
// text is neutral today because it was written to be, not because the test
// would stop you.
//
// Detection builds routing-instance -> set-of-prefixes from two sources:
//  1. native RI membership — each member interface unit's configured addresses
//     (the connected L3 space that lives in that VRF), joined via
//     ri.Interfaces -> cfg.Interfaces.Interfaces[base].Units[unit].Addresses;
//  2. PBR filter terms — a `then routing-instance <name>` term's source/dest
//     match prefixes (the L3 space steered INTO that VRF, the reachable-via-PBR
//     trigger).
//
// then compares the prefix sets of every unordered pair of distinct
// routing-instances for overlap (net/netip Prefix.Overlaps — contains-or-equal).
// Deterministic ordering (sorted RI names, sorted filter names, sorted
// prefixes) so the warning set is stable across commits.
func validateVRFOverlap(cfg *Config) []string {
	if cfg == nil {
		return nil
	}

	// riPrefixes[riName] = de-duplicated, origin-tagged prefix set.
	riPrefixes := map[string][]vrfOverlapPrefix{}
	// seen[riName][maskedPrefixString] dedupes a prefix that appears from more
	// than one origin (e.g. a native interface AND a PBR term). The first origin
	// encountered wins; native interfaces are processed before PBR terms and both
	// in deterministic order, so the retained origin is stable.
	seen := map[string]map[string]bool{}
	addPrefix := func(riName, cidr, origin string) {
		if riName == "" || cidr == "" {
			return
		}
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return
		}
		p = p.Masked()
		key := p.String()
		if seen[riName] == nil {
			seen[riName] = map[string]bool{}
		}
		if seen[riName][key] {
			return
		}
		seen[riName][key] = true
		riPrefixes[riName] = append(riPrefixes[riName], vrfOverlapPrefix{prefix: p, origin: origin})
	}

	// Source 1: native routing-instance membership -> member interface unit
	// addresses. cfg.RoutingInstances is a slice (deterministic order); each
	// ri.Interfaces entry is a Junos interface name, optionally `.unit`.
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		for _, member := range ri.Interfaces {
			base, unitTok, hasUnit := strings.Cut(member, ".")
			unitNum := 0
			if hasUnit {
				n, err := strconv.Atoi(unitTok)
				if err != nil {
					continue
				}
				unitNum = n
			}
			ifc := cfg.Interfaces.Interfaces[base]
			if ifc == nil {
				continue
			}
			unit := ifc.Units[unitNum]
			if unit == nil {
				continue
			}
			origin := fmt.Sprintf("interface %q", member)
			for _, addr := range unit.Addresses {
				addPrefix(ri.Name, addr, origin)
			}
		}
	}

	// Source 2: PBR `then routing-instance <name>` filter terms. A family-agnostic
	// filter is duplicated into both FiltersInet and FiltersInet6; process both
	// maps in sorted-name order and let the per-RI prefix de-dup collapse the
	// repeat.
	addFilterTerms := func(filterName string, filter *FirewallFilter) {
		if filter == nil {
			return
		}
		for _, term := range filter.Terms {
			if term == nil || term.RoutingInstance == "" {
				continue
			}
			origin := fmt.Sprintf("filter %q term %q", filterName, term.Name)
			for _, addr := range term.SourceAddresses {
				addPrefix(term.RoutingInstance, addr, origin)
			}
			for _, addr := range term.DestAddresses {
				addPrefix(term.RoutingInstance, addr, origin)
			}
		}
	}
	for _, filters := range []map[string]*FirewallFilter{cfg.Firewall.FiltersInet, cfg.Firewall.FiltersInet6} {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			addFilterTerms(name, filters[name])
		}
	}

	// Compare every unordered pair of distinct routing-instances. Sort RI names
	// and each RI's prefixes so the pairwise scan is deterministic.
	riNames := make([]string, 0, len(riPrefixes))
	for name := range riPrefixes {
		riNames = append(riNames, name)
	}
	sort.Strings(riNames)
	for _, name := range riNames {
		set := riPrefixes[name]
		sort.Slice(set, func(i, j int) bool {
			return set[i].prefix.String() < set[j].prefix.String()
		})
		riPrefixes[name] = set
	}

	var warnings []string
	// #5194 A3-b3-F5: bound this O(P^2) advisory scan. `comparisons` spends the
	// operation budget; the warning cap stops once enough advisories are
	// collected. Either limit trips `truncated`, which appends one notice so the
	// operator knows the scan was incomplete rather than silently under-reporting.
	comparisons := 0
	truncated := false
Scan:
	for i := 0; i < len(riNames); i++ {
		for j := i + 1; j < len(riNames); j++ {
			riA, riB := riNames[i], riNames[j]
			for _, a := range riPrefixes[riA] {
				for _, b := range riPrefixes[riB] {
					if comparisons >= vrfOverlapMaxComparisons {
						truncated = true
						break Scan
					}
					comparisons++
					// Family-separated: an IPv4 and an IPv6 prefix never overlap,
					// so skip the pair cheaply before the Overlaps() call.
					if a.prefix.Addr().Is4() != b.prefix.Addr().Is4() {
						continue
					}
					if !a.prefix.Overlaps(b.prefix) {
						continue
					}
					if len(warnings) >= vrfOverlapMaxWarnings {
						truncated = true
						break Scan
					}
					if a.prefix == b.prefix {
						warnings = append(warnings, fmt.Sprintf(
							"routing-instance %q (%s) and %q (%s) both carry %s: "+
								"overlapping L3 across routing-instances is forwarded via "+
								"PBR but is NOT session-isolated (#2387) — the session "+
								"identity carries no routing-instance discriminator, so "+
								"colliding 5-tuples may cross-forward. See #2387 for the "+
								"status of this limitation",
							riA, a.origin, riB, b.origin, a.prefix))
					} else {
						warnings = append(warnings, fmt.Sprintf(
							"routing-instance %q (%s, %s) and %q (%s, %s) carry "+
								"overlapping L3: overlapping L3 across routing-instances is "+
								"forwarded via PBR but is NOT session-isolated (#2387) — the "+
								"session identity carries no routing-instance discriminator, "+
								"so colliding 5-tuples may cross-forward. See #2387 for the "+
								"status of this limitation",
							riA, a.origin, a.prefix, riB, b.origin, b.prefix))
					}
				}
			}
		}
	}
	if truncated {
		warnings = append(warnings, fmt.Sprintf(
			"cross-routing-instance overlap validation was truncated after %d prefix "+
				"comparisons / %d advisories (config exceeds the advisory scan budget); "+
				"some overlaps may be unreported",
			comparisons, len(warnings)))
	}
	return warnings
}
