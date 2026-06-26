package userspace

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"net"
	"sort"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// unsupportedApplicationSentinel is the reserved protocol/name token emitted in
// a policy rule's application terms (#2124) when the userspace matcher cannot
// represent the rule's configured applications. It is deliberately not a valid
// protocol name or 0..255 numeric, so the Rust matcher drops it and the rule's
// all-dropped non-empty term list is rejected as a SnapshotIntegrityError
// (fail closed) instead of decoding to genuine match-any. Must stay unparseable
// by both appid.ProtocolNumber and userspace-dp parse_protocol.
const unsupportedApplicationSentinel = "__unsupported__"

// addressBookProbeLimit bounds the deterministic linear probe used to resolve
// a folded-hash collision when assigning a u32 address-book content ID. The
// folded FNV hash gives a starting slot; on a collision we walk forward by one
// slot at a time. The walk is bounded by the number of buckets actually being
// assigned plus a small fixed margin, NOT by a magic constant: with N distinct
// content buckets, at most N-1 prior IDs are taken, so a probe sequence of
// length N is guaranteed to land on a free slot in the 2^32 ID space (which is
// astronomically larger than any realistic N). Exceeding the bound therefore
// signals a builder logic error, not a credible accidental collision — and even
// then we return an error rather than panicking the daemon (#2514).
const addressBookProbeMargin = 8

// addressBookProbeLimit returns the maximum number of linear-probe steps
// allowed when resolving a folded-hash content-ID collision for nBuckets
// distinct content buckets. With at most nBuckets-1 IDs already taken, a
// forward probe of nBuckets steps is guaranteed to reach a free slot in the
// 2^32 space, so in production this bound is never reached — the
// AddressBookIDCollisionError it guards is the fail-safe, not a routine path.
// It is a package var so the #2514 fail-on-revert test can shrink the bound to
// deterministically drive the collision-exhaustion branch (proving it returns
// an error rather than panicking). Production code never reassigns it.
var addressBookProbeLimit = func(nBuckets int) int {
	return nBuckets + addressBookProbeMargin
}

// AddressBookIDCollisionError reports that the deterministic content-ID probe
// could not assign a unique u32 ID to every address-book content bucket. It is
// returned (never panicked) up the snapshot-build / apply path so a commit or
// apply rejects the offending config and the prior dataplane state is retained
// (fail-closed). FNV is not collision-resistant, so this is the defined
// failure mode for the (astronomically unlikely) case of unresolvable folded
// collisions among the configured address-book content buckets.
type AddressBookIDCollisionError struct {
	// BucketCount is the number of distinct content buckets being assigned.
	BucketCount int
	// Probes is the number of probe steps attempted before giving up.
	Probes int
}

func (e *AddressBookIDCollisionError) Error() string {
	return fmt.Sprintf(
		"address-book content-ID collision could not be resolved within %d probes (bucket count = %d); reject config, retain prior dataplane state",
		e.Probes, e.BucketCount)
}

// addressBookContentHash64 derives the FNV-1a/64 hash of an address-book
// content bucket's canonical bytes. It is a package var (not an inline call)
// solely so the #2514 fail-on-revert test can inject a degenerate hash that
// forces every bucket into the same folded-ID probe sequence — exercising the
// collision-exhaustion path that must return an AddressBookIDCollisionError
// instead of panicking. Production code never reassigns it.
var addressBookContentHash64 = func(canon []byte) uint64 {
	h := fnv.New64a()
	h.Write(canon)
	return h.Sum64()
}

func buildPolicySnapshots(cfg *config.Config) ([]PolicyRuleSnapshot, error) {
	return buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
}

func buildPolicySnapshotsWithSchedulerState(cfg *config.Config, activeState map[string]bool) ([]PolicyRuleSnapshot, error) {
	return buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, activeState, nil)
}

// buildPolicySnapshotsWithSchedulerStateAndFeeds builds the policy snapshots,
// classifying address tokens against the address-book ID map that INCLUDES the
// dynamic-address feed-prefix overlay (#2049). A policy token that names a
// feed-backed address-name resolves through nameToID to a SourceBookIDs /
// DestinationBookIDs reference (instead of falling through to a no-match
// literal), so the helper enforces the feed prefixes.
func buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg *config.Config, activeState map[string]bool, feedOverlay map[string][]string) ([]PolicyRuleSnapshot, error) {
	if cfg == nil || (len(cfg.Security.Policies) == 0 && len(cfg.Security.GlobalPolicies) == 0) {
		return nil, nil
	}
	_, nameToID, err := buildAddressBookTableWithFeeds(cfg, feedOverlay)
	if err != nil {
		return nil, err
	}
	out := make([]PolicyRuleSnapshot, 0)
	// walkPolicyRuleSlots is the single source of truth for the runtime
	// policy-ID namespace (#3143/#3145). Using it on the snapshot WRITE side
	// guarantees the IDs assigned here decode back to the same policy on the
	// counter READ side (policyRuleIDForCounter), and enforces the
	// MaxRulesPerPolicy cap so an app-set expansion cannot spill into the next
	// policy set's namespace.
	if err := walkPolicyRuleSlots(cfg, func(slot policyRuleSlot) error {
		policyID := slot.policyID()
		snap := buildOneRuleSnapshot(cfg, nameToID, slot.Policy, slot.FromZone, slot.ToZone, policyID, activeState)
		out = append(out, snap)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// policyRuleSlot describes a single configured policy's assignment within the
// runtime policy-ID namespace. The numeric runtime policy ID is
// PolicySetID*MaxRulesPerPolicy + RuleIndex, and the policy occupies Span
// contiguous IDs starting at that base (one per application-set expansion term).
type policyRuleSlot struct {
	PolicySetID uint32
	RuleIndex   uint32 // start index within the policy set's 256-slot namespace
	Span        uint32 // expansion slots consumed (>=1)
	FromZone    string
	ToZone      string
	Policy      *config.Policy
}

func (s policyRuleSlot) policyID() uint32 {
	return s.PolicySetID*dataplane.MaxRulesPerPolicy + s.RuleIndex
}

// walkPolicyRuleSlots invokes fn for every configured policy in config order,
// assigning each policy its slot in the runtime policy-ID namespace. It is the
// SHARED contract behind both the snapshot builder (the ID-WRITE side, #3145)
// and the counter resolver (the ID-READ side, #3143) so the two can never
// drift on how a policy ID maps to a (policy-set, rule-index) pair.
//
// Each policy's application-set expansion advances the per-set rule index by
// userspacePolicyRuleExpansionCount. If a policy set's cumulative expansion
// reaches MaxRulesPerPolicy (256), the next policy's ID would cross into the
// following set's namespace; this mirrors the legacy compiler guard
// (pkg/dataplane/compiler.go) and is rejected fail-closed so the apply path
// retains the prior good dataplane state.
func walkPolicyRuleSlots(cfg *config.Config, fn func(slot policyRuleSlot) error) error {
	if cfg == nil {
		return nil
	}
	policySetID := uint32(0)
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			policySetID++
			continue
		}
		ruleIndex := uint32(0)
		for _, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			span := userspacePolicyRuleExpansionCount(cfg, pol.Match.Applications)
			if ruleIndex+span >= dataplane.MaxRulesPerPolicy {
				return fmt.Errorf("policy %s->%s: expanded rules reach MaxRulesPerPolicy (%d) and would spill into the next policy set's ID namespace",
					zpp.FromZone, zpp.ToZone, dataplane.MaxRulesPerPolicy)
			}
			if err := fn(policyRuleSlot{
				PolicySetID: policySetID,
				RuleIndex:   ruleIndex,
				Span:        span,
				FromZone:    zpp.FromZone,
				ToZone:      zpp.ToZone,
				Policy:      pol,
			}); err != nil {
				return err
			}
			ruleIndex += span
		}
		policySetID++
	}
	globalRuleIndex := uint32(0)
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		span := userspacePolicyRuleExpansionCount(cfg, pol.Match.Applications)
		if globalRuleIndex+span >= dataplane.MaxRulesPerPolicy {
			return fmt.Errorf("global policy: expanded rules reach MaxRulesPerPolicy (%d) and would spill into the next policy set's ID namespace",
				dataplane.MaxRulesPerPolicy)
		}
		if err := fn(policyRuleSlot{
			PolicySetID: policySetID,
			RuleIndex:   globalRuleIndex,
			Span:        span,
			FromZone:    "junos-global",
			ToZone:      "junos-global",
			Policy:      pol,
		}); err != nil {
			return err
		}
		globalRuleIndex += span
	}
	return nil
}

func buildOneRuleSnapshot(
	cfg *config.Config,
	nameToID map[string]uint32,
	pol *config.Policy,
	fromZone, toZone string,
	policyID uint32,
	activeState map[string]bool,
) PolicyRuleSnapshot {
	// Legacy back-compat field: full expansion. Same as today's
	// behaviour for old-Rust readers.
	sourceAddresses, okSrc := expandUserspacePolicyAddresses(cfg, pol.Match.SourceAddresses)
	if !okSrc {
		sourceAddresses = append([]string(nil), pol.Match.SourceAddresses...)
	}
	destinationAddresses, okDst := expandUserspacePolicyAddresses(cfg, pol.Match.DestinationAddresses)
	if !okDst {
		destinationAddresses = append([]string(nil), pol.Match.DestinationAddresses...)
	}
	applicationTerms, ok := expandUserspacePolicyApplications(cfg, pol.Match.Applications)
	if !ok {
		// #2124: the rule cites application terms the userspace matcher cannot
		// honor (unrepresentable protocol or port). Emit a reserved unparseable
		// sentinel term instead of nil. nil would decode on the Rust side as
		// GENUINE match-any (no application constraint), so even though the
		// capability gate sets ForwardingSupported=false the published snapshot
		// could fail OPEN in the window before the helper is disarmed (and on a
		// same-plan refresh). The sentinel makes Rust drop the only term, see
		// an all-dropped non-empty term list, and reject the WHOLE snapshot via
		// SnapshotIntegrityError (keeping the previous good state) — an
		// action-agnostic fail-closed for both permit and deny rules.
		applicationTerms = []PolicyApplicationSnapshot{{
			Name:     unsupportedApplicationSentinel,
			Protocol: unsupportedApplicationSentinel,
		}}
	}
	// #1606 v3 fields: classify each address token as "named book
	// reference" vs "free-form literal".
	srcBookIDs, srcLiterals := classifyPolicyAddresses(cfg, nameToID, pol.Match.SourceAddresses)
	dstBookIDs, dstLiterals := classifyPolicyAddresses(cfg, nameToID, pol.Match.DestinationAddresses)
	schedulerName := pol.SchedulerName
	// #2508: carry the per-policy `then log session-init`/`session-close`
	// selection into the snapshot so the dataplane can gate the per-policy
	// RT_FLOW SYSLOG records. The global NetFlow/IPFIX close exporter
	// (#2460) is independent of these flags.
	var logSessionInit, logSessionClose bool
	if pol.Log != nil {
		logSessionInit = pol.Log.SessionInit
		logSessionClose = pol.Log.SessionClose
	}
	return PolicyRuleSnapshot{
		RuleID:               stablePolicyRuleID(fromZone, toZone, pol.Name),
		PolicyID:             policyID,
		Name:                 pol.Name,
		FromZone:             fromZone,
		ToZone:               toZone,
		SchedulerName:        schedulerName,
		Inactive:             policyRuleInactive(schedulerName, activeState),
		SourceAddresses:      sourceAddresses,
		DestinationAddresses: destinationAddresses,
		SourceBookIDs:        srcBookIDs,
		DestinationBookIDs:   dstBookIDs,
		SourceLiterals:       srcLiterals,
		DestinationLiterals:  dstLiterals,
		Applications:         append([]string(nil), pol.Match.Applications...),
		ApplicationTerms:     applicationTerms,
		Action:               policyActionString(pol.Action),
		// #2008 H2: carry the match-inversion flags to the dataplane.
		SourceAddressExcluded:      pol.Match.SourceAddressExcluded,
		DestinationAddressExcluded: pol.Match.DestinationAddressExcluded,
		// #2508: per-policy RT_FLOW SYSLOG log selection.
		LogSessionInit:  logSessionInit,
		LogSessionClose: logSessionClose,
	}
}

// classifyPolicyAddresses splits the policy's address-token list
// into (book IDs, free-form CIDR literals). #1606. The returned
// bookIDs are sorted + deduped.
func classifyPolicyAddresses(cfg *config.Config, nameToID map[string]uint32, addrs []string) ([]uint32, []string) {
	if len(addrs) == 0 {
		return nil, nil
	}
	bookSet := make(map[uint32]struct{}, len(addrs))
	literals := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, tok := range addrs {
		if tok == "" {
			continue
		}
		if id, ok := nameToID[tok]; ok {
			bookSet[id] = struct{}{}
			continue
		}
		// Not a known book name → treat as a free-form literal.
		// Includes "any", "any4", "any6", or a CIDR/IP literal.
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		literals = append(literals, tok)
	}
	if len(bookSet) == 0 {
		return nil, literals
	}
	bookIDs := make([]uint32, 0, len(bookSet))
	for id := range bookSet {
		bookIDs = append(bookIDs, id)
	}
	sort.Slice(bookIDs, func(i, j int) bool { return bookIDs[i] < bookIDs[j] })
	return bookIDs, literals
}

// buildAddressBookTable builds the deduplicated #1606 address-book
// table for inclusion on the wire ConfigSnapshot. Returns the
// table + a map from each declared address-book name (Addresses
// and AddressSets) to its assigned u32 ID. Names that reference
// the same canonical CIDR content share an ID.
//
// HA determinism: names are iterated in lexicographic sorted order
// before any hashing/ID assignment. Content hashing buckets by
// canonical bytes (not by hash), and the bucket sort key is
// (hash64, canonical_bytes) so collision-resolution is fully
// deterministic across HA peers.
func buildAddressBookTable(cfg *config.Config) ([]AddressBookSnapshot, map[string]uint32, error) {
	return buildAddressBookTableWithFeeds(cfg, nil)
}

// buildAddressBookTableWithFeeds is buildAddressBookTable plus the
// dynamic-address feed-prefix overlay (#2049). feedOverlay maps an
// address-name (a `security dynamic-address address-name ... profile
// feed-name` binding) to the union of its live feed-backed CIDR strings
// (resolved by the daemon from feeds.Manager.SnapshotForBindings).
//
// For each overlay name the feed CIDRs are merged into that name's content
// bucket BEFORE canonicalize/dedup/sort/hash/ID-assign, so:
//   - the name gets an AddressBookSnapshot row carrying the feed prefixes,
//   - nameToID[name] is populated, so classifyPolicyAddresses routes a policy
//     token naming the feed into SourceBookIDs/DestinationBookIDs (it was a
//     no-match literal before #2049),
//   - a feed-backed name with identical content to a static book shares an ID
//     (the content-equality invariant is preserved — feed CIDRs flow through
//     the same expand/normalize/dedup path),
//   - a feed content change shifts the row → the snapshot content hash shifts
//     → the duplicate-publish gate (snapshotContentHash) lets the refresh
//     through. This is why the join MUST live in the snapshot builder.
//
// An overlay name with no prefixes (startup before first fetch, or an
// operator-opted hold-interval drop) still produces a (possibly empty) bucket
// and a nameToID entry, so the policy token is routed as a book reference that
// matches nothing (fail-closed) rather than a no-match literal — either way it
// matches nothing, but routing it as a book keeps the wire shape consistent
// and lets a later refresh populate the same name without re-classifying.
//
// When the static AddressBook is nil but a feed overlay is present, the table
// is still built from the overlay alone (the pre-#2049 early-return only fired
// because there were no static books to enumerate).
func buildAddressBookTableWithFeeds(cfg *config.Config, feedOverlay map[string][]string) ([]AddressBookSnapshot, map[string]uint32, error) {
	if cfg == nil {
		return nil, nil, nil
	}
	ab := cfg.Security.AddressBook
	if ab == nil && len(feedOverlay) == 0 {
		return nil, nil, nil
	}

	// Collect all unique names: static Addresses + AddressSets ∪ feed-overlay
	// names. A feed-backed name need not exist in the static book at all.
	nameSet := make(map[string]struct{})
	if ab != nil {
		for name := range ab.Addresses {
			nameSet[name] = struct{}{}
		}
		for name := range ab.AddressSets {
			nameSet[name] = struct{}{}
		}
	}
	for name := range feedOverlay {
		nameSet[name] = struct{}{}
	}
	allNames := make([]string, 0, len(nameSet))
	for name := range nameSet {
		allNames = append(allNames, name)
	}
	sort.Strings(allNames)

	type bucket struct {
		canonical []byte
		hash64    uint64
		names     []string // declaring names in this bucket, sorted
		v4        []string
		v6        []string
	}
	contentToBucket := make(map[string]*bucket)
	for _, name := range allNames {
		v4, v6 := expandBookNameToCIDRs(cfg, name)
		// #2049: merge the live feed prefixes bound to this name. Feed CIDRs
		// are already canonical (masked) strings; split by family. They join
		// the same dedup/sort/canonicalize path as static members, so a
		// feed-backed name with content identical to a static book shares an
		// ID by the existing content-equality invariant.
		if feeds := feedOverlay[name]; len(feeds) > 0 {
			fv4, fv6 := splitFeedPrefixesByFamily(feeds)
			v4 = append(v4, fv4...)
			v6 = append(v6, fv6...)
		}
		// Normalise "any" → 0.0.0.0/0 + ::/0 (Codex r6 refinement).
		v4, v6 = normalizeAnyInCIDRs(v4, v6)
		// Canonical sort + dedup within each family. Without
		// dedup, two books that differ only by repeated members
		// would canonicalize to different bytes and not share an
		// ID (Codex code-review F3).
		sortV4CIDRs(v4)
		sortV6CIDRs(v6)
		v4 = dedupSortedStrings(v4)
		v6 = dedupSortedStrings(v6)
		canon := canonicalizeAddressBookContent(v4, v6)
		key := string(canon)
		b, exists := contentToBucket[key]
		if !exists {
			b = &bucket{canonical: canon, hash64: addressBookContentHash64(canon), v4: v4, v6: v6}
			contentToBucket[key] = b
		}
		b.names = append(b.names, name) // already in sorted-name order
	}

	// Sort buckets by (hash64, canonical_bytes) for deterministic
	// ID assignment.
	buckets := make([]*bucket, 0, len(contentToBucket))
	for _, b := range contentToBucket {
		buckets = append(buckets, b)
	}
	sort.Slice(buckets, func(i, j int) bool {
		if buckets[i].hash64 != buckets[j].hash64 {
			return buckets[i].hash64 < buckets[j].hash64
		}
		return bytes.Compare(buckets[i].canonical, buckets[j].canonical) < 0
	})

	// Assign u32 IDs via deterministic linear probe. ID 0 is
	// reserved.
	used := make(map[uint32]struct{})
	out := make([]AddressBookSnapshot, 0, len(buckets))
	nameToID := make(map[string]uint32)
	for _, b := range buckets {
		id := uint32(b.hash64 & 0xFFFFFFFF)
		if id == 0 {
			id = 1
		}
		if _, dup := used[id]; dup {
			// Linear probe (deterministic given bucket sort). The
			// walk is bounded by the number of buckets being
			// assigned plus a small margin: with N buckets at most
			// N-1 IDs are already taken, so a free slot is reached
			// within N probes in the 2^32 ID space. Exceeding the
			// bound returns an AddressBookIDCollisionError (#2514)
			// — config-shaped input must never panic a security
			// appliance. The caller rejects the config and retains
			// the prior dataplane state (fail-closed).
			folded := uint32(b.hash64 ^ (b.hash64 >> 32))
			probeLimit := addressBookProbeLimit(len(buckets))
			resolved := false
			for probe := 1; probe <= probeLimit; probe++ {
				cand := folded + uint32(probe)
				if cand == 0 {
					cand = 1
				}
				if _, dup := used[cand]; !dup {
					id = cand
					resolved = true
					break
				}
			}
			if !resolved {
				return nil, nil, &AddressBookIDCollisionError{
					BucketCount: len(buckets),
					Probes:      probeLimit,
				}
			}
		}
		used[id] = struct{}{}
		// Diagnostic name: smallest in this bucket.
		diagName := ""
		if len(b.names) > 0 {
			diagName = b.names[0]
		}
		out = append(out, AddressBookSnapshot{
			ID:         id,
			Name:       diagName,
			PrefixesV4: b.v4,
			PrefixesV6: b.v6,
		})
		for _, n := range b.names {
			nameToID[n] = id
		}
	}
	return out, nameToID, nil
}

// splitFeedPrefixesByFamily classifies feed-backed CIDR strings into v4 and
// v6 lists (#2049). Feed prefixes are already canonicalized to masked CIDR
// form by the feed manager (192.0.2.0/24, 2001:db8::/32), and a bare IP is
// normalized to /32 or /128 there, so this is a pure family split. A prefix
// that fails to parse (defensive — should not happen for canonical feed
// content) is dropped.
func splitFeedPrefixesByFamily(prefixes []string) (v4, v6 []string) {
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		if isV4CIDR(p) {
			v4 = append(v4, p)
			continue
		}
		if isV6CIDR(p) {
			v6 = append(v6, p)
			continue
		}
		// Not a CIDR — try a bare IP for robustness.
		if ip := net.ParseIP(p); ip != nil {
			if ip.To4() != nil {
				v4 = append(v4, ip.String()+"/32")
			} else {
				v6 = append(v6, ip.String()+"/128")
			}
		}
	}
	return v4, v6
}

// expandBookNameToCIDRs resolves a single address-book name
// (Address or AddressSet, recursively) into its v4 + v6 CIDR
// lists. Returns empty slices if name does not exist.
//
// Junos address-book values can be:
//   - CIDR strings (10.0.0.0/24)
//   - bare IPs (10.0.0.1, normalized to /32 or /128)
//   - "any" → both 0.0.0.0/0 and ::/0
//
// All three forms are surfaced here as canonical CIDRs so the wire
// row carries concrete prefixes.
func expandBookNameToCIDRs(cfg *config.Config, name string) ([]string, []string) {
	ab := cfg.Security.AddressBook
	if ab == nil {
		return nil, nil
	}
	visited := make(map[string]bool)
	values := expandBookNameRecursive(ab, name, visited, 0)
	var v4, v6 []string
	for _, value := range values {
		if value == "" || value == "any" {
			v4 = append(v4, "0.0.0.0/0")
			v6 = append(v6, "::/0")
			continue
		}
		if isV4CIDR(value) {
			v4 = append(v4, value)
			continue
		}
		if isV6CIDR(value) {
			v6 = append(v6, value)
			continue
		}
		// Bare IP: normalize to /32 (v4) or /128 (v6).
		if ip := net.ParseIP(value); ip != nil {
			if ip.To4() != nil {
				v4 = append(v4, ip.String()+"/32")
			} else {
				v6 = append(v6, ip.String()+"/128")
			}
		}
	}
	return v4, v6
}

// expandBookNameRecursive resolves named book references via
// path-based cycle detection. No depth cap (matches the legacy
// `resolveUserspaceAddressBookEntry` semantics — Copilot review C2).
// `visited` is mutated on entry and unwound on exit so siblings
// can share parents without false cycles.
func expandBookNameRecursive(ab *config.AddressBook, name string, visited map[string]bool, _depth int) []string {
	if visited[name] {
		return nil
	}
	visited[name] = true
	defer func() { delete(visited, name) }()
	if addr, ok := ab.Addresses[name]; ok {
		return []string{addr.Value}
	}
	if as, ok := ab.AddressSets[name]; ok {
		var out []string
		for _, member := range as.Addresses {
			out = append(out, expandBookNameRecursive(ab, member, visited, 0)...)
		}
		for _, nested := range as.AddressSets {
			out = append(out, expandBookNameRecursive(ab, nested, visited, 0)...)
		}
		return out
	}
	return nil
}

func normalizeAnyInCIDRs(v4, v6 []string) ([]string, []string) {
	hasAny4 := false
	hasAny6 := false
	cleanV4 := v4[:0]
	for _, s := range v4 {
		if s == "0.0.0.0/0" {
			hasAny4 = true
		}
		cleanV4 = append(cleanV4, s)
	}
	cleanV6 := v6[:0]
	for _, s := range v6 {
		if s == "::/0" {
			hasAny6 = true
		}
		cleanV6 = append(cleanV6, s)
	}
	_ = hasAny4
	_ = hasAny6
	return cleanV4, cleanV6
}

func sortV4CIDRs(s []string) {
	sort.Slice(s, func(i, j int) bool {
		_, a, errA := net.ParseCIDR(s[i])
		_, b, errB := net.ParseCIDR(s[j])
		if errA != nil || errB != nil {
			return s[i] < s[j]
		}
		if c := bytes.Compare(a.IP, b.IP); c != 0 {
			return c < 0
		}
		ma, _ := a.Mask.Size()
		mb, _ := b.Mask.Size()
		return ma < mb
	})
}

func sortV6CIDRs(s []string) {
	sortV4CIDRs(s) // same logic; works on any net.IP
}

// canonicalizeAddressBookContent serializes the v4 + v6 CIDR
// lists into a fixed byte stream with explicit family + count
// framing (Codex r3 F4 fix).
//
// Layout:
//
//	"V4" || u32_be(len(v4)) || (for each: u8(prefix_len) || u32_be(addr_bytes))
//	"V6" || u32_be(len(v6)) || (for each: u8(prefix_len) || u128_be(addr_bytes))
//
// CIDR strings that fail to parse are skipped (defensive).
func canonicalizeAddressBookContent(v4, v6 []string) []byte {
	var buf bytes.Buffer
	buf.WriteString("V4")
	binary.Write(&buf, binary.BigEndian, uint32(len(v4)))
	for _, s := range v4 {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		buf.WriteByte(byte(ones))
		buf.Write(ipnet.IP.To4())
	}
	buf.WriteString("V6")
	binary.Write(&buf, binary.BigEndian, uint32(len(v6)))
	for _, s := range v6 {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		buf.WriteByte(byte(ones))
		buf.Write(ipnet.IP.To16())
	}
	return buf.Bytes()
}

func dedupSortedStrings(s []string) []string {
	if len(s) <= 1 {
		return s
	}
	out := s[:1]
	for i := 1; i < len(s); i++ {
		if s[i] != out[len(out)-1] {
			out = append(out, s[i])
		}
	}
	return out
}

func isV4CIDR(s string) bool {
	ip, _, err := net.ParseCIDR(s)
	return err == nil && ip.To4() != nil
}

func isV6CIDR(s string) bool {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return false
	}
	// To4 returning non-nil means the string parsed as a 4-byte
	// address (or v4-mapped); only return true if the underlying
	// representation is 16 bytes (v6).
	return ip.To4() == nil && len(ipnet.IP) == net.IPv6len
}

// Silence unused-import warnings when this build is ever stripped
// of address-book content.
var _ = hex.EncodeToString

func stablePolicyRuleID(fromZone, toZone, ruleName string) string {
	return fmt.Sprintf("%s->%s/%s", fromZone, toZone, ruleName)
}

func userspacePolicyRuleExpansionCount(cfg *config.Config, apps []string) uint32 {
	if len(apps) == 0 {
		return 1
	}
	seen := make(map[string]struct{}, len(apps))
	for _, appName := range apps {
		if appName == "" || appName == "any" {
			return 1
		}
		resolved, ok := resolveUserspaceApplicationNames(cfg, appName)
		if !ok || len(resolved) == 0 {
			return 1
		}
		for _, name := range resolved {
			seen[name] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return 1
	}
	return uint32(len(seen))
}

func policyRuleInactive(schedulerName string, activeState map[string]bool) bool {
	if schedulerName == "" {
		return false
	}
	if activeState == nil {
		return true
	}
	active, ok := activeState[schedulerName]
	return !ok || !active
}

// PolicyInactive reports whether a policy bound to schedulerName is
// currently runtime-inactive given the daemon-maintained per-scheduler
// active-state map (see Manager.PolicySchedulerActiveState). It is the
// SSOT predicate shared between the snapshot builder (policyRuleInactive)
// and the read-only show surfaces (#3062 CLI/gRPC policy detail), so the
// display planes report exactly what the dataplane enforces rather than
// recomputing wall-clock schedule windows. An empty schedulerName is
// always active; a nil map (scheduler state not yet published) treats a
// scheduled policy as inactive, matching the builder's fail-closed
// behaviour — the dataplane drops such a rule until state arrives.
func PolicyInactive(schedulerName string, activeState map[string]bool) bool {
	return policyRuleInactive(schedulerName, activeState)
}

func policyActionString(action config.PolicyAction) string {
	switch action {
	case config.PolicyPermit:
		return "permit"
	case config.PolicyReject:
		return "reject"
	default:
		return "deny"
	}
}
