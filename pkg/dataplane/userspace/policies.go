package userspace

import (
	"encoding/hex"
	"fmt"
	"net"

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

// unsupportedAddressSentinel is the reserved address literal emitted in a policy
// rule's source/destination address fields (#3261) when the userspace matcher
// cannot represent the rule's configured addresses — an undefined address-book
// name, or a defined book whose value is a non-literal (Junos dns-name /
// wildcard-address / range-address). It is the ADDRESS analog of
// unsupportedApplicationSentinel: without it the raw address strings fall
// through to the Rust matcher, which silently drops an unparseable literal
// (parse_literal_cidr_into) or empties a non-literal book, collapsing the side
// to MatchNone. A `deny <unrepresentable-address>` rule would then match
// nothing and fall through to a later permit / default-permit — a deny
// fail-OPEN. Emitting this sentinel makes the Rust integrity preflight raise
// SnapshotIntegrityError::UnrepresentableAddress, rejecting the WHOLE snapshot
// (previous-good retained; fresh-boot default-deny), symmetric to the
// application path. It is deliberately not a valid CIDR/IP so it can never
// match real traffic even on an older helper that lacks the preflight arm.
// Must stay in lock-step with userspace-dp policy.rs UNREPRESENTABLE_ADDRESS_SENTINEL.
const unsupportedAddressSentinel = "__unsupported_address__"

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
	// addrRepresentable reports whether the userspace matcher can represent a
	// single policy address token. A token is representable iff it is match-any,
	// a valid literal CIDR/IP, a feed-bound name (in the overlay — an empty feed
	// is MatchNone BY DESIGN per #2049, NOT unrepresentable), or a known book/
	// address-set that is STRUCTURALLY representable (nameRepresentable: every
	// resolved member parses to a concrete prefix or is itself feed-bound).
	//
	// #3261: the structural check (not "row has >=1 prefix") is what closes the
	// two fail-opens Codex caught. (A) An address-book entry whose value is a
	// Junos dns-name / wildcard-address / range-address compiles to Value==""
	// (compiler_validate_warn.go) and expandBookNameToCIDRs USED to widen "" to
	// 0.0.0.0/0 — so a `deny <dns-name-book>` installed an overbroad deny-all
	// and a `permit` widened to permit-any. (B) A book MIXING a literal and a
	// dns-name member had row content from the literal, so a "row non-empty"
	// check called it representable while the dns-name member was silently
	// dropped (deny narrowing / under-match). nameRepresentable rejects BOTH
	// (any unrepresentable member taints the name) so the address sentinel is
	// emitted and the Rust preflight rejects the whole snapshot (previous-good
	// retained / fresh-boot default-deny). A set that CONTAINS a feed-bound
	// member stays representable (the member resolves via the overlay) and
	// #3294 (A′) now merges that member's live feed prefixes INTO the set's row,
	// so a `deny <set-with-a-feed>` enforces the feed portion instead of
	// under-denying it.
	addrRepresentable := func(tok string) bool {
		switch tok {
		// `any4`/`any6` are the internal short forms; `any-ipv4`/`any-ipv6` are
		// the Junos config keywords. A committed config never carries the Junos
		// keywords raw — compilePolicy rewrites them to 0.0.0.0/0 // ::/0
		// (compiler_security_policy.go normalizePolicyAddrToken) — but a lenient /
		// HA-synced / hand-built snapshot can, and the Rust matcher accepts the
		// WHOLE set as a family wildcard (policy.rs parse_v3_literal_set:
		// `"any4" | "any-ipv4" => any_v4`). Accept the same set so the
		// representability gate never emits a false __unsupported_address__
		// sentinel (a spurious whole-snapshot fail-close) for a token the matcher
		// actually honors — which would also make the #4394 match-policies
		// simulator falsely report ContentRejected for a raw `any-ipv4` policy.
		case "", "any", "any4", "any6", "any-ipv4", "any-ipv6":
			return true
		}
		if isUserspaceLiteralAddress(tok) {
			return true
		}
		if _, feedBound := feedOverlay[tok]; feedBound {
			return true
		}
		if _, known := nameToID[tok]; known {
			return nameRepresentable(cfg.Security.AddressBook, feedOverlay, tok, make(map[string]bool))
		}
		return false
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
		snap := buildOneRuleSnapshot(cfg, nameToID, addrRepresentable, slot.Policy, slot.FromZone, slot.ToZone, policyID, activeState)
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
	SliceIndex  uint32 // raw position within the set's policy slice (display key)
	Span        uint32 // expansion slots consumed (>=1)
	FromZone    string
	ToZone      string
	Policy      *config.Policy
}

func (s policyRuleSlot) policyID() uint32 {
	return s.PolicySetID*dataplane.MaxRulesPerPolicy + s.RuleIndex
}

// RuntimePolicyIDs returns the span-accumulated runtime/RT_FLOW policy ID for
// every configured policy, keyed by [policySetID, sliceIndex] where policySetID
// is the zone-pair set index (global policies occupy set len(Policies)) and
// sliceIndex is the raw position within that set's policy slice — exactly the
// (policySetID, i) loop variables the read-only show surfaces already track.
//
// The IDs are computed by walkPolicyRuleSlots, the same SSOT that assigns
// PolicyRuleSnapshot.PolicyID on the dataplane write side, so a display surface
// keying off this lookup prints the identical numeric ID the RT_FLOW/event path
// logs (#3063). Before this, the CLI policy-detail Index used the raw ordinal
// policySetID*MaxRulesPerPolicy + i, which does NOT advance by application-set
// expansion, so the displayed Index drifted from the logged policy ID after a
// multi-application policy and an operator cross-referencing a policy-deny log
// landed on the wrong row.
//
// Returned IDs are display identity only; they are NOT the counter handle. The
// per-policy counter store is name-keyed and ReadPolicyCounters takes the raw
// ordinal handle that round-trips through policyRuleIDForCounter — callers MUST
// keep passing the raw ordinal to ReadPolicyCounters. On a config that would
// overflow MaxRulesPerPolicy the walk stops early and the partial map omits the
// offending entries; a caller falls back to the raw ordinal for any missing key
// (such a config cannot be applied anyway, so the dataplane never enforces it).
func RuntimePolicyIDs(cfg *config.Config) map[[2]uint32]uint32 {
	out := make(map[[2]uint32]uint32)
	_ = walkPolicyRuleSlots(cfg, func(slot policyRuleSlot) error {
		out[[2]uint32{slot.PolicySetID, slot.SliceIndex}] = slot.policyID()
		return nil
	})
	return out
}

// PolicyIDsByStableKey maps every configured policy's STABLE string identity
// (StablePolicyRuleID: "<from>-><to>/<name>", global policies keyed with
// from==to=="junos-global") to the numeric runtime policy ID the dataplane
// stamps on each admitted session's policy_id (#3056). It is the same
// span-accumulated base ID walkPolicyRuleSlots writes to
// PolicyRuleSnapshot.PolicyID, so the value round-trips to what a live session
// carries.
//
// Unlike RuntimePolicyIDs — keyed by the POSITIONAL [policySetID, sliceIndex] —
// the key here is invariant to a sibling policy's deletion: removing policy B
// does not shift policy A's key, only (possibly) its numeric ID. A caller can
// therefore diff two configs by key and recover, from the OLD config, the
// numeric IDs of policies present before but absent after — the exact IDs the
// deleted policies' still-live sessions carry. The commit-time deletion-clear
// (#4234) uses this to invalidate those sessions.
//
// The numeric IDs are unique per policy within a single config (the userspace
// preflight rejects a duplicate policy_id, policy.rs DuplicatePolicyId), so the
// returned values collide only across the DIFFERENT configs a caller diffs —
// which is exactly the intended semantics (a deleted policy's OLD ID identifies
// its OLD sessions, independent of any NEW policy that inherits that slot).
//
// A config that would overflow MaxRulesPerPolicy stops the walk early (as in
// RuntimePolicyIDs); such a config is rejected at apply and never enforced, so a
// partial map is harmless.
func PolicyIDsByStableKey(cfg *config.Config) map[string]uint32 {
	out := make(map[string]uint32)
	_ = walkPolicyRuleSlots(cfg, func(slot policyRuleSlot) error {
		out[stablePolicyRuleID(slot.FromZone, slot.ToZone, slot.Policy.Name)] = slot.policyID()
		return nil
	})
	return out
}

// PoliciesByStableKey maps the same stable policy key PolicyIDsByStableKey uses
// (StablePolicyRuleID: "<from>-><to>/<name>", globals keyed junos-global) to the
// compiled *config.Policy behind it. It exists so a caller can diff two configs
// by key and, for a policy present in BOTH, compare its match/action to detect a
// MODIFICATION — the commit-time modified-policy re-evaluation (#4234
// policy-rematch) uses this alongside PolicyIDsByStableKey (which supplies the
// OLD numeric ID that a modified policy's still-live sessions carry). A policy
// expanded into multiple rule slots (application-set expansion) maps its key to
// the same *config.Policy on every slot, so last-write-wins stores the one
// policy object — exactly what a match/action comparison needs.
func PoliciesByStableKey(cfg *config.Config) map[string]*config.Policy {
	out := make(map[string]*config.Policy)
	_ = walkPolicyRuleSlots(cfg, func(slot policyRuleSlot) error {
		out[stablePolicyRuleID(slot.FromZone, slot.ToZone, slot.Policy.Name)] = slot.Policy
		return nil
	})
	return out
}

// walkPolicyRuleSlots invokes fn for every configured policy in config order,
// assigning each policy its slot in the runtime policy-ID namespace. It is the
// SHARED contract behind both the snapshot builder (the ID-WRITE side, #3145)
// and the counter resolver (the ID-READ side, #3143) so the two can never
// drift on how a policy ID maps to a (policy-set, rule-index) pair.
//
// Each policy's application-set expansion advances the per-set rule index by
// userspacePolicyRuleExpansionCount. A policy set may exactly fill its 256-slot
// namespace (indices 0..255, the full MaxRulesPerPolicy range) — every such ID
// stays inside the set's own namespace. Only a policy whose expansion would
// advance the per-set rule index PAST MaxRulesPerPolicy (256) — i.e. require an
// ID at index >= 256 — would cross into the following set's namespace; that is
// rejected fail-closed so the apply path retains the prior good dataplane state.
// This mirrors the legacy compiler guard (pkg/dataplane/compiler.go).
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
		for sliceIdx, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			span := userspacePolicyRuleExpansionCount(cfg, pol.Match.Applications)
			if ruleIndex+span > dataplane.MaxRulesPerPolicy {
				return fmt.Errorf("policy %s->%s: expanded rules exceed MaxRulesPerPolicy (%d) and would spill into the next policy set's ID namespace",
					zpp.FromZone, zpp.ToZone, dataplane.MaxRulesPerPolicy)
			}
			if err := fn(policyRuleSlot{
				PolicySetID: policySetID,
				RuleIndex:   ruleIndex,
				SliceIndex:  uint32(sliceIdx),
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
	for sliceIdx, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		span := userspacePolicyRuleExpansionCount(cfg, pol.Match.Applications)
		if globalRuleIndex+span > dataplane.MaxRulesPerPolicy {
			return fmt.Errorf("global policy: expanded rules exceed MaxRulesPerPolicy (%d) and would spill into the next policy set's ID namespace",
				dataplane.MaxRulesPerPolicy)
		}
		if err := fn(policyRuleSlot{
			PolicySetID: policySetID,
			RuleIndex:   globalRuleIndex,
			SliceIndex:  uint32(sliceIdx),
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
	addrRepresentable func(tok string) bool,
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
	// #3261: a side that names an address the matcher cannot represent (an
	// undefined book name, or a static book that resolves to no prefix — but
	// NOT a feed-bound name, whose empty content is MatchNone by design) must
	// reject the WHOLE snapshot rather than silently collapse to MatchNone. The
	// raw address strings otherwise fall through to the Rust matcher, which
	// drops an unparseable literal / empties a non-literal book; a
	// `deny <unrepresentable-address>` rule would then match nothing and fall
	// through to a later permit / default-permit (deny fail-OPEN). The sentinel
	// is the address analog of the application sentinel below.
	srcUnrepresentable := !allAddressTokensRepresentable(addrRepresentable, pol.Match.SourceAddresses)
	dstUnrepresentable := !allAddressTokensRepresentable(addrRepresentable, pol.Match.DestinationAddresses)
	// #3376: capture the exact offending tokens BEFORE the side collapses to
	// the sentinel so collectPolicyContentRejections can name them per side.
	var rejectedSrc, rejectedDst, rejectedApps []string
	if srcUnrepresentable {
		rejectedSrc = offendingAddressTokens(addrRepresentable, pol.Match.SourceAddresses)
		sourceAddresses = []string{unsupportedAddressSentinel}
	}
	if dstUnrepresentable {
		rejectedDst = offendingAddressTokens(addrRepresentable, pol.Match.DestinationAddresses)
		destinationAddresses = []string{unsupportedAddressSentinel}
	}
	applicationTerms, ok := expandUserspacePolicyApplications(cfg, pol.Match.Applications)
	if !ok {
		rejectedApps = offendingApplicationTokens(cfg, pol.Match.Applications)
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
	// #3261: force the unrepresentable-address sentinel onto BOTH the v3
	// (book-ids + literals) and the legacy (sourceAddresses, set above) address
	// shapes, clearing the book IDs, so the Rust preflight raises
	// UnrepresentableAddress no matter which shape it reads. Covers an undefined
	// book name (classified as a literal Rust would drop) AND a static
	// non-literal book (classified as a book ID whose table entry is empty).
	if srcUnrepresentable {
		srcBookIDs, srcLiterals = nil, []string{unsupportedAddressSentinel}
	}
	if dstUnrepresentable {
		dstBookIDs, dstLiterals = nil, []string{unsupportedAddressSentinel}
	}
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
		// #3148: a global policy keeps fromZone/toZone == "junos-global"
		// (preserving global-tier classification + ordering) and carries its
		// optional zone context out-of-band in these fields. For a zone-pair
		// policy pol.Match.FromZone/ToZone are empty, so this is inert.
		MatchFromZone: pol.Match.FromZone,
		MatchToZone:   pol.Match.ToZone,
		// #3376: build-time-only offending-token detail (not serialized).
		rejectedSourceAddresses: rejectedSrc,
		rejectedDestAddresses:   rejectedDst,
		rejectedApplications:    rejectedApps,
	}
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
	return StablePolicyRuleID(fromZone, toZone, ruleName)
}

// StablePolicyRuleID returns the stable string rule identity
// ("<from>-><to>/<name>") carried as PolicyRuleSnapshot.RuleID and joined to
// runtime events. It is exported so the read-only inventory surfaces (REST
// GetPolicies, gRPC GetPolicies) can emit the identical rule_id the snapshot /
// event path uses, without re-deriving the format and risking drift (#3336).
// Global policies pass fromZone == toZone == "junos-global", matching the
// snapshot builder.
func StablePolicyRuleID(fromZone, toZone, ruleName string) string {
	return fmt.Sprintf("%s->%s/%s", fromZone, toZone, ruleName)
}

// RuntimePolicyIndex returns the span-accumulated runtime/RT_FLOW policy ID for
// the policy at (policySetID, sliceIndex) from a RuntimePolicyIDs map, falling
// back to the raw ordinal policySetID*MaxRulesPerPolicy + sliceIndex when the
// map has no entry (a config the dataplane would reject for MaxRulesPerPolicy
// overflow — byte-identical to the pre-#3063 ordinal). This is the DISPLAY
// identity an inventory surface should report as policy_id so it matches the
// numeric ID the RT_FLOW/event path logs; it is NOT the counter handle passed
// to ReadPolicyCounters (callers keep passing the raw ordinal). Exported for
// the REST/gRPC inventory surfaces (#3336), the gRPC text detail renderer, and
// the local CLI detail renderer (which now delegates here) so the Index column
// cannot drift across surfaces (#3667).
func RuntimePolicyIndex(ids map[[2]uint32]uint32, policySetID, sliceIndex uint32) uint32 {
	if id, ok := ids[[2]uint32{policySetID, sliceIndex}]; ok {
		return id
	}
	return policySetID*dataplane.MaxRulesPerPolicy + sliceIndex
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
