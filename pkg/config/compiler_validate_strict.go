package config

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// validateDataplaneTypeStrict rejects retired dataplane backends at
// commit time. The parse path accepts `dataplane-type dpdk` as a
// legal known value (see compileSystemDataplaneType +
// validDataplaneType) so that `load merge` / `load override` of a
// pre-retirement config does not syntax-error; this strict validator
// is what tells the operator to migrate.
//
// Acceptance criterion in #1526 pins the verbatim message:
//
//	"the DPDK dataplane backend has been retired; use 'set system dataplane-type userspace' (see #1525)"
//
// Tests substring-match the phrase so the same assertion holds
// whether the error is observed via `CompileConfig` directly,
// via `Store.CommitCheck()` (which returns the raw error), or via
// `Store.Commit()` (which wraps it as "commit check failed: ...").
func validateDataplaneTypeStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if cfg.System.DataplaneType == dataplaneTypeDPDK {
		return ErrDPDKDataplaneRetired
	}
	if cfg.System.DataplaneType == dataplaneTypeEBPF {
		return ErrEBPFDataplaneRetired
	}
	return nil
}

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

// reservedZoneNames is the set of tokens the dataplane / Junos grammar reserves
// for a special context and that therefore must NEVER be the name of an
// operator-defined `security zones security-zone <name>` (#3055). It is used
// ONLY by the zone-DEFINITION gate (validateReservedZoneNamesStrict).
//
// It is DELIBERATELY DISTINCT from policyZoneSpecialTokens (the zone-REFERENCE
// exemption set) — see that var's comment. The two gates are mutually
// reinforcing and must not be unified: a zone named "junos-global" is rejected
// at definition here, while a policy that REFERENCES `from-zone junos-global`
// against no defined zone stays hard-rejected by the reference gate (NOT made
// reference-exempt). Adding "junos-global" to the reference-exempt set would
// silently re-open the device-wide-permit class this gate closes, because the
// dataplane (userspace-dp/src/policy.rs:1021) classifies a "junos-global"
// reference as a device-wide global rule.
//
//   - "junos-global" — the device-wide global-policy sentinel. The userspace
//     dataplane (userspace-dp/src/policy.rs) string-matches a from-zone/to-zone
//     literally equal to "junos-global" and reclassifies the policy as a global
//     fallback (JUNOS_GLOBAL_ZONE_ID = u16::MAX) evaluated for EVERY flow. An
//     operator-defined zone of this name would silently turn its zone-scoped
//     rules into device-wide fallbacks that permit traffic for unrelated zone
//     pairs — a security-boundary escape.
//
//   - "any"         — Junos wildcard zone (`from-zone any`/`to-zone any`); a
//     reserved policy-context token, never a named zone-id lookup, so a real
//     zone named "any" can never be selected and would shadow the wildcard.
//     (The dataplane DOES index a from-zone/to-zone `any` policy as of #3090 —
//     dedicated from-any/to-any/both-any tiers in userspace-dp/src/policy.rs —
//     but a zone DEFINITION named "any" is rejected here regardless.)
//
//   - "junos-host"  — Junos reserved self-traffic zone (host-inbound / host-
//     outbound policy context); it is never declared as a `security zone`.
var reservedZoneNames = map[string]struct{}{
	"junos-global": {},
	"any":          {},
	"junos-host":   {},
}

// policyZoneSpecialTokens is the set of reserved from-zone/to-zone tokens
// that name a context rather than an operator-defined security zone, and so
// must be exempt from the "zone must be defined" gate
// (validatePolicyZoneReferencesStrict, #2401):
//
//   - ""            — an empty token: a zone-pair with no name compiles to no
//     usable rule and is not an undefined-zone reference per se; leave it to
//     the structural compiler rather than reporting a confusing `""` error.
//   - "any"         — Junos wildcard zone (`from-zone any`/`to-zone any`); kept
//     exempt HERE so the undefined-zone gate does not emit a confusing "define
//     `security zones security-zone any`" error (such a zone definition is
//     itself rejected). A from-zone/to-zone `any` is a fully-enforced wildcard
//     as of #3090 (indexed into the from-any/to-any/both-any tiers in
//     userspace-dp/src/policy.rs), so it is accepted here and NOT specially
//     rejected — it is simply not an undefined-zone reference.
//   - "junos-host"  — Junos reserved self-traffic zone (host-inbound / host-
//     outbound policy context); it is never declared as a `security zone`.
//
// This set is DELIBERATELY NOT derived from reservedZoneNames and DELIBERATELY
// OMITS "junos-global" (#3055). The two gates serve opposite purposes: the
// definition gate rejects a reserved NAME, while this reference gate must keep
// hard-rejecting (+ warning) a policy that REFERENCES `from-zone junos-global`
// / `to-zone junos-global` when no such zone is defined — making junos-global
// reference-exempt would let that reference reach the dataplane, which then
// (policy.rs:1021) classifies it as a device-wide global rule: the exact
// fail-OPEN this PR closes. The definition gate already guarantees no zone
// named junos-global can exist, so an explicit junos-global reference is always
// the bug, never a legitimate named-zone use. Global policies (`security
// policies global { ... }`) keep the `junos-global` sentinel on their
// structural from/to-zone (mapped only when the dataplane snapshot is built,
// see pkg/dataplane/userspace/policies.go), so they never reference an
// undefined STRUCTURAL zone. As of #3148 a global policy MAY carry an optional
// `match from-zone`/`match to-zone` context, which validatePolicyZoneReferences
// Strict now validates against this same special-token + defined-zone gate
// (empty = all-zones, exempt via "").
var policyZoneSpecialTokens = map[string]struct{}{
	"":           {},
	"any":        {},
	"junos-host": {},
}

// validateReservedZoneNamesStrict hard-rejects a `security zones security-zone
// <name>` DEFINITION whose name is a reserved sentinel token (#3055).
//
// The bug: compileZones accepts any zone name, and the userspace dataplane
// (userspace-dp/src/policy.rs) string-matches a from-zone/to-zone literally
// equal to "junos-global" and reclassifies the policy as a device-wide global
// fallback (JUNOS_GLOBAL_ZONE_ID = u16::MAX) evaluated for every flow. So an
// operator-defined zone named "junos-global" turns its zone-scoped policies
// into device-wide fallbacks that can permit traffic for unrelated zone pairs —
// a silent security-boundary escape. "any" and "junos-host" are reserved policy
// context tokens that must likewise never be a real zone name (a zone the
// dataplane could never select, shadowing the wildcard / self-traffic context).
//
// Strict on the commit / commit-check path (CompileConfig — hard reject so the
// operator sees it); downgraded to a cfg.Warnings entry on the tolerant load /
// peer-sync paths (CompileConfigLenient / CompileConfigForNodeLenient, flag
// lenientReservedZoneNames) so an already-persisted or peer-synced config an
// older binary accepted still BOOTS (#1960 fail-closed-on-load doctrine).
// Iteration is over cfg.Security.Zones in sorted name order so the first-
// reported error is deterministic. Reserved tokens are reported in a fixed
// order for a stable message.
func validateReservedZoneNamesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, reserved := reservedZoneNames[name]; reserved {
			return fmt.Errorf(
				"security zone %q uses a reserved name: %q (along with \"any\" "+
					"and \"junos-host\") is a reserved dataplane/Junos context "+
					"token and cannot be the name of a `security zones "+
					"security-zone` — the dataplane would reclassify the zone's "+
					"policies as device-wide global fallbacks (or never select "+
					"the zone), silently breaking zone isolation; rename the zone",
				name, name)
		}
	}
	return nil
}

// validateScreenProfileReferencesStrict hard-rejects a security zone whose
// `screen <name>` references a screen-ids-option profile the configuration
// never defines under `set security screen ids-option <name>` (#3066).
//
// Before this gate the reference was WARNED only (ValidateConfig /
// compiler_validate_warn.go), so the commit succeeded with an unenforceable
// reference. At runtime the userspace dataplane fails OPEN: a missing profile
// makes ScreenEngine::check_packet_with_zone_id return ScreenVerdict::Pass
// (userspace-dp/src/screen/mod.rs — `let Some(profile) = self.profiles.get(zone)
// else { return ScreenVerdict::Pass; }`), so EVERY screen check (land,
// syn-flood, ping-death, teardrop, scans, rate limits) is silently skipped for
// that zone. A typo'd or uncreated profile name thus leaves the zone with no
// screen protection while the operator believes screening is active — the same
// silent fail-OPEN commit-validation class as the closed #2401 (undefined
// policy zone references). Junos rejects an undefined `screen ids-option`
// reference at commit; this validator restores that fail-CLOSED parity.
//
// Strict on the commit / commit-check path (CompileConfig — hard-reject);
// downgraded to a cfg.Warnings entry on the tolerant load / peer-sync paths
// (CompileConfigLenient / CompileConfigForNodeLenient, flag
// lenientScreenProfileRefs) so an already-persisted or peer-synced config that
// an older binary accepted still BOOTS (#1960 fail-closed-on-load doctrine).
// On that tolerant path the dataplane is NOT independently safe — the missing
// profile fails open — so the warning is the operator's only signal; the strict
// commit gate is the real fix that keeps a bad reference from ever reaching the
// dataplane. Iteration is over cfg.Security.Zones in sorted name order so the
// first-reported error is deterministic.
func validateScreenProfileReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		zone := cfg.Security.Zones[name]
		if zone == nil || zone.ScreenProfile == "" {
			continue
		}
		if _, ok := cfg.Security.Screen[zone.ScreenProfile]; !ok {
			return fmt.Errorf(
				"security zone %q references undefined screen profile %q; define `set security screen ids-option %s` in the same commit or the zone silently runs with NO screen protection (the dataplane fails open for a missing profile)",
				name, zone.ScreenProfile, zone.ScreenProfile)
		}
	}
	return nil
}

// sortedScreenNames returns the screen-profile names in deterministic order so
// the strict validators report the first offender stably across runs.
func sortedScreenNames(screens map[string]*ScreenProfile) []string {
	names := make([]string, 0, len(screens))
	for name := range screens {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// validateScreenNumericStrict hard-rejects a screen profile carrying a numeric
// threshold / count leaf whose explicitly-provided value is not a positive
// integer — #3317.
//
// Screen threshold leaves (icmp/udp flood, ip ip-sweep threshold, tcp port-scan
// threshold, the tcp syn-flood alarm/attack/source/destination-threshold and
// timeout subfields, and limit-session source/destination-ip-based) are untyped
// in the schema. Before this gate compileScreen swallowed the strconv.Atoi
// failure and silently fell back to a Junos default (icmp/udp flood, ip-sweep,
// port-scan, syn-flood attack-threshold via #3024/#3230) or to zero/disabled
// (the other syn-flood subfields and limit-session). A typo'd value
// (`attack-threshold abc`, `udp flood 99999999999999999999`, `source-ip-based
// -1`) therefore committed cleanly while the enforced control was materially
// different from — usually weaker or fully disabled relative to — what the
// operator authored: a silent fail-open. SRX rejects a non-numeric screen value
// at commit.
//
// compileScreen records every explicitly-provided value that does not parse as
// a positive integer on ScreenProfile.BadNumeric (path + raw value); an EMPTY
// value is the "enabled without an explicit threshold" case and is NOT recorded
// (it legitimately takes the Junos default — #3230). This gate makes the
// refusal operator-visible at commit, naming the screen profile, the leaf path,
// and the offending value. The walk is deterministic (profiles sorted by name,
// BadNumeric in config order). On the tolerant load / peer-sync path the caller
// downgrades the returned error to a warning (#1960 no-brick); compileScreen
// applied the default for the bad value independently, so a leniently-loaded
// profile is no worse than the pre-gate behavior — but the operator never
// reaches that state through a commit. Mirrors validateFilterDSCPStrict.
func validateScreenNumericStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for _, name := range sortedScreenNames(cfg.Security.Screen) {
		profile := cfg.Security.Screen[name]
		if profile == nil || len(profile.BadNumeric) == 0 {
			continue
		}
		bad := profile.BadNumeric[0]
		return fmt.Errorf(
			"security screen ids-option %q: `%s` value %q is not a positive "+
				"integer (an unparseable value is silently dropped and the leaf "+
				"falls back to a default or to zero/disabled, so the protection "+
				"is weaker than — or fully different from — what was configured)",
			name, bad.Path, bad.Value)
	}
	return nil
}

// validateScreenUnknownStrict hard-rejects a screen profile carrying a leaf the
// dataplane does NOT support — #3318.
//
// The screen schema subtrees are open (schema_security.go: `icmp`, `tcp`, `ip`,
// `udp` model only their named children; an unknown keyword resolves to a nil
// schema child and returns no error), and compileScreen switched only on the
// known child names with no default arm. A misspelled or unsupported leaf
// (`icmp pong-death`, `tcp syn-flood whitelist`, `ip bad-option`, an unsupported
// SRX screen such as `tcp sweep`/`ip block-frag`) therefore committed cleanly
// and was silently DROPPED — the operator believed a protection was enabled when
// it was entirely absent, a "configured but not enforced" posture with no
// warning. SRX fails commit on an unknown screen option.
//
// The supported set is EXACTLY the compileScreen switch cases: icmp
// {ping-death, fragment, flood}; ip {source-route-option, tear-drop, ip-sweep
// {threshold}}; tcp {land, winnuke, syn-frag, syn-fin, no-flag, fin-no-ack,
// syn-flood {alarm/attack/source/destination-threshold, timeout}, port-scan
// {threshold}}; udp {flood}; limit-session {source-ip-based,
// destination-ip-based}. These are the leaves compileScreen ACCEPTS (records a
// typed field for) — most also map to a field the userspace screen engine
// (userspace-dp/src/screen) enforces, but a few are accepted-but-not-yet-
// published to the snapshot: the syn-flood alarm-threshold / source-threshold /
// destination-threshold / timeout subfields are compiled into SynFloodConfig and
// not currently emitted to the dataplane (tracked in #3315). This gate's
// contract is "rejects what compileScreen does NOT model", not "guarantees every
// accepted leaf is enforced" — closing the publish gap is #3315's scope.
// compileScreen's default arms record every
// other leaf — at the top-level family, per-family, and per-subtree depth — on
// ScreenProfile.UnknownLeaves (the full `<family> <leaf>` path); this gate makes
// the refusal operator-visible at commit. No NEW screening is implemented — the
// unsupported leaf is rejected, which is the fail-closed-correct outcome. The
// walk is deterministic (profiles sorted by name, UnknownLeaves in config
// order). On the tolerant load / peer-sync path the caller downgrades the
// returned error to a warning (#1960 no-brick); the dataplane never represented
// the leaf, so a leniently-loaded profile runs without it independently — but
// the operator never reaches that state through a commit. Mirrors
// validateFilterFromMatchStrict.
func validateScreenUnknownStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for _, name := range sortedScreenNames(cfg.Security.Screen) {
		profile := cfg.Security.Screen[name]
		if profile == nil || len(profile.UnknownLeaves) == 0 {
			continue
		}
		return fmt.Errorf(
			"security screen ids-option %q: `%s` is not a supported screen "+
				"option (the dataplane does not enforce it, so it would be "+
				"silently dropped and the protection the operator believes is "+
				"enabled would be absent); remove it or use a supported option "+
				"such as icmp ping-death/fragment/flood, ip source-route-option/tear-drop/"+
				"ip-sweep, tcp land/winnuke/syn-frag/syn-fin/no-flag/fin-no-ack/"+
				"syn-flood/port-scan, udp flood, or limit-session",
			name, profile.UnknownLeaves[0])
	}
	return nil
}

// validateTrailingTokensStrict hard-rejects trailing tokens that rode past
// the legitimate value arity of a config leaf the generic schema-walk scalar
// gate cannot reach (#3332). Two shapes leak:
//
//   - address-book `address <name> <prefix>` / `address <name> description
//     <text>`: the `address` schema node is `multi:true` (it must absorb the
//     `description` sub-token onto its Keys to keep the #2419 dual-AST shape),
//     so the scalar-leaf arity gate skips it, and the compiler reads only the
//     prefix / description-text slot — `address h2 description web-server
//     bogus` silently drops `bogus`.
//   - IKE gateway compact-hierarchical `dynamic hostname <fqdn> <extra>`: the
//     flat-set form lands a `hostname` scalar CHILD the generic gate covers,
//     but the compact form collapses the tokens onto the parent `dynamic`
//     node's Keys and the compiler reads only Keys[2].
//
// Both record the leftover tokens on the typed struct during compile
// (mergeAddressNode / compileIPsec); this gate makes the silent drop
// operator-visible. Strict on commit / commit-check; the call site
// (compiler.go) downgrades to a warning on the tolerant load / peer-sync
// path so an already-persisted or peer-synced config still boots (#1960
// no-brick) — the dropped token never reached the dataplane, so a leniently
// loaded config runs exactly as it did before the gate. The walk is
// deterministic (entries sorted by name). Mirrors validateScreenUnknownStrict.
func validateTrailingTokensStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// Address books: the global book plus every zone-local book. The
	// zone-local originals (sec.Zones[z].AddressBook) carry the recorded
	// TrailingTokens; resolveZoneLocalAddressBooks copies only Value /
	// Description into the qualified global entries, so both sources are
	// walked to catch the leak regardless of attachment point.
	checkBook := func(scope string, book *AddressBook) error {
		if book == nil {
			return nil
		}
		names := make([]string, 0, len(book.Addresses))
		for name := range book.Addresses {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			addr := book.Addresses[name]
			if addr == nil || len(addr.TrailingTokens) == 0 {
				continue
			}
			return fmt.Errorf(
				"security %saddress-book address %q: unexpected trailing token "+
					"%q (an address takes a single prefix or `description "+
					"<text>`; the extra token would be silently dropped — "+
					"quote a multi-word description as `\"...\"`)",
				scope, name, addr.TrailingTokens[0])
		}
		return nil
	}
	if err := checkBook("", cfg.Security.AddressBook); err != nil {
		return err
	}
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, zn := range zoneNames {
		z := cfg.Security.Zones[zn]
		if z == nil {
			continue
		}
		if err := checkBook(fmt.Sprintf("zones security-zone %s ", zn), z.AddressBook); err != nil {
			return err
		}
	}

	// IKE gateways: compact-hierarchical `dynamic hostname <fqdn> <extra>`.
	gwNames := make([]string, 0, len(cfg.Security.IPsec.Gateways))
	for name := range cfg.Security.IPsec.Gateways {
		gwNames = append(gwNames, name)
	}
	sort.Strings(gwNames)
	for _, gn := range gwNames {
		gw := cfg.Security.IPsec.Gateways[gn]
		if gw == nil || len(gw.DynamicHostnameExtras) == 0 {
			continue
		}
		return fmt.Errorf(
			"security ike gateway %q dynamic hostname: unexpected trailing "+
				"token %q (the dynamic peer hostname is a single FQDN; the "+
				"extra token would be silently dropped)",
			gn, gw.DynamicHostnameExtras[0])
	}
	return nil
}

// validateFlowAgingStrict is the #3440 H2 commit-time gate for
// `security flow aging`. The aging subtree was an opaque untyped schema
// node, so its values were parsed with a bare strconv.Atoi and stored with
// no cross-field check. The typed schema leaves (schema_security.go) now
// bound each individual value (early-ageout >= 0, watermarks 0..100), but
// two failure modes are cross-field / structural and must be caught here:
//
//   - an unknown child leaf (`set security flow aging bogus 5`) — the schema
//     walker leaves unknown keywords to the compiler, and compileFlow used
//     to silently drop them; they are now recorded on
//     FlowConfig.AgingUnknownLeaves and rejected here (mirrors #3318
//     validateScreenUnknownStrict).
//   - low-watermark >= high-watermark when both are nonzero — aging
//     activates at high-watermark and deactivates below low-watermark, so a
//     low >= high config can never deactivate (it oscillates or latches on),
//     which is the H2 "high-watermark 90 low-watermark 95" example. Junos
//     requires low < high.
//
// Strict on commit / commit-check; the call site (compiler.go) downgrades
// to a warning on the tolerant load / peer-sync path so an already-persisted
// or peer-synced config still boots (#1960 no-brick) — the userspace
// dataplane does not enforce watermark aging at all (the #3440 H1 warning),
// so a leniently-loaded bad value is inert anyway.
func validateFlowAgingStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	flow := cfg.Security.Flow
	if len(flow.AgingUnknownLeaves) > 0 {
		return fmt.Errorf(
			"security flow aging: `%s` is not a supported aging option "+
				"(it would be silently dropped and have no effect); the "+
				"supported options are early-ageout, high-watermark, and "+
				"low-watermark",
			flow.AgingUnknownLeaves[0])
	}
	if flow.AgingHighWatermark > 0 && flow.AgingLowWatermark > 0 &&
		flow.AgingLowWatermark >= flow.AgingHighWatermark {
		return fmt.Errorf(
			"security flow aging: low-watermark %d must be less than "+
				"high-watermark %d (aging activates at high-watermark and "+
				"only deactivates below low-watermark; low >= high can never "+
				"deactivate)",
			flow.AgingLowWatermark, flow.AgingHighWatermark)
	}
	return nil
}

// MaxUsableZoneID is the largest security-zone id the live AF_XDP userspace
// dataplane can carry, and therefore the maximum number of DISTINCT zones a
// config may define. #3075 widened the two same-host event-stream u8 chokepoints
// (event_stream/codec.rs, forwarding_build/zones.rs + the fabric zone MAC) to
// u16 and replaced the sorted 1..N positional id assignment with a stable
// name-hash (config.StableZoneID, folded into [1, ZoneIDReservedMin-1]). The
// binding constraint is therefore no longer the old u8 wire field (#2391, now
// SUPERSEDED) but the reserved-sentinel range at the top of the u16 space:
// JUNOS_GLOBAL_ZONE_ID (u16::MAX) and the junos-host zone (u16::MAX-1 =
// ZoneIDReservedMin). The usable space is [1, ZoneIDReservedMin-1] = [1, 65533],
// so a config cannot define more than that many distinct zones (pigeonhole: a
// stable id is a 1:1 function of the name into 65533 slots). The fold guarantees
// no configured zone ever lands in the reserved range; the StableZoneID
// collision gate (validateZoneIDCollisionAST) is the PRIMARY duplicate-id guard.
const MaxUsableZoneID = int(ZoneIDReservedMin) - 1 // 65533

// validateZoneCountStrict hard-rejects a configuration that defines more
// security zones than the u16 zone-id space can address. After #3075 zone ids
// are a stable name-hash folded into [1, ZoneIDReservedMin-1]; by the pigeonhole
// principle a config with more than MaxUsableZoneID distinct zones cannot be
// assigned distinct ids (and would in practice be rejected far sooner by the
// StableZoneID collision gate, which fires on the first hash collision). This
// validator is a cheap O(1) belt against that pathological count; the collision
// gate (validateZoneIDCollisionAST) is the real duplicate-id protection and the
// fold itself guarantees no reserved-sentinel id is ever produced. (#2391 is
// SUPERSEDED: the cap is no longer a 255-id u8 wire limit.)
//
// Strict on the commit / commit-check path (CompileConfig — hard-reject);
// downgraded to a cfg.Warnings entry on the tolerant load / peer-sync paths
// (CompileConfigLenient / CompileConfigForNodeLenient, flag lenientZoneCount) so
// an already-persisted or peer-synced config that an older binary accepted still
// BOOTS (#1960 fail-closed-on-load doctrine).
func validateZoneCountStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	n := len(cfg.Security.Zones)
	if n > MaxUsableZoneID {
		return fmt.Errorf(
			"configuration defines %d security zones, but the dataplane can address at most %d distinct zones (zone ids are a stable name-hash in a u16 space, top two ids reserved); reduce the zone count to %d or fewer",
			n, MaxUsableZoneID, MaxUsableZoneID)
	}
	return nil
}

// zoneIfaceLogicalKeys returns the set of effective logical-interface keys a
// single `set security zones security-zone <z> interfaces <iface>` entry
// claims, mirroring how pkg/dataplane/userspace.buildInterfaceZoneMap expands a
// zone-interface entry into the userspace interface->zone lookup (#3072). It is
// the conflict-detection counterpart of that expansion: two zones whose key
// sets intersect would map the same physical/logical interface to two zone ids,
// which buildInterfaceZoneMap silently resolves first-writer-wins over the
// sorted zone names.
//
//   - A unit-qualified entry (`base.unit`, e.g. `ge-0/0/0.0`) claims exactly the
//     one logical unit key `base.unit`. It deliberately does NOT claim the bare
//     `base` key: two DIFFERENT units of one physical interface in two zones
//     (`ge-0/0/0.0` in trust, `ge-0/0/0.1` in untrust) is a valid VLAN sub-
//     interface split and must not be rejected. (buildInterfaceZoneMap's bare
//     `base` fallback for untagged lookups is a coarse first-writer-wins
//     artifact, not an operator-visible second assignment.)
//   - A bare entry (`base`, no unit) claims the whole physical interface: the
//     bare key `base` plus every configured unit `base.<n>` from
//     cfg.Interfaces. Listing the same physical interface bare in two zones, or
//     bare in one zone and a unit of it in another, is a genuine multi-zone
//     assignment.
//
// A trailing-dot form (`base.`) is treated as bare (no specific unit), matching
// buildInterfaceZoneMap which falls through to the unit-expansion branch when
// the unit token is empty.
func zoneIfaceLogicalKeys(cfg *Config, iface string) []string {
	base, unit, ok := strings.Cut(iface, ".")
	if ok && unit != "" {
		return []string{base + "." + unit}
	}
	// Bare interface: claim the physical interface and all its configured units.
	if base == "" {
		base = iface
	}
	keys := []string{base}
	if cfg != nil {
		if ifCfg := cfg.Interfaces.Interfaces[base]; ifCfg != nil {
			for unitNum := range ifCfg.Units {
				keys = append(keys, fmt.Sprintf("%s.%d", base, unitNum))
			}
		}
	}
	return keys
}

// validateZoneInterfaceMembershipStrict hard-rejects a configuration that
// assigns the same interface to more than one security zone (#3072).
//
// pkg/dataplane/userspace.buildInterfaceZoneMap builds the interface->zone
// lookup by iterating the zone names in SORTED order and writing each interface
// (plus its base/unit aliases) first-writer-wins. So an interface listed under
// two zones is silently accepted at commit and resolved to whichever zone name
// sorts first — independent of operator intent or config order. A packet that
// should be evaluated as `trust -> untrust` is instead evaluated as
// `aaa -> untrust` purely because "aaa" < "trust", causing an unintended permit
// or deny. Junos rejects an interface in two zones; a security appliance must
// not silently choose one.
//
// This validator restores that fail-CLOSED parity. It computes, per zone (in
// sorted order for a deterministic first-reported error), the logical-interface
// keys each zone-interface entry claims (zoneIfaceLogicalKeys — the same
// base/unit expansion buildInterfaceZoneMap performs) and rejects the first key
// claimed by two different zones, naming the interface and BOTH conflicting
// zones. Listing the same interface twice WITHIN one zone is harmless (a
// repeated `set`) and is not flagged. Two distinct units of one physical
// interface in two zones (a valid VLAN split) is NOT flagged — see
// zoneIfaceLogicalKeys.
//
// Strict on the commit / commit-check path (CompileConfig — hard-reject);
// downgraded to a cfg.Warnings entry on the tolerant load / peer-sync paths
// (CompileConfigLenient / CompileConfigForNodeLenient, flag
// lenientZoneInterfaceMembership) so an already-persisted or peer-synced config
// that an older binary accepted still BOOTS (#1960 fail-closed-on-load
// doctrine). On that tolerant path behavior is unchanged and deterministic:
// buildInterfaceZoneMap keeps its first-writer-wins (sorted-zone) resolution, so
// the leniently-loaded config forwards exactly as it did before this gate
// existed — just with an operator-visible warning.
func validateZoneInterfaceMembershipStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	type claim struct {
		zone string
		raw  string
	}
	owner := make(map[string]claim)
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, zoneName := range zoneNames {
		zone := cfg.Security.Zones[zoneName]
		if zone == nil {
			continue
		}
		for _, iface := range zone.Interfaces {
			if iface == "" {
				continue
			}
			for _, key := range zoneIfaceLogicalKeys(cfg, iface) {
				prev, exists := owner[key]
				if exists {
					if prev.zone != zoneName {
						return fmt.Errorf(
							"interface %q is assigned to security zones %q and %q; an interface must belong to exactly one security zone (the dataplane silently resolves a multi-zone interface to whichever zone name sorts first, evaluating traffic against the wrong zone's policy) — remove it from one zone",
							iface, prev.zone, zoneName)
					}
					// Same zone (repeated set, or base/unit overlap within
					// one zone): keep the first claim, not a conflict.
					continue
				}
				owner[key] = claim{zone: zoneName, raw: iface}
			}
		}
	}
	return nil
}

// #1830 (e): the #1733 MaxEqualFlowWorkers constant and
// validateEqualFlowWorkerCapStrict were retired together with the Rust
// MAX_WORKERS_SCRATCH cap they mirrored. The v8 lease rotation scratch
// is now heap-sized to the true worker count, so equal-flow-enforcement
// is supported at any configured worker count.

const (
	dataplaneTypeEBPF      = "ebpf"
	dataplaneTypeDPDK      = "dpdk"
	dataplaneTypeUserspace = "userspace"
)

func effectiveDataplaneType(dpType string) string {
	if dpType == "" {
		return dataplaneTypeUserspace
	}
	return dpType
}

func validDataplaneType(dpType string) bool {
	switch dpType {
	case dataplaneTypeEBPF, dataplaneTypeDPDK, dataplaneTypeUserspace:
		return true
	default:
		return false
	}
}

func userspaceSynCookieProtectionActive(cfg *Config) bool {
	if cfg == nil || effectiveDataplaneType(cfg.System.DataplaneType) != dataplaneTypeUserspace ||
		cfg.Security.Flow.SynFloodProtectionMode != "syn-cookie" {
		return false
	}
	for _, zone := range cfg.Security.Zones {
		if zone == nil || zone.ScreenProfile == "" {
			continue
		}
		profile := cfg.Security.Screen[zone.ScreenProfile]
		if profile != nil && profile.TCP.SynFlood != nil &&
			profile.TCP.SynFlood.AttackThreshold > 0 {
			return true
		}
	}
	return false
}

// knownManagedProcessNames is the set of Junos process names that bpfrx
// actually honours when `system processes X disable` is configured.
// The runtime sites hard-code their process name (not a table lookup):
//   - pkg/daemon/daemon.go ~:715 — `isProcessDisabled(cfg, "snmpd")`
//   - pkg/daemon/daemon_system.go ~:383 — `isProcessDisabled(cfg, "ntp")`
//
// This table mirrors those hard-codes for the purpose of the #654
// validation warning. Any addition here MUST be paired with a matching
// runtime gating site, or the warning will go quiet while the knob
// remains a no-op.
var knownManagedProcessNames = map[string]struct{}{
	"snmpd": {},
	"ntp":   {},
}

func isKnownProcessName(name string) bool {
	_, ok := knownManagedProcessNames[name]
	return ok
}

// validateDHCPStaticBindingsStrict (#2243) hard-rejects, at commit /
// commit-check, a DHCP-server static (fixed/reserved) host binding that
// would render a broken or silently-mismatched Kea reservation:
//
//   - a binding missing its fixed-address (no reservation can be emitted);
//   - a fixed-address that is not a valid IP literal;
//   - a fixed-address whose family disagrees with the local-server family
//     (a v6 literal under dhcp-local-server, or a v4 literal under
//     dhcpv6-local-server) — Kea would reject the subnet;
//   - a fixed-address outside the enclosing pool's subnet (Kea silently
//     ignores such a reservation, so the client never gets the reserved
//     address — fail loud instead);
//   - a duplicate MAC identity or duplicate fixed-address within the same
//     pool (the reservation set would be ambiguous / Kea-rejected).
//
// The MAC shape itself is already gated by the schema (ValidateMAC); this
// validator re-parses it only to normalize the duplicate-identity key. A
// binding with no Subnet on its pool skips the in-subnet check (the pool is
// then incomplete in other ways the operator will hit first) but still gets
// the family/duplicate checks.
func validateDHCPStaticBindingsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(srv *DHCPLocalServerConfig, family string, wantV6 bool) error {
		if srv == nil {
			return nil
		}
		// Deterministic iteration so the first reported error is stable
		// across runs (map order is otherwise random).
		groupNames := make([]string, 0, len(srv.Groups))
		for name := range srv.Groups {
			groupNames = append(groupNames, name)
		}
		sort.Strings(groupNames)
		for _, gname := range groupNames {
			group := srv.Groups[gname]
			if group == nil {
				continue
			}
			for _, pool := range group.Pools {
				if pool == nil || len(pool.StaticBindings) == 0 {
					continue
				}
				var prefix netip.Prefix
				havePrefix := false
				if pool.Subnet != "" {
					if p, err := netip.ParsePrefix(pool.Subnet); err == nil {
						prefix = p.Masked()
						havePrefix = true
					}
				}
				seenMAC := make(map[string]string, len(pool.StaticBindings))
				seenAddr := make(map[string]string, len(pool.StaticBindings))
				for _, sb := range pool.StaticBindings {
					if sb == nil {
						continue
					}
					where := fmt.Sprintf("%s group %q pool %q static-binding %q",
						family, group.Name, pool.Name, sb.MACAddress)
					if sb.FixedAddress == "" {
						return fmt.Errorf("%s has no fixed-address — a reservation cannot be emitted", where)
					}
					addr, err := netip.ParseAddr(sb.FixedAddress)
					if err != nil {
						return fmt.Errorf("%s fixed-address %q is not a valid IP address", where, sb.FixedAddress)
					}
					if wantV6 && !addr.Is6() {
						return fmt.Errorf("%s fixed-address %q is not an IPv6 address (required under dhcpv6-local-server)", where, sb.FixedAddress)
					}
					if !wantV6 && !addr.Is4() {
						return fmt.Errorf("%s fixed-address %q is not an IPv4 address (required under dhcp-local-server)", where, sb.FixedAddress)
					}
					if havePrefix && !prefix.Contains(addr) {
						return fmt.Errorf("%s fixed-address %q is outside the pool subnet %s (Kea would silently drop the reservation)", where, sb.FixedAddress, pool.Subnet)
					}
					macKey := strings.ToLower(sb.MACAddress)
					if prev, dup := seenMAC[macKey]; dup {
						return fmt.Errorf("%s duplicates the hardware-address already bound to %s in the same pool", where, prev)
					}
					seenMAC[macKey] = sb.FixedAddress
					addrKey := addr.String()
					if prevMAC, dup := seenAddr[addrKey]; dup {
						return fmt.Errorf("%s fixed-address %q is already reserved for %s in the same pool", where, sb.FixedAddress, prevMAC)
					}
					seenAddr[addrKey] = sb.MACAddress
				}
			}
		}
		return nil
	}
	if err := check(cfg.System.DHCPServer.DHCPLocalServer, "dhcp-local-server", false); err != nil {
		return err
	}
	return check(cfg.System.DHCPServer.DHCPv6LocalServer, "dhcpv6-local-server", true)
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

// vrrpVIPHostIP returns the host IP of a VRRP virtual-address string. xpf
// requires a /prefix (schema_interfaces.go vrrpGroupSchemaNode), so the VIP is
// normally CIDR (e.g. 10.0.1.1/24); a bare IP is tolerated here so a leniently-
// loaded legacy config is still classified. An unparseable value returns nil
// and is left to the schema validator's concern.
func vrrpVIPHostIP(vip string) net.IP {
	if vip == "" {
		return nil
	}
	if ip, _, err := net.ParseCIDR(vip); err == nil {
		return ip
	}
	return net.ParseIP(vip)
}

// validateVRRPVirtualAddressSubnet (#3013) rejects a VRRP virtual-address that
// does not fall within any subnet configured on the same interface unit for the
// matching address family.
//
// Background: a `vrrp-group <id> virtual-address <vip>` block is authored under
// a `family inet|inet6 address <prefix>` on a unit. In Junos/vSRX a VIP outside
// every on-link subnet of the unit is a commit-time configuration error. xpf
// accepted it: at runtime the daemon installs the VIP as a host address, but
// with no connected route covering it return traffic sourced from the VIP has
// no on-link subnet association — a silent misconfiguration (operator-visible
// only as a blackhole). This check restores vSRX config-parity by catching the
// misconfig at commit instead of at runtime.
//
// For each VIP the validator asserts containment in the prefix of at least one
// address configured on the SAME unit of the MATCHING family. The owning /
// priority-255 case (VIP equals an interface address) is covered for free — an
// interface address is trivially contained in its own subnet. A cross-family
// VIP (e.g. a v4 literal authored under a v6-only address) has no matching-
// family subnet to contain it and is therefore rejected, which is the intent.
//
// A unit carrying a real VRRP group always has at least the parent address of
// the VIP's family in unit.Addresses (the group is nested under it), so the
// matching-family subnet set is non-empty in the valid case — the only empty
// case is the genuine cross-family/out-of-subnet misconfig.
//
// Strict (commit / commit-check): hard-reject, naming the interface, unit,
// group, VIP and family. Lenient (load / peer-sync): warn so an already-
// persisted or peer-synced config an older binary accepted still boots (#1960
// fail-closed-on-load class).
func validateVRRPVirtualAddressSubnet(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil, nil
	}
	var warnings []string
	// Deterministic iteration so commit errors / warnings are stable.
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil || len(unit.VRRPGroups) == 0 {
				continue
			}
			// Pre-parse the unit's configured subnets by family. The
			// containment test is textual-CIDR based (net.ParseCIDR), so an
			// unparseable address is skipped — not this validator's concern.
			var v4nets, v6nets []*net.IPNet
			for _, a := range unit.Addresses {
				_, ipnet, err := net.ParseCIDR(a)
				if err != nil || ipnet == nil {
					continue
				}
				if ipnet.IP.To4() != nil {
					v4nets = append(v4nets, ipnet)
				} else {
					v6nets = append(v6nets, ipnet)
				}
			}
			gkeys := make([]string, 0, len(unit.VRRPGroups))
			for k := range unit.VRRPGroups {
				gkeys = append(gkeys, k)
			}
			sort.Strings(gkeys)
			for _, gk := range gkeys {
				vg := unit.VRRPGroups[gk]
				if vg == nil {
					continue
				}
				for _, vip := range vg.VirtualAddresses {
					ip := vrrpVIPHostIP(vip)
					if ip == nil {
						// Bare/garbage VIP: the schema CIDR validator is
						// responsible for rejecting a non-address value.
						continue
					}
					nets := v6nets
					fam := "inet6"
					if ip.To4() != nil {
						nets = v4nets
						fam = "inet"
					}
					contained := false
					for _, n := range nets {
						if n.Contains(ip) {
							contained = true
							break
						}
					}
					if contained {
						continue
					}
					msg := fmt.Sprintf(
						"interfaces %s unit %d vrrp-group %d virtual-address %s: "+
							"not within any family %s subnet configured on the unit; "+
							"the VIP would install without a connected route and "+
							"blackhole return traffic (vSRX rejects this at commit)",
						ifName, un, vg.ID, vip, fam)
					if lenient {
						warnings = append(warnings, msg+
							" (ignored: VIP installed without a connected route until corrected)")
						continue
					}
					return nil, fmt.Errorf("%s", msg)
				}
			}
		}
	}
	return warnings, nil
}

// validateHostInboundTokensStrict rejects an unknown / typo'd
// `security zones <z> host-inbound-traffic { system-services <tok>; protocols
// <tok>; }` token at commit (#3200). The schema models system-services /
// protocols as untyped containers and the compiler copies every child token
// verbatim, so before this gate a typo such as `system-services sssh` committed
// cleanly. At runtime the two enforcement layers then DISAGREED: the nftables
// kernel mirror emitted no match for the unknown token (and, for a stanza whose
// tokens were all unrecognized, fell OPEN), while the Rust AF_XDP classifier
// ignored the unknown token and denied everything else — fail CLOSED. One typo
// silently produced a split-brain posture.
//
// The recognized token sets are the shared SSOT in host_inbound_tokens.go
// (KnownHostInboundSystemServices / KnownHostInboundProtocols), the same sets
// the nft builder + Rust classifier understand. Matching is case-sensitive
// against the canonical lowercase spellings. Runtime normalizes case on both
// layers (nft via lowerTokens, Rust via to_ascii_lowercase), so wrong-case is
// not a runtime split-brain; we reject it at commit for Junos-parity/typo-
// hygiene (host-inbound keywords are lowercase-canonical). Zones are walked in
// sorted order so the first-reported error is deterministic.
func validateHostInboundTokensStrict(cfg *Config) error {
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		zone := cfg.Security.Zones[name]
		if zone == nil {
			continue
		}
		if zone.HostInboundTraffic != nil {
			if err := validateHostInboundStanzaStrict(name, "", zone.HostInboundTraffic); err != nil {
				return err
			}
		}
		// #3362: the per-interface override carries the same token grammar and
		// MUST be validated identically — an unknown token on an interface-level
		// stanza would otherwise produce the same kernel-nft vs Rust-classifier
		// split-brain the zone-level gate exists to close. Interfaces are walked
		// in sorted order so the first-reported error is deterministic.
		ifNames := make([]string, 0, len(zone.InterfaceHostInbound))
		for ifName := range zone.InterfaceHostInbound {
			ifNames = append(ifNames, ifName)
		}
		sort.Strings(ifNames)
		for _, ifName := range ifNames {
			if err := validateHostInboundStanzaStrict(name, ifName, zone.InterfaceHostInbound[ifName]); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateHostInboundStanzaStrict validates one host-inbound-traffic stanza's
// system-services / protocols tokens against the recognized SSOT sets. When
// ifName is non-empty the error message names the per-interface scope (#3362);
// when empty it names the zone-level stanza.
func validateHostInboundStanzaStrict(zone, ifName string, hib *HostInboundTraffic) error {
	if hib == nil {
		return nil
	}
	scope := "host-inbound-traffic"
	if ifName != "" {
		scope = fmt.Sprintf("interfaces %q host-inbound-traffic", ifName)
	}
	for _, svc := range hib.SystemServices {
		if !KnownHostInboundSystemServices[svc] {
			return fmt.Errorf(
				"security zone %q %s system-services %q "+
					"is not a recognized system-service; an unknown token "+
					"commits but enforces inconsistently (kernel nft path vs "+
					"Rust dataplane disagree) — fix the typo or remove it",
				zone, scope, svc)
		}
	}
	for _, proto := range hib.Protocols {
		if !KnownHostInboundProtocols[proto] {
			return fmt.Errorf(
				"security zone %q %s protocols %q is not a "+
					"recognized protocol; an unknown token commits but "+
					"enforces inconsistently (kernel nft path vs Rust "+
					"dataplane disagree) — fix the typo or remove it",
				zone, scope, proto)
		}
	}
	return nil
}
