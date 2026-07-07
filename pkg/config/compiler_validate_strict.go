package config

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
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
