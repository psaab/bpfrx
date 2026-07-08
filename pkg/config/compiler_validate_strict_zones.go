package config

import (
	"fmt"
	"sort"
	"strings"
)

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

// zoneReferenceableInterfaceBases returns the set of interface BASE names a
// `security zones security-zone <z> interfaces <if>` entry may legitimately
// reference. It is the union validateZoneInterfaceDefinedStrict checks a zone
// member against, and is DELIBERATELY GENEROUS to avoid the #4191
// over-rejection class: a false reject would brick an otherwise-valid commit,
// which is far worse than missing a typo (the daemon already brings an
// interface that is ABSENT from the config DOWN, so an unresolved zone member
// is fail-CLOSED for real traffic — a missed typo silently carries no packets,
// it never fails open).
//
// The union is:
//
//   - every explicitly-configured interface (cfg.Interfaces.Interfaces) — the
//     ordinary case; a zone member "ge-0/0/0.0" strips to base "ge-0/0/0".
//     GRE / IPIP / WireGuard tunnels (`set interfaces gr-0/0/0 tunnel ...`)
//     and VRF (routing-instance) member interfaces are covered by this term
//     for free: a tunnel device and a routing-instance member must both be
//     configured under `interfaces`, so they are already keys of this map.
//   - "lo0" — the loopback is a reserved, always-present interface in Junos
//     and is always materialized by the daemon, so a zone may reference it
//     (host-inbound self-traffic) even with no explicit `set interfaces lo0`.
//   - every secure-tunnel base derived from an IPsec `bind-interface`
//     (cfg.Security.IPsec.VPNs[*].BindInterface). `bind-interface st0.0`
//     materializes the st0 xfrmi device at apply time (daemon_apply
//     ApplyXfrmi -> routing.ApplyXfrmi) even when the config carries no
//     explicit `set interfaces st0 unit 0`, so a zone referencing st0.0 is a
//     valid, daemon-materialized dynamic interface. The base is the bind
//     string with any ".unit" stripped (st0.0 -> st0, st0 -> st0), so every
//     unit of a bound secure tunnel is admitted.
func zoneReferenceableInterfaceBases(cfg *Config) map[string]bool {
	known := make(map[string]bool, len(cfg.Interfaces.Interfaces)+1)
	for name := range cfg.Interfaces.Interfaces {
		known[name] = true
	}
	// lo0 is always materialized (loopback); reserved always-present in Junos.
	known["lo0"] = true
	// Secure-tunnel devices are materialized from IPsec bind-interface strings
	// at apply time even without an explicit `set interfaces stN`.
	for _, vpn := range cfg.Security.IPsec.VPNs {
		if vpn == nil || vpn.BindInterface == "" {
			continue
		}
		base := vpn.BindInterface
		if idx := strings.Index(base, "."); idx > 0 {
			base = base[:idx]
		}
		known[base] = true
	}
	return known
}

// validateZoneInterfaceDefinedStrict hard-rejects a `security zones
// security-zone <z> interfaces <if>` entry that names an interface which is
// neither configured under `interfaces` nor a daemon-materialized dynamic
// interface (loopback / IPsec secure-tunnel) — the ps-review-002 F6 parity gap
// (#4515). Junos hard-rejects a zone member that references an undefined
// interface; xpf previously only WARNED (compiler_validate_warn.go), then
// compiled and KEPT the zone. At runtime the referenced interface is absent, so
// the daemon brings it DOWN (fail-closed for real traffic) — safe, but silent:
// the operator's typo'd `ge-0/0/99` zone member carries no packets with no
// commit-time signal. This gate restores the Junos commit-time reject.
//
// The reference set is the GENEROUS union zoneReferenceableInterfaceBases
// builds (see its comment): the naive check that built the set only from
// cfg.Interfaces.Interfaces is why this gap was left warn-only — it would
// FALSE-REJECT a zone that legitimately references a daemon-materialized
// interface such as an IPsec `bind-interface st0.0` secure tunnel or lo0 (the
// #4191 over-rejection class). Unioning lo0 + the IPsec secure-tunnel bases in
// first is the safeguard that makes the promotion safe.
//
// Strict on the commit / commit-check path (CompileConfig — hard-reject so the
// operator sees the typo); downgraded to a cfg.Warnings entry on the tolerant
// load / peer-sync paths (CompileConfigLenient / CompileConfigForNodeLenient,
// flag lenientZoneInterfaceDefined) so an already-persisted or peer-synced
// config an older binary accepted still BOOTS (#1960 fail-closed-on-load
// doctrine) — the runtime keeps its existing behavior (the unresolved member
// carries no traffic), just with an operator-visible warning instead of a hard
// reject. Zones are walked in sorted name order so the first-reported error is
// deterministic. Unit suffixes are stripped exactly as the dataplane
// interface->zone map (and the prior warn loop) do, so a `.0`/`.50` unit
// reference resolves against its base.
func validateZoneInterfaceDefinedStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	known := zoneReferenceableInterfaceBases(cfg)
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
		for _, ifName := range zone.Interfaces {
			if ifName == "" {
				continue
			}
			base := ifName
			if idx := strings.Index(ifName, "."); idx > 0 {
				base = ifName[:idx]
			}
			if !known[base] {
				return fmt.Errorf(
					"security zone %q references interface %q, which is not "+
						"defined under `interfaces` (nor materialized as the lo0 "+
						"loopback or an IPsec secure-tunnel bind-interface); Junos "+
						"rejects a zone member that names no configured interface — "+
						"define the interface or fix the typo (the daemon brings an "+
						"unconfigured interface DOWN, so the zone member silently "+
						"carries no traffic)",
					zoneName, ifName)
			}
		}
	}
	return nil
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
