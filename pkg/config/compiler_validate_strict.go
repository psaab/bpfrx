package config

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

func validateThreeColorPolicersStrict(policers map[string]*ThreeColorPolicerConfig) error {
	for name, pol := range policers {
		if pol == nil {
			continue
		}
		displayName := pol.Name
		if displayName == "" {
			displayName = name
		}
		if pol.SingleRateConfigured && pol.TwoRateConfigured {
			return fmt.Errorf("firewall three-color-policer %q cannot configure both single-rate and two-rate", displayName)
		}
		if pol.ColorBlindConfigured && pol.ColorAwareConfigured {
			return fmt.Errorf("firewall three-color-policer %q cannot configure both color-blind and color-aware", displayName)
		}
		if pol.CIR == 0 {
			return fmt.Errorf("firewall three-color-policer %q requires positive committed-information-rate", displayName)
		}
		if pol.CBS == 0 {
			return fmt.Errorf("firewall three-color-policer %q requires positive committed-burst-size", displayName)
		}
		if pol.PBS == 0 {
			if pol.TwoRate {
				return fmt.Errorf("firewall three-color-policer %q requires positive peak-burst-size", displayName)
			}
			return fmt.Errorf("firewall three-color-policer %q requires positive excess-burst-size", displayName)
		}
		if pol.TwoRate {
			if pol.PIR == 0 {
				return fmt.Errorf("firewall three-color-policer %q requires positive peak-information-rate", displayName)
			}
			if pol.PIR < pol.CIR {
				return fmt.Errorf("firewall three-color-policer %q peak-information-rate must be >= committed-information-rate", displayName)
			}
			if pol.PBS < pol.CBS {
				return fmt.Errorf("firewall three-color-policer %q peak-burst-size must be >= committed-burst-size", displayName)
			}
		}
	}
	return nil
}

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

func validatePolicySchedulerReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(scope string, pol *Policy) error {
		if pol == nil || pol.SchedulerName == "" {
			return nil
		}
		if _, ok := cfg.Schedulers[pol.SchedulerName]; ok {
			return nil
		}
		if scope != "" {
			return fmt.Errorf("%s policy %q references undefined scheduler %q", scope, pol.Name, pol.SchedulerName)
		}
		return fmt.Errorf("policy %q references undefined scheduler %q", pol.Name, pol.SchedulerName)
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if err := check("", pol); err != nil {
				return err
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if err := check("global", pol); err != nil {
			return err
		}
	}
	return nil
}

// validateIPsecPolicyProposalReferencesStrict hard-rejects an IPsec
// (Phase 2) policy whose `proposals` reference does not resolve to a
// defined IPsec proposal (#2073). resolveESPSettings (pkg/ipsec/ike.go)
// resolves the policy's proposal ref, or falls back to the policy name
// when no `proposals` leaf is given. When that reference dangles, the
// renderer would otherwise fall through to `esp_proposals = default`,
// silently substituting the operator's entire Phase-2 proposal set —
// including any configured perfect-forward-secrecy DH group — with the
// strongSwan default (which carries no required modp term). That is the
// same silent-crypto-weakening class ValidateDHGroup closes for DH-group
// leaves; this validator closes it for the policy→proposal cross-
// reference.
//
// Rejected unconditionally (not only when PFSGroup > 0): a dangling
// reference substitutes the whole proposal, not just PFS. Mirrors
// validatePolicySchedulerReferencesStrict, which rejects any undefined
// scheduler reference.
//
// On the tolerant load / peer-sync paths the call site downgrades this
// to a warning (opts.lenientIPsecPolicyProposalRef) so an already-
// persisted or peer-synced config still boots; the render-path safety
// net in resolveESPSettings preserves the configured PFS group on that
// boot rather than dropping it.
func validateIPsecPolicyProposalReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	policies := cfg.Security.IPsec.Policies
	proposals := cfg.Security.IPsec.Proposals
	// Policies is a map (unordered); sort keys so the first-error
	// commit-check message is deterministic across runs.
	names := make([]string, 0, len(policies))
	for name := range policies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		pol := policies[name]
		if pol == nil {
			continue
		}
		propRef := pol.Proposals
		explicitRef := propRef != ""
		if !explicitRef {
			// Mirror resolveESPSettings' policy-name fallback: a policy
			// with no `proposals` leaf resolves against a proposal named
			// after the policy itself.
			propRef = pol.Name
		}
		if _, ok := proposals[propRef]; ok {
			continue
		}
		if explicitRef {
			return fmt.Errorf("ipsec policy %q references undefined ipsec proposal %q "+
				"(the configured proposal set, including any perfect-forward-secrecy "+
				"group, would be silently dropped to the strongSwan default)",
				pol.Name, propRef)
		}
		// No explicit `proposals` leaf was given, so do not blame a
		// phantom proposal named after the policy — describe the actual
		// gap instead.
		return fmt.Errorf("ipsec policy %q has no resolvable ipsec proposal "+
			"(no `proposals` reference and no proposal named %q); the configured "+
			"perfect-forward-secrecy group would be silently dropped — define a "+
			"proposal or reference one", pol.Name, pol.Name)
	}
	return nil
}

// validateLogProfileStreamReferencesStrict hard-rejects a
// `security log profile <name>` whose `stream-name` reference does not
// resolve to a configured `security log stream` (#2008 H7). xpf routes
// log events per stream (a Junos superset — every matching stream
// receives the event), so a profile's `stream-name` designates the
// stream that carries its events. A profile naming a stream that is not
// configured routes to nowhere: the operator authored a log profile
// whose target silently never fires. Before H7 the whole profile stanza
// was dropped before compile, so the typo was invisible; now the
// reference is validated.
//
// A profile with no `stream-name` is accepted: Junos permits a profile
// that relies on the global routing inheritance, and there is nothing to
// dangle. Only a non-empty `stream-name` that misses the stream map is
// rejected.
//
// Note: compileLog only records a stream in Log.Streams when it has a
// host (a host-less stream is not a real destination and is dropped by
// the stream loop), so a profile referencing a host-less stream is
// treated as a dangling reference — consistent with the stream's own
// "must have a host to exist" semantics.
//
// On the tolerant load / peer-sync paths the call site downgrades this
// to a warning (opts.lenientLogProfileStreamRef) so an already-persisted
// config (older binaries dropped the stanza entirely) or a peer-synced
// config still boots. Mirrors validateIPsecPolicyProposalReferencesStrict.
func validateLogProfileStreamReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	profiles := cfg.Security.Log.Profiles
	if len(profiles) == 0 {
		return nil
	}
	streams := cfg.Security.Log.Streams
	// Profiles is a map (unordered); sort keys so the first-error
	// commit-check message is deterministic across runs.
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := profiles[name]
		if p == nil || p.StreamName == "" {
			continue
		}
		if _, ok := streams[p.StreamName]; ok {
			continue
		}
		return fmt.Errorf("security log profile %q references undefined "+
			"log stream %q (the profile would route to nowhere — define "+
			"the stream or fix the stream-name)", p.Name, p.StreamName)
	}
	return nil
}

// routingRedistProtocolTokens is the set of bare protocol keywords that an
// OSPF/OSPFv3/BGP/IS-IS `export` (or a RIP `redistribute`) accepts in lieu
// of a named policy-statement. resolveRedistribute (pkg/frr/policy_render.go)
// emits a bare `redistribute <token>` for these. It mirrors
// knownRedistProtocols there, plus Junos's `direct` spelling for FRR's
// `connected`. Keep the two in sync: a token accepted here but unknown to
// the renderer would emit a line FRR rejects; a token the renderer accepts
// but missing here would be wrongly rejected at commit.
var routingRedistProtocolTokens = map[string]bool{
	"connected": true, "direct": true, "static": true, "kernel": true,
	"ospf": true, "bgp": true, "rip": true, "isis": true,
}

// validateRoutingExportReferencesStrict hard-rejects a dynamic-protocol
// `export` (OSPF / OSPFv3 / BGP / IS-IS), a RIP `redistribute`, a BGP
// group/neighbor `export`, or a `routing-options forwarding-table export`
// whose token resolves to neither a known redistribution protocol nor a
// defined policy-statement (#2144).
//
// Without this gate a typo passes commit and reaches FRR render-time, where
// it fails OPEN in three distinct ways:
//
//   - resolveRedistribute's fallback (policy_render.go) emits
//     `redistribute <typo>` for any unknown token. FRR either rejects the
//     line — failing the whole frr-reload (a single vtysh -f add-batch
//     exits non-zero on any CMD_WARNING_CONFIG_FAILED) — or silently
//     no-ops, so the intended redistribution never happens.
//   - a BGP group/neighbor `export` renders `neighbor <addr> route-map
//     <typo> out`. FRR resolves a route-map name with no definition to
//     NULL, which it treats as permit-all — the outbound filter the
//     operator wrote silently advertises EVERYTHING.
//   - `forwarding-table export <typo>` is read by resolveECMP
//     (config_render.go), which returns 0 max-paths when the policy is
//     missing — silently DISABLING the expected ECMP / consistent-hash
//     load balancing instead of rejecting the config.
//
// Protocol-token acceptance differs by site. A redistribute-backed export
// (OSPF/OSPFv3/BGP/IS-IS export, RIP redistribute) legitimately names a
// bare protocol (`export static`) OR a policy-statement, matching
// resolveRedistribute. A BGP group/neighbor export and a forwarding-table
// export render directly as a route-map / ECMP policy name, so only a
// defined policy-statement is valid there — a protocol token would be a
// dangling route-map / missing-policy reference, not a redistribute verb.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientRoutingExportRef) so an already-persisted or
// peer-synced config carrying the typo still boots (#1960
// fail-closed-on-load class); the render-path fallbacks above keep it inert
// or fail-open-on-an-already-committed-config exactly as before. Commit /
// commit-check stay strict. Mirrors validateLogProfileStreamReferencesStrict.
func validateRoutingExportReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	defined := func(name string) bool {
		if cfg.PolicyOptions.PolicyStatements == nil {
			return false
		}
		_, ok := cfg.PolicyOptions.PolicyStatements[name]
		return ok
	}

	// checkRedist validates a redistribute-backed export list: each token
	// must be a known protocol OR a defined policy-statement.
	checkRedist := func(scope, proto string, exports []string) error {
		for _, e := range exports {
			if e == "" || routingRedistProtocolTokens[e] || defined(e) {
				continue
			}
			return fmt.Errorf("%s%s export %q references neither a known "+
				"redistribution protocol (connected/direct/static/kernel/"+
				"ospf/bgp/rip/isis) nor a defined policy-statement — the "+
				"FRR redistribute line would be rejected or silently no-op; "+
				"define the policy-statement or fix the export name",
				scope, proto, e)
		}
		return nil
	}

	// checkPolicyRef validates an export list that renders directly as a
	// route-map / ECMP policy name: only a defined policy-statement is valid.
	checkPolicyRef := func(detail, name string) error {
		if name == "" || defined(name) {
			return nil
		}
		return fmt.Errorf("%s references undefined policy-statement %q; %s",
			detail, name, "define the policy-statement or fix the export name")
	}

	checkProtocols := func(scope string, ospf *OSPFConfig, ospfv3 *OSPFv3Config, bgp *BGPConfig, rip *RIPConfig, isis *ISISConfig) error {
		if ospf != nil {
			if err := checkRedist(scope, "protocols ospf", ospf.Export); err != nil {
				return err
			}
		}
		if ospfv3 != nil {
			if err := checkRedist(scope, "protocols ospf3", ospfv3.Export); err != nil {
				return err
			}
		}
		if rip != nil {
			if err := checkRedist(scope, "protocols rip", rip.Redistribute); err != nil {
				return err
			}
		}
		if isis != nil {
			if err := checkRedist(scope, "protocols isis", isis.Export); err != nil {
				return err
			}
		}
		if bgp != nil {
			if err := checkRedist(scope, "protocols bgp", bgp.Export); err != nil {
				return err
			}
			// A BGP group/neighbor export renders `route-map <name> out`,
			// so it must be a defined policy-statement (no protocol-token
			// fallback). Sort neighbor addresses for a deterministic
			// first-error message.
			neighbors := append([]*BGPNeighbor(nil), bgp.Neighbors...)
			sort.SliceStable(neighbors, func(i, j int) bool {
				return neighbors[i].Address < neighbors[j].Address
			})
			for _, n := range neighbors {
				if n == nil {
					continue
				}
				for _, e := range n.Export {
					detail := fmt.Sprintf("%sprotocols bgp neighbor %s export", scope, n.Address)
					if n.GroupName != "" {
						detail = fmt.Sprintf("%sprotocols bgp group %s neighbor %s export", scope, n.GroupName, n.Address)
					}
					if err := checkPolicyRef(detail, e); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}

	// Top-level protocols.
	if err := checkProtocols("", cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.BGP, cfg.Protocols.RIP, cfg.Protocols.ISIS); err != nil {
		return err
	}

	// Per routing-instance protocols.
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := checkProtocols(scope, ri.OSPF, ri.OSPFv3, ri.BGP, ri.RIP, ri.ISIS); err != nil {
			return err
		}
	}

	// forwarding-table export → resolveECMP (config_render.go). Renders
	// directly as an ECMP policy lookup, so it must be a defined
	// policy-statement; a missing one silently disables ECMP/consistent-hash.
	if err := checkPolicyRef(
		"routing-options forwarding-table export",
		cfg.RoutingOptions.ForwardingTableExport,
	); err != nil {
		return fmt.Errorf("%s (the expected ECMP / consistent-hash "+
			"load-balancing would be silently disabled)", err)
	}

	return nil
}

// validateFirewallPolicerReferencesStrict hard-rejects a firewall-filter
// term whose `then policer <name>` (Finding A, #2217) references neither a
// defined single-rate policer (`firewall policer <name>`) nor a defined
// three-color-policer (`firewall three-color-policer <name>`).
//
// The schema declares `then policer` with no validator and ValidateConfig
// never checked the reference, so a typo'd / dangling policer name compiled
// cleanly: the term keeps Policer="no-such-policer" and the rate-limit
// silently never applies (fail-OPEN — traffic the operator meant to police
// passes unpoliced). This gate turns that silent fail-open into an operator-
// visible commit error, mirroring the SNAT/DNAT-pool reference family.
//
// Both filter families (inet + inet6) are walked, sorted by filter name then
// by the term's position, so the first-reported error is deterministic across
// runs (Go map order is randomized).
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientFirewallRefs) so an already-persisted or peer-synced
// config carrying the typo still BOOTS (#1960 fail-closed-on-load class); the
// dataplane simply does not police the term, exactly as before. Commit /
// commit-check stay strict. Mirrors validateRoutingExportReferencesStrict.
func validateFirewallPolicerReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	defined := func(name string) bool {
		if cfg.Firewall.Policers != nil {
			if _, ok := cfg.Firewall.Policers[name]; ok {
				return true
			}
		}
		if cfg.Firewall.ThreeColorPolicers != nil {
			if _, ok := cfg.Firewall.ThreeColorPolicers[name]; ok {
				return true
			}
		}
		return false
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil || term.Policer == "" || defined(term.Policer) {
					continue
				}
				return fmt.Errorf(
					"firewall family %s filter %q term %q references undefined "+
						"policer %q (define `firewall policer %s` or `firewall "+
						"three-color-policer %s`, or fix the policer name — the "+
						"rate-limit would otherwise silently never apply)",
					family, name, term.Name, term.Policer, term.Policer, term.Policer)
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateFirewallRoutingInstanceReferencesStrict hard-rejects a
// firewall-filter term whose `then routing-instance <name>` (FBF /
// filter-based-forwarding, Finding C, #2217) does not name a routing-instance
// defined under `routing-instances <name>`.
//
// ValidateConfig validated routing-instance INTERFACE membership but never the
// FBF steering reference. A dangling reference compiled with no warning; the
// FBF snapshot carries the unknown instance name and the dataplane steers
// matched packets toward a routing table that does not exist — a silent
// blackhole / fall-through to the default table. This gate makes the typo
// operator-visible at commit, consistent with the other cross-reference gates.
//
// Any defined routing-instance is a valid steer target (Junos FBF accepts
// virtual-router / vrf / forwarding instances alike); the gap closed here is
// strictly the dangling-name case, so instance-type is intentionally not
// constrained.
//
// Both filter families are walked, sorted by filter name then by term position
// for a deterministic first-error. On the tolerant load / peer-sync paths the
// call site downgrades to a warning (opts.lenientFirewallRefs) so an already-
// persisted or peer-synced config still BOOTS (#1960). Mirrors
// validateFirewallPolicerReferencesStrict.
func validateFirewallRoutingInstanceReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	defined := make(map[string]bool, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name != "" {
			defined[ri.Name] = true
		}
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil || term.RoutingInstance == "" || defined[term.RoutingInstance] {
					continue
				}
				return fmt.Errorf(
					"firewall family %s filter %q term %q references undefined "+
						"routing-instance %q (define `routing-instances %s` or "+
						"fix the name — filter-based-forwarding would otherwise "+
						"steer matched traffic into a routing table that does not "+
						"exist, silently blackholing it or falling through to the "+
						"default table)",
					family, name, term.Name, term.RoutingInstance, term.RoutingInstance)
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateApplicationSetMembersStrict hard-rejects an `applications
// application-set <set>` (Finding B, #2217) whose member references neither a
// defined application (user-defined or junos-* predefined), nor a defined
// nested application-set.
//
// ValidateConfig warned on a POLICY referencing an unknown application but
// never validated the MEMBERS of an application-set. A policy referencing a
// defined application-set whose member is undefined passed validation with no
// warning; at the dataplane that member simply never matches, so the policy
// silently fails to match the intended traffic (an effective no-op term,
// fail-OPEN). This gate validates each set's membership at commit.
//
// Reuses ExpandApplicationSet, the SAME resolver the compiler and the strict
// application-spec gate already use to expand a set: it recurses nested sets
// (max depth 3), resolves each leaf member through ResolveApplication
// (user-defined first, then the junos-* predefined table), and returns an
// error on the first dangling/over-nested member — so no new divergent
// definedness table is introduced. Sets are iterated in sorted name order for
// a deterministic first-error.
//
// IMPLICIT sets minted for multi-term user applications (compileApplications
// stores `applications application <name> term ...` as an ApplicationSet whose
// members are the generated per-term application names) are skipped: their
// members are synthesized by the compiler, always resolve, and are not
// operator-authored references — validating them would only risk a false
// reject on a compiler-internal name shape.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientApplicationSetMembers) so an already-persisted or peer-
// synced config carrying a dangling member still BOOTS (#1960); the dataplane
// drops the unresolved member independently, so it is already inert. Commit /
// commit-check stay strict. Mirrors validateApplicationSpecsStrict.
func validateApplicationSetMembersStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	sets := cfg.Applications.ApplicationSets
	if len(sets) == 0 {
		return nil
	}
	// An implicit set minted for a multi-term application shares its name with
	// a user application term-bundle; its members are compiler-synthesized, not
	// operator references. Skip those.
	isImplicitTermSet := func(setName string) bool {
		set := sets[setName]
		if set == nil {
			return false
		}
		for _, member := range set.Applications {
			// A synthesized term application is named "<parent>-<term>"; the
			// reliable signal that this is a compiler-minted set (rather than an
			// operator `application-set`) is that EVERY member is a user
			// application whose name is prefixed with the set name plus "-". A
			// hand-authored application-set members reference unrelated app names.
			if _, isUserApp := cfg.Applications.Applications[member]; !isUserApp {
				return false
			}
			if !strings.HasPrefix(member, setName+"-") {
				return false
			}
		}
		return true
	}
	names := make([]string, 0, len(sets))
	for name := range sets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		set := sets[name]
		if set == nil || len(set.Applications) == 0 || isImplicitTermSet(name) {
			continue
		}
		if _, err := ExpandApplicationSet(name, &cfg.Applications); err != nil {
			return fmt.Errorf(
				"applications application-set %q: %w (define the missing "+
					"application / application-set or fix the member name — a "+
					"policy matching this set would otherwise silently fail to "+
					"match the intended traffic)", name, err)
		}
	}
	return nil
}

// validatePolicyMatchAddressesStrict hard-rejects a policy
// source-address / destination-address token that is neither a known
// address-book name (Address or AddressSet), the `any` keyword, nor a
// parseable CIDR / bare IP (#2008). Such a token (a typo) reaches the
// dataplane as an opaque string, fails CIDR/IP parsing in the Rust
// literal parser, and is silently dropped to an empty set. Under
// `*-address-excluded` inversion an empty set evaluates to MATCH-ALL —
// a silent fail-open security bypass (a policy meant to exclude one
// address ends up matching every address). Failing the typo at commit
// turns the bypass into an operator-visible error.
//
// Legitimate forms accepted: address-book names, `any` (and the
// family-scoped `any-ipv4` / `any-ipv6`, which compilePolicy already
// normalizes to `0.0.0.0/0` / `::/0` and which parse as CIDRs anyway),
// literal CIDRs, and bare IPv4 / IPv6 addresses. Junos address RANGES
// are an address-book construct (expanded to /32s under the book) and
// are referenced from a policy only by book NAME, so no range form
// reaches this token list.
func validatePolicyMatchAddressesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// Collect valid address-book names (Addresses + AddressSets).
	bookNames := make(map[string]bool)
	if ab := cfg.Security.AddressBook; ab != nil {
		for name := range ab.Addresses {
			bookNames[name] = true
		}
		for name := range ab.AddressSets {
			bookNames[name] = true
		}
	}
	validToken := func(tok string) bool {
		switch tok {
		case "", "any", "any-ipv4", "any-ipv6":
			return true
		}
		if bookNames[tok] {
			return true
		}
		if _, _, err := net.ParseCIDR(tok); err == nil {
			return true
		}
		return net.ParseIP(tok) != nil
	}
	check := func(scope string, pol *Policy) error {
		if pol == nil {
			return nil
		}
		for _, addr := range pol.Match.SourceAddresses {
			if !validToken(addr) {
				return policyMatchAddressError(scope, pol.Name, "source-address", addr)
			}
		}
		for _, addr := range pol.Match.DestinationAddresses {
			if !validToken(addr) {
				return policyMatchAddressError(scope, pol.Name, "destination-address", addr)
			}
		}
		return nil
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if err := check("", pol); err != nil {
				return err
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if err := check("global", pol); err != nil {
			return err
		}
	}
	return nil
}

// validateApplicationSpecsStrict hard-rejects a user-defined application
// (`set applications application <name> ...`) whose destination-port /
// source-port is malformed (not a valid numeric port, port range, or known
// service name, out of 1..65535, or an inverted low>high range) or whose
// protocol token is not a known name, a junos-*
// alias, or a 0..255 number (#2142) — but ONLY for applications that are
// actually REFERENCED by a security policy or a source/destination-NAT rule's
// `match application` (#2187), or for ALL applications when
// `services application-identification` is enabled (every app then compiles
// into the app-id catalog). Such a spec is accepted by ValidateConfig as a
// WARNING only; commit succeeds, the dataplane app-id compiler records the
// AppID name and then `continue`s past the unparsable port (a never-match
// AppID), and a policy referencing the application fails CLOSED on a permit
// rule or falls through OPEN on a deny rule. Failing the spec at commit turns
// that silent semantic break into an operator-visible error.
//
// The referenced-only scope is deliberate (the issue's explicit
// referenced-vs-unreferenced distinction): an UNREFERENCED, app-id-disabled
// application definition compiles into nothing the dataplane can match against,
// so its malformed spec cannot break a live policy decision — it stays a
// warning so an operator iterating on a not-yet-wired application library is
// not blocked, and so existing configs that carry an unreferenced app with a
// port form the policy matcher cannot represent (e.g. a `source-port 0-N`
// range, which Rust parse_port_spec rejects on low==0) still commit. The moment
// such an app is referenced by a policy, or app-id is turned on, the gate
// engages.
//
// It reuses validatePortSpec and validateProtocol — the same config-layer
// validators that produce the warning in ValidateConfig — so no new divergent
// port/protocol table is introduced (the dataplane's #2124 capability gate is
// the runtime backstop, and these validators are a superset of what it admits).
// Iteration is sorted by application name so the first-reported error is
// deterministic across runs (Go map order is randomized).
func validateApplicationSpecsStrict(cfg *Config) error {
	if cfg == nil || len(cfg.Applications.Applications) == 0 {
		return nil
	}
	toCheck := applicationsToValidateStrict(cfg)
	if len(toCheck) == 0 {
		return nil
	}
	names := make([]string, 0, len(toCheck))
	for name := range toCheck {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		app := cfg.Applications.Applications[name]
		if app == nil {
			continue
		}
		if err := validatePortSpec(app.DestinationPort); err != nil {
			return fmt.Errorf("application %q: destination-port: %w", name, err)
		}
		if err := validatePortSpec(app.SourcePort); err != nil {
			return fmt.Errorf("application %q: source-port: %w", name, err)
		}
		if app.Protocol != "" {
			if err := validateProtocol(app.Protocol); err != nil {
				return fmt.Errorf("application %q: %w", name, err)
			}
		}
	}
	return nil
}

// applicationsToValidateStrict returns the set of user-defined application
// names whose port/protocol spec is validated as a hard COMMIT error rather
// than a warning. That is every user application referenced (directly, or as a
// member of a referenced application-set) by a zone-pair or global security
// policy, OR by a source/destination-NAT rule's `match application` (#2187 — a
// NAT term consumes the app's port/proto the same way a policy does, so a
// malformed app referenced only by a NAT rule must reject too), plus — when
// `services application-identification` is enabled — every user application
// (app-id compiles them all into the catalog). It mirrors the policy-reference
// walk in appid.CatalogNames; the logic is duplicated here because pkg/appid
// imports pkg/config (so the compiler cannot call back into appid without an
// import cycle). Predefined junos-* applications are never returned — they are
// not in cfg.Applications.Applications and their specs are owned by the
// predefined table, not the operator. Static NAT carries no application match,
// so only source and destination NAT rule-sets are walked.
func applicationsToValidateStrict(cfg *Config) map[string]struct{} {
	out := make(map[string]struct{})
	if cfg == nil {
		return out
	}
	userApps := cfg.Applications.Applications
	// app-id enabled: the catalog compiles every user application, so validate
	// them all.
	if cfg.Services.ApplicationIdentification {
		for name := range userApps {
			out[name] = struct{}{}
		}
		return out
	}
	addRef := func(appName string) {
		if appName == "" || appName == "any" {
			return
		}
		if set, isSet := cfg.Applications.ApplicationSets[appName]; isSet {
			expanded, err := ExpandApplicationSet(appName, &cfg.Applications)
			if err == nil {
				for _, member := range expanded {
					if _, isUser := userApps[member]; isUser {
						out[member] = struct{}{}
					}
				}
				return
			}
			// ExpandApplicationSet bails on the FIRST dangling/undefined or
			// over-nested member, which would otherwise let a MALFORMED user app
			// that is ALSO a direct member of the same set escape the strict gate
			// (commit silently succeeds — the #2142 fail-closed-on-permit
			// pathology, scoped to a set carrying a dangling member). A dangling
			// member is a separate existing concern; it must not mask a malformed
			// spec on a sibling member. Fall back to the set's DIRECT user-app
			// members so each one that resolves is still hard-rejected at commit.
			if set != nil {
				for _, member := range set.Applications {
					if _, isUser := userApps[member]; isUser {
						out[member] = struct{}{}
					}
				}
			}
			return
		}
		if _, isUser := userApps[appName]; isUser {
			out[appName] = struct{}{}
		}
	}
	walk := func(policies []*Policy) {
		for _, pol := range policies {
			if pol == nil {
				continue
			}
			for _, appName := range pol.Match.Applications {
				addRef(appName)
			}
		}
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		walk(zpp.Policies)
	}
	walk(cfg.Security.GlobalPolicies)

	// #2187: a source/destination-NAT rule with `match application <name>` also
	// consumes the referenced app's port/proto (pkg/dataplane/userspace/nat.go
	// appPortsFromSpec). A malformed spec there returns nil ports, so the NAT
	// term silently never-matches (or over-matches on a degenerate proto) with
	// no commit error — and a bad app referenced ONLY by a NAT rule (not by any
	// policy) escaped both this commit gate (policy-only) and the #2124 runtime
	// gate (policy-only). Collect NAT-rule app references the same way as policy
	// references (single app or application-set) so they are hard-rejected at
	// commit, lenient on load — identical wiring to the policy path. Static NAT
	// is intentionally not walked: StaticNATRule has no application match
	// (compileNATStatic parses only source/destination-address), so there is no
	// app reference to validate there.
	walkNATRules := func(rs *NATRuleSet) {
		if rs == nil {
			return
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			addRef(rule.Match.Application)
		}
	}
	for _, rs := range cfg.Security.NAT.Source {
		walkNATRules(rs)
	}
	if cfg.Security.NAT.Destination != nil {
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			walkNATRules(rs)
		}
	}
	return out
}

// ApplicationsToValidateStrict exposes the strict-validation reference set
// (the user-app names the commit-time gate hard-rejects) for cross-checking
// against appid.CatalogNames. The strict walk INLINE-duplicates CatalogNames's
// policy-reference resolution because pkg/appid imports pkg/config (so the
// compiler cannot call back into appid without a cycle). This accessor lets a
// pkg/appid test assert the two walks agree on the user-app subset, so a future
// change to CatalogNames's resolution cannot let the compiler copy drift
// silently. It is a TEST seam, not a runtime coupling — production code uses the
// unexported validateApplicationSpecsStrict directly.
func ApplicationsToValidateStrict(cfg *Config) map[string]struct{} {
	return applicationsToValidateStrict(cfg)
}

// validateFilterProtocolsStrict hard-rejects any firewall-filter term whose
// `from protocol <token>` is not resolvable by the centralized protocol SSOT
// (#2175) — neither a known protocol name, a junos-* alias, nor a 0..255
// number. It walks every inet and inet6 filter and reports the first offending
// family / filter / term / token (sorted by filter name, then by the term's
// position, so the first-reported error is deterministic across runs).
//
// Resolution goes through filterProtocolResolvable, which INLINE-mirrors the
// acceptance set of appid.ProtocolNumber. The compiler cannot call
// appid.ProtocolNumber directly because pkg/appid imports pkg/config (an import
// cycle) — the same constraint that forces validateApplicationSpecsStrict to
// duplicate appid.CatalogNames's policy-reference walk (#2142). A pkg/appid
// drift-guard test (TestFilterProtocolResolvableMatchesProtocolNumber) asserts
// the two acceptance sets agree via the exported FilterProtocolResolvable
// accessor, so a future change to appid.ProtocolNumber cannot let this copy
// drift silently.
//
// The dataplane compiler (compileFirewallFilters → validateFilterProtocols)
// keeps an identical check as defense-in-depth, but its error is swallowed by
// the daemon (compileErrorMustAbortApply == false): this commit-check gate is
// what makes the refusal operator-visible. On the tolerant load / peer-sync
// path the caller downgrades the returned error to a warning (#1960 no-brick).
func validateFilterProtocolsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil || term.Protocol == "" {
					continue
				}
				if !filterProtocolResolvable(term.Protocol) {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: unknown protocol %q "+
							"(use a protocol name such as tcp/udp/icmp/icmpv6/gre/esp/ah/"+
							"sctp/ospf or a numeric value 0-255)",
						family, name, term.Name, term.Protocol)
				}
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// filterProtocolResolvable reports whether a `from protocol <token>` is
// representable: it INLINE-mirrors the acceptance set of
// appid.ProtocolNumber's ok==true result (the #2124/#2175 SSOT). pkg/config
// cannot import pkg/appid (import cycle: pkg/appid imports pkg/config), so the
// known-name set is duplicated here and pinned by the pkg/appid drift-guard
// test TestFilterProtocolResolvableMatchesProtocolNumber via the exported
// FilterProtocolResolvable accessor.
//
// The acceptance set is intentionally TIGHTER than validateProtocol (used by
// validateApplicationSpecsStrict): validateProtocol blanket-accepts ANY
// "junos-" prefix, but appid.ProtocolNumber only resolves the specific
// junos-* aliases below, so an unknown "junos-foobar" must be rejected here to
// stay consistent with the dataplane SSOT — otherwise commit would pass while
// the swallowed dataplane gate dropped the constraint.
func filterProtocolResolvable(token string) bool {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "tcp", "junos-tcp-any",
		"udp", "junos-udp-any",
		"icmp", "junos-icmp-all", "junos-ping",
		"icmpv6", "icmp6", "junos-icmp6-all", "junos-pingv6",
		"gre", "junos-gre",
		"ospf", "junos-ospf",
		"junos-ip-in-ip", "junos-ipip", "ipip",
		"egp",
		"igmp",
		"pim",
		"ah",
		"esp",
		"sctp",
		"vrrp":
		return true
	default:
		// Numeric protocol number, including the deliberate "0" (HOPOPT).
		if n, err := strconv.Atoi(strings.TrimSpace(token)); err == nil && n >= 0 && n < 256 {
			return true
		}
		return false
	}
}

// FilterProtocolResolvable exposes filterProtocolResolvable for the pkg/appid
// drift-guard test (TestFilterProtocolResolvableMatchesProtocolNumber), which
// asserts this acceptance set agrees with appid.ProtocolNumber's ok==true
// result so the INLINE-duplicated table cannot drift from the SSOT silently. It
// is a TEST seam, not a runtime coupling — production code uses the unexported
// filterProtocolResolvable directly.
func FilterProtocolResolvable(token string) bool {
	return filterProtocolResolvable(token)
}

func policyMatchAddressError(scope, polName, field, addr string) error {
	if scope != "" {
		return fmt.Errorf(
			"%s policy %q: %s %q is not a defined address-book entry, the `any` keyword, or a valid CIDR/IP address",
			scope, polName, field, addr)
	}
	return fmt.Errorf(
		"policy %q: %s %q is not a defined address-book entry, the `any` keyword, or a valid CIDR/IP address",
		polName, field, addr)
}

func validateClassOfServiceStrict(cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	for _, sched := range cos.Schedulers {
		if sched == nil {
			continue
		}
		if sched.EqualFlowEnforcement && (!sched.TransmitRateExact || sched.TransmitRateBytes == 0) {
			return fmt.Errorf(
				"class-of-service scheduler %q equal-flow-enforcement requires positive transmit-rate exact",
				sched.Name)
		}
		if sched.EqualFlowEnforcement && sched.SurplusSharing {
			return fmt.Errorf(
				"class-of-service scheduler %q equal-flow-enforcement cannot be combined with surplus-sharing",
				sched.Name)
		}
		// #1746: the schema enum validator catches bad values on the
		// set path; re-check here so externally-assembled configs
		// cannot smuggle an unknown policy to the dataplane (which
		// would silently parse it as "slowest").
		switch sched.EqualFlowTargetPolicy {
		case "", "slowest", "mean", "ideal-share":
		default:
			return fmt.Errorf(
				"class-of-service scheduler %q equal-flow-target-policy %q is not one of slowest | mean | ideal-share",
				sched.Name, sched.EqualFlowTargetPolicy)
		}
		// Both buffer-size forms set simultaneously is ambiguous. The compiler
		// always clears the unused field (see compiler_class_of_service.go
		// buffer-size case), so this can only arise in constructed or
		// externally-assembled configs. Reject early rather than silently
		// applying the "byte-size wins" runtime preference.
		if sched.BufferSizeBytes > 0 && sched.BufferSizePercent > 0 {
			return fmt.Errorf(
				"class-of-service scheduler %q has both buffer-size bytes (%d) "+
					"and buffer-size percent (%.4g%%) set; use one form only",
				sched.Name, sched.BufferSizeBytes, sched.BufferSizePercent)
		}
	}
	// Aggregate percent check: Junos does not allow per-queue buffer
	// allocations to exceed 100% of the interface's total buffer pool.
	// Check each scheduler-map independently and reject overcommit here
	// so the runtime never silently over-allocates. A sum of exactly
	// 100% is permitted (full pool allocation).
	//
	// A small epsilon (1e-9) guards against accumulated IEEE 754 rounding
	// when summing multiple float64 percent values: e.g. 33.33% * 3 may
	// round to 99.99000000000001% rather than exactly 99.99%, so the check
	// must not reject legitimate 100%-summing configs.
	const maxTotalBufferPercent = 100.0
	const bufferPercentEpsilon = 1e-9
	for _, schedMap := range cos.SchedulerMaps {
		if schedMap == nil {
			continue
		}
		var totalPercent float64
		for _, entry := range schedMap.Entries {
			if entry == nil || entry.Scheduler == "" {
				continue
			}
			sched, ok := cos.Schedulers[entry.Scheduler]
			if !ok || sched == nil {
				continue
			}
			totalPercent += sched.BufferSizePercent
		}
		if totalPercent > maxTotalBufferPercent+bufferPercentEpsilon {
			return fmt.Errorf(
				"class-of-service scheduler-map %q: "+
					"sum of buffer-size percent across all schedulers is %.4g%% "+
					"(must not exceed 100%%)",
				schedMap.Name, totalPercent)
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

// validateRibGroupImportRibReferencesStrict hard-rejects a
// `routing-options rib-groups <group> import-rib <rib>` entry whose rib
// name resolves to no real routing table (#2226).
//
// A valid import-rib names one of:
//   - inet.0 / inet6.0 (the main table), OR
//   - "<instance>.inet.0" / "<instance>.inet6.0" where <instance> is a
//     defined routing-instance.
//
// Any other name — a typo, a non-existent instance, or unparseable
// garbage — is undefined. ValidateConfig only ever emitted an over-limit
// WARNING for rib-groups; it never validated that an import-rib names a
// real rib. The applier's resolveRibTable previously mapped any
// unresolvable name to a bare table 0 (see pkg/routing/rules.go). Because
// a routing-instance's source table is always >= 100, an unresolvable
// import-rib yielded targetTable(0) != sourceTable, which set needsLeak
// and installed an `ip rule from all lookup <sourceTable> pref 33000` for
// a rib that does not exist — a silent mis-leak of the source table into
// the main lookup, with no diagnostic. This gate makes the dangling
// reference an operator-visible commit error; resolveRibTable's ok=false
// path is the defense-in-depth backstop for any reference that still
// reaches apply via the tolerant load / peer-sync path.
//
// Rib-group names are iterated in sorted order, and each group's
// import-rib list is walked in declaration order, so the first-reported
// error is deterministic (Go map order is randomized). Every defined
// rib-group is validated (not only ones referenced by an instance's
// interface-routes rib-group), mirroring Junos, which rejects an
// undefined rib regardless of whether the group is in use.
//
// On the tolerant load / peer-sync paths the call site downgrades this to
// a warning (opts.lenientRibGroupRefs) so an already-persisted or peer-
// synced config carrying a dangling import-rib still BOOTS (#1960
// fail-closed-on-load class); the applier's ok=false guard keeps it inert
// (the phantom rib is skipped, no rule is installed), exactly matching the
// post-fix runtime behaviour. Commit / commit-check stay strict. Mirrors
// validateRoutingExportReferencesStrict.
func validateRibGroupImportRibReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ribGroups := cfg.RoutingOptions.RibGroups
	if len(ribGroups) == 0 {
		return nil
	}
	definedInstance := make(map[string]bool, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name != "" {
			definedInstance[ri.Name] = true
		}
	}
	// resolvable mirrors pkg/routing.resolveRibTable's definedness view:
	// inet.0 / inet6.0, or "<defined-instance>.inet[6].0".
	resolvable := func(ribName string) bool {
		if ribName == "inet.0" || ribName == "inet6.0" {
			return true
		}
		if idx := strings.Index(ribName, ".inet"); idx > 0 {
			return definedInstance[ribName[:idx]]
		}
		return false
	}
	names := make([]string, 0, len(ribGroups))
	for name := range ribGroups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rg := ribGroups[name]
		if rg == nil {
			continue
		}
		for _, ribName := range rg.ImportRibs {
			if ribName == "" || resolvable(ribName) {
				continue
			}
			return fmt.Errorf(
				"routing-options rib-groups %q import-rib %q references an "+
					"undefined rib (name a defined routing-instance as "+
					"\"<instance>.inet.0\" / \"<instance>.inet6.0\", or use "+
					"inet.0 / inet6.0 for the main table — an undefined rib "+
					"would otherwise silently leak this table's routes into "+
					"the main lookup)",
				name, ribName)
		}
	}
	return nil
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
