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

// validateIKEPolicyChainReferencesStrict hard-rejects an IKE (Phase 1)
// reference chain that cannot resolve to a real proposal (#2270). A
// gateway names an `ike-policy`; that policy names a `proposals` (an
// `ike-proposal`). resolveIKESettings (pkg/ipsec/ike.go) walks
// gateway -> ike-policy -> ike-proposal. When that chain breaks — the
// ike-policy is undefined, or the policy's `proposals` reference dangles —
// resolveIKESettings used to return an empty proposal string with a nil
// error, and renderConfig (which guards the line with `if ikeProposals !=
// ""`) emitted the connection block with NO `proposals =` line. strongSwan
// then negotiates phase-1 with its compiled-in default proposal set instead
// of the configured/required crypto — a silent security-posture downgrade,
// the same class validateIPsecPolicyProposalReferencesStrict closes for the
// Phase-2 (ESP) chain.
//
// What is accepted (mirror resolveIKESettings exactly so commit and render
// agree on what resolves):
//   - a gateway with no `ike-policy` at all: the intentional no-policy
//     case — strongSwan's default set is the operator's explicit choice,
//     nothing dangles.
//   - gateway -> defined ike-policy -> defined ike-proposal.
//   - the legacy direct-proposal fallback: a gateway whose `ike-policy`
//     value is itself the NAME of a defined IPsec (Phase 2) proposal, which
//     resolveIKESettings renders via buildIKEProposal when the ike-policy
//     chain is absent. Accepted so a config that genuinely renders a
//     non-empty proposal is never rejected.
//
// Rejected:
//   - a gateway whose `ike-policy` names no defined ike-policy AND is not a
//     defined IPsec-proposal name (a typo / dangling reference).
//   - a gateway whose `ike-policy` resolves to a defined ike-policy but
//     that policy's `proposals` reference names no defined ike-proposal,
//     and the ike-policy value is not also a defined IPsec-proposal name.
//
// Only gateways actually referenced by a VPN are validated: an orphan
// gateway never reaches render, so an unreferenced dangling chain is inert
// (and Junos likewise only faults a gateway in use). Gateways are iterated
// via the sorted VPN list so the first-reported error is deterministic.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientIKEPolicyChainRef) so an already-persisted or
// peer-synced config carrying a dangling reference still BOOTS (#1960
// fail-closed-on-load class); the render-path safety net in pkg/ipsec
// (resolveIKESettings -> errIKEChainUnresolved -> renderConfig skips the
// VPN) keeps the bad tunnel out of the generated config rather than letting
// it negotiate with defaults. Commit / commit-check stay strict. Mirrors
// validateIPsecPolicyProposalReferencesStrict.
func validateIKEPolicyChainReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ipsec := &cfg.Security.IPsec
	if len(ipsec.VPNs) == 0 {
		return nil
	}
	gateways := ipsec.Gateways
	ikePolicies := ipsec.IKEPolicies
	ikeProposals := ipsec.IKEProposals
	espProposals := ipsec.Proposals

	// chainResolves mirrors resolveIKESettings' acceptance: the
	// ike-policy -> ike-proposal chain, OR the legacy direct-proposal
	// fallback (the ike-policy value is itself a defined Phase-2 proposal
	// name).
	chainResolves := func(ikePolicyName string) bool {
		if pol, ok := ikePolicies[ikePolicyName]; ok && pol != nil {
			if _, ok := ikeProposals[pol.Proposals]; ok {
				return true
			}
		}
		// Legacy fallback: a gateway's ike-policy value naming an IPsec
		// proposal directly. resolveIKESettings only consults this when the
		// ike-policy chain is absent, so checking it unconditionally here is
		// a superset that never wrongly rejects a renderable config.
		if _, ok := espProposals[ikePolicyName]; ok {
			return true
		}
		return false
	}

	// VPNs is a map (unordered); sort keys so the first-error commit-check
	// message is deterministic across runs.
	vpnNames := make([]string, 0, len(ipsec.VPNs))
	for name := range ipsec.VPNs {
		vpnNames = append(vpnNames, name)
	}
	sort.Strings(vpnNames)
	for _, vpnName := range vpnNames {
		vpn := ipsec.VPNs[vpnName]
		if vpn == nil || vpn.Gateway == "" {
			continue
		}
		gw, ok := gateways[vpn.Gateway]
		if !ok || gw == nil {
			// An undefined / inline gateway is the domain of
			// validateIPsecGatewayReferencesStrict (#2074); there is no
			// ike-policy chain to validate here.
			continue
		}
		if gw.IKEPolicy == "" {
			// Intentional no-policy case (strongSwan defaults chosen).
			continue
		}
		if chainResolves(gw.IKEPolicy) {
			continue
		}
		// A gateway may be authored under either `security ike gateway` or
		// `security ipsec gateway` (both compileIKE and compileIPsec populate
		// the same Gateways map; #2279). The typed gateway does not record
		// which stanza it came from, so the message names both candidates
		// rather than asserting a single (possibly wrong) prefix.
		if _, polDefined := ikePolicies[gw.IKEPolicy]; !polDefined {
			return fmt.Errorf("gateway %q (under `security ike` or "+
				"`security ipsec`, used by ipsec vpn %q) references undefined "+
				"ike-policy %q; phase-1 would silently negotiate with the "+
				"strongSwan default proposal set instead of the configured "+
				"crypto",
				gw.Name, vpnName, gw.IKEPolicy)
		}
		pol := ikePolicies[gw.IKEPolicy]
		if pol.Proposals == "" {
			// The ike-policy exists but has no `proposals` leaf at all, so
			// pol.Proposals is the empty string. Reporting an "undefined
			// ike-proposal \"\"" misleads the operator into hunting for a
			// proposal named "" — say plainly that the policy is missing its
			// proposals configuration.
			return fmt.Errorf("ike-policy %q (via gateway %q, ipsec vpn %q) "+
				"has no proposals configured; phase-1 would silently negotiate "+
				"with the strongSwan default proposal set instead of the "+
				"configured crypto",
				gw.IKEPolicy, gw.Name, vpnName)
		}
		return fmt.Errorf("ike-policy %q (via gateway %q, ipsec vpn %q) "+
			"references undefined ike-proposal %q; phase-1 would silently "+
			"negotiate with the strongSwan default proposal set instead of "+
			"the configured crypto",
			gw.IKEPolicy, gw.Name, vpnName, pol.Proposals)
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

// validateFlowServerTemplateReferencesStrict hard-rejects a per-flow-server
// NetFlow v9 / IPFIX template reference (`version9 { template <name> }`,
// `version9-template <name>`, `version-ipfix { template <name> }`, or
// `version-ipfix-template <name>`) that names no template defined under the
// matching `services flow-monitoring` version stanza (#2461).
//
// Without this gate the live exporter (pkg/flowexport) ignored the per-server
// reference entirely and built one export config from the FIRST Go-map-
// iteration template, broadcasting it to every collector of that version. A
// collector that asked for a specific template silently received whichever
// template the map happened to yield first, and that choice flipped across
// process restarts (map order is not an operator contract). A reference to a
// template that does not exist at all is the clearest form of the same defect:
// the operator's intent (timeouts / export-extensions) is simply dropped.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientFlowServerTemplateRef) so an already-persisted or
// peer-synced config carrying the typo still boots (#1960 fail-closed-on-load
// class). The resolver (ResolveV9TemplateGroups / ResolveIPFIXTemplateGroups)
// drops a group whose referenced template is undefined, so a leniently-loaded
// bad config exports nothing for that collector rather than the wrong
// template. Commit / commit-check stay strict so the operator's next edit
// fails loudly. Mirrors validateLogProfileStreamReferencesStrict.
func validateFlowServerTemplateReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	fm := cfg.Services.FlowMonitoring
	if cfg.ForwardingOptions.Sampling == nil {
		return nil
	}

	v9Defined := map[string]bool{}
	ipfixDefined := map[string]bool{}
	if fm != nil {
		if fm.Version9 != nil {
			for name := range fm.Version9.Templates {
				v9Defined[name] = true
			}
		}
		if fm.VersionIPFIX != nil {
			for name := range fm.VersionIPFIX.Templates {
				ipfixDefined[name] = true
			}
		}
	}

	// Walk the sampling instances in a deterministic key order so the
	// first-error commit-check message is stable across runs (the instance
	// map is unordered).
	instNames := make([]string, 0, len(cfg.ForwardingOptions.Sampling.Instances))
	for name := range cfg.ForwardingOptions.Sampling.Instances {
		instNames = append(instNames, name)
	}
	sort.Strings(instNames)

	for _, instName := range instNames {
		inst := cfg.ForwardingOptions.Sampling.Instances[instName]
		if inst == nil {
			continue
		}
		for _, fam := range []*SamplingFamily{inst.FamilyInet, inst.FamilyInet6} {
			if fam == nil {
				continue
			}
			for _, fs := range fam.FlowServers {
				if fs == nil {
					continue
				}
				if fs.Version9Template != "" && !v9Defined[fs.Version9Template] {
					return fmt.Errorf("forwarding-options sampling instance %q "+
						"flow-server %s references undefined version9 template %q "+
						"(define it under services flow-monitoring version9, or fix "+
						"the template name — the collector would otherwise receive "+
						"an arbitrary template)", instName, fs.Address, fs.Version9Template)
				}
				if fs.VersionIPFIXTemplate != "" && !ipfixDefined[fs.VersionIPFIXTemplate] {
					return fmt.Errorf("forwarding-options sampling instance %q "+
						"flow-server %s references undefined version-ipfix template "+
						"%q (define it under services flow-monitoring version-ipfix, "+
						"or fix the template name — the collector would otherwise "+
						"receive an arbitrary template)", instName, fs.Address, fs.VersionIPFIXTemplate)
				}
			}
		}
	}
	return nil
}

// flowServerExportVersion mirrors flowexport.resolveFlowServerVersion: it
// returns the export protocol a single flow-server binds to, given the
// per-server selector and which global `services flow-monitoring` version
// stanzas are configured. It is duplicated here (not imported) because
// pkg/config must not depend on pkg/flowexport. Returns "" when the server
// resolves to no configured version. Keep in sync with
// pkg/flowexport.resolveFlowServerVersion.
func flowServerExportVersion(fs *FlowServer, hasV9, hasIPFIX bool) string {
	switch fs.Version {
	case FlowServerVersion9:
		if hasV9 {
			return FlowServerVersion9
		}
		return ""
	case FlowServerVersionIPFIX:
		if hasIPFIX {
			return FlowServerVersionIPFIX
		}
		return ""
	}
	switch {
	case hasIPFIX:
		return FlowServerVersionIPFIX
	case hasV9:
		return FlowServerVersion9
	default:
		return ""
	}
}

// validateSamplingInstanceConflictsStrict hard-rejects an unsupported
// multi-sampling-instance configuration (#2462).
//
// The defect: multiple `forwarding-options sampling instance` blocks were
// silently flattened into one global export policy — one rate (the first
// nonzero InputRate in Go map order), one merged collector set, one zone
// eligibility map. Flows from instance A could export to instance B's
// collectors and the effective rate depended on map-iteration order.
//
// The fix makes each instance a first-class export policy: its own rate, its
// own 1-in-N counter, its own collectors. A flow is attributed to an instance
// by ADDRESS FAMILY (the only per-flow selector available — the interface
// `family inet { sampling { input; } }` stanza is a plain boolean; there is
// NO per-interface sampling-instance selector in the config model, so two
// instances serving the SAME family for the SAME export version are genuinely
// ambiguous: the runtime cannot tell which instance a given IPv4 (or IPv6)
// flow belongs to). Rather than guess (the flatten-and-hope behavior this
// issue reports), that combination is rejected.
//
// Supported: a single instance (any rate / families / collectors — the common
// case, unchanged); multiple instances disambiguated by family (e.g. instance
// A serves inet, instance B serves inet6) and/or by export version (an inet
// instance bound to version9 vs an inet instance bound to version-ipfix —
// distinct datagram streams, the flow is duplicated to both intentionally,
// same as today's single-instance dual-version behavior).
//
// Rejected: two or more instances each configuring a flow-server that
// resolves to the SAME (export-version, address-family) pair.
//
// Strict on commit / commit-check (hard reject so the operator sees it);
// lenient on load / peer-sync (the call site downgrades to a warning via
// opts.lenientSamplingInstanceConflicts so an already-persisted or
// peer-synced config still boots — #1960; the resolver still emits both
// instances' independent ExportConfigs, so a leniently-loaded conflicting
// config duplicates eligible flows to both instances rather than bricking).
func validateSamplingInstanceConflictsStrict(cfg *Config) error {
	if cfg == nil || cfg.ForwardingOptions.Sampling == nil {
		return nil
	}
	insts := cfg.ForwardingOptions.Sampling.Instances
	if len(insts) < 2 {
		return nil // single instance is always unambiguous
	}
	fm := cfg.Services.FlowMonitoring
	hasV9 := fm != nil && fm.Version9 != nil
	hasIPFIX := fm != nil && fm.VersionIPFIX != nil

	// Deterministic instance order so the first-conflict message is stable.
	names := make([]string, 0, len(insts))
	for name := range insts {
		names = append(names, name)
	}
	sort.Strings(names)

	// claim key "<version>\x00<family>" -> first instance that claimed it.
	claimed := map[string]string{}
	for _, name := range names {
		inst := insts[name]
		if inst == nil {
			continue
		}
		fams := []struct {
			fam    *SamplingFamily
			family string
		}{
			{inst.FamilyInet, "inet"},
			{inst.FamilyInet6, "inet6"},
		}
		// Collect THIS instance's distinct (version, family) claims, so the
		// same instance binding two collectors to the same (version, family)
		// does not self-conflict.
		selfClaims := map[string]bool{}
		for _, fe := range fams {
			if fe.fam == nil {
				continue
			}
			for _, fs := range fe.fam.FlowServers {
				if fs == nil {
					continue
				}
				ver := flowServerExportVersion(fs, hasV9, hasIPFIX)
				if ver == "" {
					continue // resolves to no configured version; exports nothing
				}
				selfClaims[ver+"\x00"+fe.family] = true
			}
		}
		// Deterministic order over this instance's claims.
		keys := make([]string, 0, len(selfClaims))
		for k := range selfClaims {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if owner, ok := claimed[key]; ok {
				parts := strings.SplitN(key, "\x00", 2)
				return fmt.Errorf("forwarding-options sampling instances %q and %q "+
					"both export %s family %s flows: the runtime cannot attribute a "+
					"flow to one instance (there is no per-interface sampling-instance "+
					"selector — eligibility is per address family), so the two would "+
					"silently merge. Use a single instance for this version/family, or "+
					"separate the instances by family or export version",
					owner, name, parts[0], parts[1])
			}
			claimed[key] = name
		}
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

	// checkPolicyRef validates a reference that renders directly as a
	// route-map / ECMP policy name: only a defined policy-statement is valid.
	// hint is the trailing remediation text — direction-aware so an import
	// failure does not say "fix the export name" (Copilot review, #2490).
	checkPolicyRef := func(detail, name, hint string) error {
		if name == "" || defined(name) {
			return nil
		}
		return fmt.Errorf("%s references undefined policy-statement %q; %s",
			detail, name, hint)
	}
	const (
		hintExport = "define the policy-statement or fix the export name"
		hintImport = "define the policy-statement or fix the import name"
	)

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
			// A global `protocols bgp import` renders `route-map <name> in`.
			// Unlike export, import has NO redistribute equivalent — inbound
			// filtering is route-map-only — so it must name a DEFINED
			// policy-statement (no protocol-token fallback). An undefined ref
			// would render a dangling `route-map in` that FRR resolves to
			// PERMIT-ALL, accepting every inbound advertisement and defeating
			// the operator's filter (#2490, the #2473 lesson on the inbound
			// direction). #2490.
			for _, e := range bgp.Import {
				detail := fmt.Sprintf("%sprotocols bgp import", scope)
				if err := checkPolicyRef(detail, e, hintImport); err != nil {
					return err
				}
			}
			// A BGP group/neighbor export renders `route-map <name> out`,
			// and a group/neighbor import renders `route-map <name> in`, so
			// both must be defined policy-statements (no protocol-token
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
					if err := checkPolicyRef(detail, e, hintExport); err != nil {
						return err
					}
				}
				for _, e := range n.Import {
					detail := fmt.Sprintf("%sprotocols bgp neighbor %s import", scope, n.Address)
					if n.GroupName != "" {
						detail = fmt.Sprintf("%sprotocols bgp group %s neighbor %s import", scope, n.GroupName, n.Address)
					}
					if err := checkPolicyRef(detail, e, hintImport); err != nil {
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
		hintExport,
	); err != nil {
		return fmt.Errorf("%s (the expected ECMP / consistent-hash "+
			"load-balancing would be silently disabled)", err)
	}

	return nil
}

// frrTokenUnsafeIndex returns the byte index of the first character in s
// that FRR's command lexer cannot carry inside a single config token, or
// -1 if every character is safe.
//
// FRR's CLI lexer (lib/command_lex.l) tokenizes a vtysh / frr.conf line on
// ASCII whitespace and has NO quoted-string rule and NO rest-of-line
// ("LINE") token — a double-quoted value is NOT grouped, the quotes are
// taken literally. So any whitespace inside a rendered value splits it into
// multiple arguments: a password / auth key is truncated at the first space,
// or trailing words become spurious vtysh arguments. We therefore reject
// only the characters that actually break tokenization: ASCII space, tab,
// and the C0 / DEL control set (which sanitizeFRRValue would otherwise turn
// into spaces at render time, re-introducing the same split). Other
// punctuation (`.`, `@`, `!`, `#`, …) is matched by the lexer's single-char
// catch-all rule and stays adjacent with no whitespace, so it is safe.
func frrTokenUnsafeIndex(s string) int {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c < 0x20 || c == 0x7f {
			return i
		}
	}
	return -1
}

// validateFRRAuthValuesStrict hard-rejects a dynamic-routing authentication
// secret that cannot be rendered as a single FRR/vtysh token (#2889):
//
//   - a BGP neighbor TCP-MD5 password (`neighbor <addr> password ...`)
//   - an OSPF interface authentication key (`ip ospf message-digest-key`
//     md5 / `ip ospf authentication-key`)
//   - a RIP authentication key (`ip rip authentication string`)
//   - an IS-IS area/domain or per-interface authentication key
//     (`area-password` / `domain-password` / `isis password`)
//
// All of these render the secret directly into a frr.conf line. FRR's
// command lexer (lib/command_lex.l) splits on whitespace and supports
// neither a quoted string nor a rest-of-line token, so a secret containing
// a space or tab is parsed as multiple arguments at config load: the secret
// is truncated at the first space, or — worse — the trailing words are
// interpreted as additional vtysh arguments (a malformed-line / injection
// risk). The render-side belt (sanitizeFRRValue, #1798) already collapses
// embedded control characters to spaces, so it cannot rescue this; it would
// only widen the split. Quoting is not an option here, so the safe contract
// is to reject the value at commit, naming the field.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientFRRAuthValues) so an already-persisted or peer-synced
// config carrying such a value still BOOTS (#1960 fail-closed-on-load
// class); the render path strips control chars and the offending line stays
// inert / single-line. Commit / commit-check stay strict. Mirrors
// validateRoutingExportReferencesStrict.
func validateFRRAuthValuesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	const why = "FRR's vtysh config lexer splits on whitespace and supports " +
		"no quoting, so the secret would be truncated at the first space or " +
		"inject trailing words as extra arguments at frr.conf load — remove " +
		"the whitespace/control characters from the value"

	checkKey := func(scope, field string, s Secret) error {
		if s == "" {
			return nil
		}
		if i := frrTokenUnsafeIndex(s.Reveal()); i >= 0 {
			return fmt.Errorf("%s%s contains whitespace or a control "+
				"character (at byte offset %d) that cannot be represented "+
				"in FRR config — %s", scope, field, i, why)
		}
		return nil
	}

	checkProtocols := func(scope string, ospf *OSPFConfig, bgp *BGPConfig, rip *RIPConfig, isis *ISISConfig) error {
		if ospf != nil {
			for _, area := range ospf.Areas {
				if area == nil {
					continue
				}
				for _, iface := range area.Interfaces {
					if iface == nil {
						continue
					}
					fld := fmt.Sprintf("protocols ospf area %s interface %s authentication-key", area.ID, iface.Name)
					if err := checkKey(scope, fld, iface.AuthKey); err != nil {
						return err
					}
				}
			}
		}
		if rip != nil {
			if err := checkKey(scope, "protocols rip authentication-key", rip.AuthKey); err != nil {
				return err
			}
		}
		if isis != nil {
			if err := checkKey(scope, "protocols isis authentication-key", isis.AuthKey); err != nil {
				return err
			}
			for _, iface := range isis.Interfaces {
				if iface == nil {
					continue
				}
				fld := fmt.Sprintf("protocols isis interface %s authentication-key", iface.Name)
				if err := checkKey(scope, fld, iface.AuthKey); err != nil {
					return err
				}
			}
		}
		if bgp != nil {
			// Sort neighbor addresses for a deterministic first-error
			// message (Go map / slice authoring order is not stable across
			// the parse paths).
			neighbors := append([]*BGPNeighbor(nil), bgp.Neighbors...)
			sort.SliceStable(neighbors, func(i, j int) bool {
				return neighbors[i].Address < neighbors[j].Address
			})
			for _, n := range neighbors {
				if n == nil {
					continue
				}
				fld := fmt.Sprintf("protocols bgp neighbor %s authentication-key", n.Address)
				if n.GroupName != "" {
					fld = fmt.Sprintf("protocols bgp group %s neighbor %s authentication-key", n.GroupName, n.Address)
				}
				if err := checkKey(scope, fld, n.AuthPassword); err != nil {
					return err
				}
			}
		}
		return nil
	}

	// Top-level protocols.
	if err := checkProtocols("", cfg.Protocols.OSPF, cfg.Protocols.BGP, cfg.Protocols.RIP, cfg.Protocols.ISIS); err != nil {
		return err
	}

	// Per routing-instance protocols.
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := checkProtocols(scope, ri.OSPF, ri.BGP, ri.RIP, ri.ISIS); err != nil {
			return err
		}
	}

	return nil
}

// validateBGPNeighborPeerASStrict hard-rejects a BGP neighbor whose effective
// peer-as (remote-as) is missing/0 or out of the valid AS range (#2963).
//
// peer-as is optional in the parser/compiler (compiler_protocols.go assigns
// BGPNeighbor.PeerAS only when a per-neighbor `peer-as` token or an inherited
// group `peer-as` is present; otherwise it stays the zero value). The FRR
// renderer (pkg/frr/policy_render.go) emits `neighbor <addr> remote-as <PeerAS>`
// unconditionally, so a neighbor authored without a peer-as renders
// `neighbor <addr> remote-as 0`. AS 0 is reserved (RFC 7607) and FRR/vtysh
// rejects it: the whole frr-reload fails (a single vtysh -f add-batch exits
// non-zero on any CMD_WARNING_CONFIG_FAILED), leaving dynamic routing in a
// broken/stale state. That is a commit-accepted config the routing daemon
// cannot load — exactly the fail-class this gate closes.
//
// The valid 4-byte AS space is 1..4294967295 (uint32 max); 0 is reserved
// (RFC 7607) and 23456 (AS_TRANS) is reserved for 4-byte transition but is a
// legal configured remote-as, so only 0 is rejected here. (PeerAS is a uint32
// so the upper bound cannot be exceeded by the typed value — the range check
// documents intent and is robust to a future wider type.)
//
// Both the global `protocols bgp` and per-routing-instance scopes are checked.
// Neighbor addresses are sorted for a deterministic first-error message.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientBGPNeighborPeerAS) so an already-persisted or
// peer-synced config carrying such a neighbor still BOOTS (#1960
// fail-closed-on-load class); the render path now skips a remote-as-0 neighbor
// (defense-in-depth) so AS 0 never reaches frr.conf and a leniently-loaded bad
// neighbor is inert. Commit / commit-check stay strict. Mirrors
// validateRoutingExportReferencesStrict.
func validateBGPNeighborPeerASStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	checkBGP := func(scope string, bgp *BGPConfig) error {
		if bgp == nil {
			return nil
		}
		neighbors := append([]*BGPNeighbor(nil), bgp.Neighbors...)
		sort.SliceStable(neighbors, func(i, j int) bool {
			return neighbors[i].Address < neighbors[j].Address
		})
		for _, n := range neighbors {
			if n == nil {
				continue
			}
			if n.PeerAS == 0 {
				detail := fmt.Sprintf("%sprotocols bgp neighbor %s", scope, n.Address)
				if n.GroupName != "" {
					detail = fmt.Sprintf("%sprotocols bgp group %s neighbor %s", scope, n.GroupName, n.Address)
				}
				return fmt.Errorf("%s: missing/invalid peer-as — a BGP neighbor "+
					"requires a peer-as (remote-as) in 1..4294967295; AS 0 is "+
					"reserved (RFC 7607) and FRR/vtysh rejects `remote-as 0`, "+
					"failing the frr-reload — set the neighbor (or its group) "+
					"peer-as", detail)
			}
		}
		return nil
	}

	if err := checkBGP("", cfg.Protocols.BGP); err != nil {
		return err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := checkBGP(scope, ri.BGP); err != nil {
			return err
		}
	}
	return nil
}

// validateRouterIDStrict hard-rejects an OSPF / OSPFv3 / BGP router-id that is
// not a valid 32-bit IPv4 dotted-quad (#2980).
//
// router-id is parsed as a raw string and stored verbatim
// (compiler_protocols.go assigns OSPF/OSPFv3/BGP RouterID = child.Keys[1] with
// no validation). The FRR renderer (pkg/frr/policy_render.go) emits
// `ospf router-id <v>` / `ospf6 router-id <v>` / `bgp router-id <v>` whenever
// the field is non-empty. FRR/vtysh requires a 32-bit dotted-quad router-id
// for ALL of these protocols — including the IPv6 protocols OSPFv3 (ospf6) and
// BGP — and rejects anything else (e.g. `foo`, `300.1.2.3`, or an IPv6
// address): the whole frr-reload fails (a single vtysh -f add-batch exits
// non-zero on any CMD_WARNING_CONFIG_FAILED), leaving dynamic routing in a
// broken/stale state. That is a commit-accepted config the routing daemon
// cannot load — exactly the fail-class this gate closes.
//
// A router-id is the 32-bit dotted-quad form even for IPv6 protocols, so the
// check is net.ParseIP + To4()!=nil (net/netip ParseAddr+Is4 is equivalent;
// To4 keeps the validator on the same net.* surface the file already uses for
// other address checks). Empty is allowed at every scope — an unset router-id
// is omitted by the renderer and FRR auto-derives one, which is the documented
// Junos/FRR default.
//
// Both the global `protocols {}` and per-routing-instance scopes are checked,
// covering OSPF, OSPFv3, and BGP. Routing instances are walked in declaration
// order for a deterministic first-error message.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientRouterID) so an already-persisted or peer-synced config
// carrying a bad router-id still BOOTS (#1960 fail-closed-on-load class); the
// render path now skips an invalid router-id (defense-in-depth) so a malformed
// value never reaches frr.conf and a leniently-loaded bad router-id is inert.
// Commit / commit-check stay strict. Mirrors validateBGPNeighborPeerASStrict.
func validateRouterIDStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	check := func(scope, proto, routerID string) error {
		if routerID == "" {
			return nil
		}
		if ip := net.ParseIP(routerID); ip == nil || ip.To4() == nil {
			return fmt.Errorf("%s%s router-id %q is not a valid IPv4 "+
				"dotted-quad address — FRR/vtysh requires a 32-bit IPv4 "+
				"router-id for all routing protocols (including OSPFv3 and "+
				"BGP) and rejects anything else, failing the frr-reload",
				scope, proto, routerID)
		}
		return nil
	}

	checkScope := func(scope string, ospf *OSPFConfig, ospfv3 *OSPFv3Config, bgp *BGPConfig) error {
		if ospf != nil {
			if err := check(scope, "protocols ospf", ospf.RouterID); err != nil {
				return err
			}
		}
		if ospfv3 != nil {
			if err := check(scope, "protocols ospf3", ospfv3.RouterID); err != nil {
				return err
			}
		}
		if bgp != nil {
			if err := check(scope, "protocols bgp", bgp.RouterID); err != nil {
				return err
			}
		}
		return nil
	}

	if err := checkScope("", cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.BGP); err != nil {
		return err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := checkScope(scope, ri.OSPF, ri.OSPFv3, ri.BGP); err != nil {
			return err
		}
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

// validateFirewallPrefixListReferencesStrict hard-rejects a firewall-filter
// term whose `from source-prefix-list <name>` / `destination-prefix-list
// <name>` (with or without `except`) names a prefix-list not defined under
// `policy-options prefix-list <name>` (#2506).
//
// A dangling prefix-list reference compiled cleanly and the userspace snapshot
// builder contributed NO prefixes for it, so the term reached the dataplane
// with no address scope from that reference — a silent fail-open (accept/PBR
// permits unintended traffic) or fail-closed (discard/reject drops everything),
// action-dependent. This gate makes the typo operator-visible at commit,
// consistent with the policer and routing-instance reference gates.
//
// Both filter families are walked, sorted by filter name then by term position
// for a deterministic first error. On the tolerant load / peer-sync paths the
// call site downgrades to a warning (opts.lenientFirewallRefs) so an already-
// persisted or peer-synced config still BOOTS (#1960); the resolver then
// contributes no prefixes for the unresolved reference. Mirrors
// validateFirewallPolicerReferencesStrict.
func validateFirewallPrefixListReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	defined := func(name string) bool {
		if cfg.PolicyOptions.PrefixLists == nil {
			return false
		}
		_, ok := cfg.PolicyOptions.PrefixLists[name]
		return ok
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
				if term == nil {
					continue
				}
				for _, ref := range term.SourcePrefixLists {
					if defined(ref.Name) {
						continue
					}
					return fmt.Errorf(
						"firewall family %s filter %q term %q references undefined "+
							"source-prefix-list %q (define `policy-options prefix-list "+
							"%s` or fix the name — the address scope would otherwise be "+
							"silently lost)",
						family, name, term.Name, ref.Name, ref.Name)
				}
				for _, ref := range term.DestPrefixLists {
					if defined(ref.Name) {
						continue
					}
					return fmt.Errorf(
						"firewall family %s filter %q term %q references undefined "+
							"destination-prefix-list %q (define `policy-options "+
							"prefix-list %s` or fix the name — the address scope would "+
							"otherwise be silently lost)",
						family, name, term.Name, ref.Name, ref.Name)
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

// policyZoneSpecialTokens is the set of reserved from-zone/to-zone tokens
// that name a context rather than an operator-defined security zone, and so
// must be exempt from the "zone must be defined" gate
// (validatePolicyZoneReferencesStrict, #2401):
//
//   - ""            — an empty token: a zone-pair with no name compiles to no
//     usable rule and is not an undefined-zone reference per se; leave it to
//     the structural compiler rather than reporting a confusing `""` error.
//   - "any"         — Junos wildcard zone (`from-zone any`/`to-zone any`); the
//     dataplane treats it as match-any, never a named zone-id lookup.
//   - "junos-host"  — Junos reserved self-traffic zone (host-inbound / host-
//     outbound policy context); it is never declared as a `security zone`.
//
// Global policies (`security policies global { ... }`) are not validated here:
// they live in cfg.Security.GlobalPolicies with no from/to-zone strings and
// are mapped to the `junos-global` sentinel only when the dataplane snapshot is
// built (see pkg/dataplane/userspace/policies.go), so they cannot reference an
// undefined zone.
var policyZoneSpecialTokens = map[string]struct{}{
	"":           {},
	"any":        {},
	"junos-host": {},
}

// validatePolicyZoneReferencesStrict hard-rejects a security policy zone-pair
// (`from-zone <a> to-zone <b> { policy ... }`) whose from-zone or to-zone names
// a security zone the configuration never defines (#2401).
//
// Such a stanza is compiled and the rules are KEPT, but the userspace
// dataplane resolves the unknown zone name to no zone-id and therefore never
// indexes the rule into its zone-pair lookup table (userspace-dp/src/policy.rs:
// the unknown-zone branch logs "policy rule references unknown zone(s) ...
// (rule kept, but not indexed)"). At match time the zone pair has no indexed
// rule, so evaluation falls through to `state.default_action`: under a permit
// default this is a silent fail-OPEN (a deny rule the operator wrote against a
// mistyped/uncreated zone does nothing); under a deny default it blackholes
// with no operator-visible signal beyond a stderr line. Junos rejects an
// undefined zone reference at commit; this validator restores that fail-CLOSED
// parity.
//
// ValidateConfig already surfaced this as a warning only (commit succeeded with
// an unenforceable rule). This is the strict commit / commit-check gate;
// CompileConfigLenient downgrades it back to a warning (lenientPolicyZoneRefs)
// so an already-persisted or peer-synced config carrying a stale zone reference
// still boots — the dataplane drops the unindexed rule on its own, so a
// leniently-loaded bad config is inert.
//
// Special zone tokens (`any`, `junos-host`, the empty token) are exempt; global
// policies are not iterated (see policyZoneSpecialTokens). Iteration is in
// cfg.Security.Policies order, which is deterministic (built in config order by
// compileSecurityPolicies), so the first-reported error is stable.
func validatePolicyZoneReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	defined := func(zone string) bool {
		if _, special := policyZoneSpecialTokens[zone]; special {
			return true
		}
		_, ok := cfg.Security.Zones[zone]
		return ok
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		if !defined(zpp.FromZone) {
			return fmt.Errorf(
				"security policy from-zone %q to-zone %q references undefined from-zone %q; define `set security zones security-zone %s` in the same commit or the rule is silently never matched (zone-pair falls through to the default policy)",
				zpp.FromZone, zpp.ToZone, zpp.FromZone, zpp.FromZone)
		}
		if !defined(zpp.ToZone) {
			return fmt.Errorf(
				"security policy from-zone %q to-zone %q references undefined to-zone %q; define `set security zones security-zone %s` in the same commit or the rule is silently never matched (zone-pair falls through to the default policy)",
				zpp.FromZone, zpp.ToZone, zpp.ToZone, zpp.ToZone)
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

// policyActionName renders a PolicyAction as its Junos `then` token for
// operator-facing validator errors.
func policyActionName(a PolicyAction) string {
	switch a {
	case PolicyPermit:
		return "permit"
	case PolicyDeny:
		return "deny"
	case PolicyReject:
		return "reject"
	default:
		return fmt.Sprintf("action(%d)", int(a))
	}
}

// policyTerminalActionError formats the commit-time error for a policy that
// does not resolve to exactly one terminal action (#3043).
func policyTerminalActionError(scope, polName, detail string) error {
	if scope != "" {
		return fmt.Errorf("%s policy %q: %s", scope, polName, detail)
	}
	return fmt.Errorf("policy %q: %s", polName, detail)
}

// validatePolicyTerminalActionStrict hard-rejects a security policy that does
// not specify EXACTLY ONE terminal action (#3043).
//
// PolicyAction's zero value is PolicyPermit (types_security.go:
// `PolicyPermit PolicyAction = iota`), so before this gate a policy whose
// `then` stanza carried only modifiers (`then log session-init` /
// `then count`) — or a typo'd / dropped terminal action — compiled with
// Action == PolicyPermit and silently PERMITTED every packet matching its
// match conditions. A rule the operator wrote as an audit/drop placeholder
// thus became a zone-pair-wide permit: a silent fail-OPEN security hole.
// Symmetrically, a policy that named MORE than one terminal action (e.g. a
// group-merged `then permit` + `then deny`) resolved last-wins by child
// visitation order rather than failing the commit, so the enforced action
// depended on parse order.
//
// Junos requires every policy term to have exactly one terminal action; this
// validator restores that fail-CLOSED parity. It checks each per-zone-pair
// policy and each global policy: terminalActions (populated in config order by
// compilePolicy) must have length exactly 1.
//
// Strict on the commit / commit-check path (CompileConfig — hard-reject);
// downgraded to a cfg.Warnings entry on the tolerant load / peer-sync paths
// (CompileConfigLenient / CompileConfigForNodeLenient, flag
// lenientPolicyTerminalAction) so an already-persisted or peer-synced config
// that an older binary accepted still BOOTS (#1960 fail-closed-on-load
// doctrine). On that tolerant path the runtime is independently safe:
// compilePolicy defaults an actionless policy's Action to PolicyDeny (NOT
// permit), so a leniently-loaded actionless policy DENIES rather than fails
// open. Iteration order (cfg.Security.Policies, then GlobalPolicies) is
// deterministic, so the first-reported error is stable.
func validatePolicyTerminalActionStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(scope string, pol *Policy) error {
		if pol == nil {
			return nil
		}
		switch len(pol.terminalActions) {
		case 1:
			return nil
		case 0:
			return policyTerminalActionError(scope, pol.Name,
				"no terminal action; every policy must specify exactly one of "+
					"`then permit`, `then deny`, or `then reject` (a log-only / "+
					"count-only or typo'd policy silently PERMITTED all matching "+
					"traffic; it now defaults to deny on load)")
		default:
			names := make([]string, 0, len(pol.terminalActions))
			for _, a := range pol.terminalActions {
				names = append(names, policyActionName(a))
			}
			return policyTerminalActionError(scope, pol.Name, fmt.Sprintf(
				"%d conflicting terminal actions (%s); a policy must specify "+
					"exactly one of permit/deny/reject (the enforced action would "+
					"otherwise depend on parse order)",
				len(pol.terminalActions), strings.Join(names, ", ")))
		}
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

// MaxUsableZoneID is the largest security-zone id the live AF_XDP userspace
// dataplane can carry. Zone ids are assigned sequentially 1..N in
// pkg/dataplane/compiler.go and reach the dataplane two ways: as the per-flow
// ingress/egress zone in the event-stream wire record (a u8 field — see
// userspace-dp/src/event_stream/codec.rs, "[21] IngressZoneID u8"), and as the
// zone-table key in the forwarding snapshot. The userspace forwarding builder
// rejects any zone id >= ZONE_ID_RESERVED_MIN (u16::MAX-1, reserved for the
// JUNOS_GLOBAL_ZONE_ID sentinel) and any id > u8::MAX
// (userspace-dp/src/afxdp/forwarding_build/zones.rs). The binding constraint is
// therefore the u8 wire field, NOT the reserved sentinel: the usable range is
// [1, min(255, ZONE_ID_RESERVED_MIN-1)] = [1, 255]. With more than 255 zones the
// 256th+ ids exceed the u8 field and were silently dropped by the dataplane,
// collapsing the referencing interfaces to zone 0 ("unknown") — a silent
// fail-open/fail-closed mis-attribution rather than a commit-time rejection
// (#2391).
const MaxUsableZoneID = 255

// validateZoneCountStrict hard-rejects a configuration that defines more
// security zones than the dataplane wire format can address (#2391). Zone ids
// are assigned 1..N sequentially over the sorted zone names; with N >
// MaxUsableZoneID the highest ids overflow the u8 event-stream zone field and
// were silently dropped by the userspace forwarding builder, mapping the
// affected interfaces to zone 0 instead of failing the commit. This validator is
// the PRIMARY gate: bounding N at MaxUsableZoneID guarantees no out-of-range id
// is ever produced, so the dataplane's defense-in-depth skip path is never
// reached for a clean commit.
//
// Strict on the commit / commit-check path (CompileConfig — hard-reject);
// downgraded to a cfg.Warnings entry on the tolerant load / peer-sync paths
// (CompileConfigLenient / CompileConfigForNodeLenient, flag lenientZoneCount) so
// an already-persisted or peer-synced config that an older binary accepted still
// BOOTS (#1960 fail-closed-on-load doctrine) — the dataplane independently fails
// closed on every overflowing zone, so a leniently-loaded over-cap config is
// inert (the overflow zones simply do not forward) rather than mis-attributed.
func validateZoneCountStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	n := len(cfg.Security.Zones)
	if n > MaxUsableZoneID {
		return fmt.Errorf(
			"configuration defines %d security zones, but the dataplane can address at most %d (zone ids are carried in a u8 wire field); reduce the zone count to %d or fewer — zones beyond the limit are dropped by the dataplane and their interfaces silently fall back to the \"unknown\" zone",
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
				if term == nil {
					continue
				}
				// #2545: protocol is multi-value — every token must resolve.
				for _, proto := range term.Protocols {
					if proto == "" {
						continue
					}
					if !filterProtocolResolvable(proto) {
						return fmt.Errorf(
							"firewall family %s filter %q term %q: unknown protocol %q "+
								"(use a protocol name such as tcp/udp/icmp/icmpv6/gre/esp/ah/"+
								"sctp/ospf or a numeric value 0-255)",
							family, name, term.Name, proto)
					}
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

// validateFilterActionsStrict hard-rejects any firewall-filter term whose
// `then` block carries a token that is neither a recognized terminating action
// (accept/reject/discard) nor a recognized modifier (count/log/syslog/
// forwarding-class/loss-priority/dscp/traffic-class/policer/routing-instance)
// — #2399 finding 032-16.
//
// Before this gate, compileFilterThen silently DROPPED an unrecognized or
// misspelled `then` token. The term's Action stayed "", which the dataplane
// compiler (pkg/dataplane/compiler_filter.go) and the Rust filter
// (userspace-dp/src/filter/compiler.rs parse_term) BOTH map to
// FilterAction::Accept — a fail-open permit. An operator who typed `then
// frobnicate` (or a future action a peer node understands) got an ACCEPT for a
// filter term they intended to deny. In Junos an unknown filter action is a
// commit error, so the safe behavior is fail-CLOSED: refuse the commit and
// name the offending token rather than silently permit.
//
// The walk is deterministic (filters sorted by name, terms in config order)
// so the first-reported error is stable across runs, matching
// validateFilterProtocolsStrict. On the tolerant load / peer-sync path the
// caller downgrades the returned error to a warning (#1960 no-brick); the
// dataplane still has no representation for the unknown token, so the
// leniently-loaded term defaults to accept independently — but the operator
// never reaches that state through a commit.
func validateFilterActionsStrict(cfg *Config) error {
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
				if term == nil || len(term.UnknownActions) == 0 {
					continue
				}
				return fmt.Errorf(
					"firewall family %s filter %q term %q: unknown `then` action %q "+
						"(use accept/reject/discard/next-term or a modifier such as "+
						"count/log/syslog/forwarding-class/loss-priority/dscp/"+
						"traffic-class/policer/routing-instance)",
					family, name, term.Name, term.UnknownActions[0])
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
	// inet.0 / inet6.0, or "<defined-instance>.inet[6].0". The instance form
	// requires an EXACT family suffix (see ribInstanceFromName) — a loose
	// ".inet" substring match would accept malformed names like
	// "<instance>.inetX.0" and "<instance>.inet.0.garbage" (#2253). The
	// commit-time gate and pkg/routing's runtime applier MUST agree on what
	// resolves, so both call the same exact-suffix matcher (#2226).
	resolvable := func(ribName string) bool {
		if ribName == "inet.0" || ribName == "inet6.0" {
			return true
		}
		if instance, ok := ribInstanceFromName(ribName); ok {
			return definedInstance[instance]
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

// ribInstanceFromName extracts the routing-instance prefix from a non-default
// rib name of the EXACT form "<instance>.inet.0" or "<instance>.inet6.0",
// returning ok=false for any other shape. The instance prefix must be
// non-empty. Bare "inet.0" / "inet6.0" (the main table) are NOT instance ribs
// and are handled by callers directly. Malformed family tokens
// (".inetX.0", ".inetfoo.0", ".inet60.0") and trailing garbage (".inet.0.x")
// return ok=false (#2253). This mirrors pkg/routing.ribInstanceFromName — the
// two MUST stay in lockstep so the commit-time gate and the runtime applier
// agree on what resolves (#2226).
func ribInstanceFromName(ribName string) (string, bool) {
	for _, suffix := range []string{".inet.0", ".inet6.0"} {
		if instance, ok := strings.CutSuffix(ribName, suffix); ok && instance != "" {
			return instance, true
		}
	}
	return "", false
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
			anyGood := false
			for _, raw := range destAddrs {
				ipPart := natCIDRIPPart(raw)
				if ipPart != "" && net.ParseIP(ipPart) != nil {
					anyGood = true
					break
				}
			}
			if !anyGood {
				return fmt.Errorf(
					"destination-nat rule-set %q rule %q: no valid destination-address "+
						"(every match destination-address is malformed: %s); "+
						"the rule would commit but never translate any traffic",
					rs.Name, rule.Name, strings.Join(destAddrs, ", "))
			}
		}
	}
	return nil
}

// dnatProtocolResolvable reports whether a DNAT `match protocol` token is one
// the userspace dataplane can resolve. It is the Go mirror of the Rust
// ip_proto::proto_number SSOT (userspace-dp/src/ip_proto.rs): the DNAT path
// emits the token VERBATIM (no junos-* pre-resolution), and proto_number
// accepts ONLY bare protocol names and a 0-255 number — NOT junos-* aliases
// (those are resolved by the application path, never the raw match-protocol
// path). Normalization (trim + lower-case) matches proto_number exactly, so
// the commit gate and the dataplane agree on the accepted set.
//
// This is deliberately a TIGHTER set than filterProtocolResolvable /
// appid.ProtocolNumber (which add junos-* aliases for the filter/application
// paths): a junos-* token in a DNAT match-protocol would resolve in those
// supersets but be DROPPED by proto_number, so accepting it here would
// re-introduce the #2396 silent drop. Empty ("" = any protocol) is the IP-only
// wildcard and is always resolvable.
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
// drift-guard test that asserts this acceptance set agrees with the Rust
// proto_number SSOT (the two INLINE copies cannot drift silently). TEST seam,
// not a runtime coupling.
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
			if !dnatProtocolResolvable(rule.Match.Protocol) {
				return fmt.Errorf(
					"destination-nat rule-set %q rule %q: match protocol %q is not a "+
						"resolvable protocol (known name or 0-255 number); the rule would "+
						"commit but never translate any traffic",
					rs.Name, rule.Name, rule.Match.Protocol)
			}
		}
	}
	return nil
}

// validateRouteFilterMatchTypesStrict gates the two route-filter match-types
// that the FRR prefix-list backend cannot render losslessly (#2525):
//
//   - "through <prefix2>" has NO FRR equivalent. Junos "through" matches the
//     base prefix, prefix2, and only the prefixes on the direct radix-tree
//     path between them — not every prefix of intermediate length. FRR
//     prefix-lists express only length ranges (ge/le), so any rendering would
//     change the match set. Reject it loudly rather than silently degrade.
//
//   - "prefix-length-range /low-/high" maps to FRR "ge low le high", but only
//     when the bounds are well-formed. Reject a malformed, inverted, out-of-
//     family-range, or below-base range so the operator fixes it instead of
//     getting the pre-#2525 silent open-ended "le maxLen" fall-through.
//
// Strict on commit / commit-check (hard reject so the unsupported / malformed
// match-type is operator-visible); the compiler downgrades this to a warning on
// the tolerant load / peer-sync path (#1960) so an already-persisted or
// peer-synced config still boots — the renderer then skips the offending entry
// (match-nothing, fail-closed). Runs on the fully-compiled *Config.
func validateRouteFilterMatchTypesStrict(cfg *Config) error {
	if cfg == nil || cfg.PolicyOptions.PolicyStatements == nil {
		return nil
	}
	// Deterministic first-error: iterate policy-statements by sorted name.
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ps := cfg.PolicyOptions.PolicyStatements[name]
		if ps == nil {
			continue
		}
		for _, term := range ps.Terms {
			if term == nil {
				continue
			}
			for _, rf := range term.RouteFilters {
				if rf == nil {
					continue
				}
				switch rf.MatchType {
				case "through":
					return fmt.Errorf(
						"policy-statement %q term %q route-filter %q through %q: the "+
							"`through` match-type is not supported by the FRR routing "+
							"backend — it matches a two-prefix containment path that has "+
							"no lossless prefix-list (ge/le) equivalent. Use "+
							"`prefix-length-range /<low>-/<high>`, `upto /<n>`, or "+
							"`orlonger` instead",
						name, term.Name, rf.Prefix, rf.ThroughPrefix)
				case "prefix-length-range":
					if err := validatePrefixLengthRange(rf); err != nil {
						return fmt.Errorf(
							"policy-statement %q term %q route-filter %q prefix-length-range: %v",
							name, term.Name, rf.Prefix, err)
					}
				}
			}
		}
	}
	return nil
}

// validatePrefixLengthRange enforces the semantic constraints on a
// prefix-length-range route-filter (#2525): both bounds parsed (non-zero), the
// per-family max not exceeded, low<=high, and low at least the base prefix
// length (Junos requires the range to be no less specific than the base).
func validatePrefixLengthRange(rf *RouteFilter) error {
	maxLen := 32
	if strings.Contains(rf.Prefix, ":") {
		maxLen = 128
	}
	if rf.RangeLow == 0 || rf.RangeHigh == 0 {
		return fmt.Errorf(
			"malformed range (expected /<low>-/<high> with both lengths in 1..%d, e.g. /16-/24)",
			maxLen)
	}
	if rf.RangeLow > maxLen || rf.RangeHigh > maxLen {
		return fmt.Errorf(
			"range /%d-/%d exceeds the address-family maximum /%d",
			rf.RangeLow, rf.RangeHigh, maxLen)
	}
	if rf.RangeLow > rf.RangeHigh {
		return fmt.Errorf(
			"inverted range /%d-/%d (low must be <= high)",
			rf.RangeLow, rf.RangeHigh)
	}
	// The base prefix length floors the range: the range low bound must be
	// STRICTLY more specific than the base prefix. Junos requires this, and FRR
	// rejects a prefix-list whose `ge` value is not strictly greater than the
	// prefix length ("len < ge-value"). Accepting RangeLow == baseLen would emit
	// `ge baseLen le high` → FRR rejects the line → frr-reload exits non-zero on
	// the whole managed batch → FRR brick (#1880-class). The renderer carries
	// the same guard for the lenient (downgraded-to-warning) path.
	if _, ipnet, err := net.ParseCIDR(rf.Prefix); err == nil {
		baseLen, _ := ipnet.Mask.Size()
		if rf.RangeLow <= baseLen {
			return fmt.Errorf(
				"range low /%d must be more specific than the base prefix /%d "+
					"(low > base; FRR rejects a ge value not strictly greater "+
					"than the prefix length)",
				rf.RangeLow, baseLen)
		}
	}
	return nil
}

// validateNATSourceAddressNameReferencesStrict hard-rejects a source or
// destination NAT rule whose `match source-address-name <name>` names an
// address-book entry not defined under `security address-book` (#2416).
//
// The name is resolved to concrete source prefixes at snapshot-build time
// (appendNATSourceAddressName). A dangling reference contributes no prefix and
// the rule fails closed (matches NOTHING) — safe, but silent: the operator's
// intended source scoping vanishes with no signal. This gate makes the typo
// operator-visible at commit, consistent with the firewall prefix-list and
// policer reference gates.
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
	check := func(natType string, rs *NATRuleSet) error {
		if rs == nil {
			return nil
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.Match.SourceAddressName == "" {
				continue
			}
			if defined(rule.Match.SourceAddressName) {
				continue
			}
			return fmt.Errorf(
				"%s NAT rule-set %q rule %q references undefined "+
					"source-address-name %q (define `security address-book "+
					"address %s` / `address-set %s`, or fix the name — the "+
					"source scope would otherwise be silently lost and the "+
					"rule would match no traffic)",
				natType, rs.Name, rule.Name, rule.Match.SourceAddressName,
				rule.Match.SourceAddressName, rule.Match.SourceAddressName)
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
