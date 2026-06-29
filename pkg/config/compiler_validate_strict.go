package config

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// validateLogEventModeFormatStrict rejects a top-level `security log format`
// that the EVENT-mode writer cannot honor (#3349 follow-up). The top-level
// format leaf is schema-validated to one of {binary, sd-syslog, structured,
// syslog} regardless of mode, but the value feeds two different runtimes:
//
//   - stream mode (remote syslog): honors binary (formatBinaryRecord),
//     structured (formatStructuredMsg), sd-syslog (RFC 5424 envelope in
//     SyslogClient.Send), and the standard RFC 3164 default — all four.
//   - event mode (local file, pkg/logging LocalLogWriter via
//     ringbuf.go ProcessRawEvent local-writer fanout): branches ONLY on
//     `binary`; every other value writes standard text. So `structured`
//     and `sd-syslog` SILENTLY fall back to standard text — the exact
//     silent-config-fallback #3349 exists to eliminate, on the new typed
//     surface.
//
// This is a CROSS-FIELD rule (format validity depends on the sibling mode),
// which the declarative per-leaf SchemaValidate walker cannot express, so it
// lives here as a post-compile pass on cfg.Security.Log. When mode is event,
// only the event-honorable formats are accepted; structured / sd-syslog are
// rejected at commit instead of silently no-opping. Event-mode structured /
// sd-syslog support is a feature gap tracked separately (see the follow-up
// issue cited in docs/config-schema.md); restricting the enum here is the
// fail-closed half.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientLogEventModeFormat) so an already-persisted or
// peer-synced config that an older binary accepted still boots — the runtime
// already falls back to standard text, so a leniently-loaded value is inert
// rather than bricking the load (#1960 / #3261). Commit / commit-check stay
// strict. Mirrors validateLogProfileStreamReferencesStrict.
//
// The event-honorable set MUST stay in sync with the LocalLogWriter fanout in
// pkg/logging/ringbuf.go (binary branch + standard-text default): a value
// allowed here but unhonored there reintroduces the silent fallback.
func validateLogEventModeFormatStrict(cfg *Config) error {
	if cfg == nil || cfg.Security.Log.Mode != "event" {
		return nil
	}
	switch cfg.Security.Log.Format {
	case "", "binary", "syslog":
		// "" / "syslog" => standard RFC 3164 text (what the writer produces
		// and what the operator named); "binary" => binary records. All
		// honored by the event-mode LocalLogWriter.
		return nil
	default:
		return fmt.Errorf("security log format %q is not honored in event mode "+
			"(the local-file writer only emits binary or standard text); use "+
			"`binary` or `syslog`, or switch to `mode stream` for structured / "+
			"sd-syslog output", cfg.Security.Log.Format)
	}
}

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

// validateDynamicAddressFeedServerEndpointStrict hard-rejects a
// `security dynamic-address feed-server <name>` that configures no endpoint —
// neither `url` nor `hostname` (#3300 residual). feeds.Manager.Apply derives
// each server's base URL via resolveBaseURL (feeds.go): explicit `url`, else
// `https://<hostname>`, else the empty string — and an empty base URL makes
// Apply SKIP the whole server (it registers NONE of its feeds, including any
// nested feed-name entries). The endpoint-less server still compiles into
// SecurityConfig.DynamicAddress.FeedServers, so its feed names are
// syntactically "declared", but at runtime no feed exists: an address-name
// bound to one resolves to an empty (match-nothing) address book and a
// feed-backed deny policy silently denies nothing — the same #3300 fail-open
// symptom one layer up, at the feed-server root rather than the binding.
//
// This gate replicates resolveBaseURL's emptiness condition directly on the
// FeedServer config struct (feedServerBaseURLEmpty) rather than importing
// pkg/feeds (pkg/config must not depend on pkg/feeds). resolveBaseURL prefers
// `url` and returns strings.TrimRight(url, "/") BEFORE it ever falls back to
// `hostname`, so a slash-only `url` (e.g. `/`, `//`) trims to "" and the
// server is skipped even when a hostname is also set — feedServerBaseURLEmpty
// mirrors that branch order exactly. Keep in sync with resolveBaseURL.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientDynamicAddressFeedRef, shared with the feed-name
// cross-reference gate) so an already-persisted or peer-synced config carrying
// an endpoint-less server still boots — the runtime already drops the server
// (registers no feed), so any bound address-name is fail-closed match-none
// rather than bricking the load (#1960 / #3261 class). Commit / commit-check
// stay strict. Mirrors validateLogProfileStreamReferencesStrict.
func validateDynamicAddressFeedServerEndpointStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	servers := cfg.Security.DynamicAddress.FeedServers
	if len(servers) == 0 {
		return nil
	}
	// FeedServers is a map (unordered); sort keys so the first-error
	// commit-check message is deterministic across runs.
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fs := servers[name]
		if fs == nil {
			continue
		}
		if feedServerBaseURLEmpty(fs) {
			display := fs.Name
			if display == "" {
				display = name
			}
			return fmt.Errorf("security dynamic-address feed-server %q resolves "+
				"to an empty endpoint (no url or hostname, or a slash-only url) "+
				"so it registers no feeds — any address-name bound to it "+
				"silently matches nothing; set a valid url or hostname",
				display)
		}
	}
	return nil
}

// feedServerBaseURLEmpty reports whether feeds.resolveBaseURL would return ""
// for this feed-server — i.e. feeds.Manager.Apply would SKIP it and register
// none of its feeds. It mirrors resolveBaseURL (pkg/feeds/feeds.go)
// BRANCH-FOR-BRANCH:
//
//	if URL != "":            empty iff strings.TrimRight(URL, "/") == ""
//	else if Hostname != "":  never empty ("https://" + ... is always non-empty)
//	else:                    empty
//
// The URL branch wins outright, so a slash-only `url` (e.g. `/`, `//`) trims to
// "" and the server is skipped EVEN IF a hostname is also configured — the
// fallback is never reached. resolveBaseURL performs no whitespace trimming
// (only strings.TrimRight on "/"), so this does not either. pkg/config cannot
// import pkg/feeds (import cycle); keep this in sync with resolveBaseURL.
func feedServerBaseURLEmpty(fs *FeedServer) bool {
	if fs.URL != "" {
		return strings.TrimRight(fs.URL, "/") == ""
	}
	if fs.Hostname != "" {
		return false
	}
	return true
}

// validateDynamicAddressFeedReferencesStrict hard-rejects a
// `security dynamic-address address-name <addr> profile feed-name <feed>`
// binding whose `<feed>` resolves to no declared feed (#3300). The
// address-name→feed binding is recorded verbatim into
// AddressBinding.FeedNames with no cross-reference against the configured
// feed-servers (compileDynamicAddress in compiler_services.go), and at
// runtime an unknown feed name contributes nothing: feeds.Manager.
// SnapshotForBindings skips a feed it never registered and still publishes
// a non-nil EMPTY prefix set for the binding (feeds.go SnapshotForBindings),
// so the AF_XDP address book gets a book ID that matches nothing
// (fail-closed). The runtime fail-closed posture is correct for "feed
// declared but not yet fetched", but a TYPO in the feed-name is
// indistinguishable from that and arms a silent match-none book: a
// feed-backed deny policy referencing the dynamic-address denies nothing,
// with no commit error. Junos rejects an address-name whose profile
// feed-name does not resolve to a declared feed at commit; this gate
// restores that behavior.
//
// The valid feed-name set mirrors the keys feeds.Manager registers (feeds.go
// Start): a feed-server with per-feed entries contributes each FeedEntry.Name;
// a single-feed server contributes its FeedName, or the server name itself
// when no explicit feed-name is set. This parity is EXACT because
// validateDynamicAddressFeedServerEndpointStrict (run just before this gate)
// rejects any feed-server with no url/hostname — the only servers
// feeds.Manager.Apply silently SKIPS — so every server in the declared set is
// one Apply would actually register. The schema accepts `profile feed-name` as
// a free-form value leaf (schema_security.go), so the undefined-token gate
// (#2008/#2009) does NOT cover a typo here — only this cross-reference does.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientDynamicAddressFeedRef) so an already-persisted config
// (older binaries never validated the reference) or a peer-synced config
// still boots — the runtime is already fail-closed (match-none) for an
// unknown feed, so a leniently-loaded typo denies nothing rather than
// bricking the load (#1960 / #3261 class). Commit / commit-check stay strict
// so the operator's next edit fails loudly. Mirrors
// validateLogProfileStreamReferencesStrict.
func validateDynamicAddressFeedReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	da := cfg.Security.DynamicAddress
	if len(da.AddressBindings) == 0 {
		return nil
	}

	// Build the set of declared feed names exactly as feeds.Manager keys
	// them (pkg/feeds Start): FeedEntries name each feed; a single-feed
	// server keys on FeedName, falling back to the server name.
	declared := make(map[string]bool)
	for _, fs := range da.FeedServers {
		if fs == nil {
			continue
		}
		if len(fs.FeedEntries) > 0 {
			for _, fe := range fs.FeedEntries {
				declared[fe.Name] = true
			}
			continue
		}
		key := fs.FeedName
		if key == "" {
			key = fs.Name
		}
		if key != "" {
			declared[key] = true
		}
	}

	// AddressBindings is a map (unordered); sort keys so the first-error
	// commit-check message is deterministic across runs.
	names := make([]string, 0, len(da.AddressBindings))
	for name := range da.AddressBindings {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ab := da.AddressBindings[name]
		if ab == nil {
			continue
		}
		for _, fn := range ab.FeedNames {
			if fn == "" || declared[fn] {
				continue
			}
			return fmt.Errorf("security dynamic-address address-name %q "+
				"profile references undefined feed-name %q (the binding would "+
				"resolve to an empty address set — a feed-backed policy would "+
				"silently match nothing; declare the feed under a "+
				"dynamic-address feed-server or fix the feed-name)", ab.Name, fn)
		}
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

// validatePolicyCommunityReferencesStrict hard-rejects a policy-statement term
// whose `from community <name>` or `then community delete <name>` references a
// community the config never defines under `policy-options community <name>`
// (#2881).
//
// xpf renders `from community <name>` as the FRR route-map clause
// `match community <name>` and `then community delete <name>` (added in #2848)
// as `set comm-list <name> delete`. Both clauses reference an FRR
// `bgp community-list <name>`, which xpf emits ONLY for a defined
// `policy-options community <name>` (policy_render.go). With no validation an
// undefined name passes commit and breaks at FRR render time: a dangling
// `match community` / `set comm-list ... delete` line is rejected by
// frr-reload, and because a single vtysh -f add-batch exits non-zero on any
// CMD_WARNING_CONFIG_FAILED, the WHOLE reload fails — leaving dynamic routing
// stale, a commit-accepted config the routing daemon cannot load.
//
// Only NAME references are checked. `then community (set|add) <value>` and the
// bare `then community <value>` carry a community VALUE (e.g. 65000:100 /
// no-export), not a community-list reference, so they are not validated here;
// `then community none` carries no argument. Multiple `from community` siblings
// (FromCommunity slice) and a multi-list `then community delete [ a b ]`
// (CommunityDelete slice) are each fully walked.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientPolicyCommunityRef) so an already-persisted or
// peer-synced config carrying the typo still boots (#1960 fail-closed-on-load
// class). Commit / commit-check stay strict. Runs on the fully-compiled
// *Config so the community map is populated regardless of authoring order.
// Mirrors validateRoutingExportReferencesStrict.
func validatePolicyCommunityReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	defined := func(name string) bool {
		if cfg.PolicyOptions.Communities == nil {
			return false
		}
		_, ok := cfg.PolicyOptions.Communities[name]
		return ok
	}

	// Sort policy-statement names for a deterministic first-error message
	// (the typed-config map iteration order is otherwise random).
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, psName := range names {
		ps := cfg.PolicyOptions.PolicyStatements[psName]
		if ps == nil {
			continue
		}
		for _, term := range ps.Terms {
			if term == nil {
				continue
			}
			for _, c := range term.FromCommunity {
				if c == "" || defined(c) {
					continue
				}
				return fmt.Errorf("policy-statement %s term %s `from community %s` "+
					"references undefined community %q — xpf renders no "+
					"`bgp community-list %s`, so the `match community` line would "+
					"fail frr-reload (failing the entire FRR config load); define "+
					"`policy-options community %s` or fix the name",
					psName, term.Name, c, c, c, c)
			}
			for _, c := range term.CommunityDelete {
				if c == "" || defined(c) {
					continue
				}
				return fmt.Errorf("policy-statement %s term %s `then community delete %s` "+
					"references undefined community %q — xpf renders no "+
					"`bgp community-list %s`, so the `set comm-list %s delete` line "+
					"would fail frr-reload (failing the entire FRR config load); "+
					"define `policy-options community %s` or fix the name",
					psName, term.Name, c, c, c, c, c)
			}
		}
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

// validatePolicyMatchApplicationsStrict hard-rejects a security-policy
// `match application <name>` token that resolves to NONE of: a predefined
// junos-* application, a user-defined `applications application <name>`, or a
// user-defined `applications application-set <name>` (#3144). Such a token (a
// typo or an undefined app) was only WARNED at commit
// (compiler_validate_warn.go), yet the userspace capability gate
// (resolveUserspaceApplicationNames in pkg/dataplane/userspace/capabilities.go)
// resolves the SAME name set and returns false for an unknown name →
// expandUserspacePolicyApplications fails → the built rule carries the reserved
// __unsupported__ sentinel term → the dataplane refuses to arm that policy
// (#3261, helper integrity preflight). The operator
// gets a green commit and a silently DISARMED policy engine on the firewall's
// primary allow/deny path — a commit/apply contract split. Failing the
// undefined reference at commit turns the silent disarm into an
// operator-visible error.
//
// Resolution mirrors the runtime gate EXACTLY (ResolveApplication, which checks
// user apps then the predefined table, plus ResolveApplicationSet) so the
// commit gate and the runtime gate cannot diverge. The `any` keyword and the
// empty token are always accepted. Covers both zone-pair and global policies,
// and the multi-value `application [ a b c ]` list — pol.Match.Applications is
// populated from every list value (compiler_security.go reads m.Keys[1:] for
// the collapsed-bracket form and m.Children for the hierarchical form, the same
// accumulation firewallMatchValues performs), so iterating the typed list
// covers each element.
//
// Distinct from #2217 (validateApplicationSetMembersStrict), which rejects a
// DANGLING MEMBER of a DEFINED application-set. A direct policy reference to a
// wholly undefined name is neither an app nor a set, so #2217's
// ExpandApplicationSet walk never sees it — this gate is the one that catches
// it. Composes cleanly: a defined set with a bad member is #2217's error; an
// undefined top-level name is this gate's error.
//
// Strict on commit / commit-check (hard reject). Lenient on load / peer-sync
// (warn so an already-persisted or peer-synced config that an older binary
// accepted still BOOTS — #1960 no-brick; the dataplane independently refuses to
// arm such a policy, so a leniently-loaded bad config is no worse off than
// before, now flagged).
func validatePolicyMatchApplicationsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// appRefError returns nil if the token resolves, or a tailored reject.
	// Resolution mirrors resolveUserspaceApplicationNames
	// (pkg/dataplane/userspace/capabilities.go) EXACTLY so the commit gate and
	// the runtime gate cannot diverge: a name resolves only if it is a
	// predefined / user application OR an application-set that EXPANDS to >= 1
	// member. A defined-but-EMPTY application-set resolves by NAME but expands
	// to zero members → the runtime gate returns false → the built rule carries
	// the __unsupported__ sentinel → the dataplane refuses to arm that policy
	// (#3146 — the same fail-open class this gate kills).
	// #2217's validateApplicationSetMembersStrict `continue`s on an empty set,
	// so nothing else catches it.
	appRefError := func(scope, policyName, name string) error {
		switch name {
		case "", "any":
			return nil
		}
		if _, ok := ResolveApplication(name, cfg.Applications.Applications); ok {
			return nil
		}
		if _, ok := ResolveApplicationSet(name, cfg.Applications.ApplicationSets); ok {
			// A malformed member (ExpandApplicationSet error) is #2217's gate's
			// job and runs first; here a clean expansion to zero members is the
			// empty-set fail-open (#3146).
			expanded, err := ExpandApplicationSet(name, &cfg.Applications)
			if err == nil && len(expanded) == 0 {
				return policyMatchEmptyAppSetError(scope, policyName, name)
			}
			return nil
		}
		return policyMatchApplicationError(scope, policyName, name)
	}
	check := func(scope string, pol *Policy) error {
		if pol == nil {
			return nil
		}
		for _, app := range pol.Match.Applications {
			if err := appRefError(scope, pol.Name, app); err != nil {
				return err
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

// policyMatchApplicationError formats the #3144 undefined-application reject,
// naming the policy scope, the policy, and the unresolved application token.
func policyMatchApplicationError(scope, policyName, app string) error {
	where := fmt.Sprintf("policy %q", policyName)
	if scope != "" {
		where = fmt.Sprintf("%s policy %q", scope, policyName)
	}
	return fmt.Errorf(
		"security policies %s match application %q is not defined "+
			"(no predefined junos-* application, no `applications application "+
			"%q`, and no `applications application-set %q`) — an undefined "+
			"application reference commits but the userspace dataplane then "+
			"REFUSES to arm security policies (commit/apply split, fail-open) "+
			"— define the application/application-set or fix the name (#3144)",
		where, app, app, app)
}

// policyMatchEmptyAppSetError formats the #3146 reject for a policy
// referencing a DEFINED but EMPTY application-set. The set exists by name but
// expands to zero members, so the runtime resolveUserspaceApplicationNames
// returns false (ExpandApplicationSet len==0) and the dataplane refuses to arm
// security policies — the same commit/apply fail-open class as #3144.
func policyMatchEmptyAppSetError(scope, policyName, name string) error {
	where := fmt.Sprintf("policy %q", policyName)
	if scope != "" {
		where = fmt.Sprintf("%s policy %q", scope, policyName)
	}
	return fmt.Errorf(
		"security policies %s match application %q is a defined but EMPTY "+
			"application-set (it expands to zero applications) — the policy "+
			"commits but the userspace dataplane then REFUSES to arm security "+
			"policies (commit/apply split, fail-open) — add at least one "+
			"`applications application-set %q application <name>` member or "+
			"remove the reference (#3146)",
		where, name, name)
}

// policyMatchAddressBookResolves mirrors the runtime address resolver
// resolveUserspaceAddressBookEntry + expandUserspacePolicyAddresses
// (pkg/dataplane/userspace/capabilities.go) for a single address-book NAME
// token. It returns nil when the name fully resolves to >= 1 literal address
// (i.e. the runtime capability gate accepts it), or an error describing the
// FIRST member that does not resolve / the empty expansion that makes the
// gate refuse to arm.
//
// The fail-closed semantics are copied verbatim from the runtime so the commit
// gate and the runtime gate cannot diverge:
//
//   - a defined `address` with a non-empty Value resolves (accumulates one
//     literal); an `address` with an EMPTY value does NOT (the runtime returns
//     false on addr.Value == "").
//   - an `address-set` resolves only if EVERY direct and nested member resolves
//     AND it has at least one member (resolvedAny). A dangling member (a name
//     that is neither a defined address nor a defined set) fails the WHOLE set
//     — the runtime's `if !resolve(member) { return false }`. A defined-but-
//     EMPTY set fails (resolvedAny stays false).
//   - a cycle short-circuits to "resolved" for the inner visit (the runtime's
//     `if seenSets[ref] { return true }`), but a name that expands to ZERO
//     literals (e.g. a pure self-cycle) is still rejected by the outer
//     len(values) == 0 check that expandUserspacePolicyAddresses applies.
//
// `seen` is NOT backtracked (no defer delete), matching the runtime's
// persistent seenSets — this is deliberately distinct from ExpandAddressSet
// (predefined.go), whose visited map backtracks for a different purpose.
func policyMatchAddressBookResolves(ab *AddressBook, name string) error {
	seen := make(map[string]bool)
	count := 0 // literal addresses accumulated (mirrors expanded slice length)
	var firstErr error
	var resolve func(ref string) bool
	resolve = func(ref string) bool {
		if ref == "" {
			if firstErr == nil {
				firstErr = fmt.Errorf("empty member reference")
			}
			return false
		}
		if addr := ab.Addresses[ref]; addr != nil {
			if addr.Value == "" {
				if firstErr == nil {
					firstErr = fmt.Errorf("address %q has no configured prefix "+
						"(it resolves to no usable address)", ref)
				}
				return false
			}
			count++
			return true
		}
		set := ab.AddressSets[ref]
		if set == nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("member %q is not a defined address or "+
					"address-set", ref)
			}
			return false
		}
		if seen[ref] {
			return true // cycle: already counted up the stack (mirror runtime)
		}
		seen[ref] = true
		resolvedAny := false
		for _, m := range set.Addresses {
			if !resolve(m) {
				return false
			}
			resolvedAny = true
		}
		for _, m := range set.AddressSets {
			if !resolve(m) {
				return false
			}
			resolvedAny = true
		}
		if !resolvedAny {
			if firstErr == nil {
				firstErr = fmt.Errorf("address-set %q is empty "+
					"(it expands to no addresses)", ref)
			}
			return false
		}
		return true
	}
	if !resolve(name) {
		if firstErr == nil {
			firstErr = fmt.Errorf("%q resolves to no address", name)
		}
		return firstErr
	}
	if count == 0 {
		// Resolved true but accumulated no literal (e.g. a pure cycle):
		// mirrors expandUserspacePolicyAddresses' len(values) == 0 reject.
		return fmt.Errorf("address-set %q expands to no addresses", name)
	}
	return nil
}

// validatePolicyMatchAddressSetMembersStrict hard-rejects a security-policy
// source-address / destination-address that names a DEFINED address-book entry
// (an address or an address-set) the runtime address resolver cannot fully
// resolve to >= 1 literal address (#3149; also folds the empty-address-set case
// #3147). This is the address-book sibling of #2217
// (validateApplicationSetMembersStrict, the application-set member gate) and the
// #3144/#3146 application gate.
//
// The split with validatePolicyMatchAddressesStrict (#2008): that gate rejects a
// WHOLLY UNDEFINED token (a typo that is neither a defined name, `any`, nor a
// literal CIDR/IP). This gate handles the token that IS a defined book name but
// whose (recursive) members dangle, or that is a defined-but-EMPTY set, or a
// defined address with no prefix. In all of these the runtime
// resolveUserspaceAddressBookEntry returns false / an empty expansion →
// expandUserspacePolicyAddresses fails → the built rule carries the
// __unsupported_address__ sentinel → the dataplane refuses to arm that policy.
// The operator got a
// green commit (only a compiler_validate_warn.go warning) and a silently
// DISARMED allow/deny path — the same commit/apply fail-open class #3144/#3146
// close for applications.
//
// #3147 excluded-inversion safety: the resolver is applied to the SAME
// SourceAddresses / DestinationAddresses lists the runtime gate checks,
// regardless of the *-address-excluded flag. Rejecting an empty / dangling set
// at COMMIT is therefore fail-CLOSED for the excluded case too: an empty
// excluded set can never be committed, so it can never reach the dataplane and
// invert to match-all (the historic fail-open this constraint guards against).
//
// Resolution mirrors resolveUserspaceAddressBookEntry +
// expandUserspacePolicyAddresses EXACTLY (see policyMatchAddressBookResolves),
// so the commit gate and the runtime gate cannot diverge. `any` / `any-ipv4` /
// `any-ipv6` / the empty token and literal CIDR/IP tokens are not book names and
// are passed through (the #2008 gate already covers literals). Covers zone-pair
// + global policies and both source and destination, including the recursive
// address-set-of-address-sets case.
//
// Strict on commit / commit-check (hard reject naming the policy scope, the
// policy, the field, and the unresolved member). Lenient on load / peer-sync
// (warn via opts.lenientPolicyMatchAddressSetMembers so an already-persisted or
// peer-synced config an older binary accepted still BOOTS — #1960; the dataplane
// independently refuses to arm such a policy, so a leniently-loaded bad config
// is no worse off, now flagged). Same doctrine as lenientPolicyMatchApplications.
func validatePolicyMatchAddressSetMembersStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ab := cfg.Security.AddressBook
	if ab == nil {
		return nil
	}
	isDefinedName := func(tok string) bool {
		if _, ok := ab.Addresses[tok]; ok {
			return true
		}
		if _, ok := ab.AddressSets[tok]; ok {
			return true
		}
		return false
	}
	checkToken := func(scope, policyName, field, tok string) error {
		switch tok {
		case "", "any", "any-ipv4", "any-ipv6":
			return nil
		}
		// A wholly-undefined token / literal is the domain of
		// validatePolicyMatchAddressesStrict (#2008); only inspect defined names.
		if !isDefinedName(tok) {
			return nil
		}
		if err := policyMatchAddressBookResolves(ab, tok); err != nil {
			return policyMatchAddressSetError(scope, policyName, field, tok, err)
		}
		return nil
	}
	check := func(scope string, pol *Policy) error {
		if pol == nil {
			return nil
		}
		for _, addr := range pol.Match.SourceAddresses {
			if err := checkToken(scope, pol.Name, "source-address", addr); err != nil {
				return err
			}
		}
		for _, addr := range pol.Match.DestinationAddresses {
			if err := checkToken(scope, pol.Name, "destination-address", addr); err != nil {
				return err
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

// policyMatchAddressSetError formats the #3149 / #3147 reject, naming the policy
// scope, the policy, the match field, the unresolved book name, and the inner
// resolution failure.
func policyMatchAddressSetError(scope, policyName, field, name string, cause error) error {
	where := fmt.Sprintf("policy %q", policyName)
	if scope != "" {
		where = fmt.Sprintf("%s policy %q", scope, policyName)
	}
	return fmt.Errorf(
		"security policies %s match %s %q does not fully resolve: %w — the "+
			"policy commits but the userspace dataplane then REFUSES to arm "+
			"security policies (commit/apply split, fail-open) — define the "+
			"missing address/address-set or fix the member (#3149)",
		where, field, name, cause)
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
	// #3148: a global policy may carry optional from-zone/to-zone match
	// context. An empty context means "all zones" (exempt via the "" special
	// token); a non-empty context that names an undefined zone makes the
	// dataplane fail CLOSED (GlobalZoneScope::Unresolved → matches nothing,
	// userspace-dp/src/policy.rs), so the operator's scoped global policy
	// silently does nothing. Reject it at commit for the same fail-closed
	// parity as the zone-pair case above; the lenient path downgrades to a
	// warning so an already-persisted config still boots.
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		// The reserved self-traffic zone `junos-host` cannot be honored as a
		// global-policy from/to-zone match context: the userspace dataplane
		// does NOT evaluate a zone-scoped global policy on the host-bound
		// (LocalDelivery) path, so a `match from-zone junos-host` / `to-zone
		// junos-host` global would commit but silently never match (a
		// commit-vs-dataplane divergence on a security leaf). Reject it at
		// commit so the two layers agree; real junos-host global-zone-context
		// support is a follow-up. (`any` and the empty token stay exempt =
		// all-zones, matching build_global_zone_scope in policy.rs.)
		if pol.Match.FromZone == "junos-host" {
			return fmt.Errorf(
				"security policies global policy %q match from-zone %q is not supported (a zone-scoped global policy is not evaluated on the host-bound path, so it would silently never match); remove the junos-host match context (#3148)",
				pol.Name, pol.Match.FromZone)
		}
		if pol.Match.ToZone == "junos-host" {
			return fmt.Errorf(
				"security policies global policy %q match to-zone %q is not supported (a zone-scoped global policy is not evaluated on the host-bound path, so it would silently never match); remove the junos-host match context (#3148)",
				pol.Name, pol.Match.ToZone)
		}
		if !defined(pol.Match.FromZone) {
			return fmt.Errorf(
				"security policies global policy %q match from-zone %q references undefined zone; define `set security zones security-zone %s` in the same commit or the global policy is silently never matched (the dataplane fails closed for an unknown match zone)",
				pol.Name, pol.Match.FromZone, pol.Match.FromZone)
		}
		if !defined(pol.Match.ToZone) {
			return fmt.Errorf(
				"security policies global policy %q match to-zone %q references undefined zone; define `set security zones security-zone %s` in the same commit or the global policy is silently never matched (the dataplane fails closed for an unknown match zone)",
				pol.Name, pol.Match.ToZone, pol.Match.ToZone)
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
		scope := fmt.Sprintf("from-zone %s to-zone %s", zpp.FromZone, zpp.ToZone)
		for _, pol := range zpp.Policies {
			if err := check(scope, pol); err != nil {
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

// validatePolicyLogActionStrict hard-rejects a security policy whose `then log`
// names neither `session-init` nor `session-close` (#3060).
//
// Junos requires `then log` to carry at least one of session-init /
// session-close — a bare `then log` is not valid syntax. xpf's schema accepts
// the bare form, and compilePolicy sets pol.Log = &PolicyLog{} for it while
// leaving both SessionInit and SessionClose false. The result is a config that
// REPORTS logging enabled over REST (pkg/api/security.go: `Log: rule.Log !=
// nil`) and gRPC/CLI, yet emits NO session records because both log flags are
// false. On a security appliance this is the worst kind of silent gap: audit
// looks active while producing nothing.
//
// Rejecting the bare form at commit (Junos parity) is the strongest, simplest
// contract: no bare-log config can exist post-commit, which moots the
// REST/gRPC/CLI display divergence entirely (every surface agrees because a
// reported `pol.Log != nil` always carries at least one real session flag).
// Both per-zone-pair policies and global policies are checked. Iteration order
// (cfg.Security.Policies, then GlobalPolicies) is deterministic, so the
// first-reported error is stable.
//
// Strict on the commit / commit-check path (CompileConfig — hard-reject);
// downgraded to a cfg.Warnings entry on the tolerant load / peer-sync paths
// (CompileConfigLenient / CompileConfigForNodeLenient, flag
// lenientPolicyLogAction) so an already-persisted or peer-synced config that an
// older binary accepted still BOOTS (#1960 fail-closed-on-load doctrine). A
// leniently-loaded bare-log policy is harmless: it simply logs nothing (the
// pre-existing behavior), and the warning is the operator's signal to fix it.
// Same doctrine as validatePolicyTerminalActionStrict.
func validatePolicyLogActionStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(scope string, pol *Policy) error {
		if pol == nil || pol.Log == nil {
			return nil
		}
		if pol.Log.SessionInit || pol.Log.SessionClose {
			return nil
		}
		detail := "`then log` requires `session-init` and/or `session-close` " +
			"(a bare `then log` reports logging enabled but emits NO session " +
			"records — Junos requires at least one of session-init/session-close)"
		if scope != "" {
			return fmt.Errorf("%s policy %q: %s", scope, pol.Name, detail)
		}
		return fmt.Errorf("policy %q: %s", pol.Name, detail)
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
// protocol token is not a known name, a RESOLVABLE junos-* alias (one the
// dataplane's appid.ProtocolNumber actually knows — #3150), is MISSING entirely
// (a protocol-less port-only application the matcher cannot represent — #3109),
// or a 0..255 number
// (#2142) — but ONLY for applications that are
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
// It reuses validatePortSpec for ports. For the protocol it uses
// filterProtocolResolvable (the #2124/#2175 appid.ProtocolNumber mirror) rather
// than the lenient validateProtocol: validateProtocol blanket-accepts any
// "junos-" prefix, so a referenced app with `protocol junos-foobar` would commit
// cleanly while the dataplane's appid.ProtocolNumber rejects it, disarming the
// userspace policy capability gate (a commit/apply split — #3150). Using the
// same authority the dataplane uses keeps commit and apply in agreement (the
// dataplane's #2124 capability gate stays the runtime backstop). Iteration is
// sorted by application name so the first-reported error is deterministic across
// runs (Go map order is randomized).
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
		// #3109: a referenced application with NO protocol is unrepresentable by
		// the userspace matcher, which keys every term on a protocol number
		// (appid.ProtocolNumber) plus the port — a port has no meaning without a
		// protocol. compileApplications defaults a protocol-less application to the
		// empty protocol (compiler_applications.go: `protocols = []string{""}`),
		// which the runtime then cannot represent on EITHER side: the Go capability
		// gate (pkg/dataplane/userspace/capabilities.go
		// normalizeUserspaceApplicationProtocol == "" → expandUserspacePolicyApplications
		// ok=false) trips #2124's refuse-to-arm, which sets ForwardingSupported=false
		// for the WHOLE userspace dataplane — one protocol-less app silently disables
		// security-policy enforcement for the entire config (it falls to the kernel
		// slow path, a system-level fail-OPEN); and the Rust snapshot builder rejects
		// the snapshot with SnapshotIntegrityError::UnrepresentableApplicationProtocol
		// (parse_protocol("") => None). Junos requires `protocol` for a usable
		// application, so the Junos-parity fix is to reject the protocol-less spec at
		// COMMIT (the same strict-at-commit / #1960 fail-closed doctrine as the #3150
		// unresolvable-protocol case below and the #2142 malformed-port case above).
		// The blast radius of a NEW config is now one NAMED application caught at
		// commit instead of a silent whole-dataplane disable at apply. On the
		// tolerant load / peer-sync path the call site (compiler.go,
		// lenientApplicationSpecs) downgrades this to a warning so an
		// already-persisted or older-peer-synced config still BOOTS (no-brick).
		//
		// IMPORTANT (truthful caveat, see #3261): the #2124 runtime gate does NOT
		// isolate this to one policy. deriveUserspaceCapabilities
		// (pkg/dataplane/userspace/capabilities.go) is coarse — ANY policy whose
		// application is unrepresentable sets ForwardingSupported=false for the
		// WHOLE userspace dataplane, which disarms userspace forwarding and falls
		// back to the kernel slow path (a system-level fail-OPEN). So on the lenient
		// path a single protocol-less app STILL disables enforcement globally. This
		// strict commit gate is the real fix: it keeps such an app from ever being
		// committed. Per-policy fail-closed isolation of the lenient/HA-sync path is
		// design-sensitive (it conflicts with the #2124 whole-snapshot-reject
		// fail-closed family — term-dropping is fail-open for deny rules) and is
		// tracked separately in #3261.
		if app.Protocol == "" {
			return fmt.Errorf(
				"application %q: no protocol specified; an application referenced by "+
					"a security policy or NAT rule (or any application when "+
					"`services application-identification` is enabled) must set "+
					"`protocol` (e.g. tcp/udp/icmp/icmpv6/gre, a junos-* alias such "+
					"as junos-ping, or a numeric value 0-255). The userspace matcher "+
					"keys on protocol+port and cannot represent a protocol-less "+
					"application — accepting it would disarm the userspace dataplane "+
					"for the whole config (the referencing policy's enforcement falls "+
					"to the kernel slow path)",
				name)
		}
		// #3150: resolve the protocol against the SAME authority the dataplane
		// uses (appid.ProtocolNumber, mirrored by filterProtocolResolvable) — NOT
		// the lenient validateProtocol, which blanket-accepts any "junos-" prefix.
		// validateProtocol would commit `protocol junos-foobar` cleanly while
		// appid.ProtocolNumber rejects it, so the userspace policy capability gate
		// (pkg/dataplane/userspace) then disarms — a commit-succeeds / apply-fails
		// split. filterProtocolResolvable accepts only the concrete junos-* aliases
		// the catalog knows (e.g. junos-ping, junos-tcp-any), real protocol names,
		// and 0..255 numbers, so a referenced app whose protocol the dataplane
		// cannot represent is rejected at commit instead.
		if !filterProtocolResolvable(app.Protocol) {
			return fmt.Errorf(
				"application %q: unknown protocol %q (use a protocol name such as "+
					"tcp/udp/icmp/icmpv6/gre/esp/ah/sctp/ospf, a resolvable junos-* "+
					"alias such as junos-ping/junos-tcp-any, or a numeric value "+
					"0-255 — the dataplane resolves protocols via appid.ProtocolNumber "+
					"and cannot represent an arbitrary junos-* token, so accepting it "+
					"would commit cleanly but fail to arm the referencing policy)",
				name, app.Protocol)
		}
		// #3373: a source-port/destination-port constraint is only meaningful on a
		// port-bearing transport (TCP/UDP/SCTP). The protocol is already known
		// resolvable here (filterProtocolResolvable passed above), so a port on any
		// OTHER protocol — icmp/icmpv6/gre/ospf/esp/ah/vrrp/igmp/pim/ip-in-ip — is a
		// silent operator error: the userspace matcher (userspace-dp src/policy.rs)
		// indexes every application term by protocol number and keys port terms on
		// src_port/dst_port, but a non-port protocol always presents ports of 0, so
		// the term becomes a never-match. For a deny rule that fails OPEN; for a
		// permit rule it fails CLOSED. Junos does not couple ports to non-port
		// protocols, so reject at COMMIT (the same strict-at-commit / #1960
		// fail-closed doctrine as the protocol-less #3109 and unresolvable-protocol
		// #3150 cases above). The call site downgrades this to a warning on the
		// tolerant load / peer-sync path (compiler.go, lenientApplicationSpecs) so an
		// already-persisted or older-peer-synced config still BOOTS.
		if !protocolIsPortBearing(app.Protocol) {
			if port := app.DestinationPort; port != "" {
				return fmt.Errorf(
					"application %q: destination-port %q is set on protocol %q, which "+
						"does not carry L4 ports — source-port/destination-port are valid "+
						"only on tcp/udp (the dataplane keys port terms on the "+
						"packet's ports, which are always 0 for a non-port protocol, so the "+
						"term would never match; remove the port or change the protocol)",
					name, port, app.Protocol)
			}
			if port := app.SourcePort; port != "" {
				return fmt.Errorf(
					"application %q: source-port %q is set on protocol %q, which does "+
						"not carry L4 ports — source-port/destination-port are valid only "+
						"on tcp/udp (the dataplane keys port terms on the packet's "+
						"ports, which are always 0 for a non-port protocol, so the term "+
						"would never match; remove the port or change the protocol)",
					name, port, app.Protocol)
			}
		}
		// #3320: an application inactivity-timeout / timeout that did not parse to
		// a valid integer in [1, 86400] seconds (non-numeric like "thirty", a unit
		// suffix like "30s", a negative, or an out-of-range integer) was SILENTLY
		// dropped by compileApplications (the strconv.Atoi error was ignored),
		// leaving InactivityTimeout at its zero default — which the userspace
		// snapshot serializer treats as "use the global per-protocol timeout"
		// (pkg/dataplane/userspace/capabilities.go clampNonNegU32). The operator's
		// intent to age a sensitive application early is silently lost, with no
		// commit error and no log. compileApplications records the offending raw
		// token in app.UnknownTimeouts (mirroring UnknownActions / UnknownFlexMatch
		// for the other fail-open gates); reject the first one here so the silent
		// drop becomes an operator-visible commit error. Junos rejects a
		// non-integer / out-of-range inactivity-timeout at commit. Strict on the
		// commit / commit-check path; the call site (compiler.go,
		// lenientApplicationSpecs) downgrades this to a warning on the tolerant
		// load / peer-sync path so an already-persisted or older-peer-synced config
		// carrying a bad timeout still BOOTS (#1960 no-brick) — the dataplane
		// already falls back to the global timeout for it.
		if len(app.UnknownTimeouts) > 0 {
			return fmt.Errorf(
				"application %q: invalid inactivity-timeout/timeout %q; must be an "+
					"integer number of seconds in %d..%d (a non-numeric, out-of-range, "+
					"or unit-suffixed value is silently dropped and the application "+
					"falls back to the global per-protocol timeout instead of the "+
					"configured one)",
				name, app.UnknownTimeouts[0], appTimeoutMin, appTimeoutMax)
		}
		// #3348: a malformed icmp-type / icmp-code (non-integer or outside
		// 0..255). The schema range-validates the TOP-LEVEL application leaves at
		// commit-check, but an inline `term` is opaque to the schema walk
		// (children:nil), so a bad inline icmp-type would otherwise be silently
		// dropped by parseICMPTypeCode — leaving the term UNCONSTRAINED (matching
		// EVERY ICMP type), a fail-open widening that is the exact inverse of this
		// issue's fix. compileApplications records the raw token in app.UnknownICMP
		// (mirroring UnknownTimeouts); reject the first one here so the silent
		// widening becomes an operator-visible commit error. Strict on the
		// commit / commit-check path; the call site (compiler.go,
		// lenientApplicationSpecs) downgrades it to a warning on the tolerant
		// load / peer-sync path (#1960 no-brick).
		if len(app.UnknownICMP) > 0 {
			return fmt.Errorf(
				"application %q: invalid icmp-type/icmp-code %q; must be an integer "+
					"in 0..255 (a non-numeric or out-of-range value is silently dropped "+
					"and leaves the application matching EVERY ICMP type instead of the "+
					"intended one)",
				name, app.UnknownICMP[0])
		}
		// #3348: an icmp-type/icmp-code constraint is only meaningful on an
		// ICMP/ICMPv6 protocol. The userspace matcher keys icmp_constraints
		// under the ICMP protocol number (userspace-dp policy.rs), and the
		// pkg/policymatch simulator only consults app.ICMPType when the query
		// protocol is ICMP/ICMPv6 — so a type/code on tcp/udp/gre/... compiles a
		// term that can never match (fail-open for a deny rule, fail-closed for a
		// permit rule), the same #3373 hazard as a port on a non-port protocol.
		// Junos couples icmp-type/code to an ICMP application, so reject at COMMIT
		// (strict-at-commit / #1960 fail-closed). The call site downgrades to a
		// warning on the tolerant load / peer-sync path.
		if (app.ICMPType != nil || app.ICMPCode != nil) && !protocolIsICMPFamily(app.Protocol) {
			return fmt.Errorf(
				"application %q: icmp-type/icmp-code is set on protocol %q, which is "+
					"not an ICMP protocol; an ICMP type/code constraint is valid only on "+
					"icmp/icmpv6 (or the junos-ping/junos-pingv6/junos-icmp-all aliases, "+
					"or protocol number 1/58) — on any other protocol the term can never "+
					"match (remove the constraint or change the protocol)",
				name, app.Protocol)
		}
		// A code with no type leaves the matcher constraining the code while
		// ignoring the type (pkg/policymatch matchSingleApp checks ICMPCode
		// independently of ICMPType), an ambiguous half-constraint Junos does not
		// allow. Require a type whenever a code is set.
		if app.ICMPCode != nil && app.ICMPType == nil {
			return fmt.Errorf(
				"application %q: icmp-code is set without icmp-type; an ICMP code is "+
					"meaningful only together with a type (set icmp-type as well, or "+
					"remove icmp-code)",
				name)
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

// validateFilterMatchValuesStrict hard-rejects any firewall-filter term that
// carries a SYMBOLIC match value (icmp-type / icmp-code name or a named port)
// the compiler could not resolve to a number — #3205 (agy-070 #07/#08).
//
// Before this gate the compiler silently dropped an unresolved symbolic value:
//
//   - an unresolved icmp-type left ICMPTypes empty, which means "match ANY
//     ICMP" — a term meant to narrow to one type (e.g. `then accept` of
//     echo-request only) silently permitted every ICMP type (policy bypass);
//   - an unresolved named port left the port set constrained-but-empty, and a
//     `*-port-except` term then matched ALL ports — it accepted the very port
//     it was meant to exclude (fail open).
//
// compileFilterFrom records each unresolved token on the term (UnknownICMPTypes
// / UnknownICMPCodes / UnknownPorts, mirroring UnknownActions); this gate is
// what makes the refusal operator-visible at commit. The walk is deterministic
// (filters sorted by name, terms in config order). On the tolerant load /
// peer-sync path the caller downgrades the returned error to a warning (#1960
// no-brick); the unresolved token is kept verbatim on the wire so the dataplane
// fails CLOSED (constrained-but-unparseable) independently.
func validateFilterMatchValuesStrict(cfg *Config) error {
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
				if len(term.UnknownICMPTypes) > 0 {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: unknown icmp-type %q "+
							"(use a numeric value 0-255 or a Junos icmp-type name such as "+
							"echo-request/echo-reply/destination-unreachable/time-exceeded)",
						family, name, term.Name, term.UnknownICMPTypes[0])
				}
				if len(term.UnknownICMPCodes) > 0 {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: unknown icmp-code %q "+
							"(use a numeric value 0-255)",
						family, name, term.Name, term.UnknownICMPCodes[0])
				}
				if len(term.UnknownPorts) > 0 {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: unknown port %q "+
							"(use a numeric port 1-65535, a `low-high` range, or a Junos "+
							"service name such as ssh/http/https/domain)",
						family, name, term.Name, term.UnknownPorts[0])
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

// validateFilterFlexMatchStrict hard-rejects any firewall-filter term whose
// `from flexible-match-range` carries a numeric token (byte-offset / bit-length
// / match-value / match-mask) the compiler could not parse or that fell outside
// the representable range — #3203 (agy-070 #02/#03/#04).
//
// Before this gate compileFilterFrom IGNORED the strconv error on each of these
// fields, leaving the offending value at its zero default. A malformed or
// >32-bit match-value silently became 0x0 and the rule then matched value 0
// instead of the intended pattern; an out-of-range bit-length truncated through
// an unchecked uint8() cast (999 -> 231). The commit succeeded cleanly, so the
// operator never saw the misclassification — a security-policy correctness gap.
//
// compileFilterFrom now records each unparseable/out-of-range token on the term
// (UnknownFlexMatch, mirroring UnknownActions); this gate makes the refusal
// operator-visible at commit. The walk is deterministic (filters sorted by name,
// terms in config order). On the tolerant load / peer-sync path the caller
// downgrades the returned error to a warning (#1960 no-brick).
func validateFilterFlexMatchStrict(cfg *Config) error {
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
				if term == nil || len(term.UnknownFlexMatch) == 0 {
					continue
				}
				return fmt.Errorf(
					"firewall family %s filter %q term %q: invalid "+
						"flexible-match-range %q (byte-offset 0-255, bit-length "+
						"1-32, match-value/match-mask a hex value up to "+
						"0xFFFFFFFF, match-start layer-3 or layer-4)",
					family, name, term.Name, term.UnknownFlexMatch[0])
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateFilterPortExceptStrict hard-rejects any firewall-filter term that
// carries BOTH a positive port match and the negated `*-port-except` list in
// the SAME direction — #3297.
//
// Junos treats `source-port` / `destination-port` and their
// `source-port-except` / `destination-port-except` counterparts as mutually
// exclusive match families and rejects a term carrying both at commit. xpf's
// parser, however, lands the positive list on term.SourcePorts /
// term.DestinationPorts and the negated list on term.SourcePortsExcept /
// term.DestPortsExcept (compileFilterFrom), so both can coexist on one term.
//
// The Rust matcher (userspace-dp filter/compiler.rs) resolves the ambiguity
// deterministically as positive-wins (the positive list builds the matcher and
// the except list is ignored). That is fail-safe at runtime — the configured
// positive scope is honored, no traffic leaks — but it silently accepts a
// Junos-invalid term and discards one side of the operator's intent. This gate
// makes the conflict an operator-visible commit error instead.
//
// The walk is deterministic (filters sorted by name, terms in config order).
// On the tolerant load / peer-sync path the caller downgrades the returned
// error to a warning (#1960 no-brick); the dataplane's positive-wins fallback
// keeps that direction fail-safe independently.
func validateFilterPortExceptStrict(cfg *Config) error {
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
				if len(term.SourcePorts) > 0 && len(term.SourcePortsExcept) > 0 {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: `from source-port` and "+
							"`from source-port-except` are mutually exclusive in the same "+
							"term (Junos rejects this; remove one)",
						family, name, term.Name)
				}
				if len(term.DestinationPorts) > 0 && len(term.DestPortsExcept) > 0 {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: `from destination-port` and "+
							"`from destination-port-except` are mutually exclusive in the same "+
							"term (Junos rejects this; remove one)",
						family, name, term.Name)
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

// validateFilterAddressExceptStrict hard-rejects any firewall-filter term that
// mixes a POSITIVE address match (a literal `source-address`/`destination-address`
// OR a non-except `source-prefix-list`/`destination-prefix-list`) with an
// `except` prefix-list in the SAME direction — #3359.
//
// Junos treats a positive address match and an `except` prefix-list as mutually
// exclusive in one term and rejects the combination at commit. xpf's parser,
// however, lands literal addresses on term.SourceAddresses / term.DestAddresses
// and prefix-list references (positive AND except) on term.SourcePrefixLists /
// term.DestPrefixLists (compileFilterFrom), so a positive set and an except set
// can coexist on one direction of one term.
//
// The userspace lowering (pkg/dataplane/userspace/filters.go
// resolvePrefixListAddrs) has no single boolean-inversion representation for the
// mixed shape — one direction would need both a positive set and a negated set.
// Before this gate it FOLDED the except prefixes into the positive match set
// (dropping the `except` modifier) and only emitted a runtime slog.Warn. That
// fold is a silent fail-OPEN on a stateless drop path: for a `discard`/`reject`
// term the operator's `(positive) AND NOT (except)` (or `NOT(except)`) intent
// collapses to a plain positive match, and traffic the operator meant to drop
// via the except carve-out is no longer dropped. For an `accept` term the fold
// is also fail-open in the other direction — it ADMITS the except prefixes the
// operator wrote to exclude. The runtime fold is now changed to positive-wins
// (the except side is ignored, never folded in) so a leniently-loaded term is
// fail-safe; this gate makes the conflict an operator-visible commit error so
// the term is split into faithful per-direction terms instead.
//
// The walk is deterministic (filters sorted by name, terms in config order). On
// the tolerant load / peer-sync path the caller downgrades the returned error to
// a warning (#1960 no-brick); the dataplane's positive-wins fallback keeps that
// direction fail-safe independently. Mirrors validateFilterPortExceptStrict
// (#3297, the port-match sibling of this address-match case).
func validateFilterAddressExceptStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// hasExcept reports whether any prefix-list ref in the direction carries the
	// `except` modifier; hasPositiveRef whether any ref is a plain (non-except)
	// reference.
	hasExcept := func(refs []PrefixListRef) bool {
		for _, ref := range refs {
			if ref.Except {
				return true
			}
		}
		return false
	}
	hasPositiveRef := func(refs []PrefixListRef) bool {
		for _, ref := range refs {
			if !ref.Except {
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
				if term == nil {
					continue
				}
				srcPositive := len(term.SourceAddresses) > 0 || hasPositiveRef(term.SourcePrefixLists)
				if srcPositive && hasExcept(term.SourcePrefixLists) {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: a positive source "+
							"address match (`from source-address` or a non-except "+
							"`from source-prefix-list`) and an `except` "+
							"source-prefix-list are mutually exclusive in the same "+
							"term (Junos rejects this; split into separate terms — the "+
							"mixed shape cannot be enforced faithfully and would "+
							"fail open for discard/reject)",
						family, name, term.Name)
				}
				dstPositive := len(term.DestAddresses) > 0 || hasPositiveRef(term.DestPrefixLists)
				if dstPositive && hasExcept(term.DestPrefixLists) {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: a positive destination "+
							"address match (`from destination-address` or a non-except "+
							"`from destination-prefix-list`) and an `except` "+
							"destination-prefix-list are mutually exclusive in the same "+
							"term (Junos rejects this; split into separate terms — the "+
							"mixed shape cannot be enforced faithfully and would "+
							"fail open for discard/reject)",
						family, name, term.Name)
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

// validateFilterAddressLiteralsStrict hard-rejects any firewall-filter term
// whose literal `from source-address` / `destination-address` carries a MALFORMED
// token or an address of the WRONG family for the filter — #3433 (codex audit 094
// H02/H09).
//
// The firewall-filter address leaves were untyped at commit:
// validateFilterMatchValuesStrict checks only icmp-type/icmp-code/named-ports and
// validateFilterFromMatchStrict only rejects unimplemented `from` leaves, so a
// malformed CIDR (`10.0.0.0/99`) or a wrong-family literal (a v4 CIDR under
// `family inet6`) reached the lowering verbatim. In the kernel lo0 mirror it then
// emitted invalid nft (`ip6 saddr 10.0.0.0/24`, `ip saddr 10.0.0.0/99`) that
// failed the atomic `nft -f -` load — breaking a legitimate commit, or on the
// lenient/peer-sync path leaving the kernel mirror ABSENT while userspace stayed
// armed (a host-protection divergence). The userspace matcher dropped the bad
// token at parse time and, because the direction was still constrained, fell
// CLOSED (match nothing); the kernel mirror could not. This gate makes the bad
// token an operator-visible commit error so the two enforcement paths converge on
// a clean config.
//
// `any` and the empty string are NO-CONSTRAINT placeholders (the userspace
// matcher's addr_is_real / parse_address drop them); they are NOT malformed and
// are accepted here. Prefix-list references are NOT validated for family — a
// prefix-list may legitimately carry both families and the matcher only consults
// the chain's family vector, so a cross-family prefix in a list is harmless (the
// empty-resolution / unresolved cases are covered by #2506 + the existing
// validateFirewallPrefixListReferencesStrict gate).
//
// The walk is deterministic (filters sorted by name, terms in config order). On
// the tolerant load / peer-sync path the caller downgrades the returned error to a
// warning (#1960 no-brick); the lowering's defensive family-filter (#3433,
// nftFamilyAddrs) and the userspace matcher both fail closed for the bad token
// independently, so a leniently-loaded config still enforces fail-safe. Mirrors
// validateFilterFromMatchStrict.
func validateFilterAddressLiteralsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		wantV6 := family == "inet6"
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
				for _, side := range []struct {
					leaf  string
					addrs []string
				}{
					{"source-address", term.SourceAddresses},
					{"destination-address", term.DestAddresses},
				} {
					for _, a := range side.addrs {
						// `any` / empty are no-constraint placeholders, not literals.
						if a == "" || a == "any" {
							continue
						}
						isV6, ok := classifyFilterAddrFamily(a)
						if !ok {
							return fmt.Errorf(
								"firewall family %s filter %q term %q: malformed `from %s` "+
									"value %q (use a valid IPv%s address or CIDR prefix)",
								family, name, term.Name, side.leaf, a,
								map[bool]string{false: "4", true: "6"}[wantV6])
						}
						if isV6 != wantV6 {
							return fmt.Errorf(
								"firewall family %s filter %q term %q: `from %s` value %q is "+
									"the wrong address family (an inet filter takes IPv4, an "+
									"inet6 filter takes IPv6); it would emit unloadable nft and "+
									"match nothing in the dataplane",
								family, name, term.Name, side.leaf, a)
						}
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

// classifyFilterAddrFamily reports whether a literal firewall-filter address is
// IPv6 (isV6) and whether it parsed at all (ok), accepting both a CIDR prefix
// (10.0.0.0/24) and a bare host IP (10.0.0.1 -> /32, ::1 -> /128) — exactly the
// forms the userspace matcher's parse_address accepts.
func classifyFilterAddrFamily(a string) (isV6 bool, ok bool) {
	if pfx, err := netip.ParsePrefix(a); err == nil {
		return pfx.Addr().Is6(), true
	}
	if ip, err := netip.ParseAddr(a); err == nil {
		return ip.Is6(), true
	}
	return false, false
}

// validateFilterFromMatchStrict hard-rejects any firewall-filter term whose
// `from` block carries a match leaf the dataplane does NOT enforce — #3307.
//
// The schema gate is opt-in (schema_walk.go: an unknown keyword resolves to a
// nil schema child and returns no error), and compileFilterFrom's switch had no
// default arm, so a `from` leaf the matcher does not implement (ttl,
// source-mac-address, ip-options, fragment-offset, hop-limit, ...) committed
// cleanly and was silently DROPPED from the compiled term. The resulting term
// then enforced a BROADER match than the operator authored: a less-constrained
// `accept` term permits MORE than intended (fail open) and a less-constrained
// `discard`/`reject` term drops MORE than intended (over-drop). The operator
// saw neither a commit error nor an apply error — a vSRX/SRX-imported filter
// could carry a supported-looking but unimplemented match condition and enforce
// silently-wrong.
//
// The enforced set is EXACTLY the compileFilterFrom switch cases: every one
// maps to a wire field the snapshot builder emits (pkg/dataplane/userspace/
// filters.go) and the Rust matcher evaluates (userspace-dp/src/filter/engine).
// `next-header` is IN that enforced set — it is the IPv6 alias for `protocol`
// (compileFilterFrom routes it to term.Protocols), so it is NOT one of the
// rejected unenforced leaves despite not having its own typed field.
// compileFilterFrom's default arm records every other leaf on the term
// (UnknownFrom, mirroring UnknownActions / UnknownFlexMatch); this gate makes
// the refusal operator-visible at commit. No NEW matching is implemented — the
// unsupported leaf is rejected, which is the fail-closed-correct outcome (a
// constraint is never silently dropped). The walk is deterministic (filters
// sorted by name, terms in config order). On the tolerant load / peer-sync path
// the caller downgrades the returned error to a warning (#1960 no-brick); the
// dataplane never represented the leaf, so a leniently-loaded term keeps
// matching without that constraint independently — but the operator never
// reaches that state through a commit. Mirrors validateFilterActionsStrict.
func validateFilterFromMatchStrict(cfg *Config) error {
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
				if term == nil || len(term.UnknownFrom) == 0 {
					continue
				}
				return fmt.Errorf(
					"firewall family %s filter %q term %q: `from %s` is not enforced "+
						"by the dataplane (the constraint would be silently dropped, "+
						"so the term would match more broadly than authored — an "+
						"accept over-permits, a discard/reject over-drops); remove it "+
						"or use a supported match such as source-address/"+
						"destination-address/protocol/next-header/source-port/"+
						"destination-port/dscp/traffic-class/icmp-type/icmp-code/"+
						"tcp-flags/is-fragment/flexible-match-range",
					family, name, term.Name, term.UnknownFrom[0])
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateFilterRoutingInstanceConflictStrict hard-rejects a firewall-filter
// term that co-locates `then routing-instance <x>` with a terminating
// `then discard` / `then reject` — #3308.
//
// Such a term is contradictory: it asks the dataplane to BOTH route the packet
// via the named instance AND drop/reject it. There was no commit-time
// mutual-exclusion gate, and on the PBR runtime path the deny/reject was reduced
// to a LOG-ONLY event — ingress_route_table_override (userspace-dp/src/afxdp/
// forwarding/mod.rs) logs routing_result.action (the discard/reject) and then
// UNCONDITIONALLY returns the routing-table string, so the packet is still
// forwarded through <x>.inet.0 / <x>.inet6.0. The audit/syslog stream records
// the packet as DENY/REJECT while it was actually routed — worse than a syntax
// gap: the audit trail lies and the security intent is defeated (fail-open PBR).
//
// The conflict is on the typed fields term.RoutingInstance (the
// `then routing-instance` value) and term.Action ("discard" / "reject", set by
// compileFilterThen). A routing-instance term with `then accept` (or no terminal
// action) is the legitimate filter-based-forwarding case and is NOT rejected.
//
// The walk is deterministic (filters sorted by name, terms in config order). On
// the tolerant load / peer-sync path the caller downgrades the returned error to
// a warning (#1960 no-brick); the runtime already routes-and-mislogs such a term
// independently, but the operator never reaches that state through a commit.
// Mirrors validateFilterPortExceptStrict.
func validateFilterRoutingInstanceConflictStrict(cfg *Config) error {
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
				if term == nil || term.RoutingInstance == "" {
					continue
				}
				if term.Action == "discard" || term.Action == "reject" {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: `then routing-instance "+
							"%s` and `then %s` are mutually exclusive in the same term — "+
							"the dataplane would still route the packet via the named "+
							"instance while logging it as denied (the audit trail would "+
							"lie); keep only the routing-instance or only the discard/"+
							"reject",
						family, name, term.Name, term.RoutingInstance, term.Action)
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

// validateFilterDSCPStrict hard-rejects a firewall-filter term whose
// `from dscp` / `from traffic-class` MATCH token or `then dscp` /
// `then traffic-class` REWRITE token is neither a known DSCP code-point name nor
// an integer in 0..63 — #3309.
//
// Before this gate the compiler appended the raw token to term.DSCPs /
// term.DSCPRewrite with no validation, and the snapshot builder
// (pkg/dataplane/userspace/filters.go) emitted only a known name or a numeric
// 0..63 and SILENTLY DROPPED everything else. A dropped `from dscp` value left
// the term with NO DSCP constraint — it then matched ALL DSCPs (a policy
// widening: `from dscp not-a-code then accept` becomes an unconstrained accept;
// `from dscp 64 then discard` drops broader traffic than intended). A dropped
// `then dscp` rewrite silently did nothing. There was no commit-time DSCP /
// traffic-class token validation — the same silent fail-open class as #3205's
// icmp/port unresolved-token gate, but DSCP was uncovered.
//
// The valid name set is filterDSCPResolvable, which INLINE-mirrors
// dataplane.DSCPValues (the snapshot builder's table) plus the numeric 0..63
// range it accepts. pkg/config cannot import pkg/dataplane (import cycle:
// pkg/dataplane imports pkg/config), so the name set is duplicated and pinned by
// a drift-guard test (TestFilterDSCPResolvableMatchesDSCPValues) via the
// exported FilterDSCPResolvable accessor — the same arrangement as
// filterProtocolResolvable / appid.ProtocolNumber. Both `dscp` and
// `traffic-class` (the IPv6 spelling) compile to the same fields and share the
// same 0..63 / code-point-name range, so one check covers both.
//
// The walk is deterministic (filters sorted by name, terms in config order). On
// the tolerant load / peer-sync path the caller downgrades the returned error to
// a warning (#1960 no-brick); the snapshot builder drops the bad token
// independently (a leniently-loaded match widens, a rewrite no-ops) — but the
// operator never reaches that state through a commit. Mirrors
// validateFilterMatchValuesStrict.
func validateFilterDSCPStrict(cfg *Config) error {
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
				for _, d := range term.DSCPs {
					if d == "" || filterDSCPResolvable(d) {
						continue
					}
					return fmt.Errorf(
						"firewall family %s filter %q term %q: unknown `from` dscp/"+
							"traffic-class value %q (use a code-point name such as "+
							"be/ef/af11-af43/cs0-cs7 or a number 0-63) — an unresolved "+
							"value is silently dropped, leaving the term matching ALL "+
							"DSCPs",
						family, name, term.Name, d)
				}
				if r := term.DSCPRewrite; r != "" && !filterDSCPResolvable(r) {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: unknown `then` dscp/"+
							"traffic-class rewrite value %q (use a code-point name such "+
							"as be/ef/af11-af43/cs0-cs7 or a number 0-63) — an unresolved "+
							"value is silently dropped, so the rewrite never happens",
						family, name, term.Name, r)
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

// filterDSCPNames INLINE-mirrors the KEY set of dataplane.DSCPValues
// (pkg/dataplane/types.go) — the code-point names the snapshot builder
// (pkg/dataplane/userspace/filters.go) resolves for a firewall-filter dscp /
// traffic-class match or rewrite. pkg/config cannot import pkg/dataplane (import
// cycle), so the names are duplicated here and pinned to the SSOT by the
// drift-guard test TestFilterDSCPResolvableMatchesDSCPValues via the exported
// FilterDSCPResolvable accessor. Keep in sync with dataplane.DSCPValues.
var filterDSCPNames = map[string]bool{
	"ef":   true,
	"af11": true, "af12": true, "af13": true,
	"af21": true, "af22": true, "af23": true,
	"af31": true, "af32": true, "af33": true,
	"af41": true, "af42": true, "af43": true,
	"cs0": true, "cs1": true, "cs2": true, "cs3": true,
	"cs4": true, "cs5": true, "cs6": true, "cs7": true,
	"be": true,
}

// filterDSCPResolvable reports whether a firewall-filter dscp / traffic-class
// token (match or rewrite) is representable: a known code-point name
// (case-insensitive, mirroring filters.go's strings.ToLower lookup) or an
// integer in 0..63 (the 6-bit DSCP field). It mirrors the snapshot builder's
// emit condition branch-for-branch so commit and emission agree on what
// resolves. Keep in sync with pkg/dataplane/userspace/filters.go.
func filterDSCPResolvable(token string) bool {
	if filterDSCPNames[strings.ToLower(token)] {
		return true
	}
	if v, err := strconv.Atoi(token); err == nil && v >= 0 && v <= 63 {
		return true
	}
	return false
}

// FilterDSCPResolvable exposes filterDSCPResolvable for the drift-guard test
// TestFilterDSCPResolvableMatchesDSCPValues, which asserts this acceptance set
// agrees with dataplane.DSCPValues + the snapshot builder's 0..63 numeric range
// so the INLINE-duplicated table cannot drift from the SSOT silently. It is a
// TEST seam, not a runtime coupling — production code uses the unexported
// filterDSCPResolvable directly.
func FilterDSCPResolvable(token string) bool {
	return filterDSCPResolvable(token)
}

// FilterDSCPNames exposes the config-side code-point NAME set (the keys of
// filterDSCPNames) for the BIDIRECTIONAL drift-guard test
// TestFilterDSCPResolvableMatchesDSCPValues. The forward direction (every
// dataplane.DSCPValues key is accepted here) catches the config mirror missing a
// name; this accessor lets the test assert the inverse — every name the config
// mirror accepts is STILL present in dataplane.DSCPValues — so a name DROPPED
// from the dataplane SSOT (which the snapshot builder would then silently fail to
// emit) cannot leave a stale accept here. TEST seam only.
func FilterDSCPNames() []string {
	names := make([]string, 0, len(filterDSCPNames))
	for name := range filterDSCPNames {
		names = append(names, name)
	}
	return names
}

// filterProtocolResolvable reports whether a `from protocol <token>` is
// representable: it INLINE-mirrors the acceptance set of
// appid.ProtocolNumber's ok==true result (the #2124/#2175 SSOT). pkg/config
// cannot import pkg/appid (import cycle: pkg/appid imports pkg/config), so the
// known-name set is duplicated here and pinned by the pkg/appid drift-guard
// test TestFilterProtocolResolvableMatchesProtocolNumber via the exported
// FilterProtocolResolvable accessor.
//
// The acceptance set is intentionally TIGHTER than validateProtocol (the
// lenient validator used by ValidateConfig's warning surface): validateProtocol
// blanket-accepts ANY "junos-" prefix, but appid.ProtocolNumber only resolves
// the specific junos-* aliases below, so an unknown "junos-foobar" must be
// rejected here to stay consistent with the dataplane SSOT — otherwise commit
// would pass while the swallowed dataplane gate dropped the constraint. Since
// #3150, validateApplicationSpecsStrict also resolves an application's own
// `protocol` leaf through THIS helper (not validateProtocol) for the same
// reason — the broad junos-* accept there caused a commit/apply split.
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

// protocolIsPortBearing reports whether a protocol token names a transport for
// which THIS dataplane actually extracts L4 ports — i.e. a protocol for which a
// source-port/destination-port constraint is enforceable. The authoritative set
// is the dataplane's own port-extraction predicate, NOT a name→number resolver:
//
//   - userspace-dp/src/ip_proto.rs `has_l4_ports(protocol)` == TCP | UDP, and
//   - userspace-dp/src/afxdp/frame/inspect.rs `parse_flow_ports` reads port
//     bytes only for TCP | UDP (SCTP and everything else fall through to None).
//
// So ONLY TCP (6) and UDP (17) carry ports the dataplane reads. ICMP/ICMPv6,
// GRE, OSPF, ESP, AH, VRRP, IGMP, PIM, IP-in-IP — and crucially SCTP (132) —
// do not: SCTP HAS ports on the wire, but this dataplane deliberately never
// extracts or rewrites them (CRC32c checksum, see the ip_proto.rs has_l4_ports
// comment), so an SCTP packet still presents dst_port/src_port = 0 to the
// matcher. policy.rs (`PortMatcher::lookup` / `matches`) indexes every
// application term by protocol number and keys port terms on those extracted
// ports; for any protocol outside the extraction set a port-constrained term
// becomes a NEVER-MATCH — fail-open for a deny rule, fail-closed for a permit
// rule (the #3373 hole). Rejecting a port on such a protocol at commit is the
// fail-closed-correct outcome: the dataplane cannot enforce the constraint, so
// refuse it rather than silently compile a term that never matches.
//
// This subset is replicated inline because appid cannot be imported here
// (pkg/appid imports pkg/config — the same import-cycle constraint that forces
// filterProtocolResolvable to be duplicated). The
// TestProtocolIsPortBearingMatchesDataplaneExtraction drift-guard pins it to the
// ip_proto.rs has_l4_ports SSOT (TCP/UDP).
func protocolIsPortBearing(token string) bool {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "tcp", "junos-tcp-any",
		"udp", "junos-udp-any":
		return true
	default:
		// Numeric protocol number form: only 6 (TCP) and 17 (UDP). Note 132
		// (SCTP) is intentionally absent — this dataplane does not extract SCTP
		// ports (ip_proto.rs has_l4_ports).
		if n, err := strconv.Atoi(strings.TrimSpace(token)); err == nil {
			return n == 6 || n == 17
		}
		return false
	}
}

// protocolIsICMPFamily reports whether a protocol token names ICMP or ICMPv6 —
// the only protocols on which an application `icmp-type`/`icmp-code` constraint
// is enforceable (#3348). It recognizes the canonical names, the junos-*
// aliases that resolve to ICMP/ICMPv6 (including junos-ping/junos-pingv6, which
// carry an implicit echo type), and the numeric protocol numbers 1 (ICMP) and
// 58 (ICMPv6). The set mirrors the ICMP arm of filterProtocolResolvable.
func protocolIsICMPFamily(token string) bool {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "icmp", "junos-icmp-all", "junos-ping",
		"icmpv6", "icmp6", "junos-icmp6-all", "junos-pingv6":
		return true
	default:
		if n, err := strconv.Atoi(strings.TrimSpace(token)); err == nil {
			return n == 1 || n == 58
		}
		return false
	}
}

// ProtocolIsPortBearing exposes protocolIsPortBearing for the pkg/appid
// drift-guard test so the inline port-bearing subset cannot silently drift from
// the dataplane's port-extraction set (ip_proto.rs has_l4_ports). Test seam only
// — production code uses the unexported form directly.
func ProtocolIsPortBearing(token string) bool {
	return protocolIsPortBearing(token)
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
// destination NAT rule whose `match source-address-name <name>` OR `match
// destination-address-name <name>` (#3229) names an address-book entry not
// defined under `security address-book` (#2416).
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
			if rule == nil {
				continue
			}
			if rule.Match.SourceAddressName != "" && !defined(rule.Match.SourceAddressName) {
				return fmt.Errorf(
					"%s NAT rule-set %q rule %q references undefined "+
						"source-address-name %q (define `security address-book "+
						"address %s` / `address-set %s`, or fix the name — the "+
						"source scope would otherwise be silently lost and the "+
						"rule would match no traffic)",
					natType, rs.Name, rule.Name, rule.Match.SourceAddressName,
					rule.Match.SourceAddressName, rule.Match.SourceAddressName)
			}
			// #3229: destination-address-name is the destination twin of
			// source-address-name and resolves through the same address-book
			// expander (appendNATDestinationAddressName). A dangling reference
			// installs no destination = the rule matches nothing (fail-closed
			// but silent); gate it here so the typo is operator-visible at
			// commit, exactly like the source name above.
			if rule.Match.DestinationAddressName != "" && !defined(rule.Match.DestinationAddressName) {
				return fmt.Errorf(
					"%s NAT rule-set %q rule %q references undefined "+
						"destination-address-name %q (define `security address-book "+
						"address %s` / `address-set %s`, or fix the name — the "+
						"destination scope would otherwise be silently lost and the "+
						"rule would match no traffic)",
					natType, rs.Name, rule.Name, rule.Match.DestinationAddressName,
					rule.Match.DestinationAddressName, rule.Match.DestinationAddressName)
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
		if zone == nil || zone.HostInboundTraffic == nil {
			continue
		}
		for _, svc := range zone.HostInboundTraffic.SystemServices {
			if !KnownHostInboundSystemServices[svc] {
				return fmt.Errorf(
					"security zone %q host-inbound-traffic system-services %q "+
						"is not a recognized system-service; an unknown token "+
						"commits but enforces inconsistently (kernel nft path vs "+
						"Rust dataplane disagree) — fix the typo or remove it",
					name, svc)
			}
		}
		for _, proto := range zone.HostInboundTraffic.Protocols {
			if !KnownHostInboundProtocols[proto] {
				return fmt.Errorf(
					"security zone %q host-inbound-traffic protocols %q is not a "+
						"recognized protocol; an unknown token commits but "+
						"enforces inconsistently (kernel nft path vs Rust "+
						"dataplane disagree) — fix the typo or remove it",
					name, proto)
			}
		}
	}
	return nil
}

// validateAddressBookEntryNamesStrict (#3061) hard-rejects a `/` character in
// any address-book entry NAME — a global `address`/`address-set` name, a
// zone-local `address`/`address-set` name — or any security-zone NAME. Junos
// object-naming rules disallow `/` in such identifiers, but the xpf lexer
// permits `/` in an identifier token (it is needed for IP-literal values like
// 10.0.0.0/24), and no other validator rejected it.
//
// This is load-bearing for the zone-local address-book fold
// (resolveZoneLocalAddressBooks): the fold mints synthetic global names of the
// form zone-local/<zone>/<name>. If an operator could type a name containing
// `/` (e.g. a global address literally named zone-local/trust/web-server),
// that name could collide with a synthetic name and be silently clobbered by
// the fold — wrong policy address resolution with no commit error. Rejecting
// `/` in every operator-typed name makes the synthetic `zone-local/...`
// namespace collision-proof.
//
// IMPORTANT: only the NAME token is checked, never an address VALUE/prefix —
// `address web-server 10.0.0.0/24` is fine (the name is web-server; the
// 10.0.0.0/24 prefix is the value, not validated here).
//
// MUST run on the PRISTINE global book, i.e. BEFORE resolveZoneLocalAddressBooks
// injects the `/`-bearing synthetic names; the caller enforces that ordering.
func validateAddressBookEntryNamesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	checkName := func(kind, name string) error {
		if strings.Contains(name, "/") {
			return fmt.Errorf(
				"%s name %q must not contain '/'; '/' is reserved for "+
					"address prefixes and for the internal zone-local "+
					"address-book namespace — rename the object", kind, name)
		}
		return nil
	}
	checkBook := func(kind string, ab *AddressBook) error {
		if ab == nil {
			return nil
		}
		names := make([]string, 0, len(ab.Addresses)+len(ab.AddressSets))
		for n := range ab.Addresses {
			names = append(names, n)
		}
		for n := range ab.AddressSets {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if err := checkName(kind, n); err != nil {
				return err
			}
		}
		return nil
	}

	if err := checkBook("address-book entry", cfg.Security.AddressBook); err != nil {
		return err
	}

	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for z := range cfg.Security.Zones {
		zoneNames = append(zoneNames, z)
	}
	sort.Strings(zoneNames)
	for _, z := range zoneNames {
		if err := checkName("security-zone", z); err != nil {
			return err
		}
		zone := cfg.Security.Zones[z]
		if zone == nil {
			continue
		}
		if err := checkBook(fmt.Sprintf("security-zone %q address-book entry", z), zone.AddressBook); err != nil {
			return err
		}
	}
	return nil
}
