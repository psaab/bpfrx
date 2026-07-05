package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

// sortedPoolNames returns the keys of a NAT pool map in deterministic sorted
// order, so advisory / warning messages that enumerate pools are stable across
// compiles (Go map iteration order is randomized). Used by the #4291/#4292
// accepted-only NAT advisories.
func sortedPoolNames(pools map[string]*NATPool) []string {
	if len(pools) == 0 {
		return nil
	}
	names := make([]string, 0, len(pools))
	for name := range pools {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ValidateConfig performs non-fatal validation on a compiled config.
// Returns warnings for unresolved references and operator-visible
// compatibility/deprecation conditions.
func ValidateConfig(cfg *Config) []string {
	var warnings []string

	// Note (#1476): the previous "ebpf is deprecated" warning was
	// removed because `validateDataplaneTypeStrict` now hard-rejects
	// `dataplane-type ebpf` at commit time with
	// `ErrEBPFDataplaneRetired`. ValidateConfig is never reached for
	// EBPF-typed configs after that gate; keeping the warning here
	// would be dead code.

	// #653: when `services application-identification` is enabled,
	// emit a one-line warning at commit time so operators see what
	// the knob actually does on xpf vs Junos vSRX. The runtime is
	// port + protocol matching only — there is NO L7 DPI / signature
	// engine. See `show services application-identification status`
	// and docs/services-application-identification.md for the full
	// contract.
	if cfg.Services.ApplicationIdentification {
		warnings = append(warnings,
			"services application-identification is enabled, but xpf "+
				"AppID is port+protocol catalog matching only — no L7 "+
				"DPI / signature engine. Run `show services "+
				"application-identification status` for the contract; "+
				"see docs/services-application-identification.md.")
	}

	if userspaceSynCookieProtectionActive(cfg) &&
		(cfg.System.RootAuthentication == nil ||
			cfg.System.RootAuthentication.EncryptedPassword == "") {
		warnings = append(warnings,
			"active userspace-dp SYN-cookie screen profiles require "+
				"system root-authentication encrypted-password material "+
				"for the userspace cookie key; the userspace dataplane "+
				"fails closed until it is set. Legacy eBPF SYN-cookie "+
				"handling uses kernel helpers and is not affected by "+
				"this warning.")
	}

	// #1944 §5.8: warn when a configured login user has no usable auth
	// method — no ssh-* keys AND no usable encrypted-password (absent, or
	// a bare lock sentinel which only locks the account). Mirrors the
	// root-auth warning style above; directly addresses the "non-root
	// operator cannot log in" bug class this issue closes.
	if cfg.System.Login != nil {
		for _, u := range cfg.System.Login.Users {
			if u == nil || u.Name == "" || u.Name == "root" {
				continue
			}
			// A usable password is a non-empty value that is neither a bare
			// lock sentinel ("*"/"!"/"!!") NOR a locked-but-restorable form
			// (any value beginning with "!", e.g. "!$6$salt$hash"). A
			// leading "!" means the account cannot password-login until it
			// is unlocked, so it does not count (Codex #1944 r1 Low).
			pw := u.EncryptedPassword.Reveal()
			usablePassword := pw != "" && pw != "*" && !strings.HasPrefix(pw, "!")
			if len(u.SSHKeys) == 0 && !usablePassword {
				warnings = append(warnings, fmt.Sprintf(
					"login user %s has no usable authentication method: no "+
						"ssh keys and no encrypted-password (a bare lock "+
						"sentinel does not count) — this account cannot log "+
						"in. Set `authentication encrypted-password` (hash "+
						"from `openssl passwd -6`) or an ssh key.", u.Name))
			}
		}
	}

	// Collect valid zone names
	zones := make(map[string]bool)
	for name := range cfg.Security.Zones {
		zones[name] = true
	}

	// Collect valid address-book entries (Addresses + AddressSets). Used by the
	// address-set member validation below, which deliberately does NOT accept a
	// dynamic-address feed binding as a set member (feed-in-set is enforced on
	// the dataplane set-row merge, not strict-accepted — #3294).
	addrs := make(map[string]bool)
	if ab := cfg.Security.AddressBook; ab != nil {
		for name := range ab.Addresses {
			addrs[name] = true
		}
		for name := range ab.AddressSets {
			addrs[name] = true
		}
	}

	// #3958: a policy source/destination-address reference is valid in several
	// forms that are NOT plain address-book names — the `any`/`any-ipv4`/
	// `any-ipv6` wildcards, a literal IPv4/IPv6 address or CIDR, and a
	// dynamic-address feed binding name. The previous warn check only excluded
	// `any` and address-book entries, so it emitted a false "not in
	// address-book" warning for every literal / any-ipv4 / any-ipv6 / feed
	// reference in a perfectly valid policy — alarm fatigue that trains
	// operators to ignore validation warnings. Mirror the strict gate
	// (validatePolicyMatchAddressesStrict, #2008/#3294) EXACTLY via the shared
	// policyMatchAddressTokenRecognized predicate so the warn pass and the
	// strict path cannot diverge; only a token recognized by NONE of the valid
	// forms — a genuinely undefined reference — still warns.
	policyAddrRefs := policyMatchNamedAddressRefs(cfg)

	// Validate application port specs and protocols
	for name, app := range cfg.Applications.Applications {
		if app == nil { // #3494: tolerant/HA-sync path may carry a nil application
			continue
		}
		if err := validatePortSpec(app.DestinationPort); err != nil {
			warnings = append(warnings, fmt.Sprintf("application %s: destination-port: %v", name, err))
		}
		if err := validatePortSpec(app.SourcePort); err != nil {
			warnings = append(warnings, fmt.Sprintf("application %s: source-port: %v", name, err))
		}
		if app.Protocol != "" {
			if err := validateProtocol(app.Protocol); err != nil {
				warnings = append(warnings, fmt.Sprintf("application %s: %v", name, err))
			}
		}
	}

	// Validate policies. Exempt the reserved special-zone tokens (`any`,
	// `junos-host`, the empty token) via the SAME policyZoneSpecialTokens set
	// the strict gate (validatePolicyZoneReferencesStrict, #2401) uses — a
	// single source of truth so a config that legitimately references
	// `junos-host` (or carries an empty token) does not draw a spurious
	// "zone not defined" warning while the strict path correctly accepts it.
	policyZoneDefined := func(zone string) bool {
		if _, special := policyZoneSpecialTokens[zone]; special {
			return true
		}
		return zones[zone]
	}
	for _, zpp := range cfg.Security.Policies {
		// #3494: the tolerant / HA-sync config path (#3474) can leave a nil
		// zone-pair set (Policies is []*ZonePairPolicies); skip it like the
		// runtime walker (pkg/dataplane/userspace/policies.go) does rather
		// than panicking on zpp.FromZone while generating warnings.
		if zpp == nil {
			continue
		}
		if !policyZoneDefined(zpp.FromZone) {
			warnings = append(warnings, fmt.Sprintf(
				"policy from-zone %q: zone not defined", zpp.FromZone))
		}
		if !policyZoneDefined(zpp.ToZone) {
			warnings = append(warnings, fmt.Sprintf(
				"policy to-zone %q: zone not defined", zpp.ToZone))
		}
		for _, p := range zpp.Policies {
			// #3494: skip a nil rule (Policies is []*Policy) like the
			// runtime walker does, mirroring the guards already present at
			// lines ~813/1084, rather than dereferencing p.Match.
			if p == nil {
				continue
			}
			for _, addr := range p.Match.SourceAddresses {
				if !policyMatchAddressTokenRecognized(addr, policyAddrRefs) {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: source-address %q not in address-book", p.Name, addr))
				}
			}
			for _, addr := range p.Match.DestinationAddresses {
				if !policyMatchAddressTokenRecognized(addr, policyAddrRefs) {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: destination-address %q not in address-book", p.Name, addr))
				}
			}
			// An undefined `match application` reference is no longer
			// warned here: validatePolicyMatchApplicationsStrict (#3144)
			// hard-rejects it at commit and emits the warning on the
			// tolerant load / peer-sync path. Resolving it here too (with a
			// narrower 24-entry builtin list) produced a duplicate warning
			// and a false positive for predefined apps outside that list
			// (e.g. junos-pingv6, junos-tcp-any).
		}
	}

	// Validate NAT zone references
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil { // #3494: tolerant/HA-sync path may carry a nil rule-set
			continue
		}
		if rs.FromZone != "" && !zones[rs.FromZone] {
			warnings = append(warnings, fmt.Sprintf(
				"source-nat ruleset %q: from-zone %q not defined", rs.Name, rs.FromZone))
		}
		if rs.ToZone != "" && !zones[rs.ToZone] {
			warnings = append(warnings, fmt.Sprintf(
				"source-nat ruleset %q: to-zone %q not defined", rs.Name, rs.ToZone))
		}
	}
	// Static NAT rule-sets carry a `from zone` scope that the dataplane
	// enforces on the inbound (DNAT) direction (static_nat.rs match_dnat:
	// the entry is skipped unless its from_zone matches the ingress zone
	// name exactly). A typo'd or undefined zone therefore yields a rule
	// that silently never matches, with no other operator signal — mirror
	// the source-NAT zone validation above so the divergence surfaces at
	// commit (#2008 H15).
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		if rs.FromZone != "" && !zones[rs.FromZone] {
			warnings = append(warnings, fmt.Sprintf(
				"static-nat ruleset %q: from-zone %q not defined", rs.Name, rs.FromZone))
		}
	}

	// Validate screen references in zones
	for name, zone := range cfg.Security.Zones {
		if zone == nil { // #3494: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		if zone.ScreenProfile != "" {
			if _, ok := cfg.Security.Screen[zone.ScreenProfile]; !ok {
				warnings = append(warnings, fmt.Sprintf(
					"zone %q: screen profile %q not defined", name, zone.ScreenProfile))
			}
		}
	}

	// Validate address-book entries have valid CIDR or IP formats
	if ab := cfg.Security.AddressBook; ab != nil {
		for name, entry := range ab.Addresses {
			if entry == nil { // #3494: tolerant/HA-sync path may carry a nil address
				continue
			}
			if entry.Value == "" {
				// An `address <name>` entry with no compiled prefix —
				// either no prefix at all, or only an as-yet-uncompiled
				// sub-stanza (dns-name/range-address/wildcard-address) —
				// resolves to nothing: net.ParseCIDR("") errors at match
				// time, so every policy referencing it denies (fail-closed,
				// #2229). That is safe but silent, so surface the operator
				// authoring error at commit. This is a WARNING, never a
				// hard reject: an empty-prefix address never forwarded and
				// rejecting it would brick existing configs.
				warnings = append(warnings, fmt.Sprintf(
					"address-book %q: no usable prefix configured; it will match nothing", name))
				continue
			}
			if _, _, err := net.ParseCIDR(entry.Value); err != nil {
				if net.ParseIP(entry.Value) == nil {
					warnings = append(warnings, fmt.Sprintf(
						"address-book %q: invalid address %q", name, entry.Value))
				}
			}
		}
		// Validate address-set members reference valid entries
		for setName, as := range ab.AddressSets {
			if as == nil { // #3494: tolerant/HA-sync path may carry a nil address-set
				continue
			}
			for _, m := range as.Addresses {
				if !addrs[m] {
					warnings = append(warnings, fmt.Sprintf(
						"address-set %q: member %q not in address-book", setName, m))
				}
			}
			for _, m := range as.AddressSets {
				if !addrs[m] {
					warnings = append(warnings, fmt.Sprintf(
						"address-set %q: nested set %q not in address-book", setName, m))
				}
			}
		}
	}

	// Validate static route destinations are valid CIDR
	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		if sr == nil { // #3494: tolerant/HA-sync path may carry a nil static route
			continue
		}
		if sr.Destination != "" {
			if _, _, err := net.ParseCIDR(sr.Destination); err != nil {
				warnings = append(warnings, fmt.Sprintf(
					"static route: invalid destination %q", sr.Destination))
			}
		}
	}

	// Validate DNAT pool references
	if dnat := cfg.Security.NAT.Destination; dnat != nil {
		for _, rs := range dnat.RuleSets {
			if rs == nil { // #3494: tolerant/HA-sync path may carry a nil rule-set
				continue
			}
			for _, rule := range rs.Rules {
				if rule == nil { // #3494: tolerant/HA-sync path may carry a nil rule
					continue
				}
				if rule.Then.PoolName != "" {
					if _, ok := dnat.Pools[rule.Then.PoolName]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"destination-nat %q rule %q: pool %q not defined",
							rs.Name, rule.Name, rule.Then.PoolName))
					}
				}
			}
		}
	}

	// Validate SNAT pool references
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil { // #3494: tolerant/HA-sync path may carry a nil rule-set
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil { // #3494: tolerant/HA-sync path may carry a nil rule
				continue
			}
			if rule.Then.PoolName != "" {
				if _, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"source-nat %q rule %q: pool %q not defined",
						rs.Name, rule.Name, rule.Then.PoolName))
				}
			}
		}
	}

	// Validate zone interface references
	configuredIfaces := make(map[string]bool)
	for name := range cfg.Interfaces.Interfaces {
		configuredIfaces[name] = true
	}
	for zoneName, zone := range cfg.Security.Zones {
		if zone == nil { // #3494: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifName := range zone.Interfaces {
			// Strip unit suffix (e.g. "trust0.0" -> "trust0")
			base := ifName
			if idx := strings.Index(ifName, "."); idx > 0 {
				base = ifName[:idx]
			}
			if !configuredIfaces[base] {
				warnings = append(warnings, fmt.Sprintf(
					"zone %q: interface %q not in interfaces config", zoneName, ifName))
			}
		}
	}

	// Validate scheduler references in policies
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil { // #3494: tolerant/HA-sync path may carry a nil zone-pair set
			continue
		}
		for _, p := range zpp.Policies {
			if p == nil { // #3494: tolerant/HA-sync path may carry a nil rule
				continue
			}
			if p.SchedulerName != "" {
				if _, ok := cfg.Schedulers[p.SchedulerName]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: scheduler %q not defined", p.Name, p.SchedulerName))
				}
			}
		}
	}
	for _, p := range cfg.Security.GlobalPolicies {
		if p == nil { // #3494: tolerant/HA-sync path may carry a nil global rule
			continue
		}
		if p.SchedulerName != "" {
			if _, ok := cfg.Schedulers[p.SchedulerName]; !ok {
				warnings = append(warnings, fmt.Sprintf(
					"global policy %q: scheduler %q not defined", p.Name, p.SchedulerName))
			}
		}
	}

	// #3860: warn when a scheduler defines no effective window. Post-#3849/
	// #3858 the runtime evaluator (pkg/scheduler.isWithinWindow) fail-closes
	// such a scheduler to INACTIVE — an absent window is never treated as
	// always-on. That direction is safe (the config is degenerate), but an
	// operator migrating a config that relied on the old always-on bug loses
	// enforcement silently. Surface the flip at commit. A scheduler carrying
	// any time-of-day window (daily/weekday arm or all-day) or a start/stop
	// calendar range is well-formed and does NOT warn. Iterate by sorted name
	// so warnings are deterministic across commits (map iteration is
	// randomized).
	schedNames := make([]string, 0, len(cfg.Schedulers))
	for name := range cfg.Schedulers {
		schedNames = append(schedNames, name)
	}
	sort.Strings(schedNames)
	for _, name := range schedNames {
		sched := cfg.Schedulers[name]
		if sched == nil {
			continue
		}
		if schedulerHasEffectiveWindow(sched) {
			continue
		}
		warnings = append(warnings, fmt.Sprintf(
			"scheduler %q defines no time window; policies bound to it will "+
				"be INACTIVE (use `daily all-day` for always-on)", name))
	}

	// Validate routing-instance interface references
	for _, ri := range cfg.RoutingInstances {
		if ri == nil { // #3494: tolerant/HA-sync path may carry a nil routing-instance
			continue
		}
		for _, ifName := range ri.Interfaces {
			base := ifName
			if idx := strings.Index(ifName, "."); idx > 0 {
				base = ifName[:idx]
			}
			if !configuredIfaces[base] {
				warnings = append(warnings, fmt.Sprintf(
					"routing-instance %q: interface %q not in interfaces config",
					ri.Name, ifName))
			}
		}
	}

	// Firewall filter references on interfaces (and lo0) are validated by the
	// strict commit gate validateFirewallFilterReferencesStrict (#3296):
	// hard-reject on commit / commit-check, downgraded to a warning on the
	// tolerant load / peer-sync path. The strict gate fully subsumes the
	// warn-only loop that previously lived here (it would otherwise emit a
	// duplicate warning alongside the downgraded gate warning on the lenient
	// path).

	// Validate chassis cluster fabric config
	if cc := cfg.Chassis.Cluster; cc != nil {
		// fabric1-interface without fabric1-peer-address (or vice versa) is incomplete
		if (cc.Fabric1Interface != "") != (cc.Fabric1PeerAddress != "") {
			warnings = append(warnings, "chassis cluster: fabric1-interface and fabric1-peer-address must both be set for dual-fabric")
		}
		// Check fabric interfaces are defined in interface config
		for _, pair := range [][2]string{
			{cc.FabricInterface, "fabric-interface"},
			{cc.Fabric1Interface, "fabric1-interface"},
		} {
			ifName, label := pair[0], pair[1]
			if ifName != "" {
				if _, ok := cfg.Interfaces.Interfaces[ifName]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"chassis cluster %s %q: interface not defined", label, ifName))
				}
			}
		}
		// Check control interface is defined
		if cc.ControlInterface != "" {
			if _, ok := cfg.Interfaces.Interfaces[cc.ControlInterface]; !ok {
				warnings = append(warnings, fmt.Sprintf(
					"chassis cluster control-interface %q: interface not defined", cc.ControlInterface))
			}
		}
		// Check fabric member interfaces don't overlap between fab0 and fab1
		if cc.FabricInterface != "" && cc.Fabric1Interface != "" {
			fab0Members := make(map[string]bool)
			if f0 := cfg.Interfaces.Interfaces[cc.FabricInterface]; f0 != nil {
				for _, m := range f0.FabricMembers {
					fab0Members[m] = true
				}
			}
			if f1 := cfg.Interfaces.Interfaces[cc.Fabric1Interface]; f1 != nil {
				for _, m := range f1.FabricMembers {
					if fab0Members[m] {
						warnings = append(warnings, fmt.Sprintf(
							"chassis cluster: fabric member %q shared between %s and %s",
							m, cc.FabricInterface, cc.Fabric1Interface))
					}
				}
			}
		}
	}

	// Validate strict-vip-ownership requires VRRP (incompatible with no-reth-vrrp / private-rg-election)
	if cc := cfg.Chassis.Cluster; cc != nil && (cc.NoRethVRRP || cc.PrivateRGElection) {
		for _, rg := range cc.RedundancyGroups {
			if rg == nil { // #3494: tolerant/HA-sync path may carry a nil redundancy-group
				continue
			}
			if rg.StrictVIPOwnership {
				warnings = append(warnings, fmt.Sprintf(
					"redundancy-group %d: strict-vip-ownership incompatible with no-reth-vrrp (no VRRP instances to gate on)", rg.ID))
			}
		}
	}

	// Warn if no-reth-vrrp set explicitly — redundant since private-rg-election is now default
	if cc := cfg.Chassis.Cluster; cc != nil && cc.PrivateRGElection && cc.NoRethVRRP {
		warnings = append(warnings, "chassis cluster: no-reth-vrrp is redundant (private-rg-election is the default)")
	}

	if cfg.System.PersistGroupsInheritance {
		warnings = append(warnings, "system commit persist-groups-inheritance configured but group inheritance persistence is not implemented")
	}

	// #2008 H13 Stage 1: the leaf is now typed (schema + field) instead of
	// being silently dropped, but the idle-yield dataplane runtime is not
	// implemented — the userspace AF_XDP workers busy-poll. Warn so the
	// operator knows the knob is accepted but currently has no effect.
	if cfg.ForwardingOptions.AllowDataplaneSleep {
		warnings = append(warnings, "forwarding-options allow-dataplane-sleep configured but is accepted-only — the userspace dataplane workers busy-poll and idle-yield is not yet implemented")
	}

	// #2078: the `security flow tcp-session` presence flags are typed and
	// committed but the userspace AF_XDP dataplane enforces none of them
	// today. no-syn-check / no-syn-check-in-tunnel would gate the
	// session-create SYN check; rst-invalidate-session would tear a session
	// down on RST; no-sequence-check (#2008 M9) would skip sequence-window
	// validation. The dataplane session table is a pure 5-tuple flow entry
	// with no TCP state machine and no sequence/window tracking, so there is
	// nothing for any of these knobs to enforce or skip. This is an
	// intentional, reviewed parity gap (see #2008 M9 and the RST design
	// rationale in docs/active-active-new-connections.md); research #2078
	// converged PLAN-KILL on enforcement. Warn so an operator who sets one
	// of these is not silently misled into believing it has runtime effect.
	if ts := cfg.Security.Flow.TCPSession; ts != nil {
		var unenforced []string
		if ts.NoSynCheck {
			unenforced = append(unenforced, "no-syn-check")
		}
		if ts.NoSynCheckInTunnel {
			unenforced = append(unenforced, "no-syn-check-in-tunnel")
		}
		if ts.RstInvalidateSession {
			unenforced = append(unenforced, "rst-invalidate-session")
		}
		if ts.NoSequenceCheck {
			unenforced = append(unenforced, "no-sequence-check")
		}
		if len(unenforced) > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"security flow tcp-session %s configured but accepted-only — the userspace dataplane has no TCP state machine and does not enforce these knobs (config-only parity, #2078)",
				strings.Join(unenforced, ", ")))
		}
	}

	// #4233/#4234: `security policies policy-rematch [extensive]` is typed and
	// recorded (compiler_security_policy.go). The Junos-DEFAULT deletion-clear
	// now ships (#4234): a session admitted by a policy that a commit DELETES is
	// invalidated immediately at commit (daemon_apply.go →
	// clearSessionsForDeletedPolicies), independent of this knob. What
	// policy-rematch additionally promises — re-evaluating an in-progress session
	// against a MODIFIED (not deleted) policy set — is still accepted-only: xpf
	// does not re-classify live sessions, so a session admitted by a policy whose
	// match/action later changed keeps forwarding until its idle timeout. Warn so
	// the operator is not silently misled into believing modified-policy
	// re-evaluation is active. Mirrors the #2078 / #2008 H13 accepted-only
	// doctrine; the modified-policy re-eval half stays tracked in #4234.
	if cfg.Security.PolicyRematch {
		knob := "policy-rematch"
		if cfg.Security.PolicyRematchExtensive {
			knob = "policy-rematch extensive"
		}
		warnings = append(warnings, fmt.Sprintf(
			"security policies %s configured but only partially enforced — a "+
				"DELETED policy's sessions are now dropped at commit (Junos "+
				"default, #4234), but xpf does not yet re-evaluate an in-progress "+
				"session against a MODIFIED policy; such a session keeps forwarding "+
				"until its idle timeout (#4233; modified-policy re-eval tracked in "+
				"#4234)", knob))
	}

	// #4231 (fable-167 P-3): five `security flow` knobs are now typed +
	// committed (schema leaves + compileFlow) but the userspace AF_XDP
	// dataplane enforces none of them today. Mirror the #2078 tcp-session
	// accepted-only doctrine: warn so an operator who sets one is not silently
	// misled into believing it has runtime effect. sync-icmp-session gets its
	// own, distinct line because it is a no-op for a DIFFERENT reason than the
	// other four: xpf ALREADY syncs ICMP sessions to the HA peer
	// UNCONDITIONALLY — the session-sync path is protocol-agnostic at every
	// layer (publish_shared_session / snapshot_all_sessions_export in
	// userspace-dp; the Go pkg/cluster wire has no protocol filter), so the
	// Junos opt-in knob has nothing to turn on. The two duration knobs
	// (route-change-timeout, multicast-session-lifetime) are "present" when > 0
	// (0 = unset / disabled, no behavior to warn about); the toggles warn on
	// presence.
	{
		flow := cfg.Security.Flow
		var flowUnenforced []string
		if flow.RouteChangeTimeout > 0 {
			flowUnenforced = append(flowUnenforced, "route-change-timeout")
		}
		if flow.ForceIPReassembly {
			flowUnenforced = append(flowUnenforced, "force-ip-reassembly")
		}
		if flow.MulticastSessionLifetime > 0 {
			flowUnenforced = append(flowUnenforced, "multicast-session-lifetime")
		}
		if flow.PreserveIncomingFragmentSize {
			flowUnenforced = append(flowUnenforced, "preserve-incoming-fragment-size")
		}
		if len(flowUnenforced) > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"security flow %s configured but accepted-only — the userspace dataplane does not enforce these knobs (config-only parity, #4231)",
				strings.Join(flowUnenforced, ", ")))
		}
		if flow.SyncICMPSession {
			warnings = append(warnings,
				"security flow sync-icmp-session configured but has no effect — xpf syncs ICMP sessions to the HA peer UNCONDITIONALLY (the session-sync path is protocol-agnostic), so this Junos opt-in knob is a no-op: ICMP session sync is already always on and cannot be turned off (config-only parity, #4231)")
		}
	}

	// #4291 (fable-167 N-2): the NAT `port-overloading` knobs are now typed +
	// committed (schema leaves + compileNAT) but the userspace AF_XDP SNAT
	// allocator enforces neither. `security nat source interface port-overloading
	// off` disables source-port reuse across destinations (a src-port-uniqueness
	// hardening posture) — xpf's allocator always overloads source ports, so
	// `off` hardens NOTHING. `port-overloading-factor <n>` scales the concurrent
	// translations per pool address — xpf has no factor-scaled port budget.
	// Mirror the #2078/#4231 accepted-only doctrine: warn so an operator is not
	// silently misled into believing `off` is a real control. Full enforcement is
	// a userspace-dp SNAT-allocator follow-up.
	{
		var poParts []string
		if cfg.Security.NAT.SourceInterfacePortOverloadingOff {
			poParts = append(poParts, "interface port-overloading off")
		}
		var poFactorPools []string
		for _, name := range sortedPoolNames(cfg.Security.NAT.SourcePools) {
			if p := cfg.Security.NAT.SourcePools[name]; p != nil && p.PortOverloadingFactor > 0 {
				poFactorPools = append(poFactorPools, name)
			}
		}
		if len(poFactorPools) > 0 {
			poParts = append(poParts, fmt.Sprintf("pool %s port-overloading-factor", strings.Join(poFactorPools, ", ")))
		}
		if len(poParts) > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"security nat source %s configured but accepted-only — the "+
					"userspace dataplane always overloads source ports, so "+
					"port-overloading off hardens nothing and "+
					"port-overloading-factor has no effect (config-only parity, "+
					"#4291)",
				strings.Join(poParts, " / ")))
		}
	}

	// #4292 (fable-167 N-3): NAT translation-TARGET routing-instance is now typed
	// + recorded (compileNAT) but not enforced. `then static-nat {inet|prefix
	// <ip>} routing-instance <ri>` and a source / destination NAT pool
	// `routing-instance <ri>` would place the TRANSLATED packet in a different
	// routing table (cross-VRF NAT) — distinct from the #3096 from/to SCOPE
	// routing-instance, which IS enforced. The dataplane does not route the
	// post-translation packet against a non-ingress table, so the target RI is
	// dropped. Mirror the #2078/#4231 accepted-only doctrine: warn so the dropped
	// target is operator-visible. Full enforcement is a cross-VRF-NAT userspace-dp
	// follow-up.
	{
		targetRISeen := make(map[string]bool)
		var targetRIParts []string
		addRI := func(part string) {
			if !targetRISeen[part] {
				targetRISeen[part] = true
				targetRIParts = append(targetRIParts, part)
			}
		}
		for _, rs := range cfg.Security.NAT.Static {
			if rs == nil {
				continue
			}
			for _, rule := range rs.Rules {
				if rule != nil && rule.ThenRoutingInstance != "" {
					addRI(fmt.Sprintf("static rule-set %q rule %q then static-nat routing-instance %q", rs.Name, rule.Name, rule.ThenRoutingInstance))
				}
			}
		}
		for _, name := range sortedPoolNames(cfg.Security.NAT.SourcePools) {
			if p := cfg.Security.NAT.SourcePools[name]; p != nil && p.RoutingInstance != "" {
				addRI(fmt.Sprintf("source pool %q routing-instance %q", name, p.RoutingInstance))
			}
		}
		if cfg.Security.NAT.Destination != nil {
			for _, name := range sortedPoolNames(cfg.Security.NAT.Destination.Pools) {
				if p := cfg.Security.NAT.Destination.Pools[name]; p != nil && p.RoutingInstance != "" {
					addRI(fmt.Sprintf("destination pool %q routing-instance %q", name, p.RoutingInstance))
				}
			}
		}
		if len(targetRIParts) > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"security nat translation-target routing-instance configured but "+
					"accepted-only — the userspace dataplane routes the "+
					"post-translation packet against the ingress / default "+
					"routing instance, so the target routing-instance is not "+
					"applied (%s) (config-only parity, #4292)",
				strings.Join(targetRIParts, "; ")))
		}
	}

	// #4232 (fable-167 P-4a): a `security alg <proto>` stanza whose proto is
	// not one of the four the dataplane wires (dns/ftp/sip/tftp) was silently
	// dropped. Warn so the operator knows the stanza is accepted-but-inert
	// (e.g. h323, msrpc) rather than silently enforced. Dedup across repeated
	// `security {}` blocks (compileALG runs per security root) for a clean,
	// deterministic message.
	if protos := cfg.Security.ALG.UnsupportedProtos; len(protos) > 0 {
		seen := make(map[string]bool, len(protos))
		var uniq []string
		for _, p := range protos {
			if !seen[p] {
				seen[p] = true
				uniq = append(uniq, p)
			}
		}
		warnings = append(warnings, fmt.Sprintf(
			"security alg %s accepted but inert — the userspace dataplane implements ALG control only for dns/ftp/sip/tftp, so this stanza has no effect (#4232)",
			strings.Join(uniq, ", ")))
	}

	// #4232 (fable-167 P-4b): a DIRECT child of `policy <name>` whose keyword
	// the compiler does not read (anything but match/then/description/
	// scheduler-name) was silently dropped — a typo'd `descripton` /
	// `scheduler-nam` vanished. Junos rejects the unknown keyword at commit;
	// this advisory at least surfaces it. Report the fully-qualified policy
	// path so the operator can find the offending line.
	var policyUnknown []string
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			for _, kw := range pol.UnknownChildren {
				policyUnknown = append(policyUnknown,
					fmt.Sprintf("%s->%s/%s `%s`", zpp.FromZone, zpp.ToZone, pol.Name, kw))
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		for _, kw := range pol.UnknownChildren {
			policyUnknown = append(policyUnknown, fmt.Sprintf("global/%s `%s`", pol.Name, kw))
		}
	}
	if len(policyUnknown) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"security policy: unrecognized child keyword(s) accepted but dropped (probable typo — xpf reads only match/then/description/scheduler-name at the policy level; Junos rejects unknown keywords at commit): %s (#4232)",
			strings.Join(policyUnknown, ", ")))
	}

	// #3440 H1: `security flow aging` (early-ageout / high-watermark /
	// low-watermark) drives the Go-side conntrack GC watermark hysteresis
	// (pkg/conntrack/gc.go), but that GC sweep is skipped entirely whenever
	// the userspace AF_XDP dataplane is active (daemon_run.go installs
	// gc.SkipSweep = true for the userspace delta-drainer, which is the only
	// runtime forwarding path post #1373/#1476). The userspace session
	// expiry (userspace-dp/src/session/expire.rs) ages each entry only on its
	// own per-session idle timeout (expires_after_ns) with no watermark-driven
	// pressure shedding. So the documented early-ageout/watermark behavior
	// never runs on the userspace dataplane: an operator who configures it
	// believes they have pressure-based session shedding when they do not.
	// Warn so the knob is not silently misleading (matching the #2078 /
	// #2008 H13 accepted-only treatment). Note: per-application
	// inactivity-timeout (#3227) is a DIFFERENT, fully-enforced knob — it
	// reaches the userspace session table via the snapshot and is honored by
	// expire.rs; only the aging watermark machinery here is inert.
	if f := cfg.Security.Flow; f.AgingEarlyAgeout > 0 || f.AgingHighWatermark > 0 || f.AgingLowWatermark > 0 {
		warnings = append(warnings,
			"security flow aging configured but accepted-only — the userspace AF_XDP dataplane ages sessions on their per-session idle timeout only and does not enforce early-ageout / high-watermark / low-watermark pressure-based shedding (config-only, #3440)")
	}

	// #654: warn on `system processes X disable` for a process that
	// bpfrx does not actually manage. Silently accepting the knob (as
	// used to happen with e.g. `utmd disable` on vSRX) means the
	// operator gets no signal that the setting is a no-op.
	for _, proc := range cfg.System.DisabledProcesses {
		if !isKnownProcessName(proc) {
			warnings = append(warnings, fmt.Sprintf(
				"system processes %q disable: bpfrx does not manage %q; setting has no runtime effect", proc, proc))
		}
	}

	// #651: warn when archive-sites include inline `password`
	// credentials. Runtime archival shells out to `scp` with
	// `-o BatchMode=yes`, so the password is silently ignored and
	// archival can fail unless matching SSH keys are already set up.
	if cfg.System.Archival != nil {
		for _, url := range cfg.System.Archival.ArchiveSitesWithPassword {
			warnings = append(warnings, fmt.Sprintf(
				"system archival archive-sites %q: inline password is accepted but ignored — archival uses scp BatchMode and relies on SSH keys, not passwords", url))
		}
	}

	if cfg.System.Services != nil && cfg.System.Services.DNSProxyConfigured {
		warnings = append(warnings, "system services dns dns-proxy configured but DNS proxy/forwarder runtime is not implemented")
	}

	// #1715: `system services dns` no longer selects a systemd-resolved
	// owner runtime branch. xpf owns /etc/resolv.conf directly as a
	// managed plain file and keeps resolved disabled+masked regardless of
	// this stanza. Warn so an operator who set it expecting resolved is
	// not surprised that resolved stays off.
	if cfg.System.Services != nil && cfg.System.Services.DNSEnabled {
		warnings = append(warnings, "system services dns: resolved-owner mode is not supported; xpf manages /etc/resolv.conf directly and keeps systemd-resolved disabled+masked")
	}

	if fm := cfg.Services.FlowMonitoring; fm != nil {
		// #3270: flow-dir is derived from the per-zone sampling-direction
		// (`sampling input`/`output`). With no sampling-direction configured
		// anywhere the derived flowDirection is always 0 (ingress), so the
		// exported IE 61 would be a constant — warn the operator in that case.
		hasSampling := anySamplingDirectionConfigured(cfg)
		checkExtWarning := func(kind, name string, exts []string) {
			for _, ext := range exts {
				switch ext {
				case "app-id":
					warnings = append(warnings, fmt.Sprintf(
						"flow-monitoring %s template %s: export-extension app-id configured but application data is not available in flow records", kind, name))
				case "flow-dir":
					// #3270: flowDirection (IE 61) is exported again, derived in
					// Go from the per-zone sampling-direction. It is only
					// meaningful when at least one zone has `sampling input` or
					// `sampling output`; otherwise every record reports 0.
					if !hasSampling {
						warnings = append(warnings, fmt.Sprintf(
							"flow-monitoring %s template %s: export-extension flow-dir configured but no interface has sampling input/output; flowDirection will always be 0 (ingress)", kind, name))
					}
				}
			}
		}
		if fm.Version9 != nil {
			for _, tmpl := range fm.Version9.Templates {
				if tmpl == nil { // #3494: tolerant/HA-sync path may carry a nil template
					continue
				}
				checkExtWarning("version9", tmpl.Name, tmpl.ExportExtensions)
			}
		}
		if fm.VersionIPFIX != nil {
			for _, tmpl := range fm.VersionIPFIX.Templates {
				if tmpl == nil { // #3494: tolerant/HA-sync path may carry a nil template
					continue
				}
				checkExtWarning("version-ipfix", tmpl.Name, tmpl.ExportExtensions)
			}
		}
	}

	if cos := cfg.ClassOfService; cos != nil {
		warnedClassifierLossPriority := false
		warnedRewriteLossPriority := false
		warnedPriorityLowMinShare := false
		for _, class := range cos.ForwardingClasses {
			if class == nil {
				continue
			}
			if class.Queue < 0 || class.Queue > 255 {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service forwarding-class %q uses out-of-range queue %d (expected 0..255)",
					class.Name, class.Queue))
			}
		}
		// #915: surplus-sharing is meaningful only on transmit-rate
		// exact schedulers; warn-and-strip when set without exact so
		// the runtime never sees the no-op flag (see #1183 lesson).
		for _, sched := range cos.Schedulers {
			if sched == nil {
				continue
			}
			if sched.SurplusSharing && !sched.TransmitRateExact {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service scheduler %q surplus-sharing is meaningful only with transmit-rate exact; ignored",
					sched.Name))
				sched.SurplusSharing = false
			}
			// #1746: warn-not-strip. A policy without enforcement is a
			// harmless no-op (the dataplane gates it on
			// equal-flow-enforcement), but the operator should know it
			// is inert.
			if sched.EqualFlowTargetPolicy != "" && !sched.EqualFlowEnforcement {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service scheduler %q equal-flow-target-policy %q has no effect without equal-flow-enforcement",
					sched.Name, sched.EqualFlowTargetPolicy))
			}
			// #1746: non-work-conserving cost warning. Clipping fast
			// flows frees capacity that CANNOT reach slow flows on
			// other workers, so these policies trade aggregate
			// throughput for per-flow evenness (see
			// docs/cos-traffic-shaping.md).
			if sched.EqualFlowEnforcement {
				switch sched.EqualFlowTargetPolicy {
				case "slowest", "mean":
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service scheduler %q equal-flow-target-policy %s is non-work-conserving: it clips fast flows and reduces aggregate class throughput; it cannot lift slow flows",
						sched.Name, sched.EqualFlowTargetPolicy))
				}
			}
			// #4218: codel-target (#1614 A3 CoDel AQM) is typed and stored
			// (CodelTargetNS) so a garbage value is rejected at commit, but
			// the AQM itself is NOT enforced — #1829 Phase 2 was PLAN-KILLED.
			// Warn so an operator who sets it is not misled into believing it
			// bounds queue latency. Mirrors the accepted-but-inert doctrine
			// used for loss-priority and the #2078/#3440 knobs.
			if sched.CodelTargetNS > 0 {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service scheduler %q codel-target is accepted for compatibility but inert: the userspace dataplane has no CoDel AQM (#1829 Phase 2 not shipped), so the configured target has no runtime effect",
					sched.Name))
			}
		}
		for _, schedMap := range cos.SchedulerMaps {
			if schedMap == nil {
				continue
			}
			for className := range schedMap.Entries {
				if _, ok := cos.ForwardingClasses[className]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service scheduler-map %q references undefined forwarding-class %q",
						schedMap.Name, className))
				}
				// A scheduler-map entry naming an undefined scheduler is no
				// longer warn-only: validateClassOfServiceSchedulerMapRefsStrict
				// hard-rejects it at strict commit / commit-check and downgrades
				// it to a cfg.Warnings entry on the tolerant load / peer-sync
				// paths (#1960). Leaving a parallel warning here would
				// double-report it on the lenient path and duplicates a rule
				// that now lives in one place, consistent with every other
				// cross-reference gate (IPsec proposal, policy zone/scheduler,
				// log-stream, feed-name), none of which warn from ValidateConfig.
			}
		}
		for _, classifier := range cos.DSCPClassifiers {
			if classifier == nil {
				continue
			}
			for _, entry := range classifier.Entries {
				if entry == nil || entry.ForwardingClass == "" {
					continue
				}
				if _, ok := cos.ForwardingClasses[entry.ForwardingClass]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service dscp classifier %q references undefined forwarding-class %q",
						classifier.Name, entry.ForwardingClass))
				}
				if entry.LossPriority != "" && !warnedClassifierLossPriority {
					warnings = append(warnings, "class-of-service dscp/802.1p classifier loss-priority is accepted for compatibility but not yet enforced by the userspace dataplane")
					warnedClassifierLossPriority = true
				}
			}
		}
		for _, classifier := range cos.IEEE8021Classifiers {
			if classifier == nil {
				continue
			}
			for _, entry := range classifier.Entries {
				if entry == nil || entry.ForwardingClass == "" {
					continue
				}
				if _, ok := cos.ForwardingClasses[entry.ForwardingClass]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service ieee-802.1 classifier %q references undefined forwarding-class %q",
						classifier.Name, entry.ForwardingClass))
				}
				if entry.LossPriority != "" && !warnedClassifierLossPriority {
					warnings = append(warnings, "class-of-service dscp/802.1p classifier loss-priority is accepted for compatibility but not yet enforced by the userspace dataplane")
					warnedClassifierLossPriority = true
				}
			}
		}
		for _, rewriteRule := range cos.DSCPRewriteRules {
			if rewriteRule == nil {
				continue
			}
			for _, entry := range rewriteRule.Entries {
				if entry == nil || entry.ForwardingClass == "" {
					continue
				}
				if _, ok := cos.ForwardingClasses[entry.ForwardingClass]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service dscp rewrite-rule %q references undefined forwarding-class %q",
						rewriteRule.Name, entry.ForwardingClass))
				}
				if entry.LossPriority != "" && !warnedRewriteLossPriority {
					warnings = append(warnings, "class-of-service dscp rewrite-rule loss-priority is accepted for compatibility but not yet enforced by the userspace dataplane")
					warnedRewriteLossPriority = true
				}
			}
		}
		// #4220 / #4219: priority-low-min-share (#1614 A2) is typed and
		// stored (PriorityLowMinShareBytes) so garbage is rejected at
		// commit, but the knob is INERT — it is wire-surface-only and no
		// scheduler code consults it (the cap_eff per-pass reservation that
		// would enforce it is deferred research). Warn ONCE (map iteration
		// is randomized; a generic message stays deterministic) so an
		// operator is not misled into believing the priority-low queue has
		// a protected minimum. The enforcement itself is a separate
		// deferred item.
		warnPriorityLowMinShareInert := func(bytes uint64) {
			if bytes > 0 && !warnedPriorityLowMinShare {
				warnings = append(warnings,
					"class-of-service priority-low-min-share is accepted for compatibility but inert: the userspace dataplane does not yet enforce a priority-low minimum share (#1614 A2; the cap_eff reservation is deferred), so the configured value has no runtime effect")
				warnedPriorityLowMinShare = true
			}
		}
		for _, iface := range cos.Interfaces {
			if iface == nil {
				continue
			}
			// #hb166 G-6: a class-of-service binding whose interface (or
			// logical unit) is not configured under [interfaces] commits
			// cleanly but shapes nothing — the dataplane applier only
			// visits CoS bindings inside the cfg.Interfaces iteration, so
			// a typo'd interface name or an unconfigured unit is a silent
			// no-op. Warn (not reject: the interface could be added
			// later) so the operator knows the binding is currently inert.
			ifCfg := cfg.Interfaces.Interfaces[iface.Name]
			if ifCfg == nil {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service interface %s is bound but not configured under [interfaces]; its shaping/classifiers are inert until the interface is configured",
					iface.Name))
			}
			if iface.Level != nil {
				warnPriorityLowMinShareInert(iface.Level.PriorityLowMinShareBytes)
			}
			for _, unit := range iface.Units {
				if unit == nil {
					continue
				}
				if ifCfg != nil {
					if _, ok := ifCfg.Units[unit.Unit]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d is bound but unit %d is not configured under [interfaces %s]; its shaping/classifiers are inert",
							iface.Name, unit.Unit, unit.Unit, iface.Name))
					}
				}
				warnPriorityLowMinShareInert(unit.PriorityLowMinShareBytes)
				if unit.SchedulerMap != "" {
					if _, ok := cos.SchedulerMaps[unit.SchedulerMap]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined scheduler-map %q",
							iface.Name, unit.Unit, unit.SchedulerMap))
					}
				}
				if unit.DSCPClassifier != "" {
					if _, ok := cos.DSCPClassifiers[unit.DSCPClassifier]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined dscp classifier %q",
							iface.Name, unit.Unit, unit.DSCPClassifier))
					}
				}
				if unit.IEEE8021Classifier != "" {
					if _, ok := cos.IEEE8021Classifiers[unit.IEEE8021Classifier]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined ieee-802.1 classifier %q",
							iface.Name, unit.Unit, unit.IEEE8021Classifier))
					}
				}
				if unit.DSCPRewriteRule != "" {
					if _, ok := cos.DSCPRewriteRules[unit.DSCPRewriteRule]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined dscp rewrite-rule %q",
							iface.Name, unit.Unit, unit.DSCPRewriteRule))
					}
				}
				// #hb166 T-4: a behavior-aggregate classifier code-point that
				// maps to a forwarding-class whose queue is NOT materialized on
				// this interface (no scheduler-map entry) is a silent blackhole
				// in the pre-fix dataplane. It is now fail-SAFE (the userspace
				// helper forwards such traffic on the best-effort queue,
				// forwarding_build/cos.rs), but the operator should still see
				// that the intended queue does not exist on this interface.
				// WARN, not reject: unlike the dangling-SCHEDULER case
				// (validateClassOfServiceSchedulerMapRefsStrict), a classifier
				// steering to a forwarding-class that simply lacks a
				// scheduler-map entry is a valid Junos config (queues exist by
				// default there), so a strict reject would refuse configs Junos
				// accepts.
				warnings = append(warnings,
					classOfServiceClassifierQueueWarnings(cos, iface.Name, unit)...)
			}
		}
		hasCoSRuntimeConfig := len(cos.Interfaces) > 0 ||
			len(cos.DSCPClassifiers) > 0 ||
			len(cos.IEEE8021Classifiers) > 0 ||
			len(cos.DSCPRewriteRules) > 0
		if hasCoSRuntimeConfig && effectiveDataplaneType(cfg.System.DataplaneType) != dataplaneTypeUserspace {
			warnings = append(warnings, "class-of-service shaping, classifier attachment, and dscp rewrite-rule attachment are only implemented in the userspace dataplane; configuration is accepted but will not take effect on this dataplane")
		}

		// #1614 A4: operator-visible warning when the sum of an
		// interface unit's exact-class transmit-rates exceeds the
		// unit's shaping-rate. Under oversubscription, every class
		// will receive less than its configured rate; the visible
		// distribution depends on the unit's oversubscription-policy.
		warnings = append(warnings, validateCoSOversubscriptionWarnings(cos)...)
	}

	// #1706: the next-table and rib-group ip-rule reconcilers program
	// into fixed 100-priority windows that their clear() passes scan.
	// The applier hard-caps at the window boundary so out-of-range rules
	// never leak, but a config that exceeds the window would be silently
	// truncated at apply time. Surface the over-limit condition here at
	// commit time so the operator sees it before applying.
	warnings = append(warnings, validateRoutingRuleWindowWarnings(cfg)...)

	// #3876: warn when an interface-routes rib-group import cannot be fully
	// realized by the Phase-1 per-prefix leak (no enumerable static connected
	// prefix, or a VRF→VRF import target that Phase 1 does not install) so the
	// operator sees a fail-loud diagnostic rather than a silent no-op.
	warnings = append(warnings, validateRibGroupLeakWarnings(cfg)...)

	// #1387: DHCP dynamic-DNS live-backend validation. Increment 2 wired the
	// live RFC 2136 backend, so the increment-1 "no records are published"
	// deferred-backend warning is retired. The warnings here flag a config
	// that the now-live path cannot act on (enabled rfc2136 with no
	// update-server), a still-deferred backend (kea-d2), and the now-consumed
	// free-form leaves (update-server parseability, TSIG algorithm support).
	// All are WARN-only (never an error) so a malformed inert value committed
	// against increment 1 cannot brick a boot (plan §4.5 / §7 Q-C).
	warnings = append(warnings, validateDDNSBackendWarnings(cfg)...)

	// #2691 P2: warn on a per-interface Surface A `dynamic-dns` binding that
	// references a missing/incomplete provider or omits a hostname, and on a
	// `system services dynamic-dns provider` whose rfc2136 backend is unusable.
	// WARN-only (never a hard reject) — a previously-inert misconfig must not
	// brick a boot; the runtime degrades to a logged no-op for that scope.
	warnings = append(warnings, validateSurfaceADDNSWarnings(cfg)...)

	// #2507: firewall-filter `then loss-priority <low|...|high>` is parsed and
	// stored on the term (FirewallFilterTerm.LossPriority) but is never wired
	// onto the wire (no FirewallTermSnapshot field) and the userspace dataplane
	// has no per-packet loss-priority consumer — the three-color policer always
	// meters at PacketColor::Green and color-aware mode stays fail-closed until
	// inherited packet color is carried through trusted metadata (see
	// userspace-dp/src/filter/README.md). So the action commits and silently
	// does nothing. Mirror the CoS classifier/rewrite loss-priority warning
	// above: WARN-only (loss-priority is valid Junos — never fail the commit),
	// once per filter/term, naming the filter and term so the operator knows
	// the QoS action is inert. Same principle as #2486 (ipsec-vpn): never
	// silently accept config the dataplane cannot enforce.
	warnings = append(warnings, validateFilterLossPriorityWarnings(cfg)...)

	// #3445: an lo0 INPUT filter is mirrored onto a kernel nftables chain
	// (the PRIMARY enforcement for host-bound traffic the XDP shim shunts to the
	// kernel). That chain honors match predicates + `then log` + `then count`
	// but cannot faithfully honor the CoS / rate-control `then` modifiers
	// (policer, dscp-rewrite, forwarding-class). Warn — naming each term+modifier
	// — rather than silently dropping them from the kernel mirror. loss-priority
	// is already covered by validateFilterLossPriorityWarnings above.
	warnings = append(warnings, validateLo0FilterKernelMirrorWarnings(cfg)...)

	// #3295: a firewall filter attached to an interface/lo0 input/output hook
	// with no terminal catch-all term relies on xpf's implicit-accept of
	// unmatched traffic — the deliberate divergence from Junos's implicit final
	// discard. WARN-only: surface the divergence (and the explicit-final-term
	// workaround) without changing the runtime default, which would blackhole
	// the classify-and-pass output-filter idiom ("keep GOOD", #2124/#3261). See
	// docs/research/3295-filter-failopen/plan.md and
	// userspace-dp/src/filter/README.md.
	warnings = append(warnings, validateFilterNoCatchAllWarnings(cfg)...)

	// #2509: `security pre-id-default-policy then log session-init/session-close`
	// is parsed and stored on PreIDDefaultPolicy.LogSessionInit/LogSessionClose
	// but has NO consumer in the userspace dataplane after the eBPF retirement
	// (#1373/#1476). The only reader was the retired eBPF compiler
	// (pkg/dataplane/compiler.go, which mapped the bits to FlowConfigValue.
	// AppFlags). The userspace runtime has no pre-identification session-admit
	// path: app-id is best-effort labeling of already-admitted sessions, not a
	// "default policy admits the session before app-id resolves, then
	// re-evaluate" pipeline, so there is no session to stamp the pre-id log
	// mode onto (unlike the per-policy #2508 path, which stamps the admitting
	// policy's log flags at install). The stanza therefore commits and is
	// silently inert. Mirror the #2507 filter loss-priority / CoS
	// loss-priority warnings: WARN-only (pre-id-default-policy is valid Junos —
	// never fail the commit; a hard reject would brick a boot on a
	// previously-inert committed value), naming the inert action so the
	// operator knows the logging signal is not produced.
	warnings = append(warnings, validatePreIDDefaultPolicyLogWarnings(cfg)...)

	// #3534: `security policies default-policy-log session-init/session-close`
	// emits RT_FLOW session logs for the implicit default-policy verdict, but
	// only a default-PERMIT verdict installs a session for those records to fire
	// on. A default-DENY/REJECT verdict installs no session and is already logged
	// unconditionally via the policy-deny RT_FLOW record, so the session-init/
	// session-close flags are inert there. WARN-only (the stanza is valid and
	// must not brick a previously-committed config).
	warnings = append(warnings, validateDefaultPolicyLogWarnings(cfg)...)

	// #4146 (H-1 slice c): warn when a `to-zone junos-host` policy expresses a
	// constraint STRICTER than the coarse kernel host-inbound gate can enforce
	// on the DIRECT host-bound path. Ordinary traffic to a firewall interface
	// IP is delivered by the Linux kernel — the XDP shim shunts local-destined
	// packets to the kernel on a session miss (userspace-xdp/src/lib.rs
	// is_local_destination) — and the nft xpf_hostinbound chain admits
	// configured system-services from ANY source with no per-source /
	// per-application deny. The fine junos-host restriction is enforced only on
	// the userspace AF_XDP LocalDelivery path (e.g. DNAT/static-NAT to a
	// firewall-local address), which the direct host-bound packet never
	// reaches, so a configured deny (or source-scoped permit) is silently
	// unenforced there — a false sense of security. WARN-only: the config is
	// legal Junos and the enforcement decision (a/b) is PLAN-DEFERRED
	// (availability-vs-security tradeoff). See docs/host-inbound-service-
	// matrix.md "to-zone junos-host and the direct host-bound path".
	warnings = append(warnings, validateJunosHostDirectDeliveryWarnings(cfg)...)

	return warnings
}

// validateDefaultPolicyLogWarnings emits a WARN-only commit-time message when
// `security policies default-policy-log session-init/session-close` is
// configured together with a default-DENY or default-REJECT verdict (#3534).
// The session-init/session-close RT_FLOW records fire only for a default-PERMIT
// verdict (which installs a session); a deny/reject verdict installs no session
// and is already logged via the policy-deny RT_FLOW record, so the flags are
// accepted-but-inert. It is never an error: the stanza is valid and a hard
// reject would brick a boot on a previously-committed value.
func validateDefaultPolicyLogWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	if !cfg.Security.DefaultPolicyLogSessionInit && !cfg.Security.DefaultPolicyLogSessionClose {
		return nil
	}
	// Meaningful for permit-all (a session is installed). deny-all/reject-all
	// install no session, so the session-init/close records never fire.
	if cfg.Security.DefaultPolicy == PolicyPermit {
		return nil
	}
	var modes []string
	if cfg.Security.DefaultPolicyLogSessionInit {
		modes = append(modes, "session-init")
	}
	if cfg.Security.DefaultPolicyLogSessionClose {
		modes = append(modes, "session-close")
	}
	action := "deny-all"
	if cfg.Security.DefaultPolicy == PolicyReject {
		action = "reject-all"
	}
	return []string{fmt.Sprintf(
		"security policies default-policy-log `%s` is inert under default-policy "+
			"%s: a deny/reject verdict installs no session, so no RT_FLOW "+
			"session-init/session-close record is produced (the default verdict "+
			"is already logged via the policy-deny RT_FLOW record). These flags "+
			"take effect only with `default-policy permit-all`",
		strings.Join(modes, "/"), action)}
}

// junosHostPolicySourceScoped reports whether a policy match carries a genuine
// source-address restriction — i.e. it is narrower than "any source". A match
// with only the reserved wildcards (`any`/`any-ipv4`/`any-ipv6`/the empty
// token) is NOT scoped; a match naming a concrete address-book entry, literal
// prefix, or feed binding IS. `source-address-excluded` is inherently a
// restriction (permit/deny all EXCEPT the named sources) and so counts as
// scoped regardless of the token. Mirrors the wildcard set recognized by
// policyMatchAddressTokenRecognized (#3958) so the two agree on "any".
func junosHostPolicySourceScoped(m PolicyMatch) bool {
	if m.SourceAddressExcluded {
		return true
	}
	for _, a := range m.SourceAddresses {
		switch a {
		case "", "any", "any-ipv4", "any-ipv6":
			continue
		}
		return true
	}
	return false
}

// junosHostPolicyStricterThanCoarseGate reports whether a `to-zone junos-host`
// policy expresses a constraint the coarse kernel host-inbound gate cannot
// enforce on the direct host-bound path, and if so a short human label for the
// reason. The nft `xpf_hostinbound` chain (the PRIMARY enforcement for
// host-bound traffic the XDP shim shunts to the kernel) is permit-by-service
// only: it admits configured `system-services`/`protocols` to a firewall-local
// address from ANY source, with no per-source or per-application DENY. So a
// junos-host policy is stricter — and therefore silently unenforced on the
// direct path — when it:
//   - denies/rejects: the coarse gate cannot deny a service it permits, OR
//   - permits but restricts the source: the coarse gate admits any source.
//
// A plain `then permit` from any source only mirrors (or loosens) the coarse
// permit-by-service gate and adds no restriction the coarse gate lacks, so it
// does NOT warn — the conservative trigger the #4146 plan calls for (warn only
// on a genuinely stricter-than-coarse-gate junos-host policy, not every one).
// An application-only scope is deliberately not a standalone trigger: the
// coarse gate already filters by service/dport, so a narrow single-port
// application largely overlaps it; only the deny and the source restriction are
// dimensions the coarse gate has no expression for at all.
func junosHostPolicyStricterThanCoarseGate(action PolicyAction, m PolicyMatch) (bool, string) {
	switch action {
	case PolicyDeny:
		return true, "deny"
	case PolicyReject:
		return true, "reject"
	}
	if junosHostPolicySourceScoped(m) {
		return true, "source-restricted permit"
	}
	return false, ""
}

// validateJunosHostDirectDeliveryWarnings emits a WARN-only commit-time message
// for each `to-zone junos-host` security policy — zone-pair or global — that is
// stricter than the coarse kernel host-inbound gate can enforce on the DIRECT
// host-bound path (#4146 H-1 slice c).
//
// The gap: ordinary traffic to a firewall interface IP is delivered by the
// Linux kernel (the XDP shim shunts local-destined packets to the kernel on a
// session miss — userspace-xdp/src/lib.rs is_local_destination →
// cpumap_or_pass), whose nft `xpf_hostinbound` chain has no junos-host
// awareness: it admits configured system-services from any source with no
// per-source / per-application deny. The fine `to-zone junos-host` restriction
// runs only on the userspace AF_XDP LocalDelivery path
// (junos_host_local_policy), which a direct host-bound packet never reaches.
// So a configured deny (or source-scoped permit) to junos-host is silently
// unenforced on the primary host-bound path — a false sense of security this
// warning surfaces at commit.
//
// It is never an error: the config is legal Junos, and the actual enforcement
// fix (withhold the IP from the local set / mirror the policy into nft) is a
// PLAN-DEFERRED availability-vs-security decision (#4146 directions a/b) — a
// hard reject would also brick a previously-committed config. Iteration is over
// the ordered policy slices (deterministic by config order), so the warnings
// are stable across commits.
func validateJunosHostDirectDeliveryWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var warnings []string
	msg := func(who, reason string) string {
		return fmt.Sprintf(
			"security policy %s expresses a %s to-zone junos-host that the kernel "+
				"host-inbound gate cannot enforce on the direct host-bound path: "+
				"traffic to a firewall interface IP is delivered by the kernel (the "+
				"XDP shim shunts local-destined packets to it on a session miss) and "+
				"nft xpf_hostinbound admits configured system-services from ANY "+
				"source with no per-source/per-application deny. The junos-host "+
				"restriction is enforced only on the userspace AF_XDP local-delivery "+
				"path (e.g. DNAT/static-NAT to a firewall-local address), so this "+
				"management-plane restriction may not fully apply to the direct path "+
				"(#4146, known vSRX-parity limitation — see "+
				"docs/host-inbound-service-matrix.md)",
			who, reason)
	}
	// Zone-pair policies: `from-zone X to-zone junos-host { policy ... }`.
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.ToZone != "junos-host" {
			continue
		}
		for _, p := range zpp.Policies {
			if p == nil {
				continue
			}
			if stricter, reason := junosHostPolicyStricterThanCoarseGate(p.Action, p.Match); stricter {
				warnings = append(warnings, msg(fmt.Sprintf(
					"%q (from-zone %q)", p.Name, zpp.FromZone), reason))
			}
		}
	}
	// Global policies with a `match to-zone junos-host` context (#3639). A
	// `match from-zone junos-host` global is already hard-rejected at commit
	// (validatePolicyZoneReferencesStrict), so it never reaches here.
	for _, p := range cfg.Security.GlobalPolicies {
		if p == nil || p.Match.ToZone != "junos-host" {
			continue
		}
		if stricter, reason := junosHostPolicyStricterThanCoarseGate(p.Action, p.Match); stricter {
			warnings = append(warnings, msg(fmt.Sprintf("global %q", p.Name), reason))
		}
	}
	return warnings
}

// validatePreIDDefaultPolicyLogWarnings emits a WARN-only commit-time message
// when `security pre-id-default-policy then log session-init/session-close` is
// configured. The flags are parsed and stored but have no runtime consumer in
// the userspace dataplane (#2509) — there is no pre-identification
// session-admit path to stamp the log mode onto — so the logging action is
// accepted-but-inert. It is never an error: pre-id-default-policy is valid
// Junos and a hard reject would brick a boot on a previously-inert committed
// value.
func validatePreIDDefaultPolicyLogWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	p := cfg.Security.PreIDDefaultPolicy
	if p == nil || (!p.LogSessionInit && !p.LogSessionClose) {
		return nil
	}
	var modes []string
	if p.LogSessionInit {
		modes = append(modes, "session-init")
	}
	if p.LogSessionClose {
		modes = append(modes, "session-close")
	}
	return []string{fmt.Sprintf(
		"security pre-id-default-policy `then log %s` is accepted for "+
			"compatibility but is inert in the userspace dataplane (no "+
			"pre-identification session-admit path exists to emit the "+
			"RT_FLOW session log)",
		strings.Join(modes, "/"))}
}

// validateFilterLossPriorityWarnings emits a WARN-only commit-time message for
// each firewall-filter term carrying `then loss-priority`. The action is parsed
// and stored but has no runtime consumer in the userspace dataplane (#2507), so
// it is accepted-but-inert. It is never an error: loss-priority is valid Junos
// and a hard reject would brick a boot on a previously-inert committed value.
func validateFilterLossPriorityWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var warnings []string
	emit := func(family string, filters map[string]*FirewallFilter) {
		// Stable order: iterate by sorted filter name so warnings are
		// deterministic across commits (map iteration is randomized).
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
				if term == nil || term.LossPriority == "" {
					continue
				}
				warnings = append(warnings, fmt.Sprintf(
					"firewall family %s filter %q term %q `then loss-priority %s` is "+
						"accepted for compatibility but is inert in the userspace "+
						"dataplane (no per-packet loss-priority action is enforced)",
					family, name, term.Name, term.LossPriority))
			}
		}
	}
	emit("inet", cfg.Firewall.FiltersInet)
	emit("inet6", cfg.Firewall.FiltersInet6)
	return warnings
}

// validateLo0FilterKernelMirrorWarnings emits a WARN-only commit-time message
// for each term in an lo0 INPUT filter (`interfaces lo0 unit 0 family inet[6]
// filter input <name>`) that carries a `then` modifier the kernel nftables lo0
// mirror cannot faithfully honor (#3445).
//
// Ordinary host-bound traffic to a firewall interface IP / VRRP VIP is shunted
// to the Linux kernel by the XDP shim before it reaches userspace-dp, so the
// `inet xpf_lo0` nftables chain (pkg/daemon/daemon_nft.go) is the PRIMARY
// enforcement of the lo0 input filter for that traffic. That chain honors the
// match predicates plus `then log`/`then syslog` (nft `log`) and `then count`
// (a named nft counter), but a `hook input` chain has no faithful expression for
// these CoS / rate-control modifiers:
//   - then policer <name>: a Junos policer is a bandwidth+burst token bucket
//     with a configurable then-action (discard / loss-priority); nft `limit`
//     cannot reproduce the bandwidth/burst mapping or the loss-priority action,
//     so mirroring it would silently rate-limit host-bound traffic by a
//     DIFFERENT rule than userspace. The kernel mirror does not enforce it.
//   - then dscp <v> (traffic-class rewrite) / then forwarding-class <fc>: these
//     select egress CoS, which is meaningless for traffic the kernel delivers
//     LOCALLY (there is no egress queue for host-bound packets), so the kernel
//     input mirror performs no rewrite / class selection.
//
// loss-priority is intentionally NOT repeated here: validateFilterLossPriority
// Warnings (#2507) already reports it as globally inert (no per-packet consumer
// in EITHER dataplane), which subsumes the kernel-mirror gap.
//
// It is never an error: these modifiers are valid Junos and a hard reject would
// brick a boot on a previously-committed config; userspace remains authoritative
// for whatever lo0-filtered traffic actually reaches the XSK. The warning names
// the family, filter, term, and modifier so the operator knows the kernel
// host-bound path will not enforce them.
func validateLo0FilterKernelMirrorWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var warnings []string
	emit := func(family, filterName string, filter *FirewallFilter) {
		if filterName == "" || filter == nil {
			return
		}
		for _, term := range filter.Terms {
			if term == nil {
				continue
			}
			// Stable, deterministic per-term modifier order.
			type mod struct{ kind, val string }
			var mods []mod
			if term.Policer != "" {
				mods = append(mods, mod{"policer", term.Policer})
			}
			if term.DSCPRewrite != "" {
				mods = append(mods, mod{"dscp (traffic-class rewrite)", term.DSCPRewrite})
			}
			if term.ForwardingClass != "" {
				mods = append(mods, mod{"forwarding-class", term.ForwardingClass})
			}
			for _, m := range mods {
				warnings = append(warnings, fmt.Sprintf(
					"firewall family %s filter %q term %q `then %s %s` is accepted but "+
						"the kernel lo0 input mirror (nftables xpf_lo0, the PRIMARY "+
						"enforcement for host-bound traffic) cannot honor it; the modifier "+
						"applies only to lo0-filtered traffic that reaches the userspace "+
						"dataplane",
					family, filterName, term.Name, m.kind, m.val))
			}
			// #3724 M04: a routing-instance (policy-based routing) term terminates
			// as ACCEPT on the kernel lo0 input mirror (daemon_nft.go
			// terminate-as-accept, #3427). The accept VERDICT is honored, but the
			// kernel `hook input` chain cannot perform the route-selection the term
			// requests. Warn so the operator knows the PBR route selection is
			// silently NOT performed on the primary host-bound path; userspace-dp
			// remains authoritative for lo0-filtered traffic that reaches the XSK.
			// Not folded into the mods loop above because that loop's message says
			// the modifier "cannot be honored", whereas here the verdict IS honored
			// and only the route selection is dropped.
			if term.RoutingInstance != "" {
				warnings = append(warnings, fmt.Sprintf(
					"firewall family %s filter %q term %q `then routing-instance %s` "+
						"terminates as accept on the kernel lo0 input mirror (nftables "+
						"xpf_lo0, the PRIMARY enforcement for host-bound traffic): the "+
						"verdict is honored but the kernel input hook cannot perform the "+
						"route selection; policy-based routing applies only to "+
						"lo0-filtered traffic that reaches the userspace dataplane",
					family, filterName, term.Name, term.RoutingInstance))
			}
		}
	}
	emit("inet", cfg.System.Lo0FilterInputV4, cfg.Firewall.FiltersInet[cfg.System.Lo0FilterInputV4])
	emit("inet6", cfg.System.Lo0FilterInputV6, cfg.Firewall.FiltersInet6[cfg.System.Lo0FilterInputV6])
	return warnings
}

// validateFilterNoCatchAllWarnings emits a WARN-only commit-time message when a
// firewall filter ATTACHED to an interface (or lo0) input/output hook has no
// terminal catch-all term — i.e. it relies on xpf's implicit-accept of any
// packet that matches no term.
//
// Junos stateless firewall filters carry an implicit final DISCARD: a packet
// matching no explicit term is silently dropped. xpf instead falls through to
// an implicit ACCEPT (userspace-dp/src/filter/engine/eval.rs: a no-match
// evaluation returns FilterResult::default(), whose action is Accept). So an
// imported SRX/Junos allowlist filter (terms that accept specific traffic, no
// final discard) PERMITS everything it did not explicitly match under xpf,
// where it would deny under Junos.
//
// This divergence is DELIBERATE and is not changed at runtime (#3295). A global
// flip of the no-match default to discard would blackhole the classify-and-pass
// OUTPUT filter idiom that rides the implicit accept — concretely the CoS
// `bandwidth-output` filters attached as `interfaces reth0 unit 80 family
// inet/inet6 filter output` (a pure dest-port allowlist with no final
// catch-all), whose unmatched egress would be dropped at TX selection
// (afxdp/tx/cos_classify.rs gates drop on action != Accept). That violates the
// project "keep GOOD" doctrine (#2124/#3261). The research record is
// docs/research/3295-filter-failopen/plan.md; the runtime contract is in
// userspace-dp/src/filter/README.md.
//
// The warning is the operator-visibility mitigation: it surfaces the divergence
// at commit so an operator who WANTS Junos stateless-discard parity can append
// an explicit final `term <last> { then discard; }` (the inverse of Junos's
// "write a final accept"). It is never an error — implicit-accept is the
// documented, intentional default, and a hard reject would brick a boot on a
// previously-accepted committed config.
//
// Scope: only filters actually attached to an input/output hook are checked
// (library/unused filters are skipped to avoid noise). lo0 is covered because
// it is stored as an ordinary interface unit under
// cfg.Interfaces.Interfaces["lo0"].
func validateFilterNoCatchAllWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var warnings []string
	// Stable order: sorted interface names, then sorted unit numbers, so the
	// warning set is deterministic across commits (map iteration is randomized).
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil { // #3494: tolerant/HA-sync path may carry a nil interface
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for unitNum := range ifc.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := ifc.Units[unitNum]
			if unit == nil { // #3494: tolerant/HA-sync path may carry a nil unit
				continue
			}
			// (direction label, referenced filter name, resolved filter). The
			// label mirrors the existing missing-reference warn loop above
			// (input / input-v6 / output / output-v6). A filter that does not
			// resolve is left to that loop (missing-reference warning); this
			// pass only judges a filter that EXISTS and is attached.
			type hook struct {
				dir    string
				name   string
				filter *FirewallFilter
			}
			for _, h := range []hook{
				{"input", unit.FilterInputV4, cfg.Firewall.FiltersInet[unit.FilterInputV4]},
				{"input-v6", unit.FilterInputV6, cfg.Firewall.FiltersInet6[unit.FilterInputV6]},
				{"output", unit.FilterOutputV4, cfg.Firewall.FiltersInet[unit.FilterOutputV4]},
				{"output-v6", unit.FilterOutputV6, cfg.Firewall.FiltersInet6[unit.FilterOutputV6]},
			} {
				if h.name == "" || h.filter == nil {
					continue
				}
				if firewallFilterHasCatchAllTerminator(h.filter) {
					continue
				}
				warnings = append(warnings, fmt.Sprintf(
					"interface %s unit %d: filter %s %q has no terminal "+
						"catch-all term; xpf accepts traffic matching no term "+
						"(Junos stateless filters imply a final discard) — append "+
						"an explicit final `term { then discard; }` for "+
						"Junos-style deny-by-default, or `then accept` to make "+
						"permit-by-default explicit",
					ifName, unitNum, h.dir, h.name))
			}
		}
	}
	return warnings
}

// schedulerHasEffectiveWindow reports whether a compiled scheduler carries any
// window the runtime evaluator (pkg/scheduler.isWithinWindow) can act on: a
// daily/weekday time-of-day arm, an all-day flag, or a start/stop calendar
// range. A scheduler with none of these resolves to fail-closed INACTIVE at
// runtime (#3849/#3858) — ValidateConfig warns on it (#3860). The predicate
// mirrors pkg/scheduler.schedulerHasTimeWindow || schedulerHasDateRange; a
// bare `daily;` or an empty `scheduler x {}` leaves every field zero and
// therefore has no effective window.
func schedulerHasEffectiveWindow(s *SchedulerConfig) bool {
	if s == nil {
		return false
	}
	if s.AllDay || s.StartTime != "" || s.StopTime != "" || len(s.Days) > 0 {
		return true
	}
	if s.StartDate != "" || s.StopDate != "" {
		return true
	}
	return false
}

// firewallFilterHasCatchAllTerminator reports whether the filter contains a
// term that both (a) is a terminating action (`then accept`/`discard`/`reject`
// with no `then next term`) and (b) has a fully unconstrained `from` (matches
// every packet). Such a term governs every packet that reaches it, so the
// filter does not rely on the implicit no-match default. A `then next term` or
// modifier-only fall-through is NOT a terminator; a `then routing-instance` PBR
// term terminates but is not accept/discard/reject and so is not a catch-all.
func firewallFilterHasCatchAllTerminator(f *FirewallFilter) bool {
	if f == nil {
		return false
	}
	for _, t := range f.Terms {
		if t == nil {
			continue
		}
		if firewallTermIsTerminatingAction(t) && firewallTermFromUnconstrained(t) {
			return true
		}
	}
	return false
}

// firewallTermIsTerminatingAction reports whether the term carries an explicit
// terminating action (accept/discard/reject) and is not an explicit
// fall-through (`then next term`). `then routing-instance` (PBR) and
// modifier-only terms (Action == "") are not terminating for this purpose.
func firewallTermIsTerminatingAction(t *FirewallFilterTerm) bool {
	if t.NextTerm {
		return false
	}
	switch t.Action {
	case "accept", "discard", "reject":
		return true
	default:
		return false
	}
}

// firewallTermFromUnconstrained reports whether the term's `from` is empty
// across EVERY match dimension — it matches any packet. This must enumerate all
// match fields on FirewallFilterTerm (types_system.go); a term carrying any
// constraint, including an unresolved/unknown match value (which the dataplane
// keeps verbatim and fails closed on, #3205/#3203/#3307), is constrained and is
// therefore NOT a catch-all. Adding a new match field to FirewallFilterTerm
// requires adding it here.
func firewallTermFromUnconstrained(t *FirewallFilterTerm) bool {
	return len(t.SourceAddresses) == 0 &&
		len(t.DestAddresses) == 0 &&
		len(t.SourcePrefixLists) == 0 &&
		len(t.DestPrefixLists) == 0 &&
		len(t.DSCPs) == 0 &&
		len(t.Protocols) == 0 &&
		len(t.DestinationPorts) == 0 &&
		len(t.SourcePorts) == 0 &&
		len(t.SourcePortsExcept) == 0 &&
		len(t.DestPortsExcept) == 0 &&
		len(t.ICMPTypes) == 0 &&
		len(t.ICMPCodes) == 0 &&
		len(t.UnknownICMPTypes) == 0 &&
		len(t.UnknownICMPCodes) == 0 &&
		len(t.UnknownPorts) == 0 &&
		len(t.TCPFlags) == 0 &&
		!t.IsFragment &&
		t.FlexMatch == nil &&
		len(t.UnknownFlexMatch) == 0 &&
		len(t.UnknownFrom) == 0
}

// validateDDNSBackendWarnings emits WARN-only commit-time messages for the
// now-live DHCP dynamic-DNS backend (#1387 increment 2). It never returns
// an error: the typed schema already accepts these leaves, and a stricter
// HARD reject would brick a boot on a previously-inert malformed value
// (plan §7 Q-C). The reconciler/backend degrade safely at runtime (an
// unusable backend resolves to a no-op and counts a no-backend skip).
func validateDDNSBackendWarnings(cfg *Config) []string {
	d := cfg.System.DHCPServer.DynamicDNS
	if d == nil || !d.Enabled {
		return nil
	}
	var warnings []string

	backend := d.Backend
	if backend == "" {
		backend = "rfc2136"
	}
	switch backend {
	case "rfc2136":
		if d.UpdateServer == "" {
			warnings = append(warnings, "dhcp dynamic-dns is enabled with "+
				"backend rfc2136 but no update-server is configured; no records "+
				"will be published until an update-server is set")
		} else if !ddnsUpdateServerParseable(d.UpdateServer) {
			warnings = append(warnings, fmt.Sprintf("dhcp dynamic-dns "+
				"update-server %q is not a valid host or host:port; the backend "+
				"will fail to send updates", d.UpdateServer))
		}
		if d.TSIGKeyName != "" && !ddnsTSIGAlgorithmSupported(d.TSIGAlgorithm) {
			warnings = append(warnings, fmt.Sprintf("dhcp dynamic-dns "+
				"tsig-algorithm %q is not supported (use hmac-sha1, hmac-sha224, "+
				"hmac-sha256, hmac-sha384, or hmac-sha512; hmac-md5 is rejected as "+
				"insecure); the backend will fail to sign updates", d.TSIGAlgorithm))
		}
		// TSIG tuple completeness (#2666 / #2691 P0): RFC 8945 TSIG needs the
		// full {key name, algorithm, secret} triple. The backend enables
		// signing whenever tsig-key is set and copies the secret without an
		// empty check, so a key without a secret signs with an empty key and
		// a real authoritative server rejects it (BADKEY/BADSIG) at RUNTIME.
		// A secret without a key is silently ignored (no signing happens).
		// Warn at commit so the operator sees the incomplete tuple instead of
		// debugging a runtime failure. WARN-only (never a hard reject): a
		// previously-inert partial TSIG config must not brick a boot.
		keySet := d.TSIGKeyName != ""
		secretSet := d.TSIGSecret.Reveal() != ""
		switch {
		case keySet && !secretSet:
			warnings = append(warnings, "dhcp dynamic-dns tsig-key is set but "+
				"tsig-secret is empty; TSIG signing will use an empty key and the "+
				"authoritative server will reject updates (BADKEY/BADSIG) — set "+
				"tsig-secret to complete the TSIG key")
		case secretSet && !keySet:
			warnings = append(warnings, "dhcp dynamic-dns tsig-secret is set but "+
				"tsig-key is empty; without a key name TSIG signing is disabled and "+
				"the secret is ignored — set tsig-key to enable authenticated "+
				"updates")
		}
	case "kea-d2":
		warnings = append(warnings, "dhcp dynamic-dns backend kea-d2 is "+
			"reserved but not implemented (Kea D2 is not in the image); no "+
			"records will be published with this backend")
	}
	return warnings
}

// ddnsUpdateServerParseable reports whether an update-server string is a
// usable host or host:port (mirrors the backend's normalizeUpdateServer).
func ddnsUpdateServerParseable(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return true
	}
	// No port: treat as a bare host (the backend attaches :53). Reject only
	// when it is obviously not a host (e.g. embedded whitespace).
	return !strings.ContainsAny(s, " \t")
}

// ddnsTSIGAlgorithmSupported reports whether a TSIG algorithm string is one
// the backend can sign with (default hmac-sha256 when unset; hmac-md5
// rejected). Mirrors ddns_rfc2136.canonicalTSIGAlgorithm without importing
// the dhcpserver package into pkg/config.
func ddnsTSIGAlgorithmSupported(algo string) bool {
	a := strings.ToLower(strings.TrimSpace(algo))
	a = strings.TrimSuffix(a, ".")
	switch a {
	case "", "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512":
		return true
	default:
		return false
	}
}

// ddnsKnownDyndns2NameSet mirrors pkg/ddns.dyndns2Endpoints for the commit-time
// completeness warning ONLY (config cannot import pkg/ddns). It must stay in
// sync with that table; a name here but missing there (or vice versa) only
// affects whether the operator gets a "no server" warning, never runtime
// behavior — the runtime resolver in pkg/ddns is authoritative.
var ddnsKnownDyndns2NameSet = map[string]bool{
	"dyn": true, "dyndns": true, "no-ip": true, "noip": true,
	"dynu": true, "easydns": true, "dnsomatic": true,
	// NOTE: duckdns is intentionally NOT here — DuckDNS is its own backend
	// (#2960), not a dyndns2 alias (it uses domains=/token=/OK and clear=true).
}

// ddnsKnownDyndns2Provider reports whether a provider NAME is a recognized
// built-in dyndns2 endpoint (so a missing `server` is not warned).
func ddnsKnownDyndns2Provider(name string) bool {
	return ddnsKnownDyndns2NameSet[strings.ToLower(name)]
}

// ddnsDyndns2ServerValid mirrors pkg/ddns.resolveDyndns2Endpoint's `server`
// parsing for the commit-time warning ONLY (config cannot import pkg/ddns). It
// must stay in sync with that resolver; a divergence only affects whether the
// operator gets a warning at commit — the runtime resolver in pkg/ddns is
// authoritative and fails closed (falls back to no-op) regardless (#3737).
//
// A dyndns2 `server` is either a full update URL (carrying a scheme) or a bare
// host that the resolver suffixes with the canonical /nic/update path over
// HTTPS. URL schemes are case-INSENSITIVE per RFC 3986 §3.1, so a full URL is
// detected by the "://" delimiter and its scheme compared with EqualFold
// ("HTTPS://host" is valid), matching ddnsCheckIPURLValid (#2842). Both cases
// require a non-empty host so a hostless value ("http://", "https:///nic/update",
// ":8080") is flagged at commit instead of failing only at the first publish.
// The input is TrimSpace'd first so it stays in lockstep with the runtime
// resolver, which trims p.Server before parsing; a whitespace-only server is
// treated as empty (the "no server" completeness branch handles it).
func ddnsDyndns2ServerValid(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		// Hostname() (not Host) so a port-only authority is treated as hostless,
		// matching the runtime resolver.
		if err != nil || u.Hostname() == "" {
			return false
		}
		return strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")
	}
	// Bare host → canonical https://<host>/nic/update; validate the host.
	u, err := url.Parse("https://" + s + "/nic/update")
	return err == nil && u.Hostname() != ""
}

// ddnsCheckIPURLValid mirrors pkg/ddns.validateCheckIPURL for the commit-time
// warning ONLY (config cannot import pkg/ddns). It must stay in sync with that
// validator; a divergence only affects whether the operator gets a warning at
// commit — the runtime CheckIP gate in pkg/ddns is authoritative and fails
// closed regardless (#2773). A checkip-url must be an http(s) URL with a host;
// without that gate a typo (ftp://, "not a url", host-less "http://") commits
// silently and then masquerades forever as a transient observation failure,
// suppressing publishing indefinitely. The scheme check is case-INSENSITIVE per
// RFC 3986 §3.1 ("HTTPS://host" is valid); it parses first and compares the
// parsed scheme with EqualFold, matching pkg/ddns.validateCheckIPURL (#2842).
func ddnsCheckIPURLValid(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Scheme, "http") || strings.EqualFold(parsed.Scheme, "https")
}

// ddnsGenericURLTemplateValid mirrors pkg/ddns.validateGenericURLTemplate for
// the commit-time warning ONLY (config cannot import pkg/ddns). It must stay in
// sync with that validator; a divergence only affects whether the operator gets
// a warning at commit — the runtime newGenericBackend gate is authoritative and
// fails closed regardless (#2841). A generic url-template must be a
// case-INSENSITIVE http(s) URL (RFC 3986 §3.1) with a host; without this warning
// a malformed template (no host / wrong scheme) commits silently and then fails
// only at the first publish. It is deliberately TEMPLATE-AWARE and string-based,
// NOT net/url-based: the value carries inadyn %h/%i/%u/%p specifiers (possibly
// in the userinfo, e.g. https://user:%p@host/upd) that are not valid
// percent-encoding and would make url.Parse fail or mangle the string (same
// reason RedactURL is string-based, #2781). Only the scheme + host portion is
// checked; any %-specifier or {{...}} placeholder in userinfo/path/query is
// tolerated. The input is TrimSpace'd before validating so this stays byte-for-
// byte in lockstep with the runtime gate, which trims (newGenericBackend trims
// p.URLTemplate before constructing): a leading-whitespace template must not
// warn at commit while the runtime trims+accepts it (#2841 lockstep fold).
func ddnsGenericURLTemplateValid(tmpl string) bool {
	tmpl = strings.TrimSpace(tmpl)
	i := strings.Index(tmpl, "://")
	if i < 0 {
		return false
	}
	if scheme := tmpl[:i]; !strings.EqualFold(scheme, "http") && !strings.EqualFold(scheme, "https") {
		return false
	}
	authStart := i + len("://")
	authEnd := len(tmpl)
	for j := authStart; j < len(tmpl); j++ {
		if c := tmpl[j]; c == '/' || c == '?' || c == '#' {
			authEnd = j
			break
		}
	}
	authority := tmpl[authStart:authEnd]
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}
	return authority != ""
}

// ddnsAllowlistMalformedTokens mirrors pkg/ddns.ParseAllowlistChecked's
// tokenization for the commit-time warning ONLY (config cannot import pkg/ddns:
// pkg/ddns imports pkg/config). It returns the comma/space/tab-separated tokens
// that are not valid IP addresses. It must stay in sync with the splitter in
// ddns.ParseAllowlistChecked; a divergence only affects whether the operator
// gets a warning at commit — the runtime parse in pkg/ddns is authoritative and
// drops the same tokens (logging once per provider) regardless (#2839).
func ddnsAllowlistMalformedTokens(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var bad []string
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	for _, f := range fields {
		tok := strings.TrimSpace(f)
		if tok == "" {
			continue
		}
		if _, err := netip.ParseAddr(tok); err != nil {
			bad = append(bad, tok)
		}
	}
	return bad
}

// validateSurfaceADDNSWarnings emits WARN-only commit-time messages for the
// Surface A router/interface-address DDNS bindings + provider catalog (#2691
// P2). It never returns an error: the typed schema already accepts the leaves,
// and a hard reject would brick a boot on a previously-inert misconfig. The
// engine degrades safely at runtime (an unresolved provider / missing hostname
// scope resolves to a no-op).
func validateSurfaceADDNSWarnings(cfg *Config) []string {
	var warnings []string

	var catalog map[string]*DDNSProvider
	if cfg.System.Services != nil && cfg.System.Services.DynamicDNS != nil {
		catalog = cfg.System.Services.DynamicDNS.Providers
	}

	// Provider-catalog completeness (rfc2136 backend).
	for name, p := range catalog {
		if p == nil {
			continue
		}
		backend := p.Backend
		if backend == "" {
			backend = "rfc2136"
		}
		switch backend {
		case "rfc2136":
			if p.UpdateServer == "" {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend rfc2136) has no update-server; scopes using it "+
					"publish nothing until an update-server is set", name))
			} else if !ddnsUpdateServerParseable(p.UpdateServer) {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q update-server %q is not a valid host or host:port", name, p.UpdateServer))
			}
			keySet := p.TSIGKeyName != ""
			secretSet := p.TSIGSecret.Reveal() != ""
			switch {
			case keySet && secretSet && !ddnsTSIGAlgorithmSupported(p.TSIGAlgorithm):
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q tsig-algorithm %q is not supported (use hmac-sha1/224/256/"+
					"384/512; hmac-md5 is rejected)", name, p.TSIGAlgorithm))
			case keySet && !secretSet:
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q tsig-key is set but tsig-secret is empty; the server will "+
					"reject updates (BADKEY/BADSIG)", name))
			case secretSet && !keySet:
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q tsig-secret is set but tsig-key is empty; signing is "+
					"disabled and the secret is ignored", name))
			}
		case "dyndns2":
			// dyndns2 needs either a server or a recognizable provider name to
			// resolve the endpoint (#2691 P3). Credentials are optional (some
			// token-in-password providers leave the username empty).
			switch {
			case p.Server == "" && !ddnsKnownDyndns2Provider(name):
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend dyndns2) has no server and no recognized provider "+
					"name; scopes using it publish nothing (set `server`)", name))
			case p.Server != "" && !ddnsDyndns2ServerValid(p.Server):
				// A set `server` that is neither a valid http(s) URL nor a valid bare
				// host is a config error: an uppercase-scheme misparse or a hostless
				// value otherwise commits silently and fails only at the first publish
				// (#3737). The runtime resolver rejects it too (no-op fallback).
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend dyndns2) server %q is not a valid http(s) URL "+
					"or host; scopes using it publish nothing", name, RedactURL(p.Server)))
			}
		case "duckdns":
			// DuckDNS authenticates by TOKEN passed as a query param (#2960). The
			// token comes from the api-token leaf (reused from cloudflare); a
			// missing token publishes nothing (DuckDNS answers KO). The endpoint
			// defaults to the built-in https://www.duckdns.org/update, so `server`
			// is optional (test/mocking only).
			if p.APIToken.Reveal() == "" {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend duckdns) has no api-token; scopes using it "+
					"publish nothing", name))
			}
		case "cloudflare":
			if p.APIToken.Reveal() == "" {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend cloudflare) has no api-token; scopes using it publish "+
					"nothing", name))
			}
			if p.Zone == "" {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend cloudflare) has no zone; scopes using it publish "+
					"nothing", name))
			}
		case "route53":
			if p.AWSAccessKeyID == "" || p.AWSSecretAccessKey.Reveal() == "" {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend route53) is missing aws-access-key / aws-secret-key; "+
					"scopes using it publish nothing", name))
			}
			if p.HostedZoneID == "" {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend route53) has no hosted-zone-id; scopes using it "+
					"publish nothing", name))
			}
		case "generic":
			if p.URLTemplate == "" {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend generic) has no url-template; scopes using it publish "+
					"nothing", name))
			} else if !ddnsGenericURLTemplateValid(p.URLTemplate) {
				// RedactURL the template: it may embed a credential in the userinfo
				// or query (%p/token=...), which must not reach a commit-warning log.
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q url-template %q is not a valid http(s) URL with a host; "+
					"scopes using it publish nothing", name, RedactURL(p.URLTemplate)))
			}
		}

		// checkip-url is a backend-independent, opt-in behind-NAT address source
		// (#2691 P3). A malformed URL is a config error, not a transient: without
		// this warning a typo commits silently and the runtime fetch fails forever,
		// masquerading as a transient observation failure that suppresses publishing
		// indefinitely (#2773). The runtime CheckIP gate fails closed regardless.
		if p.CheckIPURL != "" && !ddnsCheckIPURLValid(p.CheckIPURL) {
			warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
				"provider %q checkip-url %q is not a valid http(s) URL with a host; "+
				"scopes using address-source checkip publish nothing", name, p.CheckIPURL))
		}

		// checkip-allowlist is a bogus-IP safety gate: each entry is an address
		// the checkip parser may accept even though it is otherwise special-purpose
		// (anycast resolvers, etc.). A malformed token (operator typo, e.g.
		// "8.8.8.8x") is otherwise SILENTLY DROPPED by ddns.ParseAllowlist, so the
		// gate silently shrinks and the checkip parser admits the very IP the
		// operator meant to suppress (#2839). Surface the offending tokens at
		// commit; the runtime allowlist parse mirrors this and fails lenient (it
		// logs once per provider and keeps the valid entries). Parsing is mirrored
		// here (not via pkg/ddns) because pkg/ddns imports pkg/config.
		for _, tok := range ddnsAllowlistMalformedTokens(p.CheckIPAllowlist) {
			warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
				"provider %q checkip-allowlist entry %q is not a valid IP address; "+
				"it is ignored, shrinking the bogus-IP allowlist", name, tok))
		}
	}

	// Per-interface binding completeness.
	//
	// duckFamilies tracks, per (provider, FQDN) that resolves to a DuckDNS
	// backend, which address families are bound — to warn about the DuckDNS
	// per-family clobber (#2960). DuckDNS's update API auto-detects and SETS the
	// family whose address parameter is OMITTED ("If you do not specify the IP
	// address, then it will be detected" — duckdns.org/spec.jsp). A Surface A v6
	// scope therefore sends only ipv6= and DuckDNS auto-sets the A from the
	// source IPv4 — overwriting the A the separate v4 scope publishes. Because
	// Surface A scopes are per-family with NO per-FQDN coalescing, a dual-stack
	// DuckDNS name has two scopes that fight on every reconcile (and with
	// source-binding/multi-WAN/NAT the auto-detected A diverges from the
	// configured one). One family per DuckDNS name is the supported topology.
	type duckKey struct{ provider, fqdn string }
	duckFamilies := map[duckKey][]string{}
	isDuckDNS := func(provider string) bool {
		if provider == "" || catalog == nil {
			return false
		}
		p, ok := catalog[provider]
		return ok && p != nil && p.Backend == "duckdns"
	}
	// #3738: dyndns2 has only a HOSTNAME-level withdraw verb (offline=YES takes
	// down BOTH the A and the AAAA). Unlike DuckDNS its per-family UPDATE is fine
	// (myip= sets one family without auto-detecting the other), so the fight is
	// only on WITHDRAW. Track dyndns2 (provider, FQDN) bindings per family so a
	// dual-stack same-name dyndns2 scope is flagged too (DuckDNS was already
	// commit-warned; dyndns2 was not — the codex-157 M06 gap).
	dyndns2Families := map[duckKey][]string{}
	isDyndns2 := func(provider string) bool {
		if provider == "" || catalog == nil {
			return false
		}
		p, ok := catalog[provider]
		return ok && p != nil && p.Backend == "dyndns2"
	}
	if cfg.Interfaces.Interfaces != nil {
		ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
		for n := range cfg.Interfaces.Interfaces {
			ifNames = append(ifNames, n)
		}
		sort.Strings(ifNames)
		for _, ifName := range ifNames {
			ifc := cfg.Interfaces.Interfaces[ifName]
			if ifc == nil {
				continue
			}
			unitNums := make([]int, 0, len(ifc.Units))
			for un := range ifc.Units {
				unitNums = append(unitNums, un)
			}
			sort.Ints(unitNums)
			for _, un := range unitNums {
				unit := ifc.Units[un]
				if unit == nil {
					continue
				}
				check := func(family string, d *InterfaceDynamicDNSConfig) {
					if d == nil {
						return
					}
					loc := fmt.Sprintf("interfaces %s unit %d family %s dynamic-dns", ifName, un, family)
					if d.Hostname == "" {
						warnings = append(warnings, loc+": no hostname is set; nothing will be published")
					}
					if d.Provider == "" {
						warnings = append(warnings, loc+": no provider is set; nothing will be published")
					} else if catalog == nil {
						warnings = append(warnings, fmt.Sprintf("%s references provider %q but no "+
							"`system services dynamic-dns provider` catalog is configured", loc, d.Provider))
					} else if _, ok := catalog[d.Provider]; !ok {
						warnings = append(warnings, fmt.Sprintf("%s references undefined provider %q "+
							"(define it under system services dynamic-dns provider)", loc, d.Provider))
					}
					// #2960: record DuckDNS (provider, FQDN) bindings per family so a
					// dual-stack DuckDNS name (the clobber topology) is flagged below.
					if d.Hostname != "" && isDuckDNS(d.Provider) {
						k := duckKey{provider: d.Provider, fqdn: strings.ToLower(strings.TrimSuffix(d.Hostname, "."))}
						duckFamilies[k] = append(duckFamilies[k], family)
					}
					// #3738: record dyndns2 (provider, FQDN) bindings per family so a
					// dual-stack dyndns2 name (host-level offline withdraw) is flagged.
					if d.Hostname != "" && isDyndns2(d.Provider) {
						k := duckKey{provider: d.Provider, fqdn: strings.ToLower(strings.TrimSuffix(d.Hostname, "."))}
						dyndns2Families[k] = append(dyndns2Families[k], family)
					}
				}
				check("inet", unit.DynamicDNSInet)
				check("inet6", unit.DynamicDNSInet6)
			}
		}
	}

	// #2960: a single DuckDNS name bound on BOTH inet and inet6 is the per-family
	// clobber topology (the v6 scope's update auto-sets the A and vice versa).
	// Warn (not hard-reject, matching this validator's fail-open posture — a hard
	// reject could brick a boot on a previously-inert misconfig); the runtime
	// still publishes, but the operator is told the two families fight.
	duckNames := make([]duckKey, 0, len(duckFamilies))
	for k, fams := range duckFamilies {
		if hasFamily(fams, "inet") && hasFamily(fams, "inet6") {
			duckNames = append(duckNames, k)
		}
	}
	sort.Slice(duckNames, func(i, j int) bool {
		if duckNames[i].provider != duckNames[j].provider {
			return duckNames[i].provider < duckNames[j].provider
		}
		return duckNames[i].fqdn < duckNames[j].fqdn
	})
	for _, k := range duckNames {
		warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
			"provider %q (backend duckdns) hostname %q is bound on BOTH inet and "+
			"inet6: DuckDNS auto-detects and overwrites the family whose address is "+
			"omitted, so the two scopes clobber each other's A/AAAA on every "+
			"reconcile. Bind a DuckDNS name to a single family.", k.provider, k.fqdn))
	}

	// #3738: a single dyndns2 name bound on BOTH inet and inet6 shares one
	// hostname whose only withdraw verb (offline=YES) is HOST-level — it takes
	// both families down. A single-family withdraw therefore cannot be expressed
	// on the wire. The runtime now SUPPRESSES the offline while the sibling family
	// is still published (pkg/ddns backend_dyndns2 DeleteLease, #3738), so the
	// live sibling is preserved — but the withdrawn family's record is left stale
	// until the sibling is also withdrawn. Warn so the operator can prefer
	// separate hostnames per family for a clean per-family teardown.
	dyndns2Names := make([]duckKey, 0, len(dyndns2Families))
	for k, fams := range dyndns2Families {
		if hasFamily(fams, "inet") && hasFamily(fams, "inet6") {
			dyndns2Names = append(dyndns2Names, k)
		}
	}
	sort.Slice(dyndns2Names, func(i, j int) bool {
		if dyndns2Names[i].provider != dyndns2Names[j].provider {
			return dyndns2Names[i].provider < dyndns2Names[j].provider
		}
		return dyndns2Names[i].fqdn < dyndns2Names[j].fqdn
	})
	for _, k := range dyndns2Names {
		warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
			"provider %q (backend dyndns2) hostname %q is bound on BOTH inet and "+
			"inet6: dyndns2's withdraw verb (offline=YES) is HOSTNAME-level and takes "+
			"both families down, so a single-family withdraw cannot be expressed on "+
			"the wire. xpf suppresses the offline while the sibling family is still "+
			"published (the live sibling is preserved; the withdrawn family's record "+
			"is left stale). Use separate hostnames per family for a clean per-family "+
			"teardown.", k.provider, k.fqdn))
	}
	return warnings
}

// hasFamily reports whether fams contains the given family token.
func hasFamily(fams []string, want string) bool {
	for _, f := range fams {
		if f == want {
			return true
		}
	}
	return false
}

// validateRoutingRuleWindowWarnings emits commit-time warnings when a
// config would program more next-table or rib-group ip rules than the
// applier's fixed priority window can hold (see pkg/routing/rules.go:
// nextTableRulePriority window of 100, ribGroupRulePriority window of
// 100 split into 50 v4+v6 pairs). The counts here are CONSERVATIVE
// upper bounds computed from the same inputs the applier consumes —
// they intentionally do NOT replicate the applier's exact skip/dedup
// logic (unknown-instance skips, self-only rib-groups, duplicate source
// tables), so they may warn slightly early but never miss a real
// truncation. The runtime accepts the config; the apply-time cap is the
// hard guard against the rule leak.
func validateRoutingRuleWindowWarnings(cfg *Config) []string {
	var warnings []string

	// next-table: the applier feeds it the global inet + inet6 static
	// routes (daemon_apply.go), counting those with a NextTable set.
	const nextTableWindow = 100
	nextTableRoutes := 0
	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		if sr != nil && sr.NextTable != "" {
			nextTableRoutes++
		}
	}
	for _, sr := range cfg.RoutingOptions.Inet6StaticRoutes {
		if sr != nil && sr.NextTable != "" {
			nextTableRoutes++
		}
	}
	if nextTableRoutes > nextTableWindow {
		warnings = append(warnings, fmt.Sprintf(
			"routing-options: %d static routes use next-table, but only %d can be "+
				"programmed as ip rules; routes beyond the limit will be ignored at "+
				"apply time. Reduce the number of next-table routes.",
			nextTableRoutes, nextTableWindow))
	}

	// rib-group (#3876): the applier now programs one ip rule PER CONNECTED
	// PREFIX of each source instance whose interface-routes rib-group imports
	// the main table, into a fixed window of maxRibGroupLeakRules (1000)
	// priorities that clear() scans. Count the connected prefixes the applier
	// would leak and warn if they exceed the window (an over-count against
	// pkg/routing.maxRibGroupLeakRules — kept in lockstep here).
	const ribGroupLeakLimit = 1000
	leakPrefixes := 0
	for _, prefixes := range RibGroupConnectedPrefixes(cfg) {
		leakPrefixes += len(prefixes)
	}
	if leakPrefixes > ribGroupLeakLimit {
		warnings = append(warnings, fmt.Sprintf(
			"routing-options: interface-routes rib-group would leak %d connected "+
				"prefixes as ip rules, but only %d can be programmed; prefixes beyond "+
				"the limit will be ignored at apply time. Reduce the number of "+
				"rib-group-leaked interface prefixes.",
			leakPrefixes, ribGroupLeakLimit))
	}

	return warnings
}

// validateRibGroupLeakWarnings emits commit-time warnings for
// interface-routes rib-group imports the #3876 Phase-1 per-prefix leak
// cannot fully realize, so the operator sees a fail-loud diagnostic instead
// of a silent no-op:
//
//   - A source instance whose rib-group imports the main table but has NO
//     enumerable static connected prefix (DHCP-only / unaddressed member
//     interfaces): the leak installs no ip rule because there is no static
//     prefix to enumerate at commit. (Runtime route-copy for dynamically
//     learned addresses is the deferred Phase-2 mechanism.)
//   - A rib-group importing a NON-MAIN (VRF→VRF) rib: Phase 1 leaks only into
//     the main table; a VRF→VRF import target is not yet installed (Phase 2).
//
// The strict import-rib reference gate
// (validateRibGroupImportRibReferencesStrict) is unchanged; these are
// additional non-fatal WARN diagnostics.
func validateRibGroupLeakWarnings(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	ribGroups := cfg.RoutingOptions.RibGroups
	if len(ribGroups) == 0 {
		return nil
	}
	definedInstances := make(map[string]bool, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name != "" {
			definedInstances[ri.Name] = true
		}
	}
	connected := RibGroupConnectedPrefixes(cfg)

	var warnings []string
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		// Classify the union of this instance's v4 + v6 rib-group imports.
		importsMain := false
		var vrfTargets []string
		seenVRF := make(map[string]bool)
		for _, rgName := range []string{ri.InterfaceRoutesRibGroup, ri.InterfaceRoutesRibGroupV6} {
			if rgName == "" {
				continue
			}
			rgDef, ok := ribGroups[rgName]
			if !ok {
				continue // unknown group — the reference gate/warn covers it
			}
			for _, ribName := range rgDef.ImportRibs {
				switch ribTargetKind(ribName, ri.Name, definedInstances) {
				case "main":
					importsMain = true
				case "vrf":
					if !seenVRF[ribName] {
						seenVRF[ribName] = true
						vrfTargets = append(vrfTargets, ribName)
					}
				}
			}
		}

		if importsMain && len(connected[ri.Name]) == 0 {
			warnings = append(warnings, fmt.Sprintf(
				"routing-instance %q: interface-routes rib-group imports the main "+
					"table but the instance has no enumerable static connected prefix "+
					"(DHCP-only or unaddressed member interfaces); no leak ip rule is "+
					"installed. Configure a static interface address to leak, or note "+
					"that dynamically learned addresses are not leaked (Phase 2).",
				ri.Name))
		}
		if len(vrfTargets) > 0 {
			sort.Strings(vrfTargets)
			warnings = append(warnings, fmt.Sprintf(
				"routing-instance %q: interface-routes rib-group imports non-main "+
					"rib(s) [%s] (VRF→VRF import); this is not yet installed and takes "+
					"no effect — only imports into the main table (inet.0/inet6.0) leak "+
					"interface routes today (Phase 2 deferral).",
				ri.Name, strings.Join(vrfTargets, ", ")))
		}
	}
	return warnings
}

// validateCoSOversubscriptionWarnings emits commit-time warnings for
// every CoS interface unit whose sum of exact-class transmit rates
// exceeds the unit's configured shaping-rate. Warnings are non-fatal;
// the runtime accepts the config and the new
// oversubscription-policy knob (#1614 A1) governs distribution.
func validateCoSOversubscriptionWarnings(cos *ClassOfServiceConfig) []string {
	var warnings []string
	if cos == nil {
		return warnings
	}
	for ifaceName, iface := range cos.Interfaces {
		if iface == nil {
			continue
		}
		for unitID, unit := range iface.Units {
			if unit == nil || unit.ShapingRateBytes == 0 || unit.SchedulerMap == "" {
				continue
			}
			schedMap, ok := cos.SchedulerMaps[unit.SchedulerMap]
			if !ok || schedMap == nil {
				continue
			}
			var sumExact uint64
			for _, entry := range schedMap.Entries {
				if entry == nil || entry.Scheduler == "" {
					continue
				}
				sched, ok := cos.Schedulers[entry.Scheduler]
				if !ok || sched == nil || !sched.TransmitRateExact {
					continue
				}
				sumExact += sched.TransmitRateBytes
			}
			if sumExact <= unit.ShapingRateBytes {
				continue
			}
			policyTail := "proportional (default): each class receives classRate × shaping / sumExact (current behaviour)"
			if unit.OversubscriptionPolicy == "guarantee-rate" {
				policyTail = fmt.Sprintf(
					"guarantee-rate %g: small classes honoured to configured rate; larger classes share residual proportionally (see #1614)",
					unit.OversubscriptionGuaranteeFraction,
				)
			}
			warnings = append(warnings, fmt.Sprintf(
				"class-of-service interfaces %s unit %d: sum of exact-class transmit-rates (%d B/s) exceeds shaping-rate (%d B/s); under oversubscription the configured oversubscription-policy=%s",
				ifaceName, unitID, sumExact, unit.ShapingRateBytes, policyTail,
			))
		}
	}
	return warnings
}

// classOfServiceClassifierQueueWarnings (#hb166 T-4) flags a behavior-aggregate
// (DSCP / IEEE 802.1p) classifier code-point on this interface unit that maps
// to a DEFINED forwarding-class whose queue is NOT materialized on the unit
// (the forwarding-class has no scheduler-map entry, so the dataplane never
// builds that queue). Pre-fix such a code-point was a 100% silent blackhole;
// the dataplane now fails SAFE and forwards it on the best-effort queue
// (forwarding_build/cos.rs), but the operator should still see that the
// intended queue does not exist on this interface.
//
// This is a WARN, not a strict reject. A classifier steering to a
// forwarding-class that merely lacks a scheduler-map entry is a valid Junos
// config — Junos queues exist by default without a scheduler-map binding — so
// rejecting it (as the dangling-SCHEDULER gate does for an undefined scheduler
// name) would refuse configs Junos accepts and configs xpf's own test suite
// asserts compile.
//
// The materialization + admission model mirrors
// forwarding_build/cos.rs::build_cos_iface_config exactly so the warning fires
// iff the dataplane would have blackholed the code-point: only when the
// interface is actually admitted to CoS (a resolved scheduler-map, a
// shaping-rate, a classifier code-point that DOES hit a materialized queue, or
// a rewrite targeting a materialized class). An un-admitted interface builds no
// CoS runtime, so its classifier is inert and nothing blackholes — no warning.
func classOfServiceClassifierQueueWarnings(cos *ClassOfServiceConfig, ifaceName string, unit *CoSInterfaceUnit) []string {
	if cos == nil || unit == nil {
		return nil
	}
	dscpCls := cos.DSCPClassifiers[unit.DSCPClassifier]
	ieeeCls := cos.IEEE8021Classifiers[unit.IEEE8021Classifier]
	if dscpCls == nil && ieeeCls == nil {
		// No classifier attached (or the reference is undefined — flagged
		// elsewhere): nothing can blackhole.
		return nil
	}

	// Queues this unit materializes: the DEFINED forwarding-classes named by
	// its scheduler-map, else the synthetic best-effort queue 0 when the
	// scheduler-map resolves to nothing.
	matQueues := map[int]bool{}
	schedMapResolved := false
	if unit.SchedulerMap != "" {
		if sm := cos.SchedulerMaps[unit.SchedulerMap]; sm != nil {
			for className := range sm.Entries {
				if fc := cos.ForwardingClasses[className]; fc != nil {
					matQueues[fc.Queue] = true
					schedMapResolved = true
				}
			}
		}
	}
	if !schedMapResolved {
		matQueues = map[int]bool{0: true}
	}

	// Partition the classifier's referenced forwarding-classes into
	// materialized-queue hits vs blackholed (DEFINED class, unmaterialized
	// queue). An UNDEFINED class is skipped — the dataplane drops it from the
	// classifier table and the undefined-class warn already flags it.
	anyHit := false
	blackholed := map[string]int{}
	seen := map[string]bool{}
	classify := func(class string) {
		if class == "" || seen[class] {
			return
		}
		seen[class] = true
		fc := cos.ForwardingClasses[class]
		if fc == nil {
			return
		}
		if matQueues[fc.Queue] {
			anyHit = true
		} else {
			blackholed[class] = fc.Queue
		}
	}
	if dscpCls != nil {
		for _, e := range dscpCls.Entries {
			if e != nil {
				classify(e.ForwardingClass)
			}
		}
	}
	if ieeeCls != nil {
		for _, e := range ieeeCls.Entries {
			if e != nil {
				classify(e.ForwardingClass)
			}
		}
	}

	// A rewrite rule targeting a materialized class also admits the interface.
	rewriteHit := false
	if rr := cos.DSCPRewriteRules[unit.DSCPRewriteRule]; rr != nil {
		for _, e := range rr.Entries {
			if e == nil {
				continue
			}
			if fc := cos.ForwardingClasses[e.ForwardingClass]; fc != nil && matQueues[fc.Queue] {
				rewriteHit = true
				break
			}
		}
	}

	admitted := schedMapResolved || unit.ShapingRateBytes > 0 || anyHit || rewriteHit
	if !admitted || len(blackholed) == 0 {
		return nil
	}

	classes := make([]string, 0, len(blackholed))
	for class := range blackholed {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	warnings := make([]string, 0, len(classes))
	for _, class := range classes {
		warnings = append(warnings, fmt.Sprintf(
			"class-of-service interface %s unit %d classifier maps code-point(s) to forwarding-class %q (queue %d) which has no scheduler-map entry on this interface; the userspace dataplane forwards matching traffic on the best-effort queue",
			ifaceName, unit.Unit, class, blackholed[class]))
	}
	return warnings
}

// anySamplingDirectionConfigured reports whether any interface unit has
// sampling input or output enabled (#3270). It mirrors what
// flowexport.BuildSamplingZones consumes per zone: flow-dir derivation reads
// the per-zone sampling-direction, which is empty when no unit sets either
// flag, in which case the exported flowDirection is a constant 0.
func anySamplingDirectionConfigured(cfg *Config) bool {
	for _, iface := range cfg.Interfaces.Interfaces {
		if iface == nil {
			continue
		}
		for _, unit := range iface.Units {
			if unit == nil {
				continue
			}
			if unit.SamplingInput || unit.SamplingOutput {
				return true
			}
		}
	}
	return false
}
