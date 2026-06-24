package config

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

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

	// Collect valid address-book entries
	addrs := make(map[string]bool)
	if ab := cfg.Security.AddressBook; ab != nil {
		for name := range ab.Addresses {
			addrs[name] = true
		}
		for name := range ab.AddressSets {
			addrs[name] = true
		}
	}

	// Collect valid applications
	apps := make(map[string]bool)
	for name := range cfg.Applications.Applications {
		apps[name] = true
	}
	for name := range cfg.Applications.ApplicationSets {
		apps[name] = true
	}
	// Built-in Junos application names
	builtins := []string{"any", "junos-http", "junos-https", "junos-ssh", "junos-telnet",
		"junos-dns-udp", "junos-dns-tcp", "junos-ping", "junos-icmp-all",
		"junos-bgp", "junos-ospf", "junos-ntp", "junos-dhcp-relay",
		"junos-ftp", "junos-smtp", "junos-icmp6-all", "junos-ike",
		"junos-ipsec-nat-t", "junos-dhcp-client", "junos-dhcp-server",
		"junos-snmp", "junos-syslog", "junos-traceroute", "junos-radius"}
	for _, b := range builtins {
		apps[b] = true
	}

	// Validate application port specs and protocols
	for name, app := range cfg.Applications.Applications {
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
		if !policyZoneDefined(zpp.FromZone) {
			warnings = append(warnings, fmt.Sprintf(
				"policy from-zone %q: zone not defined", zpp.FromZone))
		}
		if !policyZoneDefined(zpp.ToZone) {
			warnings = append(warnings, fmt.Sprintf(
				"policy to-zone %q: zone not defined", zpp.ToZone))
		}
		for _, p := range zpp.Policies {
			for _, addr := range p.Match.SourceAddresses {
				if addr != "any" && !addrs[addr] {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: source-address %q not in address-book", p.Name, addr))
				}
			}
			for _, addr := range p.Match.DestinationAddresses {
				if addr != "any" && !addrs[addr] {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: destination-address %q not in address-book", p.Name, addr))
				}
			}
			for _, app := range p.Match.Applications {
				if !apps[app] {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: application %q not defined", p.Name, app))
				}
			}
		}
	}

	// Validate NAT zone references
	for _, rs := range cfg.Security.NAT.Source {
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
			for _, rule := range rs.Rules {
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
		for _, rule := range rs.Rules {
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
		for _, p := range zpp.Policies {
			if p.SchedulerName != "" {
				if _, ok := cfg.Schedulers[p.SchedulerName]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: scheduler %q not defined", p.Name, p.SchedulerName))
				}
			}
		}
	}
	for _, p := range cfg.Security.GlobalPolicies {
		if p.SchedulerName != "" {
			if _, ok := cfg.Schedulers[p.SchedulerName]; !ok {
				warnings = append(warnings, fmt.Sprintf(
					"global policy %q: scheduler %q not defined", p.Name, p.SchedulerName))
			}
		}
	}

	// Validate routing-instance interface references
	for _, ri := range cfg.RoutingInstances {
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

	// Validate firewall filter references on interfaces
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		for unitNum, unit := range ifc.Units {
			if unit.FilterInputV4 != "" {
				if _, ok := cfg.Firewall.FiltersInet[unit.FilterInputV4]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter input %q not defined",
						ifName, unitNum, unit.FilterInputV4))
				}
			}
			if unit.FilterInputV6 != "" {
				if _, ok := cfg.Firewall.FiltersInet6[unit.FilterInputV6]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter input-v6 %q not defined",
						ifName, unitNum, unit.FilterInputV6))
				}
			}
			if unit.FilterOutputV4 != "" {
				if _, ok := cfg.Firewall.FiltersInet[unit.FilterOutputV4]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter output %q not defined",
						ifName, unitNum, unit.FilterOutputV4))
				}
			}
			if unit.FilterOutputV6 != "" {
				if _, ok := cfg.Firewall.FiltersInet6[unit.FilterOutputV6]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter output-v6 %q not defined",
						ifName, unitNum, unit.FilterOutputV6))
				}
			}
		}
	}

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
		checkExtWarning := func(kind, name string, exts []string) {
			for _, ext := range exts {
				if ext == "app-id" {
					warnings = append(warnings, fmt.Sprintf(
						"flow-monitoring %s template %s: export-extension app-id configured but application data is not available in flow records", kind, name))
				}
			}
		}
		if fm.Version9 != nil {
			for _, tmpl := range fm.Version9.Templates {
				checkExtWarning("version9", tmpl.Name, tmpl.ExportExtensions)
			}
		}
		if fm.VersionIPFIX != nil {
			for _, tmpl := range fm.VersionIPFIX.Templates {
				checkExtWarning("version-ipfix", tmpl.Name, tmpl.ExportExtensions)
			}
		}
	}

	if cos := cfg.ClassOfService; cos != nil {
		warnedClassifierLossPriority := false
		warnedRewriteLossPriority := false
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
		}
		for _, schedMap := range cos.SchedulerMaps {
			if schedMap == nil {
				continue
			}
			for className, entry := range schedMap.Entries {
				if _, ok := cos.ForwardingClasses[className]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service scheduler-map %q references undefined forwarding-class %q",
						schedMap.Name, className))
				}
				if entry == nil || entry.Scheduler == "" {
					continue
				}
				if _, ok := cos.Schedulers[entry.Scheduler]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service scheduler-map %q references undefined scheduler %q",
						schedMap.Name, entry.Scheduler))
				}
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
		for _, iface := range cos.Interfaces {
			if iface == nil {
				continue
			}
			for _, unit := range iface.Units {
				if unit == nil {
					continue
				}
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

	// #1387: DHCP dynamic-DNS live-backend validation. Increment 2 wired the
	// live RFC 2136 backend, so the increment-1 "no records are published"
	// deferred-backend warning is retired. The warnings here flag a config
	// that the now-live path cannot act on (enabled rfc2136 with no
	// update-server), a still-deferred backend (kea-d2), and the now-consumed
	// free-form leaves (update-server parseability, TSIG algorithm support).
	// All are WARN-only (never an error) so a malformed inert value committed
	// against increment 1 cannot brick a boot (plan §4.5 / §7 Q-C).
	warnings = append(warnings, validateDDNSBackendWarnings(cfg)...)

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

	return warnings
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

	// rib-group: the applier walks routing-instances and programs two ip
	// rules (v4+v6) per source table that references an interface-routes
	// rib-group. Window of 100 priorities fits 50 such tables.
	const ribGroupTableLimit = 50
	ribGroupInstances := 0
	for _, inst := range cfg.RoutingInstances {
		if inst == nil {
			continue
		}
		if inst.InterfaceRoutesRibGroup != "" || inst.InterfaceRoutesRibGroupV6 != "" {
			ribGroupInstances++
		}
	}
	if ribGroupInstances > ribGroupTableLimit {
		warnings = append(warnings, fmt.Sprintf(
			"routing-options: %d routing-instances reference an interface-routes "+
				"rib-group, but only %d leaking tables can be programmed as ip rules "+
				"(two priorities each); instances beyond the limit will be ignored at "+
				"apply time. Reduce the number of rib-group-leaking instances.",
			ribGroupInstances, ribGroupTableLimit))
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
