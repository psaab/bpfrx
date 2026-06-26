package userspace

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
)

func deriveUserspaceConfig(cfg *config.Config) config.UserspaceConfig {
	out := config.UserspaceConfig{
		Workers:       1,
		RingEntries:   1024,
		ControlSocket: filepath.Join(os.TempDir(), "xpf-userspace-dp", "control.sock"),
		StateFile:     filepath.Join(os.TempDir(), "xpf-userspace-dp", "state.json"),
	}
	if cfg != nil && cfg.System.UserspaceDataplane != nil {
		out = *cfg.System.UserspaceDataplane
	}
	if out.Workers <= 0 {
		out.Workers = 1
	}
	if out.RingEntries <= 0 {
		out.RingEntries = 1024
	}
	if out.ControlSocket == "" {
		out.ControlSocket = filepath.Join(os.TempDir(), "xpf-userspace-dp", "control.sock")
	}
	if out.StateFile == "" {
		out.StateFile = filepath.Join(filepath.Dir(out.ControlSocket), "state.json")
	}
	if out.EventSocket == "" {
		out.EventSocket = filepath.Join(filepath.Dir(out.ControlSocket), "userspace-dp-events.sock")
	}
	return out
}

func deriveUserspaceCapabilities(cfg *config.Config) UserspaceCapabilities {
	caps := UserspaceCapabilities{ForwardingSupported: true}
	if cfg == nil {
		return caps
	}
	addReason := func(reason string) {
		caps.ForwardingSupported = false
		caps.UnsupportedReasons = append(caps.UnsupportedReasons, reason)
	}
	if !userspaceSupportsSecurityPolicies(cfg) {
		addReason("full security policy semantics are not implemented in the userspace dataplane")
	}
	// Pool-mode source NAT is now implemented in the userspace dataplane
	// (PortAllocator with round-robin address + port allocation).
	// NAT64 is supported — NATv6v4 config (no-v6-frag-header option) is fine
	// Session timeouts (TCP/UDP/ICMP) are supported — only gate on unsupported flow features
	// TCP MSS clamping is supported in the userspace dataplane
	// GRE acceleration (key extraction into session ports) is supported
	if !userspaceSupportsScreenProfiles(cfg) {
		addReason(
			"userspace SYN-cookie screen profiles require system root-authentication encrypted-password material",
		)
	}
	if !userspaceSupportsThreeColorPolicers(cfg) {
		addReason("userspace three-color policers require color-blind mode and then discard")
	}
	if cfg.Chassis.Cluster != nil && userspaceConfigUsesPersistentSourceNAT(cfg) {
		addReason(persistentSourceNATHAUnsupportedReason)
	}
	// Firewall filters and legacy policers are supported in the userspace
	// dataplane. Three-color policers are supported for the color-blind
	// `then discard` runtime slice above; unsupported color-aware and
	// non-drop actions remain fail-closed so the dataplane does not silently
	// promote inherited color or ignore configured treatment.
	// IPsec: kernel XFRM handles ESP encryption/decryption; the userspace
	// dataplane passes ESP/IKE traffic to the kernel via the slow-path.
	// GRE transit is now modeled as native userspace tunnel endpoints on the
	// physical NIC path. Kernel tunnel interfaces remain only for host/control
	// plane compatibility during migration.
	// Port mirroring is supported by the userspace dataplane through the
	// bounded mirror-clone runtime: snapshot mirror configs, per-binding
	// sampling, full-L2 clone delivery, lossy pressure handling, and status
	// counters are all owned by userspace-dp.
	// Flow export (NetFlow v9) is now supported in the userspace dataplane.
	return caps
}

func userspaceConfigUsesPersistentSourceNAT(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.Then.PoolName == "" {
				continue
			}
			pool := cfg.Security.NAT.SourcePools[rule.Then.PoolName]
			if pool != nil && pool.PersistentNAT != nil {
				return true
			}
		}
	}
	return false
}

func userspaceSupportsThreeColorPolicers(cfg *config.Config) bool {
	if cfg == nil {
		return true
	}
	for _, pol := range cfg.Firewall.ThreeColorPolicers {
		if pol == nil {
			continue
		}
		if !pol.ColorBlind {
			return false
		}
		if pol.ThenAction != "" && pol.ThenAction != "discard" {
			return false
		}
	}
	return true
}

func userspaceSupportsSecurityPolicies(cfg *config.Config) bool {
	if cfg == nil {
		return true
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		// SchedulerName and Count are informational — not forwarding-critical.
		// Schedulers define time windows (not DSCP), and counters are advisory.
		if !userspacePolicyAddressesSupported(cfg, pol.Match.SourceAddresses) ||
			!userspacePolicyAddressesSupported(cfg, pol.Match.DestinationAddresses) ||
			!userspacePolicyApplicationsSupported(cfg, pol.Match.Applications) {
			return false
		}
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			if !userspacePolicyAddressesSupported(cfg, pol.Match.SourceAddresses) ||
				!userspacePolicyAddressesSupported(cfg, pol.Match.DestinationAddresses) ||
				!userspacePolicyApplicationsSupported(cfg, pol.Match.Applications) {
				return false
			}
		}
	}
	return true
}

func userspacePolicyAddressesSupported(cfg *config.Config, addrs []string) bool {
	_, ok := expandUserspacePolicyAddresses(cfg, addrs)
	return ok
}

func expandUserspacePolicyAddresses(cfg *config.Config, addrs []string) ([]string, bool) {
	if len(addrs) == 0 {
		return nil, true
	}
	expanded := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	addUnique := func(value string) {
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		expanded = append(expanded, value)
	}
	for _, addr := range addrs {
		switch {
		case addr == "" || addr == "any":
			addUnique("any")
		case isUserspaceLiteralAddress(addr):
			addUnique(normalizeUserspaceLiteralAddress(addr))
		default:
			values, ok := resolveUserspaceAddressBookEntry(cfg, addr)
			if !ok || len(values) == 0 {
				return nil, false
			}
			for _, value := range values {
				if value == "" {
					return nil, false
				}
				if !isUserspaceLiteralAddress(value) {
					return nil, false
				}
				addUnique(normalizeUserspaceLiteralAddress(value))
			}
		}
	}
	sort.Strings(expanded)
	return expanded, true
}

func isUserspaceLiteralAddress(value string) bool {
	if value == "" || value == "any" {
		return true
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return true
	}
	return net.ParseIP(value) != nil
}

func normalizeUserspaceLiteralAddress(value string) string {
	if value == "" || value == "any" {
		return value
	}
	if _, ipNet, err := net.ParseCIDR(value); err == nil && ipNet != nil {
		return ipNet.String()
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return value
}

func resolveUserspaceAddressBookEntry(cfg *config.Config, name string) ([]string, bool) {
	if cfg == nil || cfg.Security.AddressBook == nil || name == "" {
		return nil, false
	}
	addressBook := cfg.Security.AddressBook
	seenSets := make(map[string]bool)
	expanded := make([]string, 0, 4)
	var resolve func(string) bool
	resolve = func(ref string) bool {
		if ref == "" {
			return false
		}
		if addr := addressBook.Addresses[ref]; addr != nil {
			if addr.Value == "" {
				return false
			}
			expanded = append(expanded, addr.Value)
			return true
		}
		set := addressBook.AddressSets[ref]
		if set == nil {
			return false
		}
		if seenSets[ref] {
			return true
		}
		seenSets[ref] = true
		resolvedAny := false
		for _, member := range set.Addresses {
			if !resolve(member) {
				return false
			}
			resolvedAny = true
		}
		for _, member := range set.AddressSets {
			if !resolve(member) {
				return false
			}
			resolvedAny = true
		}
		return resolvedAny
	}
	if !resolve(name) {
		return nil, false
	}
	sort.Strings(expanded)
	expanded = slices.Compact(expanded)
	return expanded, true
}

func userspacePolicyApplicationsSupported(cfg *config.Config, apps []string) bool {
	_, ok := expandUserspacePolicyApplications(cfg, apps)
	return ok
}

func expandUserspacePolicyApplications(cfg *config.Config, apps []string) ([]PolicyApplicationSnapshot, bool) {
	if len(apps) == 0 {
		return nil, true
	}
	expanded := make([]PolicyApplicationSnapshot, 0, len(apps))
	seen := make(map[string]struct{}, len(apps))
	for _, appName := range apps {
		if appName == "" || appName == "any" {
			return nil, true
		}
		resolved, ok := resolveUserspaceApplicationNames(cfg, appName)
		if !ok || len(resolved) == 0 {
			return nil, false
		}
		for _, resolvedName := range resolved {
			app, ok := config.ResolveApplication(resolvedName, cfg.Applications.Applications)
			if !ok || app == nil {
				return nil, false
			}
			proto := normalizeUserspaceApplicationProtocol(app.Protocol)
			if proto == "" {
				return nil, false
			}
			// #2124: fail closed on any protocol the Rust matcher cannot
			// represent. Returning ok=false trips the existing
			// ForwardingSupported=false refuse-to-arm gate
			// (userspaceSupportsSecurityPolicies). Without this a named
			// protocol like esp/ah/sctp (accepted at commit, only lowercased
			// here) reaches the matcher, gets dropped, and the rule collapses
			// to match-any — permitting ALL traffic for the zone pair.
			num, ok := appid.ProtocolNumber(proto)
			if !ok {
				return nil, false
			}
			// Canonicalize to the IANA number any protocol token the Rust
			// matcher could NOT parse before this fix — i.e. anything
			// `rustParsedProtocolBeforeFix` returns false for. In practice that
			// is the newly-supported named set (esp/ah/sctp/vrrp/igmp/pim/egp),
			// but it also covers any other appid-resolvable token outside the
			// pre-fix set (e.g. a junos-* alias such as junos-ospf, were one to
			// reach this path) so a mixed-version helper that predates the new
			// parse_protocol arms still parses it. Tokens the matcher has always
			// understood (tcp/udp/icmp/icmpv6/gre/ospf/ipip + bare numeric) are
			// left as-is to avoid churning the wire form (and the snapshot hash)
			// for every existing policy.
			if !rustParsedProtocolBeforeFix(proto) {
				proto = strconv.Itoa(int(num))
			}
			// #2124: ports must parse the way the Rust parse_port_spec does;
			// a malformed port would otherwise drop the term and collapse the
			// rule to match-any (the same fail-open as the protocol case).
			if !userspacePortSpecRepresentable(app.SourcePort) ||
				!userspacePortSpecRepresentable(app.DestinationPort) {
				return nil, false
			}
			snap := PolicyApplicationSnapshot{
				Name:            resolvedName,
				Protocol:        proto,
				SourcePort:      app.SourcePort,
				DestinationPort: app.DestinationPort,
				// #3020: carry the optional ICMP/ICMPv6 type/code constraint so
				// the Rust matcher enforces junos-ping == echo-request only,
				// rather than matching every ICMP type like junos-icmp-all.
				// nil stays nil (the all-ICMP aliases remain unconstrained).
				ICMPType: app.ICMPType,
				ICMPCode: app.ICMPCode,
				// #3227: carry the per-application inactivity (idle) timeout so
				// the userspace session GC ages a flow admitted by this app out
				// on the app's timeout, not the global per-protocol timeout
				// (the legacy eBPF maps wired this `appTimeout`; closing the
				// userspace parity regression). 0 = use the global timeout
				// (back-compat, byte-identical). A negative configured value is
				// impossible (the parser stores a non-negative int), but clamp
				// defensively so a stray value can never wrap the u32.
				InactivityTimeout: clampNonNegU32(app.InactivityTimeout),
			}
			key := strings.Join([]string{snap.Name, snap.Protocol, snap.SourcePort, snap.DestinationPort,
				icmpKeyPart(snap.ICMPType), icmpKeyPart(snap.ICMPCode),
				strconv.FormatUint(uint64(snap.InactivityTimeout), 10)}, "\x00")
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			expanded = append(expanded, snap)
		}
	}
	sort.Slice(expanded, func(i, j int) bool {
		if expanded[i].Name != expanded[j].Name {
			return expanded[i].Name < expanded[j].Name
		}
		if expanded[i].Protocol != expanded[j].Protocol {
			return expanded[i].Protocol < expanded[j].Protocol
		}
		if expanded[i].SourcePort != expanded[j].SourcePort {
			return expanded[i].SourcePort < expanded[j].SourcePort
		}
		if expanded[i].DestinationPort != expanded[j].DestinationPort {
			return expanded[i].DestinationPort < expanded[j].DestinationPort
		}
		// #3020: keep ICMP type/code in the sort key so two terms differing
		// ONLY by the ICMP constraint (e.g. junos-ping vs junos-icmp-all, both
		// proto icmp, no ports) order deterministically across HA peers.
		if k := icmpKeyPart(expanded[i].ICMPType); k != icmpKeyPart(expanded[j].ICMPType) {
			return k < icmpKeyPart(expanded[j].ICMPType)
		}
		return icmpKeyPart(expanded[i].ICMPCode) < icmpKeyPart(expanded[j].ICMPCode)
	})
	return expanded, true
}

// icmpKeyPart renders an optional ICMP type/code constraint as a stable string
// for snapshot-term dedup + deterministic ordering (#3020). A nil constraint
// (match-all) sorts before any concrete value so it is distinct from type/code
// 0 (the "" vs "0" distinction the dedup key relies on).
func icmpKeyPart(v *uint8) string {
	if v == nil {
		return ""
	}
	return strconv.Itoa(int(*v))
}

// clampNonNegU32 converts a configured seconds value to the wire u32. A value
// <= 0 means "use the global per-protocol timeout" (the back-compat sentinel),
// so it maps to 0; a positive value passes through, saturating at the u32 max
// so a pathological config can never wrap. #3227.
func clampNonNegU32(v int) uint32 {
	if v <= 0 {
		return 0
	}
	if v > int(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(v)
}

func resolveUserspaceApplicationNames(cfg *config.Config, name string) ([]string, bool) {
	if cfg == nil || name == "" {
		return nil, false
	}
	if _, ok := config.ResolveApplication(name, cfg.Applications.Applications); ok {
		return []string{name}, true
	}
	if _, ok := config.ResolveApplicationSet(name, cfg.Applications.ApplicationSets); ok {
		expanded, err := config.ExpandApplicationSet(name, &cfg.Applications)
		if err != nil || len(expanded) == 0 {
			return nil, false
		}
		sort.Strings(expanded)
		return slices.Compact(expanded), true
	}
	return nil, false
}

func normalizeUserspaceApplicationProtocol(proto string) string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "icmp6":
		return "icmpv6"
	default:
		return strings.ToLower(strings.TrimSpace(proto))
	}
}

// rustParsedProtocolBeforeFix reports whether the Rust dataplane's
// parse_protocol recognized this protocol token PRIOR to #2124 (the named arms
// {tcp,udp,icmp,icmpv6,gre,ospf,ipip} plus any pure-numeric token). Such tokens
// are emitted on the wire unchanged so existing policy snapshots keep their
// current protocol string (and hash); only the newly-supported named protocols
// are canonicalized to their number for old-helper compatibility. `proto` is
// already lowercased by normalizeUserspaceApplicationProtocol.
func rustParsedProtocolBeforeFix(proto string) bool {
	switch proto {
	case "tcp", "udp", "icmp", "icmpv6", "gre", "ospf", "ipip":
		return true
	}
	// A bare numeric token (e.g. "132") was always parsed by parse_protocol's
	// numeric fallback.
	if _, err := strconv.ParseUint(proto, 10, 8); err == nil {
		return true
	}
	return false
}

// userspacePortSpecRepresentable reports whether a policy application port spec
// parses the way the Rust dataplane's parse_port_spec does (#2124). It must stay
// in lock-step with userspace-dp/src/policy.rs::parse_port_spec, because a spec
// this gate accepts but Rust rejects would silently drop the term and collapse
// the rule to match-any (the same fail-open this fix closes). Empty means "no
// port constraint" (ok); known service aliases resolve to a single port; a bare
// number must be 1..65535; a low-high range needs low > 0 && low <= high.
//
// The service-alias match is CASE-SENSITIVE on the raw spec, mirroring Rust
// `parse_port_spec` exactly (it matches `"http"` literally and does NOT
// lowercase). Lowercasing here would accept e.g. "HTTP" that Rust would reject
// and then drop — the precise mismatch that reopens the fail-open.
func userspacePortSpecRepresentable(spec string) bool {
	if spec == "" {
		return true
	}
	switch spec {
	case "http", "https", "ssh", "telnet", "ftp", "ftp-data", "smtp",
		"dns", "pop3", "imap", "snmp", "ntp", "bgp", "ldap", "syslog":
		return true
	}
	if low, high, found := strings.Cut(spec, "-"); found {
		l, errL := strconv.ParseUint(low, 10, 16)
		h, errH := strconv.ParseUint(high, 10, 16)
		if errL != nil || errH != nil {
			return false
		}
		return l != 0 && l <= h
	}
	p, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return false
	}
	return p != 0
}

func userspaceSupportsSourceNAT(ruleSets []*config.NATRuleSet) bool {
	for _, rs := range ruleSets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			if rule.Then.Interface || rule.Then.Off {
				continue
			}
			return false
		}
	}
	return true
}
