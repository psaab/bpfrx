package ipsec

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// childSelector is a resolved child SA traffic-selector pair for swanctl
// config generation.
type childSelector struct {
	Name     string
	LocalTS  string
	RemoteTS string
}

func (m *Manager) generateConfig(ipsecCfg *config.IPsecConfig) string {
	cfg, _ := m.renderConfig(ipsecCfg)
	return cfg
}

func (m *Manager) renderConfig(ipsecCfg *config.IPsecConfig) (string, error) {
	var b strings.Builder

	b.WriteString("# xpf managed config - do not edit\n\n")

	// skipped records VPNs whose gateway reference is not renderable
	// (#2074) so the secrets loop below emits no orphan ike-<name> secret
	// for a connection that was never written.
	skipped := make(map[string]bool)

	// Connections
	b.WriteString("connections {\n")
	for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
		vpn := ipsecCfg.VPNs[name]

		// Resolve the remote gateway endpoint. remote_addrs must be a
		// real IP / hostname strongSwan can use — never a bare gateway
		// config-object name (#2074). The hard diagnostic for a bad
		// reference is the commit-time validator
		// (validateIPsecGatewayReferencesStrict); this render belt is the
		// by-construction backstop for any path that reaches render
		// without passing local commit (HA peer-sync, direct
		// IPsecConfig construction, a config persisted before the fix).
		remoteAddr, localAddr, gw, ok := resolveRemoteAddr(ipsecCfg, vpn)
		if !ok {
			skipped[name] = true
			slog.Warn("skipping IPsec VPN: ike gateway not renderable "+
				"(undefined or addressless) — fix the gateway reference",
				"vpn", name, "gateway", vpn.Gateway)
			continue
		}

		// Resolve the IKE settings BEFORE writing the connection block so a
		// gateway whose ike-policy chain does not resolve SKIPS this VPN
		// instead of emitting a proposal-less connection (#2270). An empty
		// `proposals =` line lets strongSwan fall back to its compiled-in
		// default phase-1 set — a silent crypto downgrade. The hard
		// diagnostic for a dangling reference is the commit-time validator
		// (validateIKEPolicyChainReferencesStrict); this render belt is the
		// by-construction backstop for any path that reaches render without
		// passing local commit (HA peer-sync, direct IPsecConfig
		// construction, a config persisted before the fix). One bad
		// reference never zeroes a healthy tunnel. A non-chain resolve error
		// (e.g. an unknown auth-method token from authMethodToSwan) is a
		// different class and still aborts the whole render.
		authMethod, ikeProposals, ikeLifetime, aggressive, err := resolveIKESettings(ipsecCfg, gw)
		if err != nil {
			if errors.Is(err, errIKEChainUnresolved) {
				skipped[name] = true
				slog.Warn("skipping IPsec VPN: ike-policy chain does not "+
					"resolve — fix the ike-policy / ike-proposal reference "+
					"(emitting no proposal would silently downgrade phase-1 "+
					"to strongSwan defaults)",
					"vpn", name, "ike_policy", gw.IKEPolicy)
				continue
			}
			return "", fmt.Errorf("vpn %s: %w", name, err)
		}

		fmt.Fprintf(&b, "  %s {\n", sanitizeSwanctlValue(name))
		espProposals, espLifetime := resolveESPSettings(ipsecCfg, vpn)
		dpd := deriveDPD(gw, vpn)

		// IKE version
		if gw != nil && gw.Version == "v2-only" {
			b.WriteString("    version = 2\n")
		} else if gw != nil && gw.Version == "v1-only" {
			b.WriteString("    version = 1\n")
		}

		if aggressive {
			b.WriteString("    aggressive = yes\n")
		}

		if localAddr != "" {
			fmt.Fprintf(&b, "    local_addrs = %s\n", localAddr)
		}
		if remoteAddr != "" {
			fmt.Fprintf(&b, "    remote_addrs = %s\n", remoteAddr)
		}

		// NAT traversal
		if gw != nil {
			switch gw.NATTraversal {
			case "disable":
				b.WriteString("    encap = no\n")
			case "force":
				b.WriteString("    encap = yes\n")
				b.WriteString("    forceencaps = yes\n")
			default:
				// "enable" or empty = strongSwan default (auto-detect NAT)
				if gw.NoNATTraversal {
					b.WriteString("    encap = no\n")
				}
			}
		}

		if dpd.Delay > 0 {
			fmt.Fprintf(&b, "    dpd_delay = %ds\n", dpd.Delay)
		}
		if dpd.Timeout > 0 {
			fmt.Fprintf(&b, "    dpd_timeout = %ds\n", dpd.Timeout)
		}

		// Local auth section
		b.WriteString("    local {\n")
		fmt.Fprintf(&b, "      auth = %s\n", authMethod)
		if gw != nil && gw.LocalCertificate != "" {
			fmt.Fprintf(&b, "      certs = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(gw.LocalCertificate)))
		}
		if gw != nil && gw.LocalIDValue != "" {
			// Quote + escape the identity: a distinguished-name id with
			// spaces/commas (id = CN=fw, O=acme) is mis-parsed when
			// emitted unquoted, and swanctl accepts a quoted value for
			// every identity type (@fqdn, IP, DN) (#2126).
			fmt.Fprintf(&b, "      id = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(formatIdentity(gw.LocalIDType, gw.LocalIDValue))))
		}
		b.WriteString("    }\n")

		// Remote auth section
		b.WriteString("    remote {\n")
		fmt.Fprintf(&b, "      auth = %s\n", authMethod)
		if gw != nil && gw.RemoteIDValue != "" {
			fmt.Fprintf(&b, "      id = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(formatIdentity(gw.RemoteIDType, gw.RemoteIDValue))))
		}
		b.WriteString("    }\n")

		if ikeProposals != "" {
			fmt.Fprintf(&b, "    proposals = %s\n", ikeProposals)
		}
		if ikeLifetime > 0 {
			fmt.Fprintf(&b, "    rekey_time = %ds\n", ikeLifetime)
			b.WriteString("    rand_time = 0s\n")
		}

		// Start immediately?
		if vpn.EstablishTunnels == "immediately" {
			b.WriteString("    start_action = start\n")
		}

		// Compute XFRM interface ID from bind-interface name
		ifID := xfrmiIfID(vpn.BindInterface)

		fmt.Fprintf(&b, "    children {\n")
		for _, child := range effectiveTrafficSelectors(name, vpn) {
			fmt.Fprintf(&b, "      %s {\n", sanitizeSwanctlValue(child.Name))
			if child.LocalTS != "" {
				fmt.Fprintf(&b, "        local_ts = %s\n", child.LocalTS)
			}
			if child.RemoteTS != "" {
				fmt.Fprintf(&b, "        remote_ts = %s\n", child.RemoteTS)
			}
			fmt.Fprintf(&b, "        esp_proposals = %s\n", espProposals)
			if espLifetime > 0 {
				fmt.Fprintf(&b, "        rekey_time = %ds\n", espLifetime)
				b.WriteString("        rand_time = 0s\n")
			}
			if vpn.DFBit == "copy" {
				fmt.Fprintf(&b, "        copy_df = yes\n")
			} else if vpn.DFBit == "set" {
				fmt.Fprintf(&b, "        copy_df = no\n")
			}
			if vpn.EstablishTunnels == "immediately" {
				fmt.Fprintf(&b, "        start_action = start\n")
			}
			if dpd.Action != "" {
				fmt.Fprintf(&b, "        dpd_action = %s\n", dpd.Action)
			}
			if ifID > 0 {
				fmt.Fprintf(&b, "        if_id_in = %d\n", ifID)
				fmt.Fprintf(&b, "        if_id_out = %d\n", ifID)
			}
			fmt.Fprintf(&b, "      }\n")
		}
		fmt.Fprintf(&b, "    }\n")

		fmt.Fprintf(&b, "  }\n")
	}
	b.WriteString("}\n\n")

	// Secrets — resolve PSK from IKE policy chain
	b.WriteString("secrets {\n")
	for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
		if skipped[name] {
			// No connection was written for this VPN (#2074) — emit no
			// orphan ike-<name> secret.
			continue
		}
		vpn := ipsecCfg.VPNs[name]
		secret := vpn.PSK.Reveal()
		// Resolve PSK from IKE policy chain: VPN -> gateway -> IKE policy -> PSK
		if secret == "" {
			if gw, ok := ipsecCfg.Gateways[vpn.Gateway]; ok {
				if ikePol, ok := ipsecCfg.IKEPolicies[gw.IKEPolicy]; ok {
					secret = ikePol.PSK.Reveal()
				}
			}
		}
		if secret != "" {
			decoded, err := normalizePSK(secret)
			if err != nil {
				return "", fmt.Errorf("vpn %s: %w", name, err)
			}
			fmt.Fprintf(&b, "  ike-%s {\n", sanitizeSwanctlValue(name))
			// sanitizeSwanctlValue strips control chars (#1798); the
			// quote/backslash escaper (#2126) makes a PSK containing a
			// double-quote or backslash render as a balanced, swanctl-
			// parseable quoted string instead of corrupting the block.
			fmt.Fprintf(&b, "    secret = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(decoded)))
			fmt.Fprintf(&b, "  }\n")
		}
	}
	b.WriteString("}\n")

	return b.String(), nil
}

// resolveRemoteAddr resolves the swanctl remote_addrs value (a real IP /
// dotted hostname) for a VPN, plus the effective local address and the
// resolved gateway. ok=false means there is nothing usable to render —
// the caller MUST skip the connection so a bare gateway config-object
// NAME never leaks into remote_addrs (#2074):
//
//   - defined gateway with an address / dynamic hostname -> remote = that
//   - defined gateway flagged responder-only (dynamic, no addr/host)
//     -> remote = "%any" (strongSwan responds, never initiates) (#2404)
//   - defined gateway with neither + not responder-only   -> ok=false
//   - no gateway object, vpn.Gateway is a usable IP/host -> remote = it
//   - no gateway object, vpn.Gateway empty               -> ok=true,
//     remote="" (connection emitted with no remote_addrs line, as before)
//   - no gateway object, vpn.Gateway a dangling/dotless name -> ok=false
//
// This mirrors the commit-time validator validateIPsecGatewayReferencesStrict
// exactly, using the same config.IsUsableIPsecEndpoint predicate.
func resolveRemoteAddr(ipsecCfg *config.IPsecConfig, vpn *config.IPsecVPN) (
	remoteAddr, localAddr string, gw *config.IPsecGateway, ok bool) {

	localAddr = vpn.LocalAddr
	if g, found := ipsecCfg.Gateways[vpn.Gateway]; found {
		gw = g
		switch {
		case gw.Address != "":
			remoteAddr = gw.Address
		case gw.DynamicHostname != "":
			remoteAddr = gw.DynamicHostname
		case gw.ResponderOnly:
			// Responder-only / dynamic-IP peer (#2404): the peer initiates
			// from an unknown source address, so strongSwan listens with
			// remote_addrs = %any and never initiates to this gateway.
			remoteAddr = "%any"
		default:
			// Gateway exists but has nothing routable and is not flagged
			// responder-only. Do NOT fall back to the object name.
			return "", localAddr, gw, false
		}
		if gw.LocalAddress != "" && localAddr == "" {
			localAddr = gw.LocalAddress
		}
		return remoteAddr, localAddr, gw, true
	}
	if vpn.Gateway == "" {
		// Legitimately omitted remote endpoint — emit the connection with
		// no remote_addrs line (unchanged behavior).
		return "", localAddr, nil, true
	}
	if config.IsUsableIPsecEndpoint(vpn.Gateway) {
		// Legacy inline shape: the VPN names the peer endpoint directly
		// as a literal IP or dotted hostname, with no Gateways entry.
		return vpn.Gateway, localAddr, nil, true
	}
	// Dangling / dotless single-label name — not a known gateway and not
	// a usable IP/hostname. Rendering it would leak the name.
	return "", localAddr, nil, false
}

func sortedVPNNames(vpns map[string]*config.IPsecVPN) []string {
	names := make([]string, 0, len(vpns))
	for name := range vpns {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func effectiveTrafficSelectors(connName string, vpn *config.IPsecVPN) []childSelector {
	// A nil VPN has no traffic selectors and no LocalID/RemoteID to fall
	// back to — return no children rather than dereferencing vpn. The
	// sole caller iterates non-nil config VPN map values, so this guard
	// is defensive, but the previous nil branch panicked on vpn.LocalID.
	if vpn == nil {
		return nil
	}
	if len(vpn.TrafficSelectors) == 0 {
		return []childSelector{{
			Name:     connName,
			LocalTS:  vpn.LocalID,
			RemoteTS: vpn.RemoteID,
		}}
	}

	names := make([]string, 0, len(vpn.TrafficSelectors))
	for name := range vpn.TrafficSelectors {
		names = append(names, name)
	}
	sort.Strings(names)

	children := make([]childSelector, 0, len(names))
	for _, name := range names {
		ts := vpn.TrafficSelectors[name]
		localTS := vpn.LocalID
		remoteTS := vpn.RemoteID
		if ts.LocalIP != "" {
			localTS = ts.LocalIP
		}
		if ts.RemoteIP != "" {
			remoteTS = ts.RemoteIP
		}
		children = append(children, childSelector{
			Name:     connName + "-" + sanitizeChildName(name),
			LocalTS:  localTS,
			RemoteTS: remoteTS,
		})
	}
	return children
}

// sanitizeSwanctlValue strips ASCII control characters — the C0 set
// (0x00-0x1F, including newline) and DEL (0x7F), each replaced by a
// space — from a free-text config value (connection name, IKE
// identity, certificate name, pre-shared key) before it is
// interpolated into a generated swanctl.conf line. Render-side belt
// for #1798: an embedded newline must not be able to inject extra
// swanctl sections/keys even if the commit-time validation layer were
// bypassed.
func sanitizeSwanctlValue(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] < 0x20 || b[i] == 0x7f {
			b[i] = ' '
		}
	}
	return string(b)
}

// escapeSwanctlQuoted escapes a string for safe inclusion inside a
// swanctl double-quoted value (secret = "...", id = "...",
// certs = "..."). The swanctl settings lexer treats a bare double-quote
// as the string terminator and processes backslash escapes inside
// quotes (\\ -> a literal backslash, \" -> a literal double-quote).
// Without escaping, a value containing a double-quote — legal in a real
// pre-shared key or a distinguished-name identity — truncates or
// corrupts the rendered config (#2126).
//
// Order matters: backslashes are doubled FIRST, then double-quotes are
// escaped. Escaping quotes first would let the second pass double the
// backslash it just inserted. A literal backslash renders as \\ (lexer
// \\. -> \) and a literal " renders as \" (lexer \\. -> "), so a PSK
// like `a\nb` renders as `a\\nb` and round-trips to the literal
// backslash + n, never the \n newline escape.
func escapeSwanctlQuoted(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func sanitizeChildName(name string) string {
	if name == "" {
		return "traffic-selector"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		return "traffic-selector"
	}
	return out
}

// formatIdentity formats an IKE identity for strongSwan.
func formatIdentity(idType, idValue string) string {
	switch idType {
	case "hostname", "fqdn":
		return "@" + idValue
	default: // "inet", "ipv4", etc.
		return idValue
	}
}

func authMethodToSwan(method string) (string, error) {
	switch method {
	case "", "pre-shared-keys":
		return "psk", nil
	case "rsa-signatures", "ecdsa-signatures":
		return "pubkey", nil
	default:
		return "", fmt.Errorf("unsupported IKE authentication-method %q", method)
	}
}

// xfrmiIfID derives the XFRM interface ID from a bind-interface name.
func xfrmiIfID(bindIface string) uint32 {
	_, ifID := config.XFRMIfNameAndID(bindIface)
	return ifID
}

// PrepareConfig resolves runtime-only IPsec values from the full config.
// The returned config is a deep copy that can be safely mutated by the IPsec
// runtime without affecting the active config tree.
func PrepareConfig(cfg *config.Config) *config.IPsecConfig {
	if cfg == nil {
		return nil
	}

	src := &cfg.Security.IPsec
	out := &config.IPsecConfig{
		IKEProposals: make(map[string]*config.IKEProposal, len(src.IKEProposals)),
		IKEPolicies:  make(map[string]*config.IKEPolicy, len(src.IKEPolicies)),
		Gateways:     make(map[string]*config.IPsecGateway, len(src.Gateways)),
		Proposals:    make(map[string]*config.IPsecProposal, len(src.Proposals)),
		Policies:     make(map[string]*config.IPsecPolicyDef, len(src.Policies)),
		VPNs:         make(map[string]*config.IPsecVPN, len(src.VPNs)),
	}

	for name, prop := range src.IKEProposals {
		cp := *prop
		out.IKEProposals[name] = &cp
	}
	for name, pol := range src.IKEPolicies {
		cp := *pol
		out.IKEPolicies[name] = &cp
	}
	for name, gw := range src.Gateways {
		cp := *gw
		if cp.LocalAddress == "" && cp.ExternalIface != "" {
			cp.LocalAddress = resolveInterfaceAddress(
				cfg, cp.ExternalIface, gatewayRemoteFamilyHint(&cp))
		}
		out.Gateways[name] = &cp
	}
	for name, prop := range src.Proposals {
		cp := *prop
		out.Proposals[name] = &cp
	}
	for name, pol := range src.Policies {
		cp := *pol
		out.Policies[name] = &cp
	}
	for name, vpn := range src.VPNs {
		cp := *vpn
		if vpn.TrafficSelectors != nil {
			cp.TrafficSelectors = make(map[string]*config.IPsecTrafficSelector, len(vpn.TrafficSelectors))
			for tsName, ts := range vpn.TrafficSelectors {
				tsCopy := *ts
				cp.TrafficSelectors[tsName] = &tsCopy
			}
		}
		out.VPNs[name] = &cp
	}

	return out
}

// HasDHCPBoundGateway reports whether any IPsec gateway resolves its
// local bind address DYNAMICALLY from a DHCP-managed interface — i.e.
// the gateway sets external-interface, carries no explicit
// local-address (so PrepareConfig resolves local_addrs at apply time),
// and the referenced interface unit is DHCP/DHCPv6-managed. Such a
// gateway's swanctl local_addrs tracks the lease, so a runtime lease
// change (DHCP renew to a new address) must trigger a swanctl
// re-render; otherwise strongSwan keeps binding to the stale IP and the
// tunnel cannot re-establish (#2884).
//
// It returns false when no gateway is lease-dependent, letting the
// daemon skip the swanctl re-render on unrelated DHCP lease refreshes
// (e.g. a management-only interface no IPsec gateway uses) and avoid an
// SA-resetting reload storm.
func HasDHCPBoundGateway(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, gw := range cfg.Security.IPsec.Gateways {
		if gw == nil || gw.ExternalIface == "" || gw.LocalAddress != "" {
			continue
		}
		if interfaceRefIsDHCP(cfg, gw.ExternalIface) {
			return true
		}
	}
	return false
}

// interfaceRefIsDHCP reports whether the interface reference (e.g.
// "ge-0/0/0" or "ge-0/0/0.0") names a unit configured for DHCPv4 or
// DHCPv6. A bare reference (no unit) matches if ANY of the interface's
// units is DHCP-managed. Mirrors resolveConfiguredInterfaceAddress's
// base/unit parsing so the two derivations cannot drift.
func interfaceRefIsDHCP(cfg *config.Config, ifaceRef string) bool {
	parts := strings.SplitN(ifaceRef, ".", 2)
	ifc, ok := cfg.Interfaces.Interfaces[parts[0]]
	if !ok || ifc == nil {
		return false
	}
	if len(parts) == 2 {
		if n, err := strconv.Atoi(parts[1]); err == nil {
			unit, ok := ifc.Units[n]
			return ok && unit != nil && (unit.DHCP || unit.DHCPv6)
		}
		return false
	}
	for _, unit := range ifc.Units {
		if unit != nil && (unit.DHCP || unit.DHCPv6) {
			return true
		}
	}
	return false
}

// resolveInterfaceAddress selects the local-address to bind for an IKE SA
// from the external interface, constrained to the remote gateway's address
// family. family is the resolved remote family hint (4, 6, or 0 for
// "either" — see gatewayRemoteFamilyHint). Constraining by family is what
// keeps a dual-stack appliance from sourcing the SA out of the wrong family
// vs the resolved peer (#2757): if the remote is/resolves to IPv6, the IPv6
// local-address is chosen, and vice versa.
//
// When the constrained family yields no local-address on the interface (the
// interface is single-stack in the other family), we fall back to a
// family-agnostic selection so a misconfiguration degrades to the legacy
// behavior rather than emitting no local_addrs line at all.
func resolveInterfaceAddress(cfg *config.Config, ifaceRef string, family int) string {
	if addr := resolveInterfaceAddressFamily(cfg, ifaceRef, family); addr != "" {
		return addr
	}
	if family != 0 {
		// The remote family has no matching local-address on this
		// interface — fall back to whatever the interface offers rather
		// than rendering an empty local_addrs.
		return resolveInterfaceAddressFamily(cfg, ifaceRef, 0)
	}
	return ""
}

func resolveInterfaceAddressFamily(cfg *config.Config, ifaceRef string, family int) string {
	if addr := resolveConfiguredInterfaceAddress(cfg, ifaceRef, family); addr != "" {
		return addr
	}

	resolvedRef := cfg.ResolveReth(ifaceRef)
	for _, name := range []string{
		config.LinuxIfName(resolvedRef),
		config.LinuxIfName(ifaceRef),
	} {
		if addr := resolveKernelInterfaceAddress(name, family); addr != "" {
			return addr
		}
	}

	return ""
}

// resolveHostFamilyTimeout bounds the default dynamic-hostname DNS lookup.
// PrepareConfig runs SYNCHRONOUSLY in the daemon's ordered apply sequence
// (pkg/daemon/daemon_apply.go) and the CLI commit path (pkg/cli/apply.go),
// neither of which did any DNS before #2757. This lookup is only a *family
// hint* (strongSwan does the authoritative resolution at IKE time), so it
// must never stall commit/apply for the full glibc resolver timeout. 2s is
// ample for a hint; on timeout/error the default returns family 0 and the
// interface-decides fallback applies — graceful degradation, never a hang.
const resolveHostFamilyTimeout = 2 * time.Second

// resolveHostFamily is the hook used to resolve a dynamic-hostname gateway to
// an address family for local-address selection. It is a package var so tests
// can make resolution deterministic without real DNS (tests inject a fake; no
// real DNS in the test suite). It returns 4 if the host resolves to (or
// prefers) IPv4, 6 for IPv6, and 0 if it cannot resolve, times out, or the
// host is dual-stack with no clear preference (let the local interface
// decide). The default uses the system resolver bounded by
// resolveHostFamilyTimeout.
var resolveHostFamily = defaultResolveHostFamily

func defaultResolveHostFamily(host string) int {
	ctx, cancel := context.WithTimeout(
		context.Background(), resolveHostFamilyTimeout)
	defer cancel()

	var r net.Resolver
	ips, err := r.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		// Timeout / NXDOMAIN / SERVFAIL: fall back to family-agnostic so a
		// slow or unreachable resolver degrades to interface-decides rather
		// than stalling commit/apply or guessing the family.
		return 0
	}
	var has4, has6 bool
	for _, addr := range ips {
		if addr.IP.To4() != nil {
			has4 = true
		} else {
			has6 = true
		}
	}
	switch {
	case has4 && has6:
		// Dual-stack peer: no explicit preference is configured, so let
		// the local interface's available family decide (family-agnostic).
		return 0
	case has6:
		return 6
	case has4:
		return 4
	default:
		return 0
	}
}

// gatewayRemoteFamilyHint determines the address family (4, 6, or 0 for
// either) that the local-address for this gateway must match. A gateway with
// a literal remote Address takes the family of that IP. A dynamic-hostname
// gateway (Address empty, DynamicHostname set) is resolved via
// resolveHostFamily so the chosen local-address matches the family the peer
// actually resolves to (#2757) — previously the empty Address yielded a
// family-agnostic hint and the wrong-family local-address could win on a
// dual-stack appliance.
func gatewayRemoteFamilyHint(gw *config.IPsecGateway) int {
	if gw == nil {
		return 0
	}
	if gw.Address != "" {
		return addressFamilyHint(gw.Address)
	}
	if gw.DynamicHostname != "" {
		// A bare IP in the hostname slot still classifies directly.
		if f := addressFamilyHint(gw.DynamicHostname); f != 0 {
			return f
		}
		return resolveHostFamily(gw.DynamicHostname)
	}
	return 0
}

func resolveConfiguredInterfaceAddress(cfg *config.Config, ifaceRef string, family int) string {
	parts := strings.SplitN(ifaceRef, ".", 2)
	base := parts[0]
	unitNum := 0
	if len(parts) == 2 {
		if n, err := strconv.Atoi(parts[1]); err == nil {
			unitNum = n
		}
	}

	ifc, ok := cfg.Interfaces.Interfaces[base]
	if !ok {
		return ""
	}

	// Zone identifier for a link-local result is the kernel interface name of
	// the configured ifaceRef base (#2885) — the vSRX name xpfd renames to.
	zone := config.LinuxIfName(base)

	if unit, ok := ifc.Units[unitNum]; ok {
		if addr := selectUnitAddress(unit, family); addr != "" {
			return zoneQualify(addr, zone)
		}
	}

	if len(parts) == 1 && len(ifc.Units) > 0 {
		unitIDs := make([]int, 0, len(ifc.Units))
		for id := range ifc.Units {
			unitIDs = append(unitIDs, id)
		}
		sort.Ints(unitIDs)
		for _, id := range unitIDs {
			if addr := selectUnitAddress(ifc.Units[id], family); addr != "" {
				return zoneQualify(addr, zone)
			}
		}
	}

	return ""
}

func selectUnitAddress(unit *config.InterfaceUnit, family int) string {
	if unit == nil {
		return ""
	}

	candidates := make([]string, 0, 2+len(unit.Addresses))
	candidates = append(candidates, unit.PrimaryAddress, unit.PreferredAddress)
	candidates = append(candidates, unit.Addresses...)
	// Global-wins is order-independent (#2885): selectFamilyAddress scans
	// family-6 candidates for a global address before admitting link-local.
	return selectFamilyAddress(candidates, family)
}

func resolveKernelInterfaceAddress(ifaceName string, family int) string {
	if ifaceName == "" {
		return ""
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	candidates := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		candidates = append(candidates, addr.String())
	}
	// A global address always wins over a link-local one regardless of
	// kernel enumeration order (#2885); zone-qualify a link-local result with
	// the interface name so strongSwan can disambiguate fe80:: on a
	// multi-interface box.
	if addr := selectFamilyAddress(candidates, family); addr != "" {
		return zoneQualify(addr, ifaceName)
	}
	return ""
}

// selectFamilyAddress chooses one address from candidates for the requested
// family. For family 6 it scans twice: the first pass admits only
// global-unicast addresses, and a link-local (fe80::/10) candidate is accepted
// only if no global address is present. This makes "global wins" independent of
// candidate enumeration order (config order or kernel order) — without it a
// link-local enumerated before the global IPv6 would be selected first (#2885).
// For family 4 and family-agnostic (0) selection, link-local is never admitted
// by matchFamily, so a single pass is sufficient.
func selectFamilyAddress(candidates []string, family int) string {
	if family == 6 {
		for _, c := range candidates {
			if ip := bareIPGlobalOnly(c); ip != "" {
				return ip
			}
		}
	}
	for _, c := range candidates {
		if ip := bareIP(c, family); ip != "" {
			return ip
		}
	}
	return ""
}

func bareIP(addr string, family int) string {
	ip := parseBareIP(addr)
	if ip == nil {
		return ""
	}
	return matchFamily(ip, family)
}

// bareIPGlobalOnly is bareIP restricted to global-unicast IPv6 — the first pass
// of the family-6 global-wins scan in selectFamilyAddress (#2885).
func bareIPGlobalOnly(addr string) string {
	ip := parseBareIP(addr)
	if ip == nil || !ip.IsGlobalUnicast() || ip.To4() != nil {
		return ""
	}
	return matchFamily(ip, 6)
}

func parseBareIP(addr string) net.IP {
	if addr == "" {
		return nil
	}
	if ip, _, err := net.ParseCIDR(addr); err == nil {
		return ip
	}
	return net.ParseIP(addr)
}

// zoneQualify appends the IPv6 zone (%<iface>) to a link-local source address
// so strongSwan/the kernel can pick the right interface when more than one
// interface carries an fe80:: address (#2885). Non-link-local addresses, an
// empty iface name, and addresses already carrying a zone are returned
// unchanged.
func zoneQualify(addr, ifaceName string) string {
	if ifaceName == "" || strings.Contains(addr, "%") {
		return addr
	}
	if ip := net.ParseIP(addr); ip != nil && ip.IsLinkLocalUnicast() && ip.To4() == nil {
		return addr + "%" + ifaceName
	}
	return addr
}

func addressFamilyHint(addr string) int {
	ip := net.ParseIP(addr)
	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return 4
	}
	return 6
}

func matchFamily(ip net.IP, family int) string {
	if ip == nil {
		return ""
	}
	// Global unicast covers the common case. IPv6 link-local unicast
	// (fe80::/10) is also a valid IPsec local-bind source on point-to-point
	// / link-local IPv6 links (#2885); IsGlobalUnicast() rejects it, so admit
	// it explicitly here. Multicast, unspecified, and loopback stay excluded.
	if !ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() {
		return ""
	}
	switch family {
	case 4:
		// IPv4 link-local (169.254.0.0/16) is not a usable IPsec source.
		if ip.IsLinkLocalUnicast() {
			return ""
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
	case 6:
		if ip.To4() == nil {
			return ip.String()
		}
	default:
		// Family-agnostic selection: never surface a link-local address
		// implicitly — only an explicit family-6 hint may bind link-local.
		if ip.IsLinkLocalUnicast() {
			return ""
		}
		return ip.String()
	}
	return ""
}
