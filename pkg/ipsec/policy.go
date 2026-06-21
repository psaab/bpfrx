package ipsec

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"

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

		fmt.Fprintf(&b, "  %s {\n", sanitizeSwanctlValue(name))
		authMethod, ikeProposals, ikeLifetime, aggressive, err := resolveIKESettings(ipsecCfg, gw)
		if err != nil {
			return "", fmt.Errorf("vpn %s: %w", name, err)
		}
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
//   - defined gateway with neither (addressless)         -> ok=false
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
		default:
			// Gateway exists but has nothing routable. Do NOT fall back
			// to the object name. (Forecloses a future responder-only /
			// %any peer that legitimately omits remote_addrs — no such
			// concept exists in the parser today; revisit if added.)
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
			cp.LocalAddress = resolveInterfaceAddress(cfg, cp.ExternalIface, cp.Address)
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

func resolveInterfaceAddress(cfg *config.Config, ifaceRef, remoteAddr string) string {
	family := addressFamilyHint(remoteAddr)
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

	if unit, ok := ifc.Units[unitNum]; ok {
		if addr := selectUnitAddress(unit, family); addr != "" {
			return addr
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
				return addr
			}
		}
	}

	return ""
}

func selectUnitAddress(unit *config.InterfaceUnit, family int) string {
	if unit == nil {
		return ""
	}

	for _, candidate := range []string{unit.PrimaryAddress, unit.PreferredAddress} {
		if addr := bareIP(candidate, family); addr != "" {
			return addr
		}
	}
	for _, candidate := range unit.Addresses {
		if addr := bareIP(candidate, family); addr != "" {
			return addr
		}
	}
	return ""
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
	for _, addr := range addrs {
		if ip := bareIP(addr.String(), family); ip != "" {
			return ip
		}
	}
	return ""
}

func bareIP(addr string, family int) string {
	if addr == "" {
		return ""
	}
	if ip, _, err := net.ParseCIDR(addr); err == nil {
		return matchFamily(ip, family)
	}
	if ip := net.ParseIP(addr); ip != nil {
		return matchFamily(ip, family)
	}
	return ""
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
	if ip == nil || !ip.IsGlobalUnicast() {
		return ""
	}
	switch family {
	case 4:
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
	case 6:
		if ip.To4() == nil {
			return ip.String()
		}
	default:
		return ip.String()
	}
	return ""
}
