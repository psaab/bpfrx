package ipsec

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/bpfrx/pkg/config"
)

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
