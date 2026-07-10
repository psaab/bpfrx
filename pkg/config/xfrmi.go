package config

import (
	"fmt"
	"strconv"
	"strings"
)

// XFRMIfNameAndID resolves a secure-tunnel bind-interface to the Linux xfrmi
// device name and a stable XFRM if_id.
func XFRMIfNameAndID(bindIface string) (string, uint32) {
	if bindIface == "" {
		return "", 0
	}

	parts := strings.SplitN(bindIface, ".", 2)
	devName := parts[0]
	if len(devName) < 3 || devName[:2] != "st" {
		return "", 0
	}

	stIndex, err := strconv.Atoi(devName[2:])
	if err != nil || stIndex < 0 || stIndex >= 0x10000 {
		return "", 0
	}

	unit := 0
	if len(parts) == 2 {
		unit, err = strconv.Atoi(parts[1])
		if err != nil || unit < 0 || unit >= 0xffff {
			return "", 0
		}
	}

	ifID := uint32(stIndex)<<16 | uint32(unit+1)
	if ifID == 0 {
		return "", 0
	}

	return LinuxIfName(bindIface), ifID
}

// ValidateSecureTunnelBindInterface reports whether a `security ipsec vpn
// <name> bind-interface` value is a canonical secure-tunnel interface — the
// only shape the route-based-VPN datapath can bind. The accepted lexical form
// is st<N> or st<N>.<unit> (e.g. st0, st0.1); XFRMIfNameAndID resolves every
// other name to if_id 0, which the pkg/routing reconciler treats as "invalid
// bind-interface name" and creates NO XFRM device for. Such a config commits
// successfully yet the VPN is silently DOWN (#5297).
//
// The if_id-0 sentinel from XFRMIfNameAndID is the authoritative
// "creates no XFRM device" signal; the message states the canonical lexical
// requirement so the operator sees an actionable error rather than an opaque
// id reference.
//
// Used both as the #1319 typed-leaf commit-check validator on the
// `bind-interface` schema leaf (schema_security.go) and — mirrored via
// XFRMIfNameAndID's if_id-0 check — by the compiled-config strict gate in
// compiler_ipsec_bindiface.go, which additionally catches group-expanded /
// packed forms the schema layer can miss (#1960 layered-defense doctrine).
func ValidateSecureTunnelBindInterface(raw string, _ *Config) error {
	name := strings.TrimSpace(raw)
	if name == "" {
		return fmt.Errorf(
			"missing bind-interface (expected a secure-tunnel interface " +
				"st<N> or st<N>.<unit>, e.g. st0 or st0.1)")
	}
	if _, ifID := XFRMIfNameAndID(name); ifID == 0 {
		return fmt.Errorf(
			"invalid bind-interface %q: must be a secure-tunnel interface "+
				"st<N> or st<N>.<unit> (e.g. st0 or st0.1); any other name "+
				"resolves to no XFRM interface, so the route-based VPN commits "+
				"but carries no traffic (silent tunnel down)",
			raw)
	}
	return nil
}
