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

// IsSecureTunnelIfName reports whether an interface BASE name (no unit
// suffix) is a secure-tunnel interface — `st<N>` with a numeric N.
//
// This is the shared lexical predicate behind the "kernel device name is the
// dotted ref VERBATIM" rule. A secure tunnel is materialized by the xfrmi
// reconciler (pkg/routing/xfrm.go) under exactly `LinuxIfName(bindInterface)`
// — so `bind-interface st0.0` creates a netdev literally named `st0.0`, NOT
// `st0`. Every resolver that maps a Junos ref to a kernel ifname must
// therefore skip the usual unit-0 collapse for these interfaces
// (`st0.0` -> `st0` is a name that exists on no box).
//
// Callers: ResolveKernelIfName (types.go) and snapshotLinuxName
// (pkg/dataplane/userspace/interfaces.go). The two are pinned against each
// other by TestSecureTunnelResolverParity — before #5619 the dataplane copy
// silently lacked this rule, so a secure-tunnel unit resolved to a
// nonexistent netdev, reported ifindex 0 / MTU 0 / no addresses, and fell out
// of every ifindex-keyed dataplane set.
//
// Scope: this is the LEXICAL shape only. XFRMIfNameAndID additionally bounds
// the st index (and the unit) to the range that yields a usable if_id; that
// stricter test decides whether an XFRM device is actually created, and is
// deliberately NOT folded in here so this predicate stays a pure name-shape
// question with no behavior change for the resolvers that adopt it.
func IsSecureTunnelIfName(base string) bool {
	if !strings.HasPrefix(base, "st") || len(base) < 3 {
		return false
	}
	_, err := strconv.Atoi(base[2:])
	return err == nil
}

// SecureTunnelNetdevForRef returns the Linux netdev the xfrmi reconciler
// creates for a secure-tunnel UNIT reference (e.g. "st0.0"), resolved from the
// AUTHORED `bind-interface` string rather than reconstructed from the ref.
//
// This distinction is the whole point. The reconciler creates the device as
// `LinuxIfName(bindInterface)` VERBATIM, and a bare `st0` and an explicit
// `st0.0` derive the SAME XFRM if_id under DIFFERENT device names — stated
// outright in pkg/routing/xfrm.go:
//
//	"a bare "st0" and an explicit "st0.0" both yield if_id 1 ... under
//	 DIFFERENT device names ("st0" vs "st0.0")"
//
// So the netdev name simply CANNOT be derived from the unit ref: `st0.0` is
// the device for `bind-interface st0.0` and `st0` is the device for
// `bind-interface st0`, and the ref is identical in both cases. It has to be
// read back from whichever string the operator actually authored.
//
// The if_id is the join key that makes that lookup well-defined, and
// XFRMIfNameAndID is the single source of truth for both halves of it.
// Reconstructing a name that another component owns is exactly what caused the
// #5619 drift; doing it again inside the fix would be the same mistake one
// level down.
//
// Returns ("", false) when no configured VPN binds this ref's if_id — then no
// xfrmi device exists for the unit at all and the caller keeps its own
// fallback, rather than this inventing a name for a device nobody creates.
//
// Deterministic under an if_id collision (two DISTINCT bind-interface strings
// sharing one if_id): the lexicographically smallest device name wins. Such a
// config is rejected at commit by the #2933 gate and refused at apply by the
// #2909 routing guard, so this only governs the tolerant-load path — but it
// must still be a pure function of the config rather than map-order dependent.
func (c *Config) SecureTunnelNetdevForRef(ref string) (string, bool) {
	if c == nil {
		return "", false
	}
	_, wantID := XFRMIfNameAndID(ref)
	if wantID == 0 {
		return "", false
	}
	best := ""
	for _, vpn := range c.Security.IPsec.VPNs {
		if vpn == nil || vpn.BindInterface == "" {
			continue
		}
		name, id := XFRMIfNameAndID(vpn.BindInterface)
		if id != wantID || name == "" {
			continue
		}
		if best == "" || name < best {
			best = name
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
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
