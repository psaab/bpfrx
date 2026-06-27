package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_ipsec_bindiface.go carries the #2933 reject-at-commit gate for two
// distinct secure-tunnel `bind-interface` aliases that derive the SAME Linux
// XFRM if_id.
//
// The defect: `security ipsec vpn <name> bind-interface` is a free-form 1-arg
// string (schema_security.go) stored verbatim on the typed VPN
// (compiler_ipsec.go). The runtime resolves it to a Linux xfrmi device name
// and a stable XFRM if_id via XFRMIfNameAndID (xfrmi.go):
//
//	if_id = stIndex<<16 | (unit+1)        (unit defaults to 0)
//
// so `bind-interface st0` and `bind-interface st0.0` BOTH derive if_id 1 — a
// bare `st0` is the same xfrmi device as `st0.0`. Two VPNs that bind these two
// distinct strings committed cleanly, but at apply time only one xfrm device
// can carry that if_id. Before #2929 this silently leaked one VPN's SA onto the
// other's tunnel; #2929 added a pkg/routing last-line-of-defense guard that
// refuses to create EITHER device and logs an ERROR — correct, but the operator
// experience is "both tunnels silently down with a journal ERROR" rather than a
// config-commit error.
//
// This gate turns that apply-time both-down into a Junos-style commit-check
// error (candidate rejected, live config untouched). The #2929 routing guard
// stays as the runtime backstop.
//
// Scope — surgical: the gate fires ONLY when two DISTINCT bind-interface
// strings derive the SAME non-zero if_id. It does NOT fire when:
//   - the same bind-interface string is shared by multiple VPNs (that is one
//     device, one if_id — not the ambiguous-alias case #2929 named), nor
//   - a bind-interface XFRMIfNameAndID cannot parse as `st<N>[.unit]`
//     (if_id 0) — out of scope here; some other path handles a bad string.
//
// An unambiguous map (st0.0 + st0.1, or st0 + st1) commits cleanly.
//
// This is an AST pre-walk (like validateUnsupportedInterfaceStanzasAST / the other
// reject-at-commit gates) rather than a typed-Config validator so it runs on
// the group-expanded, inactive-pruned tree in compileExpanded: an
// apply-groups-inherited bind-interface is covered and an `inactive:` VPN is
// ignored for free.
//
// Strict path (commit / commit-check, lenient=false): the first colliding
// if_id is a hard compile error naming every offending bind-interface string,
// its VPN(s), and the shared if_id.
//
// Lenient path (load / peer-sync, lenient=true): every collision is returned as
// a warning and compilation continues — an already-persisted or peer-synced
// config that an older binary silently accepted still BOOTS (#1960
// fail-closed-on-load class). Mirrors the other lenient gates' no-prune
// handling; the runtime #2929 routing guard still refuses the colliding
// devices.
func validateSecureTunnelBindInterfaceAST(nodes []*Node, lenient bool) ([]string, error) {
	var security *Node
	for _, n := range nodes {
		if n.Name() == "security" {
			security = n
			break
		}
	}
	if security == nil {
		return nil, nil
	}
	ipsec := security.FindChild("ipsec")
	if ipsec == nil {
		return nil, nil
	}

	// bindRef tracks the VPN(s) that configured one distinct bind-interface
	// string (a single string may legitimately be shared by several VPNs).
	type bindRef struct {
		vpns []string
	}
	// if_id -> distinct bind-interface string -> the VPN(s) that bound it.
	byID := map[uint32]map[string]*bindRef{}
	order := []uint32{} // first-seen if_id order for deterministic errors

	for _, inst := range namedInstances(ipsec.FindChildren("vpn")) {
		biNode := inst.node.FindChild("bind-interface")
		if biNode == nil {
			continue
		}
		bindIface := nodeVal(biNode)
		if bindIface == "" {
			continue
		}
		_, ifID := XFRMIfNameAndID(bindIface)
		if ifID == 0 {
			// Not a recognizable st<N>[.unit] secure-tunnel binding; out of
			// scope for the if_id-collision gate.
			continue
		}
		group, ok := byID[ifID]
		if !ok {
			group = map[string]*bindRef{}
			byID[ifID] = group
			order = append(order, ifID)
		}
		ref, ok := group[bindIface]
		if !ok {
			ref = &bindRef{}
			group[bindIface] = ref
		}
		ref.vpns = append(ref.vpns, inst.name)
	}

	var warnings []string
	emit := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	for _, ifID := range order {
		group := byID[ifID]
		if len(group) < 2 {
			// One distinct bind-interface string for this if_id (possibly
			// shared by several VPNs) — not the ambiguous-alias case.
			continue
		}
		// Two or more DISTINCT bind-interface strings collide on this if_id.
		names := make([]string, 0, len(group))
		for name := range group {
			names = append(names, name)
		}
		sort.Strings(names)
		descs := make([]string, 0, len(names))
		for _, name := range names {
			vpns := append([]string(nil), group[name].vpns...)
			sort.Strings(vpns)
			descs = append(descs, fmt.Sprintf(
				"bind-interface %q (security ipsec vpn %s)",
				name, strings.Join(vpns, ", ")))
		}
		if err := emit(
			"secure-tunnel bind-interface alias collision: %s all derive the "+
				"same XFRM if_id %d (a bare st<N> is unit 0, so st<N> and "+
				"st<N>.0 are the same xfrm device); only one device can carry "+
				"that if_id, so the others are dropped at apply time (both "+
				"tunnels down / cross-VPN SA leak). Bind each VPN to a distinct "+
				"secure-tunnel unit, e.g. st0.0 and st0.1 (#2933)",
			strings.Join(descs, " and "), ifID,
		); err != nil {
			return nil, err
		}
	}
	return warnings, nil
}
