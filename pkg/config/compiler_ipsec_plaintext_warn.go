package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_ipsec_plaintext_warn.go carries the #5619 commit-time WARNING that
// a route-based IPsec VPN's decrypted plaintext is not zone-adjudicated.
//
// The defect it makes visible: route-based IPsec decrypts in the KERNEL XFRM
// stack, which delivers the plaintext on the xfrmi netdev. xpf's userspace
// dataplane does not adjudicate that interface — it is excluded from the
// ingress-adjudication map and the AF_XDP binding plan
// (userspaceSkipsIngressInterface / include_userspace_binding_interface, both
// keyed off IsSecureTunnelIfName) because there is no path to hand a plaintext
// frame back INTO an xfrmi for the egress direction. xpf installs only
// `hook input` nftables chains and force-enables ip_forward, so the plaintext
// is forwarded by the kernel with no zone policy, no session, no NAT and no
// screen.
//
// Why a warning and not a rejection. Route-based (st0/XFRM) IPsec is the ONLY
// IPsec model xpf supports — policy-based `then permit tunnel` is hard-rejected
// at commit (#3114). Rejecting a route-based VPN would not be a guard, it would
// be a feature removal, and it would leave an operator with a working tunnel
// unable to commit an UNRELATED change. This is the #1960 no-brick posture:
// strict enough to tell the truth, never strict enough to brick a config the
// box already accepts and runs.
//
// This function CANNOT reject. It has no error return and takes no `lenient`
// flag — the no-brick property is structural, not a convention a later edit
// could quietly invert. If a future change genuinely needs to reject one of
// these, that belongs in a separate gate with its own justification, not here.
//
// Why the operator needs telling. Before #5619 the config gave an affirmative
// FALSE signal: `set security zones security-zone vpn interfaces st0.0`
// commits cleanly (#4515 accepts a zone referencing a bind-interface even with
// no explicit `set interfaces st0 unit 0`), the Go compiler programs
// iface_zone_map for the xfrmi ifindex, and the XDP shim is attached to it.
// Everything reads as enforced. An operator who zones a VPN interface and sees
// it accepted has been told something specific and untrue about their security
// posture — which is worse than an unimplemented feature, and is what this
// warning corrects.
//
// Coupling. The warning keys off the SAME predicate as the dataplane exclusion
// (IsSecureTunnelIfName), so the two cannot drift apart into a state where the
// dataplane adjudicates the tunnel while the warning still claims it does not,
// or vice versa. When the dataplane learns to own an xfrmi end-to-end, the
// exclusion arms and this warning are keyed off one name and go together.
//
// An AST pre-walk (like validateSecureTunnelBindInterfaceAST) rather than a
// typed-Config pass, so it runs on the group-expanded, inactive-pruned tree in
// compileExpanded: an apply-groups-inherited bind-interface is covered and an
// `inactive:` VPN is ignored for free.
func warnSecureTunnelPlaintextUnadjudicatedAST(nodes []*Node) []string {
	zoneByIface := collectZoneInterfaceRefsAST(nodes)

	type finding struct {
		vpn       string
		bindIface string
		zone      string
	}
	seen := map[string]struct{}{}
	var findings []finding

	// #3562 shape: iterate EVERY top-level `security` node and EVERY `ipsec`
	// sibling. parseStatements APPENDS a repeated top-level block rather than
	// merging it, and the compiler compiles every one, so a VPN can live in a
	// duplicate block and must not be missed here either.
	_ = forEachChild(nodes, "security", func(security *Node) error {
		return forEachChild(security.Children, "ipsec", func(ipsec *Node) error {
			for _, inst := range namedInstances(ipsec.FindChildren("vpn")) {
				biNode := inst.node.FindChild("bind-interface")
				if biNode == nil {
					continue
				}
				bindIface := nodeVal(biNode)
				if bindIface == "" {
					continue
				}
				// An if_id of 0 means the name materializes NO xfrm device, so
				// there is no plaintext path to warn about — that config is
				// already reported by the #5297 arm of
				// validateSecureTunnelBindInterfaceAST (silent tunnel down).
				// Warning here too would just add noise to a config that is
				// already being told about a worse problem.
				if _, ifID := XFRMIfNameAndID(bindIface); ifID == 0 {
					continue
				}
				// Split the unit suffix off exactly as XFRMIfNameAndID does,
				// so the predicate below sees the same base name the device
				// derivation does.
				base := bindIface
				if i := strings.IndexByte(base, '.'); i >= 0 {
					base = base[:i]
				}
				// Keyed off the SAME predicate as the dataplane exclusion, so
				// the warning and the behaviour it describes cannot drift.
				// Today every valid secure tunnel is non-adjudicable; this
				// stays correct if that ever becomes conditional.
				if !IsSecureTunnelIfName(base) {
					continue
				}
				key := inst.name + "\x00" + bindIface
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				findings = append(findings, finding{
					vpn:       inst.name,
					bindIface: bindIface,
					zone:      zoneByIface[bindIface],
				})
			}
			return nil
		})
	})

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].vpn != findings[j].vpn {
			return findings[i].vpn < findings[j].vpn
		}
		return findings[i].bindIface < findings[j].bindIface
	})

	warnings := make([]string, 0, len(findings))
	for _, f := range findings {
		msg := fmt.Sprintf(
			"security ipsec vpn %s: decrypted traffic arriving on secure tunnel %q "+
				"is NOT evaluated against xpf security policies. Route-based IPsec "+
				"decrypts in the kernel XFRM stack and the plaintext is forwarded by "+
				"Linux routing, which xpf does not adjudicate — no zone policy, no "+
				"session, no NAT and no screen are applied to it. Restrict what the "+
				"tunnel can reach with routing or with the peer's own policy until "+
				"this is enforced (#5619)",
			f.vpn, f.bindIface)
		if f.zone != "" {
			msg += fmt.Sprintf(
				". NOTE: %q is assigned to security-zone %q, but that zone assignment "+
					"does NOT currently govern the decrypted traffic — the zone is "+
					"accepted at commit and programmed, yet the plaintext bypasses it",
				f.bindIface, f.zone)
		}
		warnings = append(warnings, msg)
	}
	return warnings
}

// collectZoneInterfaceRefsAST maps each `security zones security-zone <z>
// interfaces <ref>` member to its zone name, across every duplicate `security`
// and `zones` block.
//
// Membership is read through zoneInterfaceMembers, the shared flattener the
// real zone compiler uses (#5248/#2419): a bracketed list
// `interfaces [ st0.0 st0.1 ]` arrives bracket-stripped and NESTED under the
// first member rather than as siblings, so reading only iface.Name() would see
// just the first and silently miss the rest. A missed member here would mean a
// zoned tunnel whose warning omits the zone clause — a quieter warning than the
// operator has earned.
func collectZoneInterfaceRefsAST(nodes []*Node) map[string]string {
	out := map[string]string{}
	_ = forEachChild(nodes, "security", func(security *Node) error {
		return forEachChild(security.Children, "zones", func(zones *Node) error {
			for _, inst := range namedInstances(zones.FindChildren("security-zone")) {
				if inst.name == "" {
					continue
				}
				for _, prop := range inst.node.Children {
					if prop.Name() != "interfaces" {
						continue
					}
					for _, iface := range prop.Children {
						for _, member := range zoneInterfaceMembers(iface) {
							if member == "" {
								continue
							}
							// First zone wins; a duplicate assignment is a
							// separate concern with its own gate.
							if _, exists := out[member]; !exists {
								out[member] = inst.name
							}
						}
					}
				}
			}
			return nil
		})
	})
	return out
}
