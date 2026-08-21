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
// ONE aggregated advisory per commit, not one per tunnel. An advisory that
// fires N times on every commit is filtered out, and then it protects nobody —
// the same reason compiler_system.go folds several inert knobs into a single
// message. The affected tunnels are named inside it.
//
// It fires whenever a secure tunnel is configured, NOT only when one carries a
// zone. Leaving a tunnel out of a zone is not a mitigation: an interface in no
// zone resolves to zone id 0, and a `from-zone any to-zone any permit` rule
// matches zone-pair (0,0) with no zone guard (#6682). So an unzoned tunnel's
// plaintext is not merely unpoliced — it can be affirmatively PERMITTED by a
// wildcard rule. Gating this advisory on zoning would tell that operator
// nothing at all.
//
// The two groups are worded differently on purpose. A ZONED tunnel is the acute
// case and reads as an escalation, because the operator has been told something
// specific and untrue. An unzoned tunnel is a plain statement of the gap.
//
// Why the operator needs telling. Before #5619 the config gave an affirmative
// FALSE signal: `set security zones security-zone vpn interfaces st0.0`
// commits cleanly (#4515 accepts a zone referencing a bind-interface even with
// no explicit `set interfaces st0 unit 0`), the zone assignment is accepted,
// and nothing in the CLI or the commit output distinguishes it from a zone
// that is enforced. Everything READS as enforced.
//
// What actually happens is the opposite, and it is worth naming precisely
// because the obvious description of it is wrong twice over. The tunnel is
// excluded from the ingress-adjudication set, and `syncInterfaceAttachments`
// (pkg/dataplane/userspace/manager_compile.go) then builds an `allowed` set
// from buildUserspaceIngressIfindexes and calls DetachXDP on every ifindex
// outside it — so the shim is DETACHED from the xfrmi, not attached to it.
// (An earlier revision of this comment said "the XDP shim is attached to it",
// and attributed the programming to `iface_zone_map`, which now exists only in
// the retired-eBPF tree — pkg/dataplane/loader.go and maps_stale.go, behind
// the retirement canary. Neither statement described this code.) An operator who zones a VPN interface and sees
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
	zoneByIfID := collectZoneInterfaceRefsAST(nodes)

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
				_, ifID := XFRMIfNameAndID(bindIface)
				if ifID == 0 {
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
					zone:      zoneByIfID[ifID],
				})
			}
			return nil
		})
	})

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].bindIface != findings[j].bindIface {
			return findings[i].bindIface < findings[j].bindIface
		}
		return findings[i].vpn < findings[j].vpn
	})
	if len(findings) == 0 {
		return nil
	}

	// ONE aggregated advisory per commit, not one per tunnel. An advisory that
	// fires N times on every commit gets filtered out, and then it protects
	// nobody — the same reason compiler_system.go folds several inert knobs
	// into a single message.
	//
	// The two groups are stated separately and worded differently on purpose.
	// A ZONED tunnel is the acute case: the operator has been told something
	// specific and untrue, because the zone commits cleanly and is programmed
	// and so the posture READS as enforced. An unzoned tunnel is a plain gap.
	var zoned, unzoned []finding
	for _, f := range findings {
		if f.zone != "" {
			zoned = append(zoned, f)
		} else {
			unzoned = append(unzoned, f)
		}
	}

	var b strings.Builder
	b.WriteString("security ipsec: decrypted traffic on route-based IPsec secure tunnels is " +
		"NOT evaluated against xpf security policies (#5619).")
	if len(zoned) > 0 {
		b.WriteString("\n  ASSIGNED A ZONE THAT IS NOT ENFORCED — this reads as protected and is not:")
		for _, f := range zoned {
			fmt.Fprintf(&b, "\n    %s (security ipsec vpn %s) is assigned to security-zone %q, "+
				"but that zone does NOT govern its decrypted traffic",
				f.bindIface, f.vpn, f.zone)
		}
	}
	if len(unzoned) > 0 {
		b.WriteString("\n  NOT ZONE-ADJUDICATED:")
		for _, f := range unzoned {
			fmt.Fprintf(&b, "\n    %s (security ipsec vpn %s)", f.bindIface, f.vpn)
		}
	}
	b.WriteString("\n  Route-based IPsec decrypts in the kernel XFRM stack and the plaintext is " +
		"forwarded by Linux routing, which xpf does not adjudicate: no zone policy, no " +
		"session, no NAT and no screen are applied to it.")
	if len(unzoned) > 0 {
		// Leaving a tunnel out of a zone is not a mitigation, and an operator
		// reading only the zoned paragraph could conclude that it is.
		b.WriteString(" An UNZONED tunnel is not safer: an interface in no zone resolves to " +
			"zone id 0, which a `from-zone any to-zone any permit` rule matches (#6682).")
	}
	b.WriteString(" Restrict what the tunnel can reach with routing or with the peer's own " +
		"policy until this is enforced.")

	return []string{b.String()}
}

// collectZoneInterfaceRefsAST maps each `security zones security-zone <z>
// interfaces <ref>` secure-tunnel member to its zone name, keyed by XFRM
// if_id rather than by the literal ref string.
//
// The if_id is the key because the two spellings of one device are NOT
// interchangeable as strings but ARE the same device: `bind-interface st0` and
// a zone on `st0.0` describe the same xfrmi (both if_id 1,
// pkg/routing/xfrm.go). Matching literally would miss that pairing and report a
// ZONED tunnel as unzoned — dropping the escalation in exactly the case that
// earns it, where the operator HAS been told something untrue. This is the same
// spelling-mismatch class as the #5619 netdev-name bug, so it is keyed the same
// way: join on if_id, with XFRMIfNameAndID as the single source of truth.
//
// Membership is read through zoneInterfaceMembers, the shared flattener the
// real zone compiler uses (#5248/#2419): a bracketed list
// `interfaces [ st0.0 st0.1 ]` arrives bracket-stripped and NESTED under the
// first member, so reading only iface.Name() would see just the first and
// silently miss the rest.
func collectZoneInterfaceRefsAST(nodes []*Node) map[uint32]string {
	out := map[uint32]string{}
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
							_, ifID := XFRMIfNameAndID(member)
							if ifID == 0 {
								// Not a secure tunnel; irrelevant here.
								continue
							}
							// First zone wins; a duplicate assignment is a
							// separate concern with its own gate.
							if _, exists := out[ifID]; !exists {
								out[ifID] = inst.name
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
