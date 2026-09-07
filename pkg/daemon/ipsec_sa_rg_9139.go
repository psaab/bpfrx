package daemon

// ipsec_sa_rg_9139.go — per-redundancy-group attribution for IPsec SA sync
// and re-initiation (#9139).
//
// THE DEFECT, and it is the shape #3764 already fixed once in this tree.
// advertiseIPsecSAOnce gated on IsLocalPrimary(0) and reinitiateIPsecSAs was
// wired only to applyRG0OwnershipTransition. Active/active is a supported
// configuration — docs/active-active-new-connections.md designs it and
// `make test-active-active` gates it — and in the asymmetric case (RG0 primary
// node 0, RG1 primary node 1, IPsec anchored on an RG1 reth) NEITHER half runs:
//
//   - node 1 holds the SAs and short-circuits at IsLocalPrimary(0), so it never
//     advertises;
//   - node 0 is RG0 primary, so it advertises its OWN set, which is empty, and
//     ipsecSASyncAdvertise suppresses a steady-empty set — nothing on the wire
//     either way;
//   - node 1 dies, node 0 takes RG1, and there is NO RG0 transition (node 0 was
//     already RG0 primary), so reinitiateIPsecSAs never fires — and the peer set
//     it would read is empty regardless.
//
// charon does not paper over it: pkg/ipsec/policy.go emits `start_action = start`
// ONLY for `establish-tunnels immediately`, so on the default setting the tunnel
// waits for the REMOTE peer to initiate. Every site-to-site VPN stays down until
// it does, with IPsecSASync configured and reporting healthy.
//
// #3764 in daemon_ipmon.go is the same defect on the ip-monitoring overlay and
// its comment describes the identical failure: "Keying on the lowest data RG
// alone suppressed the ENTIRE overlay on any node that was not primary for that
// lowest RG."
//
// WHY ATTRIBUTION IS NEEDED AND NOT JUST A WIDER GATE. Widening the advertise
// gate to IsLocalPrimaryAny() alone would make BOTH nodes advertise, and
// reinitiateIPsecSAs initiates the peer's WHOLE set. On a per-RG failover where
// the peer is still ALIVE and still owns another RG, taking RG1 would also
// initiate the tunnels the peer still holds on RG2 — a second IKE SA to the same
// remote from a different local address. Trading a missed re-initiation for a
// duplicate one is not a fix.
//
// The attribution below is deliberately evaluated at INITIATE time rather than
// at advertise time: it asks "does this node currently own the interface this
// connection would bind to", which is a local question with a local answer, and
// it needs no new wire field. It also tightens the pre-existing RG0 path, which
// initiated everything the peer advertised regardless of what this node owns.

import (
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// ipsecConnRedundancyGroup reports the redundancy group that owns the external
// interface an IPsec connection binds to.
//
// The swanctl connection name IS the VPN name (pkg/ipsec/policy.go renders
// `  <sanitized vpn name> {`), so the walk is vpn -> gateway -> external-interface
// -> reth -> redundant-ether-options redundancy-group.
//
// A connection that resolves to no reth returns RG 0, which is the historical
// behaviour and the right default rather than a refusal: before #9139 every
// peer-advertised name was re-initiated on the RG0 transition, so attributing an
// unanchored connection to RG0 preserves exactly that. Refusing to attribute it
// would silently STOP re-initiating tunnels that work today, which is the
// failure direction that matters here.
func ipsecConnRedundancyGroup(cfg *config.Config, connName string) int {
	if cfg == nil || connName == "" {
		return 0
	}
	vpn := lookupIPsecVPNByConnName(cfg, connName)
	if vpn == nil || vpn.Gateway == "" {
		return 0
	}
	gw := cfg.Security.IPsec.Gateways[vpn.Gateway]
	if gw == nil || gw.ExternalIface == "" {
		return 0
	}
	base := gw.ExternalIface
	if i := strings.Index(base, "."); i > 0 {
		base = base[:i]
	}
	ifc := cfg.Interfaces.Interfaces[base]
	if ifc == nil {
		return 0
	}
	return ifc.RedundancyGroup
}

// lookupIPsecVPNByConnName finds the VPN whose RENDERED connection name matches.
//
// The rendered name is sanitizeSwanctlValue(vpn name), which can differ from the
// configured name, and pkg/ipsec does not export that transform. Matching the
// configured name first and falling back to a comparison that ignores the
// characters sanitisation would have replaced keeps this correct for every name
// that survives sanitisation unchanged — which is all of them for a name that
// passed the commit-time validator — without importing a private helper or
// duplicating its rule, which would be a second thing to keep in step.
func lookupIPsecVPNByConnName(cfg *config.Config, connName string) *config.IPsecVPN {
	if vpn, ok := cfg.Security.IPsec.VPNs[connName]; ok {
		return vpn
	}
	for name, vpn := range cfg.Security.IPsec.VPNs {
		if vpn == nil {
			continue
		}
		if strings.EqualFold(name, connName) {
			return vpn
		}
	}
	return nil
}

// ownsIPsecConn reports whether this node is currently the primary for the
// redundancy group that owns the connection's external interface — i.e. whether
// this node holds the local address the IKE SA would bind to.
//
// A cluster-less daemon owns everything: the gate exists to prevent two CLUSTER
// nodes initiating the same tunnel, and there is no second node to collide with.
//
// RG0 IS NOT NECESSARILY A DECLARED GROUP, and getting this wrong is a silent
// regression rather than a visible one. cluster.Manager.UpdateConfig creates a
// group only for an RG the config DECLARES, so on a config carrying
// `redundancy-group 1` and no `redundancy-group 0`, groups[0] does not exist and
// IsLocalPrimary(0) is permanently FALSE. Gating an unanchored connection on it
// there would mean never re-initiating it — worse than the pre-#9139 behaviour
// this change is supposed to extend. LocalGroupPrimary (#8640) exists precisely
// to tell "not primary" from "no such group", so an undeclared RG0 falls back to
// "primary for anything", which is the same question #3764 settled on for the
// ip-monitoring overlay.
//
// The fallback is NOT used when RG0 is declared (the shipped cluster configs
// declare it), because there the honest answer is narrower: an unanchored tunnel
// binds an interface present on both nodes, so a node taking only a DATA RG
// while the peer keeps RG0 must not initiate it — the peer still has it.
func (d *Daemon) ownsIPsecConn(cfg *config.Config, connName string) bool {
	if d.cluster == nil {
		return true
	}
	rg := ipsecConnRedundancyGroup(cfg, connName)
	if rg != 0 {
		return d.cluster.IsLocalPrimary(rg)
	}
	if primary, known := d.cluster.LocalGroupPrimary(0); known {
		return primary
	}
	return d.cluster.IsLocalPrimaryAny()
}
