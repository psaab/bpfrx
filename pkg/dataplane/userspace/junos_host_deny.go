package userspace

import (
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// junos_host_deny.go layers the KERNEL-netdev iifname scope onto the config-level
// #4146 junos-host DENY projection (config.BuildJunosHostDenyProjection). The
// projection SSOT lives in pkg/config (it owns policies / address book /
// applications / schedulers / feed bindings and is reused by the #4168 commit
// warning); this wrapper resolves each ingress zone's non-lifeline interface
// refs to the kernel netdev names a host-bound packet actually arrives on, so the
// daemon can scope every DROP rule by `iifname` (NOT destination address —
// daddr under-/over-denies across zones, plan §3.2).
//
// The direct host-bound packet is delivered by the Linux kernel, so enforcement
// is Go-only in the nft `xpf_hostinbound` chain: no Rust, no shim, no verifier
// interaction.

// JunosHostProgram is one ingress zone's effective junos-host DENY program,
// enriched with the kernel iifnames the daemon scopes each DROP rule by. Only
// representable programs that resolve to >=1 non-lifeline netdev AND emit >=1
// rule are returned.
type JunosHostProgram struct {
	Zone string
	// IngressIfnames is the sorted, de-duplicated set of kernel netdev names for
	// the zone's non-lifeline interfaces (physical, VLAN-subunit, and — for a
	// bondless-RETH VLAN whose frames arrive on the physical member — the parent
	// member netdev). Never a lifeline; never a netdev shared with another zone.
	IngressIfnames []string
	// RulesV4 / RulesV6 are the projected DROP rules (config SSOT) in first-match
	// order.
	RulesV4 []config.JunosHostDenyRule
	RulesV6 []config.JunosHostDenyRule
	// CoarseAdmitsIKE / CoarseIdentResets / HasApplicationAnyDeny drive the
	// daemon's fine-eligible-L4 exemption rules ahead of an `application any`
	// drop (§6.6).
	CoarseAdmitsIKE       bool
	CoarseIdentResets     bool
	HasApplicationAnyDeny bool
}

// BuildJunosHostPrograms returns the per-ingress-zone junos-host DENY programs
// the daemon renders into the kernel `xpf_hostinbound` chain. It calls the
// config projection for the representable ordered DROP rules and resolves the
// iifname scope from the live interface snapshots. A representable program that
// resolves to no non-lifeline netdev (lifeline-only, or a freshly-renamed
// interface not yet in the snapshot) is dropped — it emits nothing and the
// #4168 warning stays (the config projection already keeps the warning for such
// a zone because it never lands in RenderedPolicyKeys without a rendered rule).
func BuildJunosHostPrograms(cfg *config.Config) []JunosHostProgram {
	proj := config.BuildJunosHostDenyProjection(cfg)
	if len(proj.Programs) == 0 {
		return nil
	}
	netByZone := junosHostZoneNetdevs(cfg)
	var out []JunosHostProgram
	for _, p := range proj.Programs {
		if !p.Representable {
			continue
		}
		if len(p.RulesV4) == 0 && len(p.RulesV6) == 0 {
			continue
		}
		ifnames := netByZone[p.Zone]
		if len(ifnames) == 0 {
			continue
		}
		out = append(out, JunosHostProgram{
			Zone:                  p.Zone,
			IngressIfnames:        ifnames,
			RulesV4:               p.RulesV4,
			RulesV6:               p.RulesV6,
			CoarseAdmitsIKE:       p.CoarseAdmitsIKE,
			CoarseIdentResets:     p.CoarseIdentResets,
			HasApplicationAnyDeny: p.HasApplicationAnyDeny,
		})
	}
	return out
}

// junosHostZoneNetdevs resolves each zone to the set of kernel netdev names a
// host-bound packet on it arrives with, EXCLUDING lifelines and any netdev
// claimed by more than one zone (an ambiguous shared physical parent — kept out
// so a zone's deny can never over-fire on another zone's ingress).
func junosHostZoneNetdevs(cfg *config.Config) map[string][]string {
	snaps := buildInterfaceSnapshots(cfg)
	lifelines := hostInboundLifelineSet(cfg)
	// Candidate netdevs per zone, plus a global claim count per netdev.
	cand := map[string]map[string]bool{}
	claims := map[string]map[string]bool{} // netdev -> set of zones
	addCand := func(zone, nd string) {
		if nd == "" {
			return
		}
		if cand[zone] == nil {
			cand[zone] = map[string]bool{}
		}
		cand[zone][nd] = true
		if claims[nd] == nil {
			claims[nd] = map[string]bool{}
		}
		claims[nd][zone] = true
	}
	for _, s := range snaps {
		if s.Zone == "" || hostInboundLifelineInterface(s.Name, lifelines) {
			continue
		}
		// The netdev the row's own frames arrive on: the child VLAN netdev when
		// it exists, else the row's own physical netdev.
		addCand(s.Zone, s.LinuxName)
		// A VLAN subunit whose frames ride the physical parent (a bondless-RETH
		// VLAN with no Linux child netdev, LogicalOnly) arrives on the parent —
		// include it so the iifname scope still matches. Including the parent for
		// an ordinary VLAN child too is harmless (the parent only carries this
		// zone's traffic when it is not ambiguous, which the claim filter below
		// enforces).
		if s.VLANID != 0 && s.ParentLinuxName != "" {
			addCand(s.Zone, s.ParentLinuxName)
		}
	}
	out := map[string][]string{}
	for zone, nds := range cand {
		var keep []string
		for nd := range nds {
			if len(claims[nd]) == 1 { // unambiguous: only this zone claims nd
				keep = append(keep, nd)
			}
		}
		if len(keep) > 0 {
			sort.Strings(keep)
			out[zone] = keep
		}
	}
	return out
}
