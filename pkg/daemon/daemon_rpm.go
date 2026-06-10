// daemon_rpm.go — RPM probe lifecycle wiring (#1827 PR-1a).
//
// Before #1827 the RPM manager was applied once at daemon start and
// never re-applied on commit: probe config changes required a restart.
// reconcileRPM runs on every config apply but is CONFIG-HASH-GATED — it
// re-applies probes (and the probe next-hop pin rules) only when the
// rendered RPM stanza actually changed, so probe state (and the
// ip-monitoring engine's sensor input) is never wiped by unrelated
// commits or by route-overlay actuations.
package daemon

import (
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

// rpmConfigHash computes a stable hash of the effective RPM stanza plus
// the RETH→physical map (which affects destination-interface
// resolution). Go's json.Marshal emits map keys in sorted order, so the
// encoding is deterministic.
func rpmConfigHash(rpmCfg *config.RPMConfig, rethMap map[string]string) [32]byte {
	payload := struct {
		RPM     *config.RPMConfig
		RethMap map[string]string
	}{RPM: rpmCfg, RethMap: rethMap}
	data, err := json.Marshal(&payload)
	if err != nil {
		// Marshal of plain config structs cannot realistically fail;
		// fall back to a zero hash (forces re-apply) rather than
		// silently skipping one.
		return [32]byte{}
	}
	return sha256.Sum256(data)
}

// effectiveRPMConfig returns the RPM config that should actually run
// on this node: in cluster mode the §4.4 ip-monitoring gating scope
// removes gated probes while the node is not primary for their data
// RG; everything else (and all standalone probes) keeps today's
// run-everywhere behavior.
func (d *Daemon) effectiveRPMConfig(cfg *config.Config) *config.RPMConfig {
	if cfg == nil {
		return nil
	}
	return d.filterRPMForHAGating(cfg)
}

// filterRPMForHAGating implements the §4.4 primary-only gating scope
// (#1827 PR-1b). Gating applies ONLY to probes that are (a) referenced
// by a `services ip-monitoring` policy, or (b) bound via
// destination-interface / source-address to a VIP-owned (RETH)
// interface — uplink addresses are VRRP-owned VIPs, so a standby probe
// would fail structurally, not informatively. All other probes are
// untouched. Within the gated scope, a probe runs only on the node
// that is primary for the probe's redundancy group.
func (d *Daemon) filterRPMForHAGating(cfg *config.Config) *config.RPMConfig {
	rpmCfg := cfg.Services.RPM
	if rpmCfg == nil || d.cluster == nil || cfg.Chassis.Cluster == nil {
		return rpmCfg
	}

	gatedRG := rpmProbeGatingRGs(cfg)
	if len(gatedRG) == 0 {
		return rpmCfg
	}

	filtered := &config.RPMConfig{Probes: make(map[string]*config.RPMProbe, len(rpmCfg.Probes))}
	dropped := 0
	for name, probe := range rpmCfg.Probes {
		if rgID, gated := gatedRG[name]; gated && !d.cluster.IsLocalPrimary(rgID) {
			dropped++
			continue
		}
		filtered.Probes[name] = probe
	}
	if dropped > 0 {
		slog.Info("RPM probes gated off while secondary", "gated", dropped)
	}
	return filtered
}

// rpmProbeGatingRGs returns the probes inside the §4.4 gating scope,
// mapped to the redundancy group whose primaryship gates them: the RG
// of a bound RETH interface when one exists, otherwise the lowest
// configured data RG.
func rpmProbeGatingRGs(cfg *config.Config) map[string]int {
	rpmCfg := cfg.Services.RPM
	if rpmCfg == nil {
		return nil
	}

	// Probes referenced by ip-monitoring policies.
	referenced := make(map[string]bool)
	if cfg.Services.IPMonitoring != nil {
		for _, pol := range cfg.Services.IPMonitoring.Policies {
			if pol != nil && pol.MatchRPMProbe != "" {
				referenced[pol.MatchRPMProbe] = true
			}
		}
	}

	// RETH interface → RG, plus RETH unit VIP addresses for
	// source-address matching.
	rethRG := make(map[string]int)
	rethVIPs := make(map[string]int)
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil || ifc.RedundancyGroup <= 0 || !strings.HasPrefix(name, "reth") {
			continue
		}
		rethRG[name] = ifc.RedundancyGroup
		for _, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			for _, addr := range unit.Addresses {
				ip := addr
				if i := strings.IndexByte(ip, '/'); i >= 0 {
					ip = ip[:i]
				}
				rethVIPs[ip] = ifc.RedundancyGroup
			}
		}
	}

	defaultRG := lowestDataRG(cfg)

	gated := make(map[string]int)
	for probeName, probe := range rpmCfg.Probes {
		if probe == nil {
			continue
		}
		rgID, inScope := defaultRG, false
		if referenced[probeName] {
			inScope = true
		}
		for _, test := range probe.Tests {
			if test == nil {
				continue
			}
			if test.DestinationInterface != "" {
				base := test.DestinationInterface
				if i := strings.IndexByte(base, '.'); i >= 0 {
					base = base[:i]
				}
				if rg, ok := rethRG[base]; ok {
					inScope, rgID = true, rg
				}
			}
			if test.SourceAddress != "" {
				if rg, ok := rethVIPs[test.SourceAddress]; ok {
					inScope, rgID = true, rg
				}
			}
		}
		if inScope {
			gated[probeName] = rgID
		}
	}
	return gated
}

// lowestDataRG returns the lowest configured redundancy group ID >= 1
// (the data RG), falling back to 0 when only RG 0 exists.
func lowestDataRG(cfg *config.Config) int {
	rg := -1
	if cfg.Chassis.Cluster != nil {
		for _, g := range cfg.Chassis.Cluster.RedundancyGroups {
			if g == nil || g.ID < 1 {
				continue
			}
			if rg == -1 || g.ID < rg {
				rg = g.ID
			}
		}
	}
	if rg == -1 {
		return 0
	}
	return rg
}

// reconcileRPM applies the RPM probe set when (and only when) the
// rendered stanza changed, returning whether a re-apply happened (the
// return value exists for the gating tests). Probe pin rules (fwmark +
// reserved probe tables) follow the prober lifecycle: they are
// reprogrammed on the same gate. Safe to call from applyConfigLocked
// AND from other reconcile paths; rpmMu serializes callers.
func (d *Daemon) reconcileRPM(cfg *config.Config) bool {
	if d.rpm == nil || d.daemonCtx == nil || cfg == nil {
		return false
	}
	d.rpmMu.Lock()
	defer d.rpmMu.Unlock()

	effective := d.effectiveRPMConfig(cfg)
	rethMap := cfg.RethToPhysical()
	h := rpmConfigHash(effective, rethMap)
	if h == d.activeRPMHash {
		return false
	}

	// Pin state follows the prober lifecycle: clear-and-program the
	// reserved band alongside every probe re-apply.
	if d.routing != nil {
		if err := d.routing.ApplyProbePins(routing.BuildProbePins(effective, rethMap)); err != nil {
			slog.Warn("failed to apply probe pin rules", "err", err)
		}
	}

	d.rpm.SetRethMap(rethMap)
	d.rpm.Apply(d.daemonCtx, effective)
	d.activeRPMHash = h
	probes := 0
	if effective != nil {
		probes = len(effective.Probes)
	}
	slog.Info("RPM probe set applied", "probes", probes)
	return true
}
