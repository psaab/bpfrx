package userspace

import (
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func buildSnapshot(cfg *config.Config, ucfg config.UserspaceConfig, generation uint64, fibGeneration uint32) *ConfigSnapshot {
	return buildSnapshotWithSchedulerState(cfg, ucfg, generation, fibGeneration, nil)
}

func buildSnapshotWithSchedulerState(cfg *config.Config, ucfg config.UserspaceConfig, generation uint64, fibGeneration uint32, activeState map[string]bool) *ConfigSnapshot {
	if cfg == nil {
		return &ConfigSnapshot{
			Version:       ProtocolVersion,
			Generation:    generation,
			FIBGeneration: 0,
			GeneratedAt:   time.Now().UTC(),
			Capabilities:  deriveUserspaceCapabilities(nil),
			MapPins:       userspaceMapPins(),
			Userspace:     ucfg,
		}
	}
	policyCount := len(cfg.Security.Policies)
	interfaces := buildInterfaceSnapshots(cfg)
	return &ConfigSnapshot{
		Version:            ProtocolVersion,
		Generation:         generation,
		FIBGeneration:      fibGeneration,
		GeneratedAt:        time.Now().UTC(),
		Capabilities:       deriveUserspaceCapabilities(cfg),
		MapPins:            userspaceMapPins(),
		Userspace:          ucfg,
		Zones:              buildZoneSnapshots(cfg),
		Interfaces:         interfaces,
		Fabrics:            buildFabricSnapshots(cfg),
		TunnelEndpoints:    buildTunnelEndpointSnapshots(cfg, interfaces),
		Neighbors:          buildNeighborSnapshots(cfg),
		Routes:             buildRouteSnapshots(cfg, interfaces),
		Flow:               buildFlowSnapshot(cfg),
		DefaultPolicy:      policyActionString(cfg.Security.DefaultPolicy),
		Policies:           buildPolicySnapshotsWithSchedulerState(cfg, activeState),
		SourceNAT:          buildSourceNATSnapshots(cfg),
		StaticNAT:          buildStaticNATSnapshots(cfg),
		DestinationNAT:     buildDestinationNATSnapshots(cfg),
		NAT64:              buildNAT64Snapshots(cfg),
		Nptv6:              buildNptv6Snapshots(cfg),
		Screens:            buildScreenSnapshots(cfg),
		SYNCookieMasterKey: buildSYNCookieMasterKey(cfg),
		Filters:            buildFirewallFilterSnapshots(cfg),
		Policers:           buildPolicerSnapshots(cfg),
		ThreeColorPolicers: buildThreeColorPolicerSnapshots(cfg),
		ClassOfService:     buildClassOfServiceSnapshot(cfg),
		FlowExport:         buildFlowExportSnapshot(cfg),
		MirrorConfigs:      buildMirrorConfigSnapshotsFailClosed(cfg, interfaces),
		Config:             cfg,
		Summary: SnapshotSummary{
			HostName:       cfg.System.HostName,
			DataplaneType:  cfg.System.DataplaneType,
			InterfaceCount: len(cfg.Interfaces.Interfaces),
			ZoneCount:      len(cfg.Security.Zones),
			PolicyCount:    policyCount,
			SchedulerCount: len(cfg.Schedulers),
			HAEnabled:      cfg.Chassis.Cluster != nil,
		},
	}
}

// snapshotContentHash computes a SHA-256 hash over the stable content of a
// snapshot, excluding volatile fields (Generation, FIBGeneration, GeneratedAt)
// that change on every build even when the forwarding-relevant content is
// identical. Used to skip redundant control-socket publishes.
func snapshotContentHash(snap *ConfigSnapshot) ([32]byte, bool) {
	// Create a shallow copy with volatile fields zeroed, then JSON-encode.
	// This is cheaper than a custom hasher and reuses the existing JSON tags.
	tmp := *snap
	tmp.Generation = 0
	tmp.FIBGeneration = 0
	tmp.GeneratedAt = time.Time{}
	tmp.Config = nil // exclude raw config from content hash to avoid churn from non-forwarding metadata
	// #1197 (Copilot review): hash only PUBLISHABLE neighbors so
	// the dedup compares against what userspace-dp actually sees.
	// Filtered-out rows (state="none", malformed MAC) never reach
	// the dataplane, so churn in them must not shift the hash.
	tmp.Neighbors = filterPublishableNeighbors(snap.Neighbors)
	data, err := json.Marshal(&tmp)
	if err != nil {
		slog.Warn("snapshotContentHash: marshal failed, skipping dedup", "err", err)
		return [32]byte{}, false
	}
	return sha256.Sum256(data), true
}

func userspaceMapPins() UserspaceMapPins {
	return UserspaceMapPins{
		Ctrl:        dataplane.UserspaceCtrlPinPath(),
		Bindings:    dataplane.UserspaceBindingsPinPath(),
		Heartbeat:   dataplane.UserspaceHeartbeatPinPath(),
		XSK:         dataplane.UserspaceXSKMapPinPath(),
		LocalV4:     dataplane.UserspaceLocalV4PinPath(),
		LocalV6:     dataplane.UserspaceLocalV6PinPath(),
		Sessions:    dataplane.UserspaceSessionsPinPath(),
		ConntrackV4: dataplane.ConntrackV4PinPath(),
		ConntrackV6: dataplane.ConntrackV6PinPath(),
		DnatTable:   dataplane.UserspaceDnatTablePinPath(),
		DnatTableV6: dataplane.UserspaceDnatTableV6PinPath(),
		Trace:       dataplane.UserspaceTracePinPath(),
	}
}
