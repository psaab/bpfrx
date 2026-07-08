package daemon

import (
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type userspaceSessionExporter interface {
	ExportOwnerRGSessions(rgIDs []int, max uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error)
}

type userspaceEventStreamExporter interface {
	ExportAllSessionsViaEventStream() error
}

// primaryOwnerRGIDs returns the redundancy-group IDs in cfg for which this node
// is the local primary. It enumerates the ACTUAL configured redundancy groups
// (from cfg, the same active config the zone IDs are built from) rather than a
// hardcoded 0..15 range. Junos redundancy-group ids are not bounded to 15 (the
// `<group-id>` config slot has no validator and is parsed via an unbounded
// strconv.Atoi), so a hardcoded 0..15 loop silently skipped any RG with id >=
// 16 — its owned sessions were never re-exported on a full resync, so the
// standby never received them and they were dropped on failover of that RG
// (#4028). Reading the configured RG set closes that hole for every id.
// Returns nil when there is no cluster manager or the config has no cluster/RGs;
// every caller must tolerate an empty slice. Nil RG entries (#3494) are skipped.
func (d *Daemon) primaryOwnerRGIDs(cfg *config.Config) []int {
	if d.cluster == nil || cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	var rgIDs []int
	for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
		if rg == nil {
			continue
		}
		if d.cluster.IsLocalPrimary(rg.ID) {
			rgIDs = append(rgIDs, rg.ID)
		}
	}
	return rgIDs
}

func (d *Daemon) exportUserspaceOwnerRGSessionsWithConfig(
	exporter userspaceSessionExporter,
	cfg *config.Config,
	rgIDs []int,
) (int, error) {
	if exporter == nil || cfg == nil || len(rgIDs) == 0 {
		return 0, nil
	}
	deltas, _, err := exporter.ExportOwnerRGSessions(rgIDs, 0)
	if err != nil {
		return 0, err
	}
	return d.queueUserspaceSessionDeltas(buildZoneIDs(cfg), deltas), nil
}
