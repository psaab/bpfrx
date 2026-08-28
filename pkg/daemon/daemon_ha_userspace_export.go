package daemon

import (
	"errors"
	"fmt"

	"github.com/psaab/xpf/pkg/cluster"
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

// userspaceBulkSnapshotWithConfig gathers the authoritative, owner-RG-filtered
// live session set for ONE cold-prime / re-drive bulk window from the helper's
// in-process SessionTable (#6031).
//
// This is the table-truth counterpart to cluster.SessionSync.BulkSync's walk of
// the `sessions`/`sessions_v6` BPF conntrack maps. Those maps are a best-effort
// DISPLAY mirror. Until #6965 the Rust helper published a conntrack row only on
// the host-inbound install, the missing-neighbor seed, and the reverse-companion
// repair, and the ordinary TRANSIT forward install — "the single place a locally
// learned transit forward flow is installed", userspace-dp
// afxdp/poll_descriptor — wrote only the shim steering map and the shared
// session tables, so a transit session was STRUCTURALLY absent from that walk.
// #6965 added the transit publish; the mirror is nonetheless a best-effort copy
// of a table the helper OWNS, so it is not table-truth however complete it is,
// and this export stays the authoritative source.
// Since #5085 the receiver reconciles authoritatively against the delimited
// window and DELETES every eligible session missing from it, so a mirror-framed
// cold prime wipes exactly the live peer-owned transit sessions the standby
// needs at failover.
//
// ExportOwnerRGSessions is synchronous: the helper enqueues the export to every
// worker, waits for their acks, and returns the drained delta set in the control
// response (userspace-dp afxdp/ha/export.rs, OwnerRgExportWait::wait_and_collect).
// max=0 requests the UNBOUNDED set — a capped export would silently truncate the
// window and delete the remainder on the peer.
//
// The deltas are converted through walkUserspaceSessionDeltas, the SAME walk and
// the SAME eligibility filter the incremental path uses, so the bulk window and
// the delta stream admit one set by construction.
func (d *Daemon) userspaceBulkSnapshotWithConfig(
	exporter userspaceSessionExporter,
	ss *cluster.SessionSync,
	cfg *config.Config,
	rgIDs []int,
) (cluster.BulkSnapshot, error) {
	if exporter == nil {
		return cluster.BulkSnapshot{}, errors.New("userspace session exporter not available")
	}
	if ss == nil {
		return cluster.BulkSnapshot{}, errors.New("session sync not ready")
	}
	if cfg == nil {
		return cluster.BulkSnapshot{}, errors.New("no active config")
	}
	deltas, _, err := exporter.ExportOwnerRGSessions(rgIDs, 0)
	if err != nil {
		return cluster.BulkSnapshot{}, fmt.Errorf("export owner-RG sessions: %w", err)
	}
	sink := newSnapshotDeltaSink()
	d.walkUserspaceSessionDeltas(ss, buildZoneIDs(cfg), deltas, sink)
	return sink.snapshot(), nil
}

// userspaceBulkSnapshot resolves the live daemon state and delegates to
// userspaceBulkSnapshotWithConfig. It is the function wired into
// cluster.SessionSync.BulkSnapshotSource.
//
// Every failure is returned rather than degraded into an empty or partial
// snapshot: doBulkSync fails CLOSED on an error and frames no window at all,
// leaving the caller's cold-prime / resync obligation armed for the next
// attempt. Returning an empty snapshot instead would be an ASSERTION that this
// node owns nothing, and the peer would act on it by deleting every session it
// holds for our RGs.
func (d *Daemon) userspaceBulkSnapshot() (cluster.BulkSnapshot, error) {
	ss := d.getSessionSync()
	if ss == nil {
		return cluster.BulkSnapshot{}, errors.New("session sync not ready")
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return cluster.BulkSnapshot{}, errors.New("no active config")
	}
	exporter, ok := d.dataplane().(userspaceSessionExporter)
	if !ok {
		return cluster.BulkSnapshot{}, errors.New("dataplane does not export owner-RG sessions")
	}
	return d.userspaceBulkSnapshotWithConfig(exporter, ss, cfg, d.primaryOwnerRGIDs(cfg))
}
