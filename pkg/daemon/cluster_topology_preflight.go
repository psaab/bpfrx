package daemon

import (
	"errors"
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

// errClusterTopologyRequiresRestart is the #5840 sentinel returned when a
// commit (or a peer-synced replay) would flip a running daemon between
// standalone and chassis-cluster mode. Callers surface it verbatim to the
// operator (CLI/gRPC/REST); tests match it with errors.Is.
var errClusterTopologyRequiresRestart = errors.New(
	"standalone<->cluster topology change requires a restart/offline workflow")

// clusterTopologyConfigured reports whether a compiled config engages
// chassis-cluster (HA) mode. A nil config is treated as standalone.
func clusterTopologyConfigured(cfg *config.Config) bool {
	return cfg != nil && cfg.Chassis.Cluster != nil
}

// clusterTopologyCommitPreflight is the #5840 standalone<->cluster topology
// commit guard.
//
// The chassis-cluster runtime — the d.cluster manager, its election,
// heartbeat/watchdog writer, session/config/DHCP-lease sync, event watcher,
// VRRP sync hold, and the gRPC fabric listener — is constructed EXACTLY ONCE,
// at process startup, and ONLY when the boot-time active config already
// contains `chassis cluster` (pkg/daemon/daemon_run.go: initManagers +
// startClusterComms). A DAY-2 apply reconciles that runtime only inside
// `if d.cluster != nil` guards (daemon_apply.go steps 19-20); it can neither
// construct it when the old config was standalone nor tear it down when the new
// config drops the cluster.
//
// Constructing/tearing that runtime down live is UNSAFE for two independent
// reasons (issue #5840):
//
//   - d.cluster is a bare, write-once-at-boot *cluster.Manager pointer read
//     without a lifecycle lock from ~129 sites (gRPC/CLI `show chassis cluster`
//     handlers, the DHCP-relay decision, the RG reconcile ticker, the health
//     loop, ...). Assigning it during an apply is a data race and exposes a
//     partially-initialized runtime to those readers.
//   - The userspace dataplane arms clustered forwarding semantics
//     (clusterHA=true, seeded HA groups) from the NEW config DURING THE SAME
//     apply — before any watchdog writer or election exists — so the Rust HA
//     gate would treat transit as HAInactive and drop it persistently until a
//     restart.
//
// Silently accepting the commit therefore publishes a half-built hybrid state:
// no HA plus a persistent transit outage until xpfd restarts under the new
// config (the #5840 bug). Instead we REJECT the topology-mode change at commit
// time — BEFORE store promotion and any dataplane mutation — and direct the
// operator to the restart/offline workflow. An intra-mode edit (both
// standalone, or both clustered with only redundancy-group/interface/transport
// changes) is unaffected and still reconciles live.
//
// old is the currently-active config being replaced; new is the compiled
// candidate about to be promoted. A nil old is the initial config load, where
// there is no running mode to transition and the boot path owns construction —
// permitted. Full day-2 runtime construction is the separate #5840 follow-up.
func clusterTopologyCommitPreflight(old, new *config.Config) error {
	if old == nil {
		// Initial config load: the boot path constructs the runtime; there is
		// no running standalone/cluster generation being transitioned.
		return nil
	}
	oldCluster := clusterTopologyConfigured(old)
	newCluster := clusterTopologyConfigured(new)
	if oldCluster == newCluster {
		return nil
	}
	if newCluster {
		return fmt.Errorf("commit rejected: adding `chassis cluster` on a running "+
			"standalone system cannot form the cluster without a restart — the HA "+
			"runtime (election, heartbeat/watchdog, session and config sync, VRRP) "+
			"is constructed only at daemon startup. Commit this change with the "+
			"system offline, or restart xpfd into the clustered configuration: %w",
			errClusterTopologyRequiresRestart)
	}
	return fmt.Errorf("commit rejected: removing `chassis cluster` on a running "+
		"clustered system cannot tear down the HA runtime without a restart. "+
		"Restart xpfd into the standalone configuration: %w",
		errClusterTopologyRequiresRestart)
}
