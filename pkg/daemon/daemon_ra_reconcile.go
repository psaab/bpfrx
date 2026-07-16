package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// reconcileClusterRAServices converges the cluster RA senders to the union of
// buildRAConfigs filtered to the RGs this node is the CURRENT active owner for
// (#5861). It is the single authoritative cluster RA applier: every RA-affecting
// cluster event — a day-2 config commit, a VRRP MASTER/BACKUP transition, and
// the periodic dropped-event safety pass in reconcileRGState — funnels through
// it. Standalone (non-cluster) mode is a no-op here; that path applies RA
// directly in applyServicesReconcile.
//
// The pre-#5861 bug: a config commit in cluster mode SKIPPED ra.Apply (RA was
// managed only by ownership events) and the reconcile loop re-applied RA only
// on an rg_active transition (`if tr.Changed`). So a day-2 RA edit (add/remove
// prefix, change DNS/MTU/lifetime) on an RG that stayed MASTER never reached
// ra.Apply and the primary kept advertising the OLD set until failover/restart.
//
// Owner gating + demotion-race guard: the desired set is built from
// snapshotRethMasterState() — an RG's interfaces are included ONLY while this
// node is its active owner. The ownership snapshot and the ra.Apply run under
// raReconcileMu, and the VRRP demote path updates rg-state (SetVRRP/Reconcile)
// BEFORE it calls this function, so a config apply that races a demotion either
// snapshots the RG as already-inactive (its senders are withdrawn / never
// armed) or snapshots it active — in which case the node genuinely was the
// owner at apply time and the demote's own reconcile pass, serialized behind
// this one on raReconcileMu, withdraws immediately after. An inactive owner
// never transmits; a removal emits the lifetime-0 goodbye only from the current
// owner (ra.Apply's graceful-withdraw path).
//
// Idempotence: a stable digest of the desired set (lastRAReconcileHash) gates
// the actual ra.Apply, so the periodic safety pass is free when nothing moved.
// The digest is updated only on a successful apply, so a transient apply error
// is retried on the next pass rather than being latched as converged.
func (d *Daemon) reconcileClusterRAServices(reason string) {
	d.raReconcileMu.Lock()
	defer d.raReconcileMu.Unlock()

	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		// Standalone mode owns RA directly in applyServicesReconcile.
		return
	}

	apply := d.raApplyFn
	if apply == nil {
		if d.ra == nil {
			return
		}
		apply = d.ra.Apply
	}

	desired := d.desiredClusterRA(cfg)
	newHash := raDesiredHash(desired)
	if newHash == d.lastRAReconcileHash {
		return
	}

	if err := apply(desired); err != nil {
		slog.Warn("ra: cluster RA reconcile failed; will retry",
			"reason", reason, "err", err)
		return
	}
	if len(desired) > 0 {
		slog.Info("ra: cluster RA reconciled to current active owners",
			"reason", reason, "interfaces", len(desired))
	} else if d.lastRAReconcileHash != "" {
		slog.Info("ra: cluster RA withdrawn (no active owner)", "reason", reason)
	}
	d.lastRAReconcileHash = newHash
}

// desiredClusterRA returns the union of buildRAConfigs entries whose interface
// belongs to an RG this node is currently the active owner for. The union is
// sorted by interface name so the digest is stable across map-iteration order
// (snapshotRethMasterState and rethInterfacesForRG both iterate maps). Callers
// must hold raReconcileMu.
func (d *Daemon) desiredClusterRA(cfg *config.Config) []*config.RAInterfaceConfig {
	ownedIfaces := make(map[string]bool)
	for rgID, active := range d.snapshotRethMasterState() {
		if !active {
			continue
		}
		for _, n := range rethInterfacesForRG(cfg, rgID) {
			ownedIfaces[n] = true
		}
	}
	if len(ownedIfaces) == 0 {
		return nil
	}

	var desired []*config.RAInterfaceConfig
	for _, ra := range d.buildRAConfigs(cfg) {
		if ownedIfaces[ra.Interface] {
			desired = append(desired, ra)
		}
	}
	sort.Slice(desired, func(i, j int) bool {
		return desired[i].Interface < desired[j].Interface
	})
	return desired
}

// raDesiredHash returns a stable digest of the desired RA set. An empty set
// hashes to "" so a pure-backup node (no active owner) matches the zero-value
// lastRAReconcileHash and never issues a spurious withdraw. A non-empty set
// hashes to a 64-char hex digest, which can never collide with "".
func raDesiredHash(desired []*config.RAInterfaceConfig) string {
	if len(desired) == 0 {
		return ""
	}
	b, err := json.Marshal(desired)
	if err != nil {
		// Marshal of exported-field structs cannot fail in practice; fall back
		// to a value that forces an apply rather than a false cache hit.
		return "unhashable"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
