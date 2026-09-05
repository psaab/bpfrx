package daemon

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/psaab/xpf/pkg/config"
)

// #8967: the IPsec SA sync publisher is the one comms-scoped loop that did not
// handle being enabled by a later commit.
//
// `startClusterSyncAuxLoops` launches four loops. Three of them state, in
// place, that the knob may be toggled from the apply path:
//
//	configSyncReconcileLoop      unconditional -- "config-sync may be enabled by
//	                             a later commit without a comms restart"
//	ensureDHCPLeaseSyncLoop      idempotent starter (#4647) -- "a later
//	                             dhcp-lease-synchronization knob toggle from the
//	                             apply path shares this same launch/stop path"
//	runPersistentNatLeaseSyncLoop  unconditional
//	syncIPsecSAPeriodic          `if cc.IPsecSASync { go ... }` -- START-TIME ONLY
//
// Counting each knob's presence on the apply path made the asymmetry a
// measurement rather than a reading:
//
//	IPsecSASync    comms-wiring=2  apply-path=0   <- the only zero
//	DHCPLeaseSync  comms-wiring=2  apply-path=2
//	ConfigSync     comms-wiring=0  apply-path=8
//	SessionSync    comms-wiring=6  apply-path=1
//
// So enabling `ipsec-sa-synchronization` on a running cluster committed
// successfully and started nothing, until an unrelated comms restart. The
// operator sees a successful commit and no SA advertisement, with nothing
// naming the gap.
//
// THE REMEDY IS #4647's, NOT A NEW DESIGN. `ensureDHCPLeaseSyncLoop` already
// solved this exact problem for the sibling knob: an idempotent starter called
// from BOTH the comms-start path and the apply tail, so a knob-unchanged commit
// is a no-op, a knob-ON commit launches against the live comms context, and a
// knob-OFF commit stops the loop. This mirrors it deliberately -- a second
// shape here would be a second thing to keep in step.

// ipsecSASyncState guards the publisher's lifecycle. Mirrors
// `dhcpLeaseSyncState`'s loop half; the IPsec publisher needs no
// change-detection fields because `syncIPsecSAPeriodic` keeps its own.
type ipsecSASyncState struct {
	// loopMu guards the lifecycle. loopCancel is the cancel func of the
	// running publisher's context, nil when it is not running.
	loopMu     sync.Mutex
	loopCancel context.CancelFunc
	// launches counts ACTUAL launches, so idempotence is observable rather
	// than inferred. Without it, "a cancel is registered" is true both when
	// the second call was a no-op and when it started a second publisher and
	// overwrote the first one's cancel -- leaking the first loop. A mutation
	// removing the idempotence guard survived every other assertion in this
	// file until this counter existed.
	launches atomic.Uint64
}

// ensureIPsecSASyncLoop starts or stops the #4385 IPsec SA advertisement loop
// to match `enabled`, idempotently.
//
// Safe to call from the apply path before comms exist: it returns without
// starting when the comms context or the IPsec manager is not ready, and the
// connect-time call runs it again once they are, so a knob-ON state committed
// early is not lost. That "skip now, relaunch later" property is what makes
// one starter serve both call sites.
func (d *Daemon) ensureIPsecSASyncLoop(enabled bool) {
	d.ipsecSASync.loopMu.Lock()
	defer d.ipsecSASync.loopMu.Unlock()

	if !enabled {
		if d.ipsecSASync.loopCancel != nil {
			d.ipsecSASync.loopCancel()
			d.ipsecSASync.loopCancel = nil
			slog.Info("cluster: IPsec SA sync publisher stopped (knob disabled)")
		}
		return
	}
	if d.ipsecSASync.loopCancel != nil {
		return // already running — idempotent, guards double-launch
	}
	commsCtx := d.getClusterCommsCtx()
	if commsCtx == nil || d.ipsec == nil {
		// Not an error: the apply path can run before comms are up. The
		// comms-start call re-runs this once they are.
		return
	}
	loopCtx, cancel := context.WithCancel(commsCtx)
	d.ipsecSASync.loopCancel = cancel
	d.ipsecSASync.launches.Add(1)
	slog.Info("cluster: IPsec SA sync publisher started")
	go func() {
		d.syncIPsecSAPeriodic(loopCtx)
		d.ipsecSASync.loopMu.Lock()
		// Only clear if this loop is still the registered one: a stop
		// followed by a restart must not have the OLD goroutine's exit
		// clear the NEW loop's cancel.
		if d.ipsecSASync.loopCancel != nil && loopCtx.Err() != nil {
			d.ipsecSASync.loopCancel = nil
		}
		d.ipsecSASync.loopMu.Unlock()
	}()
}

// ipsecSASyncEnabled reports the committed knob, nil-safe for the apply path.
func (d *Daemon) ipsecSASyncEnabled(cfg *config.Config) bool {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return false
	}
	return cfg.Chassis.Cluster.IPsecSASync
}
