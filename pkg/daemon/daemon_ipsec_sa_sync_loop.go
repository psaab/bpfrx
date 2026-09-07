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
	// loopGen identifies WHICH loop `loopCancel` belongs to (#9176).
	//
	// The exit path used to test `loopCtx.Err() != nil`, whose comment says it
	// clears only "if this loop is still the registered one". It cannot:
	// `syncIPsecSAPeriodic` has exactly ONE return, `case <-ctx.Done()`, so the
	// error is ALWAYS non-nil there and the guard reduces to "always clear" --
	// precisely the behaviour the comment forbids. A stop-then-restart while the
	// old goroutine is still in flight then had A's exit clear B's cancel, and
	// loop B ran UNREGISTERED: a later knob-OFF silently did nothing and a later
	// knob-ON started a SECOND publisher.
	//
	// A counter rather than the cancel func itself because Go cannot compare
	// func values -- only against nil, which is the comparison that was already
	// there and already insufficient.
	loopGen uint64
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
	d.ipsecSASync.loopGen++
	myGen := d.ipsecSASync.loopGen
	d.ipsecSASync.launches.Add(1)
	slog.Info("cluster: IPsec SA sync publisher started")
	go func() {
		d.syncIPsecSAPeriodic(loopCtx)
		d.clearIPsecSALoopIfCurrent(myGen)
	}()
}

// ipsecSASyncEnabled reports the committed knob, nil-safe for the apply path.
func (d *Daemon) ipsecSASyncEnabled(cfg *config.Config) bool {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return false
	}
	return cfg.Chassis.Cluster.IPsecSASync
}

// resetIPsecSASyncLoop tears the publisher down on comms teardown, beside its
// DHCP sibling in stopClusterComms.
//
// #9176: `stopClusterComms` called `resetDHCPLeaseSyncLoop` and had no IPsec
// counterpart, while `ensureIPsecSASyncLoop` returns early on a non-nil
// `loopCancel` -- so a comms teardown left the handle set and the next `ensure`
// no-opped against a context that was already cancelled.
//
// Its exposure is smaller than it first appears, and recording that accurately
// matters more than the fix: `daemon_apply_tail.go` calls `ensureIPsecSASyncLoop`
// on EVERY apply, outside the transport-change branch, so recovery was bounded
// by "until the next commit" rather than needing a knob toggle. The window is
// sub-millisecond unless the goroutine is blocked in a strongSwan vici query
// (`ActiveConnectionNames()`), which is the only realistic widener.
func (d *Daemon) resetIPsecSASyncLoop() {
	d.ipsecSASync.loopMu.Lock()
	defer d.ipsecSASync.loopMu.Unlock()
	if d.ipsecSASync.loopCancel != nil {
		d.ipsecSASync.loopCancel()
		d.ipsecSASync.loopCancel = nil
	}
	// Bump the generation so an in-flight goroutine's exit cannot clear a
	// handle installed after this teardown.
	d.ipsecSASync.loopGen++
}

// clearIPsecSALoopIfCurrent is the exiting goroutine's teardown: drop the
// registered cancel only if the registered loop is still THIS one.
//
// #9176: this replaces `if loopCancel != nil && loopCtx.Err() != nil`, whose
// comment promised exactly this behaviour and whose condition could not deliver
// it -- `syncIPsecSAPeriodic` has one return, `case <-ctx.Done()`, so the error
// is always non-nil here and the guard read "always clear".
//
// EXTRACTED so the case can be driven deterministically. The defect needs an
// OVERLAP -- goroutine A exiting after loop B is registered -- and a cell that
// stops and restarts SEQUENTIALLY passes on the broken code. Reproducing the
// overlap by racing a real goroutine would make the cell timing-dependent, and a
// low-rate flake is worse than no cell: it passes for its author and fails for
// someone else in an unrelated package. As a pure function of the generation,
// both orderings are exact.
func (d *Daemon) clearIPsecSALoopIfCurrent(myGen uint64) {
	d.ipsecSASync.loopMu.Lock()
	defer d.ipsecSASync.loopMu.Unlock()
	if d.ipsecSASync.loopGen == myGen {
		d.ipsecSASync.loopCancel = nil
	}
}
