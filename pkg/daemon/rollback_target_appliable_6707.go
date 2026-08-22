package daemon

import (
	"errors"
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

// errRollbackTargetUnappliable is the #6707 sentinel: `commit confirmed` was
// asked to arm a rollback timer whose TARGET the dataplane is guaranteed to
// refuse.
var errRollbackTargetUnappliable = errors.New("commit confirmed rollback target cannot be applied")

// rollbackTargetAppliablePreflight refuses to ARM a `commit confirmed` whose
// rollback target — the currently-active config, restored when the confirm
// timer expires — carries the #5575 lenient-content poison and therefore cannot
// become the running dataplane snapshot.
//
// WHY THIS IS A PRE-FLIGHT AND NOT A ROLLBACK-TIME ABORT. The rollback path
// applies its target UNCONDITIONALLY and deliberately: by then
// PromoteRollback has already reverted the STORE, so aborting the dataplane
// apply would leave the store and the dataplane disagreeing — a split-brain
// strictly worse than applying the target (#1956 OQ-15.2,
// daemon_apply_commit.go). That reasoning holds, which is exactly why the
// decision has to be made BEFORE the store is committed to. The existing
// device-map, cluster-topology and cluster-identity gates already validate the
// rollback target for the same reason; this extends "KNOWN-safe" from
// "will not strand management on next boot" to "can actually be applied".
//
// WHAT MAKES THE PREDICTION SOUND. LenientContentDropped is not a heuristic. A
// policy carrying it is stamped with the __unsupported__ application sentinel
// when the snapshot is lowered (pkg/dataplane/userspace/policies_lower.go), and
// the Rust integrity preflight rejects the WHOLE snapshot on that sentinel. So
// the flag is a local, allocation-free proof that the helper will refuse this
// config — no round trip, and no dependence on helper liveness at arm time.
//
// It fires ONLY on the tolerant path's poison, which a strict commit already
// rejects outright. So the target can only be poisoned if it arrived by a route
// that does not strict-compile: a lenient boot load of a persisted config, or a
// peer-sync SyncApply. That is precisely the #6707 sequence — boot from a
// poisoned persisted config A, correct it in candidate B, and `commit confirmed`
// B — where the safety net silently could not fire.
//
// The refusal is deliberately narrow. A plain `commit` of B is unaffected and
// remains the way forward: it makes B permanent, which is what an operator
// correcting a broken active config wants. Only the CONFIRMED variant is
// refused, and only because its promise — "this reverts cleanly if I lose
// contact" — would be false.
func rollbackTargetAppliablePreflight(rollbackTarget *config.Config) error {
	// A nil target is the first-commit case: there is nothing to roll back to,
	// which the timeout path already handles by reverting to bootstrap mode
	// (daemon_apply_commit.go's nil-prevCfg branch). Not this gate's business.
	if rollbackTarget == nil {
		return nil
	}
	locator := config.LenientDroppedPolicyLocator(rollbackTarget)
	if locator == "" {
		return nil
	}
	return fmt.Errorf(
		"%w: the active configuration (which `commit confirmed` would restore when the "+
			"timer expires) contains security policy %s whose match/then content was "+
			"DROPPED when it was loaded — the dataplane refuses that whole policy snapshot "+
			"(#5575 fail-closed), so the rollback would revert the configuration store "+
			"without reverting forwarding, leaving the store and the dataplane "+
			"disagreeing. Use a plain `commit` to make this change permanent, or repair "+
			"the active configuration first (a strict `commit` reports the exact leaf)",
		errRollbackTargetUnappliable, locator)
}
