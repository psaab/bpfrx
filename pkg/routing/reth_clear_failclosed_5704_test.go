package routing

import (
	"errors"
	"strings"
	"testing"
)

// #5704 (codex-review-182 M30): rethManager.Clear scanned LinkList for reth*
// bond devices and LinkDel'd each, but a per-bond LinkDel failure was only
// LOGGED (slog.Warn) and then swallowed — Clear ALWAYS returned nil. A stale
// reth* bond that could not be torn down (EBUSY / EPERM / transient netlink
// error) therefore stayed in the kernel — with potentially stale VIP/MAC
// ownership — while the daemon (and the commit) reported a clean teardown
// (fail-open). The fix aggregates the LinkDel errors with errors.Join and
// returns them so the reconcile fails closed, mirroring the #4901
// xfrm/bond/tunnel Clear fix and the #5310/#5703 fail-closed discipline.
//
// This reuses fakeBondLinkOps (bond_test.go): seedBond seeds a real
// *netlink.Bond (reth.Clear filters on the *netlink.Bond type assertion),
// LinkList returns the seeded links, and failLinkDel injects a delete failure.

// TestRethClearReturnsOnLinkDelFailure is the RED-on-revert guard: a failed
// reth* LinkDel during Clear must make Clear return a non-nil error naming the
// bond, instead of the swallowed nil. Neutralize the fix (drop the errs
// aggregation / return nil) and this fails RED.
func TestRethClearReturnsOnLinkDelFailure(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedBond("reth0", 10)
	ops.seedBond("reth1", 11)
	ops.failLinkDel["reth0"] = errors.New("injected EBUSY")

	r := &rethManager{ops: ops}

	err := r.Clear()
	if err == nil {
		t.Fatal("Clear must return the LinkDel failure, not nil (stale reth bond left in kernel, reported as clean teardown)")
	}
	if !strings.Contains(err.Error(), "reth0") {
		t.Errorf("Clear error should name the failed reth bond: %v", err)
	}
	// The healthy reth bond must still be torn down (a failure on one bond
	// does not abort deletion of the others).
	if !sliceHas(ops.delCalls, "reth1") {
		t.Errorf("healthy reth1 must still be deleted despite reth0 failure; delCalls=%v", ops.delCalls)
	}
	// The failed bond's delete was attempted (so the next reconcile's re-scan
	// retries — there is no ownership map to retain for reth).
	if !sliceHas(ops.delCalls, "reth0") {
		t.Errorf("failed reth0 delete must have been attempted; delCalls=%v", ops.delCalls)
	}
}

// TestRethClearAggregatesMultipleLinkDelFailures: two failing reth bonds must
// BOTH surface in the joined error (errors.Join aggregation, not first-error
// short-circuit).
func TestRethClearAggregatesMultipleLinkDelFailures(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedBond("reth0", 10)
	ops.seedBond("reth1", 11)
	ops.failLinkDel["reth0"] = errors.New("injected EBUSY")
	ops.failLinkDel["reth1"] = errors.New("injected EPERM")

	r := &rethManager{ops: ops}

	err := r.Clear()
	if err == nil {
		t.Fatal("Clear must return the aggregated LinkDel failures, not nil")
	}
	if !strings.Contains(err.Error(), "reth0") || !strings.Contains(err.Error(), "reth1") {
		t.Errorf("joined error must name BOTH failed reth bonds: %v", err)
	}
}

// TestRethClearSuccessReturnsNil: when every reth* LinkDel succeeds, Clear
// returns nil (errors.Join of an empty slice). Guards against the fix
// over-reporting a spurious error on the happy path.
func TestRethClearSuccessReturnsNil(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedBond("reth0", 10)
	ops.seedBond("reth1", 11)

	r := &rethManager{ops: ops}

	if err := r.Clear(); err != nil {
		t.Fatalf("Clear must return nil when all reth deletes succeed, got %v", err)
	}
	if !sliceHas(ops.delCalls, "reth0") || !sliceHas(ops.delCalls, "reth1") {
		t.Errorf("both reth bonds must be deleted; delCalls=%v", ops.delCalls)
	}
}

// TestRethClearIdempotentWhenAlreadyGone: an already-absent RETH (no reth*
// bond present in the kernel) is a no-op that returns nil — deleting a
// nonexistent device is never attempted (Clear only deletes what LinkList
// reports), so idempotence is preserved and the teardown is not a spurious
// failure. A non-bond reth-prefixed link (e.g. a reth0.50 VLAN) and a
// non-reth bond are both left untouched.
func TestRethClearIdempotentWhenAlreadyGone(t *testing.T) {
	ops := newFakeBondLinkOps()
	// A reth-prefixed link that is NOT a bond (VLAN member) — skipped.
	ops.seedMember("reth0.50")
	// A bond that is NOT reth-prefixed — not our concern, left alone.
	ops.seedBond("bond0", 20)

	r := &rethManager{ops: ops}

	if err := r.Clear(); err != nil {
		t.Fatalf("Clear over an already-gone RETH must return nil (idempotent), got %v", err)
	}
	if len(ops.delCalls) != 0 {
		t.Errorf("no LinkDel should be attempted when no reth* bond exists; delCalls=%v", ops.delCalls)
	}
}
