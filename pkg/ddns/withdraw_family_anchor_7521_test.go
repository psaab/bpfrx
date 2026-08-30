package ddns

import "testing"

// #7521: disabling one DDNS family could withdraw its records through the OTHER
// family's backend.
//
// The live-updater-for-withdraw guard substituted `m.updater` — a SINGLE
// "last live backend seen" slot, advanced from whichever family happened to be
// live. So on a box running v6 DDNS only, `m.updater` holds the v6 backend, and
// when v4 became BACKEND-LESS while still owning records the guard sent v4's
// WITHDRAWAL to the v6 endpoint. The wrong server is asked to delete a record
// it never published: the delete is refused or lands in the wrong zone, and the
// real A record is orphaned live while the manager believes it withdrew.
//
// The trigger is narrow, and narrower than the source report said: the family
// must become backend-LESS — both blocks disappearing, or backend construction
// failing — while a withdrawal is needed. The ordinary disable path resolves to
// a nop with the anchor intact and was never affected.
//
// `lastLiveUpdater` is the per-family anchor #5814 already added for the
// endpoint-transition path. It sat directly beside this guard, unused by it.

// managerWithAnchors7521 builds the smallest manager that exercises
// applyWithdrawAnchors: per-family anchors, the cross-family `m.updater` slot
// set to the V6 backend (the state that produced the defect on a v6-only box),
// and an ownership store seeded per family.
func managerWithAnchors7521(v4, v6 DNSUpdater, owns4, owns6 bool) *Manager {
	recs := map[string]ownedRecord{}
	if owns4 {
		recs["a"] = ownedRecord{Family: 4}
	}
	if owns6 {
		recs["aaaa"] = ownedRecord{Family: 6}
	}
	m := &Manager{state: &ddnsState{records: recs}}
	m.lastLiveUpdater = [2]DNSUpdater{v4, v6}
	// The cross-family slot the old guard read. Set to the V6 backend so a
	// regression that reads it substitutes v6 into the v4 arm — visibly.
	m.updater = v6
	return m
}

// THE DEFECT. v4 is backend-less and still owns records; v6 is live. The v4
// withdrawal must go through v4's own anchor, never v6's.
func TestV4WithdrawDoesNotUseTheV6Backend7521(t *testing.T) {
	v4, v6 := &fakeUpdater{}, &fakeUpdater{}
	m := managerWithAnchors7521(v4, v6, true, true)

	out := m.applyWithdrawAnchors([2]DNSUpdater{nopUpdater{}, v6})

	if out[0] == DNSUpdater(v6) {
		t.Fatal("the v4 withdrawal was routed to the V6 backend. That server never " +
			"published the A record: the delete is refused or lands in the wrong " +
			"zone, and the real record is orphaned live while the manager believes " +
			"it withdrew (#7521)")
	}
	if out[0] != DNSUpdater(v4) {
		t.Errorf("the v4 arm resolved to %T, want v4's own anchor", out[0])
	}
	if out[1] != DNSUpdater(v6) {
		t.Errorf("the live v6 arm was disturbed: %T", out[1])
	}
}

// The mirror, so a fix that hard-codes index 0 is caught. Without it, "v4 uses
// v4's anchor" is satisfied by a function that always returns anchors[0].
func TestV6WithdrawDoesNotUseTheV4Backend7521(t *testing.T) {
	v4, v6 := &fakeUpdater{}, &fakeUpdater{}
	m := managerWithAnchors7521(v4, v6, true, true)

	out := m.applyWithdrawAnchors([2]DNSUpdater{v4, nopUpdater{}})

	if out[1] == DNSUpdater(v4) {
		t.Fatal("the v6 withdrawal was routed to the V4 backend (#7521)")
	}
	if out[1] != DNSUpdater(v6) {
		t.Errorf("the v6 arm resolved to %T, want v6's own anchor", out[1])
	}
}

// OWNERSHIP GATES THE SUBSTITUTION. A family that resolved to nop and owns
// NOTHING has nothing to withdraw, so the nop must stand — otherwise every
// disabled family reinstates a backend and the nop never takes effect.
func TestNoOwnedRecordsLeavesTheNop7521(t *testing.T) {
	v4, v6 := &fakeUpdater{}, &fakeUpdater{}
	m := managerWithAnchors7521(v4, v6, false, true)

	out := m.applyWithdrawAnchors([2]DNSUpdater{nopUpdater{}, v6})
	if !isNopUpdater(out[0]) {
		t.Errorf("a family owning no records had its nop replaced by %T; the "+
			"substitution exists only to withdraw records that exist", out[0])
	}
}

// A LIVE arm is never overwritten by its anchor — the substitution applies only
// to a nop. Without this, the function could return the anchor unconditionally
// and every cell above still passes.
func TestLiveArmIsNotOverwritten7521(t *testing.T) {
	v4, v6 := &fakeUpdater{}, &fakeUpdater{}
	fresh := &fakeUpdater{}
	m := managerWithAnchors7521(v4, v6, true, true)

	out := m.applyWithdrawAnchors([2]DNSUpdater{fresh, v6})
	if out[0] != DNSUpdater(fresh) {
		t.Errorf("a LIVE v4 arm was replaced by the anchor (%T); this cycle's "+
			"resolved backend must win over the previous cycle's", out[0])
	}
}

// THE NIL ANCHOR — the post-restart state, and the reason this is not a
// one-word substitution.
func TestNilAnchorDoesNotSubstitute7521(t *testing.T) {
	m := managerWithAnchors7521(nil, nil, true, true)
	m.updater = nil
	out := m.applyWithdrawAnchors([2]DNSUpdater{nopUpdater{}, nopUpdater{}})
	if !isNopUpdater(out[0]) || !isNopUpdater(out[1]) {
		t.Fatalf("a nil anchor was substituted (%T, %T). isNopUpdater is a type "+
			"assertion so it answers FALSE for nil, and lastLiveUpdater starts as "+
			"two nils — without an explicit nil check this substitutes nil and "+
			"segfaults the restart path (#7521)", out[0], out[1])
	}
}

// A NOP anchor must not be substituted either, or a family disabled for two
// cycles reinstates its own nop and the guard becomes a no-op wearing the shape
// of a safeguard.
func TestNopAnchorDoesNotSubstitute7521(t *testing.T) {
	m := managerWithAnchors7521(nopUpdater{}, nopUpdater{}, true, true)
	out := m.applyWithdrawAnchors([2]DNSUpdater{nopUpdater{}, nopUpdater{}})
	if !isNopUpdater(out[0]) || !isNopUpdater(out[1]) {
		t.Error("a nop anchor was substituted; only a LIVE previous backend may be")
	}
}
