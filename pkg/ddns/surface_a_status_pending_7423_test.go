package ddns

import (
	"path/filepath"
	"testing"
	"time"
)

// #7423 row 5: a write-ahead record must not read `published`.
//
// `PublishPending=true` means the durable row holds the DESIRED address and the
// wire add has not confirmed — its own type doc says "with PublishPending=true
// the record is NOT settled". `StatusViews` consulted only `isOwned`, so after a
// crash in that window the operator saw `State: published` AND the desired
// address, while public DNS was still serving the prior one.
//
// The setup is a REAL crash in the write-ahead window (`crashPending5334`),
// not a hand-built record: the defect is about what the recovery path leaves on
// disk, and a synthetic record could encode a shape the code never produces.
func TestStatusViewsDoesNotReportAPendingRecordAsPublished_7423(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "wan.example.net"
	const addrA = "203.0.113.5"
	const addrB = "198.51.100.9"
	sc := surfaceAScope(fqdn, FamilyV4, 0)

	// Boot 1: publish A, confirmed.
	m1 := newSurfaceAManagerForTesting(statePath, newFakeUpdater(), clock)
	if err := m1.Reconcile(t.Context(), []SurfaceAScope{sc}, fixedObserver(addrA), nil, nil); err != nil {
		t.Fatalf("boot1 publish A: %v", err)
	}
	// Liveness for the whole test: a CONFIRMED record must read `published`
	// with its address. Without this the assertions below would pass against a
	// StatusViews that reported `pending` for everything.
	if v := onlyView7423(t, m1, sc); v.State != SurfaceAStatePublished || v.Published != addrA {
		t.Fatalf("confirmed record must read published/%s, got state=%q addr=%q",
			addrA, v.State, v.Published)
	}

	// Boot 2: renumber A->B and crash mid-wire -> {AddrText=B, pending, prior=A}.
	now = now.Add(time.Hour)
	crashPending5334(t, statePath, []SurfaceAScope{sc}, fixedObserver(addrB), clock)
	if rec := onlyOwned5285(t, statePath); !rec.PublishPending ||
		rec.AddrText != addrB || rec.PriorAddrText != addrA {
		t.Fatalf("crash setup: want pending {AddrText=B, prior=A}, got %+v", rec)
	}

	// Boot 3: a fresh manager over the crashed state, as a restart sees it.
	now = now.Add(time.Hour)
	m3 := newSurfaceAManagerForTesting(statePath, newFakeUpdater(), clock)
	v := onlyView7423(t, m3, sc)

	if v.State == SurfaceAStatePublished {
		t.Errorf("a write-ahead record reads %q; public DNS is still serving %s while the "+
			"appliance claims the publish settled", v.State, addrA)
	}
	if v.State != SurfaceAStatePending {
		t.Errorf("want state %q for an unsettled record, got %q", SurfaceAStatePending, v.State)
	}
	// The address column must show what public DNS actually serves, not the
	// phantom desired value AddrText holds until the wire confirms.
	if v.Published == addrB {
		t.Errorf("reported the DESIRED address %s as published; the live RR is still %s",
			addrB, addrA)
	}
	if v.Published != addrA {
		t.Errorf("want the last CONFIRMED address %s in the published column, got %q",
			addrA, v.Published)
	}
}

// #7423 row 5, the aggravating half: a scope whose re-publish keeps FAILING must
// not read `published` either.
//
// The issue frames this as an ordering problem — `case isOwned` is the first arm
// and so wins over `rt.lastErr != ""`. Reordering would be the wrong fix: a
// healthy settled scope that once hit a transient error would then report
// `error` while its RR is live and correct. The pending bit is the real
// discriminator and it covers this case on its own, because the write-ahead save
// sets PublishPending at every attempt and only the confirm-save clears it. This
// cell exists to hold that: it must stay green WITHOUT the switch being
// reordered.
func TestStatusViewsDoesNotReportAFailingRepublishAsPublished_7423(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "wan.example.net"
	const addrA = "203.0.113.5"
	const addrB = "198.51.100.9"
	sc := surfaceAScope(fqdn, FamilyV4, 0)

	m1 := newSurfaceAManagerForTesting(statePath, newFakeUpdater(), clock)
	if err := m1.Reconcile(t.Context(), []SurfaceAScope{sc}, fixedObserver(addrA), nil, nil); err != nil {
		t.Fatalf("boot1 publish A: %v", err)
	}

	// The renumber to B fails on the wire, repeatedly.
	now = now.Add(time.Hour)
	crashPending5334(t, statePath, []SurfaceAScope{sc}, fixedObserver(addrB), clock)

	now = now.Add(time.Hour)
	m3 := newSurfaceAManagerForTesting(statePath, newFakeUpdater(), clock)
	v := onlyView7423(t, m3, sc)
	if v.State == SurfaceAStatePublished {
		t.Errorf("a scope whose re-publish has not settled reads %q", v.State)
	}
}

// onlyView7423 returns the single status view for sc, failing the test if the
// manager reports any other number — an assertion on "the" view is meaningless
// if there are two.
func onlyView7423(t *testing.T, m *SurfaceAManager, sc SurfaceAScope) SurfaceAStatusView {
	t.Helper()
	views := m.StatusViews([]SurfaceAScope{sc})
	if len(views) != 1 {
		t.Fatalf("want exactly one status view, got %d: %+v", len(views), views)
	}
	return views[0]
}

// TestStatusViewsFirstPublishPendingClaimsNothing_7423 is the case the first cut
// of this fix got wrong, and it is the one where the false claim is least
// supportable.
//
// A crash in the write-ahead window of a FIRST publish leaves
// {AddrText=B, PublishPending=true, PriorAddrText=""} — nothing has ever been
// confirmed live at this name. Guarding the prior-address substitution with
// `PriorAddrText != ""` (the obvious way to avoid blanking the column) fell
// back to AddrText for exactly this shape, so the surface still reported the
// unconfirmed address as published.
//
// The correct render is nothing: State pending, address column empty.
func TestStatusViewsFirstPublishPendingClaimsNothing_7423(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	const fqdn = "fresh.example.net"
	const addrB = "198.51.100.9"
	sc := surfaceAScope(fqdn, FamilyV4, 0)

	// No boot-1 publish: this name has never had a confirmed record.
	crashPending5334(t, statePath, []SurfaceAScope{sc}, fixedObserver(addrB), clock)
	rec := onlyOwned5285(t, statePath)
	if !rec.PublishPending || rec.AddrText != addrB || rec.PriorAddrText != "" {
		t.Fatalf("first-publish crash setup: want pending {AddrText=B, prior=\"\"}, got %+v", rec)
	}

	now = now.Add(time.Hour)
	m := newSurfaceAManagerForTesting(statePath, newFakeUpdater(), clock)
	v := onlyView7423(t, m, sc)

	if v.State == SurfaceAStatePublished {
		t.Errorf("an unconfirmed first publish reads %q", v.State)
	}
	if v.Published == addrB {
		t.Errorf("address column reports %s as published; the wire add never "+
			"confirmed and nothing has ever been live at this name", addrB)
	}
	if v.Published != "" {
		t.Errorf("nothing was ever confirmed at this name, so the last-confirmed "+
			"address column must be empty, got %q", v.Published)
	}
}
