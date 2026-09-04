package ddns

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// #8597 K50. reconcileOnceLocked's Pass-1 -> Pass-2 "blocked" maps stop an add
// that would conflict with an RR a FAILED delete left live. blockedFQDN was
// keyed on the bare forward name, and a dual-stack host publishes ONE name for
// both its A and its AAAA — so a failed A delete suppressed that host's
// unrelated AAAA publish for the whole cycle. It is now keyed by (family,name).
//
// The finding offered two fix directions and only one of them is correct.
// Dropping the name gate is the WRONG one: it is the only gate covering a
// same-family REASSIGNMENT (a different client taking over a name at a
// different address matches neither the identity nor the address gate).
// TestAFailedDeleteStillBlocksASameFamilyNameReassignment_8597 is the
// over-reach control that fails if the gate is dropped rather than scoped.

// familyDeleteRefuser fails DeleteLease for ONE address family and delegates
// everything else. fakeUpdater's own failDel map is keyed by FQDN alone, which
// cannot express "fail the A delete but not the AAAA delete" for a dual-stack
// host — exactly the distinction these cells are about.
type familyDeleteRefuser struct {
	*fakeUpdater
	refuseFamily int // 4 or 6; 0 refuses nothing
}

func (f *familyDeleteRefuser) DeleteLease(ctx context.Context, rec LeaseDNSRecord) error {
	fam := 6
	if rec.Addr.Is4() {
		fam = 4
	}
	if fam == f.refuseFamily {
		return fmt.Errorf("test: v%d delete of %s refused", fam, rec.FQDN)
	}
	return f.fakeUpdater.DeleteLease(ctx, rec)
}

func leaseV6(addr, ident, host string) Lease {
	return Lease{Family: 6, Address: addr, Identity: ident, HostName: host, SubnetID: "1"}
}

// upsertedName reports whether an "<fqdn>=<addr>" pair was published.
func upserted(t *testing.T, f *fakeUpdater, want string) bool {
	t.Helper()
	for _, got := range f.upsertNames() {
		if got == want {
			return true
		}
	}
	return false
}

// seedOneV4 publishes an initial A record and returns the manager + updater.
func seedOneV4(t *testing.T, refuse int) (*Manager, *familyDeleteRefuser, ddnsPolicy) {
	t.Helper()
	up := &familyDeleteRefuser{fakeUpdater: newFakeUpdater()}
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.1.5", "cid:aa", "laptop")}); err != nil {
		t.Fatalf("seed reconcile: %v", err)
	}
	if !upserted(t, up.fakeUpdater, "laptop.example.com=10.0.1.5") {
		t.Fatalf("seed did not publish the A record: %v", up.upsertNames())
	}
	up.refuseFamily = refuse
	return m, up, pol
}

// A failed A delete must not suppress the SAME host's AAAA. Before the fix the
// AAAA was never published: the v4 delete failure wrote the bare name into
// blockedFQDN and Pass 2 skipped every desired record carrying that name.
func TestAFailedV4DeleteDoesNotSuppressTheSameHostsAAAA_8597(t *testing.T) {
	m, up, pol := seedOneV4(t, 4)

	// The v4 lease moves (forcing a delete of the seeded A, which is refused)
	// and a NEW v6 lease for the same host appears.
	err := runReconcile(t, m, pol, []Lease{
		leaseV4("10.0.1.9", "cid:aa", "laptop"),
		leaseV6("2001:db8::5", "duid:bb", "laptop"),
	})
	if err == nil {
		t.Fatal("the refused v4 delete must still fail the pass")
	}
	if !upserted(t, up.fakeUpdater, "laptop.example.com=2001:db8::5") {
		t.Fatalf("the AAAA was suppressed by an unrelated v4 delete failure; upserts=%v",
			up.upsertNames())
	}
	// The v4 re-add IS still correctly blocked — same identity, and the old A
	// is still live at the server.
	if upserted(t, up.fakeUpdater, "laptop.example.com=10.0.1.9") {
		t.Fatalf("the v4 move was published while its own delete was failing; upserts=%v",
			up.upsertNames())
	}
}

// The mirror direction, so a fix that hardcodes one family does not pass. A
// failed AAAA delete must not suppress the same host's A.
func TestAFailedV6DeleteDoesNotSuppressTheSameHostsA_8597(t *testing.T) {
	up := &familyDeleteRefuser{fakeUpdater: newFakeUpdater()}
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []Lease{leaseV6("2001:db8::5", "duid:bb", "laptop")}); err != nil {
		t.Fatalf("seed reconcile: %v", err)
	}
	up.refuseFamily = 6

	err := runReconcile(t, m, pol, []Lease{
		leaseV6("2001:db8::9", "duid:bb", "laptop"),
		leaseV4("10.0.1.5", "cid:aa", "laptop"),
	})
	if err == nil {
		t.Fatal("the refused v6 delete must still fail the pass")
	}
	if !upserted(t, up.fakeUpdater, "laptop.example.com=10.0.1.5") {
		t.Fatalf("the A was suppressed by an unrelated v6 delete failure; upserts=%v",
			up.upsertNames())
	}
	if upserted(t, up.fakeUpdater, "laptop.example.com=2001:db8::9") {
		t.Fatalf("the v6 move was published while its own delete was failing; upserts=%v",
			up.upsertNames())
	}
}

// OVER-REACH CONTROL. The name gate is the ONLY one covering a same-family
// reassignment: a different client taking over a name at a different address
// matches neither blockedIdentity nor blockedAddress. Scoping the gate by
// family must keep that; DROPPING the gate — the finding's other stated fix
// direction — publishes A name->new while A name->old is still live, which is
// the state this whole mechanism exists to avoid. Measured: with the gate
// removed this cell sees "laptop.example.com=10.0.1.9" published.
func TestAFailedDeleteStillBlocksASameFamilyNameReassignment_8597(t *testing.T) {
	m, up, pol := seedOneV4(t, 4)

	// A DIFFERENT client (cid:bb) takes over "laptop" at a different address.
	// Neither the identity nor the address matches the owned record.
	err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.1.9", "cid:bb", "laptop")})
	if err == nil {
		t.Fatal("the refused delete must still fail the pass")
	}
	if upserted(t, up.fakeUpdater, "laptop.example.com=10.0.1.9") {
		t.Fatalf("a reassigned name was published while the old A delete was failing "+
			"and that RR is still live; upserts=%v", up.upsertNames())
	}
}

// The fix must not launder the delete failure into a clean pass: the reconcile
// still has to report it so the caller's reconcile_runs_total{result=fail}
// accounting and the retry cadence are unchanged.
func TestTheCrossFamilyPublishStillReportsTheDeleteFailure_8597(t *testing.T) {
	m, up, pol := seedOneV4(t, 4)

	err := runReconcile(t, m, pol, []Lease{
		leaseV4("10.0.1.9", "cid:aa", "laptop"),
		leaseV6("2001:db8::5", "duid:bb", "laptop"),
	})
	if err == nil {
		t.Fatal("a refused delete must fail the pass even though the AAAA published")
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Fatalf("the reported error is not the delete failure: %v", err)
	}
	if !upserted(t, up.fakeUpdater, "laptop.example.com=2001:db8::5") {
		t.Fatalf("non-vacuous check: the AAAA must have published for this cell to "+
			"be about the fixed behaviour; upserts=%v", up.upsertNames())
	}
}
