package ddns

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #4422 provider-transition integration: the CLEAN case the #3735 orphan proofs
// deliberately do NOT cover. Those tests all exercise an UN-withdrawable old
// record — the old provider was REMOVED from the catalog (H01), MUTATED in place
// (H02), or edited after the binding was removed (H03) — so the transition ends
// in a KEEP-ownership + loud orphan alarm. The everyday operator action is the
// opposite: two providers are BOTH defined in the catalog and a binding's
// `provider` reference is switched from A to B. Here the old A record is fully
// withdrawable at A's OWN (unchanged) endpoint, so the transition must be a clean
// hand-off: publish B, then WITHDRAW A at A's endpoint — no orphan, no leaked
// ownership, no leaked runtime state, and A's credentials must never be reused
// for B (each op routes to its own provider's endpoint).
//
// This pins the ownedBackendOK real-withdraw arm of classifyOwnedBackend (the
// old scope's provider stays in the catalog with a matching fingerprint) plus
// the provider-aware adopt-in-place guard NOT swallowing a genuine A→B switch to
// a different endpoint. It is behavior-pinning: the code is correct today.

// TestSurfaceAProviderSwitchBothConfiguredCleanHandoff drives the clean
// transition: provider A (ns-a) publishes; the binding is then switched to
// provider B (ns-b) with BOTH A and B still present in the catalog. The old A
// record must be withdrawn at A's ORIGINAL endpoint (not orphaned, not left
// live), B must take over at its own endpoint, and no state may leak.
//
// FAIL-ON-REVERT sensitivity:
//   - if classifyOwnedBackend wrongly reported the still-present provider A as
//     gone/mismatched, the withdraw becomes a KEEP+orphan → Orphaned==1,
//     DeleteOK==0, ns-a deletes==0 all go RED;
//   - if the provider-blind #2903 adopt-in-place guard were restored, A would be
//     dropped WITHOUT a wire delete (leaking the RR at A) → ns-a deletes==0 RED;
//   - if the A withdraw were mis-routed to B's endpoint (credential/endpoint
//     mis-carry), ns-b deletes==1 goes RED.
func TestSurfaceAProviderSwitchBothConfiguredCleanHandoff(t *testing.T) {
	reg := newEndpointRegistry()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceAProviderChangeManager(t, reg, func() time.Time { return now })

	const fqdn = "wan.example.net"
	const addr = "203.0.113.5"

	// Reconcile 1 — publish through provider A (ns-a).
	scA, provA := providerScope("prov-a", "ns-a.example.net:53", fqdn)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scA}, fixedObserver(addr), nil,
		map[string]*config.DDNSProvider{"prov-a": provA}); err != nil {
		t.Fatalf("publish via prov-a: %v", err)
	}
	if got := len(reg.get("ns-a.example.net:53").upserts); got != 1 {
		t.Fatalf("prov-a endpoint must receive the initial publish; upserts=%d", got)
	}

	// Reconcile 2 — the binding is switched to provider B (a DIFFERENT endpoint).
	// BOTH providers remain in the catalog — the distinguishing input vs the
	// #3735 H01 rename test, where prov-a is removed and becomes un-withdrawable.
	scB, provB := providerScope("prov-b", "ns-b.example.net:53", fqdn)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scB}, fixedObserver(addr), nil,
		map[string]*config.DDNSProvider{"prov-a": provA, "prov-b": provB}); err != nil {
		t.Fatalf("switch to prov-b (both configured): %v", err)
	}

	nsA := reg.get("ns-a.example.net:53")
	nsB := reg.get("ns-b.example.net:53")

	// B took over at its OWN endpoint; its live RR was never exact-RR deleted.
	if got := len(nsB.upserts); got != 1 {
		t.Fatalf("prov-b endpoint must receive the new publish; upserts=%d", got)
	}
	if got := len(nsB.deletes); got != 0 {
		t.Fatalf("the live RR at prov-b must not be deleted during the hand-off; deletes=%d", got)
	}

	// A was cleanly torn down at A's ORIGINAL endpoint — a real DNS DELETE, using
	// A's own provider config (the registry keys on UpdateServer, so a delete at
	// ns-a proves A's endpoint/creds were used, never B's).
	if got := len(nsA.deletes); got != 1 {
		t.Fatalf("the old prov-a record must be withdrawn at prov-a's own endpoint; ns-a deletes=%d", got)
	}
	if got := nsA.deletes[0].FQDN; got != fqdn {
		t.Fatalf("the prov-a withdraw must target the transitioned FQDN; got %q", got)
	}
	if got := len(nsA.upserts); got != 1 {
		t.Fatalf("prov-a must not receive any new publish during the switch; upserts=%d", got)
	}

	st := m.Stats()
	if st.Orphaned != 0 {
		t.Fatalf("a clean provider switch (old fully withdrawable) must NOT orphan; stats=%+v", st)
	}
	if st.DeleteOK != 1 {
		t.Fatalf("exactly one clean withdraw (of the old A record) must be counted; stats=%+v", st)
	}
	if st.UpsertOK != 2 {
		t.Fatalf("two publishes must be counted (A then B); stats=%+v", st)
	}
	if st.Scopes != 1 {
		t.Fatalf("only the new prov-b record must remain owned after the hand-off; scopes=%d", st.Scopes)
	}

	// The single surviving owned record is B's, fingerprinted for B's endpoint.
	owned, ok := m.state.get(scB.effectiveKey(), surfaceAIdentity, "")
	if !ok {
		t.Fatalf("the new prov-b record must be owned after the switch")
	}
	if owned.BackendFingerprint != backendFingerprint(provB) {
		t.Fatalf("the surviving record must carry prov-b's endpoint fingerprint; got %q", owned.BackendFingerprint)
	}
	if _, stillA := m.state.get(scA.effectiveKey(), surfaceAIdentity, ""); stillA {
		t.Fatalf("the old prov-a ownership must be dropped after the clean withdraw")
	}

	// No leaked runtime state for the retired A scope: the withdraw drops the old
	// scope's per-scope engine entry, leaving exactly the new B scope.
	if _, leaked := m.runtime[scA.scopeID()]; leaked {
		t.Fatalf("the retired prov-a scope's runtime state must be dropped, not leaked")
	}
	if _, present := m.runtime[scB.scopeID()]; !present {
		t.Fatalf("the active prov-b scope must have runtime state")
	}
	if len(m.runtime) != 1 {
		t.Fatalf("exactly one runtime entry (prov-b) must remain after the hand-off; got %d", len(m.runtime))
	}

	// Operator status: exactly one published row, naming provider B; no orphan row.
	views := m.StatusViews([]SurfaceAScope{scB})
	if r := orphanRow(views); r != nil {
		t.Fatalf("a clean switch must surface no orphan row; got %+v", r)
	}
	var published int
	for _, v := range views {
		if v.State == SurfaceAStatePublished {
			published++
			if v.Provider != "prov-b" {
				t.Fatalf("the published row must name the new provider prov-b; got %q", v.Provider)
			}
		}
	}
	if published != 1 {
		t.Fatalf("exactly one published row (prov-b) must be present; views=%+v", views)
	}
}

// TestSurfaceAProviderUnchangedSteadyStateNoWithdraw is the steady-state guard
// (#4422): a re-assert of the SAME provider (same catalog, force-refresh) must be
// a pure republish — never a withdraw and never an orphan. This pins that the
// provider-transition machinery (Pass-2 gone-from-config sweep + fingerprint
// classify) does not fire when nothing about the provider changed, so the clean-
// transition test above cannot pass merely because every re-assert withdraws.
//
// FAIL-ON-REVERT: if a same-provider re-assert wrongly treated the scope as a
// withdraw candidate or a fingerprint mismatch, DeleteOK>0 or Orphaned>0 go RED.
func TestSurfaceAProviderUnchangedSteadyStateNoWithdraw(t *testing.T) {
	reg := newEndpointRegistry()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceAProviderChangeManager(t, reg, func() time.Time { return now })

	sc, prov := providerScope("prov", "ns.example.net:53", "wan.example.net")
	catalog := map[string]*config.DDNSProvider{"prov": prov}

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, catalog); err != nil {
		t.Fatalf("initial publish: %v", err)
	}
	// Re-assert the identical provider; force so the unchanged address still fires
	// the wire path (proving it is a republish, not a change-detection skip).
	m.ForceRefresh()
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, catalog); err != nil {
		t.Fatalf("steady-state re-assert: %v", err)
	}

	ep := reg.get("ns.example.net:53")
	if got := len(ep.deletes); got != 0 {
		t.Fatalf("a same-provider re-assert must never withdraw; deletes=%d", got)
	}
	if got := len(ep.upserts); got != 2 {
		t.Fatalf("a forced re-assert must republish (two upserts total); upserts=%d", got)
	}
	st := m.Stats()
	if st.Orphaned != 0 {
		t.Fatalf("steady-state single-provider must not orphan; stats=%+v", st)
	}
	if st.DeleteOK != 0 {
		t.Fatalf("steady-state single-provider must count no withdraw; stats=%+v", st)
	}
	if st.Scopes != 1 {
		t.Fatalf("steady-state single-provider must keep exactly one owned record; scopes=%d", st.Scopes)
	}
}
