package daemon

import (
	"testing"
)

// #9087: a SUPPRESSED proxy-ARP interface must stay in the remembered set, so
// the sweep keeps deleting its NTF_PROXY entry on every later pass.
//
// THE DEFECT THIS PINS, measured on the loss cluster rather than reasoned
// about: fw1 sat in secondary-hold logging "suppressing responder for an
// interface this node does not own" every 30 seconds AND still holding the
// kernel entry for the pool address, with fw0 holding it too — the #8297
// two-MAC state, indefinitely. Not a 30-second window: a permanent leak.
//
// The mechanism is a ONE-SHOT teardown. proxyARPIfaceMapFiltered's own doc says
// a suppressed entry "must be actively torn down by the reconcile sweep rather
// than retained", and the sweep can only reach an interface present in
// ifaceMap or priorIfaceMap. A suppressed interface is in neither AFTER the
// first suppressed pass, because that pass stores an `enabled` set with the
// interface gone — so priorNames is empty from then on. The teardown therefore
// had exactly one chance, on the pass that ran during demotion, which is
// precisely when programRethMAC's link DOWN/UP makes the netdev hardest to
// resolve.
func TestSuppressedProxyIfaceStaysASweepTarget9087(t *testing.T) {
	const iface = "ge-7-0-2.80"
	prior := map[string]map[int]struct{}{
		iface: {2: {}}, // AF_INET
	}
	// The reconcile pass produced an EMPTY enabled set: the interface was
	// suppressed, so nothing was installed for it.
	enabled := map[string]map[int]struct{}{}

	got := retainSuppressedProxySweepTargets(enabled, prior, []string{iface})

	fams, ok := got[iface]
	if !ok {
		t.Fatal("#9087: a suppressed interface was dropped from the remembered set. " +
			"Every later pass then has an empty priorIfaceMap, so the sweep can never " +
			"reach the interface again and the orphaned NTF_PROXY entry survives " +
			"forever — both nodes answering for one pool address, which is #8297.")
	}
	if len(fams) != 1 {
		t.Errorf("#9087: retained families = %v, want the prior set carried forward", fams)
	}
}

// An interface suppressed BEFORE it was ever installed contributes nothing:
// there is no entry of ours to sweep, and inventing one would make the daemon
// claim responder state it never created.
func TestSuppressedIfaceWithNoPriorStateIsNotInvented9087(t *testing.T) {
	got := retainSuppressedProxySweepTargets(
		map[string]map[int]struct{}{}, map[string]map[int]struct{}{}, []string{"ge-7-0-2.80"})
	if len(got) != 0 {
		t.Errorf("#9087: retained %v for an interface with no prior state; the daemon "+
			"would be claiming responder state it never installed", got)
	}
}

// The control that keeps the two retentions apart. #6536's
// retainUnresolvedProxyResponders protects a LIVE responder on an interface
// that did not resolve; this one keeps a SUPPRESSED interface swept. Folding
// them together would make one of the two do the other's job wrongly, so a
// fresh enabled entry must win over the retained one in BOTH.
func TestFreshEnabledStateWinsOverSuppressedRetention9087(t *testing.T) {
	const iface = "ge-7-0-2.80"
	fresh := map[string]map[int]struct{}{iface: {10: {}}} // AF_INET6, freshly enabled
	prior := map[string]map[int]struct{}{iface: {2: {}}}

	got := retainSuppressedProxySweepTargets(fresh, prior, []string{iface})
	if _, ok := got[iface][10]; !ok {
		t.Error("#9087: the retention clobbered a freshly-enabled family; an interface " +
			"that resolved and installed on THIS pass must keep its fresh state")
	}
	if _, stale := got[iface][2]; stale {
		t.Error("#9087: the retention re-added a stale family over fresh state")
	}
}
