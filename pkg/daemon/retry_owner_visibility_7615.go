package daemon

// Operator-visible signal for the always-on retry owners (#7615).
//
// Six loops in `Run` re-drive a failure that had no other retry owner. Two of
// them already publish — #6800's managed-service reload debt and #6802's
// host-inbound conntrack revocation — and the value of that is not the metric
// itself but that a node carrying an unpaid debt stops being indistinguishable
// from a healthy one. A retry owner nobody can see is the blindness the owner
// exists to end: a node can re-drive a failing repair for hours while every
// dashboard shows a firewall that committed cleanly.
//
// These three accessors put the remaining debt-driven owners on the same
// surface. Each is a thin, allocation-free read of the SAME predicate its loop
// gates on — deliberately, so the gauge and the loop cannot disagree about
// whether anything is owed. A metric derived from a second, parallel predicate
// would be a new way to be wrong.
//
// Proxy-ARP is absent on purpose. `reassertProxyARPOnce` keeps no debt and asks
// no question — it re-runs its reconcile unconditionally every tick — so there
// is no outstanding state to publish and a gauge wired to it could only report
// a constant. Giving it a real signal needs a predicate invented first, which
// is design rather than wiring; tracked as #7685.

// RADeadSenderPending reports whether an RA sender's asynchronous conn open
// failed and has not yet been rebuilt (#6793).
//
// While true, an interface is advertising NOTHING: hosts on that segment get no
// default route from this firewall, on a node whose commit reported success.
// `raDeadSenderReassertLoop` re-drives it every 30s; this is the only way to
// see that it is doing so.
func (d *Daemon) RADeadSenderPending() bool { return d.raHasDeadSenders() }

// FabricOverlayMissing reports whether a configured fabric IPVLAN is absent or
// down (#6791).
//
// While true the node has no cluster heartbeat and no session-sync transport,
// which is the condition #6791 added the retry owner for. Reads the active
// config through the same `missingFabricOverlays` gate the loop uses; nil-safe
// so a daemon without a store (a test, or pre-bringup) reports false rather
// than panicking on a scrape.
func (d *Daemon) FabricOverlayMissing() bool {
	if d.store == nil {
		return false
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return false
	}
	return len(d.missingFabricOverlays(cfg)) > 0
}

// ManagementListenerDown reports whether a management listener the
// configuration asked for is not currently serving (#6803).
//
// While true the operator's own management API is unreachable at an endpoint
// the running configuration still claims — the one failure an operator is least
// able to observe by other means, because the channel they would use to look is
// the channel that is down.
func (d *Daemon) ManagementListenerDown() bool { return d.mgmtListenerDown() }
