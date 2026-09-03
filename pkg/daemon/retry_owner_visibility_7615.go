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
// Proxy-ARP joined them in #7685, but NOT by the predicate that was expected.
// `reassertProxyARPOnce` still keeps no debt and asks no question — it re-runs
// its reconcile unconditionally every tick — so "did the loop run" and "did the
// kernel drift" remain unpublishable: drift is EXPECTED after a legitimate link
// flap and is corrected on the next tick, so a gauge for it reads false almost
// always and a counter for it reports a routine event.
//
// The reconcile did already hold a debt, though, and the code already called it
// that: a CONFIGURED proxy-arp interface whose Linux netdev does not resolve is
// retained rather than torn down (#6536), with its own log line naming it debt.
// That condition does NOT self-heal on the next tick — it persists until the
// interface appears — and while it holds, the responder is not answering on a
// node whose commit reported success. See ProxyARPUnresolved below.

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

// ProxyARPUnresolved reports whether a CONFIGURED proxy-arp interface failed to
// resolve to a Linux netdev on the most recent reconcile (#7685).
//
// While true, proxy-arp is configured on that interface and the responder is
// NOT answering: the reconcile could not enable it, and it retains the prior
// state as debt rather than tearing it down (#6536). The operator's commit
// reported success, so this is invisible by every other means.
//
// Unlike a drifted sysctl — which the always-on loop re-asserts on its next
// tick and which is expected after a link flap — this does not clear until the
// interface exists. That difference is why this is the predicate published and
// "the kernel had drifted" is not: this one persists, and a signal that
// persists is one an operator can act on.
//
// Reads the value the reconcile itself computed rather than recomputing it, so
// the gauge and the reconcile cannot disagree, and costs nothing on the common
// path — `proxyARPIfaceMap` is not called at all when no proxy-arp is
// configured, preserving the loop's no-op-when-unconfigured property.
func (d *Daemon) ProxyARPUnresolved() bool { return len(d.proxyARPUnresolvedNames()) > 0 }
