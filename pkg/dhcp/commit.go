package dhcp

import (
	"slices"
	"time"
)

// This file holds the shared lease-commit path and the pure decision
// helpers behind it (#1777). Before #1777 the run loops committed a
// lease only on the initial-acquisition path; a successful T1 renew /
// T2 rebind dead-assigned the result and `continue`d into a fresh full
// DORA / Solicit, discarding the renewal. Both run loops now commit
// every successful exchange through commitLease and return to the T1
// wait; only failure at both T1 and T2 falls back to re-acquisition.
//
// Wire-behavior note (#2994): the T1/T2 attempts now run the
// RFC-correct renewal exchange, not a full re-acquisition. At T1 the v4
// client unicasts a RENEWING DHCPREQUEST to the granting server (ciaddr
// set to the held address, no DISCOVER) and the v6 client sends a RENEW
// echoing the held IA_NA/IA_PD with the granting server's DUID; at T2
// the v4 client broadcasts a REBINDING DHCPREQUEST and the v6 client
// multicasts a REBIND (no server DUID). Only lease expiry (both renew
// and rebind failed) falls back to a full DISCOVER/SOLICIT. The RFC 2131
// §4.4.5 / RFC 8415 §18.2.4-5 citations now describe both the
// TIMER-AND-FALLBACK structure (T1 → T2 → re-acquire) and the wire
// messages. A renew that nonetheless lands on a different server is
// handled by the address-move path below. This supersedes the pre-#2994
// force-DORA / Rapid-Solicit behavior (the old #1832 review note).
//
// The decision helpers live here as directly testable functions (see
// commit_test.go). The run-loop state machine itself — the
// acquire→renew→rebind→re-acquire transitions and lease preservation —
// is exercised through the doV4ExchangeForTest / doV6ExchangeForTest /
// afterForTest / waitLinkLocalForTest seams (#2994); the real run loops
// otherwise open AF_PACKET/UDP sockets via nclient4/nclient6 and clamp
// the T1 wait to 30s. The wire builders (buildV4RenewRequest,
// v4RenewDest, buildV6RenewMessage in renew.go) are pure and
// unit-tested directly — see renew_test.go.

// renewalTimers computes the two waits of one renewal cycle from a
// lease duration: t1 is the wait until the renew attempt (50% of the
// lease time, clamped to a 30s minimum), t2Remaining is the additional
// wait from T1 to the rebind attempt (87.5% − 50% of the lease time,
// clamped to a 1s minimum). The formulas are unchanged from the
// pre-#1777 inline code; they are extracted so both families share one
// definition and tests can pin the clamps.
func renewalTimers(leaseTime time.Duration) (t1, t2Remaining time.Duration) {
	t1 = leaseTime / 2
	if t1 < 30*time.Second {
		t1 = 30 * time.Second
	}
	t2Remaining = leaseTime*7/8 - leaseTime/2
	if t2Remaining < time.Second {
		t2Remaining = time.Second
	}
	return t1, t2Remaining
}

// leaseContentChanged reports whether two leases differ in any field a
// downstream consumer reads (address, gateway, DNS — what reconcileDNS,
// FRR route generation, and the compiled config consume). Obtained and
// LeaseTime are excluded: they change on every successful renewal and
// feed only the run loop's own T1/T2 timers, never compiled state.
func leaseContentChanged(prev, next *Lease) bool {
	return prev.Address != next.Address ||
		prev.Gateway != next.Gateway ||
		!slices.Equal(prev.DNS, next.DNS)
}

// delegatedPrefixesChanged reports whether the delegated-prefix set
// differs in prefix value or lifetimes. Obtained is excluded (refreshed
// on every reply). Lifetimes are included so a server that decays
// remaining lifetimes still propagates them to the RA sender — for the
// common fixed-lifetime server they are stable across renewals and do
// not fire. The compare is order-sensitive: servers return IA_PD
// prefixes in stable order, and a spurious fire on reorder is harmless
// (Reconcile keys on config identity, never lease state).
func delegatedPrefixesChanged(prev, next []DelegatedPrefix) bool {
	if len(prev) != len(next) {
		return true
	}
	for i := range next {
		if prev[i].Prefix != next[i].Prefix ||
			prev[i].PreferredLifetime != next[i].PreferredLifetime ||
			prev[i].ValidLifetime != next[i].ValidLifetime {
			return true
		}
	}
	return false
}

// commitLease installs a freshly acquired or renewed lease as the
// active one for key. It is the single commit path shared by initial
// acquisition, T1 renew, and T2 rebind (#1777), so a renewal result
// gets exactly the same address-apply / store / notify treatment as a
// fresh DORA or Solicit result.
//
//   - If the server moved the address (renewed lease's address differs
//     from prev), the previous address is removed before the new one is
//     applied — re-acquisition-equivalent handling; applyAddress's
//     AddrReplace only installs the new address and would leave the old
//     one lingering on the interface.
//   - The lease record (and, for DHCPv6, any delegated prefixes) is
//     stored for Leases()/DelegatedPrefixes() consumers. A reply with
//     no IA_PD options leaves previously delegated prefixes in place
//     (pre-#1777 semantics).
//   - The debounced onAddressChange callback fires only when lease
//     content actually changed. The callback re-enters the daemon's
//     applyConfig (full recompile) and thus Reconcile; an
//     unchanged-content renewal must not trigger that every T1
//     interval. Reconcile keys strictly on config identity (#1793), so
//     firing is never a restart-loop hazard — only recompile churn.
//
// prev is the lease currently applied to the interface (nil on first
// acquisition); prevPDs the delegated prefixes currently stored. On
// error (address apply failed) nothing is stored and the caller falls
// back to re-acquisition.
func (m *Manager) commitLease(key clientKey, lease, prev *Lease, prefixes, prevPDs []DelegatedPrefix) error {
	if lease.Address.IsValid() {
		if prev != nil && prev.Address.IsValid() && prev.Address != lease.Address {
			m.removeAddress(key.iface, prev)
		}
		if err := m.applyAddress(key.iface, lease); err != nil {
			return err
		}
	}

	m.mu.Lock()
	m.leases[key] = lease
	if len(prefixes) > 0 {
		m.delegatedPDs[key.iface] = prefixes
	}
	m.mu.Unlock()

	// #1844: gateway-change hook for ip-monitoring interface-typed
	// next-hops. Strictly narrower than leaseContentChanged —
	// address/DNS-only deltas do not fire. Fired outside m.mu (see
	// fireGatewayChange) and undebounced: the consumer is the ipmon
	// engine's dirty-bit + debounce/throttle queue, which absorbs it.
	if prev == nil || prev.Gateway != lease.Gateway {
		m.fireGatewayChange()
	}

	if prev == nil || leaseContentChanged(prev, lease) ||
		(len(prefixes) > 0 && delegatedPrefixesChanged(prevPDs, prefixes)) {
		m.scheduleRecompile()
	}
	return nil
}
