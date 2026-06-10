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
// Wire-behavior note (Codex review on PR #1832): the T1/T2 attempts
// still use the client's full exchange on the wire (v4: nclient4
// Discover/Offer/Request/Ack — force-discover; v6: Information-Request
// or Rapid Solicit), NOT RFC-style unicast RENEW/REBIND messages, so a
// different server can answer and the address-move path below handles
// that. The RFC 2131 §4.4.5 / RFC 8415 §18.2.4-5 citations describe
// the TIMER-AND-FALLBACK structure this loop implements (T1 → T2 →
// re-acquire), not the wire messages. Switching to true unicast renew
// (nclient4.Client.Renew) is a possible follow-up, deliberately out of
// scope here.
//
// The run loops themselves are not unit-testable (doDHCPv4/doDHCPv6
// open real AF_PACKET/UDP sockets via nclient4/nclient6, and the T1
// wait has a 30s clamp with no injectable clock), so the decision
// logic lives here as directly testable helpers — see commit_test.go.

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

	if prev == nil || leaseContentChanged(prev, lease) ||
		(len(prefixes) > 0 && delegatedPrefixesChanged(prevPDs, prefixes)) {
		m.scheduleRecompile()
	}
	return nil
}
