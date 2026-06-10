package dhcp

import (
	"net/netip"
	"testing"
	"time"
)

// The run loops (runDHCPv4/runDHCPv6) cannot be unit-tested directly:
// doDHCPv4/doDHCPv6 open real AF_PACKET/UDP sockets via nclient4/
// nclient6, and the T1 wait is clamped to a 30s minimum with no
// injectable clock. The #1777 fix therefore concentrates the decision
// logic in commitLease + renewalTimers + the changed-content helpers,
// which these tests pin: a committed renewal stores the lease, fires
// the (debounced) onAddressChange only on content change, and handles
// an address move as remove-old/apply-new. Loop control flow (renew
// success returns to the T1 wait; only NAK/timeout at both T1 and T2
// falls back to re-acquisition) is enforced by structure: commitLease
// is the only success path and `break` to re-acquisition exists only
// on commit/renew failure.

// recompileArmed reports whether a commit scheduled the debounced
// onAddressChange callback. scheduleRecompile arms m.recompileTimer
// synchronously, so this is observable without waiting out the 2s
// debounce.
func recompileArmed(m *Manager) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recompileTimer != nil
}

// disarmRecompile clears the debounce timer between commits so each
// commit's fire/no-fire decision is observed independently.
func disarmRecompile(m *Manager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recompileTimer != nil {
		m.recompileTimer.Stop()
		m.recompileTimer = nil
	}
}

func v4Lease(addr string, opts ...func(*Lease)) *Lease {
	l := &Lease{
		Interface: "ge-0-0-3",
		Family:    AFInet,
		Address:   netip.MustParsePrefix(addr),
		Gateway:   netip.MustParseAddr("10.0.0.1"),
		DNS:       []netip.Addr{netip.MustParseAddr("10.0.0.53")},
		LeaseTime: time.Hour,
		Obtained:  time.Now(),
	}
	for _, o := range opts {
		o(l)
	}
	return l
}

func TestRenewalTimers(t *testing.T) {
	tests := []struct {
		name          string
		leaseTime     time.Duration
		wantT1        time.Duration
		wantT2Remains time.Duration
	}{
		{"one hour", time.Hour, 30 * time.Minute, 1350 * time.Second},
		{"t1 clamped to 30s", 40 * time.Second, 30 * time.Second, 15 * time.Second},
		{"t2 remainder clamped to 1s", 2 * time.Second, 30 * time.Second, time.Second},
		{"zero lease time", 0, 30 * time.Second, time.Second},
		{"60s lease", 60 * time.Second, 30 * time.Second, 22500 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t1, t2 := renewalTimers(tt.leaseTime)
			if t1 != tt.wantT1 {
				t.Errorf("t1 = %s, want %s", t1, tt.wantT1)
			}
			if t2 != tt.wantT2Remains {
				t.Errorf("t2Remaining = %s, want %s", t2, tt.wantT2Remains)
			}
		})
	}
}

func TestLeaseContentChanged(t *testing.T) {
	base := v4Lease("10.0.0.5/24")
	tests := []struct {
		name string
		next *Lease
		want bool
	}{
		{"identical content, fresh timestamps", v4Lease("10.0.0.5/24", func(l *Lease) {
			l.Obtained = time.Now().Add(time.Hour)
			l.LeaseTime = 2 * time.Hour
		}), false},
		{"address changed", v4Lease("10.0.0.99/24"), true},
		{"prefix length changed", v4Lease("10.0.0.5/25"), true},
		{"gateway changed", v4Lease("10.0.0.5/24", func(l *Lease) {
			l.Gateway = netip.MustParseAddr("10.0.0.254")
		}), true},
		{"dns changed", v4Lease("10.0.0.5/24", func(l *Lease) {
			l.DNS = []netip.Addr{netip.MustParseAddr("10.0.0.54")}
		}), true},
		{"dns removed", v4Lease("10.0.0.5/24", func(l *Lease) {
			l.DNS = nil
		}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := leaseContentChanged(base, tt.next); got != tt.want {
				t.Errorf("leaseContentChanged = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDelegatedPrefixesChanged(t *testing.T) {
	pd := func(p string, pref, valid time.Duration) DelegatedPrefix {
		return DelegatedPrefix{
			Interface:         "ge-0-0-3",
			Prefix:            netip.MustParsePrefix(p),
			PreferredLifetime: pref,
			ValidLifetime:     valid,
			Obtained:          time.Now(),
		}
	}
	base := []DelegatedPrefix{pd("2001:db8:1000::/56", time.Hour, 2*time.Hour)}
	tests := []struct {
		name string
		next []DelegatedPrefix
		want bool
	}{
		{"same set, fresh Obtained", []DelegatedPrefix{
			pd("2001:db8:1000::/56", time.Hour, 2*time.Hour)}, false},
		{"prefix changed", []DelegatedPrefix{
			pd("2001:db8:2000::/56", time.Hour, 2*time.Hour)}, true},
		{"lifetime changed", []DelegatedPrefix{
			pd("2001:db8:1000::/56", time.Hour, 3*time.Hour)}, true},
		{"prefix added", []DelegatedPrefix{
			pd("2001:db8:1000::/56", time.Hour, 2*time.Hour),
			pd("2001:db8:2000::/56", time.Hour, 2*time.Hour)}, true},
		{"all withdrawn", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := delegatedPrefixesChanged(base, tt.next); got != tt.want {
				t.Errorf("delegatedPrefixesChanged = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCommitLeaseInitialAcquisition: a first commit (prev == nil) must
// store the lease and fire the callback unconditionally.
func TestCommitLeaseInitialAcquisition(t *testing.T) {
	m := NewManagerForTesting(nil)
	key := clientKey{iface: "ge-0-0-3", family: AFInet}
	lease := v4Lease("10.0.0.5/24")

	if err := m.commitLease(key, lease, nil, nil, nil); err != nil {
		t.Fatalf("commitLease: %v", err)
	}
	if got := m.LeaseFor("ge-0-0-3", AFInet); got == nil || got.Address != lease.Address {
		t.Fatalf("lease not stored: %+v", got)
	}
	if !recompileArmed(m) {
		t.Fatal("initial acquisition must fire onAddressChange")
	}
	disarmRecompile(m)
}

// TestCommitLeaseUnchangedRenewalNoCallback pins the #1777 callback
// contract: a renewal whose content is unchanged (same address,
// gateway, DNS — only Obtained/LeaseTime refreshed) must store the new
// lease record but must NOT fire onAddressChange, because the callback
// re-enters the daemon's applyConfig (full recompile) and would
// otherwise run every T1 interval.
func TestCommitLeaseUnchangedRenewalNoCallback(t *testing.T) {
	m := NewManagerForTesting(nil)
	key := clientKey{iface: "ge-0-0-3", family: AFInet}
	prev := v4Lease("10.0.0.5/24")
	if err := m.commitLease(key, prev, nil, nil, nil); err != nil {
		t.Fatalf("initial commitLease: %v", err)
	}
	disarmRecompile(m)

	renewed := v4Lease("10.0.0.5/24", func(l *Lease) {
		l.Obtained = prev.Obtained.Add(30 * time.Minute)
	})
	if err := m.commitLease(key, renewed, prev, nil, nil); err != nil {
		t.Fatalf("renewal commitLease: %v", err)
	}
	got := m.LeaseFor("ge-0-0-3", AFInet)
	if got == nil || !got.Obtained.Equal(renewed.Obtained) {
		t.Fatalf("renewed lease record not stored: %+v", got)
	}
	if recompileArmed(m) {
		t.Fatal("unchanged-content renewal must not fire onAddressChange")
	}
}

// TestCommitLeaseChangedContentFiresCallback: renewals that move the
// address or change DNS must fire the callback so the daemon's
// recompile picks up the new state.
func TestCommitLeaseChangedContentFiresCallback(t *testing.T) {
	tests := []struct {
		name string
		next *Lease
	}{
		{"address moved", v4Lease("10.0.0.99/24")},
		{"dns changed", v4Lease("10.0.0.5/24", func(l *Lease) {
			l.DNS = []netip.Addr{netip.MustParseAddr("10.0.0.54")}
		})},
		{"gateway changed", v4Lease("10.0.0.5/24", func(l *Lease) {
			l.Gateway = netip.MustParseAddr("10.0.0.254")
		})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewManagerForTesting(nil)
			key := clientKey{iface: "ge-0-0-3", family: AFInet}
			prev := v4Lease("10.0.0.5/24")
			if err := m.commitLease(key, prev, nil, nil, nil); err != nil {
				t.Fatalf("initial commitLease: %v", err)
			}
			disarmRecompile(m)

			if err := m.commitLease(key, tt.next, prev, nil, nil); err != nil {
				t.Fatalf("renewal commitLease: %v", err)
			}
			got := m.LeaseFor("ge-0-0-3", AFInet)
			if got == nil || got.Address != tt.next.Address {
				t.Fatalf("renewed lease not stored: %+v", got)
			}
			if !recompileArmed(m) {
				t.Fatal("changed-content renewal must fire onAddressChange")
			}
			disarmRecompile(m)
		})
	}
}

// TestCommitLeaseDelegatedPrefixes pins the DHCPv6 PD handling: PDs are
// stored on commit, an empty IA_PD reply retains the previous PDs
// (pre-#1777 semantics), an unchanged PD set does not fire the
// callback, and a changed set does.
func TestCommitLeaseDelegatedPrefixes(t *testing.T) {
	m := NewManagerForTesting(nil)
	key := clientKey{iface: "ge-0-0-3", family: AFInet6}
	pds := []DelegatedPrefix{{
		Interface:         "ge-0-0-3",
		Prefix:            netip.MustParsePrefix("2001:db8:1000::/56"),
		PreferredLifetime: time.Hour,
		ValidLifetime:     2 * time.Hour,
		Obtained:          time.Now(),
	}}
	lease := &Lease{
		Interface: "ge-0-0-3",
		Family:    AFInet6,
		Address:   netip.MustParsePrefix("2001:db8::5/128"),
		LeaseTime: time.Hour,
		Obtained:  time.Now(),
	}

	if err := m.commitLease(key, lease, nil, pds, nil); err != nil {
		t.Fatalf("initial commitLease: %v", err)
	}
	if got := m.DelegatedPrefixes(); len(got) != 1 || got[0].Prefix != pds[0].Prefix {
		t.Fatalf("delegated prefixes not stored: %+v", got)
	}
	disarmRecompile(m)

	// Renewal with the same address and the same PD set (fresh
	// Obtained): stored, no callback.
	samePDs := []DelegatedPrefix{pds[0]}
	samePDs[0].Obtained = time.Now().Add(time.Minute)
	renewed := *lease
	renewed.Obtained = time.Now().Add(time.Minute)
	if err := m.commitLease(key, &renewed, lease, samePDs, pds); err != nil {
		t.Fatalf("renewal commitLease: %v", err)
	}
	if recompileArmed(m) {
		t.Fatal("unchanged lease+PD renewal must not fire onAddressChange")
	}

	// Renewal reply with no IA_PD options: previously delegated
	// prefixes stay stored, no callback.
	if err := m.commitLease(key, &renewed, &renewed, nil, samePDs); err != nil {
		t.Fatalf("empty-PD commitLease: %v", err)
	}
	if got := m.DelegatedPrefixes(); len(got) != 1 {
		t.Fatalf("empty-PD reply must retain stored prefixes, got %+v", got)
	}
	if recompileArmed(m) {
		t.Fatal("empty-PD renewal with unchanged lease must not fire onAddressChange")
	}

	// Renewal with a different PD set: stored + callback.
	newPDs := []DelegatedPrefix{{
		Interface:         "ge-0-0-3",
		Prefix:            netip.MustParsePrefix("2001:db8:2000::/56"),
		PreferredLifetime: time.Hour,
		ValidLifetime:     2 * time.Hour,
		Obtained:          time.Now(),
	}}
	if err := m.commitLease(key, &renewed, &renewed, newPDs, samePDs); err != nil {
		t.Fatalf("changed-PD commitLease: %v", err)
	}
	if got := m.DelegatedPrefixes(); len(got) != 1 || got[0].Prefix != newPDs[0].Prefix {
		t.Fatalf("changed PD set not stored: %+v", got)
	}
	if !recompileArmed(m) {
		t.Fatal("changed-PD renewal must fire onAddressChange")
	}
	disarmRecompile(m)
}

// TestCommitLeaseStatelessNoAddress: a stateless DHCPv6 lease (no
// address) commits its DNS without touching address state, and an
// unchanged hourly refresh stays silent.
func TestCommitLeaseStatelessNoAddress(t *testing.T) {
	m := NewManagerForTesting(nil)
	key := clientKey{iface: "ge-0-0-3", family: AFInet6}
	lease := &Lease{
		Interface: "ge-0-0-3",
		Family:    AFInet6,
		DNS:       []netip.Addr{netip.MustParseAddr("2001:db8::53")},
		LeaseTime: time.Hour,
		Obtained:  time.Now(),
	}

	if err := m.commitLease(key, lease, nil, nil, nil); err != nil {
		t.Fatalf("initial commitLease: %v", err)
	}
	if got := m.LeaseFor("ge-0-0-3", AFInet6); got == nil || len(got.DNS) != 1 {
		t.Fatalf("stateless lease not stored: %+v", got)
	}
	if !recompileArmed(m) {
		t.Fatal("initial stateless commit must fire onAddressChange")
	}
	disarmRecompile(m)

	refresh := *lease
	refresh.Obtained = time.Now().Add(time.Hour)
	if err := m.commitLease(key, &refresh, lease, nil, nil); err != nil {
		t.Fatalf("refresh commitLease: %v", err)
	}
	if recompileArmed(m) {
		t.Fatal("unchanged stateless refresh must not fire onAddressChange")
	}
}
