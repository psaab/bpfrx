// ddns_iapd_5072_test.go — #5072.
//
// End-to-end of the keaLeaseParser → pkg/ddns engine wiring for the v6
// lease_type discriminator: a Kea memfile with BOTH an active IA_NA address
// lease and an active IA_PD delegated-prefix binding must publish ONLY the
// IA_NA lease. Before #5072 the adapter dropped the lease_type field, so the
// reconciler read the IA_PD prefix base (e.g. 2001:db8:bbbb::) as a host
// address and published an AAAA/PTR for a delegated network base — an
// info-disclosure / policy violation. The fix carries lease_type through the
// adapter and rejects any non-address lease (IA_PD / unknown) via an explicit
// address-lease allowlist before name/record derivation.
package dhcpserver

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestDDNSMixedIANAIAPDPublishesOnlyIANA(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	_, p6 := m.DDNSLeasePaths()

	cfg := &config.DHCPServerConfig{
		DynamicDNS: &config.DHCPDynamicDNSConfig{
			Enabled:    true,
			Domain:     "example.com",
			TTLSeconds: 300,
		},
	}

	// A v6 memfile with two ACTIVE (state 0) leases differing ONLY in
	// lease_type: row 1 is IA_NA (lease_type 0, a host address); row 2 is IA_PD
	// (lease_type 2, a delegated-prefix base). Both carry a publishable
	// hostname, so before #5072 both produced an AAAA.
	writeCSV(t, p6, `address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state
2001:db8:aaaa::10,00:01:00:01:de:ad,3600,1900000000,1,1800,0,7,128,1,1,host-na,aa:bb,0
2001:db8:bbbb::,00:01:00:01:be:ef,3600,1900000000,1,1800,2,8,56,1,1,net-pd,aa:cc,0
`)

	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// Exactly one publish — the IA_NA host — and nothing for the IA_PD base.
	up.mu.Lock()
	upserts := append([]LeaseDNSRecord(nil), up.upserts...)
	up.mu.Unlock()

	var sawIANA bool
	for _, r := range upserts {
		if r.Addr.String() == "2001:db8:bbbb::" || r.FQDN == "net-pd.example.com" {
			t.Fatalf("IA_PD delegated-prefix base was published as host DNS "+
				"(%s -> %s) — a prefix binding must never become an AAAA/PTR (#5072)",
				r.FQDN, r.Addr)
		}
		if r.Addr.String() == "2001:db8:aaaa::10" && r.FQDN == "host-na.example.com" {
			sawIANA = true
		}
	}
	if !sawIANA {
		t.Fatalf("IA_NA address lease was not published; upserts=%+v", upserts)
	}

	// The IA_NA record is owned; the IA_PD base is NOT owned.
	if !m.OwnedForTesting("duid:00:01:00:01:de:ad/7", "2001:db8:aaaa::10") {
		t.Fatal("IA_NA lease not recorded as owned")
	}
	if m.OwnedForTesting("duid:00:01:00:01:be:ef/8", "2001:db8:bbbb::") {
		t.Fatal("IA_PD delegated-prefix base was recorded as an owned host record (#5072)")
	}

	// The skip is observable on the stats counter.
	if got := m.Stats().SkippedNonAddress; got != 1 {
		t.Fatalf("Stats().SkippedNonAddress = %d, want 1 (the IA_PD lease)", got)
	}
}
