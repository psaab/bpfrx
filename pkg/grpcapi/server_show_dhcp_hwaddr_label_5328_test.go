package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

// TestShowDHCPServer_V6ColumnLabeledHWAddress_5328 is the #5328 (A8-b2-F6)
// RED-on-revert guard for the gRPC DHCP-server renderer reached by the remote
// `cmd/cli`. Kea's GetLeases6 populates Lease.HWAddress (the link-layer
// address), NOT the client DUID/IAID, so the DHCPv6 lease table's second column
// must be labeled "HWAddress". The pre-fix header said "DUID" while rendering
// l.HWAddress — the exact mislabel #4908 fixed in pkg/cli but which this remote
// renderer still carried.
//
// FAIL-ON-REVERT: restore the "DUID" header → the "HWAddress" assertion goes
// RED (and the no-"DUID" assertion catches the reintroduced mislabel).
func TestShowDHCPServer_V6ColumnLabeledHWAddress_5328(t *testing.T) {
	dir := t.TempDir()
	// v4 absent → healthy empty (no banner, no v4 table).
	leaseFile4 := filepath.Join(dir, "leases4.csv")
	// One active (state=0), non-expired (expire far in the future) v6 lease
	// carrying a distinctive hwaddr so we can prove a lease actually rendered.
	leaseFile6 := filepath.Join(dir, "leases6.csv")
	const hwaddr = "aa:bb:cc:dd:ee:ff"
	csv := "address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state\n" +
		"2001:db8::5,00:01:00:01:de:ad,3600,4000000000,1,1800,0,7,128,1,1,host-6," + hwaddr + ",0\n"
	if err := os.WriteFile(leaseFile6, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}

	m := dhcpserver.New()
	m.SetLeaseSyncSeamsForTesting(nil, "", "", leaseFile4, leaseFile6)
	m.SetUnitActiveForTesting(func(unit string) (bool, error) { return true, nil })

	s := &Server{dhcpServer: m}
	var buf strings.Builder
	s.showDHCPServer(&buf)
	out := buf.String()

	if !strings.Contains(out, "DHCPv6 Leases") {
		t.Fatalf("expected a DHCPv6 lease table (lease did not render):\n%s", out)
	}
	if !strings.Contains(out, hwaddr) {
		t.Fatalf("expected the v6 lease hwaddr %q to render:\n%s", hwaddr, out)
	}
	if !strings.Contains(out, "HWAddress") {
		t.Fatalf("DHCPv6 lease column must be labeled HWAddress (#5328 A8-b2-F6):\n%s", out)
	}
	if strings.Contains(out, "DUID") {
		t.Fatalf("DHCPv6 lease column mislabeled DUID while rendering HWAddress:\n%s", out)
	}
}
