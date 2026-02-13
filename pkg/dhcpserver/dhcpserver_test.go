package dhcpserver

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseLeaseCSV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-leases4.csv")
	csv := `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.0.1.100,aa:bb:cc:dd:ee:01,,86400,1707868800,1,0,0,client1,0,,0
10.0.1.101,aa:bb:cc:dd:ee:02,,86400,1707955200,1,0,0,client2,0,,0
`
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}

	leases, err := parseLeaseCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 2 {
		t.Fatalf("got %d leases, want 2", len(leases))
	}

	l := leases[0]
	if l.Address != "10.0.1.100" {
		t.Errorf("address: got %q", l.Address)
	}
	if l.HWAddress != "aa:bb:cc:dd:ee:01" {
		t.Errorf("hwaddr: got %q", l.HWAddress)
	}
	if l.Hostname != "client1" {
		t.Errorf("hostname: got %q", l.Hostname)
	}
	if l.ValidLife != "86400" {
		t.Errorf("valid_lifetime: got %q", l.ValidLife)
	}
	if l.SubnetID != "1" {
		t.Errorf("subnet_id: got %q", l.SubnetID)
	}
}

func TestParseLeaseCSV_NoFile(t *testing.T) {
	leases, err := parseLeaseCSV("/nonexistent/path")
	if err != nil {
		t.Fatal(err)
	}
	if leases != nil {
		t.Errorf("expected nil for nonexistent file, got %v", leases)
	}
}

func TestParseLeaseCSV_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-leases4.csv")
	if err := os.WriteFile(path, []byte("address,hwaddr\n"), 0644); err != nil {
		t.Fatal(err)
	}

	leases, err := parseLeaseCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 0 {
		t.Errorf("expected no leases, got %d", len(leases))
	}
}
