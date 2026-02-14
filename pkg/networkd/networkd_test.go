package networkd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateLink(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:       "trust0",
		MACAddress: "52:54:00:aa:bb:cc",
	}
	got := m.generateLink(ifc)
	if !strings.Contains(got, "[Match]\n") {
		t.Error("missing [Match] section")
	}
	if !strings.Contains(got, "MACAddress=52:54:00:aa:bb:cc\n") {
		t.Error("missing MACAddress")
	}
	if !strings.Contains(got, "[Link]\n") {
		t.Error("missing [Link] section")
	}
	if !strings.Contains(got, "Name=trust0\n") {
		t.Error("missing Name")
	}
}

func TestGenerateNetwork_Static(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:      "trust0",
		Addresses: []string{"10.0.1.10/24", "2001:db8::1/64"},
	}
	got := m.generateNetwork(ifc)
	if !strings.Contains(got, "Name=trust0\n") {
		t.Error("missing Name")
	}
	if !strings.Contains(got, "IPv6AcceptRA=no\n") {
		t.Error("missing RA disable")
	}
	if !strings.Contains(got, "LinkLocalAddressing=ipv6\n") {
		t.Error("missing LinkLocalAddressing")
	}
	if !strings.Contains(got, "Address=10.0.1.10/24\n") {
		t.Error("missing IPv4 address")
	}
	if !strings.Contains(got, "Address=2001:db8::1/64\n") {
		t.Error("missing IPv6 address")
	}
}

func TestGenerateNetwork_Unmanaged(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:      "unused0",
		Unmanaged: true,
	}
	got := m.generateNetwork(ifc)
	if !strings.Contains(got, "ActivationPolicy=always-down\n") {
		t.Error("missing ActivationPolicy=always-down")
	}
	if !strings.Contains(got, "RequiredForOnline=no\n") {
		t.Error("missing RequiredForOnline=no")
	}
	if !strings.Contains(got, "DHCP=no\n") {
		t.Error("missing DHCP=no")
	}
	if !strings.Contains(got, "LinkLocalAddressing=no\n") {
		t.Error("missing LinkLocalAddressing=no for unmanaged")
	}
	// Should NOT have any Address= lines
	if strings.Contains(got, "Address=") {
		t.Error("unmanaged interface should not have addresses")
	}
}

func TestGenerateNetwork_VLANParent(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:         "wan0",
		IsVLANParent: true,
		Addresses:    []string{"172.16.50.5/24"}, // should be ignored
	}
	got := m.generateNetwork(ifc)
	if !strings.Contains(got, "RequiredForOnline=no\n") {
		t.Error("missing RequiredForOnline=no for VLAN parent")
	}
	if !strings.Contains(got, "DHCP=no\n") {
		t.Error("missing DHCP=no for VLAN parent")
	}
	if strings.Contains(got, "Address=") {
		t.Error("VLAN parent should not have addresses (they go on sub-interface)")
	}
}

func TestGenerateNetwork_DHCP(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:   "mgmt0",
		DHCPv4: true,
	}
	got := m.generateNetwork(ifc)
	// DHCP interfaces should NOT have static Address= lines
	if strings.Contains(got, "Address=") {
		t.Error("DHCP interface should not have static addresses")
	}
	// But should still have link-local and RA settings
	if !strings.Contains(got, "IPv6AcceptRA=no\n") {
		t.Error("missing RA disable for DHCP interface")
	}
	if !strings.Contains(got, "LinkLocalAddressing=ipv6\n") {
		t.Error("missing LinkLocalAddressing for DHCP interface")
	}
}

func TestFindExternallyManaged(t *testing.T) {
	dir := t.TempDir()

	// Write a non-bpfrx .network file
	external := "[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n"
	os.WriteFile(filepath.Join(dir, "50-mgmt.network"), []byte(external), 0644)

	// Write a bpfrx-managed .network file (should be ignored)
	bpfrx := "[Match]\nName=trust0\n\n[Network]\nAddress=10.0.1.10/24\n"
	os.WriteFile(filepath.Join(dir, filePrefix+"trust0.network"), []byte(bpfrx), 0644)

	// Write a .link file (not .network, should be ignored)
	os.WriteFile(filepath.Join(dir, "99-custom.link"), []byte("[Match]\nName=foo\n"), 0644)

	result := FindExternallyManaged(dir)
	if !result["eth0"] {
		t.Error("eth0 should be externally managed")
	}
	if result["trust0"] {
		t.Error("trust0 should not be externally managed (has bpfrx prefix)")
	}
	if result["foo"] {
		t.Error("foo should not match (was .link, not .network)")
	}
}

func TestWriteIfChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.network")

	// First write — should return true
	if !writeIfChanged(path, "content1") {
		t.Error("first write should return true")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "content1" {
		t.Errorf("got %q, want %q", string(data), "content1")
	}

	// Same content — should return false
	if writeIfChanged(path, "content1") {
		t.Error("same content should return false")
	}

	// Different content — should return true
	if !writeIfChanged(path, "content2") {
		t.Error("different content should return true")
	}
	data, _ = os.ReadFile(path)
	if string(data) != "content2" {
		t.Errorf("got %q, want %q", string(data), "content2")
	}
}

func TestGenerateLink_MTU(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:       "trust0",
		MACAddress: "52:54:00:aa:bb:cc",
		MTU:        1400,
	}
	got := m.generateLink(ifc)
	if !strings.Contains(got, "MTUBytes=1400\n") {
		t.Error("missing MTUBytes=1400 in .link file")
	}

	// MTU=0 should not produce MTUBytes
	ifc.MTU = 0
	got = m.generateLink(ifc)
	if strings.Contains(got, "MTUBytes") {
		t.Error("MTU=0 should not produce MTUBytes line")
	}
}

func TestGenerateNetwork_PrimaryAddress(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:           "trust0",
		Addresses:      []string{"10.0.1.10/24", "10.0.1.20/24", "10.0.1.30/24"},
		PrimaryAddress: "10.0.1.20/24",
	}
	got := m.generateNetwork(ifc)
	// Primary address should appear first
	idx1 := strings.Index(got, "Address=10.0.1.20/24")
	idx2 := strings.Index(got, "Address=10.0.1.10/24")
	idx3 := strings.Index(got, "Address=10.0.1.30/24")
	if idx1 < 0 || idx2 < 0 || idx3 < 0 {
		t.Fatalf("missing addresses in output:\n%s", got)
	}
	if idx1 > idx2 || idx1 > idx3 {
		t.Errorf("primary address should be first, got:\n%s", got)
	}
}

func TestGenerateNetwork_PreferredAddress(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:             "trust0",
		Addresses:        []string{"10.0.1.10/24", "10.0.1.20/24"},
		PreferredAddress: "10.0.1.20/24",
	}
	got := m.generateNetwork(ifc)
	// Should use [Address] sections
	if !strings.Contains(got, "[Address]\n") {
		t.Fatalf("expected [Address] sections, got:\n%s", got)
	}
	// Preferred address should have PreferredLifetime=forever
	if !strings.Contains(got, "Address=10.0.1.20/24\nPreferredLifetime=forever\n") {
		t.Errorf("preferred address should have PreferredLifetime=forever, got:\n%s", got)
	}
	// Non-preferred address should NOT have PreferredLifetime
	// Find the [Address] section for 10.0.1.10
	sections := strings.Split(got, "[Address]\n")
	for _, sec := range sections {
		if strings.HasPrefix(sec, "Address=10.0.1.10/24\n") {
			if strings.Contains(sec, "PreferredLifetime") {
				t.Errorf("non-preferred address should not have PreferredLifetime")
			}
		}
	}
}

func TestGenerateNetwork_PrimaryAndPreferred(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:             "trust0",
		Addresses:        []string{"10.0.1.10/24", "10.0.1.20/24", "2001:db8::1/64"},
		PrimaryAddress:   "10.0.1.20/24",
		PreferredAddress: "10.0.1.20/24",
	}
	got := m.generateNetwork(ifc)
	// Primary should be first [Address] section
	sections := strings.Split(got, "[Address]\n")
	if len(sections) < 2 {
		t.Fatalf("expected [Address] sections, got:\n%s", got)
	}
	// First [Address] section should be the primary+preferred
	if !strings.HasPrefix(sections[1], "Address=10.0.1.20/24\nPreferredLifetime=forever\n") {
		t.Errorf("first address section should be primary+preferred, got:\n%s", got)
	}
}

func TestOrderAddresses(t *testing.T) {
	addrs := []string{"10.0.1.10/24", "10.0.1.20/24", "10.0.1.30/24"}

	// Primary reorders
	got := orderAddresses(addrs, "10.0.1.20/24")
	if got[0] != "10.0.1.20/24" {
		t.Errorf("expected primary first, got %v", got)
	}
	if len(got) != 3 {
		t.Errorf("expected 3 addresses, got %d", len(got))
	}

	// No primary = no change
	got = orderAddresses(addrs, "")
	if got[0] != "10.0.1.10/24" {
		t.Errorf("expected original order, got %v", got)
	}

	// Primary not in list = no change
	got = orderAddresses(addrs, "192.168.1.1/24")
	if got[0] != "10.0.1.10/24" {
		t.Errorf("expected original order for missing primary, got %v", got)
	}
}
