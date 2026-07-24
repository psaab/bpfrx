package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #6468: a DHCP lease hostname (option 12) and the DHCP-DDNS forward record
// name built from it are device-controlled. The gRPC ShowText renderer feeds
// the remote `cli`, which prints resp.Output VERBATIM to the operator's
// terminal (cmd/cli: fmt.Print(resp.Output)), so this surface is the SAME
// terminal-escape-injection vector as the in-process CLI. These are the
// fail-on-revert guards for the remote-cli surface: dropping the
// termsafe.SanitizeForDisplay calls in server_show_dhcp_lldp_snmp.go makes the
// raw ESC/OSC/BEL bytes reappear in the emitted text.

// An OSC 52 clipboard-write + BEL terminator embedded in a device-supplied
// hostname. Rendered raw it would rewrite the operator's clipboard.
const evilHostname6468 = "pwn\x1b]52;c;YWFhYWFh\x07host"

// A CSI erase-line escape (ESC [ 2 K) embedded in the device-supplied client
// hardware address. Kea stores the chaddr opaque (pkg/dhcpserver stores it via
// the same field() helper as the hostname), so a raw ESC survives to the gRPC
// text renderer exactly as a hostname does — the HWAddress column feeds the
// remote cli's verbatim print on the same lease row and needs the same guard.
const evilHWAddr6468 = "de:ad\x1b[2Kbe:ef"

// hasRawTermControl6468 reports whether s carries a raw terminal control byte
// an operator's terminal would act on: any C0 byte EXCEPT the structural \n/\t
// a rendered table legitimately uses, DEL (0x7F), a C1 control rune
// (0x80-0x9F), or an invalid UTF-8 byte. C0/DEL are byte-level (never UTF-8
// continuation/lead bytes); C1 is rune-level so a valid multibyte continuation
// byte in 0x80-0x9F is not mistaken for a control.
func hasRawTermControl6468(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == '\n' || b == '\t' {
			continue
		}
		if b < 0x20 || b == 0x7f {
			return true
		}
	}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return true
		}
		if r >= 0x80 && r <= 0x9f {
			return true
		}
		i += size
	}
	return false
}

// writeEscapeLeaseManager builds a dhcpserver.Manager returning one active v4
// AND one active v6 lease whose hostname carries the OSC 52 escape, with
// IsRunning() forced true (the gRPC renderer gates on it).
func writeEscapeLeaseManager(t *testing.T) *dhcpserver.Manager {
	t.Helper()
	dir := t.TempDir()
	leaseFile4 := filepath.Join(dir, "leases4.csv")
	leaseFile6 := filepath.Join(dir, "leases6.csv")
	// Non-expired (expire far in the future), active (state=0) leases.
	csv4 := "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n" +
		"10.0.1.50,aa:bb:cc:dd:ee:01,,3600,4000000000,1,0,0," + evilHostname6468 + ",0\n"
	csv6 := "address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state\n" +
		"2001:db8::50,00:01:00:01:de:ad,3600,4000000000,1,1800,0,7,128,0,0," + evilHostname6468 + ",aa:bb:cc:dd:ee:02,0\n"
	if err := os.WriteFile(leaseFile4, []byte(csv4), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leaseFile6, []byte(csv6), 0o644); err != nil {
		t.Fatal(err)
	}
	m := dhcpserver.New()
	m.SetLeaseSyncSeamsForTesting(nil, "", "", leaseFile4, leaseFile6)
	m.SetUnitActiveForTesting(func(unit string) (bool, error) { return true, nil })
	return m
}

// writeHWAddrEscapeLeaseManager builds a Manager returning one active v4 AND one
// active v6 lease whose HARDWARE ADDRESS carries the CSI escape while the
// hostname is clean. This isolates the HWAddress termsafe.SanitizeForDisplay
// guard: the hostname fixtures above attack Hostname with a CLEAN HWAddress, so
// dropping the HWAddress sanitize call leaves them green — only evil bytes in
// the HWAddress column bind that call.
func writeHWAddrEscapeLeaseManager(t *testing.T) *dhcpserver.Manager {
	t.Helper()
	dir := t.TempDir()
	leaseFile4 := filepath.Join(dir, "leases4.csv")
	leaseFile6 := filepath.Join(dir, "leases6.csv")
	csv4 := "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n" +
		"10.0.1.60," + evilHWAddr6468 + ",,3600,4000000000,1,0,0,cleanhost4,0\n"
	csv6 := "address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state\n" +
		"2001:db8::60,00:01:00:01:de:ad,3600,4000000000,1,1800,0,7,128,0,0,cleanhost6," + evilHWAddr6468 + ",0\n"
	if err := os.WriteFile(leaseFile4, []byte(csv4), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leaseFile6, []byte(csv6), 0o644); err != nil {
		t.Fatal(err)
	}
	m := dhcpserver.New()
	m.SetLeaseSyncSeamsForTesting(nil, "", "", leaseFile4, leaseFile6)
	m.SetUnitActiveForTesting(func(unit string) (bool, error) { return true, nil })
	return m
}

func TestShowDHCPServer_RemoteCLIEscapesHostname_6468(t *testing.T) {
	s := &Server{dhcpServer: writeEscapeLeaseManager(t)}
	var buf strings.Builder
	s.showDHCPServer(&buf)
	out := buf.String()

	if !strings.Contains(out, "10.0.1.50") || !strings.Contains(out, "2001:db8::50") {
		t.Fatalf("both v4 and v6 leases must render (else the guard is vacuous):\n%s", out)
	}
	if hasRawTermControl6468(out) {
		t.Fatalf("remote-cli DHCP lease renderer emitted raw terminal control bytes "+
			"(unsanitized device hostname reaches the operator terminal, #6468):\n%q", out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Fatalf("expected the escaped hostname (\\x1b) to render, proving the field was "+
			"sanitized rather than dropped:\n%s", out)
	}
}

func TestShowDHCPServerDetail_RemoteCLIEscapesHostname_6468(t *testing.T) {
	// A non-nil local server clears the "No DHCP server configured" early return;
	// the lease tables render from the manager regardless of pool config.
	cfg := &config.Config{}
	cfg.System.DHCPServer.DHCPLocalServer = &config.DHCPLocalServerConfig{}
	cfg.System.DHCPServer.DHCPv6LocalServer = &config.DHCPLocalServerConfig{}

	s := &Server{dhcpServer: writeEscapeLeaseManager(t)}
	var buf strings.Builder
	s.showDHCPServerDetail(cfg, &buf)
	out := buf.String()

	if !strings.Contains(out, "10.0.1.50") || !strings.Contains(out, "2001:db8::50") {
		t.Fatalf("both v4 and v6 detail leases must render (else the guard is vacuous):\n%s", out)
	}
	if hasRawTermControl6468(out) {
		t.Fatalf("remote-cli DHCP detail lease renderer emitted raw terminal control bytes (#6468):\n%q", out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Fatalf("expected the escaped hostname (\\x1b) to render in the detail table:\n%s", out)
	}
}

func TestShowDHCPServer_RemoteCLIEscapesHWAddress_6468(t *testing.T) {
	s := &Server{dhcpServer: writeHWAddrEscapeLeaseManager(t)}
	var buf strings.Builder
	s.showDHCPServer(&buf)
	out := buf.String()

	if !strings.Contains(out, "10.0.1.60") || !strings.Contains(out, "2001:db8::60") {
		t.Fatalf("both v4 and v6 leases must render (else the guard is vacuous):\n%s", out)
	}
	if hasRawTermControl6468(out) {
		t.Fatalf("remote-cli DHCP lease renderer emitted raw terminal control bytes "+
			"(unsanitized device HWAddress reaches the operator terminal, #6468):\n%q", out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Fatalf("expected the escaped HWAddress (\\x1b) to render, proving the field was "+
			"sanitized rather than dropped:\n%s", out)
	}
}

func TestShowDHCPServerDetail_RemoteCLIEscapesHWAddress_6468(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.DHCPServer.DHCPLocalServer = &config.DHCPLocalServerConfig{}
	cfg.System.DHCPServer.DHCPv6LocalServer = &config.DHCPLocalServerConfig{}

	s := &Server{dhcpServer: writeHWAddrEscapeLeaseManager(t)}
	var buf strings.Builder
	s.showDHCPServerDetail(cfg, &buf)
	out := buf.String()

	if !strings.Contains(out, "10.0.1.60") || !strings.Contains(out, "2001:db8::60") {
		t.Fatalf("both v4 and v6 detail leases must render (else the guard is vacuous):\n%s", out)
	}
	if hasRawTermControl6468(out) {
		t.Fatalf("remote-cli DHCP detail lease renderer emitted raw terminal control bytes "+
			"(unsanitized device HWAddress, #6468):\n%q", out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Fatalf("expected the escaped HWAddress (\\x1b) to render in the detail table:\n%s", out)
	}
}

func TestShowDHCPDynamicDNS_RemoteCLIEscapesFQDN_6468(t *testing.T) {
	// The owned-record FQDN is built from the device-supplied client hostname.
	cfg := &config.Config{}
	cfg.System.DHCPServer.DynamicDNS = &config.DHCPDynamicDNSConfig{Enabled: true}

	s := &Server{
		ddnsStatsFn: func() *dhcpserver.DDNSStats { return &dhcpserver.DDNSStats{} },
		ddnsOwnedRecordsFn: func() []dhcpserver.DDNSOwnedRecordView {
			return []dhcpserver.DDNSOwnedRecordView{{
				FQDN:        evilHostname6468 + ".example.com",
				ForwardType: "A",
				Address:     "10.0.1.50",
				PTRName:     "50.1.0.10.in-addr.arpa",
			}}
		},
	}
	var buf strings.Builder
	s.showDHCPDynamicDNS(cfg, &buf, true)
	out := buf.String()

	if !strings.Contains(out, "example.com") {
		t.Fatalf("the owned record must render (else the guard is vacuous):\n%s", out)
	}
	if hasRawTermControl6468(out) {
		t.Fatalf("remote-cli DDNS owned-record renderer emitted raw terminal control bytes (#6468):\n%q", out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Fatalf("expected the escaped FQDN (\\x1b) to render:\n%s", out)
	}
}
