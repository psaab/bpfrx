package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #6468: a DHCP lease hostname (option 12) and the DHCP-DDNS forward record
// name built from it are device-controlled. The in-process interactive CLI
// prints them to the operator's terminal; rendered raw they can smuggle
// terminal escape sequences (OSC 52 clipboard write, CSI erase). These are the
// fail-on-revert guards for the local-CLI surface: dropping the
// termsafe.SanitizeForDisplay calls in show_services_dhcp.go /
// show_services_ddns.go makes the raw ESC/OSC/BEL bytes reappear on stdout.

// An OSC 52 clipboard-write + BEL terminator embedded in a device hostname.
const evilHostname6468 = "pwn\x1b]52;c;YWFhYWFh\x07host"

// A CSI erase-line escape (ESC [ 2 K) embedded in the device-supplied client
// hardware address. Kea stores the chaddr opaque (pkg/dhcpserver stores it via
// the same field() helper as the hostname), so a raw ESC survives to the
// display layer exactly as a hostname does — the HWAddress column feeds the
// operator's terminal on the same lease row and needs the same guard.
const evilHWAddr6468 = "de:ad\x1b[2Kbe:ef"

// hasRawTermControl6468 reports whether s carries a raw terminal control byte —
// any C0 byte EXCEPT the structural \n/\t a rendered table uses, DEL, a C1
// control rune, or an invalid UTF-8 byte.
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

// escapeLeaseManager builds a dhcpserver.Manager returning one active v4 AND one
// active v6 lease whose hostname carries the OSC 52 escape.
func escapeLeaseManager(t *testing.T) *dhcpserver.Manager {
	t.Helper()
	dir := t.TempDir()
	leaseFile4 := filepath.Join(dir, "leases4.csv")
	leaseFile6 := filepath.Join(dir, "leases6.csv")
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

// hwaddrEscapeLeaseManager builds a Manager returning one active v4 AND one
// active v6 lease whose HARDWARE ADDRESS carries the CSI escape while the
// hostname is clean. This isolates the HWAddress termsafe.SanitizeForDisplay
// guard: the hostname-focused fixtures above attack Hostname with a CLEAN
// HWAddress, so dropping the HWAddress sanitize call leaves them all green —
// only a fixture whose evil bytes live in the HWAddress column binds that call.
func hwaddrEscapeLeaseManager(t *testing.T) *dhcpserver.Manager {
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

// newEscapeLeaseCLI wires a CLI with a committed dhcp-local-server config (so
// showDHCPServer passes its "not configured" early return) and a dhcpServerFn
// seam pointing at the supplied malicious lease set.
func newEscapeLeaseCLI(t *testing.T, mgr func() *dhcpserver.Manager) *CLI {
	t.Helper()
	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
system {
    services {
        dhcp-local-server {
            group g {
                interface ge-0-0-0.0;
                pool p {
                    subnet 10.0.1.0/24;
                    address-range low 10.0.1.100 high 10.0.1.199;
                }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &CLI{
		store:        store,
		dhcpServerFn: mgr,
	}
}

func TestShowDHCPServer_LocalCLIEscapesHostname_6468(t *testing.T) {
	for _, detail := range []bool{false, true} {
		c := newEscapeLeaseCLI(t, func() *dhcpserver.Manager { return escapeLeaseManager(t) })
		out := captureStdout(t, func() {
			if err := c.showDHCPServer(detail); err != nil {
				t.Fatalf("showDHCPServer(%v): %v", detail, err)
			}
		})
		if !strings.Contains(out, "10.0.1.50") || !strings.Contains(out, "2001:db8::50") {
			t.Fatalf("detail=%v: both v4 and v6 leases must render (else the guard is vacuous):\n%s", detail, out)
		}
		if hasRawTermControl6468(out) {
			t.Fatalf("detail=%v: local `show dhcp server` emitted raw terminal control bytes "+
				"(unsanitized device hostname reaches the operator terminal, #6468):\n%q", detail, out)
		}
		if !strings.Contains(out, `\x1b`) {
			t.Fatalf("detail=%v: expected the escaped hostname (\\x1b) to render, proving the "+
				"field was sanitized rather than dropped:\n%s", detail, out)
		}
	}
}

func TestShowDHCPServer_LocalCLIEscapesHWAddress_6468(t *testing.T) {
	for _, detail := range []bool{false, true} {
		c := newEscapeLeaseCLI(t, func() *dhcpserver.Manager { return hwaddrEscapeLeaseManager(t) })
		out := captureStdout(t, func() {
			if err := c.showDHCPServer(detail); err != nil {
				t.Fatalf("showDHCPServer(%v): %v", detail, err)
			}
		})
		if !strings.Contains(out, "10.0.1.60") || !strings.Contains(out, "2001:db8::60") {
			t.Fatalf("detail=%v: both v4 and v6 leases must render (else the guard is vacuous):\n%s", detail, out)
		}
		if hasRawTermControl6468(out) {
			t.Fatalf("detail=%v: local `show dhcp server` emitted raw terminal control bytes "+
				"(unsanitized device HWAddress reaches the operator terminal, #6468):\n%q", detail, out)
		}
		if !strings.Contains(out, `\x1b`) {
			t.Fatalf("detail=%v: expected the escaped HWAddress (\\x1b) to render, proving the "+
				"field was sanitized rather than dropped:\n%s", detail, out)
		}
	}
}

func TestShowDHCPDynamicDNS_LocalCLIEscapesFQDN_6468(t *testing.T) {
	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
system {
    services {
        dhcp-local-server {
            dynamic-dns {
                enable;
                domain example.com;
                backend rfc2136;
                update-server 192.0.2.53;
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	c := &CLI{
		store:       store,
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
	out := captureStdout(t, func() {
		if err := c.showDHCPDynamicDNS(true); err != nil {
			t.Fatalf("showDHCPDynamicDNS: %v", err)
		}
	})
	if !strings.Contains(out, "example.com") {
		t.Fatalf("the owned record must render (else the guard is vacuous):\n%s", out)
	}
	if hasRawTermControl6468(out) {
		t.Fatalf("local DDNS owned-record renderer emitted raw terminal control bytes (#6468):\n%q", out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Fatalf("expected the escaped FQDN (\\x1b) to render:\n%s", out)
	}
}
