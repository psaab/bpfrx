package api

import (
	"crypto/x509"
	"net"
	"testing"
)

// certLeaf generates a fresh self-signed cert with tlsHostname pinned to
// hostname and returns the parsed leaf. It fails the test if cert generation
// returns an error — the point of most #5719 cases is that a weird hostname
// must NOT abort generation.
func certLeaf(t *testing.T, hostname string) *x509.Certificate {
	t.Helper()
	resetTLSSeams(t)
	tlsHostname = func() (string, error) { return hostname, nil }
	dir, certPath, keyPath := tlsPaths(t)
	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath)
	if err != nil {
		t.Fatalf("hostname=%q: cert generation aborted: %v", hostname, err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatalf("hostname=%q: no certificate produced", hostname)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("hostname=%q: parse leaf: %v", hostname, err)
	}
	return leaf
}

func hasIPSAN(leaf *x509.Certificate, ip net.IP) bool {
	for _, s := range leaf.IPAddresses {
		if s.Equal(ip) {
			return true
		}
	}
	return false
}

func hasDNSSAN(leaf *x509.Certificate, name string) bool {
	for _, s := range leaf.DNSNames {
		if s == name {
			return true
		}
	}
	return false
}

// assertLoopbackSANs is the invariant that must hold for EVERY generated cert
// regardless of hostname: localhost DNS + 127.0.0.1 / ::1 IP SANs are always
// present, so a loopback-bound HTTPS client always verifies.
func assertLoopbackSANs(t *testing.T, leaf *x509.Certificate) {
	t.Helper()
	if len(leaf.DNSNames) == 0 {
		t.Fatal("generated cert has no DNS SANs; modern TLS clients reject CN-only certs")
	}
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Fatalf("VerifyHostname(localhost) = %v; want valid (cert lacks a localhost SAN)", err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("VerifyHostname(127.0.0.1) = %v; want valid (cert lacks a 127.0.0.1 IP SAN)", err)
	}
	if !hasIPSAN(leaf, net.IPv6loopback) {
		t.Fatalf("generated cert IP SANs %v missing ::1", leaf.IPAddresses)
	}
}

// TestGenerateSelfSignedCertHasSANs is a FAIL-ON-REVERT guard for the #5719
// (codex-review-182 C-API) SAN-less-generated-cert TLS hygiene gap: the
// generated HTTPS cert must carry Subject Alternative Names, not just a
// CommonName. A SAN-less cert is rejected by every modern TLS client for
// hostname verification ("x509: certificate is not valid for any names").
//
// RED on revert: drop the DNSNames/IPAddresses fields from the cert template
// and assertLoopbackSANs fails.
func TestGenerateSelfSignedCertHasSANs(t *testing.T) {
	// A plain ASCII hostname must appear as a DNS SAN alongside the loopback
	// SANs (this is the "hostname SAN is present for a valid hostname"
	// assertion the review asked for).
	leaf := certLeaf(t, "fw-node0")
	assertLoopbackSANs(t, leaf)
	if !hasDNSSAN(leaf, "fw-node0") {
		t.Fatalf("valid hostname not in DNS SANs %v", leaf.DNSNames)
	}
	if leaf.Subject.CommonName != "fw-node0" {
		t.Fatalf("CommonName = %q, want fw-node0", leaf.Subject.CommonName)
	}
}

// TestGenerateSelfSignedCertHostnameSANClassification is a FAIL-ON-REVERT
// guard for the #5719 FOLD-1/FOLD-2 hostname-guard: a non-ASCII kernel
// hostname must NOT abort cert generation (x509 marshals DNSNames as an
// IA5String and HARD-FAILS on non-ASCII — under the #5058 all-or-nothing
// management-server lifecycle that would tear down the whole HTTP+HTTPS
// server), and an IP-literal hostname must land in IPAddresses (a DNS SAN of
// an IP never verifies as an IP), never in DNSNames.
//
// RED on revert:
//   - Remove the isDNSSANSafeHostname guard (append the raw hostname to
//     DNSNames): the "café" / "fw_node\n" cases make generateSelfSignedCertAt
//     return an IA5String error → certLeaf's t.Fatalf fires.
//   - Remove the net.ParseIP → IPAddresses branch: the "10.9.9.9" case has no
//     10.9.9.9 IP SAN (and, if appended to DNSNames instead, VerifyHostname on
//     the IP still fails), tripping the assertions below.
func TestGenerateSelfSignedCertHostnameSANClassification(t *testing.T) {
	t.Run("non_ascii_hostname_degrades_to_loopback", func(t *testing.T) {
		leaf := certLeaf(t, "café")
		assertLoopbackSANs(t, leaf)
		if hasDNSSAN(leaf, "café") {
			t.Fatal("non-ASCII hostname must not be a DNS SAN")
		}
		// CommonName may legally carry the raw (UTF-8) hostname.
		if leaf.Subject.CommonName != "café" {
			t.Fatalf("CommonName = %q, want café", leaf.Subject.CommonName)
		}
	})

	t.Run("control_char_hostname_degrades_to_loopback", func(t *testing.T) {
		leaf := certLeaf(t, "fw_node\n")
		assertLoopbackSANs(t, leaf)
		if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "localhost" {
			t.Fatalf("malformed hostname must degrade to localhost-only DNS SANs, got %v", leaf.DNSNames)
		}
	})

	t.Run("ip_literal_hostname_goes_to_ip_sans", func(t *testing.T) {
		leaf := certLeaf(t, "10.9.9.9")
		assertLoopbackSANs(t, leaf)
		if hasDNSSAN(leaf, "10.9.9.9") {
			t.Fatal("IP-literal hostname must not be a DNS SAN")
		}
		if !hasIPSAN(leaf, net.ParseIP("10.9.9.9")) {
			t.Fatalf("IP-literal hostname missing from IP SANs %v", leaf.IPAddresses)
		}
		if err := leaf.VerifyHostname("10.9.9.9"); err != nil {
			t.Fatalf("VerifyHostname(10.9.9.9) = %v; want valid", err)
		}
	})

	t.Run("empty_hostname_degrades_to_loopback", func(t *testing.T) {
		leaf := certLeaf(t, "")
		assertLoopbackSANs(t, leaf)
		if leaf.Subject.CommonName != "xpf" {
			t.Fatalf("empty hostname CommonName = %q, want xpf fallback", leaf.Subject.CommonName)
		}
	})
}

// TestIsDNSSANSafeHostname unit-checks the classifier directly.
func TestIsDNSSANSafeHostname(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"fw-node0", true},
		{"fw.example.com", true},
		{"host123", true},
		{"", false},
		{"café", false},
		{"fw_node\n", false},
		{"has space", false},
		{"under_score", false},
		{"10.9.9.9", false}, // IP literal → IPAddresses, not DNSNames
		{"::1", false},
	}
	for _, c := range cases {
		if got := isDNSSANSafeHostname(c.in); got != c.want {
			t.Errorf("isDNSSANSafeHostname(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
