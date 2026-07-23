package api

import (
	"crypto/x509"
	"net"
	"testing"
)

// TestGenerateSelfSignedCertHasSANs is a FAIL-ON-REVERT guard for the #5719
// (codex-review-182 C-API) SAN-less-generated-cert TLS hygiene gap.
//
// The auto-generated HTTPS cert previously carried only a CommonName and no
// Subject Alternative Names. Every modern TLS client (Go's own client since
// 1.15, browsers, curl) rejects a SAN-less cert for hostname verification with
// "x509: certificate is not valid for any names". The fix populates the DNS
// SANs (hostname + localhost) and the loopback IP SANs (127.0.0.1, ::1) that a
// local or hostname-pinned client actually matches.
//
// RED on revert: drop the DNSNames/IPAddresses fields from the cert template
// and VerifyHostname / the SAN-presence assertions below fail.
func TestGenerateSelfSignedCertHasSANs(t *testing.T) {
	resetTLSSeams(t)
	dir, certPath, keyPath := tlsPaths(t)

	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate produced")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	// A DNS SAN must be present (not just a CommonName).
	if len(leaf.DNSNames) == 0 {
		t.Fatal("generated cert has no DNS SANs; modern TLS clients reject CN-only certs")
	}

	// localhost must be a valid name — the API binds loopback by default, so a
	// local client (curl https://localhost:8443, health probes) must verify.
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Fatalf("VerifyHostname(localhost) = %v; want valid (cert lacks a localhost SAN)", err)
	}

	// The loopback IP SANs must be present so an IP-addressed local client
	// (https://127.0.0.1:8443) also verifies.
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("VerifyHostname(127.0.0.1) = %v; want valid (cert lacks a 127.0.0.1 IP SAN)", err)
	}
	var hasV6Loopback bool
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(net.IPv6loopback) {
			hasV6Loopback = true
			break
		}
	}
	if !hasV6Loopback {
		t.Fatalf("generated cert IP SANs %v missing ::1", leaf.IPAddresses)
	}
}
