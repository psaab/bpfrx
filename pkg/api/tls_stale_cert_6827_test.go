package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
)

// #6827: three defects in the #5719 stale-management-cert diagnostic, all of
// them cases where the check says nothing when it should, or says something when
// it should not. The guards live in their own file because they pin the
// diagnostic's REACH and its FALSE-POSITIVE rule, not the SAN-minting behaviour
// tls_san_5719_test.go covers.

// captureWarn redirects slog to a buffer for the duration of fn and returns what
// was logged at WARN or above.
func captureWarn(t *testing.T, fn func()) string {
	t.Helper()
	restore := slog.Default()
	t.Cleanup(func() { slog.SetDefault(restore) })
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	fn()
	slog.SetDefault(restore)
	return buf.String()
}

// mintCert mints (not loads) a durable pair for hostname + bindHost in a fresh
// temp dir and returns the tls.Certificate. Minting is silent by construction —
// the diagnostic only runs on the LOAD path — so a caller can use the result as
// a fixture without filtering mint-time output.
func mintCert(t *testing.T, hostname, bindHost string) tls.Certificate {
	t.Helper()
	resetTLSSeams(t)
	tlsHostname = func() (string, error) { return hostname, nil }
	dir, certPath, keyPath := tlsPaths(t)
	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, bindHost)
	if err != nil {
		t.Fatalf("mint (host %q bind %q): %v", hostname, bindHost, err)
	}
	return cert
}

// legServing returns a Server whose LIVE HTTPS leg serves cert at addr.
// Constructing the leg directly (rather than binding a socket) keeps the test
// deterministic: WarnStaleMgmtCertForHostName reads only httpsLeg.srv.
func legServing(cert tls.Certificate, addr string) *Server {
	s := &Server{}
	s.httpsLeg = &listenerLeg{srv: &http.Server{
		Addr:      addr,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}}
	return s
}

const (
	noSANMsg    = "carries NO subjectAltName"
	hostNameMsg = "does not cover the current host-name"
	bindHostMsg = "does not cover bind host"
)

// TestLoadedCertWithoutSANsWarns_6827 is a FAIL-ON-REVERT guard for the SILENT
// no-SAN certificate (#6827).
//
// Both per-identity predicates gate out loopback and "localhost" on the premise
// that "the durable cert always carries the loopback SANs". That premise holds
// for a cert THIS build minted, but the load path takes whatever is on disk: a
// pair persisted by an older build (or placed by an operator) can carry no SAN
// extension at all. With a CN-only cert, hostname `localhost` and bind
// 127.0.0.1, bindHostWarnable and hostnameSANWarnable are BOTH false, so the old
// code returned before it ever parsed the leaf — total silence on the most
// broken certificate possible, while every modern client rejects it for
// `https://localhost` AND `https://127.0.0.1` (CN is not consulted without a
// SAN).
//
// RED on revert: drop the warnCertNoSANs call from warnStaleLoadedCert (or make
// certHasNoSANs always return false) and the load emits nothing.
func TestLoadedCertWithoutSANsWarns_6827(t *testing.T) {
	resetTLSSeams(t)
	tlsHostname = func() (string, error) { return "localhost", nil }
	dir, certPath, keyPath := tlsPaths(t)

	// Seed a CN-only pair (genPair carries no DNSNames/IPAddresses at all) so the
	// load path finds a usable-but-SAN-less certificate on disk.
	certPEM, keyPEM := genPair(t)
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	out := captureWarn(t, func() {
		cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, "127.0.0.1")
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		leaf, perr := x509.ParseCertificate(cert.Certificate[0])
		if perr != nil {
			t.Fatalf("parse: %v", perr)
		}
		// Precondition: the seeded pair was LOADED as-is, not re-minted (a
		// re-mint would add the loopback SANs and make the case vacuous). Read
		// the leaf directly rather than through certHasNoSANs — the predicate is
		// part of what this test pins, so routing the precondition through it
		// would report a fixture failure when the predicate is what broke.
		if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 {
			t.Fatalf("fixture re-minted: DNS %v IP %v", leaf.DNSNames, leaf.IPAddresses)
		}
	})

	if !strings.Contains(out, noSANMsg) {
		t.Fatalf("a SAN-less management cert must be diagnosed; got log %q", out)
	}
	// Terminal: the per-identity lines would each report "does not cover X" for a
	// cert that covers no X whatsoever, burying the finding under symptoms.
	if strings.Contains(out, hostNameMsg) || strings.Contains(out, bindHostMsg) {
		t.Fatalf("the no-SAN diagnostic must be terminal, not accompanied by per-identity lines; got %q", out)
	}
}

// TestUnusedKernelHostNameIsSilent_6827 is the FALSE-POSITIVE guard, and its two
// subtests are a matched pair: they differ ONLY in the naming shape of the
// cert's DNS SAN, which is the whole discriminator (#6827).
//
// A box named `fw` whose cert covers `mgmt.example.com` and its management IP is
// verifiable at every URL in use; warning that the cert misses the unused short
// kernel name tells the operator to re-mint (churning remote TOFU pins) to fix
// nothing, and a diagnostic that fires on a healthy box gets muted — taking the
// true positive with it.
//
// RED on revert: delete the hostNameLikelyAccessIdentity gate from
// warnStaleHostName and unused_qualified_cert_identity_is_silent fails.
// Deleting the whole host-name branch instead fails drifted_short_name_warns,
// which is why both halves are asserted here.
func TestUnusedKernelHostNameIsSilent_6827(t *testing.T) {
	// mintThenReload mints for mintHost/bind, then RELOADS as reloadHost with the
	// bind UNCHANGED, returning what the reload logged.
	mintThenReload := func(t *testing.T, mintHost, reloadHost, bind string) string {
		t.Helper()
		resetTLSSeams(t)
		tlsHostname = func() (string, error) { return mintHost, nil }
		dir, certPath, keyPath := tlsPaths(t)
		if _, err := generateSelfSignedCertAt(dir, certPath, keyPath, bind); err != nil {
			t.Fatalf("mint as %q: %v", mintHost, err)
		}
		tlsHostname = func() (string, error) { return reloadHost, nil }
		return captureWarn(t, func() {
			if _, err := generateSelfSignedCertAt(dir, certPath, keyPath, bind); err != nil {
				t.Fatalf("reload as %q: %v", reloadHost, err)
			}
		})
	}

	t.Run("unused_qualified_cert_identity_is_silent", func(t *testing.T) {
		// Cert DNS SANs [localhost, mgmt.example.com] + IP SAN 10.0.0.1; the box
		// is now named `fw` and is reached only as https://mgmt.example.com or by
		// IP. Both are covered — nothing is wrong, so nothing may be said.
		out := mintThenReload(t, "mgmt.example.com", "fw", "10.0.0.1")
		if strings.Contains(out, hostNameMsg) {
			t.Fatalf("a short kernel name next to a domain-qualified cert identity is not an access "+
				"identity and must not be diagnosed; got %q", out)
		}
	})

	t.Run("drifted_short_name_warns", func(t *testing.T) {
		// Same shape, but the cert's identity is the UNQUALIFIED `old-fw` — only
		// this package's mint path puts a bare name there, and what it puts there
		// is the kernel host name. So the TLS identity IS the kernel name and it
		// has drifted: diagnose.
		out := mintThenReload(t, "old-fw", "new-fw", "10.0.0.1")
		if !strings.Contains(out, hostNameMsg) {
			t.Fatalf("a drifted unqualified kernel name must still be diagnosed; got %q", out)
		}
	})
}

// TestHostNameLikelyAccessIdentity_6827 unit-checks the narrowing predicate
// directly so a neutralization is caught even if the load-path integration
// changes.
func TestHostNameLikelyAccessIdentity_6827(t *testing.T) {
	shortLeaf := leafOf(t, mintCert(t, "old-fw", "10.0.0.1"))  // DNS: localhost, old-fw
	fqdnLeaf := leafOf(t, mintCert(t, "mgmt.example.com", "")) // DNS: localhost, mgmt.example.com
	loopbackLeaf := leafOf(t, mintCert(t, "localhost", ""))    // DNS: localhost only
	ipLeaf := leafOf(t, mintCert(t, "10.9.9.9", ""))           // IP: loopback + 10.9.9.9

	cases := []struct {
		name string
		leaf *x509.Certificate
		host string
		want bool
	}{
		{"short_name_short_san", shortLeaf, "new-fw", true},
		{"short_name_fqdn_san", fqdnLeaf, "fw", false},
		{"fqdn_name_fqdn_san", fqdnLeaf, "fw2.example.com", true},
		{"fqdn_name_short_san", shortLeaf, "fw.example.com", false},
		{"short_name_loopback_only_san", loopbackLeaf, "fw", false},
		{"ip_name_with_nonloopback_ip_san", ipLeaf, "10.9.9.10", true},
		{"ip_name_loopback_only_ip_san", loopbackLeaf, "10.9.9.10", false},
	}
	for _, c := range cases {
		if got := hostNameLikelyAccessIdentity(c.leaf, c.host); got != c.want {
			t.Errorf("%s: hostNameLikelyAccessIdentity(%q) = %v, want %v (DNS %v IP %v)",
				c.name, c.host, got, c.want, c.leaf.DNSNames, c.leaf.IPAddresses)
		}
	}
}

func leafOf(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

// TestWarnStaleMgmtCertForHostName_6827 is a FAIL-ON-REVERT guard for the second
// entry point — the one a `set system host-name` commit actually reaches.
//
// The load-path diagnostic runs only while a certificate is being loaded, and
// the HTTPS leg reloads only on a TLS/bind change, so a rename on an unchanged
// endpoint never reached it. This entry point takes the host name as a
// PARAMETER, which also removes the apply-ordering hazard: the caller passes the
// name it just applied instead of racing os.Hostname() against the apply order.
//
// RED on revert: delete the WarnStaleMgmtCertForHostName body (return
// immediately) and every warning subtest fails; pass hostNameInferred instead of
// hostNameOperatorSet and operator_chosen_name_overrides_the_heuristic fails.
func TestWarnStaleMgmtCertForHostName_6827(t *testing.T) {
	t.Run("renamed_box_warns_naming_the_new_host_name", func(t *testing.T) {
		s := legServing(mintCert(t, "old-fw", "10.0.0.1"), "10.0.0.1:8443")
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
		if !strings.Contains(out, hostNameMsg) {
			t.Fatalf("a rename onto an uncovered name must warn; got %q", out)
		}
		if !strings.Contains(out, "new-fw") {
			t.Fatalf("the warning must name the NEW host name; got %q", out)
		}
	})

	t.Run("covered_name_is_silent", func(t *testing.T) {
		s := legServing(mintCert(t, "old-fw", "10.0.0.1"), "10.0.0.1:8443")
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("old-fw") })
		if strings.Contains(out, hostNameMsg) {
			t.Fatalf("a name the cert covers must not warn; got %q", out)
		}
	})

	t.Run("operator_chosen_name_overrides_the_heuristic", func(t *testing.T) {
		// The same fixture that must stay SILENT on a cert load
		// (TestUnusedKernelHostNameIsSilent_6827) must WARN here: the operator
		// just chose this name for the device, so it is an access identity by
		// direct evidence rather than by inference.
		s := legServing(mintCert(t, "mgmt.example.com", "10.0.0.1"), "10.0.0.1:8443")
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("fw") })
		if !strings.Contains(out, hostNameMsg) {
			t.Fatalf("a name the operator just applied must be diagnosed regardless of the "+
				"load-path heuristic; got %q", out)
		}
	})

	t.Run("bind_host_is_not_re_reported", func(t *testing.T) {
		// The bind host did not change, so a stale one was already reported when
		// the leg bound; repeating it on every rename is noise.
		s := legServing(mintCert(t, "old-fw", "10.0.0.1"), "10.0.0.2:8443")
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
		if strings.Contains(out, bindHostMsg) {
			t.Fatalf("the rename path must not re-report the bind host; got %q", out)
		}
	})

	t.Run("no_san_cert_is_reported_on_rename_too", func(t *testing.T) {
		certPEM, keyPEM := genPair(t)
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("build SAN-less pair: %v", err)
		}
		s := legServing(cert, "10.0.0.1:8443")
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
		if !strings.Contains(out, noSANMsg) {
			t.Fatalf("a SAN-less cert must be diagnosed on a rename too; got %q", out)
		}
	})

	t.Run("no_live_https_leg_is_a_no_op", func(t *testing.T) {
		out := captureWarn(t, func() { (&Server{}).WarnStaleMgmtCertForHostName("new-fw") })
		if out != "" {
			t.Fatalf("a server with no HTTPS leg serves no management cert; got %q", out)
		}
	})

	t.Run("disabled_https_template_is_not_diagnosed", func(t *testing.T) {
		// httpsServer survives a `ReconcileHTTPS(false, ...)` disable while
		// httpsLeg is cleared. Reading the template would warn about a
		// certificate nobody serves.
		s := &Server{httpsServer: &http.Server{
			Addr:      "10.0.0.1:8443",
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{mintCert(t, "old-fw", "10.0.0.1")}},
		}}
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
		if out != "" {
			t.Fatalf("a disabled HTTPS leg must not be diagnosed; got %q", out)
		}
	})

	t.Run("wildcard_bind_host_still_diagnoses_the_name", func(t *testing.T) {
		// A ":8443" wildcard bind names no single host, so bindHost is "" — the
		// host-name half must still run.
		s := legServing(mintCert(t, "old-fw", ""), ":8443")
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
		if !strings.Contains(out, hostNameMsg) {
			t.Fatalf("a wildcard bind must not suppress the host-name diagnostic; got %q", out)
		}
	})
}

// TestWarnStaleMgmtCertForHostNameReadsTheLiveLeg_6827 pins that the diagnostic
// reads the certificate the live leg is SERVING, not a stale construction
// template, by giving the two different certificates.
func TestWarnStaleMgmtCertForHostNameReadsTheLiveLeg_6827(t *testing.T) {
	live := mintCert(t, "old-fw", "10.0.0.1")  // does NOT cover new-fw
	stale := mintCert(t, "new-fw", "10.0.0.1") // DOES cover new-fw
	s := legServing(live, "10.0.0.1:8443")
	s.httpsServer = &http.Server{
		Addr:      "10.0.0.9:8443",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{stale}},
	}
	out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
	if !strings.Contains(out, hostNameMsg) {
		t.Fatalf("the diagnostic must read the LIVE leg's cert (which misses new-fw), "+
			"not the construction template (which covers it); got %q", out)
	}
}
