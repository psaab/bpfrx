// #6827: a `set system host-name` commit must REACH the stale-management-TLS-
// certificate diagnostic, and the diagnostic must observe the NEW kernel host
// name.
//
// Neither held before this guard. warnStaleLoadedCert runs only while a
// certificate is being loaded (pkg/api generateSelfSignedCertAt), and the
// management reconciler rebuilds the HTTPS leg only when the TLS flag or the
// HTTPS bind address changes — so a plain rename on an unchanged endpoint
// reloaded nothing and said nothing. And because reconcileWebManagement runs
// EARLY in applyConfigLocked (before the dataplane apply, so a credential
// revocation survives an aborting commit) while applyHostname runs in the apply
// tail, even a commit that DID move the HTTPS bind would have diagnosed the OLD
// kernel name.
package daemon

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
)

// seedDurableCert writes a cert/key pair into dir under the names
// SetTLSCertDirForTest hands the loader, minted for dnsName plus the loopback
// SANs and mgmtIP — i.e. the exact shape pkg/api's own mint path produces for a
// box named dnsName with its HTTPS listener on mgmtIP. The HTTPS leg then LOADS
// it as-is (the #1916 D6 durable contract), which is what makes the cert stale
// after a rename.
func seedDurableCert(t *testing.T, dir, dnsName, mgmtIP string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(6827),
		Subject:      pkix.Name{CommonName: dnsName, Organization: []string{"xpf"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", dnsName},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback, net.ParseIP(mgmtIP)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// hostNameCommitFixture stands a live management server up on a fake listener
// with an HTTPS leg serving a durable certificate minted for certName, then
// returns the daemon that owns it. The kernel/disk seams of applyHostname are
// replaced so the rename is exercised without CAP_SYS_ADMIN and without
// touching the test host's /etc/hostname; applied records what was handed to
// Sethostname.
func hostNameCommitFixture(t *testing.T, certName string) (d *Daemon, applied *[]string) {
	t.Helper()
	reg := newFakeReg()
	d = &Daemon{}
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	d.mgmt = m

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
		t.Fatalf("start HTTP leg: %v", err)
	}

	dir := t.TempDir()
	seedDurableCert(t, dir, certName, "10.0.0.1")
	m.srv.SetTLSCertDirForTest(dir)
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", nil)); err != nil {
		t.Fatalf("enable HTTPS: %v", err)
	}
	if m.srv.HTTPSCertForTest() == nil {
		t.Fatal("HTTPS leg is not serving a certificate")
	}

	restoreSet, restorePath := sethostname, hostnamePath
	t.Cleanup(func() { sethostname, hostnamePath = restoreSet, restorePath })
	var got []string
	sethostname = func(b []byte) error { got = append(got, string(b)); return nil }
	hostnamePath = filepath.Join(t.TempDir(), "hostname")
	return d, &got
}

// commitHostName6827 drives the rename and returns everything logged at WARN.
// Capture starts AFTER the fixture is built: enabling HTTPS loads the seeded
// certificate, and that load legitimately diagnoses the TEST HOST's own kernel
// name, which is not what this test is about.
func commitHostName6827(t *testing.T, d *Daemon, hostName string) string {
	t.Helper()
	restore := slog.Default()
	t.Cleanup(func() { slog.SetDefault(restore) })
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	cfg := &config.Config{}
	cfg.System.HostName = hostName
	d.applyHostname(cfg)
	slog.SetDefault(restore)
	return buf.String()
}

// TestHostNameCommitWarnsStaleMgmtCert_6827 is the headline FAIL-ON-REVERT
// guard: `set system host-name new-fw` with the HTTPS endpoint UNCHANGED must
// produce the stale-certificate diagnostic, naming the NEW host name.
//
// The certificate covers `old-fw-6827` and the management IP 10.0.0.1, and the
// bind stays 10.0.0.1:8443 — so the bind-host half of the diagnostic is
// satisfied and only the host-name half can catch this. That is the worked case
// the diagnostic was written for, and the one it could not reach.
//
// RED on revert: delete the d.warnStaleMgmtCertForHostName call from
// applyHostname and renamed_box_is_diagnosed logs nothing. Pass the PRE-rename
// name (`current`) instead of cfg.System.HostName and the assertion that the
// warning names new-fw-6827 fails — the ordering half.
func TestHostNameCommitWarnsStaleMgmtCert_6827(t *testing.T) {
	t.Run("renamed_box_is_diagnosed", func(t *testing.T) {
		d, applied := hostNameCommitFixture(t, "old-fw-6827")
		out := commitHostName6827(t, d, "new-fw-6827")

		if len(*applied) != 1 || (*applied)[0] != "new-fw-6827" {
			t.Fatalf("applyHostname did not apply the new kernel name: %v", *applied)
		}
		if !strings.Contains(out, "does not cover the current host-name") {
			t.Fatalf("a host-name commit on an UNCHANGED HTTPS endpoint must diagnose the stale "+
				"management certificate; got log %q", out)
		}
		if !strings.Contains(out, "new-fw-6827") {
			t.Fatalf("the diagnostic must observe the NEW kernel host name, not the one in place "+
				"before the commit; got %q", out)
		}
	})

	t.Run("rename_onto_the_certified_name_is_silent", func(t *testing.T) {
		// Negative control: the same code path and the same live certificate, but
		// the committed name is the one the certificate names. Sethostname still
		// runs (the test host is called something else), so this is a REAL rename
		// that must stay quiet. Without it, a diagnostic that fired on every
		// rename would pass the positive case for the wrong reason.
		d, applied := hostNameCommitFixture(t, "still-fw-6827")
		out := commitHostName6827(t, d, "still-fw-6827")
		if len(*applied) != 1 {
			t.Fatalf("expected one Sethostname call, got %v", *applied)
		}
		if strings.Contains(out, "does not cover the current host-name") {
			t.Fatalf("a covered host name must not warn; got %q", out)
		}
	})

	t.Run("rename_onto_a_san_only_name_is_silent", func(t *testing.T) {
		// Coverage is decided by the SANs, not by the CommonName: `localhost` is a
		// SAN of a certificate whose CN is old-fw-6827, and committing it must
		// stay silent.
		d, applied := hostNameCommitFixture(t, "old-fw-6827")
		out := commitHostName6827(t, d, "localhost")
		if len(*applied) != 1 {
			t.Fatalf("expected one Sethostname call, got %v", *applied)
		}
		if strings.Contains(out, "does not cover the current host-name") {
			t.Fatalf("renaming onto a name the certificate covers by SAN must not warn; got %q", out)
		}
	})

	t.Run("failed_sethostname_is_not_diagnosed", func(t *testing.T) {
		// The kernel name did not move, so there is nothing new to be stale
		// against; warning here would misreport the running identity.
		d, _ := hostNameCommitFixture(t, "old-fw-6827")
		restore := sethostname
		t.Cleanup(func() { sethostname = restore })
		sethostname = func([]byte) error { return os.ErrPermission }
		out := commitHostName6827(t, d, "new-fw-6827")
		if strings.Contains(out, "does not cover the current host-name") {
			t.Fatalf("a rename that the kernel rejected must not be diagnosed; got %q", out)
		}
	})
}

// TestWarnStaleMgmtCertForHostNameWithoutServer_6827 pins the nil paths: a
// daemon with the API disabled (no reconciler) and a reconciler whose server
// never bound must both be no-ops rather than a panic on the apply path.
func TestWarnStaleMgmtCertForHostNameWithoutServer_6827(t *testing.T) {
	(&Daemon{}).warnStaleMgmtCertForHostName("new-fw-6827")

	reg := newFakeReg()
	d := &Daemon{}
	d.mgmt = newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	d.warnStaleMgmtCertForHostName("new-fw-6827")
}
