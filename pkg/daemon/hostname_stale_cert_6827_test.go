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

// TestWarnStaleMgmtCertForHostNameWithoutServer_6827 pins the nil paths: a
// daemon with the API disabled (no reconciler) and a reconciler whose server
// never bound must both be no-ops rather than a panic on the apply path.
func TestWarnStaleMgmtCertForHostNameWithoutServer_6827(t *testing.T) {
	(&Daemon{}).noteStaleMgmtCertHostName()
	(&Daemon{}).deliverStaleMgmtCertDiagnosis()

	reg := newFakeReg()
	d := &Daemon{}
	d.mgmt = newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	d.noteStaleMgmtCertHostName()
	d.deliverStaleMgmtCertDiagnosis()
}

// stubHostname points the delivery-time kernel-name read at a fixed value.
func stubHostname(t *testing.T, name string) {
	t.Helper()
	restore := osHostname
	t.Cleanup(func() { osHostname = restore })
	osHostname = func() (string, error) { return name, nil }
}

// TestBootHostNameReachesTheDiagnostic_6827 is a FAIL-ON-REVERT guard for the
// BOOT ordering of the hook itself.
//
// The first config apply runs in startup phase 4 while startHTTPServer
// constructs d.mgmt much later in Run, so a `system host-name` applied at boot
// reaches a nil reconciler. Skipping on nil would reproduce the exact silence
// this diagnostic exists to remove, because the fallback — the load path's
// INFERRED heuristic — declines precisely this shape.
//
// RED on revert: make noteStaleMgmtCertHostName return early when d.mgmt is nil
// and boot_rename_is_diagnosed_once_mgmt_is_up logs nothing.
func TestBootHostNameReachesTheDiagnostic_6827(t *testing.T) {
	t.Run("boot_rename_is_diagnosed_once_mgmt_is_up", func(t *testing.T) {
		d := &Daemon{}
		stubHostname(t, "new-fw-6827")
		restoreSet, restorePath := sethostname, hostnamePath
		t.Cleanup(func() { sethostname, hostnamePath = restoreSet, restorePath })
		var applied []string
		sethostname = func(b []byte) error { applied = append(applied, string(b)); return nil }
		hostnamePath = filepath.Join(t.TempDir(), "hostname")

		bootOut := captureDaemonWarn(t, func() {
			cfg := &config.Config{}
			cfg.System.HostName = "new-fw-6827"
			d.applyHostname(cfg)
		})
		if len(applied) != 1 || applied[0] != "new-fw-6827" {
			t.Fatalf("boot apply did not set the kernel name: %v", applied)
		}
		if strings.Contains(bootOut, "does not cover the current host-name") {
			t.Fatalf("nothing is serving a certificate yet; the boot apply must not warn: %q", bootOut)
		}

		m := serveStaleCert(t, d, "old-fw-6827")
		_ = m
		out := captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() })
		if !strings.Contains(out, "does not cover the current host-name") {
			t.Fatalf("a host name applied before the management server existed must still be "+
				"diagnosed once it comes up; got %q", out)
		}
		if !strings.Contains(out, "new-fw-6827") {
			t.Fatalf("the deferred diagnostic must name the host name that was applied; got %q", out)
		}

		// The debt is settled: a second delivery says nothing.
		if again := captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() }); again != "" {
			t.Fatalf("a delivered diagnosis must not repeat; got %q", again)
		}
	})

	t.Run("debt_survives_a_delivery_that_reached_nothing", func(t *testing.T) {
		// MAJOR 1: the old code cleared the parked name whenever the drain RAN,
		// even if nothing was serving. With HTTPS off (or its bind failed) that
		// lost the diagnosis PERMANENTLY — the next boot's applyHostname sees
		// the name already applied and returns early, and the load path's
		// inferred heuristic declines cross-shape drift by design. The
		// certificate is durable on disk, so the staleness outlives the
		// listener and the debt must too.
		reg := newFakeReg()
		d := &Daemon{}
		m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
		d.mgmt = m
		stubHostname(t, "new-fw-6827")
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		// HTTP only: no HTTPS leg, so no certificate is served.
		if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
			t.Fatalf("start HTTP leg: %v", err)
		}

		if out := captureDaemonWarn(t, func() { d.noteStaleMgmtCertHostName() }); out != "" {
			t.Fatalf("with no certificate served there is nothing to diagnose yet; got %q", out)
		}
		d.staleCertMu.Lock()
		pending := d.staleCertPending
		d.staleCertMu.Unlock()
		if !pending {
			t.Fatal("a delivery that reached no certificate must NOT clear the debt (#6827 MAJOR 1)")
		}

		// HTTPS comes up later carrying the stale durable pair: the debt settles.
		dir := t.TempDir()
		seedDurableCert(t, dir, "old-fw-6827", "10.0.0.1")
		m.srv.SetTLSCertDirForTest(dir)
		out := captureDaemonWarn(t, func() {
			if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", nil)); err != nil {
				t.Fatalf("enable HTTPS: %v", err)
			}
			d.deliverStaleMgmtCertDiagnosis()
		})
		if !strings.Contains(out, "does not cover the current host-name") || !strings.Contains(out, "new-fw-6827") {
			t.Fatalf("a later HTTPS enable must settle the outstanding diagnosis; got %q", out)
		}
	})

	t.Run("delivery_reports_the_current_kernel_name", func(t *testing.T) {
		// MAJOR 2's consequence is removed at the root: the name is read from
		// the kernel at DELIVERY, never stored at rename time, so a deferred
		// diagnosis cannot describe a name the box no longer has.
		d := &Daemon{}
		stubHostname(t, "interim-fw-6827")
		d.noteStaleMgmtCertHostName()
		stubHostname(t, "final-fw-6827")
		serveStaleCert(t, d, "old-fw-6827")
		out := captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() })
		if !strings.Contains(out, "final-fw-6827") {
			t.Fatalf("the diagnosis must describe the CURRENT kernel name; got %q", out)
		}
		if strings.Contains(out, "interim-fw-6827") {
			t.Fatalf("the diagnosis must not replay an intermediate name; got %q", out)
		}
	})

	t.Run("rename_onto_the_certified_name_is_silent", func(t *testing.T) {
		d := &Daemon{}
		stubHostname(t, "still-fw-6827")
		serveStaleCert(t, d, "still-fw-6827")
		out := captureDaemonWarn(t, func() { d.noteStaleMgmtCertHostName() })
		if strings.Contains(out, "does not cover the current host-name") {
			t.Fatalf("a covered host name must not warn; got %q", out)
		}
	})

	t.Run("failed_sethostname_is_not_diagnosed", func(t *testing.T) {
		d := &Daemon{}
		stubHostname(t, "old-fw-6827")
		serveStaleCert(t, d, "old-fw-6827")
		restore := sethostname
		t.Cleanup(func() { sethostname = restore })
		sethostname = func([]byte) error { return os.ErrPermission }
		restorePath := hostnamePath
		t.Cleanup(func() { hostnamePath = restorePath })
		hostnamePath = filepath.Join(t.TempDir(), "hostname")
		out := captureDaemonWarn(t, func() {
			cfg := &config.Config{}
			cfg.System.HostName = "new-fw-6827"
			d.applyHostname(cfg)
		})
		if strings.Contains(out, "does not cover the current host-name") {
			t.Fatalf("a rename the kernel rejected must not be diagnosed; got %q", out)
		}
	})
}

// serveStaleCert stands a management server on d with a live HTTPS leg serving a
// durable certificate minted for certName.
func serveStaleCert(t *testing.T, d *Daemon, certName string) *managementReconciler {
	t.Helper()
	reg := newFakeReg()
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
	return m
}

// captureDaemonWarn runs fn with slog redirected to a buffer and returns what
// was logged at WARN or above.
func captureDaemonWarn(t *testing.T, fn func()) string {
	t.Helper()
	restore := slog.Default()
	t.Cleanup(func() { slog.SetDefault(restore) })
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	fn()
	slog.SetDefault(restore)
	return buf.String()
}
