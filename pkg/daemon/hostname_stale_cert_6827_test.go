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
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
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
// SCOPE: these subtests drive deliverStaleMgmtCertDiagnosis DIRECTLY, so they
// bind the MECHANISM — a debt parked against a nil reconciler survives, and
// settles once something is serving a certificate. They say nothing about
// WHERE production calls that delivery from; the two deferred call sites are
// bound separately, at their own call site, by
// TestDeferredDeliveryIsWiredAtItsRetryPoints_6827.
//
// RED on revert: make noteStaleMgmtCertHostName return early when d.mgmt is nil
// and boot_rename_is_diagnosed_once_mgmt_is_up logs nothing.
func TestBootHostNameReachesTheDiagnostic_6827(t *testing.T) {
	t.Run("boot_rename_is_diagnosed_once_mgmt_is_up", func(t *testing.T) {
		d := &Daemon{}
		restoreSet, restorePath := sethostname, hostnamePath
		t.Cleanup(func() { sethostname, hostnamePath = restoreSet, restorePath })
		hostnamePath = filepath.Join(t.TempDir(), "hostname")

		// STATEFUL stub (#6827 r3). The earlier fixture had the kernel already
		// reporting "new-fw-6827" while asking applyHostname to rename TO it —
		// a state production cannot reach, because the early return at
		// daemon_system.go fires first and sethostname is never called. It only
		// ran because that guard read os.Hostname directly while the rest of
		// the function read the seam; completing the seam reds it.
		//
		// So model the real sequence: the kernel reports the PRE-rename name,
		// and the fake sethostname advances it.
		current := "old-fw-6827"
		restoreHost := osHostname
		t.Cleanup(func() { osHostname = restoreHost })
		osHostname = func() (string, error) { return current, nil }
		var applied []string
		sethostname = func(b []byte) error {
			applied = append(applied, string(b))
			current = string(b)
			return nil
		}

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

	// #6827 r3: bind applyHostname's already-applied early return.
	//
	// It was innocuous before this PR and is LOAD-BEARING after it, because
	// noteStaleMgmtCertHostName is reachable only past it. Deleting the guard
	// left the whole pkg/daemon + pkg/api suite GREEN, so nothing noticed —
	// while in production every commit carrying an unchanged `system host-name`
	// would re-fire the debt and its delivery, and a box with a genuinely stale
	// durable cert would emit the "does not cover the current host-name" WARN on
	// EVERY commit. Muting a real diagnostic by repeating it is exactly what
	// hostNameLikelyAccessIdentity's design avoids on the load path.
	t.Run("an_unchanged_host_name_is_a_no_op", func(t *testing.T) {
		d := &Daemon{}
		restoreSet, restorePath := sethostname, hostnamePath
		t.Cleanup(func() { sethostname, hostnamePath = restoreSet, restorePath })
		hostnamePath = filepath.Join(t.TempDir(), "hostname")

		restoreHost := osHostname
		t.Cleanup(func() { osHostname = restoreHost })
		osHostname = func() (string, error) { return "steady-fw-6827", nil }
		var applied []string
		sethostname = func(b []byte) error { applied = append(applied, string(b)); return nil }

		// A cert that does NOT cover the name, so a delivery would be loud if
		// the debt were ever armed — the assertion below is not true for free.
		serveStaleCert(t, d, "other-fw-6827")

		out := captureDaemonWarn(t, func() {
			cfg := &config.Config{}
			cfg.System.HostName = "steady-fw-6827"
			d.applyHostname(cfg)
			d.deliverStaleMgmtCertDiagnosis()
		})
		if len(applied) != 0 {
			t.Fatalf("a commit whose host-name already matches the kernel must not call "+
				"sethostname; got %v", applied)
		}
		if strings.Contains(out, "does not cover the current host-name") {
			t.Fatalf("an unchanged host-name must not arm the stale-cert debt — otherwise a box "+
				"with a stale durable cert warns on EVERY commit and operators learn to ignore "+
				"it; got %q", out)
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

// TestRenameIsNotedOnlyAfterSethostname_6827 binds the ORDERING that Fix 2's
// whole mechanism rests on: the debt is recorded (and delivery attempted) only
// AFTER the kernel name has actually moved.
//
// Moving noteStaleMgmtCertHostName above the Sethostname call previously left
// every test green, so the ordering was unproven — and ordering is the point.
// The stub records the kernel name observed at the moment the note fires.
//
// RED on revert: call noteStaleMgmtCertHostName before sethostname in
// applyHostname and the observed name is the PRE-rename one.
func TestRenameIsNotedOnlyAfterSethostname_6827(t *testing.T) {
	d := &Daemon{}
	restoreSet, restorePath := sethostname, hostnamePath
	t.Cleanup(func() { sethostname, hostnamePath = restoreSet, restorePath })
	hostnamePath = filepath.Join(t.TempDir(), "hostname")

	current := "old-fw-6827"
	restoreHost := osHostname
	t.Cleanup(func() { osHostname = restoreHost })
	osHostname = func() (string, error) { return current, nil }
	sethostname = func(b []byte) error { current = string(b); return nil }

	serveStaleCert(t, d, "old-fw-6827")
	out := captureDaemonWarn(t, func() {
		cfg := &config.Config{}
		cfg.System.HostName = "new-fw-6827"
		d.applyHostname(cfg)
	})
	if !strings.Contains(out, "new-fw-6827") {
		t.Fatalf("the diagnosis must observe the POST-rename kernel name — noting before "+
			"Sethostname would report %q; got %q", "old-fw-6827", out)
	}
}

// newMgmtDeliveryDaemon builds the Daemon the two DEFERRED delivery call sites
// need: a real configstore carrying setLines as the ACTIVE (committed)
// configuration.
//
// The store is what made both sites hard to bind, and it is load-bearing in a
// different way at each. reconcileWebManagement reaches the retry through
// managementReconciler.reconcile → committedDesired, which re-derives the WHOLE
// desired state from store.ActiveConfig() (#5561 round 14): with no store that
// derivation falls back to a bare &Daemon{}'s empty bind, so the reconcile
// DISABLES the live HTTPS leg and the delivery then correctly reports nothing
// served — a green test that proves nothing. startHTTPServer reaches its
// delivery through managementReconciler.start, which dereferences
// d.store.ActiveConfig() unconditionally.
func newMgmtDeliveryDaemon(t *testing.T, setLines ...string) *Daemon {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range setLines {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("set %q: %v", line, err)
		}
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return &Daemon{store: s}
}

// TestDeferredDeliveryIsWiredAtItsRetryPoints_6827 binds the two DEFERRED call
// sites. The inline delivery inside noteStaleMgmtCertHostName is already bound
// by the subtests above; these two are what make the debt ledger a RETRY
// mechanism instead of "diagnose synchronously at the rename or never":
//
//   - startHTTPServer (daemon_run_servers.go): the boot management start. The
//     phase-4 boot config apply runs BEFORE the reconciler is constructed, so a
//     `system host-name` applied at boot parks against a nil d.mgmt, and this is
//     the first delivery that can see a reconciler at all.
//   - reconcileWebManagement (management.go): every day-2 commit, so a debt
//     incurred while HTTPS was down settles on the commit that brings it up.
//
// Both were unbound: deleting either call — or both, leaving only the inline one
// — left the whole pkg/daemon suite green, so the entire justification for
// keeping the flag pending was unmeasured.
//
// RED on revert: delete d.deliverStaleMgmtCertDiagnosis() from startHTTPServer
// and the first subtest fails; delete it from reconcileWebManagement and the
// second fails. Neither deletion is visible to the other.
func TestDeferredDeliveryIsWiredAtItsRetryPoints_6827(t *testing.T) {
	t.Run("boot_start_delivers_a_debt_parked_before_the_reconciler_existed", func(t *testing.T) {
		// No web-management stanza, so the boot start binds only the plain
		// --api-addr HTTP leg on an ephemeral loopback port. That is deliberate:
		// startHTTPServer CONSTRUCTS the api.Server itself, and the only cert-dir
		// injection seam (Server.SetTLSCertDirForTest) exists after construction,
		// so an in-process boot start cannot be handed a serving HTTPS leg
		// without driving the production /etc/xpf/tls generator. The delivery is
		// therefore observed where it is observable at boot — see below.
		d := newMgmtDeliveryDaemon(t, "system host-name new-fw-6827")
		d.opts.APIAddr = "127.0.0.1:0"

		// The kernel-name read lives INSIDE deliverStaleMgmtCertDiagnosis, past
		// its `!pending || mgmt == nil` early return, and nothing else on this
		// path reads it (the only other osHostname caller in the package is
		// applyHostname's already-applied guard, daemon_system.go, which
		// startHTTPServer never reaches). So a read during startHTTPServer is a
		// direct observation of the delivery running — and of it running AFTER
		// d.mgmt is published, since an unpublished reconciler returns before the
		// read.
		var reads int
		restore := osHostname
		t.Cleanup(func() { osHostname = restore })
		osHostname = func() (string, error) { reads++; return "new-fw-6827", nil }

		// Boot order: the rename lands while startHTTPServer has not run, so the
		// debt parks against a nil reconciler.
		d.noteStaleMgmtCertHostName()
		if reads != 0 {
			t.Fatalf("with no reconciler the delivery must not even reach the kernel-name read, "+
				"so this subtest's later count is attributable to the boot start alone; reads = %d", reads)
		}

		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		t.Cleanup(func() { cancel(); wg.Wait() })
		captureDaemonWarn(t, func() { d.startHTTPServer(ctx, &wg, nil) })

		if reads == 0 {
			t.Fatal("the boot management start did not attempt the parked diagnosis: the kernel " +
				"name was never read, so deliverStaleMgmtCertDiagnosis did not run past its nil-reconciler " +
				"guard. A host-name applied in the phase-4 boot apply is then never diagnosed, because " +
				"the next boot's applyHostname sees the name already applied and returns early (#6827)")
		}

		// Negative control: nothing served a certificate, so the debt must
		// SURVIVE the boot delivery. This is also why the WARN text cannot be the
		// observable here — there is no certificate at boot to judge.
		d.staleCertMu.Lock()
		pending := d.staleCertPending
		d.staleCertMu.Unlock()
		if !pending {
			t.Fatal("the boot delivery reached no served certificate, so it must not settle the debt")
		}
	})

	t.Run("a_day2_reconcile_settles_a_debt_incurred_while_https_was_down", func(t *testing.T) {
		d := newMgmtDeliveryDaemon(t,
			"system services web-management http",
			"system services web-management https",
		)
		reg := newFakeReg()
		m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
		d.mgmt = m
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		// Start SHORT of the committed state: HTTP only. That is the state a
		// disabled-or-failed HTTPS bind leaves behind, and the state in which a
		// rename incurs a debt no delivery can settle.
		want := m.committedDesired(nil)
		if !want.TLS || want.HTTPSAddr == "" {
			t.Fatalf("fixture: the committed config must ask for HTTPS or the reconcile has "+
				"nothing to bring up; desired = %+v", endpointOf(want))
		}
		httpOnly := want
		httpOnly.TLS, httpOnly.HTTPSAddr = false, ""
		if err := m.startTo(ctx, httpOnly); err != nil {
			t.Fatalf("start HTTP leg: %v", err)
		}

		stubHostname(t, "new-fw-6827")
		if out := captureDaemonWarn(t, func() { d.noteStaleMgmtCertHostName() }); strings.Contains(out, "does not cover the current host-name") {
			t.Fatalf("nothing is serving a certificate yet, so the rename cannot be diagnosed "+
				"at the rename itself; got %q", out)
		}
		d.staleCertMu.Lock()
		pending := d.staleCertPending
		d.staleCertMu.Unlock()
		if !pending {
			t.Fatal("the fixture must leave a debt outstanding, otherwise the reconcile has " +
				"nothing to settle and this subtest proves nothing")
		}

		// The stale durable pair the HTTPS leg LOADS when this reconcile binds it
		// (#1916 D6).
		dir := t.TempDir()
		seedDurableCert(t, dir, "old-fw-6827", "127.0.0.1")
		m.srv.SetTLSCertDirForTest(dir)

		// applyConfigLocked's entry point, not reconcileTo: the wiring under test
		// is reconcileWebManagement's, and reaching past it would bind the
		// mechanism again rather than the call site.
		captureDaemonWarn(t, func() {
			if err := d.reconcileWebManagement(d.store.ActiveConfig()); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
		})
		if m.srv.HTTPSCertForTest() == nil {
			t.Fatal("the reconcile did not bring the HTTPS leg up, so there was no certificate " +
				"for a retried delivery to reach and this subtest proves nothing")
		}

		// The DEBT FLAG, not the warning text. Bringing HTTPS up makes the
		// certificate LOAD path emit the same "does not cover the current
		// host-name" message, so a text assertion here passes with the retry
		// DELETED. Only a delivery clears the flag.
		d.staleCertMu.Lock()
		pending = d.staleCertPending
		d.staleCertMu.Unlock()
		if pending {
			t.Fatal("a web-management reconcile that brought HTTPS up left the host-name " +
				"diagnosis still owed: nothing retried the delivery, so the debt survives every " +
				"later commit on an unchanged endpoint and is discharged only by another rename (#6827)")
		}
	})
}

// TestDebtClearIsGenerationSafe_6827 pins the #6827-round-5 losing sequence: a
// delivery runs UNLOCKED across the hostname read and the certificate
// inspection, so a rename committed in that window bumps the generation and
// must NOT be settled by the older delivery's evidence.
//
// The race is reachable: applySem serializes commits with each other, but the
// boot delivery (daemon_run_servers.go, on the Run goroutine) runs OUTSIDE it
// while cluster comms are already up (started inside the phase-4 boot apply),
// so a peer SyncApply -> applyHostname can bump the generation while the boot
// delivery sits in its unlocked window.
//
// Both subtests drive the PRODUCTION comparison — an earlier version of this
// test re-implemented `d.staleCertGen == gen` in its own body and asserted on
// its own arithmetic, so the fence could be replaced by an unconditional clear
// with the whole suite still green.
//
// RED on revert: `if true || d.staleCertGen == gen` (unconditional clear) fails
// the first subtest; `if false && d.staleCertGen == gen` (never clear) fails the
// second. Neither direction passes both.
func TestDebtClearIsGenerationSafe_6827(t *testing.T) {
	t.Run("a_rename_landing_mid_delivery_is_not_settled", func(t *testing.T) {
		d := &Daemon{}
		serveStaleCert(t, d, "old-fw-6827")

		// osHostname is read INSIDE the unlocked window, so stubbing it is the
		// seam that lands a rename exactly where the race is: after this delivery
		// sampled the generation, before it decides whether to clear. It fires
		// ONCE, so the surviving debt is deliverable on a later attempt.
		restore := osHostname
		t.Cleanup(func() { osHostname = restore })
		var raced bool
		osHostname = func() (string, error) {
			if !raced {
				raced = true
				d.staleCertMu.Lock()
				d.staleCertGen++ // a newer `set system host-name` commits mid-delivery
				d.staleCertMu.Unlock()
			}
			return "new-fw-6827", nil
		}

		d.staleCertMu.Lock()
		d.staleCertPending, d.staleCertGen = true, 1
		d.staleCertMu.Unlock()

		out := captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() })
		if !strings.Contains(out, "does not cover the current host-name") {
			t.Fatalf("the delivery itself must still run and diagnose; got %q", out)
		}
		if !raced {
			t.Fatal("the stub never fired, so no rename landed in the unlocked window and " +
				"this subtest proves nothing")
		}
		d.staleCertMu.Lock()
		pending, gen := d.staleCertPending, d.staleCertGen
		d.staleCertMu.Unlock()
		if gen != 2 {
			t.Fatalf("generation = %d, want the mid-delivery bump to 2", gen)
		}
		if !pending {
			t.Fatal("an older delivery settled a rename that landed AFTER it sampled the " +
				"generation — the newer debt is lost permanently (#6827 round 5)")
		}

		// The surviving debt is still deliverable (the fence defers it, not drops it).
		if again := captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() }); !strings.Contains(again, "new-fw-6827") {
			t.Fatalf("the outstanding newer debt must still be deliverable; got %q", again)
		}
	})

	t.Run("an_unraced_delivery_settles_the_debt", func(t *testing.T) {
		// OVER-REACH GUARD (negative control): the fence must NARROW the clear to
		// the generation the delivery claimed, not suppress clearing. Stays GREEN
		// under the unconditional-clear mutation and RED under a never-clear one,
		// so the pair distinguishes the fence from both neighbours.
		d := &Daemon{}
		stubHostname(t, "new-fw-6827")
		serveStaleCert(t, d, "old-fw-6827")

		out := captureDaemonWarn(t, func() { d.noteStaleMgmtCertHostName() })
		if !strings.Contains(out, "new-fw-6827") {
			t.Fatalf("the rename must be diagnosed; got %q", out)
		}
		d.staleCertMu.Lock()
		pending := d.staleCertPending
		d.staleCertMu.Unlock()
		if pending {
			t.Fatal("a delivery that reached a served certificate with NO concurrent rename " +
				"must settle the debt — the generation fence must not suppress the clear")
		}
		if again := captureDaemonWarn(t, func() { d.deliverStaleMgmtCertDiagnosis() }); again != "" {
			t.Fatalf("a settled debt must not re-warn; got %q", again)
		}
	})
}
