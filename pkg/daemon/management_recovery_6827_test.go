// #6827 round 5 changed management-listener RECOVERY, not only the stale-cert
// diagnostic, and neither change was bound:
//
//   - reconcileTo used to `return nil` whenever m.srv was nil, so a boot HTTP
//     bind failure was ABSORBING: clearing the cause never brought the
//     management plane back, because every later reconcile returned at that
//     guard. It now retries construction via startLocked.
//   - startLocked now UNRECORDS the HTTPS fingerprint when the boot HTTPS bind
//     failed. api.Server.Start returns SUCCESS in that case (HTTPS is
//     best-effort at boot so the HTTP plane stays up), so recording
//     endpointOf(next) wholesale pinned the reconciler to a listener that does
//     not exist and an IDENTICAL later reconcile saw "no change" and never
//     issued ReconcileHTTPS.
//
// TestHTTPSBindFailureIsNotReportedAsServing_6827 (pkg/api) binds the
// HTTPSServing predicate, but calls it DIRECTLY — nothing bound the
// reconciler's USE of it, and nothing bound the srv==nil retry at all. Both
// changes could be reverted wholesale with the suite green. These bind them at
// the call site.
//
// RED on revert:
//   - `if true || m.rootCtx == nil || next.Addr == ""` (restore the absorbing
//     return) fails boot_http_bind_failure_recovers_on_a_later_reconcile.
//   - `if false && next.TLS && next.HTTPSAddr != "" && !srv.HTTPSServing()`
//     (pin the phantom fingerprint) fails
//     boot_https_bind_failure_retries_on_an_identical_reconcile.
package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/sysservices"
)

// clearBindFailure removes a fake-registry bind refusal under the registry's own
// mutex, modelling "the operator fixed whatever the kernel was rejecting".
func clearBindFailure(reg *fakeReg, addr string) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	delete(reg.failAddr, addr)
}

func TestMgmtListenerRecoversFromAFailedStart_6827(t *testing.T) {
	t.Run("boot_http_bind_failure_recovers_on_a_later_reconcile", func(t *testing.T) {
		reg := newFakeReg()
		reg.failAddr["10.0.0.1:8080"] = true
		m := newTestMgmt(reg)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Boot: the HTTP bind is refused, so nothing is constructed. `show system
		// services` correctly reports the listener Failed at the attempted addr.
		if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err == nil {
			t.Fatal("precondition: startTo must fail when the fake factory refuses the HTTP bind")
		}
		if m.srv != nil {
			t.Fatal("precondition: a failed boot bind must leave no server constructed")
		}
		if got := m.effectiveHTTPListener(); got.State != sysservices.StateFailed {
			t.Fatalf("precondition: a failed boot bind must report Failed, got %+v", got)
		}

		// The cause is cleared and a later commit reconciles to the same endpoint.
		clearBindFailure(reg, "10.0.0.1:8080")
		if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
			t.Fatalf("the retried construction must succeed once the bind is accepted: %v", err)
		}

		if m.srv == nil {
			t.Fatal("a reconcile after a failed boot bind must RETRY construction — a nil server " +
				"that returns early makes the boot failure absorbing and the management plane " +
				"never comes back without a restart (#6827 round 5)")
		}
		if got := m.effectiveHTTPListener(); got.State != sysservices.StateListening {
			t.Fatalf("the recovered HTTP listener must report Listening, got %+v", got)
		}
		if ln := reg.get("10.0.0.1:8080"); ln == nil || !ln.isOpen() {
			t.Fatal("the retried construction did not leave an open HTTP listener")
		}
	})

	t.Run("a_disabled_api_still_does_not_construct", func(t *testing.T) {
		// OVER-REACH GUARD: the retry must fire only for a FAILED start, not turn
		// every reconcile into a constructor. A genuinely disabled API — no root
		// context (startTo never ran), or an empty HTTP bind address — stays a
		// no-op. Stays GREEN under both mutations below.
		reg := newFakeReg()

		neverStarted := newTestMgmt(reg)
		if err := neverStarted.reconcileTo(cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
			t.Fatalf("a reconcile before any start must be a no-op: %v", err)
		}
		if neverStarted.srv != nil {
			t.Fatal("a reconcile with no root context must NOT construct a server — Daemon.Run " +
				"never asked for one")
		}

		reg2 := newFakeReg()
		reg2.failAddr["10.0.0.1:8080"] = true
		noAddr := newTestMgmt(reg2)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := noAddr.startTo(ctx, cfgFor(reg2, "10.0.0.1:8080", false, "", nil)); err == nil {
			t.Fatal("precondition: the boot bind must fail")
		}
		if err := noAddr.reconcileTo(cfgFor(reg2, "", false, "", nil)); err != nil {
			t.Fatalf("a reconcile to an empty HTTP bind must be a no-op: %v", err)
		}
		if noAddr.srv != nil {
			t.Fatal("a reconcile to an empty HTTP bind address must NOT construct a server " +
				"(--api-addr removed means the API is off)")
		}
	})

	t.Run("boot_https_bind_failure_retries_on_an_identical_reconcile", func(t *testing.T) {
		reg := newFakeReg()
		reg.failAddr["10.0.0.1:8443"] = true
		m := newTestMgmt(reg)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		boot := cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", nil)
		// Start returns SUCCESS: HTTP bound, HTTPS is best-effort and was refused.
		if err := m.startTo(ctx, boot); err != nil {
			t.Fatalf("an HTTPS bind failure must leave the HTTP plane up and Start successful: %v", err)
		}
		if m.srv == nil {
			t.Fatal("precondition: the HTTP leg must have constructed a server")
		}
		if m.srv.HTTPSServing() {
			t.Fatal("precondition: the refused HTTPS bind must not report as serving")
		}
		// Redirect cert generation at a writable temp dir so the retry exercises
		// the durable-load path rather than an unwritable /etc/xpf/tls (#6381).
		m.srv.SetTLSCertDirForTest(t.TempDir())

		// The cause clears and the NEXT commit carries an IDENTICAL config — the
		// sharp case: nothing about the desired endpoint changed, so only an
		// unrecorded HTTPS fingerprint can drive a retry.
		clearBindFailure(reg, "10.0.0.1:8443")
		if err := m.reconcileTo(boot); err != nil {
			t.Fatalf("identical reconcile after a failed HTTPS bind: %v", err)
		}

		if !m.srv.HTTPSServing() {
			t.Fatal("an IDENTICAL reconcile after a failed boot HTTPS bind must RETRY the bind " +
				"(#6827 round 5): recording the HTTPS fingerprint on a bind that never happened " +
				"pins the reconciler to a listener that does not exist and it never retries")
		}
		if ln := reg.get("10.0.0.1:8443"); ln == nil || !ln.isOpen() {
			t.Fatal("the retried HTTPS bind did not leave an open listener")
		}
		if !m.cur.tls || m.cur.httpsAddr != "10.0.0.1:8443" {
			t.Fatalf("the HTTPS fingerprint must advance once the leg is actually serving; "+
				"got tls=%v httpsAddr=%q", m.cur.tls, m.cur.httpsAddr)
		}
	})

	t.Run("a_successful_boot_https_bind_records_its_fingerprint", func(t *testing.T) {
		// OVER-REACH GUARD: unrecording is conditional on the bind having FAILED.
		// A successful boot HTTPS bind must still converge its fingerprint, so a
		// later identical reconcile is a genuine no-op and does not bounce a
		// healthy leg. Stays GREEN under both mutations below.
		reg := newFakeReg()
		m := newTestMgmt(reg)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		boot := cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", nil)
		if err := m.startTo(ctx, boot); err != nil {
			t.Fatalf("boot with both legs bindable: %v", err)
		}
		if !m.srv.HTTPSServing() {
			t.Fatal("precondition: the HTTPS leg must be serving after a successful boot bind")
		}
		if !m.cur.tls || m.cur.httpsAddr != "10.0.0.1:8443" {
			t.Fatalf("a SUCCESSFUL boot HTTPS bind must record its fingerprint; got tls=%v httpsAddr=%q",
				m.cur.tls, m.cur.httpsAddr)
		}
		httpsLn := reg.get("10.0.0.1:8443")
		if httpsLn == nil || !httpsLn.isOpen() {
			t.Fatal("precondition: the boot HTTPS listener must be open")
		}
		// An identical reconcile is a no-op: the SAME socket keeps serving. (The
		// strict fake models EADDRINUSE, so a needless rebind of the still-open
		// socket would also error.)
		if err := m.reconcileTo(boot); err != nil {
			t.Fatalf("an identical reconcile over a healthy HTTPS leg must be a no-op: %v", err)
		}
		if reg.get("10.0.0.1:8443") != httpsLn || !httpsLn.isOpen() {
			t.Fatal("an identical reconcile bounced a healthy HTTPS leg")
		}
	})
}
