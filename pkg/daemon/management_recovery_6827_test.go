// Over-reach guards on the management-listener BOOT RETRY, kept as the
// complement to management_bootretry_5561_test.go.
//
// #6827 round 5 and #5561 round 14 independently fixed the same defect — a boot
// bind failure was ABSORBING, so clearing the cause never brought the management
// plane back without a daemon restart — by different mechanisms. #5561's
// survived the merge: startTo ADOPTS the server whether or not the bind
// succeeded, so reconcileTo's ordinary path (which asks where the live legs are
// before it publishes a credential grant) is what retries the bind.
// #6827's mechanism — retain the root context, and re-CONSTRUCT from
// reconcileTo's `m.srv == nil` branch — was removed rather than kept alongside
// it: a second construction path would have bound a fresh api.Server with the
// committed Auth already installed, bypassing everyLiveLegNamedBy and
// publishNilDirectionLocked entirely, and two retry mechanisms that can disagree
// are worse than either alone.
//
// management_bootretry_5561_test.go pins that both boot paths retry. What it
// does NOT pin is the two directions the retry must NOT reach, which is what
// these are:
//
//   - a reconcile that arrives before any start must not construct anything;
//   - a SUCCESSFUL boot HTTPS bind must still record its fingerprint, so the
//     `!srv.HTTPSServing()` clearing cannot be widened to an unconditional one
//     that bounces a healthy leg on every commit.
//
// RED on revert: widen startTo's clearing to `if next.TLS` and
// a_successful_boot_https_bind_records_its_fingerprint fails on the
// fingerprint assertion.
package daemon

import (
	"context"
	"testing"
)

func TestMgmtBootRetryDoesNotOverReach_6827(t *testing.T) {
	t.Run("a_reconcile_before_any_start_does_not_construct", func(t *testing.T) {
		// The retry lives on the ADOPTED server, so reconcileTo's `m.srv == nil`
		// branch now means exactly one thing: Daemon.Run never asked for a
		// management server. It must stay a no-op — a reconcile is not a
		// constructor.
		reg := newFakeReg()
		neverStarted := newTestMgmt(reg)
		if err := neverStarted.reconcileTo(cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
			t.Fatalf("a reconcile before any start must be a no-op: %v", err)
		}
		if neverStarted.srv != nil {
			t.Fatal("a reconcile with no prior start must NOT construct a server — Daemon.Run " +
				"never asked for one")
		}
		if ln := reg.get("10.0.0.1:8080"); ln != nil && ln.isOpen() {
			t.Fatal("a reconcile before any start bound a listener")
		}
	})

	t.Run("a_successful_boot_https_bind_records_its_fingerprint", func(t *testing.T) {
		// OVER-REACH GUARD for startTo's `next.TLS && !srv.HTTPSServing()`
		// clearing. Unrecording is conditional on the bind having FAILED; a
		// successful boot HTTPS bind must still converge its fingerprint, so a
		// later identical reconcile is a genuine no-op and does not bounce a
		// healthy leg.
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
