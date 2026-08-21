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
// it, because on top of master's startTo it is UNREACHABLE. m.srv = srv runs
// unconditionally before startTo's error return and api.NewServer never returns
// nil, so once start has run m.srv stays non-nil for the reconciler's life; and
// in the only state that DOES reach the nil-srv branch — start never ran — the
// branch's own guard `if m.rootCtx == nil || next.Addr == "" { return nil }`
// returns nil, because rootCtx was assigned only inside startTo. (An
// API-disabled daemon does not even get here: startHTTPServer runs only under
// `if d.opts.APIAddr != ""`, so it has d.mgmt == nil, not a nil-srv
// reconciler.) Keeping it would have been dead code that reads like a second,
// disagreeing retry path.
//
// It is NOT removed because reconstructing would have failed open. That was the
// merge's original claim and it does not hold: master's recovery publishes the
// same full credential set on that path. startTo's error arm sets m.cur, m.curSet
// = mgmtEndpoint{}, false, so on the retry reconcile everyLiveLegNamedBy is
// vacuously true, the grant is sanctioned, and ReplaceAuth(next.Auth) publishes
// the whole set — the same outcome as constructing with next.Auth installed. The
// nil-Auth case is unreachable off-loopback either way, because resolveAPIBinds'
// #4047/#5127 clamp keys on hasAuth and clamps BOTH binds when it is false.
//
// management_bootretry_5561_test.go pins that both boot paths retry. What it
// does NOT pin is the directions the retry must NOT reach, which is what these
// are:
//
//   - a reconcile that arrives before any start must not construct anything;
//   - after a FAILED boot bind, a reconcile to an EMPTY HTTP bind must still
//     bind nothing;
//   - a SUCCESSFUL boot HTTPS bind must still record its fingerprint, so the
//     `!srv.HTTPSServing()` clearing cannot be widened to an unconditional one
//     that bounces a healthy leg on every commit.
//
// RED on revert: widen startTo's clearing to `if next.TLS` and
// a_successful_boot_https_bind_records_its_fingerprint fails on the
// fingerprint assertion; make reconcileTo's HTTP arm unconditional and
// a_failed_boot_then_an_empty_bind_binds_nothing fails on its no-op assertion,
// because api.Server refuses to reconcile the HTTP listener to an empty bind
// address and the reconcile surfaces that as an error.
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

	t.Run("a_failed_boot_then_an_empty_bind_binds_nothing", func(t *testing.T) {
		// This behaviour belonged to the half of the branch's
		// a_disabled_api_still_does_not_construct that the merge dropped along
		// with the mechanism it was written against. It is MASTER-owned now and
		// holds for a different reason than it did on the branch: there, a nil
		// m.srv plus the `next.Addr == ""` guard returned early; here the server
		// is adopted, and what binds nothing is that startTo's error arm reset
		// the fingerprint to mgmtEndpoint{}, so an empty desired Addr equals
		// m.cur.addr and the HTTP arm sees no change. Incidental, and nothing in
		// the package covered it — an --api-addr removal after a failed boot
		// bind must not bring a listener up.
		reg := newFakeReg()
		reg.failAddr["10.0.0.1:8080"] = true
		m := newTestMgmt(reg)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err == nil {
			t.Fatal("precondition: the boot HTTP bind must fail")
		}
		reg.failAddr["10.0.0.1:8080"] = false
		if err := m.reconcileTo(cfgFor(reg, "", false, "", nil)); err != nil {
			t.Fatalf("a reconcile to an empty HTTP bind must be a no-op: %v", err)
		}
		if ln := reg.get(""); ln != nil && ln.isOpen() {
			t.Fatal("a reconcile to an EMPTY HTTP bind bound a listener — the API is off")
		}
		if ln := reg.get("10.0.0.1:8080"); ln != nil && ln.isOpen() {
			t.Fatal("a reconcile to an empty HTTP bind re-bound the address the boot bind failed on")
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
