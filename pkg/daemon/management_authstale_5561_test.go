package daemon

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// management_authstale_5561_test.go is the fail-on-revert gate for the #5561
// round-10 finding-3 property: a FAILED listener rebind must never leave a
// SUPERSEDED api-auth credential governing the listener that is actually
// serving.
//
// reconcileTo publishes a non-nil credential set unconditionally — before the
// rebind and regardless of its outcome — because a committed revocation must
// not be blocked by a bind failure (#5561 round 7). That is right only while
// the config it came from is the newest COMMITTED one, and on the apply path it
// need not be: a caller that snapshots store.ActiveConfig() and THEN waits on
// the apply semaphore (the DHCP lease-change callback) can be overtaken by a
// commit and re-enter applyConfig carrying a superseded config. The listener
// stays where the newer commit put it — the stale replay's own rebind fails —
// while the credential the newer commit REPLACED is published onto it.
//
// Both directions are driven here, because the naive repair for one is the
// reintroduction of the other: gating the publish on the rebind outcome (the
// pre-round-7 shape) fixes the stale replay and restores the round-7 fail-open
// in the same edit. The two cases are the SAME shape from inside reconcileTo —
// differing bind, differing credential, failed rebind — and differ only in
// which config is newer, so only the second case's control proves the fix
// discriminates rather than merely refuses.
//
// A THIRD interleaving (#5561 round 12) is the one the first two fixtures could
// not express: the ACTIVE config's api-auth is NIL. Round 10 overrode the stale
// credential only when the active config carried one, so a commit that REMOVED
// api-auth left the stale replay's credential to be published — and, contrary to
// the argument that justified the asymmetry, the listener it lands on need not
// be loopback. See TestMgmtStaleReplayCannotResurrectRemovedAuth_5561 and the
// mgmtAuthConfigRemoveAuth fixture.

// mgmtAuthIfaceAddrs points the bind resolver at two fixed interface addresses,
// so two committed configs resolve to two DIFFERENT listener endpoints without
// depending on the host's real interfaces.
func mgmtAuthIfaceAddrs(t *testing.T) {
	t.Helper()
	prev := interfaceAddrsByName
	t.Cleanup(func() { interfaceAddrsByName = prev })
	interfaceAddrsByName = func(kernelName string) ([]net.Addr, error) {
		switch kernelName {
		case "ge-0-0-0":
			return []net.Addr{&net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.CIDRMask(24, 32)}}, nil
		case "ge-0-0-1":
			return []net.Addr{&net.IPNet{IP: net.IPv4(10, 0, 0, 2), Mask: net.CIDRMask(24, 32)}}, nil
		}
		return nil, fmt.Errorf("no such kernel interface: %s", kernelName)
	}
}

// mgmtAuthConfigFor is a committed web-management config binding `iface` with
// `secret` as the api-auth password. Off-loopback binds carry a credential, so
// the #4047/#5127 clamp leaves the resolved address alone.
func mgmtAuthConfigFor(iface, secret string) string {
	return "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24\n" +
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.2/24\n" +
		"set system services web-management http interface " + iface + "\n" +
		`set system services web-management api-auth user webadmin password "` + secret + `"` + "\n"
}

// mgmtAuthCommit commits text through the real configure/load/commit path and
// returns the config it promoted to ACTIVE — which is what an apply caller
// snapshots, and what a later commit supersedes.
func mgmtAuthCommit(t *testing.T, store *configstore.Store, text string) *config.Config {
	t.Helper()
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet(text); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	active := store.ActiveConfig()
	if active == nil {
		t.Fatal("store has no active config after commit")
	}
	return active
}

// mgmtAuthSecret reads the single api-auth password out of the live snapshot.
func mgmtAuthSecret(t *testing.T, snap *api.AuthConfig) string {
	t.Helper()
	if snap == nil {
		t.Fatal("the live auth snapshot is nil — this listener is off-loopback and must " +
			"carry a credential")
	}
	pw, ok := snap.Users["webadmin"]
	if !ok {
		t.Fatalf("the live auth snapshot %+v does not name webadmin", snap)
	}
	return pw
}

// TestMgmtFailedRebindKeepsTheCommittedCredential_5561 is the stale-replay
// direction.
//
// C1 binds ge-0/0/0 with secret-a; C2 binds ge-0/0/1 with secret-b and is
// committed second, so the live listener is at C2's endpoint under secret-b and
// secret-a is REVOKED. A stale apply then replays C1: it publishes a credential
// and attempts a rebind to C1's endpoint, which fails (its address is refused —
// in production, an old listener still retiring, or an address that has since
// gone away). C2's listener therefore keeps serving, and the credential
// governing it must still be the committed one.
//
// FAIL-ON-REVERT: publish next.Auth unconditionally and the retained
// off-loopback listener answers `POST /api/v1/system/action` to the secret the
// operator already replaced.
func TestMgmtFailedRebindKeepsTheCommittedCredential_5561(t *testing.T) {
	mgmtAuthIfaceAddrs(t)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))

	// C1 is committed first and then superseded; `stale` is the snapshot an
	// apply caller took before it blocked on the apply semaphore.
	stale := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/0.0", "secret-a"))
	committed := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/1.0", "secret-b"))

	reg := newFakeReg()
	d := &Daemon{store: store}
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The live listener is where the NEWEST commit put it.
	live := m.desired(committed)
	if live.Addr != "10.0.0.2:80" {
		t.Fatalf("the committed config resolves to %q, want 10.0.0.2:80 — the fixture is not "+
			"exercising two distinct endpoints", live.Addr)
	}
	if err := m.startTo(ctx, live); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	if got := mgmtAuthSecret(t, m.srv.LiveAuth()); got != "secret-b" {
		t.Fatalf("the live snapshot is %q before the case starts, want secret-b", got)
	}

	// The stale replay's own endpoint refuses to bind.
	staleDesired := m.desired(stale)
	if staleDesired.Addr != "10.0.0.1:80" {
		t.Fatalf("the stale config resolves to %q, want 10.0.0.1:80", staleDesired.Addr)
	}
	reg.failAddr[staleDesired.Addr] = true

	if err := m.reconcile(stale); err == nil {
		t.Fatal("the stale replay's rebind was expected to FAIL, so the case never reached " +
			"the state it tests (a retained listener under a republished credential)")
	}

	// The property.
	if got := mgmtAuthSecret(t, m.srv.LiveAuth()); got != "secret-b" {
		t.Fatalf("after a FAILED rebind the live listener is governed by %q, want secret-b. "+
			"The listener at 10.0.0.2:80 is still serving — the rebind that would have moved "+
			"it away failed — and it now accepts a credential the operator's later commit "+
			"REPLACED, which on this off-loopback bind is a full-power remote authentication "+
			"bypass", got)
	}
	// Control: the retained listener really is the one still serving, so the
	// assertion above is about the credential and not about a dead socket.
	if ln := reg.get("10.0.0.2:80"); ln == nil || !ln.isOpen() {
		t.Fatal("the committed listener at 10.0.0.2:80 is not serving after the failed " +
			"rebind, so the credential governing it is moot and the case proved nothing")
	}
}

// TestMgmtFailedRebindStillRevokesACommittedRotation_5561 is the OTHER
// direction — the #5561 round-7 property, restated here as the control that
// keeps the fix above from being implemented by gating the publish on the
// rebind outcome.
//
// The operator commits BOTH a new endpoint and a new secret. The endpoint's
// bind fails, so the previous listener is retained — and the previous secret
// must stop working on it anyway, because revoking a leaked credential is
// precisely what the operator committed. The REPLACEMENT secret is a different
// question and gets the opposite answer (#5561 round 12): it was committed for
// the endpoint that failed to bind, and the retained listener never accepted it,
// so it is withheld until the rebind converges. Both halves are asserted, since
// each alone is satisfiable by an implementation that gets the other wrong.
//
// FAIL-ON-REVERT: gate the whole non-nil publish on the rebind outcome and the
// retained listener keeps honouring the replaced secret indefinitely, until
// some later reconcile happens to bind.
func TestMgmtFailedRebindStillRevokesACommittedRotation_5561(t *testing.T) {
	mgmtAuthIfaceAddrs(t)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))

	first := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/0.0", "secret-a"))

	reg := newFakeReg()
	d := &Daemon{store: store}
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.startTo(ctx, m.desired(first)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	if got := mgmtAuthSecret(t, m.srv.LiveAuth()); got != "secret-a" {
		t.Fatalf("the live snapshot is %q before the case starts, want secret-a", got)
	}

	// The commit the operator actually makes: move the bind AND rotate the
	// secret. The new bind is refused.
	rotated := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/1.0", "secret-b"))
	reg.failAddr["10.0.0.2:80"] = true

	if err := m.reconcile(rotated); err == nil {
		t.Fatal("the rebind was expected to FAIL, so the case never reached the state it " +
			"tests (a retained listener under a rotated credential)")
	}

	snap := m.srv.LiveAuth()
	if snap == nil {
		t.Fatal("the live snapshot went nil on a failed rebind — that drops api-auth entirely " +
			"on an off-loopback listener, the fail-open the whole ordering exists to prevent")
	}
	if got := snap.Users["webadmin"]; got == "secret-a" {
		t.Fatal("after a FAILED rebind the retained listener still authorizes secret-a. The " +
			"operator committed a rotation — replacing secret-a means secret-a must stop " +
			"working — and deferring the revocation behind a bind that may never succeed " +
			"leaves the replaced secret live not for a race window but permanently")
	}
	if got := snap.Users["webadmin"]; got == "secret-b" {
		t.Fatal("the REPLACEMENT secret was published to the listener at 10.0.0.1:80 — an " +
			"off-loopback address this commit asked to move away from, which never accepted " +
			"secret-b. The operator's containment was to stop serving there; publishing the " +
			"new secret on it undoes that (#5561 round 12)")
	}
	if ln := reg.get("10.0.0.1:80"); ln == nil || !ln.isOpen() {
		t.Fatal("the retained listener at 10.0.0.1:80 is not serving, so the credential " +
			"governing it is moot and the case proved nothing")
	}

	// Control: the withholding ends when the endpoint converges.
	reg.failAddr["10.0.0.2:80"] = false
	if err := m.reconcile(rotated); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if got := mgmtAuthSecret(t, m.srv.LiveAuth()); got != "secret-b" {
		t.Fatalf("post-convergence live secret = %q, want secret-b — the committed credential "+
			"must land once the listener is at the address it was committed for", got)
	}
}

// mgmtAuthConfigRemoveAuth is the fixture this file was missing, and its absence
// is why the interleaving below went unseen: every other config here supplies a
// non-nil api-auth, so no case ever reached withCommittedAuth with a COMMITTED
// NIL. It deletes both the credential stanza and the interface binding, because
// the #4047 commit gate rejects an off-loopback web-management bind with no
// credential — a bare `web-management http`, resolving to the loopback default,
// is the only shape an api-auth removal can take.
func mgmtAuthConfigRemoveAuth() string {
	return "delete system services web-management api-auth\n" +
		"delete system services web-management http interface\n"
}

// TestMgmtStaleReplayCannotResurrectRemovedAuth_5561 is the third interleaving:
// the ACTIVE config has NO api-auth at all.
//
// Round 10 pinned only the non-nil direction of the override, on the argument
// that a stale replay could then over-restrict but never under-restrict,
// "because a resurrected credential over-restricts a management API that is
// clamped to loopback regardless". The premise is false, and this case is the
// counterexample the fixture above could not express.
//
// The #4047/#5127 clamp is evaluated by resolveAPIBinds against the config being
// applied, using THAT config's own api-auth. It is never re-evaluated against
// the listener that is serving. So:
//
//  1. A committed config WITH a credential binds off-loopback legitimately — the
//     clamp is a no-op for it.
//  2. A later commit REMOVES api-auth. Its own bind is clamped to loopback, and
//     that loopback bind FAILS, so the off-loopback listener from step 1 is
//     RETAINED. The nil publish is correctly suppressed, and that listener keeps
//     the credential of step 1.
//  3. The live listener is now NON-loopback while the ACTIVE config's api-auth
//     is nil — the state round 10's premise says cannot exist. The case asserts
//     it directly (m.cur.addr must not be loopback) before testing anything, so
//     a future change that made the premise TRUE would fail here loudly rather
//     than silently turn the test into a tautology.
//  4. A stale apply replay carrying the credential the operator DELETED finds
//     `committed == nil`, is not overridden, and publishes that credential onto
//     the retained off-loopback listener.
//
// The result is a deleted secret authorizing `POST /api/v1/system/action` from
// off-box: under-restriction, the exact direction round 10 claimed was
// impossible.
//
// FAIL-ON-REVERT: restore the `if committed != nil` guard in withCommittedAuth
// and the stale secret is live on the retained off-box listener.
func TestMgmtStaleReplayCannotResurrectRemovedAuth_5561(t *testing.T) {
	mgmtAuthIfaceAddrs(t)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))

	// C0: the config the stale apply caller snapshotted, with secret-a.
	stale := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/0.0", "secret-a"))
	// C1: moves the listener off-loopback under secret-b, revoking secret-a.
	served := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/1.0", "secret-b"))
	// C2: removes api-auth entirely and is the newest COMMITTED policy.
	removed := mgmtAuthCommit(t, store, mgmtAuthConfigRemoveAuth())

	reg := newFakeReg()
	d := &Daemon{store: store}
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.startTo(ctx, m.desired(served)); err != nil {
		t.Fatalf("initial start: %v", err)
	}

	// C2 applies: nil auth, clamped to loopback, and that bind fails.
	rm := m.desired(removed)
	if rm.Auth != nil {
		t.Fatalf("the api-auth removal fixture still resolves to a credential (%+v) — the case "+
			"would never reach a COMMITTED NIL, which is the whole point of it", rm.Auth)
	}
	if !mgmtAddrIsLoopback(rm.Addr) {
		t.Fatalf("the api-auth removal resolves to %q; the #4047/#5127 clamp was expected to pull "+
			"a credential-less bind to loopback", rm.Addr)
	}
	reg.failAddr[rm.Addr] = true
	if err := m.reconcile(removed); err == nil {
		t.Fatal("the loopback rebind was expected to FAIL, so the case never reached the state " +
			"it tests (an off-loopback listener retained under a nil-auth active config)")
	}

	// Step 3: the state round 10's premise denies. Asserted, not assumed.
	if mgmtAddrIsLoopback(m.cur.addr) {
		t.Fatalf("the retained live HTTP bind is %q, which IS loopback — the case cannot "+
			"demonstrate under-restriction on a clamped listener and proves nothing", m.cur.addr)
	}
	if got := mgmtAuthSecret(t, m.srv.LiveAuth()); got != "secret-b" {
		t.Fatalf("before the replay the retained listener is governed by %q, want secret-b", got)
	}

	// Step 4: the stale replay. Its own endpoint also fails to bind, so the
	// off-loopback listener from C1 keeps serving.
	sd := m.desired(stale)
	reg.failAddr[sd.Addr] = true
	if err := m.reconcile(stale); err == nil {
		t.Fatal("the stale replay's rebind was expected to FAIL")
	}

	// The property.
	snap := m.srv.LiveAuth()
	if snap == nil {
		t.Fatalf("api-auth was dropped entirely while the live listener is %q — a non-loopback "+
			"management API with no authentication is the fail-open the nil gate exists to "+
			"prevent", m.cur.addr)
	}
	if got := snap.Users["webadmin"]; got == "secret-a" {
		t.Fatalf("the off-loopback listener at %q accepts secret-a, a credential one commit "+
			"REPLACED and the next DELETED. A stale apply replay must not publish its own "+
			"credential over the committed policy, and `committed == nil` is not a licence to "+
			"skip the override — it is the case where the operator asked for the credential to "+
			"be gone", m.cur.addr)
	}
	if got := snap.Users["webadmin"]; got != "secret-b" {
		t.Fatalf("the retained listener is governed by %+v; the committed policy is nil and the "+
			"live bind is off-loopback, so the credential that was already governing it must "+
			"stay in force", snap)
	}
	if ln := reg.get("10.0.0.2:80"); ln == nil || !ln.isOpen() {
		t.Fatal("the off-loopback listener at 10.0.0.2:80 is not serving, so the credential " +
			"governing it is moot and the case proved nothing")
	}
}

// TestMgmtStaleReplayWithCommittedNilKeepsOffLoopbackAuth_5561 guards the hazard
// the fix above introduces, and the reason the repair is not simply "let the
// ACTIVE nil overwrite the stale credential".
//
// Propagating a committed NIL through a stale replay is only safe because the
// nil publish is gated on the addresses the LIVE listeners are bound to. The
// pre-round-12 gate asked a different question — did the HTTP rebind succeed? —
// which is a proxy for "the live bind is the one whose #4047/#5127 clamp
// justified the nil". A stale replay breaks the proxy: its endpoint is the OLD
// config's, that config carried a credential, so its bind is legitimately
// off-loopback and it can succeed. The proxy then reads TRUE while the live
// listener is off-loopback, and the nil is published: a routable management API
// with no authentication at all, which is strictly worse than the credential
// resurrection the round-12 fix removes.
//
// FAIL-ON-REVERT: gate the nil publish on the HTTP rebind outcome instead of on
// mgmtAddrIsLoopback(m.cur.addr) and the live snapshot goes nil on an
// off-loopback listener.
func TestMgmtStaleReplayWithCommittedNilKeepsOffLoopbackAuth_5561(t *testing.T) {
	mgmtAuthIfaceAddrs(t)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))

	stale := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/0.0", "secret-a"))
	served := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/1.0", "secret-b"))
	removed := mgmtAuthCommit(t, store, mgmtAuthConfigRemoveAuth())

	reg := newFakeReg()
	d := &Daemon{store: store}
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.startTo(ctx, m.desired(served)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	// The api-auth removal cannot bind its loopback address, so the off-loopback
	// listener is retained under secret-b.
	rm := m.desired(removed)
	reg.failAddr[rm.Addr] = true
	if err := m.reconcile(removed); err == nil {
		t.Fatal("the loopback rebind was expected to FAIL")
	}

	// The stale replay's endpoint DOES bind — it is a legitimate off-loopback
	// address, because the config it came from carried a credential.
	sd := m.desired(stale)
	if mgmtAddrIsLoopback(sd.Addr) {
		t.Fatalf("the stale config resolves to %q; the case needs an off-loopback stale endpoint "+
			"to break the rebind-outcome proxy", sd.Addr)
	}
	if err := m.reconcile(stale); err != nil {
		t.Fatalf("the stale replay's rebind was expected to SUCCEED (that is what makes the "+
			"rebind-outcome proxy read TRUE): %v", err)
	}
	if m.cur.addr != sd.Addr {
		t.Fatalf("live HTTP bind = %q, want the stale endpoint %q — the replay did not move the "+
			"listener, so the case never reached the state it tests", m.cur.addr, sd.Addr)
	}

	// The property: an off-loopback listener is never dropped to no-auth.
	snap := m.srv.LiveAuth()
	if snap == nil {
		t.Fatalf("api-auth was removed entirely while the live listener is %q — an UNAUTHENTICATED "+
			"routable management API serving the mutating config endpoints. The committed nil is "+
			"justified only by the loopback clamp on the bind that config asked for, and this is "+
			"not that bind", m.cur.addr)
	}
	if got := snap.Users["webadmin"]; got != "secret-b" {
		t.Fatalf("the live snapshot is %+v; the credential already governing the management API "+
			"must stay in force until a listener the committed nil actually justifies is "+
			"serving (want secret-b, got %q)", snap, got)
	}
}
