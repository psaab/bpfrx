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
	if got := mgmtAuthSecret(t, m.srv.AuthSnapshotForTest()); got != "secret-b" {
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
	if got := mgmtAuthSecret(t, m.srv.AuthSnapshotForTest()); got != "secret-b" {
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

// TestMgmtFailedRebindStillPublishesACommittedRotation_5561 is the OTHER
// direction — the #5561 round-7 property, restated here as the control that
// keeps the fix above from being implemented by gating the publish on the
// rebind outcome.
//
// The operator commits BOTH a new endpoint and a new secret. The endpoint's
// bind fails, so the previous listener is retained — and the previous secret
// must stop working on it anyway, because revoking a leaked credential is
// precisely what the operator committed.
//
// FAIL-ON-REVERT: gate the non-nil publish on the rebind outcome and the
// retained listener keeps honouring the replaced secret indefinitely, until
// some later reconcile happens to bind.
func TestMgmtFailedRebindStillPublishesACommittedRotation_5561(t *testing.T) {
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
	if got := mgmtAuthSecret(t, m.srv.AuthSnapshotForTest()); got != "secret-a" {
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

	if got := mgmtAuthSecret(t, m.srv.AuthSnapshotForTest()); got != "secret-b" {
		t.Fatalf("after a FAILED rebind the retained listener is governed by %q, want "+
			"secret-b. The operator committed a rotation — replacing secret-a means "+
			"secret-a must stop working — and deferring the publish behind a bind that may "+
			"never succeed leaves the replaced secret live not for a race window but "+
			"permanently", got)
	}
	if ln := reg.get("10.0.0.1:80"); ln == nil || !ln.isOpen() {
		t.Fatal("the retained listener at 10.0.0.1:80 is not serving, so the credential " +
			"governing it is moot and the case proved nothing")
	}
}
