package vrrp

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #5482 — the BACKUP-side symmetry of the #5082 fail-closed MASTER path.
//
// becomeMaster was already fail-closed (#5082): it refuses to publish MASTER when
// the VIP add fails (vip_gen_5082_test.go pins that). The symmetric hazard
// remained on the BACKUP side: becomeBackup called the VOID removeVIPs and then
// emitEvent UNCONDITIONALLY, so a swallowed netlink removal failure left this
// now-BACKUP node still answering ARP for a VIP it no longer owns — the daemon
// made the RG BACKUP (blackholes injected, rg_active cleared) while the VIP was
// still on the wire, a duplicate-address hazard against the new master.
//
// The fix makes removeVIPs return the netlink failure and has becomeBackup
// surfaceStaleVIP it: bump a failure counter, set vipDiverged, log at Error, and
// schedule an async reconcile that clears the stale VIP. BACKUP is still emitted
// (we ARE stepping down — refusing to emit would risk split-brain), so the
// divergence is no longer SILENT and it self-heals.
//
// The tests drive the netlink seams (linkByNameFn/addrDelFn) so the removal path
// runs without a real interface. becomeBackup performs no network I/O of its own.

// newBackupTestInstance builds a MASTER instance whose VIP netlink removal is
// governed by delFn, so becomeBackup exercises the surfacing path deterministically.
func newBackupTestInstance(t *testing.T, name string, delFn func(*netlink.Addr) error) (*vrrpInstance, chan VRRPEvent) {
	t.Helper()
	eventCh := make(chan VRRPEvent, 8)
	vi := newInstance(Instance{
		Interface:         name,
		GroupID:           1,
		Priority:          100,
		Family:            "inet",
		AdvertiseInterval: 1000,
		VirtualAddresses:  []string{"10.0.61.1/24"},
	}, &net.Interface{Name: name}, eventCh, nil)
	// Interface resolves; removal outcome is dictated by delFn.
	vi.linkByNameFn = func(n string) (netlink.Link, error) {
		return fiveZeroEightTwoLink(n), nil
	}
	vi.addrAddFn = func(netlink.Link, *netlink.Addr) error { return nil }
	vi.addrDelFn = func(_ netlink.Link, a *netlink.Addr) error { return delFn(a) }
	vi.setState(StateMaster) // becomeBackup is a real demotion FROM MASTER
	// Stop any async reconcile goroutine promptly at test end.
	t.Cleanup(func() {
		select {
		case <-vi.stopCh:
		default:
			close(vi.stopCh)
		}
	})
	return vi, eventCh
}

func drainForBackupEvent(t *testing.T, eventCh chan VRRPEvent) bool {
	t.Helper()
	for {
		select {
		case ev := <-eventCh:
			if ev.State == StateBackup {
				return true
			}
		default:
			return false
		}
	}
}

// TestBecomeBackupSurfacesVIPRemoveFailure_5482 is the fail-on-revert guard: with
// the netlink AddrDel primitive rigged to fail, becomeBackup must SURFACE the
// removal failure (vipRemoveFailures bumped, vipDiverged set) rather than
// silently publishing a clean BACKUP role while the VIP is still on the wire.
// BACKUP is still emitted (we are stepping down).
//
// RED on revert: replacing `vi.surfaceStaleVIP(vi.removeVIPs(), "becomeBackup")`
// with the pre-fix `vi.removeVIPs()` (discarding the error, matching the old void
// removeVIPs + unconditional emit) leaves vipRemoveFailures at 0 and vipDiverged
// false — this test then fails on the vipRemoveFailures assertion.
func TestBecomeBackupSurfacesVIPRemoveFailure_5482(t *testing.T) {
	vi, eventCh := newBackupTestInstance(t, "xpf-5482-a0", func(*netlink.Addr) error {
		return errors.New("injected netlink AddrDel failure")
	})

	mdt := time.NewTimer(time.Hour)
	defer mdt.Stop()
	adv := time.NewTimer(time.Hour)
	defer adv.Stop()

	vi.becomeBackup(mdt, adv)

	// The honest BACKUP role is still published — never withhold the step-down.
	if got := vi.getState(); got != StateBackup {
		t.Fatalf("state = %v, want StateBackup — becomeBackup must still step down", got)
	}
	if !drainForBackupEvent(t, eventCh) {
		t.Fatal("becomeBackup did not emit a BACKUP event — the step-down must be published")
	}
	// ...but the removal failure is SURFACED, not swallowed.
	if got := vi.vipRemoveFailures.Load(); got != 1 {
		t.Fatalf("becomeBackup swallowed the VIP remove failure: vipRemoveFailures = %d, "+
			"want 1 — the control-plane published BACKUP while a stale VIP remained on "+
			"the wire (#5482 silent role/VIP divergence)", got)
	}
	if !vi.vipDiverged.Load() {
		t.Fatal("vipDiverged must be set when the VIP remove fails on the BACKUP transition")
	}
}

// TestBecomeBackupCleanRemovalNoDivergence_5482 is the non-tautological control:
// when AddrDel SUCCEEDS, becomeBackup must NOT bump the failure counter or flag a
// divergence. This proves the surfacing is gated on the ACTUAL netlink outcome,
// not fired unconditionally.
func TestBecomeBackupCleanRemovalNoDivergence_5482(t *testing.T) {
	vi, eventCh := newBackupTestInstance(t, "xpf-5482-b0", func(*netlink.Addr) error {
		return nil // clean removal
	})

	mdt := time.NewTimer(time.Hour)
	defer mdt.Stop()
	adv := time.NewTimer(time.Hour)
	defer adv.Stop()

	vi.becomeBackup(mdt, adv)

	if got := vi.getState(); got != StateBackup {
		t.Fatalf("state = %v, want StateBackup", got)
	}
	if !drainForBackupEvent(t, eventCh) {
		t.Fatal("becomeBackup did not emit a BACKUP event")
	}
	if got := vi.vipRemoveFailures.Load(); got != 0 {
		t.Fatalf("vipRemoveFailures = %d, want 0 on a clean removal — surfacing must "+
			"be gated on the real netlink outcome", got)
	}
	if vi.vipDiverged.Load() {
		t.Fatal("vipDiverged must stay false when the VIP removal succeeds")
	}
}

// TestBackupStaleVIPReconcileSelfHeals_5482 proves the divergence self-heals: the
// first AddrDel fails (becomeBackup flags vipDiverged) and a later one succeeds,
// so the scheduled async reconcile clears vipDiverged without a further BACKUP
// transition. Without the reconcile the flag would stay set forever.
func TestBackupStaleVIPReconcileSelfHeals_5482(t *testing.T) {
	var calls atomic.Int32
	vi, _ := newBackupTestInstance(t, "xpf-5482-c0", func(*netlink.Addr) error {
		if calls.Add(1) == 1 {
			return errors.New("injected transient netlink AddrDel failure")
		}
		return nil // subsequent attempts succeed
	})
	// Shorten the retry backoff (per-instance, no shared global) so the async
	// reconcile fires quickly. Set before becomeBackup starts the goroutine.
	vi.vipReconcileBackoff = 5 * time.Millisecond

	mdt := time.NewTimer(time.Hour)
	defer mdt.Stop()
	adv := time.NewTimer(time.Hour)
	defer adv.Stop()

	vi.becomeBackup(mdt, adv)

	// Immediately after the (failed) synchronous removal, the divergence is flagged.
	if vi.vipRemoveFailures.Load() != 1 || !vi.vipDiverged.Load() {
		t.Fatalf("expected surfaced divergence after the failed removal: "+
			"vipRemoveFailures=%d vipDiverged=%v", vi.vipRemoveFailures.Load(), vi.vipDiverged.Load())
	}

	// The async reconcile retries the removal; the second AddrDel succeeds and
	// clears vipDiverged.
	deadline := time.Now().Add(2 * time.Second)
	for vi.vipDiverged.Load() {
		if time.Now().After(deadline) {
			t.Fatal("vipDiverged never cleared — the async stale-VIP reconcile did not self-heal")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// vipRemoveFailures is a clean count of failed BACKUP transitions — the retry
	// attempts must NOT inflate it.
	if got := vi.vipRemoveFailures.Load(); got != 1 {
		t.Fatalf("vipRemoveFailures = %d, want 1 — retry attempts must not bump the "+
			"transition-failure counter", got)
	}
}

// TestBackupRemoveAbsentVIPNoDivergence_5482 is the fail-on-revert guard for the
// EADDRNOTAVAIL false-divergence bug. The kernel returns EADDRNOTAVAIL ("cannot
// assign requested address") when AddrDel targets an address that is NOT present
// — the most common already-absent errno. On a fresh boot / restart-as-backup the
// run-startup BACKUP removal (and becomeBackup) run against VIPs that were never
// on the interface, so every AddrDel returns EADDRNOTAVAIL. That is a benign
// already-absent case, NOT a divergence: it must NOT bump vipRemoveFailures or set
// vipDiverged.
//
// RED on revert: dropping `errors.Is(err, unix.EADDRNOTAVAIL)` (and the "cannot
// assign requested address" string) from the benign already-absent set in
// removeVIPsLocked makes EADDRNOTAVAIL a real failure → surfaceStaleVIP bumps
// vipRemoveFailures to 1 and sets vipDiverged → both sub-cases fail. This
// cry-wolfs the divergence flag on EVERY clean boot.
func TestBackupRemoveAbsentVIPNoDivergence_5482(t *testing.T) {
	// Both detection arms: the raw errno (realistic netlink path) and the
	// Error()-string form (a wrapper that only exposes the message).
	cases := []struct {
		name string
		err  error
	}{
		{"eaddrnotavail-errno", unix.EADDRNOTAVAIL},
		{"cannot-assign-string", errors.New("cannot assign requested address")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			absent := tc.err
			vi, eventCh := newBackupTestInstance(t, "xpf-5482-"+tc.name, func(*netlink.Addr) error {
				return absent
			})

			mdt := time.NewTimer(time.Hour)
			defer mdt.Stop()
			adv := time.NewTimer(time.Hour)
			defer adv.Stop()

			vi.becomeBackup(mdt, adv)

			// The honest BACKUP role is still published.
			if got := vi.getState(); got != StateBackup {
				t.Fatalf("state = %v, want StateBackup", got)
			}
			if !drainForBackupEvent(t, eventCh) {
				t.Fatal("becomeBackup did not emit a BACKUP event")
			}
			// Removing an ABSENT VIP is not a divergence.
			if got := vi.vipRemoveFailures.Load(); got != 0 {
				t.Fatalf("removing an absent VIP (%v) flagged a bogus remove failure: "+
					"vipRemoveFailures = %d, want 0 — an already-absent AddrDel "+
					"(EADDRNOTAVAIL) must be benign, else every clean boot cry-wolfs "+
					"the divergence flag (#5482)", absent, got)
			}
			if vi.vipDiverged.Load() {
				t.Fatalf("removing an absent VIP (%v) set vipDiverged — a fresh boot / "+
					"restart-as-backup must not report a stuck divergence", absent)
			}
		})
	}
}

// TestBackupVIPReconcileAbortsOnRepromotion_5482 is the fail-on-revert guard for
// the re-promotion TOCTOU. The stale-VIP reconcile runs on a background goroutine
// while becomeMaster runs on the run-loop. becomeMaster does setState(MASTER)
// (bumping ownerGen) BEFORE it takes vipMu to re-add the VIP, so the reconcile's
// remove MUST re-validate state + ownerGen under vipMu and abort if the node was
// re-promoted — otherwise it strips the VIP becomeMaster just added (MASTER
// self-blackhole). removeVIPsIfBackup is that atomic gate.
//
// The test drives the gate directly for determinism (racing the async goroutine
// would be flaky). It covers BOTH revalidation arms:
//   - state flipped to MASTER (the direct re-promotion)
//   - state is BACKUP again but ownerGen advanced (a MASTER tenure intervened:
//     BACKUP→MASTER→BACKUP — the new tenure owns the divergence decision)
//
// RED on revert: removing the `state != BACKUP || ownerGen != wantGen` recheck in
// removeVIPsIfBackup makes it call removeVIPsLocked unconditionally → AddrDel
// fires on the re-owned VIP → delCalls > 0 and the returned error is not
// errReconcileSuperseded → both sub-cases fail.
func TestBackupVIPReconcileAbortsOnRepromotion_5482(t *testing.T) {
	var delCalls atomic.Int32
	vi, _ := newBackupTestInstance(t, "xpf-5482-repromo", func(*netlink.Addr) error {
		delCalls.Add(1)
		return nil
	})

	// Identity of the BACKUP tenure that scheduled the reconcile.
	vi.setState(StateBackup)
	gen := vi.ownerGen.Load()

	// Scenario 1: re-promotion to MASTER. becomeMaster ran setState(MASTER)
	// (ownerGen bumped) and re-added the VIP under vipMu; the stale reconcile from
	// the old BACKUP tenure must abort rather than strip that VIP.
	vi.setState(StateMaster)
	if err := vi.removeVIPsIfBackup(gen); !errors.Is(err, errReconcileSuperseded) {
		t.Fatalf("removeVIPsIfBackup must abort on re-promotion to MASTER: err = %v, "+
			"want errReconcileSuperseded", err)
	}
	if got := delCalls.Load(); got != 0 {
		t.Fatalf("reconcile stripped a re-owned MASTER's VIP: AddrDel called %d times, "+
			"want 0 — re-promotion TOCTOU self-blackhole (#5482)", got)
	}

	// Scenario 2: state is BACKUP again but ownerGen advanced past the captured
	// tenure (BACKUP→MASTER→BACKUP). The stale reconcile must still abort — the new
	// BACKUP tenure ran its own surfaceStaleVIP and owns the divergence decision.
	vi.setState(StateBackup)
	if vi.ownerGen.Load() == gen {
		t.Fatalf("test setup: ownerGen did not advance across the intervening MASTER "+
			"tenure (gen still %d) — the ownerGen arm would not be exercised", gen)
	}
	if err := vi.removeVIPsIfBackup(gen); !errors.Is(err, errReconcileSuperseded) {
		t.Fatalf("removeVIPsIfBackup must abort when ownerGen advanced past the "+
			"scheduling tenure: err = %v, want errReconcileSuperseded", err)
	}
	if got := delCalls.Load(); got != 0 {
		t.Fatalf("stale-tenure reconcile deleted a VIP after ownerGen advanced: "+
			"AddrDel called %d times, want 0", got)
	}
}
