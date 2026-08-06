package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/networkd"
)

// TestNetworkctlReloadRecordsActivationDebt_5718 is the pkg/daemon half of the
// #5718 fold F2 fail-on-revert.
//
// networkctlReload is the process's OTHER `networkctl reload` owner: all FIVE
// daemon-side reload sites funnel through it — linksetup's post-rename reload
// (linksetup.go), device-map's rename and teardown reloads (device_map.go, via
// networkctlReloadFn), and bootstrap's teardown and lifeline reloads
// (bootstrap.go) — and they all write or remove the same 10-xpf-* files
// pkg/networkd generates.
//
// Before the fold it bypassed networkd's #4954 activation debt entirely. That
// matters most at the linksetup call site, which is warn-only: a failed reload
// there was logged and forgotten, the renamed .link files stayed on disk
// unactivated, and networkd.Apply's debt still read false — so the next Apply
// with byte-identical content skipped the reload and returned nil, which is
// exactly the #4954 false success, reached through the other owner.
//
// #5718 fold r4b: this asserts the DEBT STATE, not the debt epoch. The epoch is
// a proxy that cannot tell a correctly-reported success from a success that was
// never reported at all — it is unchanged either way — so the success leg used
// to pass against a networkctlReload that dropped NoteReloadResult on the floor.
func TestNetworkctlReloadRecordsActivationDebt_5718(t *testing.T) {
	origRun := runCommandTimeout
	t.Cleanup(func() { runCommandTimeout = origRun })
	t.Cleanup(func() { networkd.NoteReloadResult(networkd.BeginReload(), nil) })

	reloadFails := true
	var duringReload func()
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name == "networkctl" && len(args) > 0 && args[0] == "reload" {
			if duringReload != nil {
				duringReload()
			}
			if reloadFails {
				return []byte("Failed to reload network settings"),
					errors.New("simulated networkctl reload failure")
			}
			return nil, nil
		}
		return nil, nil
	}

	// Start from a clean slate so the first assertion is about this call.
	networkd.NoteReloadResult(networkd.BeginReload(), nil)
	if networkd.ReloadDebtOutstanding() {
		t.Fatal("setup: the activation debt must start discharged")
	}

	// A FAILED daemon-side reload must record the activation debt.
	if err := networkctlReload(); err == nil {
		t.Fatal("setup: networkctlReload must surface the failing reload")
	}
	if !networkd.ReloadDebtOutstanding() {
		t.Fatal("a FAILED daemon-side `networkctl reload` must record networkd's #4954 " +
			"activation debt. Without it the generated 10-xpf-* files stay on disk " +
			"unactivated while networkd.Apply's debt reads false, so the next Apply " +
			"with unchanged content skips the reload and reports a success the " +
			"kernel never performed — and the linksetup call site is warn-only, so " +
			"this record is the only thing that carries the failure forward")
	}

	// A SUCCESSFUL daemon-side reload must DISCHARGE the outstanding debt. The
	// activation really did happen, so leaving the debt latched would make every
	// later Apply shell out forever. Reporting the success is what discharges
	// it: omit NoteReloadResult on the success path and this fails.
	reloadFails = false
	if err := networkctlReload(); err != nil {
		t.Fatalf("networkctlReload should succeed when the shell-out succeeds: %v", err)
	}
	if networkd.ReloadDebtOutstanding() {
		t.Fatal("a SUCCESSFUL daemon-side `networkctl reload` must report its result so the " +
			"activation debt is discharged. An unreported success leaves the debt latched " +
			"and every subsequent networkd.Apply re-runs a reload that is not owed")
	}

	// The epoch snapshot must be taken BEFORE the shell-out. Simulate another
	// owner recording a failure while this reload is in flight: with the
	// snapshot taken first, the epoch has moved by the time the result is
	// reported and networkd refuses the clear, so that owner's debt survives.
	// Move BeginReload() after the shell-out and the snapshot equals the
	// post-failure epoch, the clear is accepted, and the debt is lost — a reload
	// that provably could not have activated the other owner's files silently
	// marks them activated.
	duringReload = func() {
		networkd.NoteReloadResult(networkd.BeginReload(),
			errors.New("a concurrent owner's reload failed while this one was in flight"))
	}
	if err := networkctlReload(); err != nil {
		t.Fatalf("networkctlReload should succeed when the shell-out succeeds: %v", err)
	}
	duringReload = nil
	if !networkd.ReloadDebtOutstanding() {
		t.Fatal("a debt recorded by ANOTHER owner while this reload was in flight was cleared " +
			"by this reload's success. The epoch must be snapshotted BEFORE the shell-out: " +
			"this reload re-read the networkd directory before the other owner's files were " +
			"written, so it cannot have activated them, and clearing their debt tells the " +
			"next Apply to skip a reload the kernel never performed")
	}
}
