package daemon

// sshd_reload_debt_6800_test.go — #6800, the sshd half.
//
// applySSHConfig's UPDATE path already had a retry owner: when the reload
// fails, #2062's revertDropIn restores the prior content, so the file no longer
// matches desired and the next apply rewrites and reloads on its own.
//
// The REMOVAL path has nothing to revert TO. The drop-in is DELETED, the reload
// then fails, and every later apply reads `hadDropIn == false` and returns
// before reaching a reload. sshd keeps enforcing the xpf policy the operator
// REMOVED — a PermitRootLogin, cipher or MAC setting that may be MORE
// permissive than the base-image default — until a manual restart or a reboot,
// on a node whose commit reported success.
//
// That asymmetry is why the "sshd is already covered" reading is wrong, and it
// is the reason these cells exist separately from the rsyslog/chrony ones.

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

// sshdDebtDaemon6800 installs the sshd seam recorder and returns a daemon with
// an apply semaphore, ready to drive applySSHConfig and the re-assert.
func sshdDebtDaemon6800(t *testing.T) (*Daemon, *sshdSeamRecorder) {
	t.Helper()
	r := &sshdSeamRecorder{}
	installSSHDSeam(t, r)
	return &Daemon{applySem: semaphore.NewWeighted(1)}, r
}

// managedSSHCfg6800 is a config with an xpf-managed ssh setting, so
// buildSSHDConfig renders a drop-in.
func managedSSHCfg6800() *config.Config {
	return sshConfig(&config.SSHServiceConfig{RootLogin: "yes"})
}

// TestSSHDRemovalReloadFailureLatchesTheDebt6800 is the PAIRED outcome cell:
// the same removal, two reload results, opposite debt states.
func TestSSHDRemovalReloadFailureLatchesTheDebt6800(t *testing.T) {
	t.Run("failed-reload-latches", func(t *testing.T) {
		d, r := sshdDebtDaemon6800(t)
		r.present = []byte("PermitRootLogin yes\n") // a drop-in exists
		r.reloadErr = errors.New("simulated: Job for ssh.service failed")

		if err := d.applySSHConfig(sshConfig(nil)); err == nil {
			t.Fatal("setup: a failed reload must still surface an error")
		}
		if r.removed != 1 {
			t.Fatalf("setup: the drop-in must be removed, removed=%d", r.removed)
		}
		if !d.sshdReloadOwed() {
			t.Fatal("a FAILED `systemctl reload sshd` after REMOVING the drop-in " +
				"must latch the reload debt. There is nothing to revert to — the " +
				"file is gone — so the next apply reads hadDropIn==false and " +
				"returns before any reload, and sshd keeps enforcing the policy " +
				"the operator deleted (#6800)")
		}
		if owed := d.ManagedServiceReloadOwed(); !owed[svcReloadSSHD] {
			t.Errorf("owed = %v; the sshd debt must be operator-visible", owed)
		}
		// The COUNTER is asserted separately from the flag: they answer
		// different questions, and a counter wired to the flag would collapse
		// them. A gauge stuck at 1 says "not converged"; a count that climbs
		// beside it says the retry owner is running and still failing.
		if f := d.ManagedServiceReloadFailures(); f[svcReloadSSHD] != 1 {
			t.Errorf("sshd failures = %d, want 1", f[svcReloadSSHD])
		}
	})

	t.Run("successful-reload-owes-nothing", func(t *testing.T) {
		d, r := sshdDebtDaemon6800(t)
		r.present = []byte("PermitRootLogin yes\n")

		if err := d.applySSHConfig(sshConfig(nil)); err != nil {
			t.Fatalf("a clean removal must succeed: %v", err)
		}
		if d.sshdReloadOwed() {
			t.Fatal("a SUCCESSFUL reload must leave nothing owed — a latched debt " +
				"would make the re-assert SIGHUP a healthy sshd every 30s forever")
		}
		if f := d.ManagedServiceReloadFailures(); f[svcReloadSSHD] != 0 {
			t.Errorf("sshd failures = %d after a clean removal, want 0 — a counter "+
				"that moves for a successful reload is noise an operator will "+
				"learn to ignore", f[svcReloadSSHD])
		}
	})
}

// TestSSHDRemovalDebtIsRetriedOnAnUnchangedApply6800 is the headline cell for
// this half.
//
// Apply #1 removes the drop-in and its reload FAILS. Apply #2 presents the same
// empty config — and now the drop-in is genuinely absent, so `hadDropIn` is
// false, which is precisely the state in which the pre-#6800 guard returned
// early and stranded sshd on the removed policy.
//
// The fixture premise is guarded explicitly: the recorder must show the file
// really is gone before apply #2, or the cell would be exercising the ordinary
// removal path rather than the retained debt.
func TestSSHDRemovalDebtIsRetriedOnAnUnchangedApply6800(t *testing.T) {
	d, r := sshdDebtDaemon6800(t)
	r.present = []byte("PermitRootLogin yes\n")
	r.reloadErr = errors.New("simulated reload failure")

	_ = d.applySSHConfig(sshConfig(nil))
	if r.present != nil {
		t.Fatal("fixture premise broken: the drop-in must be GONE after apply #1, " +
			"or apply #2 would take the ordinary removal path and this cell would " +
			"prove nothing")
	}
	if !d.sshdReloadOwed() {
		t.Fatal("setup: the reload debt must be outstanding")
	}
	reloadsAfterFirst := r.reloads

	r.reloadErr = nil
	if err := d.applySSHConfig(sshConfig(nil)); err != nil {
		t.Fatalf("apply #2: %v", err)
	}
	if r.reloads != reloadsAfterFirst+1 {
		t.Fatalf("apply #2 issued %d reloads, want 1: the drop-in is already gone "+
			"so hadDropIn is false, and only the retained debt can re-drive the "+
			"reload. Without it sshd keeps enforcing the REMOVED xpf policy — "+
			"possibly a more permissive PermitRootLogin or cipher set than the "+
			"base image's — until a manual restart (#6800)",
			r.reloads-reloadsAfterFirst)
	}
	if d.sshdReloadOwed() {
		t.Error("the re-issued reload succeeded, so the debt must be discharged")
	}
}

// TestSSHDUnchangedApplyWithNoDebtDoesNotReload6800 is the PAIRED negative, and
// it is what keeps the fix from becoming a regression of its own: an apply with
// no managed ssh settings, no drop-in and no debt must not SIGHUP sshd at all.
// A guard widened past the debt would reload the SSH daemon on every single
// commit on the very many nodes that configure no ssh settings.
func TestSSHDUnchangedApplyWithNoDebtDoesNotReload6800(t *testing.T) {
	d, r := sshdDebtDaemon6800(t)
	r.present = nil // no drop-in

	if err := d.applySSHConfig(sshConfig(nil)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := d.applySSHConfig(sshConfig(nil)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if r.reloads != 0 {
		t.Fatalf("a no-drop-in, debt-free apply reloaded sshd %d times, want 0 — "+
			"the hadDropIn guard must still suppress the steady state (#6800)",
			r.reloads)
	}
}

// TestSSHDUpdatePathSuccessDischargesARemovalDebt6800 binds the outcome record
// on the OTHER apply path.
//
// The update path has its own retry owner, so it is tempting to leave it
// unreported. But a successful reload there means sshd has re-read its
// configuration, which pays off a debt an earlier REMOVAL left outstanding. Not
// recording it leaves the debt latched forever on a node that is actually
// healthy, and the re-assert then SIGHUPs a working sshd every 30s.
func TestSSHDUpdatePathSuccessDischargesARemovalDebt6800(t *testing.T) {
	d, r := sshdDebtDaemon6800(t)

	// Arm a removal debt the way production does.
	r.present = []byte("PermitRootLogin yes\n")
	r.reloadErr = errors.New("simulated reload failure")
	_ = d.applySSHConfig(sshConfig(nil))
	if !d.sshdReloadOwed() {
		t.Fatal("setup: the removal debt must be outstanding")
	}

	// The operator now re-adds ssh settings; the write+reload succeeds.
	r.reloadErr = nil
	if err := d.applySSHConfig(managedSSHCfg6800()); err != nil {
		t.Fatalf("update apply: %v", err)
	}
	if d.sshdReloadOwed() {
		t.Fatal("a SUCCESSFUL update-path reload must discharge the removal debt: " +
			"sshd has just re-read its configuration, so nothing is owed. Leaving " +
			"it latched makes the always-on re-assert SIGHUP a healthy sshd every " +
			"30s forever (#6800)")
	}
}

// TestReassertRedrivesTheOwedSSHDReload6800 binds the loop body for sshd,
// including the #4311 validation gate.
//
// The validation leg is not decoration. A reload is a SIGHUP, and re-execing
// sshd into a configuration that fails `sshd -t` can drop the listener — an SSH
// lockout on an appliance. The apply path gates on `sshd -t` for exactly that
// reason, and a re-assert that skipped it would reintroduce the risk on a 30s
// timer. A validation failure must also leave the debt OUTSTANDING: nothing was
// reloaded, so nothing is paid.
func TestReassertRedrivesTheOwedSSHDReload6800(t *testing.T) {
	t.Run("validation-passes-so-the-reload-is-re-driven", func(t *testing.T) {
		d, r := sshdDebtDaemon6800(t)
		r.present = []byte("PermitRootLogin yes\n")
		r.reloadErr = errors.New("simulated reload failure")
		_ = d.applySSHConfig(sshConfig(nil))
		before := r.reloads
		r.reloadErr = nil

		d.reassertServiceReloadDebtOnce(context.Background())

		if r.reloads != before+1 {
			t.Fatalf("the re-assert issued %d sshd reloads, want 1 — a boot-time "+
				"removal whose reload failed has no further apply coming, so this "+
				"loop is the only retry owner (#6800)", r.reloads-before)
		}
		if d.sshdReloadOwed() {
			t.Error("a successful re-assert must discharge the debt")
		}
		// The monotonic count is NOT rewound by recovery: the failure really
		// happened, and a counter that resets hides the flapping it exists to
		// show.
		if f := d.ManagedServiceReloadFailures(); f[svcReloadSSHD] != 1 {
			t.Errorf("sshd failures = %d after recovery, want the count from the "+
				"failed apply preserved (1)", f[svcReloadSSHD])
		}
	})

	t.Run("validation-fails-so-nothing-is-reloaded-or-discharged", func(t *testing.T) {
		d, r := sshdDebtDaemon6800(t)
		r.present = []byte("PermitRootLogin yes\n")
		r.reloadErr = errors.New("simulated reload failure")
		_ = d.applySSHConfig(sshConfig(nil))
		before := r.reloads

		r.reloadErr = nil
		r.validateErr = errors.New("simulated: bad Ciphers line")

		d.reassertServiceReloadDebtOnce(context.Background())

		if r.reloads != before {
			t.Errorf("the re-assert reloaded sshd %d times despite `sshd -t` "+
				"failing, want 0 — a SIGHUP into an invalid configuration can drop "+
				"the listener and lock an operator out of the appliance (#4311)",
				r.reloads-before)
		}
		if !d.sshdReloadOwed() {
			t.Error("a validation failure reloaded nothing, so the debt must stay " +
				"outstanding — discharging it would silently abandon the retry")
		}
		if f := d.ManagedServiceReloadFailures(); f[svcReloadSSHD] != 1 {
			t.Errorf("sshd failures = %d, want 1 — a validation failure is not a "+
				"reload ATTEMPT, so it must not inflate the reload failure count "+
				"beyond the one the apply already recorded", f[svcReloadSSHD])
		}
	})
}

// TestReassertLeavesSSHDAloneWhenNothingIsOwed6800 is the per-service gate for
// sshd, mirroring the rsyslog/chrony pair. Without it an owed rsyslog restart
// would drag a perfectly healthy sshd through a SIGHUP every 30s.
func TestReassertLeavesSSHDAloneWhenNothingIsOwed6800(t *testing.T) {
	d, restarts, setFail := syslogDaemon6800(t)
	r := &sshdSeamRecorder{}
	installSSHDSeam(t, r)
	d.applySem = semaphore.NewWeighted(1)

	setFail(errors.New("simulated restart failure"))
	d.applySyslogFiles(syslogFileCfg6800("audit"))
	if !d.rsyslogRestartOwed() || d.sshdReloadOwed() {
		t.Fatal("setup: rsyslog must owe a restart and sshd must owe nothing")
	}
	before := restarts()

	d.reassertServiceReloadDebtOnce(context.Background())

	if restarts() != before+1 {
		t.Errorf("the owed rsyslog restart was not re-driven")
	}
	if r.reloads != 0 || r.validates != 0 {
		t.Errorf("the re-assert touched sshd (%d reloads, %d validations) while "+
			"only rsyslog owed anything, want 0/0 — each service must gate on its "+
			"OWN debt, or an rsyslog failure SIGHUPs a healthy sshd every 30s "+
			"(#6800)", r.reloads, r.validates)
	}
}
