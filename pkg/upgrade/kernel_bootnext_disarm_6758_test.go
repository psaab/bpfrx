package upgrade

import (
	"errors"
	"strings"
	"testing"
)

// #6758 — BootNext could remain armed in NVRAM while every durable software
// gate classified the node as unarmed.
//
// The two-phase arm records ARMING before touching NVRAM and advances to ARMED
// only after a positive BootNext readback. Every failure between those points
// returned an error and left the journal at ARMING — but `SetBootNext` had
// ALREADY SUCCEEDED, so the firmware would still one-shot the candidate on the
// next reboot.
//
// ARMING is documented as exactly the opposite: "the firmware still boots the
// known-good default (no confirmed one-shot)". That claim is what lets `Arm`
// re-arm from ARMING and what stops self-recovery suppressing expired-lease
// failback — so a drained node could rejoin with an untested candidate kernel
// queued for its next boot, while `IsArmed()` reported false.
//
// The observable in these tests is the FIRMWARE state (the fake's bootNext),
// not the journal: the journal was always right about what it had confirmed;
// NVRAM was the half that disagreed with it.

func TestArmClearsBootNextWhenReadbackFails_6758(t *testing.T) {
	f := newFakeKernelSystem()
	f.getBootNextErr = errors.New("efivarfs readback raced / unavailable")
	r := newKernelRunner(t, f)

	if err := r.Arm("6.18.5-12-generic"); err == nil {
		t.Fatal("premise broken: the arm must fail when the readback cannot confirm")
	}
	if f.bootNext != "" {
		t.Errorf("BootNext is still %q after a failed arm — the firmware will one-shot the "+
			"candidate while the journal records ARMING (no trial) and IsArmed() reports "+
			"false (#6758)", f.bootNext)
	}
	j, err := r.loadKernelJournal()
	if err != nil {
		t.Fatal(err)
	}
	if j.State != KernelStateArming {
		t.Errorf("journal state = %s, want ARMING — the disarm must not change the "+
			"journal's meaning, only make NVRAM agree with it", j.State)
	}
}

func TestArmClearsBootNextWhenReadbackDisagrees_6758(t *testing.T) {
	f := newFakeKernelSystem()
	// The firmware silently accepted something else — a partial write or a
	// dropped variable. Whatever is in NVRAM, it must not survive a failed arm.
	f.getBootNextRet = "Boot9999"
	r := newKernelRunner(t, f)

	if err := r.Arm("6.18.5-12-generic"); err == nil {
		t.Fatal("premise broken: a readback mismatch must fail the arm")
	}
	if f.bootNext != "" {
		t.Errorf("BootNext left as %q after a readback mismatch — a one-shot the arm "+
			"refused to record must not survive it (#6758)", f.bootNext)
	}
}

// TestArmReportsAnUnclearableBootNext_6758 covers the case the disarm cannot
// fix. If the clear itself fails the divergence is real, so the error must say
// so and name the operator command — a failed arm that quietly leaves the
// firmware armed is the original defect wearing a different error message.
func TestArmReportsAnUnclearableBootNext_6758(t *testing.T) {
	f := newFakeKernelSystem()
	f.getBootNextErr = errors.New("efivarfs readback raced / unavailable")
	f.clearBootNextErr = errors.New("efibootmgr: cannot write efivarfs")
	r := newKernelRunner(t, f)

	err := r.Arm("6.18.5-12-generic")
	if err == nil {
		t.Fatal("premise broken: the arm must fail")
	}
	msg := err.Error()
	for _, want := range []string{"could not be cleared", "efibootmgr --delete-bootnext"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error must name the un-undoable divergence and the remedy; "+
				"missing %q in: %v", want, err)
		}
	}
	if !strings.Contains(msg, "readback") {
		t.Errorf("the ORIGINAL cause must survive the wrapping — an operator needs to know "+
			"why the arm failed, not only that a cleanup failed: %v", err)
	}
}

// TestSuccessfulArmKeepsBootNext_6758 is the OVER-CLEARING control, and it is
// the one that matters most: an implementation that cleared BootNext
// unconditionally would pass every test above and DISARM EVERY SUCCESSFUL ARM —
// turning a kernel upgrade into a silent no-op that boots the old kernel and
// reports success.
func TestSuccessfulArmKeepsBootNext_6758(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)

	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("premise broken: this arm must succeed: %v", err)
	}
	if f.bootNext == "" {
		t.Fatal("a SUCCESSFUL arm left BootNext cleared — the candidate would never be " +
			"trialled and the next boot would silently use the old kernel while the " +
			"journal records ARMED")
	}
	j, err := r.loadKernelJournal()
	if err != nil {
		t.Fatal(err)
	}
	if j.State != KernelStateArmed {
		t.Fatalf("journal state = %s, want ARMED", j.State)
	}
	if f.bootNext != j.BootID {
		t.Errorf("BootNext = %q but the journal records BootID %q — NVRAM and the journal "+
			"must name the SAME one-shot, which is the agreement #6758 is about",
			f.bootNext, j.BootID)
	}
	if armed, _, _ := r.IsArmed(); !armed {
		t.Error("IsArmed() must be true after a verified arm")
	}
}
