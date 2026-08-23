package daemon

// dns_ownership_failclosed_6792_test.go — #6792.
//
// Every failure in the DNS reconcile was WARN-only and `reconcile` /
// `reconcileDNSLocked` both returned nothing, so nothing could propagate. A
// commit reported success while leaving one of two states the operator did not
// ask for:
//
//   - DUAL RESOLVER: the disable+mask failed, systemd-resolved keeps running,
//     and xpf still writes /etc/resolv.conf. xpf's own networkd .network files
//     carry UseDNS=yes, so the surviving resolved is independently fed DHCP
//     nameservers.
//   - STALE resolv.conf: the write failed AFTER the mask and drop-in removal
//     had already run.
//
// No retry, no ticker, no metric — and the pre-existing tests stubbed
// disableMaskResolved to always return nil, so no failure path was covered at
// all.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/daemon/system"
)

func dnsInput6792() system.ResolvedDropinInput {
	return system.ResolvedDropinInput{NameServers: []string{"1.1.1.1"}}
}

// TestReconcileReturnsAMaskFailure6792 is PAIRED: the same reconcile, two
// disable+mask outcomes, opposite returns.
//
// The success leg is load-bearing. Without it, "returns an error when the mask
// fails" is satisfied by a reconcile that returns an error unconditionally,
// which would fail every commit on every system.
func TestReconcileReturnsAMaskFailure6792(t *testing.T) {
	maskErr := errors.New("simulated: systemctl mask refused")

	t.Run("mask-fails", func(t *testing.T) {
		dir := t.TempDir()
		r, _ := newTestReconciler(t, dir)
		r.disableMaskResolved = func() error { return maskErr }

		err := r.reconcile(dnsInput6792(), false)
		if err == nil {
			t.Fatal("reconcile returned nil after the disable+mask FAILED — " +
				"systemd-resolved may still be running as a second resolver " +
				"owner and the commit reports success (#6792)")
		}
		if !errors.Is(err, maskErr) {
			t.Fatalf("returned error does not wrap the mask failure: %v", err)
		}

		// Behaviour preserved: a mask failure must NOT skip the resolv.conf
		// write. A static file wins over an inactive stub, and returning early
		// would make a systemd hiccup also cost the resolver file.
		got := readFile(t, filepath.Join(dir, "resolv.conf"))
		if !strings.Contains(got, "1.1.1.1") {
			t.Fatalf("resolv.conf was not written after a mask failure:\n%s", got)
		}
	})

	t.Run("mask-succeeds", func(t *testing.T) {
		dir := t.TempDir()
		r, calls := newTestReconciler(t, dir)

		if err := r.reconcile(dnsInput6792(), false); err != nil {
			t.Fatalf("reconcile returned %v on the healthy path — every commit "+
				"would now fail closed on DNS", err)
		}
		if *calls == 0 {
			t.Fatal("the fixture never called disable+mask, so the failing leg " +
				"above is not exercising the path this test claims")
		}
	})
}

// TestReconcileReturnsAWriteFailure6792 covers the other reachable end state:
// the mask and drop-in removal have already run, and the write fails, so
// /etc/resolv.conf is stale while resolved is gone — the host has no working
// resolver and the commit said success.
//
// The failure is induced by making the target path a DIRECTORY, so both the
// atomic rename and its bind-mount in-place fallback fail. That is a real
// filesystem refusal rather than a stubbed error, so it also exercises
// atomicWrite's fallback chain.
func TestReconcileReturnsAWriteFailure6792(t *testing.T) {
	dir := t.TempDir()
	r, _ := newTestReconciler(t, dir)
	if err := os.MkdirAll(r.resolvConfPath, 0o755); err != nil {
		t.Fatalf("seed a directory at the resolv.conf path: %v", err)
	}

	err := r.reconcile(dnsInput6792(), false)
	if err == nil {
		t.Fatal("reconcile returned nil after the managed resolv.conf write " +
			"FAILED — the mask and drop-in removal already ran, so the host is " +
			"left with a stale (here: unwritable) resolver file and the commit " +
			"reports success (#6792)")
	}
	if !strings.Contains(err.Error(), "write managed") {
		t.Fatalf("returned error does not name the write failure: %v", err)
	}
}

// TestReconcileReturnsADropinRemovalFailure6792 covers the third warn-only
// point. A surviving drop-in re-arms resolved's view of the nameservers if it
// is ever unmasked, so failing to remove it is a failure to reach the declared
// end state — not a cosmetic one.
//
// Induced by making the drop-in a NON-EMPTY DIRECTORY, which os.Remove refuses
// with something other than IsNotExist.
func TestReconcileReturnsADropinRemovalFailure6792(t *testing.T) {
	dir := t.TempDir()
	r, _ := newTestReconciler(t, dir)
	if err := os.MkdirAll(filepath.Join(r.xpfResolvedDropin, "child"), 0o755); err != nil {
		t.Fatalf("seed an unremovable drop-in: %v", err)
	}

	err := r.reconcile(dnsInput6792(), false)
	if err == nil {
		t.Fatal("reconcile returned nil after a stale resolved drop-in could " +
			"not be removed (#6792)")
	}
	if !strings.Contains(err.Error(), "remove stale resolved drop-in") {
		t.Fatalf("returned error does not name the drop-in removal: %v", err)
	}

	// The write still happened: a drop-in that will not go away must not cost
	// the resolver file too.
	got := readFile(t, filepath.Join(dir, "resolv.conf"))
	if !strings.Contains(got, "1.1.1.1") {
		t.Fatalf("resolv.conf was not written after a drop-in removal failure:\n%s", got)
	}
}

// TestReconcileEarlyReturnsStillCarryTheirErrors6792 is the cell a naive
// accumulator fails.
//
// `reconcile` has two SUCCESS early-returns — the boot empty-merge policy and
// the idempotence skip — that run AFTER the mask and drop-in steps. An
// implementation that accumulated errors but returned a bare `nil` at those
// two points would report success for exactly the pass where nothing else
// changed and the mask failure was the only news.
func TestReconcileEarlyReturnsStillCarryTheirErrors6792(t *testing.T) {
	maskErr := errors.New("simulated: systemctl mask refused")

	t.Run("idempotence-skip", func(t *testing.T) {
		dir := t.TempDir()
		r, _ := newTestReconciler(t, dir)
		// Converge first so the content matches and the next pass skips.
		if err := r.reconcile(dnsInput6792(), false); err != nil {
			t.Fatalf("precondition reconcile: %v", err)
		}
		r.disableMaskResolved = func() error { return maskErr }

		err := r.reconcile(dnsInput6792(), false)
		if err == nil {
			t.Fatal("the idempotence skip swallowed a mask failure — on a " +
				"steady-state config that is EVERY pass, so a resolved that " +
				"came back would never be reported (#6792)")
		}
		if !errors.Is(err, maskErr) {
			t.Fatalf("idempotent pass lost the mask failure: %v", err)
		}
	})

	t.Run("boot-empty-repair-only", func(t *testing.T) {
		dir := t.TempDir()
		r, _ := newTestReconciler(t, dir)
		// A good regular file already present + no nameservers + boot policy
		// = the leave-it-alone early return.
		if err := os.WriteFile(r.resolvConfPath, []byte("nameserver 9.9.9.9\n"), 0o644); err != nil {
			t.Fatalf("seed a good resolv.conf: %v", err)
		}
		r.disableMaskResolved = func() error { return maskErr }

		err := r.reconcile(system.ResolvedDropinInput{}, true)
		if err == nil {
			t.Fatal("the boot empty-merge early return swallowed a mask " +
				"failure (#6792)")
		}
		if !errors.Is(err, maskErr) {
			t.Fatalf("boot early return lost the mask failure: %v", err)
		}
		// The policy itself is unchanged: the good file is left alone.
		if got := readFile(t, r.resolvConfPath); !strings.Contains(got, "9.9.9.9") {
			t.Fatalf("the boot policy clobbered a good resolv.conf:\n%s", got)
		}
	})
}
