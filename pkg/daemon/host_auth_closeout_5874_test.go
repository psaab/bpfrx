package daemon

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// noopCloseoutOwner is a host-auth closeout owner that always reconciles
// cleanly — a stand-in for the owners a given test is not exercising.
func noopCloseoutOwner(*config.Config) error { return nil }

// TestHostAuthCloseoutSurfacesReconcilerFailure is the #5874 fail-on-revert
// merge gate. Before the fix the post-promotion cancel closeout ran the five
// credential reconcilers (login / sudoers / absent-user / SSH / root-auth) as
// best-effort VOIDS and returned only the two nft errors, so a credential
// reconcile FAILURE was silently discarded and the cancel reported clean over a
// host-auth state that never converged. This drives the REAL reconcileSudoers
// with an unwritable sudoers directory (a genuine durable-write failure for a
// configured super-user) through the closeout's collect+summarize path and
// asserts the failure is SURFACED and attributed to the "sudoers" owner.
//
// Fail-on-revert (single compiling neutralization): drop the
// `case o.err != nil` append in summarizeHostAuthCloseout and the closeout
// returns nil for a failed owner — this test goes RED on the `err == nil`
// assertion. Control: the same reconcile against a writable dir returns nil.
func TestHostAuthCloseoutSurfacesReconcilerFailure(t *testing.T) {
	d := &Daemon{}

	// Failure injection: point reconcileSudoers at a non-existent directory so
	// its durable grant write fails for a real super-user. validateSudoersFile
	// is stubbed (unreached — the write fails first — but keeps the test
	// independent of a host visudo).
	origDir, origValidate := sudoersDir, validateSudoersFile
	validateSudoersFile = func(string) error { return nil }
	defer func() { sudoersDir, validateSudoersFile = origDir, origValidate }()
	sudoersDir = filepath.Join(t.TempDir(), "missing") // never created → write fails

	cfg := loginCfg(&config.LoginUser{Name: "admin", Class: "super-user"})

	// Only "sudoers" is the real reconciler; the other six owners are clean
	// no-ops so the assertion isolates the surfaced credential failure.
	owners := []hostAuthOwner{
		{"lo0-filter", noopCloseoutOwner},
		{"host-inbound-filter", noopCloseoutOwner},
		{"system-login", noopCloseoutOwner},
		{"sudoers", d.reconcileSudoers}, // REAL reconciler, injected to fail
		{"absent-login-users", noopCloseoutOwner},
		{"ssh-config", noopCloseoutOwner},
		{"root-auth", noopCloseoutOwner},
	}

	err := summarizeHostAuthCloseout(runHostAuthCloseoutOwners(cfg, hostAuthCloseoutBudget, owners))
	if err == nil {
		t.Fatal("host-auth cancel closeout returned nil despite a sudoers reconcile failure — " +
			"the credential-reconcile failure was DISCARDED (the #5874 bug)")
	}
	if !strings.Contains(err.Error(), "sudoers") {
		t.Fatalf("closeout error %q does not attribute the failure to the sudoers owner", err)
	}

	// Control: a writable sudoers dir → the same reconcile succeeds → clean.
	sudoersDir = t.TempDir()
	if err := summarizeHostAuthCloseout(runHostAuthCloseoutOwners(cfg, hostAuthCloseoutBudget, owners)); err != nil {
		t.Fatalf("closeout returned %v with all owners succeeding, want nil", err)
	}
}

// TestHostAuthCloseoutEnforcesBudget proves the closeout is BOUNDED (#5874): a
// wedged owner that outruns the budget is reported timed-out (fail-visible)
// rather than allowed to hang the daemon-stop path indefinitely, and every
// owner queued after the budget is exhausted is reported timed-out too — never
// silently skipped, and never launched concurrently with the abandoned one.
func TestHostAuthCloseoutEnforcesBudget(t *testing.T) {
	release := make(chan struct{})
	defer close(release) // unblock the wedged goroutine on test exit (no leak)

	wedged := func(*config.Config) error {
		<-release // block well past the budget
		return nil
	}
	launchedAfter := false
	afterBudget := func(*config.Config) error { launchedAfter = true; return nil }

	owners := []hostAuthOwner{
		{"fast", noopCloseoutOwner},
		{"wedged", wedged},
		{"after", afterBudget},
	}

	start := time.Now()
	outcomes := runHostAuthCloseoutOwners(&config.Config{}, 50*time.Millisecond, owners)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Fatalf("closeout blocked %v on a wedged owner — the wall-clock budget was not enforced", elapsed)
	}

	got := map[string]hostAuthOwnerOutcome{}
	for _, o := range outcomes {
		got[o.name] = o
	}
	if got["fast"].err != nil || got["fast"].timedOut {
		t.Errorf("fast owner outcome = %+v, want clean (nil err, not timed out)", got["fast"])
	}
	if !got["wedged"].timedOut {
		t.Errorf("wedged owner outcome = %+v, want timedOut", got["wedged"])
	}
	if !got["after"].timedOut {
		t.Errorf("owner queued after budget exhaustion = %+v, want reported timedOut (not silently skipped)", got["after"])
	}
	if launchedAfter {
		t.Error("owner after a budget-exhausting wedge was LAUNCHED — the skip-after-deadline invariant " +
			"(no concurrent run with the abandoned owner) was violated")
	}

	// The summary surfaces the timed-out owners as a joined, named error.
	err := summarizeHostAuthCloseout(outcomes)
	if err == nil || !strings.Contains(err.Error(), "wedged") || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("summary = %v, want it to name the timed-out wedged owner", err)
	}
}

// TestHostAuthCloseoutOwnerWiring guards the owner set: every security-critical
// host-authorization owner — especially the five credential reconcilers whose
// failures used to be discarded (#5874) — must stay wired into the closeout, in
// the M35 tail order (step 9.5–13). Dropping an owner here would silently narrow
// what a cancel reconciles and re-open a monotonic-revocation gap.
func TestHostAuthCloseoutOwnerWiring(t *testing.T) {
	d := &Daemon{}
	got := d.hostAuthCloseoutOwners()
	want := []string{
		"lo0-filter", "host-inbound-filter", "system-login",
		"sudoers", "absent-login-users", "ssh-config", "root-auth",
	}
	if len(got) != len(want) {
		t.Fatalf("hostAuthCloseoutOwners has %d owners %v, want %d %v", len(got), ownerNames(got), len(want), want)
	}
	for i, name := range want {
		if got[i].name != name {
			t.Errorf("owner[%d] = %q, want %q", i, got[i].name, name)
		}
		if got[i].fn == nil {
			t.Errorf("owner %q has a nil reconcile fn", name)
		}
	}
}

func ownerNames(owners []hostAuthOwner) []string {
	names := make([]string, len(owners))
	for i, o := range owners {
		names[i] = o.name
	}
	return names
}

// TestReconcileSudoersReturnsWriteFailure pins the #5874 reconciler-side change:
// reconcileSudoers now RETURNS its accumulated grant-write failures instead of
// only logging them, so the cancel closeout can attribute a failed sudo-grant
// reconcile to the sudoers owner. A configured super-user whose grant cannot be
// written (unwritable dir) yields a non-nil error; the same reconcile against a
// writable dir returns nil.
func TestReconcileSudoersReturnsWriteFailure(t *testing.T) {
	origDir, origValidate := sudoersDir, validateSudoersFile
	validateSudoersFile = func(string) error { return nil }
	defer func() { sudoersDir, validateSudoersFile = origDir, origValidate }()

	d := &Daemon{}
	cfg := loginCfg(&config.LoginUser{Name: "admin", Class: "super-user"})

	sudoersDir = filepath.Join(t.TempDir(), "missing") // never created → write fails
	if err := d.reconcileSudoers(cfg); err == nil {
		t.Fatal("reconcileSudoers returned nil despite an unwritable sudoers dir — write failure discarded")
	}

	sudoersDir = t.TempDir()
	if err := d.reconcileSudoers(cfg); err != nil {
		t.Fatalf("reconcileSudoers returned %v with a writable dir, want nil", err)
	}
}
