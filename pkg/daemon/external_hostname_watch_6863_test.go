package daemon

import (
	"context"
	"errors"
	"testing"
	"time"
)

func withHostname6863(t *testing.T, name string, err error) {
	t.Helper()
	prior := osHostname
	osHostname = func() (string, error) { return name, err }
	t.Cleanup(func() { osHostname = prior })
}

// #6863: the FIRST observation must seed the baseline and record nothing.
//
// A daemon that has just started has no earlier name to have been renamed
// from. Without this, every restart of a box whose certificate is perfectly
// current would record a debt and emit the diagnosis — the diagnostic-muting
// failure mode by volume rather than by silence.
func TestFirstObservationSeedsAndRecordsNothing_6863(t *testing.T) {
	withHostname6863(t, "fw0", nil)
	d := &Daemon{}

	if d.noteExternalHostRenameIfAny() {
		t.Error("the first observation must NOT record a debt")
	}
	d.staleCertMu.Lock()
	defer d.staleCertMu.Unlock()
	if d.lastSeenHostName != "fw0" {
		t.Errorf("baseline = %q, want fw0 — the first observation must seed it, or "+
			"every later tick re-seeds and no rename is ever detected", d.lastSeenHostName)
	}
	if d.staleCertPending {
		t.Error("staleCertPending set on the seeding observation")
	}
	if d.staleCertGen != 0 {
		t.Errorf("staleCertGen = %d, want 0 on the seeding observation", d.staleCertGen)
	}
}

// The property under test: a kernel name that moved without xpfd renaming it
// must record the debt.
func TestExternalRenameRecordsTheDebt_6863(t *testing.T) {
	withHostname6863(t, "fw0", nil)
	d := &Daemon{}
	d.noteExternalHostRenameIfAny() // seed

	withHostname6863(t, "renamed-by-hostnamectl", nil)
	if !d.noteExternalHostRenameIfAny() {
		t.Fatal("an external rename must record a debt — this is the whole gap " +
			"(#6863): hostnamectl / sethostname(2) / a provisioning rewrite never " +
			"call into xpfd, so nothing else ever sets the flag")
	}
	d.staleCertMu.Lock()
	defer d.staleCertMu.Unlock()
	if !d.staleCertPending {
		t.Error("staleCertPending not set after an external rename")
	}
	if d.staleCertGen != 1 {
		t.Errorf("staleCertGen = %d, want 1", d.staleCertGen)
	}
	if d.lastSeenHostName != "renamed-by-hostnamectl" {
		t.Errorf("baseline = %q, want the new name — otherwise the SAME rename is "+
			"re-recorded on every subsequent tick", d.lastSeenHostName)
	}
}

// A steady name must record nothing, on every tick.
//
// Without this, a watcher that recorded unconditionally would satisfy the cell
// above while emitting the diagnosis every 30 seconds forever.
func TestUnchangedHostNameRecordsNothing_6863(t *testing.T) {
	withHostname6863(t, "fw0", nil)
	d := &Daemon{}
	d.noteExternalHostRenameIfAny() // seed

	for i := 0; i < 5; i++ {
		if d.noteExternalHostRenameIfAny() {
			t.Fatalf("tick %d recorded a debt for an UNCHANGED host name", i)
		}
	}
	d.staleCertMu.Lock()
	defer d.staleCertMu.Unlock()
	if d.staleCertGen != 0 {
		t.Errorf("staleCertGen = %d, want 0 — a steady box must not accumulate "+
			"generations", d.staleCertGen)
	}
}

// The rename xpfd performs ITSELF must not be seen as external.
//
// renameHostNotingStaleMgmtCert already records the debt and applyHostname
// delivers it. If the baseline did not move under that same hold, the next tick
// would find the new name differing from a stale baseline and record a SECOND
// debt for one rename — a duplicate WARN arriving from outside the #6827
// generation fence, which the fence cannot suppress because it is a genuinely
// newer generation.
//
// This is the cell that makes the baseline update in management.go load-bearing
// rather than incidental.
func TestOwnRenameIsNotSeenAsExternal_6863(t *testing.T) {
	priorSet := sethostname
	sethostname = func([]byte) error { return nil }
	t.Cleanup(func() { sethostname = priorSet })

	withHostname6863(t, "fw0", nil)
	d := &Daemon{}
	d.noteExternalHostRenameIfAny() // seed at fw0

	if err := d.renameHostNotingStaleMgmtCert("fw1"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	// The kernel now reports the new name, as it would after a real sethostname.
	withHostname6863(t, "fw1", nil)

	genAfterRename := func() uint64 {
		d.staleCertMu.Lock()
		defer d.staleCertMu.Unlock()
		return d.staleCertGen
	}()
	if genAfterRename != 1 {
		t.Fatalf("staleCertGen = %d after our own rename, want 1", genAfterRename)
	}

	if d.noteExternalHostRenameIfAny() {
		t.Fatal("the daemon's OWN rename was recorded a second time as external — " +
			"one rename, two debts, two WARNs (#6863)")
	}
	if got := genAfterRename; func() uint64 {
		d.staleCertMu.Lock()
		defer d.staleCertMu.Unlock()
		return d.staleCertGen
	}() != got {
		t.Error("the generation advanced on a rename xpfd performed itself")
	}
}

// An unreadable kernel name is not evidence of a rename.
//
// Without this, a transient read failure would leave the baseline untouched but
// could otherwise be treated as a change to "", manufacturing a diagnosis on
// the next successful read.
func TestUnreadableHostNameRecordsNothing_6863(t *testing.T) {
	withHostname6863(t, "fw0", nil)
	d := &Daemon{}
	d.noteExternalHostRenameIfAny() // seed

	withHostname6863(t, "", errors.New("boom"))
	if d.noteExternalHostRenameIfAny() {
		t.Error("an unreadable kernel name must not record a debt")
	}
	d.staleCertMu.Lock()
	defer d.staleCertMu.Unlock()
	if d.lastSeenHostName != "fw0" {
		t.Errorf("baseline = %q, want it left at fw0 — a failed read must not move "+
			"the baseline, or the next successful read looks like a rename",
			d.lastSeenHostName)
	}
}

// #6863 WIRING: the management reassert loop must actually CALL the watcher.
//
// Every cell above drives `noteExternalHostRenameIfAny` directly, so all of
// them pass just as well when nothing invokes it — which is the state this
// issue reports about #6827's mechanism, one level up. A correct watcher that
// no tick calls is exactly as useful as no watcher.
//
// The loop is driven with a tiny interval and cancelled as soon as the
// observation lands, so this asserts the call rather than sleeping for one.
func TestReassertLoopCallsTheHostWatcher_6863(t *testing.T) {
	priorInterval := mgmtListenerReassertInterval
	mgmtListenerReassertInterval = time.Millisecond
	t.Cleanup(func() { mgmtListenerReassertInterval = priorInterval })

	observed := make(chan struct{}, 1)
	priorHost := osHostname
	osHostname = func() (string, error) {
		select {
		case observed <- struct{}{}:
		default:
		}
		return "fw0", nil
	}
	t.Cleanup(func() { osHostname = priorHost })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &Daemon{}
	go d.mgmtListenerReassertLoop(ctx)

	select {
	case <-observed:
		// The loop read the kernel host name. That is the wiring.
	case <-time.After(5 * time.Second):
		t.Fatal("the management reassert loop never read the kernel host name in 5s — " +
			"the watcher is not wired into any tick, so an external rename is " +
			"never observed no matter how correct the watcher itself is (#6863)")
	}
}
