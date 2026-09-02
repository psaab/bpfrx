package journal

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// #7174 C06 fail-on-revert: rotation must not destroy the segment an in-flight
// append is still fsyncing.
//
// The window is created by the #4829 lock discipline: Log holds j.mu only for
// the buffered f.Write and releases it before the synchronous f.Sync, so a
// second writer can rotate while the first is parked mid-durability. Renames
// are harmless — they preserve the inode — but rotation also unlinks the oldest
// kept segment, and once that inode is gone the parked writer's fsync still
// SUCCEEDS and Log still returns nil. The audit record is lost and nothing
// reports it: Store.journalLog only logs when Log returns an error.
//
// The fixture is the minimum shape in which the loss is reachable:
// maxSegments=1, so a writer's inode reaches the destroyed slot after just two
// rotations, and a syncFile hook parks the first writer between its write and
// its fsync for exactly that long. This test is what a fix has to survive; a
// version that only asserted "Log returned nil" would pass on the broken code,
// because on the broken code Log DOES return nil.
func TestRotationDoesNotDestroyInflightAppend7174C06(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".config.journal")
	// maxSegmentBytes 1: every append after the first is over threshold, so
	// each one rotates.
	j := New(path, WithMaxSegmentBytes(1), WithMaxSegments(1))

	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	prod := j.syncFile
	j.syncFile = func(f *os.File) error {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return prod(f)
	}

	var keeperErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		keeperErr = j.Log(&Entry{Action: "commit", Detail: "keeper"})
	}()

	// The keeper's bytes are written and j.mu is released; its fsync is parked.
	<-entered

	// Two more appends. Without the guard: the first renames the keeper's inode
	// to ".1", and the second os.Remove()s ".1" — destroying it.
	mustLog(t, j, &Entry{Action: "commit", Detail: "b1"})
	mustLog(t, j, &Entry{Action: "commit", Detail: "b2"})

	close(release)
	<-done
	if keeperErr != nil {
		t.Fatalf("keeper Log: %v", keeperErr)
	}

	all, err := j.Tail(0)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	var details []string
	for _, e := range all {
		details = append(details, e.Detail)
	}
	found := false
	for _, d := range details {
		if d == "keeper" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the in-flight append was destroyed by rotation and Log still "+
			"reported success — the audit record is gone with no error anywhere. "+
			"journal holds %v", details)
	}
	// The deferral must be a deferral, not a permanent stall: the appends that
	// raced the parked writer are all present too.
	for _, want := range []string{"b1", "b2"} {
		ok := false
		for _, d := range details {
			if d == want {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("append %q lost while rotation was deferred; journal holds %v", want, details)
		}
	}
}

// The control: once the in-flight append has drained, rotation must resume.
// A guard that deferred forever would satisfy the test above (nothing is ever
// destroyed if nothing ever rotates) while silently disabling retention and
// letting the current segment grow without bound.
func TestRotationResumesAfterInflightAppendDrains7174C06(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".config.journal")
	j := New(path, WithMaxSegmentBytes(1), WithMaxSegments(1))

	for i := 0; i < 4; i++ {
		mustLog(t, j, &Entry{Action: "commit", Detail: "seed"})
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotation must still happen when nothing is in flight: %v", err)
	}

	// The current segment must not have accumulated every record: with no
	// in-flight append and a 1-byte threshold, each append rotates.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat current: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatal("current segment is empty")
	}
	cur, err := tailSegment(path, 100)
	if err != nil {
		t.Fatalf("tailSegment: %v", err)
	}
	if len(cur) != 1 {
		t.Fatalf("current segment must hold exactly the last record after a "+
			"rotation, got %d — rotation is being deferred when nothing is in flight",
			len(cur))
	}
}
