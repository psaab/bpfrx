// Package lock provides a host-wide advisory lock that serializes every
// mutating xpf upgrade operation on a single host (#1965).
//
// Background: the upgrade subsystem (pkg/upgrade, cmd/xpfd/upgrade*.go,
// debian/*) durably writes a crash-safe journal, repoints symlinks, and
// installs systemd drop-ins with NO host-local serialization. Two
// mutators racing (operator `xpfd upgrade` vs the Debian postinst cut, a
// binary cut vs `xpfd upgrade kernel arm`, a `--rolling` driver vs a local
// cut) silently corrupt that state: both loadJournal() the same snapshot,
// modify independent copies, and saveJournal() last-write-wins, losing the
// PreviousVersion / rollback target. Unlike a fixed-name temp-symlink
// collision (which errors cleanly via EEXIST), the journal race is silent.
//
// The fix is one host-wide advisory lock taken by every MUTATING upgrade
// entry point — binary cut, rolling driver, postinst cut, and the mutating
// `xpfd upgrade kernel` sub-verbs (arm/promote/drain/rejoin). Read-only
// status commands stay lock-free.
//
// Design:
//   - The lock is an exclusive non-blocking BSD advisory lock
//     (flock(2), LOCK_EX|LOCK_NB) on /run/xpf/upgrade.lock.
//   - /run is tmpfs and reboot-clearing, which is exactly right: the lock
//     guards against CONCURRENT mutators, while crash recovery is journal-
//     driven (the durable journal lives under /var/lib/xpf). A reboot that
//     interrupts an upgrade leaves no stale lock; the resume reads the
//     journal, not the lock.
//   - /run/xpf is created (mkdir -p) before the acquire — a fresh boot's
//     tmpfs may not have it yet.
//   - Owner metadata (PID, subcommand, target version/kernel, start time)
//     is written into the lock file AFTER the flock succeeds, so a busy
//     error can name the CURRENT owner instead of merely reporting "busy".
//   - flock is advisory and tied to the OPEN FILE DESCRIPTION, not the
//     path: a second open()+flock() on the same path returns EWOULDBLOCK
//     while another fd holds LOCK_EX. The lock is released by closing the
//     fd (Handle.Release), and the kernel also releases it on process
//     exit, so a crashed holder never wedges the host.
package lock

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultPath is the host-wide upgrade lock file. /run is tmpfs (reboot-
// clearing) — see the package doc for why that is correct.
const DefaultPath = "/run/xpf/upgrade.lock"

// Owner is the metadata persisted into the lock file by the current
// holder. It is written after the flock succeeds and read back by a
// would-be acquirer so a busy error names the owner.
type Owner struct {
	// PID is the holding process id.
	PID int `json:"pid"`
	// Subcommand is the mutating operation, e.g. "upgrade",
	// "upgrade --rolling", "upgrade kernel arm".
	Subcommand string `json:"subcommand"`
	// Target is the target version or kernel (best-effort, may be empty
	// when not yet known at acquire time).
	Target string `json:"target,omitempty"`
	// StartedAt is when the holder acquired the lock.
	StartedAt time.Time `json:"started_at"`
}

func (o Owner) String() string {
	tgt := o.Target
	if tgt == "" {
		tgt = "(unknown)"
	}
	return fmt.Sprintf("pid=%d subcommand=%q target=%s started=%s",
		o.PID, o.Subcommand, tgt, o.StartedAt.Format(time.RFC3339))
}

// Handle is a held upgrade lock. Release MUST be called (via defer) on
// every exit path — normal, error, and panic — to drop the lock; the
// kernel also drops it on process exit as a backstop.
type Handle struct {
	f        *os.File
	released bool
}

// ErrBusy is returned by Acquire when another process holds the lock. The
// error text names the current owner (read from the lock file) when it is
// readable.
type ErrBusy struct {
	Path  string
	Owner *Owner // nil if owner metadata could not be read
}

func (e *ErrBusy) Error() string {
	if e.Owner != nil {
		return fmt.Sprintf("another upgrade is in progress (holds %s): %s",
			e.Path, e.Owner.String())
	}
	return fmt.Sprintf("another upgrade is in progress (holds %s; owner metadata unavailable)", e.Path)
}

// IsBusy reports whether err is (or wraps) an ErrBusy.
func IsBusy(err error) bool {
	var b *ErrBusy
	return errors.As(err, &b)
}

// Acquire takes the host-wide upgrade lock at DefaultPath, returning a
// Handle whose Release drops it. It is a non-blocking exclusive flock: if
// another process holds the lock, it returns an *ErrBusy naming the owner.
//
// The owner metadata (PID, subcommand, target, start time) is recorded in
// the lock file after the flock succeeds.
func Acquire(subcommand, target string) (*Handle, error) {
	return AcquireAt(DefaultPath, subcommand, target)
}

// AcquireAt is Acquire against an explicit path (for tests; production
// always uses DefaultPath via Acquire).
func AcquireAt(path, subcommand, target string) (*Handle, error) {
	// /run is tmpfs and may lack our subdir on a fresh boot.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("upgrade lock: create %s: %w", filepath.Dir(path), err)
	}

	// O_CREATE so the first acquirer makes the file; no O_TRUNC so a busy
	// acquirer can still read the holder's metadata.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("upgrade lock: open %s: %w", path, err)
	}

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		// Busy (EWOULDBLOCK) — read the holder's metadata so the error
		// names the owner. Any read failure degrades to a nil Owner.
		owner := readOwner(f)
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, &ErrBusy{Path: path, Owner: owner}
		}
		return nil, fmt.Errorf("upgrade lock: flock %s: %w", path, err)
	}

	h := &Handle{f: f}

	// We hold the lock — record owner metadata. Truncate first so a stale
	// (larger) prior record never leaves trailing bytes. A metadata-write
	// failure is non-fatal to holding the lock (the lock is the flock, not
	// the file contents) — we keep the lock but surface the write error so
	// the caller can log it; the busy path then degrades to a nil Owner.
	if err := writeOwner(f, Owner{
		PID:        os.Getpid(),
		Subcommand: subcommand,
		Target:     target,
		StartedAt:  time.Now(),
	}); err != nil {
		// Keep the lock; report a non-fatal metadata error wrapped so the
		// caller may log it but the Handle is still valid.
		return h, fmt.Errorf("upgrade lock: acquired but failed to record owner metadata: %w", err)
	}
	return h, nil
}

// Release drops the lock and closes the fd. It is idempotent and safe to
// call from a defer on every path (normal, error, panic). Closing the fd
// releases the flock; the kernel also releases on process exit.
func (h *Handle) Release() error {
	if h == nil || h.released {
		return nil
	}
	h.released = true
	// Closing the fd releases the flock (the lock is tied to the open file
	// description). Explicitly LOCK_UN first is redundant but harmless and
	// makes the release intent obvious; ignore its error since Close is the
	// authoritative drop.
	_ = unix.Flock(int(h.f.Fd()), unix.LOCK_UN)
	return h.f.Close()
}

// writeOwner truncates the lock file and writes the owner metadata as
// pretty JSON. The fd already holds the flock.
func writeOwner(f *os.File, o Owner) error {
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteAt(data, 0); err != nil {
		return err
	}
	// Best-effort durability; the lock's correctness does not depend on the
	// metadata reaching disk (tmpfs anyway).
	_ = f.Sync()
	return nil
}

// readOwner reads and parses the owner metadata from an open lock file.
// Returns nil on any read/parse failure (degrade to "busy, owner unknown").
func readOwner(f *os.File) *Owner {
	data, err := os.ReadFile(f.Name())
	if err != nil || len(data) == 0 {
		return nil
	}
	var o Owner
	if err := json.Unmarshal(data, &o); err != nil {
		return nil
	}
	return &o
}
