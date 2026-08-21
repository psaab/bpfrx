package userspace

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Socket-kind labels for removeStaleUnixSocket. They appear verbatim in the
// operator-facing error, so keep them noun phrases that read as the subject of
// "refusing to unlink <kind> <path>".
const (
	socketKindControl     = "control socket"
	socketKindEventStream = "event stream socket"
)

// removeStaleUnixSocket removes only a PROVEN STALE Unix socket at path, and is
// the single implementation of stale-socket removal in this package (#5839).
//
// Both helper sockets are named by operator-supplied configuration
// (`system dataplane control-socket`, and the event socket derived beside it),
// and xpfd runs as root, so an unconditional os.Remove would silently unlink
// whatever filesystem object the path happened to name. Four checks stand
// between the path and the unlink, in this order:
//
//  1. Lstat, with "does not exist" tolerated. A first boot has no socket, and
//     that is the normal case, not an error. Lstat rather than Stat so a
//     SYMLINK is judged on its own inode: a symlink is not a socket and is
//     therefore rejected below instead of being followed to its target.
//  2. os.ModeSocket. A regular file, directory, FIFO, device, or symlink at the
//     path is refused rather than deleted. This is the data-destruction case.
//  3. A liveness probe against the kernel Unix socket table. Unlinking the
//     socket of a LIVE listener does not stop that listener: it keeps serving
//     the now-unreachable inode while a second process binds a fresh socket at
//     the same path. For the control socket that means two helpers contending
//     for the same AF_XDP queues (the second fails to bind, EBUSY) while the
//     first becomes undialable — including by the #1993 boot armed-probe, which
//     resolves forwarding state through exactly this path. Fail closed instead:
//     a live owner is reported, never evicted.
//  4. A NON-ignored os.Remove. A removal that fails (EACCES, EROFS, an
//     immutable parent) must fail bring-up rather than let the caller proceed
//     into a bind that will fail more confusingly. ErrNotExist is tolerated
//     because a concurrent cleanup racing us to the same unlink reached the
//     intended end state.
//
// Reading /proc/net/unix is deliberately non-invasive: DIALING as a liveness
// probe would, on the event socket, make the daemon accept the probe as its new
// helper and disconnect the real one. An unreadable table is inconclusive and
// fails closed — it is never treated as "not active".
//
// The caller is responsible for whatever ownership serialization its socket
// needs (EventStream.Start holds a sidecar flock across this call). The control
// socket has no such lock because xpfd does not bind it — the Rust helper does,
// and it does not participate in the flock protocol.
//
// KNOWN RESIDUAL (#7139): checks 1-3 judge a path STRING, and check 4 unlinks
// that same string in a separate syscall. A live socket reached through a
// different spelling of the same file — most plausibly a symlinked parent
// directory — is not matched in /proc/net/unix and so reads as stale, and the
// target or its parent can be swapped between the check and the unlink. Closing
// either needs the trusted-directory rework (openat2 with RESOLVE_BENEATH, or
// an inode-keyed liveness decision) tracked in #7139, not a further string
// test here.
func removeStaleUnixSocket(kind, path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s %s: %w", kind, path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to unlink %s %s: existing path is a %s, not a Unix socket",
			kind, path, describeFileMode(info.Mode()))
	}

	active, err := unixSocketPathActive(path)
	if err != nil {
		return err
	}
	if active {
		return fmt.Errorf("refusing to unlink %s %s: it already has a live listener", kind, path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale %s %s: %w", kind, path, err)
	}
	return nil
}

// unixSocketPathActive reports whether the kernel Unix socket table lists a
// socket bound to path — i.e. some process is still holding it. A table that
// cannot be read returns an error and never a bare false, so an inconclusive
// read fails closed at the caller.
func unixSocketPathActive(path string) (bool, error) {
	data, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		return false, fmt.Errorf("inspect kernel Unix socket table for %s: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		// Columns are fixed through Flags/Type/St/Inode; the path is the
		// 8th field onward, rejoined because a bound path may contain
		// spaces.
		if len(fields) >= 8 && strings.Join(fields[7:], " ") == path {
			return true, nil
		}
	}
	return false, nil
}

// describeFileMode names the file type an operator sees at a refused path, so
// the error says what is actually there rather than only what it is not. It
// mirrors the helper-side wording in userspace-dp/src/server/lifecycle.rs
// (describe_file_type).
func describeFileMode(mode os.FileMode) string {
	switch {
	case mode&os.ModeSymlink != 0:
		return "symlink"
	case mode&os.ModeDir != 0:
		return "directory"
	case mode&os.ModeNamedPipe != 0:
		return "FIFO"
	case mode&os.ModeDevice != 0 && mode&os.ModeCharDevice != 0:
		return "character device"
	case mode&os.ModeDevice != 0:
		return "block device"
	case mode&os.ModeType == 0:
		return "regular file"
	default:
		return "non-socket file"
	}
}
