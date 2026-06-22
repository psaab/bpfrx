package logging

import (
	"runtime"
	"strconv"
)

// goID returns the current goroutine's ID, parsed from the runtime stack
// header ("goroutine <id> [running]:\n..."). It is used ONLY for the
// SyslogSlogHandler re-entrancy guard (#2287), which must distinguish a
// SAME-goroutine nested Handle (the deadlock path: Handle → Send → slog.Warn →
// Handle) from a concurrent Handle on a DIFFERENT goroutine (which must NOT be
// skipped). A per-handler atomic flag cannot make that distinction and would
// silently drop legitimate forwarding under concurrent logging.
//
// This runs on the slog path (Handle) once per forwarded record, but ONLY when
// at least one syslog client is configured: SyslogSlogHandler.Handle returns
// before calling goID on the common no-client path (#2295). It never runs
// per-packet or per-session, so the runtime.Stack cost is acceptable. The
// buffer is small because only the header line is needed.
func goID() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	// Format: "goroutine 123 [running]:\n..."
	const prefix = "goroutine "
	s := buf[:n]
	if len(s) < len(prefix) {
		return 0
	}
	s = s[len(prefix):]
	// The ID is the digits up to the first space.
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	id, err := strconv.ParseUint(string(s[:i]), 10, 64)
	if err != nil {
		return 0
	}
	return id
}
