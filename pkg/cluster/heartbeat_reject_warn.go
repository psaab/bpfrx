package cluster

import (
	"sync"
	"time"
)

// heartbeatRejectWarnNowNanos is the injectable clock for the rejection-warn
// rate limiter. Same seam idiom as epochNowNanos, and for the same reason: the
// interval is the thing under test, so a test must be able to step across it
// without sleeping. Production never replaces it.
var heartbeatRejectWarnNowNanos = MonotonicNanos

// heartbeatRejectWarnInterval bounds how often the per-frame rejection warning
// reaches the log. It matches the 30s used by NoteEpochDowngradeHeartbeat so
// the two lines that describe the SAME event cannot disagree about their rate.
const heartbeatRejectWarnInterval = 30 * time.Second

// heartbeatRejectWarnLimiter rate-limits the generic "heartbeat auth rejected"
// warning.
//
// #6669 r18 (Codex finding 8): NoteEpochDowngradeHeartbeat was rate-limited to
// one line per 30s, but admitFrame then emitted an UNCONDITIONAL slog.Warn for
// every rejected frame immediately afterwards. A peer sending 10 valid-MAC
// epochless heartbeats per second therefore produced ~10 warnings per second
// while the README claimed "the rejection logs a rate-limited, actionable
// warning". Rate-limiting only the actionable line bounded the line an operator
// most needs to see and left the noisy one unbounded — exactly backwards.
//
// Suppressed occurrences are COUNTED and reported with the next emission, so
// bounding the volume does not hide the volume: an operator sees both that the
// rejection is ongoing and how fast.
//
// It lives on heartbeatAuthState (Manager lifetime) rather than on the
// receiver, for the same reason the epoch counters do: a receiver-scoped
// limiter is reset by every StartHeartbeat — including a routine DHCP-triggered
// VRF rebind — which would restore the flood one burst per restart.
type heartbeatRejectWarnLimiter struct {
	mu         sync.Mutex
	lastNanos  int64
	started    bool
	suppressed uint64
}

// admit reports whether a warning should be emitted now and, when it should,
// how many were suppressed since the previous emission.
func (l *heartbeatRejectWarnLimiter) admit() (emit bool, suppressed uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := heartbeatRejectWarnNowNanos()
	if l.started && now-l.lastNanos < int64(heartbeatRejectWarnInterval) {
		l.suppressed++
		return false, 0
	}
	l.started = true
	l.lastNanos = now
	suppressed, l.suppressed = l.suppressed, 0
	return true, suppressed
}
