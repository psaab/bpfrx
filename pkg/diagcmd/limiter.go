package diagcmd

import (
	"errors"
	"sync"
)

// MaxConcurrentDiagnostics bounds how many host-level ping/traceroute
// diagnostics may run at once across EVERY control surface that exposes
// them (the REST API and the gRPC API share the single DefaultLimiter
// below). Each in-flight diagnostic holds a child process, its output
// pipes, a handler goroutine and — on gRPC — a stream, for up to the
// 150s diagExecCeiling. Without an aggregate bound a burst of concurrent
// diagnostic requests can pin hundreds/thousands of PIDs/FDs/goroutines
// and starve the control plane that drives the dataplane (#5057).
//
// The value is deliberately small: legitimate operator/automation use
// runs a handful of diagnostics at once, while a firewall must never let
// a diagnostic flood exhaust host resources. A per-job deadline (present
// via pingExecTimeout/diagTracerouteTimeout in the API packages) plus
// this aggregate concurrency bound together cap the worst-case resource
// footprint.
const MaxConcurrentDiagnostics = 4

// ErrBusy is returned by Limiter.Acquire when the concurrency cap is
// already reached. Callers map it to their surface's overload signal:
// HTTP 429 (REST) / codes.ResourceExhausted (gRPC).
var ErrBusy = errors.New("diagnostic concurrency limit reached")

// Limiter is a fixed-capacity counting semaphore bounding concurrent
// diagnostic executions. Acquire is fail-fast (non-blocking): excess
// callers are rejected immediately rather than queued, so a request
// flood cannot build an unbounded backlog of waiters. The zero value is
// unusable; construct with NewLimiter.
type Limiter struct {
	sem chan struct{}
}

// NewLimiter returns a Limiter admitting at most n concurrent holders.
// n < 1 is clamped to 1 so a misconfiguration cannot disable the bound.
func NewLimiter(n int) *Limiter {
	if n < 1 {
		n = 1
	}
	return &Limiter{sem: make(chan struct{}, n)}
}

// Acquire takes one slot without blocking. On success it returns a
// release function and a nil error; the caller MUST defer release so the
// slot is returned on every exit path (success, error, timeout, context
// cancel, panic). When the cap is already reached it returns ErrBusy and
// a nil release — do NOT call release in that case.
//
// The returned release is idempotent via sync.Once: an accidental double
// defer cannot over-release and free another caller's slot (which would
// re-open the very DoS window this limiter closes).
func (l *Limiter) Acquire() (release func(), err error) {
	select {
	case l.sem <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-l.sem }) }, nil
	default:
		return nil, ErrBusy
	}
}

// InFlight reports the number of slots currently held. Intended for
// tests and future metrics; it is a point-in-time read.
func (l *Limiter) InFlight() int { return len(l.sem) }

// Cap reports the maximum number of concurrent holders.
func (l *Limiter) Cap() int { return cap(l.sem) }

// DefaultLimiter is the process-wide diagnostic limiter shared by the
// REST and gRPC ping/traceroute handlers, so one aggregate cap covers
// both surfaces (a diagnostic admitted over REST and one admitted over
// gRPC draw from the same MaxConcurrentDiagnostics budget).
var DefaultLimiter = NewLimiter(MaxConcurrentDiagnostics)

// MaxConcurrentSessionWalks bounds how many full session-table walks may run
// at once across EVERY control surface that exposes them — the REST session
// list/summary/zone-pair endpoints and the REST session-clear fallback, plus
// the gRPC GetSessions/GetSessionSummary/GetZonePairSummary RPCs, the ShowText
// "sessions-top:*" scan, the gRPC ClearSessions clear (both the clear-all
// and filtered full-table walks, #5779), and the count-only SessionCount()
// walk reachable via the gRPC GetStatus RPC + the ShowText
// "buffers"/"buffers-detail" (`show system buffers[-detail]`) surfaces (#5782)
// AND the REST /api/v1/status handler (#5939) — share the single
// SessionWalkLimiter below (#5708). SessionCount is count-only (no per-entry
// alloc/enrich) but its KERNEL iteration + per-bucket lock cost is the same
// O(table) contention, so it draws from the same budget.
// Each walk holds
// per-bucket BPF-map locks across the whole v4+v6 conntrack table while
// contending with the live dataplane session-sync path, so an unbounded scan
// flood on ANY surface multiplies that contention. Before #5708 only the REST
// endpoints were gated; a gRPC caller could issue unbounded full-table scans
// through the uncovered gRPC surface (codex-review-182 M35). The value mirrors
// the original REST cap (#5318/#5433).
const MaxConcurrentSessionWalks = 4

// SessionWalkLimiter is the process-wide session-scan limiter shared by the
// REST and gRPC session list/summary handlers, so one aggregate cap covers
// both surfaces: a session scan admitted over REST and one admitted over gRPC
// draw from the same MaxConcurrentSessionWalks budget, and a mix of REST+gRPC
// scrapers cannot collectively exceed it. Mirrors DefaultLimiter.
var SessionWalkLimiter = NewLimiter(MaxConcurrentSessionWalks)
