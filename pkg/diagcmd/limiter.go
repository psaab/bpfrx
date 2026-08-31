package diagcmd

import (
	"context"
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

// leaseKey is the private, per-Limiter context key for an in-process admission
// lease (#5880). Keyed by the *Limiter identity so a lease taken on one limiter
// is never mistaken for another's, and UNFORGEABLE from outside the process: the
// type is unexported and context values cannot be constructed from any external
// input (HTTP header / gRPC metadata / request body), so only AcquireCtx below
// can stamp it.
type leaseKey struct{ l *Limiter }

// AcquireCtx is the request-graph-aware form of Acquire (#5880). It admits ONE
// logical scan per in-process request graph instead of once per handler, closing
// the reentrant double-acquire where an outer handler (e.g. a REST list) holds a
// slot and then delegates in-process to another handler (the gRPC session
// service) that acquired the SAME limiter again — self-rejecting its own fan-out
// at capacity.
//
//   - If ctx already carries THIS limiter's in-process admission lease (an
//     ancestor handler in this process already acquired a slot and propagated
//     the returned context), AcquireCtx returns a NO-OP release and ctx unchanged
//     WITHOUT taking a second slot — the nested work reuses the ancestor's
//     admission.
//   - Otherwise it takes a slot exactly like Acquire (fail-fast, ErrBusy over
//     cap) and returns a real release PLUS a child context stamped with the
//     lease. The caller MUST propagate that context to any in-process delegation
//     so the delegate reuses this slot instead of re-acquiring.
//
// The lease is per-REQUEST-GRAPH, NOT global: two DISTINCT external requests each
// begin with an unstamped context and each acquire independently, so the global
// per-node bound is preserved — only NESTED in-process delegation within ONE
// request skips. The lease does NOT cross a process/network boundary (context
// values are process-local and never serialized onto the wire), so a peer node's
// own gRPC entry point sees no lease and acquires its own local slot — remote
// admission is unchanged.
//
// The returned release is idempotent and cancellation-safe on BOTH paths: a real
// slot rides Acquire's sync.Once, and the lease-reuse path is a bare no-op, so a
// deferred release can never over-release another caller's slot.
func (l *Limiter) AcquireCtx(ctx context.Context) (release func(), out context.Context, err error) {
	if ctx.Value(leaseKey{l}) != nil {
		return func() {}, ctx, nil
	}
	rel, err := l.Acquire()
	if err != nil {
		return nil, ctx, err
	}
	return rel, context.WithValue(ctx, leaseKey{l}, struct{}{}), nil
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

// MaxConcurrentSnapshotReads bounds control-surface reads that copy an
// IN-PROCESS structure rather than walking the conntrack table.
//
// #8151: `show security nat persistent-nat` was charged against
// MaxConcurrentSessionWalks, and it does not walk. `natshow.RenderPersistent`'s
// only dataplane read is `PersistentNATTable.All()` — an O(bindings) snapshot
// copy of a Go map under that table's own RWMutex (#4811). It touches no
// conntrack bucket, holds no session-store lock, and contends with nothing on
// the shared control socket. #6553 introduced the gate describing the topic as
// one of four that "drive full v4+v6 conntrack walks"; that description was
// wrong, and its own line cites point into `RenderPersistentDetail`, a
// different function.
//
// Charging it to the session budget is not merely inaccurate, it is
// exploitable: MaxConcurrentSessionWalks is 4, REST and gRPC alias ONE
// limiter, and `ShowText` is on `fabricAllowedUnaryMethods` — so a cluster peer
// polling `persistent-nat` could hold all four slots and make genuine session
// scans (`GET /api/v1/sessions`, `GetSessions`, `GetStatus`'s SessionCount)
// start refusing.
//
// The bound is KEPT rather than dropped. An O(bindings) allocation on a
// fabric-reachable surface is still worth bounding, and removing a bound from
// a peer-reachable surface is a security-shaped decision that should not be a
// side effect of correcting which budget it draws from. What changes is that
// it no longer competes with full-table scans.
//
// Sized independently of MaxConcurrentSessionWalks on purpose: the two bound
// different costs (a map copy versus per-bucket BPF-map locks held across the
// whole v4+v6 table), so tying them would make one a hostage to the other's
// tuning.
const MaxConcurrentSnapshotReads = 4

// SnapshotReadLimiter is the process-wide limiter for the snapshot-copy reads
// described above. Separate instance, separate budget: saturating it must not
// refuse a session scan, and saturating SessionWalkLimiter must not refuse a
// snapshot read.
var SnapshotReadLimiter = NewLimiter(MaxConcurrentSnapshotReads)
