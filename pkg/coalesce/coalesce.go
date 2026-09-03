// Package coalesce provides a debounced, throttled, dirty-bit actuation loop.
//
// WHY THIS EXISTS AS ITS OWN PACKAGE (#7437). The discipline below was written
// once, in pkg/ipmon, and is the in-tree precedent for "a burst of events must
// collapse into a bounded number of expensive actuations". The #7437 kernel
// route listener needs exactly it: every publish is a FULL snapshot replace
// over a control socket whose deadline scales with payload size, and
// CLAUDE.md's control-socket rule is explicit that a new caller above 1/s
// starves session installs during bulk sync. A per-event push under BGP churn
// is a control-plane brownout, not a latency tail.
//
// It is NOT extracted FROM ipmon here, deliberately. ipmon's Engine entangles
// the same loop with policy state, next-hop resolution and `publishEnabled` —
// the HA-standby publication gate. Refactoring an HA-gated engine inside a
// feature PR would put any regression on the cluster rather than in review, and
// attribute it to the route listener.
//
// So this is written as the type ipmon WOULD adopt, and its adoption is
// tracked. Until then two implementations of one discipline exist, which is a
// real cost and is why the follow-up is filed rather than assumed: untracked
// duplication is how a time-boxed copy becomes a permanent one.
//
// ADOPTION IS TRACKED AS #8354. Until it lands, pkg/ipmon's run loop holds
// the other implementation of this same discipline — if you edit one, the
// other is the copy that will not follow.
package coalesce

import (
	"context"
	"sync"
	"time"
)

// DefaultDebounce and DefaultThrottle mirror pkg/ipmon's values, which are the
// in-tree precedent rather than an independent choice: a burst settles for
// Debounce before it actuates, and two actuations are never closer than
// Throttle.
const (
	DefaultDebounce       = 1 * time.Second
	DefaultThrottle       = 3 * time.Second
	DefaultActuateTimeout = 30 * time.Second
)

// Loop coalesces Mark() calls into bounded actuations.
//
// The actuator returns whether it CONVERGED. A false return keeps the state
// dirty and the loop retries on the next throttle-paced sweep — it does not
// hot-loop, because lastActuation advances when the attempt starts, not when
// it succeeds.
type Loop struct {
	mu            sync.Mutex
	dirtySince    time.Time // zero = clean
	dirtyGen      uint64
	lastActuation time.Time

	debounce       time.Duration
	throttle       time.Duration
	actuateTimeout time.Duration
	now            func() time.Time

	actuate func(context.Context) bool

	kick     chan struct{}
	stop     chan struct{}
	done     chan struct{}
	started  bool
	stopped  bool
	actuated uint64 // observability + tests
}

// New returns a Loop that calls actuate when a marked change has settled.
func New(actuate func(context.Context) bool) *Loop {
	return &Loop{
		debounce:       DefaultDebounce,
		throttle:       DefaultThrottle,
		actuateTimeout: DefaultActuateTimeout,
		now:            time.Now,
		actuate:        actuate,
		kick:           make(chan struct{}, 1),
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
	}
}

// SetTimings overrides the debounce/throttle. Intended for tests and for a
// caller whose actuation cost differs materially from a snapshot publish.
func (l *Loop) SetTimings(debounce, throttle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debounce, l.throttle = debounce, throttle
}

// SetClock injects a clock. Tests use it so a rate assertion is DETERMINISTIC
// rather than a race against wall time — a coalescing bound asserted with
// sleeps is the flaky-guard shape this repo keeps finding.
func (l *Loop) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
}

// Mark records that something changed.
//
// dirtyGen increments on EVERY mark, including while already dirty. The run
// loop snapshots it before actuating and clears the dirty bit only when it is
// unchanged afterwards, so a change landing DURING an actuation is not lost —
// it keeps the state dirty for the next sweep instead of being swallowed by
// the actuation that did not see it.
func (l *Loop) Mark() {
	l.mu.Lock()
	if l.dirtySince.IsZero() {
		l.dirtySince = l.now()
	}
	l.dirtyGen++
	l.mu.Unlock()
	select {
	case l.kick <- struct{}{}:
	default:
	}
}

// Actuations reports how many times the actuator has been invoked.
func (l *Loop) Actuations() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.actuated
}

// Start begins the loop. Idempotent.
func (l *Loop) Start() {
	l.mu.Lock()
	if l.started || l.stopped {
		l.mu.Unlock()
		return
	}
	l.started = true
	l.mu.Unlock()
	go l.run()
}

// Stop halts the loop and waits for it to exit.
func (l *Loop) Stop() {
	l.mu.Lock()
	if l.stopped || !l.started {
		l.stopped = true
		l.mu.Unlock()
		return
	}
	l.stopped = true
	l.mu.Unlock()
	close(l.stop)
	<-l.done
}

// Tick evaluates one sweep without running the loop goroutine. Exported for
// tests driving an injected clock: it is the whole loop body, so a test using
// it exercises the real decision rather than a model of it.
func (l *Loop) Tick(ctx context.Context) {
	l.mu.Lock()
	now := l.now()
	fire := false
	var gen uint64
	if !l.dirtySince.IsZero() &&
		now.Sub(l.dirtySince) >= l.debounce &&
		now.Sub(l.lastActuation) >= l.throttle {
		fire = true
		gen = l.dirtyGen
		// Advance BEFORE the actuation, not after: this is what paces a
		// FAILING actuation's retry to one per throttle window instead of a
		// hot loop.
		l.lastActuation = now
	}
	l.mu.Unlock()
	if !fire {
		return
	}

	ok := true
	if l.actuate != nil {
		actCtx := ctx
		var cancel context.CancelFunc
		if l.actuateTimeout > 0 {
			actCtx, cancel = context.WithTimeout(ctx, l.actuateTimeout)
		}
		ok = l.actuate(actCtx)
		if cancel != nil {
			cancel()
		}
	}

	l.mu.Lock()
	l.actuated++
	// Clear only when the actuation converged AND nothing was marked while it
	// ran. Either condition failing leaves the state dirty for the next sweep.
	if ok && l.dirtyGen == gen {
		l.dirtySince = time.Time{}
	}
	l.mu.Unlock()
}

func (l *Loop) run() {
	defer close(l.done)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A short sweep interval relative to the debounce: the loop is cheap when
	// clean, and the bound that matters is the throttle, not the poll.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-l.kick:
		case <-ticker.C:
		}
		l.Tick(ctx)
	}
}
