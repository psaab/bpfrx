// Package eventengine implements Junos-style event-options policy execution.
// It watches RPM probe events and applies configuration changes when policies match.
//
// Robustness contract (#2139/#2140/#2141/#2157):
//
//   - #2139 transactional batch: a change-configuration action either commits
//     in full or applies nothing. ThenCommands are pre-classified into a typed
//     plan BEFORE the candidate is touched, applied to the candidate,
//     validated with CommitCheck, then committed; ANY failure discards the
//     candidate (ExitConfigure) — never a half-applied config.
//   - #2140 cooldown survives reload: per-policy runtime state (sliding
//     windows + last-trigger) is reconciled (not recreated) on every Apply,
//     carried forward when (policy name, semantic revision) is unchanged.
//     The cooldown is armed on a SUCCESSFUL commit, not at evaluate time, so a
//     dropped/queued action does not consume the cooldown.
//   - #2141 fail-closed matcher: a malformed/unknown attributes-match line is
//     rejected at commit (config.ValidateEventAttributesMatchStrict); on the
//     legacy lenient-load path the runtime matcher fails CLOSED (the policy
//     does not fire) rather than dropping the constraint and over-firing.
//   - #3751 fail-closed temporal gate: a `within <seconds> { trigger
//     (on|until) <count>; }` numeric typo is rejected at commit
//     (config.validateEventOptionsWithinAST); on the legacy lenient-load path
//     a within clause with no usable positive threshold (a leftover 0 from an
//     older binary that silently coerced the typo) fails CLOSED in
//     withinMatches (the policy does not fire) rather than treating the 0 as
//     an unconditional match and always-firing the remediation.
//   - #2157 fail-safe queue: actions run on a single serialized worker
//     goroutine (removing the cross-probe EnterConfigure race) with bounded
//     backoff retry on a held config lock (configstore.ErrConfigLocked) and
//     drop/retry/commit counters, instead of silently dropping on lock-held.
//   - #3750 revalidate-before-commit: a pre-classified action carries the
//     policy's semantic revision AS OF EVALUATE TIME. Immediately before it
//     commits — under e.mu and while holding the config lock (EnterConfigure),
//     so no operator commit can interleave — the worker revalidates it against
//     live engine state and DROPS it (counted dropped_stale) if the policy was
//     removed, was redefined (semRev mismatch), or is now inside its cooldown.
//     This folds three fail-opens into one gate: a removed policy's stale batch,
//     a same-name redefine's OLD command set, and a queued duplicate that raced
//     the arm-on-commit cooldown all stop firing instead of mutating config no
//     active policy authorizes.
package eventengine

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/rpm"
)

// CommitFn atomically promotes the candidate to active and applies
// it to the dataplane. The daemon's commitAndApply implementation
// holds the apply semaphore across both steps so the engine's
// commit can't interleave with another caller's commit/apply pair.
type CommitFn func(ctx context.Context, comment string) (*config.Config, error)

// Minimum time between successive triggers of the same policy.
const policyCooldown = 30 * time.Second

// actionQueueDepth bounds the worker's pending-action channel. Dedup-by-policy
// (a newer trigger supersedes an older queued one) keeps at most one pending
// action per policy, so this is also an upper bound on distinct policies with
// a remediation in flight while the config lock is held.
const actionQueueDepth = 64

// Backoff schedule for a held config lock (#2157). The worker retries an
// action whose EnterConfigure fails with ErrConfigLocked until the deadline,
// then drops it (counted). A non-lock error is permanent (no retry).
const (
	lockRetryInitial  = 200 * time.Millisecond
	lockRetryMax      = 5 * time.Second
	lockRetryDeadline = 60 * time.Second
)

// Stats is the observable counter snapshot surfaced to pkg/api (#2157). All
// fields are cumulative since daemon start except QueueDepth, which is the
// instantaneous number of queued-but-not-yet-applied actions.
type Stats struct {
	Committed         uint64 // actions whose batch committed successfully
	Rejected          uint64 // actions rejected (bad plan / CommitCheck / apply error)
	Retried           uint64 // retry attempts after a held config lock
	DroppedQueueFull  uint64 // actions superseded/evicted because the queue was full
	DroppedLockHeld   uint64 // actions dropped after the lock-retry deadline elapsed
	DroppedStale      uint64 // actions dropped at commit: policy removed/redefined or cooldown active (#3750)
	AttributesInvalid uint64 // runtime fail-closed: malformed/unknown attributes-match line
	QueueDepth        int64  // currently queued actions
}

// engineCounters holds the atomic counters behind Stats.
type engineCounters struct {
	committed         atomic.Uint64
	rejected          atomic.Uint64
	retried           atomic.Uint64
	droppedQueueFull  atomic.Uint64
	droppedLockHeld   atomic.Uint64
	droppedStale      atomic.Uint64
	attributesInvalid atomic.Uint64
	queueDepth        atomic.Int64
}

// plannedOp is one classified ThenCommand: a candidate set or delete.
type plannedOp struct {
	isDelete bool
	// raw "set" input (without the leading "set ") for store.SetFromInput.
	setInput string
	// parsed delete path for store.Delete.
	delPath []string
	raw     string // original command text, for logging
}

// plannedAction is a fully pre-classified remediation enqueued for the worker.
// It carries no engine lock and no live runtime state — only the policy
// identity (name + the semantic revision observed AT EVALUATE TIME) and the
// typed plan. The worker applies the plan without re-reading it, but it DOES
// revalidate the identity against live engine state immediately before commit
// (#3750): a queued action for a policy that was removed, redefined, or is now
// in its cooldown must NOT commit — it is dropped as stale. Before #3750 the
// worker committed the batch unconditionally, so a removed/redefined policy's
// stale command set still mutated config, and a cooldown-window duplicate
// double-committed.
type plannedAction struct {
	policyName string
	// semRev is the policy's semantic revision (policySemanticRevision) as of
	// the evaluate that enqueued this action. The worker drops the action if the
	// live revision no longer matches (policy redefined) or is absent (removed).
	semRev string
	ops    []plannedOp
}

// triggeredPolicy pairs a policy that should fire with the semantic revision its
// runtime carried at evaluate time (#3750). evaluateEvent returns these so
// HandleEvent can stamp each enqueued action with the revision the worker
// revalidates against before committing.
type triggeredPolicy struct {
	pol    *config.EventPolicy
	semRev string
}

// policyRuntime is the per-policy temporal/cooldown state. It is split from the
// immutable EventPolicy config so it can be carried forward across an Apply
// (reconcile-not-recreate, #2140) keyed by (name, semantic revision).
type policyRuntime struct {
	// event name -> sliding window of trigger timestamps.
	windows map[string][]time.Time
	// last successful-commit time for this policy (cooldown anchor). Zero
	// means "never triggered". Armed by the worker after a successful commit,
	// not at evaluate time (#2157 SMR finding 3).
	lastTrigger time.Time
}

func newPolicyRuntime() *policyRuntime {
	return &policyRuntime{windows: make(map[string][]time.Time)}
}

// Engine evaluates event-options policies against RPM events.
type Engine struct {
	mu       sync.Mutex
	policies []*config.EventPolicy
	store    *configstore.Store
	commitFn CommitFn

	// runtime holds per-policy temporal/cooldown state keyed by policy NAME.
	// Reconciled (carried forward) on Apply when the policy semantic revision
	// is unchanged (#2140).
	runtime map[string]*policyRuntime
	// semRev records the semantic revision each policy's runtime was built
	// for, so Apply can decide carry-forward vs reset.
	semRev map[string]string

	// Compiled attributes-match regexes, keyed by the raw pattern string.
	// Built once at Apply() time so the hot HandleEvent path never compiles
	// a regex per event. Patterns are validated at COMMIT by
	// config.ValidateEventAttributesMatchStrict, so a bad pattern normally
	// never reaches here; the one exception is the tolerant LOAD path which
	// downgrades an invalid persisted pattern to a warning.
	regexCache map[string]*regexp.Regexp

	counters engineCounters

	// Action queue + single worker (#2157). actions is bounded; the worker is
	// the ONLY goroutine that enters configure mode on the engine's behalf, so
	// the cross-probe EnterConfigure race cannot occur.
	actions   chan plannedAction
	workerWG  sync.WaitGroup
	stopOnce  sync.Once
	stopCh    chan struct{}
	startOnce sync.Once

	// lifeCtx is the engine-lifetime context threaded into the remediation
	// commit (#2868). It is cancelled by Close() at the same time stopCh is
	// closed, so a remediation commit in flight at daemon shutdown (which
	// drives netlink updates, an FRR reload, and Rust dataplane sync — seconds
	// of work) is cancelled cleanly instead of blocking termination past the
	// systemd TimeoutStopSec SIGKILL. lifeCancel is its cancel func.
	lifeCtx    context.Context
	lifeCancel context.CancelFunc

	// throttle for the runtime fail-closed warning so a flapping probe with a
	// legacy malformed line cannot flood the log.
	lastInvalidWarn atomic.Int64

	// Injectable clock for tests; nil means time.Now.
	nowFn func() time.Time

	// Injectable retry-backoff timer for tests; nil means newRetryTimer
	// (backed by time.NewTimer). Returns the fire channel plus a stop func
	// that releases the underlying timer when the retry is cancelled before
	// the backoff elapses (#2890 — a plain time.After cannot be stopped, so
	// its runtime timer leaks until it fires). A test can substitute this to
	// assert the stop func is invoked on the stopCh branch.
	newTimerFn func(time.Duration) (<-chan time.Time, func() bool)

	// Lock-retry tuning, overridable in tests. Zero means the package
	// defaults (lockRetryInitial/Max/Deadline).
	retryInitial  time.Duration
	retryMax      time.Duration
	retryDeadline time.Duration
}

func (e *Engine) lockRetryInitial() time.Duration {
	if e.retryInitial > 0 {
		return e.retryInitial
	}
	return lockRetryInitial
}

func (e *Engine) lockRetryMax() time.Duration {
	if e.retryMax > 0 {
		return e.retryMax
	}
	return lockRetryMax
}

func (e *Engine) lockRetryDeadline() time.Duration {
	if e.retryDeadline > 0 {
		return e.retryDeadline
	}
	return lockRetryDeadline
}

// New creates an event engine. commitFn is the daemon's atomic
// commit+apply callback (see #846); when non-nil, the engine routes
// its committed configs through it so they serialize with HTTP/gRPC
// commits. When nil (tests), commits succeed but no apply runs.
//
// The action worker is started lazily on the first HandleEvent so a
// matcher-only test (New(nil, nil) + attributesMatch) never spawns a
// goroutine. Call Close() from the daemon shutdown path to stop it.
func New(store *configstore.Store, commitFn CommitFn) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{
		store:      store,
		commitFn:   commitFn,
		runtime:    make(map[string]*policyRuntime),
		semRev:     make(map[string]string),
		regexCache: make(map[string]*regexp.Regexp),
		actions:    make(chan plannedAction, actionQueueDepth),
		stopCh:     make(chan struct{}),
		lifeCtx:    ctx,
		lifeCancel: cancel,
	}
}

func (e *Engine) now() time.Time {
	if e.nowFn != nil {
		return e.nowFn()
	}
	return time.Now()
}

// newRetryTimer returns the backoff fire channel plus a stop func for the
// runAction retry select (#2890). Using an explicit time.NewTimer (rather than
// time.After) lets the retry release the runtime timer immediately when stopCh
// fires before the backoff elapses, instead of leaking an armed timer until it
// fires on shutdown/restart churn. The stop func reports whether it stopped the
// timer before it fired (so a caller may drain a fired-but-unread channel),
// mirroring time.Timer.Stop. Overridable in tests via newTimerFn.
func (e *Engine) newRetryTimer(d time.Duration) (<-chan time.Time, func() bool) {
	if e.newTimerFn != nil {
		return e.newTimerFn(d)
	}
	t := time.NewTimer(d)
	return t.C, t.Stop
}

// Apply loads new event-options policies, RECONCILING per-policy runtime state
// rather than recreating it (#2140): cooldown/window memory is carried forward
// for any policy whose (name, semantic revision) is unchanged, and dropped for
// removed or semantically-changed policies. This is the proven pkg/ipmon
// pattern. It also fixes the self-wipe: the engine's own remediation commit
// re-enters Apply with the SAME policy set (same revision) → state survives →
// the cooldown holds.
//
// Rebuilds the compiled-regex cache for every attributes-match pattern so the
// event hot path (HandleEvent) never compiles a regex per event; the cache is
// derived purely from config (not runtime state) so rebuilding it is cheap and
// correct.
func (e *Engine) Apply(policies []*config.EventPolicy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies = policies

	nextRuntime := make(map[string]*policyRuntime, len(policies))
	nextRev := make(map[string]string, len(policies))
	for _, pol := range policies {
		if pol == nil {
			continue
		}
		rev := policySemanticRevision(pol)
		if prev, ok := e.runtime[pol.Name]; ok && e.semRev[pol.Name] == rev {
			// Same policy, unchanged semantics: carry forward live state.
			nextRuntime[pol.Name] = prev
		} else {
			// New, removed-and-readded, or redefined policy: re-arm.
			nextRuntime[pol.Name] = newPolicyRuntime()
		}
		nextRev[pol.Name] = rev
	}
	e.runtime = nextRuntime
	e.semRev = nextRev

	e.regexCache = make(map[string]*regexp.Regexp)
	for _, pol := range policies {
		if pol == nil {
			continue
		}
		for _, attr := range pol.AttributesMatch {
			pattern, ok := config.EventAttributesMatchPattern(attr)
			if !ok {
				continue
			}
			if _, cached := e.regexCache[pattern]; cached {
				continue
			}
			// Patterns are validated at commit; a compile failure here
			// should not happen. Log and skip so a single bad pattern
			// can never wedge the engine.
			re, err := regexp.Compile(pattern)
			if err != nil {
				slog.Warn("event-options: skipping uncompilable attributes-match pattern",
					"policy", pol.Name, "pattern", pattern, "err", err)
				continue
			}
			e.regexCache[pattern] = re
		}
	}
}

// policySemanticRevision is a cheap deterministic hash of the match/action
// fields that define a policy's behavior (#2140). If it is unchanged across an
// Apply, the policy is "the same policy" and its cooldown/window memory is
// preserved; if any of these change, the policy is treated as redefined and
// re-arms. Fields included: Events, AttributesMatch (sorted — order does not
// change semantics), WithinClauses, ThenCommands. The policy NAME is the map
// key and is therefore not hashed.
func policySemanticRevision(pol *config.EventPolicy) string {
	h := sha256.New()
	writeField := func(s string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	writeField("events")
	for _, ev := range pol.Events {
		writeField(ev)
	}
	writeField("attrs")
	attrs := append([]string(nil), pol.AttributesMatch...)
	sort.Strings(attrs)
	for _, a := range attrs {
		writeField(a)
	}
	writeField("within")
	for _, wc := range pol.WithinClauses {
		if wc == nil {
			writeField("nil")
			continue
		}
		writeField(strconv.Itoa(wc.Seconds) + "/" +
			strconv.Itoa(wc.TriggerOn) + "/" +
			strconv.Itoa(wc.TriggerUntil))
	}
	writeField("then")
	for _, cmd := range pol.ThenCommands {
		writeField(cmd)
	}
	sum := h.Sum(nil)
	return string(sum)
}

// HandleEvent is the callback for RPM events. It evaluates policies under lock,
// pre-classifies the ThenCommands of every triggered policy into a typed plan
// (rejecting a malformed plan BEFORE it can occupy a queue slot), and enqueues
// the validated actions onto the single worker (#2139/#2157). The actual
// configure/commit happens off this caller goroutine on the worker, so many
// probe goroutines may call HandleEvent concurrently without racing on the
// config lock.
func (e *Engine) HandleEvent(ev rpm.Event) {
	e.startOnce.Do(e.startWorker)
	triggered := e.evaluateEvent(ev)
	for _, tp := range triggered {
		ops, ok := e.classifyPlan(tp.pol)
		if !ok {
			// Malformed/unknown command: reject the whole batch before it can
			// take a queue slot or a lock (#2139 pre-classify).
			e.counters.rejected.Add(1)
			continue
		}
		if len(ops) == 0 {
			continue // nothing to do
		}
		// Stamp the action with the policy's semantic revision as of this
		// evaluate (#3750) so the worker can revalidate it against live engine
		// state before committing.
		e.enqueue(plannedAction{policyName: tp.pol.Name, semRev: tp.semRev, ops: ops})
	}
}

// startWorker launches the single action worker. Idempotent via startOnce.
func (e *Engine) startWorker() {
	e.workerWG.Add(1)
	go e.actionWorker()
}

// Close stops the action worker and drains in-flight retries. Safe to call
// even if the worker was never started. Called from the daemon shutdown path.
func (e *Engine) Close() {
	e.stopOnce.Do(func() {
		close(e.stopCh)
		// Cancel the lifetime context so a remediation commit in flight
		// (commitFn) aborts cleanly on shutdown (#2868).
		if e.lifeCancel != nil {
			e.lifeCancel()
		}
	})
	e.workerWG.Wait()
}

// Stats returns a snapshot of the observable counters (#2157), surfaced to
// pkg/api for the xpf_event_actions_* metric family.
func (e *Engine) Stats() Stats {
	return Stats{
		Committed:         e.counters.committed.Load(),
		Rejected:          e.counters.rejected.Load(),
		Retried:           e.counters.retried.Load(),
		DroppedQueueFull:  e.counters.droppedQueueFull.Load(),
		DroppedLockHeld:   e.counters.droppedLockHeld.Load(),
		DroppedStale:      e.counters.droppedStale.Load(),
		AttributesInvalid: e.counters.attributesInvalid.Load(),
		QueueDepth:        e.counters.queueDepth.Load(),
	}
}

// enqueue adds an action to the bounded worker queue with dedup-by-policy: a
// newer trigger of the same policy supersedes an older queued one (there is no
// value in applying a stale remediation twice), which also bounds the queue to
// one pending action per policy. If the queue is full of OTHER policies'
// actions, the new action is dropped (counted) rather than blocking the caller
// goroutine (#2157 bounded queue).
func (e *Engine) enqueue(a plannedAction) {
	select {
	case e.actions <- a:
		e.counters.queueDepth.Add(1)
	case <-e.stopCh:
		// Shutting down; drop silently.
	default:
		// Queue full. Try to supersede a same-policy action by draining and
		// re-enqueuing, dropping any older same-policy entry. Best-effort,
		// non-blocking.
		if e.supersede(a) {
			return
		}
		e.counters.droppedQueueFull.Add(1)
		slog.Warn("event-options: action queue full, dropping remediation",
			"policy", a.policyName)
	}
}

// supersede non-blockingly rebuilds the queue, replacing any existing
// same-policy action with a, and returns true if a was placed. It drains at
// most the current buffered entries to avoid an unbounded loop under
// concurrent producers.
func (e *Engine) supersede(a plannedAction) bool {
	drained := make([]plannedAction, 0, actionQueueDepth)
	replaced := false
	// Drain whatever is currently buffered.
	for {
		select {
		case old := <-e.actions:
			e.counters.queueDepth.Add(-1)
			if old.policyName == a.policyName {
				// Drop the stale same-policy action; it is superseded.
				e.counters.droppedQueueFull.Add(1)
				continue
			}
			drained = append(drained, old)
		default:
			goto refill
		}
	}
refill:
	// Re-enqueue the surviving other-policy actions in their original FIFO
	// order, then place the new (superseding) action at the TAIL (#2869).
	// Prepending `a` would jump it ahead of every already-queued action of
	// OTHER policies, converting the documented FIFO queue into LIFO for the
	// newest arrival and starving older queued remediations under sustained
	// event frequency. Supersede must only drop/replace the stale SAME-policy
	// entry (done in the drain loop above); it must not reorder unrelated
	// policies relative to the order their events were observed.
	all := append(drained, a)
	for _, item := range all {
		select {
		case e.actions <- item:
			e.counters.queueDepth.Add(1)
			if item.policyName == a.policyName {
				replaced = true
			}
		default:
			// Still no room (lost the race to another producer, or the queue
			// is full of unrelated policies and there was no stale same-policy
			// entry to evict). Count the loss for any SURVIVOR we could not
			// re-place — but NOT for the new action `a` itself: supersede
			// returns false in that case and enqueue owns `a`'s single
			// queue_full count + warn. Counting it here too would
			// double-increment xpf_event_actions_dropped_total (#2869).
			if item.policyName != a.policyName {
				e.counters.droppedQueueFull.Add(1)
			}
		}
	}
	return replaced
}

// actionWorker is the single goroutine that applies remediation actions. It
// serializes all configure/commit on behalf of the engine (removing the
// cross-probe race) and retries a held config lock with bounded backoff.
func (e *Engine) actionWorker() {
	defer e.workerWG.Done()
	for {
		select {
		case <-e.stopCh:
			return
		case a := <-e.actions:
			e.counters.queueDepth.Add(-1)
			e.runAction(a)
		}
	}
}

// runAction applies one pre-classified action transactionally (#2139) with
// bounded lock-held retry (#2157). On a successful commit it arms the policy's
// cooldown (#2140 SMR finding 3 — arm on commit, not at evaluate, so a
// dropped/rejected action never consumes the cooldown).
func (e *Engine) runAction(a plannedAction) {
	deadline := e.now().Add(e.lockRetryDeadline())
	backoff := e.lockRetryInitial()
	maxBackoff := e.lockRetryMax()
	for {
		err := e.applyOnce(e.commitContext(), a)
		if err == nil {
			e.counters.committed.Add(1)
			e.armCooldown(a.policyName)
			slog.Info("event-options: configuration committed",
				"policy", a.policyName, "commands", len(a.ops))
			return
		}
		if errors.Is(err, errStaleAction) {
			// #3750: the policy was removed/redefined, or a sibling commit armed
			// the cooldown, while this action waited (on a held lock or in the
			// queue). Drop it — do NOT commit a batch no active policy authorizes,
			// and do NOT retry (the staleness is terminal for this action).
			e.counters.droppedStale.Add(1)
			slog.Info("event-options: remediation dropped (stale queued action)",
				"policy", a.policyName, "err", err)
			return
		}
		if errors.Is(err, configstore.ErrConfigLocked) {
			if e.now().After(deadline) {
				e.counters.droppedLockHeld.Add(1)
				slog.Warn("event-options: remediation dropped (config lock held past deadline)",
					"policy", a.policyName, "err", err)
				return
			}
			e.counters.retried.Add(1)
			slog.Debug("event-options: config lock held, will retry",
				"policy", a.policyName, "backoff", backoff)
			// Explicit timer (NOT time.After) so the runtime timer is
			// released the instant stopCh fires before the backoff elapses,
			// rather than leaking an armed timer until it fires (#2890). The
			// stop func is only meaningful on the stopCh branch; on the timer
			// branch the timer has already fired and stopping is a no-op.
			timerC, stopTimer := e.newRetryTimer(backoff)
			select {
			case <-e.stopCh:
				stopTimer()
				return
			case <-timerC:
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		// Permanent failure (bad apply / CommitCheck reject / read-only
		// secondary): do not retry.
		e.counters.rejected.Add(1)
		slog.Warn("event-options: remediation rejected",
			"policy", a.policyName, "err", err)
		return
	}
}

// applyOnce is the transactional batch (#2139): enter configure (the candidate
// IS the rollback), apply every planned op, validate the WHOLE candidate with
// CommitCheck, then commit. ANY failure discards the candidate (ExitConfigure)
// — never a half-applied config. Returns ErrConfigLocked unwrapped (caller
// retries) or another error (caller treats as permanent).
// commitContext returns the engine-lifetime context threaded into the
// remediation commit (#2868). An Engine built via New always has lifeCtx set;
// the nil guard covers a zero-value Engine (defensive — no test constructs one)
// so callers never pass a nil context to commitFn.
func (e *Engine) commitContext() context.Context {
	if e.lifeCtx != nil {
		return e.lifeCtx
	}
	return context.Background()
}

func (e *Engine) applyOnce(ctx context.Context, a plannedAction) error {
	if err := e.store.EnterConfigure(); err != nil {
		// Lock-held is the retryable case; bubble it up verbatim so the
		// caller can errors.Is it. Any other EnterConfigure error (read-only
		// secondary) is permanent.
		return err
	}
	// From here, any early return MUST ExitConfigure to discard the candidate.

	// #3750 revalidate-before-commit: now that we hold the config lock, no
	// operator commit — and therefore no Apply() that could remove or redefine
	// the policy — can interleave until we ExitConfigure. Check the action's
	// identity against live engine state and drop it (do NOT mutate the
	// candidate) if the policy was removed, was redefined since it was enqueued,
	// or is now inside its cooldown (a sibling commit armed it after this action
	// was queued but before it ran). This folds H1/H2/H3 into one gate.
	if reason := e.staleReason(a); reason != "" {
		e.store.ExitConfigure()
		return staleErr(reason)
	}

	for _, op := range a.ops {
		if op.isDelete {
			if err := e.store.Delete(op.delPath); err != nil {
				// A delete of a missing path is a TOLERATED exception (Junos
				// change-configuration semantics; #2139 documented carve-out):
				// it is not a half-applied batch. Any other delete error
				// aborts the batch.
				if strings.Contains(err.Error(), "path not found") {
					slog.Debug("event-options: delete skipped (path not found)",
						"policy", a.policyName, "cmd", op.raw)
					continue
				}
				e.store.ExitConfigure()
				return errBatch("delete %q: %v", op.raw, err)
			}
			continue
		}
		if err := e.store.SetFromInput(op.setInput); err != nil {
			e.store.ExitConfigure()
			return errBatch("set %q: %v", op.raw, err)
		}
	}

	// Validate the whole candidate before committing so a bad batch discards
	// cleanly instead of relying on Commit's failure path.
	if _, err := e.store.CommitCheck(); err != nil {
		e.store.ExitConfigure()
		return errBatch("commit-check: %v", err)
	}

	if e.commitFn == nil {
		// Standalone (tests): just commit; no apply.
		if _, err := e.store.Commit(); err != nil {
			e.store.ExitConfigure()
			return errBatch("commit: %v", err)
		}
		e.store.ExitConfigure()
		return nil
	}
	if _, err := e.commitFn(ctx, ""); err != nil {
		e.store.ExitConfigure()
		return errBatch("commit: %v", err)
	}
	e.store.ExitConfigure()
	return nil
}

// errBatch builds a permanent (non-retryable) batch failure error.
func errBatch(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

// errStaleAction is the sentinel returned by applyOnce when the pre-classified
// action is no longer valid to commit (#3750): its policy was removed or
// redefined, or the policy's cooldown is now active. runAction recognizes it via
// errors.Is, counts it as dropped_stale, and does NOT retry (staleness is
// terminal for that action).
var errStaleAction = errors.New("stale queued remediation")

// staleErr wraps errStaleAction with a human-readable reason for logging.
func staleErr(reason string) error {
	return fmt.Errorf("%w: %s", errStaleAction, reason)
}

// staleReason revalidates a pre-classified action against live engine state
// under e.mu (#3750) and returns a non-empty reason if it must NOT commit:
//
//   - "policy removed"   : e.semRev has no entry for the policy (H1). The
//     operator committed a config that dropped this event-options policy while
//     the action was queued/retrying; its stale command batch is unauthorized.
//   - "policy redefined" : the live semantic revision differs from the one the
//     action was stamped with at evaluate time (H2). A same-name redefinition
//     changed the policy's meaning; the OLD command set must not commit.
//   - "cooldown active"  : a successful commit of the SAME policy is within the
//     30s cooldown window (H3). The enqueue-time cooldown check in evaluateEvent
//     races the arm-on-commit timing, so a duplicate can slip into the queue
//     while the worker is blocked; the cooldown is re-enforced here at commit
//     time so a within-window duplicate is suppressed, not double-committed.
//
// The empty string means the action is safe to commit. Called by applyOnce
// while it holds the config lock, so the check reflects the last committed Apply
// and no operator commit can race it until ExitConfigure.
func (e *Engine) staleReason(a plannedAction) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	rev, ok := e.semRev[a.policyName]
	if !ok {
		return "policy removed"
	}
	if rev != a.semRev {
		return "policy redefined"
	}
	if rt := e.runtime[a.policyName]; rt != nil && !rt.lastTrigger.IsZero() &&
		e.now().Sub(rt.lastTrigger) < policyCooldown {
		return "cooldown active"
	}
	return ""
}

// classifyPlan pre-parses a policy's ThenCommands into a typed plan WITHOUT
// touching the candidate (#2139 step 1). An unknown command prefix, an
// unparseable set, or an unparseable delete makes the WHOLE plan invalid
// (ok=false) — the cheapest place to reject (no lock taken, no queue slot).
func (e *Engine) classifyPlan(pol *config.EventPolicy) ([]plannedOp, bool) {
	ops := make([]plannedOp, 0, len(pol.ThenCommands))
	for _, cmd := range pol.ThenCommands {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		switch {
		case strings.HasPrefix(cmd, "set "):
			input := strings.TrimPrefix(cmd, "set ")
			// Validate it parses now so a typo rejects the batch before any
			// candidate mutation.
			if _, err := config.ParseSetCommand("set " + input); err != nil {
				slog.Warn("event-options: set parse failed (batch rejected)",
					"policy", pol.Name, "cmd", cmd, "err", err)
				return nil, false
			}
			ops = append(ops, plannedOp{setInput: input, raw: cmd})
		case strings.HasPrefix(cmd, "delete "):
			input := strings.TrimPrefix(cmd, "delete ")
			path, err := config.ParseSetCommand("set " + input)
			if err != nil {
				slog.Warn("event-options: delete parse failed (batch rejected)",
					"policy", pol.Name, "cmd", cmd, "err", err)
				return nil, false
			}
			ops = append(ops, plannedOp{isDelete: true, delPath: path, raw: cmd})
		default:
			slog.Warn("event-options: unsupported command type (batch rejected)",
				"policy", pol.Name, "cmd", cmd)
			return nil, false
		}
	}
	return ops, true
}

// armCooldown records a successful-commit timestamp for the policy under lock
// (#2140 / #2157). Done on the worker after commit so a dropped/rejected
// action does not consume the cooldown.
func (e *Engine) armCooldown(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if rt := e.runtime[name]; rt != nil {
		rt.lastTrigger = e.now()
	}
}

// evaluateEvent checks policies under lock and returns any that should trigger.
// It records the event in the sliding window (pruning on append so a
// perpetually-cooldown-suppressed event can never grow unbounded — SMR finding
// 1) and CHECKS (does not arm) the cooldown; the cooldown is armed by the
// worker on a successful commit.
func (e *Engine) evaluateEvent(ev rpm.Event) []triggeredPolicy {
	e.mu.Lock()
	defer e.mu.Unlock()

	var triggered []triggeredPolicy
	now := e.now()
	for _, pol := range e.policies {
		if pol == nil {
			continue
		}
		if !e.eventMatches(pol, ev) {
			continue
		}

		if !e.attributesMatch(pol, ev) {
			continue
		}

		rt := e.runtime[pol.Name]
		if rt == nil {
			// Defensive: Apply always seeds runtime for every policy, but a
			// policy could be evaluated before its first Apply in a test.
			rt = newPolicyRuntime()
			e.runtime[pol.Name] = rt
		}

		// Record this event, pruning the window on append so a suppressed
		// event cannot grow it unbounded (SMR finding 1).
		rt.windows[ev.Name] = append(rt.windows[ev.Name], now)
		e.pruneWindow(pol, ev.Name, now)

		if !e.withinMatches(pol, rt, ev.Name, now) {
			continue
		}

		// Cooldown CHECK (armed on successful commit, not here): suppress a
		// re-trigger within the cooldown window so a flapping probe does not
		// flood the queue.
		if !rt.lastTrigger.IsZero() && now.Sub(rt.lastTrigger) < policyCooldown {
			continue
		}

		slog.Info("event-options policy triggered",
			"policy", pol.Name,
			"event", ev.Name,
			"test-owner", ev.TestOwner,
			"test-name", ev.TestName)

		// Capture the policy's semantic revision under the same lock so the
		// enqueued action can be revalidated against it before commit (#3750).
		triggered = append(triggered, triggeredPolicy{pol: pol, semRev: e.semRev[pol.Name]})
	}
	return triggered
}

// eventMatches checks if the event name is in the policy's event list.
func (e *Engine) eventMatches(pol *config.EventPolicy, ev rpm.Event) bool {
	for _, name := range pol.Events {
		if name == ev.Name {
			return true
		}
	}
	return false
}

// attributesMatch checks if the event attributes match the policy's filters.
// Format: "ping_test_failed.test-owner matches <pattern>".
//
// Junos `attributes-match ... matches ...` semantics are a REGEX match, not
// literal equality (this was a parity defect, #2008 M7). The operator's
// pattern is treated as an RE2 regular expression compiled once at Apply()
// time and cached here.
//
// #2141 FAIL-CLOSED: a malformed line (no " matches " / no ".") or an unknown
// <field> name is rejected at commit (config.ValidateEventAttributesMatchStrict),
// so it can only reach here on the legacy lenient-LOAD path (a config persisted
// by an older binary). In that case the matcher fails CLOSED — the policy does
// NOT trigger — rather than dropping the constraint and broadening the policy
// (the dangerous direction per #2124). This is a behavior change for legacy
// typo'd configs: they now STOP firing rather than over-fire, and are surfaced
// by the boot-time lenient-compile warning plus the AttributesInvalid counter.
func (e *Engine) attributesMatch(pol *config.EventPolicy, ev rpm.Event) bool {
	for _, attr := range pol.AttributesMatch {
		field, pattern, ok := config.ParseEventAttributesMatch(attr)
		if !ok {
			// Malformed line that slipped through a lenient load: fail closed.
			e.flagAttributesInvalid(pol.Name, attr, "malformed match expression")
			return false
		}

		if !config.EventAttributesFieldKnown(field) {
			// Unknown field that slipped through a lenient load: fail closed.
			e.flagAttributesInvalid(pol.Name, attr, "unknown field")
			return false
		}

		var value string
		switch field {
		case "test-owner":
			value = ev.TestOwner
		case "test-name":
			value = ev.TestName
		default:
			// Known to config but not yet resolvable on rpm.Event. The SSOT
			// and this switch are kept identical by a drift-guard test, so
			// this is unreachable; fail closed if it is ever hit.
			e.flagAttributesInvalid(pol.Name, attr, "unresolvable field")
			return false
		}

		re := e.regexCache[pattern]
		if re == nil {
			// Defensive: pattern was not cached (commit validation should
			// have rejected an uncompilable pattern, and Apply caches every
			// valid one). Compile on demand; an uncompilable pattern fails
			// the constraint CLOSED (the policy does not fire).
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				e.flagAttributesInvalid(pol.Name, attr, "uncompilable pattern")
				return false
			}
			re = compiled
		}

		if !re.MatchString(value) {
			return false
		}
	}
	return true
}

// flagAttributesInvalid bumps the counter and emits a throttled warning when a
// malformed/unknown attributes-match line is hit at runtime (#2141).
func (e *Engine) flagAttributesInvalid(policy, attr, reason string) {
	e.counters.attributesInvalid.Add(1)
	now := e.now().UnixNano()
	last := e.lastInvalidWarn.Load()
	if now-last >= int64(10*time.Second) {
		if e.lastInvalidWarn.CompareAndSwap(last, now) {
			slog.Warn("event-options: attributes-match invalid, policy fails closed (will not fire)",
				"policy", policy, "line", attr, "reason", reason)
		}
	}
}

// withinMatches evaluates temporal trigger clauses against the policy's runtime
// window.
// "within N { trigger on M }" — fires when M events happen within N seconds.
// "within N { trigger until M }" — fires until M events happen within N seconds, then stops.
func (e *Engine) withinMatches(pol *config.EventPolicy, rt *policyRuntime, eventName string, now time.Time) bool {
	if len(pol.WithinClauses) == 0 {
		return true // no temporal filter
	}

	timestamps := rt.windows[eventName]

	for _, wc := range pol.WithinClauses {
		// #3751 defense-in-depth: a within clause with no USABLE positive
		// threshold (both trigger on/until absent or <= 0) — or a non-positive
		// window — must fail CLOSED, not always-fire. Commit-time validation
		// (config.validateEventOptionsWithinAST) rejects such a clause outright,
		// so this belt only fires on a config that slipped through a TOLERANT
		// load / peer-sync path (an older binary silently coerced a within/
		// trigger typo to 0). Falling through to `return true` here would treat
		// that mis-arrived 0 as an unconditional match — turning a threshold-
		// gated remediation into an ALWAYS-FIRE one, the original fail-open. A
		// policy with NO within clauses at all is handled above (return true) —
		// that legitimately means "no temporal filter"; this guard is only for
		// a within clause that exists but gates nothing.
		if wc.Seconds <= 0 || (wc.TriggerOn <= 0 && wc.TriggerUntil <= 0) {
			return false
		}

		window := time.Duration(wc.Seconds) * time.Second

		// Count events within the window
		count := 0
		for _, ts := range timestamps {
			if now.Sub(ts) <= window {
				count++
			}
		}

		if wc.TriggerOn > 0 {
			// "trigger on N" — must have at least N events in window
			if count < wc.TriggerOn {
				return false
			}
		}

		if wc.TriggerUntil > 0 {
			// "trigger until N" — stop triggering once N events reached in window
			if count >= wc.TriggerUntil {
				return false
			}
		}
	}

	return true
}

// pruneWindow removes timestamps older than the policy's maximum within window
// (or a 60s default). Called on every append so a cooldown-suppressed event
// can never grow the window unbounded (SMR finding 1).
func (e *Engine) pruneWindow(pol *config.EventPolicy, eventName string, now time.Time) {
	rt := e.runtime[pol.Name]
	if rt == nil {
		return
	}

	maxWindow := time.Duration(0)
	for _, wc := range pol.WithinClauses {
		w := time.Duration(wc.Seconds) * time.Second
		if w > maxWindow {
			maxWindow = w
		}
	}
	if maxWindow == 0 {
		maxWindow = 60 * time.Second
	}

	timestamps := rt.windows[eventName]
	pruned := timestamps[:0]
	for _, ts := range timestamps {
		if now.Sub(ts) <= maxWindow {
			pruned = append(pruned, ts)
		}
	}
	rt.windows[eventName] = pruned
}
