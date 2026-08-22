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
//   - #5311 revision-aware cooldown arm: the arm-on-commit stamp is CONDITIONAL
//     on the live runtime still being the same generation (semantic revision)
//     that authorized the action. A remediation whose own commit redefines the
//     triggering policy (R1 -> R2) reconciles a FRESH re-armed runtime through
//     the commit callback's Apply; armCooldown must not stamp that successor R2
//     with R1's completion time (a name-based ABA that would suppress the
//     re-armed R2 for the whole cooldown, contradicting the "a redefined policy
//     re-arms" contract). The identity check and stamp run together under e.mu
//     so a concurrent Apply cannot swap the runtime between them.
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
//
// Its return is TRI-STATE (#5063), and the returned *config.Config — not
// the error — is the authority on whether the generation was promoted:
//
//   - (compiled != nil, nil): committed, active, dataplane armed. Success.
//   - (compiled != nil, err): committed, active, dataplane armed, but a
//     BEST-EFFORT subsystem (networkd write / Kea restart / host-inbound nft;
//     daemon_apply.go applyAndSyncCommitted) is in DEBT. The generation is
//     live — this is NOT a rejection. The engine records it as committed
//     (arms cooldown) and additionally counts the debt (#5063).
//   - (nil, err): the commit did NOT promote (bootstrap gate, compile/commit
//     failure, or a required-protocol-gate that DISARMED the dataplane). This
//     is the only genuine rejection.
type CommitFn func(ctx context.Context, comment string) (*config.Config, error)

// Minimum time between successive triggers of the same policy.
const policyCooldown = 30 * time.Second

// actionQueueDepth bounds the worker's pending-action channel. Dedup-by-policy
// (a newer trigger supersedes an older queued one) keeps at most one pending
// action per policy, so this is also an upper bound on distinct policies with
// a remediation in flight while the config lock is held. #5853: the dedup runs
// on EVERY enqueue (not only when the channel is full), so a burst from ONE
// policy occupies at most ONE slot — it can never fill the queue with redundant
// duplicates and starve an unrelated policy's remediation into a queue-full drop.
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
	Committed         uint64 // actions whose batch committed successfully (INCLUDES committed-with-apply-debt, #5063)
	CommittedWithDebt uint64 // subset of Committed that promoted+armed but left a best-effort subsystem in debt (#5063)
	Rejected          uint64 // actions rejected (bad plan / CommitCheck / commit not promoted)
	Retried           uint64 // retry attempts after a held config lock
	DroppedQueueFull  uint64 // actions genuinely dropped: the queue was full of OTHER policies (a distinct policy could not fit, or a survivor was lost) — capacity loss, alert-worthy
	Superseded        uint64 // same-policy queued actions REPLACED by a newer trigger (benign dedup; nothing lost — the newer equivalent action runs) (#5853)
	DroppedLockHeld   uint64 // actions dropped after the lock-retry deadline elapsed
	DroppedStale      uint64 // actions dropped at commit: policy removed/redefined or cooldown active (#3750)
	AttributesInvalid uint64 // runtime fail-closed: malformed/unknown attributes-match line
	QueueDepth        int64  // currently queued actions
}

// engineCounters holds the atomic counters behind Stats.
type engineCounters struct {
	committed         atomic.Uint64
	committedWithDebt atomic.Uint64
	rejected          atomic.Uint64
	retried           atomic.Uint64
	droppedQueueFull  atomic.Uint64
	superseded        atomic.Uint64
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
	// Triggering-event context, captured at evaluate time so the worker can
	// stamp a deterministic audit description on the remediation commit (#3754).
	// A security appliance that mutates its own config autonomously must record
	// in commit/rollback history WHICH policy fired and WHY.
	event     string
	testOwner string
	testName  string
	ops       []plannedOp
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
	// event name -> edge latch for a `within { trigger on N }` clause
	// (#3756 M1). Set (true) after the policy fires on a threshold CROSSING;
	// cleared (re-armed) by withinMatches the moment the in-window count drops
	// back below N. So a SUSTAINED above-threshold level fires the remediation
	// ONCE per crossing instead of re-firing every cooldown (Junos `trigger on`
	// is edge-, not level-triggered).
	onLatched map[string]bool
}

func newPolicyRuntime() *policyRuntime {
	return &policyRuntime{
		windows:   make(map[string][]time.Time),
		onLatched: make(map[string]bool),
	}
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

	// eventIndex maps an event NAME to the policies that list it, built once at
	// Apply so evaluateEvent scans only the policies relevant to the fired event
	// instead of every policy on every event (#4423 M6: linear policy scan per
	// event). Rebuilt whenever the policy set changes; read under e.mu. A policy
	// appears at most once per distinct event name it lists, preserving the
	// pre-index "match once, in config order" firing semantics.
	eventIndex map[string][]*config.EventPolicy

	counters engineCounters

	// Action queue + single worker (#2157). actions is bounded; the worker is
	// the ONLY goroutine that enters configure mode on the engine's behalf, so
	// the cross-probe EnterConfigure race cannot occur.
	actions   chan plannedAction
	workerWG  sync.WaitGroup
	stopOnce  sync.Once
	stopCh    chan struct{}
	startOnce sync.Once

	// enqueueMu serializes ALL producer-side queue mutation (#5062). HandleEvent
	// releases e.mu (evaluateEvent returns) BEFORE it enqueues, so many RPM-probe
	// goroutines run enqueue concurrently. Every enqueue runs supersede (#5853),
	// which DRAINS the accepted actions into a private slice (opening slots),
	// drops any same-policy entry, and then best-effort re-enqueues the survivors.
	// Without a producer lock a SECOND concurrent producer — via its own supersede
	// — takes those drain-freed slots between the drain and the re-enqueue, so
	// supersede's refill `default` branch DROPS a survivor (an already-accepted
	// action for a DIFFERENT policy), losing it and its FIFO position (miscounted
	// droppedQueueFull). Holding enqueueMu across the WHOLE enqueue (the supersede
	// drain+refill) makes the drain->re-enqueue atomic w.r.t. other producers: the
	// only concurrent actor left is the consumer (actionWorker), which only
	// REMOVES items, so a drain-freed slot can never be re-filled by anyone but
	// supersede itself and a survivor is preserved exactly once, in FIFO order.
	//
	// Lock ordering (no cycle, no deadlock): enqueueMu is a producer-only LEAF
	// lock. It is NEVER held while e.mu is held (enqueue runs after evaluateEvent
	// has released e.mu), and the consumer/worker path (runAction -> staleReason /
	// armCooldown, which take e.mu) NEVER takes enqueueMu — the two locks are
	// never nested in either order. Every channel op performed under enqueueMu is
	// a non-blocking select-with-default, and the consumer never holds enqueueMu,
	// so the queue always drains and no producer can block indefinitely.
	enqueueMu sync.Mutex

	// lifeCtx is the engine-lifetime context threaded into the remediation
	// commit (#2868). It is cancelled by Close() at the same time stopCh is
	// closed, so a remediation commit in flight at daemon shutdown (which
	// drives netlink updates, an FRR reload, and Rust dataplane sync — seconds
	// of work) is cancelled cleanly instead of blocking termination past the
	// systemd TimeoutStopSec SIGKILL. lifeCancel is its cancel func.
	lifeCtx    context.Context
	lifeCancel context.CancelFunc

	// Per-policy throttle for the runtime fail-closed warning so a flapping
	// probe with a legacy malformed line cannot flood the log. Keyed by policy
	// name (#4423 M11): a single global throttle let a bad line on ONE policy
	// swallow the FIRST warning about a DIFFERENT policy's distinct bad line, so
	// a real second problem could stay silent for the whole 10s window. Guarded
	// by its own mutex (not e.mu) so it is safe even when attributesMatch is
	// exercised directly by a matcher-only test that does not hold e.mu.
	invalidWarnMu sync.Mutex
	invalidWarnAt map[string]int64

	// Injectable clock for tests; nil means time.Now.
	nowFn func() time.Time

	// afterDrainFn is a test-only seam (#5062). When non-nil, supersede invokes
	// it exactly at the drain->re-enqueue boundary (after the queue has been
	// drained into the private survivor slice, before the survivors are
	// re-enqueued) so a test can deterministically drive a concurrent producer
	// into the freed slots and assert the fix serializes it. nil in production —
	// supersede is not a hot path (it fires only on a full-queue overflow), so a
	// single nil-check is negligible.
	afterDrainFn func()

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
		store:         store,
		commitFn:      commitFn,
		runtime:       make(map[string]*policyRuntime),
		semRev:        make(map[string]string),
		regexCache:    make(map[string]*regexp.Regexp),
		eventIndex:    make(map[string][]*config.EventPolicy),
		invalidWarnAt: make(map[string]int64),
		actions:       make(chan plannedAction, actionQueueDepth),
		stopCh:        make(chan struct{}),
		lifeCtx:       ctx,
		lifeCancel:    cancel,
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

	// #4423 (review follow-up): drop the per-policy invalid-warning throttle
	// entries for policies no longer present, so the map stays bounded to the
	// live policy set instead of accumulating a stamp per name ever seen. The
	// map is config-name-bounded either way; this keeps it tidy across churn.
	// Lock order matches the evaluate path (e.mu already held, then
	// invalidWarnMu — a leaf lock never held while acquiring e.mu).
	e.invalidWarnMu.Lock()
	for name := range e.invalidWarnAt {
		if _, ok := nextRev[name]; !ok {
			delete(e.invalidWarnAt, name)
		}
	}
	e.invalidWarnMu.Unlock()

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

	// Rebuild the event-name -> policies index (#4423 M6) so evaluateEvent
	// touches only the policies that list the fired event. Dedup per policy so a
	// policy that (legacy config) lists the same event name twice is still
	// evaluated once — matching the old eventMatches "return on first match".
	e.eventIndex = make(map[string][]*config.EventPolicy)
	for _, pol := range policies {
		if pol == nil {
			continue
		}
		seen := make(map[string]struct{}, len(pol.Events))
		for _, ev := range pol.Events {
			if _, dup := seen[ev]; dup {
				continue
			}
			seen[ev] = struct{}{}
			e.eventIndex[ev] = append(e.eventIndex[ev], pol)
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
	// Sort the event names before hashing (#4423 L4): the event list is a SET —
	// `events [ a b ]` and `events [ b a ]` are the same policy — so a bare
	// reorder must NOT change the semantic revision and re-arm (wiping the live
	// cooldown/window state carried forward across an Apply). This mirrors the
	// AttributesMatch treatment below; ThenCommands stay ordered because command
	// order IS semantic.
	events := append([]string(nil), pol.Events...)
	sort.Strings(events)
	for _, ev := range events {
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
// config lock. Concurrent enqueues are serialized by enqueueMu so a full-queue
// supersede cannot lose an already-accepted action to a racing producer (#5062).
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
		// state before committing, plus the triggering-event context (#3754)
		// for the remediation commit's audit description.
		e.enqueue(plannedAction{
			policyName: tp.pol.Name,
			semRev:     tp.semRev,
			event:      ev.Name,
			testOwner:  ev.TestOwner,
			testName:   ev.TestName,
			ops:        ops,
		})
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

// PolicyCount returns the number of event-options policies the engine
// currently has loaded. It is the observable seam for the daemon reconcile
// tests (#3752): after the first policy is enabled on a running daemon the
// engine must hold it, so a day-2 enable actually takes effect.
func (e *Engine) PolicyCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.policies)
}

// Stats returns a snapshot of the observable counters (#2157), surfaced to
// pkg/api for the xpf_event_actions_* metric family.
func (e *Engine) Stats() Stats {
	return Stats{
		Committed:         e.counters.committed.Load(),
		CommittedWithDebt: e.counters.committedWithDebt.Load(),
		Rejected:          e.counters.rejected.Load(),
		Retried:           e.counters.retried.Load(),
		DroppedQueueFull:  e.counters.droppedQueueFull.Load(),
		Superseded:        e.counters.superseded.Load(),
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
//
// #5853: the dedup runs on EVERY enqueue via supersede, not only when the
// channel is full. The pre-#5853 fast path did an UNCONDITIONAL send first and
// only deduped in the full/`default` branch, so while the worker was blocked
// behind the config lock a burst from ONE policy filled all 64 slots with
// redundant duplicates (later discarded by cooldown/staleness) and the next
// remediation for an UNRELATED policy was dropped queue-full. Draining and
// replacing the same-policy entry up front keeps at most one pending action per
// policy, so a same-policy burst occupies a single slot and leaves the rest free
// for other policies. supersede is non-blocking (select-with-default drain +
// refill), so this never blocks the caller even mid-shutdown (e.actions is never
// closed); a genuine full-of-other-policies queue still drops the new action
// (counted) via supersede returning false.
//
// The whole body runs under enqueueMu (#5062) so concurrent producers cannot
// interleave: supersede's drain+refill must be atomic w.r.t. other producers,
// otherwise a second producer could take a slot supersede freed while draining
// and force supersede to drop an already-accepted survivor. See the enqueueMu
// field comment for the lock-ordering rationale.
func (e *Engine) enqueue(a plannedAction) {
	e.enqueueMu.Lock()
	defer e.enqueueMu.Unlock()
	// Fast exit during shutdown: don't churn the queue for an action the worker
	// will never apply. supersede would otherwise still succeed (the channel is
	// unbounded-in-shutdown only in that it is never closed), but there is no
	// consumer left to drain it.
	select {
	case <-e.stopCh:
		return
	default:
	}
	if e.supersede(a) {
		return
	}
	// supersede could not place `a`: the queue is full of OTHER policies'
	// actions and there was no same-policy entry to evict. This is the only
	// genuine capacity drop (an unrelated policy really did fill the queue).
	e.counters.droppedQueueFull.Add(1)
	slog.Warn("event-options: action queue full, dropping remediation",
		"policy", a.policyName)
}

// supersede non-blockingly rebuilds the queue, replacing any existing
// same-policy action with a, and returns true if a was placed. It is the SOLE
// enqueue path (#5853): every enqueue drains the buffered queue, drops any
// existing same-policy entry (benign dedup, counted as superseded), re-enqueues
// the surviving OTHER-policy actions in FIFO order, and places a at the tail. It
// returns false only when the queue is full of OTHER policies and a could not be
// placed (a genuine capacity drop the caller counts as droppedQueueFull).
//
// CALLER MUST HOLD enqueueMu (#5062). That is what makes the drain->re-enqueue
// atomic w.r.t. other producers: while this runs, no other enqueue/supersede can
// take a slot the drain just freed, so every surviving other-policy action is
// re-enqueued exactly once in FIFO order (a survivor can never be dropped). The
// only concurrent actor is the consumer (actionWorker), which just REMOVES
// items, so the drain sees at most the buffered entries and the loop is bounded
// with no need to guard against a producer refilling underneath it.
func (e *Engine) supersede(a plannedAction) bool {
	drained := make([]plannedAction, 0, actionQueueDepth)
	replaced := false
	// Drain whatever is currently buffered.
	for {
		select {
		case old := <-e.actions:
			e.counters.queueDepth.Add(-1)
			if old.policyName == a.policyName {
				// Drop the stale same-policy action; it is superseded by the
				// newer trigger a. This is a benign dedup — the newer equivalent
				// action still runs — NOT a capacity loss, so count it as
				// superseded rather than droppedQueueFull (#5853). Inflating the
				// alert-worthy queue_full metric on every same-policy burst
				// (which the early dedup makes routine) would mask real capacity
				// drops.
				e.counters.superseded.Add(1)
				continue
			}
			drained = append(drained, old)
		default:
			goto refill
		}
	}
refill:
	// Test-only seam (#5062): the drain->re-enqueue boundary. In production this
	// is nil. A concurrency test sets it to drive a second producer into the
	// freed slots here and prove enqueueMu serializes it (the survivors are
	// preserved regardless of what the injected producer does).
	if e.afterDrainFn != nil {
		e.afterDrainFn()
	}
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
			// Arm the cooldown against the SAME generation that authorized this
			// action (#5311). a.semRev is the policy's semantic revision as of
			// the evaluate that enqueued the action; staleReason already proved
			// it still matched live state at commit time. Passing it lets
			// armCooldown skip the stamp if this action's OWN commit redefined
			// the policy (R1 -> R2), which reconciled a fresh re-armed runtime.
			e.armCooldown(a.policyName, a.semRev)
			slog.Info("event-options: configuration committed",
				"policy", a.policyName, "commands", len(a.ops))
			return
		}
		// #5063: committed-with-apply-debt. The generation was promoted, is active,
		// and the dataplane is armed — a best-effort subsystem (networkd / Kea /
		// host-inbound nft) is in debt. This is NOT a rejection: record it as
		// committed and arm the SAME-generation cooldown exactly as the clean-commit
		// path, so the live autonomous change is not miscounted rejected and the
		// same event cannot immediately re-commit during an incident. Also bump the
		// distinct debt counter and log a WARN so the operator sees the subsystem
		// debt. Terminal like the clean commit — no retry.
		var debt *commitDebtError
		if errors.As(err, &debt) {
			e.counters.committed.Add(1)
			e.counters.committedWithDebt.Add(1)
			e.armCooldown(a.policyName, a.semRev)
			slog.Warn("event-options: configuration committed with apply debt",
				"policy", a.policyName, "commands", len(a.ops), "err", debt.err)
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
	// #4423 L7: a matcher-only Engine (New(nil, nil)) has no store. A policy
	// that both matches AND triggers would otherwise nil-panic on EnterConfigure
	// inside the worker goroutine, taking down the daemon on a config an operator
	// could plausibly commit. Fail the batch permanently (counted rejected)
	// instead — a store is required to mutate config.
	if e.store == nil {
		return errBatch("no config store: cannot apply event-options remediation")
	}
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
				// aborts the batch. #4423 M9: match the typed sentinel
				// config.ErrPathNotFound (which DeletePath now wraps) instead of
				// substring-matching the error text — a future reword of the
				// message no longer silently turns a tolerated missing-delete
				// into a batch-aborting hard reject.
				if errors.Is(err, config.ErrPathNotFound) {
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

	// #3754: stamp a deterministic audit description so the autonomous
	// remediation lands in commit/rollback history attributed to the policy and
	// its triggering event, not as an anonymous unattributed commit.
	desc := remediationDescription(a)
	if e.commitFn == nil {
		// Standalone (tests): just commit; no apply. Still record the
		// description so the journal/history attribution is identical to the
		// daemon path.
		if _, err := e.store.CommitWithDescription(desc); err != nil {
			e.store.ExitConfigure()
			return errBatch("commit: %v", err)
		}
		e.store.ExitConfigure()
		return nil
	}
	compiled, err := e.commitFn(ctx, desc)
	// ExitConfigure unconditionally: commitFn has already promoted (or refused
	// to promote) the candidate, so the engine's configure session is done
	// either way — the same teardown the success path always ran.
	e.store.ExitConfigure()
	if err != nil {
		// #5063: the returned *config.Config, not the error, decides whether the
		// generation was promoted. A non-nil compiled means the config committed,
		// is active, and the dataplane is armed — a best-effort subsystem is just
		// in debt (see CommitFn). That is committed-with-debt, NOT a rejection:
		// signal it so runAction arms the cooldown and counts it committed instead
		// of re-committing the same event and inflating the rejected counter. Only
		// a nil compiled (commit never promoted / dataplane disarmed) is a genuine
		// permanent rejection.
		if compiled != nil {
			return &commitDebtError{err: err}
		}
		return errBatch("commit: %v", err)
	}
	return nil
}

// remediationDescription builds the deterministic audit string stamped on an
// autonomous event-options remediation commit (#3754). It names the policy,
// the triggering event/owner/test, and the command-batch size so an operator
// reading commit/rollback history can tell which policy mutated the config and
// why.
func remediationDescription(a plannedAction) string {
	return fmt.Sprintf("event-options policy %s: %s/%s/%s (%d commands)",
		a.policyName, a.event, a.testOwner, a.testName, len(a.ops))
}

// errBatch builds a permanent (non-retryable) batch failure error.
func errBatch(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

// commitDebtError is returned by applyOnce when commitFn promoted the generation
// (non-nil *config.Config) but a best-effort subsystem apply failed (#5063): the
// config is committed, active, and the dataplane armed, so it is committed — NOT
// rejected — with the wrapped subsystem error as apply debt. runAction detects it
// via errors.As, counts committed + committedWithDebt, and arms the cooldown.
// Unwrap exposes the underlying subsystem error for logging / errors.Is.
type commitDebtError struct{ err error }

func (e *commitDebtError) Error() string { return "committed with apply debt: " + e.err.Error() }
func (e *commitDebtError) Unwrap() error { return e.err }

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
//
// Revision-aware ABA guard (#5311): the stamp is CONDITIONAL on the live
// runtime still being the SAME generation that authorized this action. authRev
// is the action's semantic revision (plannedAction.semRev). A remediation whose
// own commit redefined the triggering policy (R1 -> R2) reconciles through the
// commitFn callback -> Apply, which installs a FRESH re-armed runtime for the
// successor because the semantic revision changed. That successor R2 must NOT be
// stamped with R1's completion time: doing so is a name-based ABA that would
// suppress the re-armed R2 for the whole ~30s cooldown, contradicting the
// documented "a redefined policy re-arms" contract (README, reconcile section).
// When authRev no longer matches e.semRev[name] (successor installed, or policy
// removed — no entry), skip the stamp; the successor keeps its zero lastTrigger.
// The identity check and the stamp are performed under e.mu in one critical
// section so a concurrent Apply cannot swap the runtime between them (no TOCTOU).
func (e *Engine) armCooldown(name, authRev string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.semRev[name] != authRev {
		// A successor generation was installed (or the policy was removed) while
		// this action committed. Do not throttle the successor with the
		// predecessor's completion time.
		return
	}
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
	// #4423 M6/M5: scan only the policies that list this event (index built at
	// Apply), not every policy on every event. The index guarantees the event
	// matches, so the per-policy eventMatches scan is gone; the remaining
	// per-matching-policy attributes/within work is inherent and bounded by the
	// pruned window.
	for _, pol := range e.eventIndex[ev.Name] {
		if pol == nil {
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

		// #3756 M1: arm the edge latch for this crossing so a sustained
		// above-threshold level does not re-fire every cooldown. Set only
		// AFTER the cooldown check passed — a cooldown-suppressed crossing is
		// NOT treated as already-fired, so the next event past the cooldown
		// still fires. Cleared by withinMatches when the count drops back
		// below the trigger-on threshold (re-arm).
		if policyHasTriggerOn(pol) {
			rt.onLatched[ev.Name] = true
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
		eventName, field, pattern, ok := config.ParseEventAttributesMatch(attr)
		if !ok {
			// Malformed line that slipped through a lenient load: fail closed.
			e.flagAttributesInvalid(pol.Name, attr, "malformed match expression")
			return false
		}

		// #3753: the constraint is scoped to a specific event name. Only apply
		// it when the CURRENT event IS that event; a constraint written for a
		// DIFFERENT event of a multi-event policy must NOT gate this event
		// (before this the prefix was dropped, so `event_a.test-owner ...`
		// incorrectly gated event_b too — and vice-versa). Commit-time
		// validation guarantees eventName is one of the policy's events, so an
		// out-of-scope prefix here can only be a legacy lenient-load config.
		if eventName != ev.Name {
			continue
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
		case "target":
			value = ev.Target
		case "routing-instance":
			value = ev.RoutingInstance
		case "destination-interface":
			value = ev.DestinationInterface
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
			// #4423 M10: back-fill the cache so a pattern that slipped past the
			// Apply-time build (legacy lenient-load path) is compiled ONCE, not
			// on every event. Production callers reach here under e.mu, which
			// also guards the Apply-time rebuild, so the write is serialized.
			if e.regexCache == nil {
				e.regexCache = make(map[string]*regexp.Regexp)
			}
			e.regexCache[pattern] = re
		}

		if !re.MatchString(value) {
			return false
		}
	}
	return true
}

// flagAttributesInvalid bumps the counter and emits a throttled warning when a
// malformed/unknown attributes-match line is hit at runtime (#2141). The
// throttle is PER POLICY (#4423 M11): a flapping bad line on one policy must
// not swallow the first warning about a distinct bad line on another policy.
func (e *Engine) flagAttributesInvalid(policy, attr, reason string) {
	e.counters.attributesInvalid.Add(1)
	now := e.now().UnixNano()
	e.invalidWarnMu.Lock()
	if e.invalidWarnAt == nil {
		e.invalidWarnAt = make(map[string]int64)
	}
	last := e.invalidWarnAt[policy]
	warn := last == 0 || now-last >= int64(10*time.Second)
	if warn {
		e.invalidWarnAt[policy] = now
	}
	e.invalidWarnMu.Unlock()
	if warn {
		slog.Warn("event-options: attributes-match invalid, policy fails closed (will not fire)",
			"policy", policy, "line", attr, "reason", reason)
	}
}

// policyHasTriggerOn reports whether the policy carries any `within { trigger
// on N }` clause. Only such a policy participates in the #3756 M1 edge latch;
// a no-within policy (or a `trigger until` policy) is unaffected.
func policyHasTriggerOn(pol *config.EventPolicy) bool {
	for _, wc := range pol.WithinClauses {
		if wc != nil && wc.TriggerOn > 0 {
			return true
		}
	}
	return false
}

// withinMatches evaluates temporal trigger clauses against the policy's runtime
// window.
// "within N { trigger on M }" — fires when M events happen within N seconds.
// "within N { trigger until M }" — fires until M events happen within N seconds, then stops.
//
// MULTIPLE within clauses are combined with AND (#4423 M3): the policy fires
// only when EVERY within clause passes for this event. A policy that wants
// OR-of-conditions must be written as separate policies. This AND semantics is
// the documented contract (pkg/eventengine/README.md) and is covered by
// TestWithinMultipleClausesAreANDed.
//
// The body is three passes over the clause list rather than one fused loop, so
// no verdict depends on the order the operator wrote the clauses in — see the
// #5250 note on pass 2. One deliberate ordering delta survives: a policy that
// carries BOTH a structurally invalid clause (rejected by pass 1) and a
// below-threshold trigger-on clause no longer clears the edge latch, where the
// fused loop did if the below-threshold clause came first. Such a policy fails
// closed on every event for as long as the invalid clause exists, so the
// latch's value is unobservable until the config is corrected — after which the
// next below-threshold event re-arms it through the normal path.
func (e *Engine) withinMatches(pol *config.EventPolicy, rt *policyRuntime, eventName string, now time.Time) bool {
	if len(pol.WithinClauses) == 0 {
		return true // no temporal filter
	}

	timestamps := rt.windows[eventName]

	// PASS 1 — structural validity, over every clause.
	//
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
	for _, wc := range pol.WithinClauses {
		if wc.Seconds <= 0 || (wc.TriggerOn <= 0 && wc.TriggerUntil <= 0) {
			return false
		}
	}

	counts := make([]int, len(pol.WithinClauses))
	for i, wc := range pol.WithinClauses {
		window := time.Duration(wc.Seconds) * time.Second
		for _, ts := range timestamps {
			if now.Sub(ts) <= window {
				counts[i]++
			}
		}
	}

	// PASS 2 — the "trigger on N" edge latch, decided over EVERY trigger-on
	// clause before anything returns.
	//
	// "trigger on N" is EDGE-triggered (#3756 M1): it fires on the threshold
	// CROSSING, not on every event while the level stays at or above N. Junos
	// `trigger on` re-arms only after the count drops back below N; the 30s
	// cooldown alone only THROTTLES a sustained level (re-remediating it every
	// cooldown), which is harmful for a non-idempotent then-batch and spams
	// commit/rollback history.
	//
	// #5250 (A9 F4): the re-arm and the latch check are two separate passes
	// over the clause list, and that separation IS the fix. The single fused
	// loop this replaces returned false from inside the walk, so with more
	// than one `within { trigger on N }` clause the outcome depended on the
	// order the operator wrote them in. Clauses are ANDed (below), so consider
	// `within 600 { trigger on 10 }` written BEFORE `within 60 { trigger on 3 }`
	// with the policy already latched: the 600s clause is still at/above 10, so
	// it hit the latch check and returned — and the 60s clause, which had
	// dropped below 3 and was the one that should have RE-ARMED the latch, was
	// never reached. The AND became false and then true again (a real crossing)
	// and the policy stayed silent until the long window decayed. Written in
	// the other order the same config re-arms correctly. Deciding the re-arm
	// across all clauses first makes the result independent of clause order:
	// the latch clears exactly when the ANDed condition is false, which is
	// exactly when any trigger-on clause is below its threshold.
	belowTriggerOn := false
	hasTriggerOn := false
	for i, wc := range pol.WithinClauses {
		if wc.TriggerOn <= 0 {
			continue
		}
		hasTriggerOn = true
		if counts[i] < wc.TriggerOn {
			belowTriggerOn = true
		}
	}
	if belowTriggerOn {
		// Dropped below the threshold: re-arm so the next crossing fires again.
		rt.onLatched[eventName] = false
		return false
	}
	if hasTriggerOn && rt.onLatched[eventName] {
		// Level still at/above N on every clause and this crossing already
		// fired: suppress until some clause's count drops below its threshold
		// (re-arm above). evaluateEvent sets the latch only AFTER the cooldown
		// check passes, so a cooldown-suppressed crossing is not consumed.
		return false
	}

	// PASS 3 — "trigger until N".
	//
	// "trigger until N" fires through the INCLUSIVE N-th event, then stops
	// (#3756 M2). Junos reads it as "trigger UNTIL the event has been received
	// N times" — the N-th occurrence is the LAST that fires. The event is
	// appended to the window BEFORE this check (evaluateEvent), so the N-th
	// matching event already makes count==N; using `>=` here made count==N
	// return false, so the N-th never fired and `until 1` (count==1 on the
	// first event) could NEVER fire at all — a dead-config bug. `>` fires on
	// 1..N and stops at N+1.
	for i, wc := range pol.WithinClauses {
		if wc.TriggerUntil > 0 && counts[i] > wc.TriggerUntil {
			return false
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
	// #4423 M4: the in-place compaction above reuses the SAME backing array, so
	// its capacity stays pinned at the burst high-water mark forever — a single
	// storm of a rapidly-flapping probe permanently retains that memory even
	// after the window drains back to a handful of entries. When the retained
	// capacity dwarfs the live length, copy into a right-sized slice so the old
	// backing array can be collected. The threshold keeps steady-state churn
	// cheap (no realloc for a window oscillating near its typical size).
	if cap(pruned) >= 64 && cap(pruned) > 4*len(pruned) {
		shrunk := make([]time.Time, len(pruned))
		copy(shrunk, pruned)
		pruned = shrunk
	}
	rt.windows[eventName] = pruned
}
