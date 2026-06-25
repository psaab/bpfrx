package eventengine

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/rpm"
)

// newStore builds a real configstore with an initial committed config
// (system host-name "base") so tests can observe the active config before and
// after a remediation.
func newStore(t *testing.T) *configstore.Store {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system host-name base"); err != nil {
		t.Fatalf("seed set: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	s.ExitConfigure()
	return s
}

func eventFor(name string) rpm.Event {
	return rpm.Event{Name: name, TestOwner: "owner", TestName: "tname"}
}

// waitFor polls fn until it returns true or the deadline elapses.
func waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// #2139: a change-configuration action with two valid commands and one invalid
// in the middle (a command that parses but fails CommitCheck) must commit
// NOTHING — the candidate is discarded, the active config is unchanged, and
// the action is counted as rejected.
//
// NOTE (review #2180): this case is NON-discriminating for the #2139
// classifyPlan fix. The mid-batch command (`set system dataplane-type ebpf`)
// parses and applies to the candidate fine; it fails only at the
// whole-candidate COMPILE (the eBPF retirement reject). The PRE-FIX best-effort
// path (apply-all-then-Commit) ALSO discards the whole candidate here, because
// store.Commit compiles the whole candidate atomically and refuses to promote a
// candidate that won't compile. So this test passes on both pre- and post-fix
// code. It is retained as a useful corner case (compile-time reject), but the
// GENUINE pre-fix partial-commit bug is exercised by
// TestBatch_UnknownCommandMidBatchRevertsWholeCandidate below.
func TestBatch_PartialFailureRevertsWholeCandidate(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:   "p",
		Events: []string{"ping_test_failed"},
		ThenCommands: []string{
			"set system host-name changed-1",          // valid
			"set system dataplane-type ebpf",          // parses, fails CommitCheck
			"set system domain-name should-not-apply", // valid
		},
	}
	e := New(s, nil) // nil commitFn: store.Commit path
	defer e.Close()
	e.Apply([]*config.EventPolicy{pol})

	e.HandleEvent(eventFor("ping_test_failed"))

	waitFor(t, "rejected counter", func() bool { return e.Stats().Rejected >= 1 })

	// The active config must be UNCHANGED — no half-apply.
	active := s.ActiveConfig()
	if active.System.HostName != "base" {
		t.Errorf("host-name changed to %q; batch must be all-or-nothing (no half-apply)",
			active.System.HostName)
	}
	if active.System.DomainName != "" {
		t.Errorf("domain-name applied (%q) from a rejected batch", active.System.DomainName)
	}
	if got := e.Stats().Committed; got != 0 {
		t.Errorf("Committed=%d; a rejected batch must not commit", got)
	}
}

// #2139 (review #2180): the DISCRIMINATING transactionality test. A batch with
// a valid set, then an UNSUPPORTED command (`reboot now` — not a set/delete, so
// it can never apply to the candidate), then another valid set must commit
// NOTHING. The whole batch is pre-classified and rejected BEFORE the candidate
// is touched, so the active config is unchanged and committed==0.
//
// This is the case the headline test above does NOT discriminate. Here the bad
// command is one that classifyPlan rejects BEFORE any mutation — NOT one that
// applies to the candidate and fails only at compile. On the PRE-FIX
// best-effort path (executeCommands: apply each command, log+SKIP an
// unsupported one, then store.Commit the residue), the first `set` is applied,
// `reboot now` is silently skipped, the trailing `set` is applied, and the
// resulting candidate compiles cleanly and COMMITS — a partial commit
// (host-name changed). The #2139 classifyPlan fix rejects the whole batch up
// front (unsupported prefix → ok=false), so host-name stays "base" and nothing
// commits. See the simulate-pre-fix proof recorded in the commit message:
// stubbing the engine back to apply-then-commit makes THIS test fail with
// host-name="changed-1" / Committed=1, while it passes on the real fix.
func TestBatch_UnknownCommandMidBatchRevertsWholeCandidate(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:   "p",
		Events: []string{"ping_test_failed"},
		ThenCommands: []string{
			"set system host-name changed-1",          // valid set
			"reboot now",                              // unsupported: not set/delete
			"set system domain-name should-not-apply", // valid set
		},
	}
	e := New(s, nil) // nil commitFn: store.Commit path
	defer e.Close()
	e.Apply([]*config.EventPolicy{pol})

	e.HandleEvent(eventFor("ping_test_failed"))

	// The whole batch must be rejected (pre-classify), with no candidate touched.
	waitFor(t, "rejected counter", func() bool { return e.Stats().Rejected >= 1 })

	// Give a worker (if one wrongly ran) time to commit a partial residue, then
	// assert it did NOT. On pre-fix code this is where host-name=="changed-1".
	time.Sleep(50 * time.Millisecond)

	active := s.ActiveConfig()
	if active.System.HostName != "base" {
		t.Errorf("host-name changed to %q; an unsupported mid-batch command must reject the WHOLE batch before any mutation (no partial commit)",
			active.System.HostName)
	}
	if active.System.DomainName != "" {
		t.Errorf("domain-name applied (%q) from a rejected batch", active.System.DomainName)
	}
	if got := e.Stats().Committed; got != 0 {
		t.Errorf("Committed=%d; a batch rejected at classify must not commit anything", got)
	}
}

// #2868: a remediation commit in flight at daemon shutdown must be cancelled
// cleanly. The remediation commit (commitFn) drives netlink updates, an FRR
// reload, and Rust dataplane sync — seconds of work. Before #2868 the engine
// passed context.Background() to commitFn, so a Close() landing mid-remediation
// could not cancel the in-flight commit and blocked termination past the
// systemd TimeoutStopSec SIGKILL.
//
// FAIL-ON-REVERT: this test wires a commitFn that blocks until its context is
// Done, then triggers a remediation and calls Close() (which closes stopCh AND
// cancels the lifetime context). The commit must observe ctx.Done and abort
// with ctx.Err(). If the threading is reverted to context.Background(), the
// commitFn blocks forever (Background never cancels) and the test fails on the
// timeout below.
func TestCommit_CancelledOnEngineStop(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:         "p",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name remediated"},
	}

	entered := make(chan struct{}) // commitFn reached
	done := make(chan error, 1)    // commitFn's return value (the ctx error)

	commitFn := func(ctx context.Context, comment string) (*config.Config, error) {
		close(entered)
		// Block until the lifetime context is cancelled by Close(). With the
		// #2868 fix this returns promptly on Close(); reverted to
		// context.Background() this blocks forever and the test times out.
		<-ctx.Done()
		err := ctx.Err()
		done <- err
		return nil, err
	}

	e := New(s, commitFn)
	e.Apply([]*config.EventPolicy{pol})

	e.HandleEvent(eventFor("ping_test_failed"))

	// Wait for the worker to enter the commit phase.
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("commitFn was never reached")
	}

	// Stop the engine: this closes stopCh and cancels the lifetime context,
	// which must cancel the in-flight commit.
	closed := make(chan struct{})
	go func() {
		e.Close()
		close(closed)
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("commit ctx err = %v; want context.Canceled (commit must be"+
				" cancelled on engine stop, not run under context.Background())", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight remediation commit was NOT cancelled on engine stop" +
			" — commitFn is running under an uncancellable context (#2868 regression)")
	}

	// Close must return once the worker drains.
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close() did not return after the commit was cancelled")
	}
}

// #2139: a valid-only batch commits in full.
func TestBatch_ValidBatchCommits(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:         "p",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name remediated"},
	}
	e := New(s, nil)
	defer e.Close()
	e.Apply([]*config.EventPolicy{pol})

	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "committed counter", func() bool { return e.Stats().Committed >= 1 })

	if got := s.ActiveConfig().System.HostName; got != "remediated" {
		t.Errorf("host-name=%q; valid batch should have committed 'remediated'", got)
	}
}

// #2139: a delete of a missing path inside an otherwise-valid batch still
// commits (documented tolerated exception).
func TestBatch_DeleteMissingPathTolerated(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:   "p",
		Events: []string{"ping_test_failed"},
		ThenCommands: []string{
			"delete system domain-name", // never set: "path not found", tolerated
			"set system host-name still-commits",
		},
	}
	e := New(s, nil)
	defer e.Close()
	e.Apply([]*config.EventPolicy{pol})

	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "committed counter", func() bool { return e.Stats().Committed >= 1 })

	if got := s.ActiveConfig().System.HostName; got != "still-commits" {
		t.Errorf("host-name=%q; a missing-delete must not abort the batch", got)
	}
}

// #2140: the cooldown survives the engine's own remediation-commit re-entry.
// A real daemon calls Apply on every commit, including the engine's own commit;
// the old code wiped lastTrigger on every Apply, defeating the cooldown. Here
// we simulate that by calling Apply between two triggers (with the SAME policy
// set → same semantic revision → state must be carried forward) and assert the
// second trigger is suppressed by the cooldown.
func TestCooldown_SurvivesApplyReload(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:         "p",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name cd"},
	}
	e := New(s, nil)
	defer e.Close()
	e.Apply([]*config.EventPolicy{pol})

	// First trigger commits and arms the cooldown.
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "first commit", func() bool { return e.Stats().Committed >= 1 })

	// Simulate the self-triggered commit's Apply (and any unrelated commit):
	// same policy set, so state must be reconciled (carried forward).
	e.Apply([]*config.EventPolicy{pol})

	// Second trigger with no time advance: cooldown must suppress it.
	e.HandleEvent(eventFor("ping_test_failed"))

	// Give the worker a chance to (wrongly) commit again, then assert it did
	// NOT — the cooldown held across the Apply.
	time.Sleep(50 * time.Millisecond)
	if got := e.Stats().Committed; got != 1 {
		t.Errorf("Committed=%d; cooldown must suppress the second trigger across an Apply reload", got)
	}
}

// #2140: an unrelated Apply (a different policy left unchanged in the set) must
// preserve this policy's cooldown state; changing the policy's ThenCommands
// (revision change) resets it; removing the policy drops its state.
func TestCooldown_ReconcileIdentity(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:         "p",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name v1"},
	}
	e := New(s, nil)
	defer e.Close()
	e.Apply([]*config.EventPolicy{pol})
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "first commit", func() bool { return e.Stats().Committed >= 1 })

	// Unrelated Apply: add an unrelated policy, leave p unchanged.
	other := &config.EventPolicy{Name: "other", Events: []string{"x"}, ThenCommands: []string{"set system domain-name d"}}
	e.Apply([]*config.EventPolicy{pol, other})
	e.mu.Lock()
	rt := e.runtime["p"]
	preserved := rt != nil && !rt.lastTrigger.IsZero()
	e.mu.Unlock()
	if !preserved {
		t.Error("unchanged policy lost its cooldown state across an unrelated Apply")
	}

	// Semantic change: edit ThenCommands → revision changes → re-arm (reset).
	changed := &config.EventPolicy{Name: "p", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name v2"}}
	e.Apply([]*config.EventPolicy{changed})
	e.mu.Lock()
	rt = e.runtime["p"]
	reset := rt != nil && rt.lastTrigger.IsZero()
	e.mu.Unlock()
	if !reset {
		t.Error("redefined policy kept a stale cooldown; a semantic change must re-arm")
	}

	// Removal: policy not in the new set → state dropped.
	e.Apply([]*config.EventPolicy{other})
	e.mu.Lock()
	_, present := e.runtime["p"]
	e.mu.Unlock()
	if present {
		t.Error("removed policy retained runtime state")
	}
}

// #2157: when EnterConfigure fails because the lock is held, the action is
// queued and RETRIED (not dropped); once the lock is released the action
// commits. Proves the fail-safe queue + backoff. On pre-fix code the action
// would have been dropped with only a warning.
func TestQueue_HeldLockRetriesThenCommits(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:         "p",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name after-lock"},
	}
	e := New(s, nil)
	defer e.Close()
	e.Apply([]*config.EventPolicy{pol})

	// Hold the lock as "another user" before triggering.
	if err := s.EnterConfigureSession("operator"); err != nil {
		t.Fatalf("hold lock: %v", err)
	}

	e.HandleEvent(eventFor("ping_test_failed"))

	// The worker should retry while the lock is held.
	waitFor(t, "a retry", func() bool { return e.Stats().Retried >= 1 })

	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Errorf("host-name=%q while lock held; action must wait, not apply", got)
	}

	// Release the lock; the worker's next attempt should commit.
	if !s.ExitConfigureSession("operator") {
		t.Fatal("failed to release the held lock")
	}
	waitFor(t, "commit after lock release", func() bool { return e.Stats().Committed >= 1 })
	if got := s.ActiveConfig().System.HostName; got != "after-lock" {
		t.Errorf("host-name=%q; action should have committed after the lock released", got)
	}
}

// #2157: a lock held past the retry deadline drops the action (counted), not
// applied. Uses a tiny retry deadline so the test does not wait the production
// 60s.
func TestQueue_HeldLockPastDeadlineDrops(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:         "p",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name never"},
	}
	e := New(s, nil)
	// Tiny deadline + fast backoff: give up almost immediately.
	e.retryInitial = time.Millisecond
	e.retryMax = time.Millisecond
	e.retryDeadline = 20 * time.Millisecond
	defer e.Close()
	e.Apply([]*config.EventPolicy{pol})

	if err := s.EnterConfigureSession("operator"); err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	defer s.ExitConfigureSession("operator")

	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "drop counter", func() bool { return e.Stats().DroppedLockHeld >= 1 })

	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Errorf("host-name=%q; a dropped action must not apply", got)
	}
	if got := e.Stats().Committed; got != 0 {
		t.Errorf("Committed=%d; a dropped action must not commit", got)
	}
}

// #2157 concurrency: many probe goroutines firing distinct policies must all
// serialize through the single worker with no race and each committing once.
// Run with -race to catch a regression to the per-probe EnterConfigure race.
func TestQueue_ConcurrentProbesSerialize(t *testing.T) {
	s := newStore(t)
	const n = 8
	policies := make([]*config.EventPolicy, 0, n)
	for i := 0; i < n; i++ {
		name := "p" + string(rune('a'+i))
		policies = append(policies, &config.EventPolicy{
			Name:         name,
			Events:       []string{name + "_event"},
			ThenCommands: []string{"set system host-name " + name},
		})
	}
	e := New(s, nil)
	defer e.Close()
	e.Apply(policies)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := "p" + string(rune('a'+i))
			e.HandleEvent(rpm.Event{Name: name + "_event", TestOwner: "o", TestName: "t"})
		}(i)
	}
	wg.Wait()

	// Every distinct policy should commit exactly once (serialized).
	waitFor(t, "all commits", func() bool { return e.Stats().Committed >= n })
	if got := e.Stats().Committed; got != n {
		t.Errorf("Committed=%d; want exactly %d (each distinct policy commits once)", got, n)
	}
}

// #2157 queue dedup: a second trigger of the SAME policy while the first is
// stuck behind a held lock supersedes the older queued action (dedup-by-policy)
// rather than queuing two; the drop is counted as queue_full.
func TestQueue_DedupByPolicy(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:         "p",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name dedup"},
	}
	e := New(s, nil)
	defer e.Close()
	e.Apply([]*config.EventPolicy{pol})

	// Hold the lock so the worker is stuck retrying the first action.
	if err := s.EnterConfigureSession("operator"); err != nil {
		t.Fatalf("hold lock: %v", err)
	}

	// First trigger: taken by the worker (now retrying under the held lock).
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "worker retrying first action", func() bool { return e.Stats().Retried >= 1 })

	// Fill the queue with same-policy triggers; dedup must keep at most one
	// pending and count the rest as superseded. The cooldown is armed only on
	// commit (not yet, since the lock is held), so evaluate does not filter
	// these.
	for i := 0; i < actionQueueDepth+4; i++ {
		e.HandleEvent(eventFor("ping_test_failed"))
	}

	waitFor(t, "queue_full drops", func() bool { return e.Stats().DroppedQueueFull >= 1 })

	// Release and confirm it still converges to a single commit.
	s.ExitConfigureSession("operator")
	waitFor(t, "eventual commit", func() bool { return e.Stats().Committed >= 1 })
}

// #2869 supersede ordering: when supersede() rebuilds a full queue it must
// preserve the FIFO order of UNRELATED policies and place the new (superseding)
// action at the TAIL, not the head. A prepend would let the newest event jump
// ahead of every older queued remediation (LIFO), starving older policies under
// sustained event frequency.
//
// FAIL-ON-REVERT: revert the engine.go fix back to
// `all := append([]plannedAction{a}, drained...)` and this test goes RED —
// the new policy "z" lands at index 0 instead of the tail, and the surviving
// policies are shifted out of FIFO order.
func TestSupersede_PreservesFIFOPlacesNewAtTail(t *testing.T) {
	e := New(nil, nil)
	defer e.Close()

	// Fill the bounded queue with DISTINCT other-policy actions p00..pNN in a
	// known FIFO order, PLUS one stale same-policy "z" entry at the tail. The
	// queue is now full (no free slot), so a fresh "z" trigger forces the
	// supersede() drain/refill path (the only path that reorders).
	want := make([]string, 0, actionQueueDepth)
	for i := 0; i < actionQueueDepth-1; i++ {
		name := fmt.Sprintf("p%02d", i)
		e.actions <- plannedAction{policyName: name}
		e.counters.queueDepth.Add(1)
		want = append(want, name)
	}
	// Stale same-policy entry; it must be DROPPED (superseded), freeing the slot
	// the new "z" will occupy at the TAIL.
	e.actions <- plannedAction{policyName: "z"}
	e.counters.queueDepth.Add(1)

	// New "z" trigger cannot fit (queue full); enqueue() falls into supersede().
	// The stale "z" is dropped and the new "z" is re-placed: the queue must end
	// up holding every other-policy entry in FIFO order plus "z" at the tail.
	e.enqueue(plannedAction{policyName: "z"})
	want = append(want, "z")

	if got := int(e.counters.queueDepth.Load()); got != len(want) {
		t.Fatalf("queueDepth=%d; want %d (no action should be dropped)", got, len(want))
	}

	// Drain in dequeue (FIFO) order and compare against the expected sequence.
	got := make([]string, 0, len(want))
	for {
		select {
		case a := <-e.actions:
			got = append(got, a.policyName)
			continue
		default:
		}
		break
	}

	if len(got) != len(want) {
		t.Fatalf("drained %d actions; want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("queue order wrong at index %d: got %q, want %q\nfull got=%v\nwant=%v",
				i, got[i], want[i], got, want)
		}
	}
	if got[len(got)-1] != "z" {
		t.Errorf("superseding action not at tail: tail=%q want %q", got[len(got)-1], "z")
	}
	if got[0] == "z" {
		t.Errorf("superseding action prepended to head (LIFO regression, #2869)")
	}
}

// #2869 metrics single-count: in the all-distinct-overflow case (queue full of
// DISTINCT policies, a new DISTINCT policy arrives, NO same-policy stale entry
// to evict), the new action is genuinely unfittable and must be dropped — but
// exactly ONCE on xpf_event_actions_dropped_total{reason="queue_full"}.
// supersede() returns false (it could not place `a` and evicted nothing), so
// enqueue() owns the single count + warn; supersede() must NOT also count the
// overflow of `a` itself in its refill `default` branch.
//
// FAIL-ON-REVERT: remove the `if item.policyName != a.policyName` guard around
// supersede()'s refill `default` increment and this test goes RED — the drop is
// counted twice (delta == 2).
func TestSupersede_AllDistinctOverflowCountsDropOnce(t *testing.T) {
	e := New(nil, nil)
	defer e.Close()

	// Fill the bounded queue completely with DISTINCT other-policy actions; no
	// same-policy entry exists for the incoming action, so supersede() can evict
	// nothing and the new action cannot be re-placed.
	for i := 0; i < actionQueueDepth; i++ {
		e.actions <- plannedAction{policyName: fmt.Sprintf("p%02d", i)}
		e.counters.queueDepth.Add(1)
	}

	before := e.counters.droppedQueueFull.Load()

	// A new DISTINCT policy arrives; enqueue() -> supersede() -> drop (no evict).
	e.enqueue(plannedAction{policyName: "z"})

	delta := e.counters.droppedQueueFull.Load() - before
	if delta != 1 {
		t.Fatalf("droppedQueueFull delta=%d; want exactly 1 (a single dropped action must not double-count, #2869)", delta)
	}

	// The queue must be unchanged: every original distinct action still present,
	// none evicted to make room for the unfittable new arrival (correct FIFO:
	// drop the new arrival, keep the older survivors).
	if got := int(e.counters.queueDepth.Load()); got != actionQueueDepth {
		t.Errorf("queueDepth=%d; want %d (no survivor should be evicted for an unfittable new arrival)", got, actionQueueDepth)
	}
}
