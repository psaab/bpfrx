package eventengine

import (
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
// the action is counted as rejected. Proves the transactional all-or-nothing
// batch. On pre-fix code (best-effort apply + commit-the-residue), the first
// valid command would have been committed.
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
