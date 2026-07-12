package feeds

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestRejectedApplyRetriesOnIdenticalRefetch is the #5646 fail-on-revert test.
//
// installSnapshot must (re-)fire the publish callback (onUpdate) whenever the
// fetched content differs from what was last SUCCESSFULLY applied — not merely
// from the last FETCH. The pre-#5646 code committed the content hash and then
// fired a VOID callback, so a REJECTED apply (preflight reject, compile
// failure, control-socket error) left the hash committed; a later identical
// refetch then saw "unchanged" and skipped onUpdate → the good content was
// never enforced (publication debt).
//
// RED-on-revert: on pre-fix code the second (identical) fetch does NOT re-fire
// onUpdate because the content hash already matched, so calls stays at 1 and
// this test FAILS at fetch#2. On fixed code the rejected first apply leaves
// publishedHash stale, so the identical refetch re-fires and the retry succeeds.
func TestRejectedApplyRetriesOnIdenticalRefetch(t *testing.T) {
	var calls atomic.Int32
	var rejectNext atomic.Bool
	rejectNext.Store(true) // reject the FIRST apply, accept the rest
	m := New(func() error {
		calls.Add(1)
		if rejectNext.Swap(false) {
			return fmt.Errorf("synthetic apply rejection (preflight/compile/control-socket)")
		}
		return nil
	})

	srv := &bodyServer{}
	srv.set("192.0.2.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	ctx := context.Background()

	// Fetch #1: content installed, onUpdate fires, apply REJECTED. The content
	// is installed (enforced-in-intent) but must NOT be recorded as published.
	m.fetchFeed(ctx, fs)
	if got := calls.Load(); got != 1 {
		t.Fatalf("fetch#1: onUpdate calls = %d, want 1", got)
	}
	if fs.hasPublished {
		t.Fatalf("fetch#1: a rejected apply must NOT mark content published (publishedHash must stay stale so the next refetch retries)")
	}
	if got := m.GetPrefixes("f"); len(got) != 1 || got[0] != "192.0.2.0/24" {
		t.Fatalf("fetch#1: content not installed: got %v", got)
	}

	// Fetch #2: IDENTICAL content. Pre-fix: the content hash already matches, so
	// onUpdate is skipped (calls stays 1) → publication debt, good content never
	// re-applied. Fixed: publishedHash is still stale, so onUpdate RE-FIRES
	// (retry); this time the apply succeeds and the content is recorded as
	// published.
	m.fetchFeed(ctx, fs)
	if got := calls.Load(); got != 2 {
		t.Fatalf("fetch#2 (identical content, retry after rejected apply): onUpdate calls = %d, want 2 — a rejected apply MUST be retried on an identical refetch, not suppressed as publication debt", got)
	}
	if !fs.hasPublished {
		t.Fatalf("fetch#2: a successful retry must mark content published")
	}

	// Fetch #3: IDENTICAL content, already successfully published → must NOT
	// re-fire onUpdate (no thrash / no busy-loop on a stable, applied feed).
	m.fetchFeed(ctx, fs)
	if got := calls.Load(); got != 2 {
		t.Fatalf("fetch#3 (identical content, already published): onUpdate calls = %d, want still 2 — a successfully-applied feed must not re-fire (no thrash)", got)
	}
}

// TestSuccessfulApplyThenIdenticalRefetchDoesNotThrash pins the no-thrash
// guarantee independent of any rejection: a feed whose FIRST apply is accepted
// must not re-fire onUpdate on an identical refetch. This is the counterpart to
// the retry-on-rejection behaviour and guards against a fix that over-fires.
func TestSuccessfulApplyThenIdenticalRefetchDoesNotThrash(t *testing.T) {
	var calls atomic.Int32
	m := New(func() error { calls.Add(1); return nil })

	srv := &bodyServer{}
	srv.set("203.0.113.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	ctx := context.Background()

	m.fetchFeed(ctx, fs) // install + apply accepted
	m.fetchFeed(ctx, fs) // identical refetch — must be suppressed
	m.fetchFeed(ctx, fs) // identical refetch — must be suppressed
	if got := calls.Load(); got != 1 {
		t.Fatalf("identical successful refetches fired onUpdate %d times, want 1 (no thrash)", got)
	}
	if !fs.hasPublished {
		t.Fatalf("accepted apply must mark content published")
	}
}

// TestRejectedApplyThenNewContentPublishes proves the retry decision keys off
// the LAST-PUBLISHED content, not the last fetch: after a rejected apply of set
// A, fetching a DIFFERENT set B must publish B (needsPublish is true for any
// content that was never successfully applied), and a subsequent successful
// apply advances publishedHash so an identical B refetch is then suppressed.
func TestRejectedApplyThenNewContentPublishes(t *testing.T) {
	var calls atomic.Int32
	var rejectNext atomic.Bool
	rejectNext.Store(true) // reject only the first apply
	m := New(func() error {
		calls.Add(1)
		if rejectNext.Swap(false) {
			return fmt.Errorf("synthetic apply rejection")
		}
		return nil
	})

	srv := &bodyServer{}
	srv.set("192.0.2.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	ctx := context.Background()

	m.fetchFeed(ctx, fs) // A installed, apply REJECTED (calls=1)
	if calls.Load() != 1 || fs.hasPublished {
		t.Fatalf("after rejected A: calls=%d hasPublished=%v, want 1/false", calls.Load(), fs.hasPublished)
	}

	// New content B — apply accepted this time.
	srv.set("198.51.100.0/24\n", http.StatusOK)
	m.fetchFeed(ctx, fs)
	if calls.Load() != 2 || !fs.hasPublished {
		t.Fatalf("after B: calls=%d hasPublished=%v, want 2/true", calls.Load(), fs.hasPublished)
	}
	if got := m.GetPrefixes("f"); len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("B not enforced: got %v", got)
	}

	// Identical B refetch — already published, must not re-fire.
	m.fetchFeed(ctx, fs)
	if calls.Load() != 2 {
		t.Fatalf("identical B refetch re-fired onUpdate: calls=%d, want 2", calls.Load())
	}
}
