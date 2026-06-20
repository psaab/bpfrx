package feeds

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// bodyServer returns an httptest server serving a fixed body with the given
// status. The pointer fields let a test swap the response between fetches.
type bodyServer struct {
	mu     sync.Mutex
	body   string
	status int
}

func (b *bodyServer) set(body string, status int) {
	b.mu.Lock()
	b.body, b.status = body, status
	b.mu.Unlock()
}

func (b *bodyServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		b.mu.Lock()
		body, status := b.body, b.status
		b.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// newFeed wires a feedState pointing at url with the given hold window and
// registers it on the manager so AllFeeds/GetPrefixes see it.
func (m *Manager) newFeed(name, url string, hold time.Duration) *feedState {
	fs := &feedState{name: name, url: url, holdInterval: hold}
	m.mu.Lock()
	m.feeds[name] = fs
	m.mu.Unlock()
	return fs
}

// --- parseFeed / canonicalization ---

func TestParseFeedCanonicalizesAndDedups(t *testing.T) {
	body := strings.Join([]string{
		"# a comment",
		"// another comment",
		"192.0.2.5/24", // masked -> 192.0.2.0/24
		"192.0.2.7/24", // duplicate after masking
		"203.0.113.4",  // bare v4 -> /32
		"2001:db8::1",  // bare v6 -> /128
		"not-an-ip",    // skipped silently
		"",
	}, "\n")

	res, err := parseFeed(bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("parseFeed error: %v", err)
	}
	want := []string{"192.0.2.0/24", "203.0.113.4/32", "2001:db8::1/128"}
	// canonicalize sorts; compute the sorted want for stable comparison.
	got := res.prefixes
	if len(got) != len(want) {
		t.Fatalf("got %d prefixes %v, want %d %v", len(got), got, len(want), want)
	}
	gotSet := map[string]bool{}
	for _, p := range got {
		gotSet[p] = true
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing canonical prefix %q in %v", w, got)
		}
	}
}

func TestParseFeedZeroPrefixIsError(t *testing.T) {
	// HTTP 200 with only comments / junk -> zero usable prefixes -> suspect.
	res, err := parseFeed(bytes.NewBufferString("# only comments\n// nothing\nbad-line\n"))
	if err == nil {
		t.Fatalf("expected error for zero-prefix body, got prefixes %v", res.prefixes)
	}
}

// TestParseFeedOverlongLineErrors targets the bufio.ErrTooLong / scanner.Err()
// fix. Pre-fix this returned a (possibly truncated) set with no error.
func TestParseFeedOverlongLineErrors(t *testing.T) {
	var b strings.Builder
	b.WriteString("192.0.2.0/24\n")
	// A single line longer than the scanner token cap.
	b.WriteString(strings.Repeat("a", maxLineBytes+1))
	b.WriteString("\n")

	_, err := parseFeed(strings.NewReader(b.String()))
	if err == nil {
		t.Fatal("expected scanner error for overlong line, got nil (silent truncation)")
	}
}

// --- content-based change detection ---

// TestSameCountContentChangeFires is the core #2050 bug test: a content swap
// with identical count must fire onUpdate. The old code compared len only.
func TestSameCountContentChangeFires(t *testing.T) {
	var calls atomic.Int32
	m := New(func() { calls.Add(1) })

	srv := &bodyServer{}
	srv.set("192.0.2.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	ctx := context.Background()

	m.fetchFeed(ctx, fs) // initial install
	if got := calls.Load(); got != 1 {
		t.Fatalf("initial fetch: onUpdate calls = %d, want 1", got)
	}

	// Same COUNT (1 prefix), different CONTENT.
	srv.set("198.51.100.0/24\n", http.StatusOK)
	m.fetchFeed(ctx, fs)
	if got := calls.Load(); got != 2 {
		t.Fatalf("same-count content swap: onUpdate calls = %d, want 2 (content change must fire)", got)
	}
	if got := m.GetPrefixes("f"); len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("snapshot not replaced: got %v", got)
	}
}

func TestIdenticalContentDoesNotFire(t *testing.T) {
	var calls atomic.Int32
	m := New(func() { calls.Add(1) })

	srv := &bodyServer{}
	// Same prefixes in a different order each fetch -> canonical hash identical.
	srv.set("192.0.2.0/24\n10.0.0.0/8\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	ctx := context.Background()

	m.fetchFeed(ctx, fs)
	if got := calls.Load(); got != 1 {
		t.Fatalf("initial fetch calls = %d, want 1", got)
	}

	srv.set("10.0.0.0/8\n192.0.2.0/24\n", http.StatusOK) // reordered, same set
	m.fetchFeed(ctx, fs)
	if got := calls.Load(); got != 1 {
		t.Fatalf("identical-content (reordered) refetch fired onUpdate %d times, want still 1", got)
	}
}

// --- no-stamp-on-partial / no-replace-on-error ---

// TestErrorRetainsSnapshotNoStamp targets behaviors 1 + 4: a failed fetch must
// not replace the snapshot and must not stamp lastFetch/lastSuccess.
func TestErrorRetainsSnapshotNoStamp(t *testing.T) {
	var calls atomic.Int32
	m := New(func() { calls.Add(1) })

	srv := &bodyServer{}
	srv.set("192.0.2.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	ctx := context.Background()

	m.fetchFeed(ctx, fs)
	goodStamp := fs.lastFetch
	if goodStamp.IsZero() {
		t.Fatal("expected lastFetch stamped on success")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}

	// Now serve an error (500).
	srv.set("hijacked-garbage", http.StatusInternalServerError)
	m.fetchFeed(ctx, fs)

	if fs.lastFetch != goodStamp {
		t.Errorf("lastFetch re-stamped on failed fetch: was %v now %v", goodStamp, fs.lastFetch)
	}
	if fs.lastError == "" {
		t.Error("expected lastError recorded on failed fetch")
	}
	if got := m.GetPrefixes("f"); len(got) != 1 || got[0] != "192.0.2.0/24" {
		t.Errorf("snapshot replaced on failed fetch: got %v, want last-good [192.0.2.0/24]", got)
	}
	if calls.Load() != 1 {
		t.Errorf("onUpdate fired on failed fetch within hold: calls = %d, want 1", calls.Load())
	}
}

// TestZeroPrefixRetainsLastGood targets behavior 5's zero-prefix case: an
// HTTP-200 empty body must NOT wipe the enforced set; it is treated as suspect.
func TestZeroPrefixRetainsLastGood(t *testing.T) {
	var calls atomic.Int32
	m := New(func() { calls.Add(1) })

	srv := &bodyServer{}
	srv.set("203.0.113.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	ctx := context.Background()
	m.fetchFeed(ctx, fs)

	// HTTP 200 with an empty body (or only comments) -> retain last-good.
	srv.set("# emptied feed\n", http.StatusOK)
	m.fetchFeed(ctx, fs)

	if got := m.GetPrefixes("f"); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Errorf("zero-prefix 200 wiped enforced set: got %v, want last-good", got)
	}
	if fs.lastError == "" {
		t.Error("expected lastError set for zero-prefix fetch")
	}
}

// --- HoldInterval retain-then-drop ---

// TestHoldIntervalRetainThenDrop targets behavior 5: retain last-good within
// HoldInterval, then drop to empty (fail-closed) after it elapses.
func TestHoldIntervalRetainThenDrop(t *testing.T) {
	var calls atomic.Int32
	m := New(func() { calls.Add(1) })

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var nowMu sync.Mutex
	cur := base
	m.now = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return cur
	}
	advance := func(d time.Duration) {
		nowMu.Lock()
		cur = cur.Add(d)
		nowMu.Unlock()
	}

	srv := &bodyServer{}
	srv.set("203.0.113.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	const hold = 60 * time.Second
	fs := m.newFeed("f", ts.URL, hold)
	ctx := context.Background()

	m.fetchFeed(ctx, fs) // good snapshot at base
	if calls.Load() != 1 {
		t.Fatalf("install calls = %d, want 1", calls.Load())
	}

	// Start failing.
	srv.set("nope", http.StatusBadGateway)

	// First failure: sets staleSince, retains snapshot. (t=base)
	m.fetchFeed(ctx, fs)
	if got := m.GetPrefixes("f"); len(got) != 1 {
		t.Fatalf("first failure dropped snapshot early: got %v", got)
	}
	if fs.staleSince.IsZero() {
		t.Fatal("staleSince not set on first failure")
	}

	// Within hold window (t=base+30s): still retained.
	advance(30 * time.Second)
	m.fetchFeed(ctx, fs)
	if got := m.GetPrefixes("f"); len(got) != 1 {
		t.Fatalf("snapshot dropped within hold window: got %v", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("onUpdate fired during retain window: calls = %d, want 1", calls.Load())
	}

	// At/after hold window (t=base+60s): drop to empty + fire onUpdate.
	advance(30 * time.Second)
	m.fetchFeed(ctx, fs)
	if got := m.GetPrefixes("f"); len(got) != 0 {
		t.Fatalf("snapshot not dropped after hold elapsed: got %v", got)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected onUpdate on drop-to-empty: calls = %d, want 2", calls.Load())
	}
}

// TestStartupNoSnapshotFailClosed targets behavior 5 startup semantics: before
// any good fetch, a failing feed has no snapshot and GetPrefixes is empty.
func TestStartupNoSnapshotFailClosed(t *testing.T) {
	m := New(func() {})
	srv := &bodyServer{}
	srv.set("nope", http.StatusInternalServerError)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	m.fetchFeed(context.Background(), fs)

	if got := m.GetPrefixes("f"); len(got) != 0 {
		t.Fatalf("startup-before-first-fetch not fail-closed: got %v", got)
	}
	if fs.hasSnapshot {
		t.Error("hasSnapshot true with no successful fetch")
	}
	if fs.lastError == "" {
		t.Error("expected lastError recorded on startup failure")
	}
}

// TestAllFeedsStatusFields confirms the additive status fields surface.
func TestAllFeedsStatusFields(t *testing.T) {
	m := New(func() {})
	srv := &bodyServer{}
	srv.set("192.0.2.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("office", ts.URL, time.Hour)
	m.fetchFeed(context.Background(), fs)

	info := m.AllFeeds()["office"]
	if info.Prefixes != 1 {
		t.Errorf("Prefixes = %d, want 1", info.Prefixes)
	}
	if info.LastSuccess.IsZero() || info.LastFetch.IsZero() {
		t.Error("LastSuccess/LastFetch not stamped")
	}
	if info.Hash == "" || info.Hash == strings.Repeat("0", 64) {
		t.Errorf("Hash not populated: %q", info.Hash)
	}
	if info.LastError != "" {
		t.Errorf("LastError unexpectedly set: %q", info.LastError)
	}
}
