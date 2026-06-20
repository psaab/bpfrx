// Package feeds implements dynamic address feed fetching and management.
package feeds

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// defaultHoldInterval is the retain-last-good window applied when a feed
// server does not configure hold-interval (0). Matches the Junos default and
// config.FeedServer.HoldInterval's documented "0 = default 7200" semantics.
const defaultHoldInterval = 2 * time.Hour

// maxLineBytes is the per-line scanner token cap. The default bufio.Scanner cap
// is 64 KB; a single overlong line silently truncates the whole set with the
// default cap, so we raise it. A line longer than this is treated as a failed
// fetch (bufio.ErrTooLong) rather than a silent truncation — see fetchFeed.
const maxLineBytes = 1 << 20 // 1 MiB

// Manager manages dynamic address feed servers and their periodic updates.
type Manager struct {
	mu       sync.RWMutex
	feeds    map[string]*feedState // keyed by feed-name (or feed-server name for single-feed servers)
	client   *http.Client
	onUpdate func() // callback when feeds are updated

	// now is the clock source, overridable in tests for HoldInterval timing.
	now func() time.Time
}

type feedState struct {
	name         string        // feed-name or server name
	url          string        // fully resolved URL
	holdInterval time.Duration // retain-last-good window on fetch failure

	// Active enforced snapshot (canonicalized, deduped, sorted).
	prefixes    []string
	hash        [32]byte // sha256 over the canonical join; zero when no snapshot
	hasSnapshot bool     // true once a good fetch has installed a snapshot

	// Fetch status (separate from the active snapshot).
	lastFetch   time.Time // last SUCCESSFUL fetch (kept name for show-path compat)
	lastSuccess time.Time // alias of lastFetch; explicit success timestamp
	lastError   string    // most recent fetch/parse error ("" when last fetch was good)
	staleSince  time.Time // set when a fetch fails while a good snapshot is retained

	cancel context.CancelFunc
}

// New creates a new feed manager.
// onUpdate is called whenever a feed refresh produces a semantically different
// prefix set (content change, not merely a count change).
func New(onUpdate func()) *Manager {
	return &Manager{
		feeds: make(map[string]*feedState),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		onUpdate: onUpdate,
		now:      time.Now,
	}
}

// resolveBaseURL returns the base URL for a feed server.
// Prefers explicit URL; falls back to https://hostname.
func resolveBaseURL(fsCfg *config.FeedServer) string {
	if fsCfg.URL != "" {
		return strings.TrimRight(fsCfg.URL, "/")
	}
	if fsCfg.Hostname != "" {
		return "https://" + strings.TrimRight(fsCfg.Hostname, "/")
	}
	return ""
}

// resolveHoldInterval maps the configured hold-interval (seconds, 0 = default)
// to a duration. A negative value is treated as the default.
func resolveHoldInterval(seconds int) time.Duration {
	if seconds <= 0 {
		return defaultHoldInterval
	}
	return time.Duration(seconds) * time.Second
}

// Apply configures feeds from the given dynamic address config.
// Starts background refresh goroutines for each feed server.
// When a feed-server has FeedEntries, each entry becomes a separate feed
// keyed by the feed-name with its per-feed path appended to the base URL.
func (m *Manager) Apply(ctx context.Context, daCfg *config.DynamicAddressConfig) {
	m.StopAll()

	if daCfg == nil || len(daCfg.FeedServers) == 0 {
		return
	}

	m.mu.Lock()
	for _, fsCfg := range daCfg.FeedServers {
		baseURL := resolveBaseURL(fsCfg)
		if baseURL == "" {
			continue
		}

		interval := time.Duration(fsCfg.UpdateInterval) * time.Second
		if interval <= 0 {
			interval = time.Hour
		}
		hold := resolveHoldInterval(fsCfg.HoldInterval)

		if len(fsCfg.FeedEntries) > 0 {
			// Multiple named feeds with per-feed paths
			for _, fe := range fsCfg.FeedEntries {
				feedURL := baseURL
				if fe.Path != "" {
					p := fe.Path
					if !strings.HasPrefix(p, "/") {
						p = "/" + p
					}
					feedURL = baseURL + p
				}
				feedCtx, cancel := context.WithCancel(ctx)
				fs := &feedState{
					name:         fe.Name,
					url:          feedURL,
					holdInterval: hold,
					cancel:       cancel,
				}
				m.feeds[fe.Name] = fs
				go m.refreshLoop(feedCtx, fs, interval)
				slog.Info("dynamic address feed started",
					"name", fe.Name, "server", fsCfg.Name, "url", feedURL,
					"interval", interval, "hold", hold)
			}
		} else {
			// Single feed (backward compat): keyed by FeedName or server name
			key := fsCfg.FeedName
			if key == "" {
				key = fsCfg.Name
			}
			feedCtx, cancel := context.WithCancel(ctx)
			fs := &feedState{
				name:         key,
				url:          baseURL,
				holdInterval: hold,
				cancel:       cancel,
			}
			m.feeds[key] = fs
			go m.refreshLoop(feedCtx, fs, interval)
			slog.Info("dynamic address feed started",
				"name", key, "url", baseURL, "interval", interval, "hold", hold)
		}
	}
	m.mu.Unlock()
}

// StopAll cancels all running feed refresh goroutines.
func (m *Manager) StopAll() {
	m.mu.Lock()
	for _, fs := range m.feeds {
		if fs.cancel != nil {
			fs.cancel()
		}
	}
	m.feeds = make(map[string]*feedState)
	m.mu.Unlock()
}

// GetPrefixes returns the current enforced prefixes for a named feed.
// Returns the last-good snapshot while it is still being retained, and nil
// once the hold window has elapsed (fail-closed) or before the first fetch.
func (m *Manager) GetPrefixes(name string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if fs, ok := m.feeds[name]; ok {
		return append([]string(nil), fs.prefixes...)
	}
	return nil
}

// AllFeeds returns a snapshot of all feed states for display.
func (m *Manager) AllFeeds() map[string]FeedInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]FeedInfo, len(m.feeds))
	for name, fs := range m.feeds {
		result[name] = FeedInfo{
			URL:         fs.url,
			Prefixes:    len(fs.prefixes),
			LastFetch:   fs.lastFetch,
			LastSuccess: fs.lastSuccess,
			LastError:   fs.lastError,
			StaleSince:  fs.staleSince,
			Hash:        fmt.Sprintf("%x", fs.hash),
		}
	}
	return result
}

// FeedInfo holds display information about a feed.
type FeedInfo struct {
	URL       string
	Prefixes  int
	LastFetch time.Time // last successful fetch (alias of LastSuccess for show-path compat)

	// Additive status fields (#2050).
	LastSuccess time.Time // last fully-successful fetch
	LastError   string    // most recent fetch/parse error, "" if last fetch was good
	StaleSince  time.Time // when the current snapshot started being retained as stale
	Hash        string    // hex sha256 of the canonical prefix set ("" if none)
}

func (m *Manager) refreshLoop(ctx context.Context, fs *feedState, interval time.Duration) {
	// Initial fetch
	m.fetchFeed(ctx, fs)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.fetchFeed(ctx, fs)
		}
	}
}

// fetchResult is the parsed outcome of a single feed read, separated from the
// snapshot-mutation step so the parse path is independently testable.
type fetchResult struct {
	prefixes []string // canonicalized, deduped, sorted
	hash     [32]byte
}

// fetchFeed performs a single GET, parses + canonicalizes the body, and applies
// it to the feed state. A fetch is considered SUCCESSFUL only if the transport
// read completes without error AND the parsed set is non-empty. On any failure
// the last-good snapshot is RETAINED until HoldInterval elapses, then dropped
// to empty (fail-closed). lastFetch/lastSuccess are stamped only on success.
func (m *Manager) fetchFeed(ctx context.Context, fs *feedState) {
	res, err := m.readFeed(ctx, fs)
	if err != nil {
		m.recordFailure(fs, err)
		return
	}
	m.installSnapshot(fs, res)
}

// readFeed issues the HTTP request and parses the body into a canonical set.
// It returns an error (and no snapshot is installed) on transport failure,
// non-200 status, a scanner error (including bufio.ErrTooLong for an overlong
// line), or a zero-prefix successful response (treated as suspect — a hijacked
// or misconfigured endpoint serving an empty body must not silently wipe an
// enforced set).
func (m *Manager) readFeed(ctx context.Context, fs *feedState) (fetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fs.url, nil)
	if err != nil {
		return fetchResult{}, fmt.Errorf("invalid URL: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return fetchResult{}, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fetchResult{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	return parseFeed(resp.Body)
}

// parseFeed reads CIDR/IP lines from r and returns a canonicalized set.
// Reads io.Reader (not http.Response) so it is unit-testable in isolation.
func parseFeed(r io.Reader) (fetchResult, error) {
	var prefixes []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// Validate + canonicalize as CIDR or plain IP.
		if _, ipNet, err := net.ParseCIDR(line); err == nil {
			// Normalize to masked network form (e.g. 192.0.2.5/24 -> 192.0.2.0/24).
			prefixes = append(prefixes, ipNet.String())
		} else if ip := net.ParseIP(line); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				prefixes = append(prefixes, fmt.Sprintf("%s/32", v4.String()))
			} else {
				prefixes = append(prefixes, fmt.Sprintf("%s/128", ip.String()))
			}
		}
		// Invalid lines are skipped (feed providers occasionally emit comments
		// or stray text); only a scanner-level error fails the whole fetch.
	}
	if err := scanner.Err(); err != nil {
		// Overlong line (bufio.ErrTooLong) or transport read error mid-stream.
		// Treat the entire read as failed — never install a truncated set.
		return fetchResult{}, fmt.Errorf("read body: %w", err)
	}

	canon := canonicalize(prefixes)
	if len(canon) == 0 {
		// Zero-prefix HTTP-200: suspect. Retain last-good rather than installing
		// an empty set that would fail-open an enforced denylist.
		return fetchResult{}, fmt.Errorf("feed returned no usable prefixes")
	}

	return fetchResult{prefixes: canon, hash: hashPrefixes(canon)}, nil
}

// canonicalize dedups and sorts the prefix list. Input prefixes are already in
// masked/normalized string form from parseFeed.
func canonicalize(prefixes []string) []string {
	if len(prefixes) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(prefixes))
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// hashPrefixes returns the sha256 of the canonical (sorted, deduped) set.
// The input must already be sorted+deduped so the hash is content-stable.
func hashPrefixes(canon []string) [32]byte {
	h := sha256.New()
	for _, p := range canon {
		h.Write([]byte(p))
		h.Write([]byte{'\n'})
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// installSnapshot replaces the active snapshot with a fresh good fetch, stamps
// success, clears stale/error state, and fires onUpdate only on a content
// change (hash differs from the currently installed snapshot).
func (m *Manager) installSnapshot(fs *feedState, res fetchResult) {
	m.mu.Lock()
	changed := !fs.hasSnapshot || fs.hash != res.hash
	oldCount := len(fs.prefixes)
	now := m.now()
	fs.prefixes = res.prefixes
	fs.hash = res.hash
	fs.hasSnapshot = true
	fs.lastFetch = now
	fs.lastSuccess = now
	fs.lastError = ""
	fs.staleSince = time.Time{}
	m.mu.Unlock()

	slog.Info("dynamic-address: feed updated",
		"name", fs.name, "prefixes", len(res.prefixes), "previous", oldCount,
		"changed", changed)

	if changed && m.onUpdate != nil {
		m.onUpdate()
	}
}

// recordFailure handles a failed fetch under the retain-last-good policy:
//   - records LastError (does NOT stamp lastFetch/lastSuccess),
//   - if a good snapshot is being retained, sets StaleSince on the first
//     failure and keeps the snapshot until HoldInterval elapses,
//   - once HoldInterval has elapsed (measured from StaleSince), drops the
//     snapshot to empty (fail-closed) and fires onUpdate so enforcement sees
//     the now-empty set.
func (m *Manager) recordFailure(fs *feedState, ferr error) {
	m.mu.Lock()
	now := m.now()
	fs.lastError = ferr.Error()

	dropped := false
	if fs.hasSnapshot && len(fs.prefixes) > 0 {
		if fs.staleSince.IsZero() {
			fs.staleSince = now
		}
		if now.Sub(fs.staleSince) >= fs.holdInterval {
			// Hold window elapsed with no good fetch: drop to empty.
			fs.prefixes = nil
			fs.hash = [32]byte{}
			fs.hasSnapshot = false
			dropped = true
		}
	}
	m.mu.Unlock()

	if dropped {
		slog.Warn("dynamic-address: hold interval elapsed, dropping stale feed to empty",
			"name", fs.name, "err", ferr, "hold", fs.holdInterval)
		if m.onUpdate != nil {
			m.onUpdate()
		}
	} else {
		slog.Warn("dynamic-address: fetch failed, retaining last-good",
			"name", fs.name, "err", ferr)
	}
}
