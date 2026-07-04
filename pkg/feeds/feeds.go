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

// retainForever is the sentinel holdInterval meaning "never auto-drop the
// last-good snapshot to empty on persistent failure". This is the DEFAULT
// (operator decision, #2050): a stale DENYLIST that fail-OPENs to empty is
// worse than a stale-but-enforced set, so an unset/zero hold-interval retains
// the last-good snapshot INDEFINITELY. The drop-after-N-seconds behaviour is
// now strictly opt-in via an explicit positive hold-interval.
const retainForever time.Duration = 0

// maxLineBytes is the per-line scanner token cap. The default bufio.Scanner cap
// is 64 KB; a single overlong line silently truncates the whole set with the
// default cap, so we raise it. A line longer than this is treated as a failed
// fetch (bufio.ErrTooLong) rather than a silent truncation — see fetchFeed.
const maxLineBytes = 1 << 20 // 1 MiB

// maxInvalidSample bounds how many distinct malformed lines are retained for
// operator display (#2993). A degraded feed records the total invalid-line
// count plus a small verbatim sample so an operator can identify the bad lines
// without the sample growing unbounded for a wholesale-garbage body.
const maxInvalidSample = 5

// maxFeedBodyBytes caps the total HTTP response body a single feed fetch will
// buffer (#3934). Without a cap, a feed server that returns a huge (or
// infinite/chunked) body — or a MITM on a plaintext-http feed URL — can make
// the fetcher buffer an arbitrarily large body into memory and OOM the daemon
// (a remote-triggerable DoS). The body is read through an io.LimitReader; a
// body exceeding this cap fails the whole fetch (retain last-good) rather than
// buffering unboundedly. 32 MiB is comfortably above any legitimate CIDR feed
// yet well under the 64 MiB userspace-dp control-request cap
// (MaxControlRequestBytes, #2744) so a single feed cannot dominate the apply
// snapshot.
const maxFeedBodyBytes = 32 << 20 // 32 MiB

// maxFeedPrefixes caps the number of parsed entries a single feed may install
// (#3934). This is a secondary guard on top of the byte cap: a body of many
// short lines (e.g. bare IPv4 addresses) can stay under the byte cap while
// producing an entry count that would blow the dataplane address-book map. A
// feed exceeding this count fails the whole fetch (retain last-good) — a
// partial-but-huge set is never installed. The count is measured on parsed
// (pre-dedup) entries so memory is bounded during the parse loop.
const maxFeedPrefixes = 1 << 20 // 1,048,576 entries

// httpClientTimeout bounds a single feed fetch end-to-end (connect + headers +
// body read), so a slow-loris feed server that dribbles bytes cannot hold the
// fetch open indefinitely (#3934). The next refresh tick retries.
const httpClientTimeout = 30 * time.Second

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
	name string // feed-name or server name
	url  string // fully resolved URL
	// holdInterval is the retain-last-good window on persistent fetch failure.
	// retainForever (0) — the default — means NEVER auto-drop the last-good
	// snapshot to empty; only an explicit positive value arms the
	// drop-after-N-seconds opt-in.
	holdInterval time.Duration

	// Active enforced snapshot (canonicalized, deduped, sorted).
	prefixes    []string
	hash        [32]byte // sha256 over the canonical join; zero when no snapshot
	hasSnapshot bool     // true once a good fetch has installed a snapshot

	// Parse-quality of the INSTALLED snapshot (#2993). A feed body may mix
	// valid + invalid lines: the valid prefixes are installed but the skipped
	// invalid lines are no longer silent. invalidLines counts every malformed
	// line in the last successfully-installed body; invalidSample keeps up to
	// maxInvalidSample verbatim offenders for display. Both are zero/nil for a
	// clean body (no behaviour change) and are cleared on a drop-to-empty.
	invalidLines  int
	invalidSample []string

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
			Timeout: httpClientTimeout,
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

// warnPlaintextFeed emits a one-time (per Apply) warning when a feed URL uses
// plaintext http:// (#3934). A plaintext feed has no transport integrity: a
// MITM can substitute an arbitrary body (including an over-size body aimed at
// the OOM path guarded by maxFeedBodyBytes, or a hostile prefix set). https
// is strongly preferred for any denylist/allowlist source.
func warnPlaintextFeed(name, url string) {
	if strings.HasPrefix(strings.ToLower(url), "http://") {
		slog.Warn("dynamic-address: feed URL is plaintext http (no integrity — a MITM can substitute the feed body); prefer https",
			"name", name, "url", url)
	}
}

// resolveHoldInterval maps the configured hold-interval (seconds) to a
// duration. An UNSET (zero) or negative value means retainForever — the
// last-good snapshot is kept indefinitely on persistent failure, never
// auto-dropped to empty (#2050 operator decision: never fail-OPEN a stale
// denylist). Only an explicit positive value arms the drop-after-N-seconds
// opt-in.
func resolveHoldInterval(seconds int) time.Duration {
	if seconds <= 0 {
		return retainForever
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
		// Human-readable hold for the start log: retainForever (the default)
		// would otherwise log as "0s".
		holdStr := "forever"
		if hold > 0 {
			holdStr = hold.String()
		}

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
				warnPlaintextFeed(fe.Name, feedURL)
				go m.refreshLoop(feedCtx, fs, interval)
				slog.Info("dynamic address feed started",
					"name", fe.Name, "server", fsCfg.Name, "url", feedURL,
					"interval", interval, "hold", holdStr)
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
			warnPlaintextFeed(key, baseURL)
			go m.refreshLoop(feedCtx, fs, interval)
			slog.Info("dynamic address feed started",
				"name", key, "url", baseURL, "interval", interval, "hold", holdStr)
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
//
// While a last-good snapshot is installed it is returned (retained
// indefinitely by default on persistent failure; see holdInterval). Before
// the first successful fetch — and after an explicit hold-interval drop —
// there is no snapshot and a non-nil empty slice is returned (fail-closed),
// so callers and JSON encoders see [] rather than null. An unknown feed name
// returns nil.
func (m *Manager) GetPrefixes(name string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if fs, ok := m.feeds[name]; ok {
		// Always return a non-nil slice for a known feed so a feed with no
		// installed snapshot marshals as [] (empty), not null. Copying with a
		// zero-cap make keeps the empty case non-nil.
		out := make([]string, len(fs.prefixes))
		copy(out, fs.prefixes)
		return out
	}
	return nil
}

// SnapshotForBindings resolves each dynamic-address binding to the union of
// its feed-backed prefixes, returning a deep copy keyed by address-name. This
// is the ENFORCEMENT accessor (#2049): the daemon hands the result into the
// userspace dataplane manager, which overlays the prefixes into the address
// book the AF_XDP helper enforces. It is the first production caller of the
// per-feed prefix snapshot — before #2049 the fetched prefixes were
// status-only and never reached the forwarding path.
//
// Resolution semantics:
//   - A binding's FeedNames are unioned (a binding may aggregate several
//     feeds). Prefixes are deduped across feeds and returned sorted.
//   - A feed with no installed snapshot (before first fetch, or after an
//     explicit hold-interval drop) contributes nothing; if NONE of a
//     binding's feeds have prefixes the entry maps to a non-nil empty slice,
//     so the caller can tell "bound but empty" (fail-closed: matches nothing)
//     from "not a feed binding" (absent from the map).
//   - An unknown feed-name (binding references a feed that was never started)
//     contributes nothing — it is treated the same as an empty feed.
//
// Reading the live last-good snapshot here means a persistent fetch failure
// keeps enforcing the retained prefixes (the #2050 fail-safe), and the
// startup window before the first fetch enforces an empty set — both are the
// caller's responsibility to surface; this accessor only joins the data.
func (m *Manager) SnapshotForBindings(daCfg *config.DynamicAddressConfig) map[string][]string {
	if daCfg == nil || len(daCfg.AddressBindings) == 0 {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string][]string, len(daCfg.AddressBindings))
	for name, binding := range daCfg.AddressBindings {
		if binding == nil {
			continue
		}
		// Dedup across the binding's feeds; deep-copy from the live state.
		seen := make(map[string]struct{})
		merged := make([]string, 0)
		for _, feedName := range binding.FeedNames {
			fs, ok := m.feeds[feedName]
			if !ok {
				continue
			}
			for _, p := range fs.prefixes {
				if _, dup := seen[p]; dup {
					continue
				}
				seen[p] = struct{}{}
				merged = append(merged, p)
			}
		}
		sort.Strings(merged)
		out[name] = merged
	}
	return out
}

// AllFeeds returns a snapshot of all feed states for display.
func (m *Manager) AllFeeds() map[string]FeedInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]FeedInfo, len(m.feeds))
	for name, fs := range m.feeds {
		// Copilot #1: surface "" (not 64 zero-hex chars) when no snapshot is
		// installed (before first fetch, or after an explicit hold-interval
		// drop). The zero [32]byte would otherwise format as all-zero hex and
		// masquerade as a real digest.
		hash := ""
		if fs.hasSnapshot {
			hash = fmt.Sprintf("%x", fs.hash)
		}
		result[name] = FeedInfo{
			URL:           fs.url,
			Prefixes:      len(fs.prefixes),
			LastFetch:     fs.lastFetch,
			LastSuccess:   fs.lastSuccess,
			LastError:     fs.lastError,
			StaleSince:    fs.staleSince,
			Hash:          hash,
			InvalidLines:  fs.invalidLines,
			InvalidSample: append([]string(nil), fs.invalidSample...),
			Degraded:      fs.invalidLines > 0,
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
	// StaleSince is set when a RETAINED last-good snapshot started being
	// served as stale (first failure after a good fetch) and is zero when no
	// snapshot is being retained as stale — i.e. zero before the first good
	// fetch, while the current fetch is fresh, and after an explicit
	// hold-interval drop cleared the retained snapshot.
	StaleSince time.Time
	Hash       string // hex sha256 of the canonical prefix set ("" if none)

	// Parse-quality of the installed snapshot (#2993). InvalidLines is the
	// number of malformed lines skipped while parsing the last
	// successfully-installed body; InvalidSample is a bounded verbatim sample
	// of those lines. Degraded is true when InvalidLines > 0 — the feed
	// installed a PARTIAL set (some published lines were dropped), which an
	// operator should investigate even though valid prefixes are enforced.
	InvalidLines  int
	InvalidSample []string
	Degraded      bool
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

	// invalidLines counts malformed lines skipped during parse; invalidSample
	// holds up to maxInvalidSample verbatim offenders (#2993). A clean body
	// leaves both zero/nil.
	invalidLines  int
	invalidSample []string
}

// fetchFeed performs a single GET, parses + canonicalizes the body, and applies
// it to the feed state. A fetch is considered SUCCESSFUL only if the transport
// read completes without error AND the parsed set is non-empty. On any failure
// the last-good snapshot is RETAINED — indefinitely by default, or until an
// explicit positive hold-interval elapses (the opt-in drop-to-empty).
// lastFetch/lastSuccess are stamped only on success.
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
// line), an over-size body / over-count entry set (maxFeedBodyBytes /
// maxFeedPrefixes, #3934), or a zero-prefix successful response (treated as
// suspect — a hijacked or misconfigured endpoint serving an empty body must
// not silently wipe an enforced set). The transport itself is bounded by the
// client's httpClientTimeout (slow-loris protection).
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

// countingReader wraps an io.Reader and tracks the total number of bytes read
// through it, so parseFeed can DETECT (not merely truncate at) an over-size
// body: the body is read through io.LimitReader(r, maxFeedBodyBytes+1), and if
// the counter passes maxFeedBodyBytes the feed exceeded the cap (#3934).
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// parseFeed reads CIDR/IP lines from r and returns a canonicalized set.
// Reads io.Reader (not http.Response) so it is unit-testable in isolation.
//
// The body is bounded on TWO axes (#3934) so a huge/infinite body or a MITM on
// a plaintext-http feed cannot OOM the daemon:
//   - total bytes: read through io.LimitReader(r, maxFeedBodyBytes+1); a body
//     larger than maxFeedBodyBytes fails the whole fetch (retain last-good),
//   - parsed entries: a body producing more than maxFeedPrefixes parsed entries
//     fails the whole fetch (never install a partial-but-huge set).
//
// Both over-limit conditions return an error so fetchFeed→recordFailure keeps
// the last-good snapshot rather than wiping or truncating the enforced set.
func parseFeed(r io.Reader) (fetchResult, error) {
	var prefixes []string
	var invalidLines int
	var invalidSample []string
	// Cap the total bytes buffered. Read one byte past the cap so a body that
	// exactly fills the cap is accepted while anything larger is detected.
	cr := &countingReader{r: io.LimitReader(r, maxFeedBodyBytes+1)}
	scanner := bufio.NewScanner(cr)
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
		} else {
			// A non-comment line that is neither a CIDR nor a bare IP. Feed
			// providers occasionally emit stray text, but a malformed line can
			// also be THE line that matters for a denylist (#2993). We still
			// skip it (the published valid prefixes are installed), but it is no
			// longer silent: count it and keep a bounded sample so the fetch is
			// observably degraded rather than reporting a clean success.
			invalidLines++
			if len(invalidSample) < maxInvalidSample {
				invalidSample = append(invalidSample, line)
			}
		}
		// Entry cap: bail as soon as the parsed set exceeds the per-feed limit
		// so the slice memory stays bounded during the loop and a huge feed is
		// rejected rather than truncated-and-installed (#3934).
		if len(prefixes) > maxFeedPrefixes {
			return fetchResult{}, fmt.Errorf("feed exceeds max entry count %d", maxFeedPrefixes)
		}
	}
	if err := scanner.Err(); err != nil {
		// Overlong line (bufio.ErrTooLong) or transport read error mid-stream.
		// Treat the entire read as failed — never install a truncated set.
		return fetchResult{}, fmt.Errorf("read body: %w", err)
	}
	if cr.n > maxFeedBodyBytes {
		// Body exceeded the size cap (the LimitReader delivered the extra
		// sentinel byte). Fail the whole fetch — never install a truncated set,
		// and keep the last-good snapshot (#3934).
		return fetchResult{}, fmt.Errorf("feed body exceeds max size %d bytes", maxFeedBodyBytes)
	}

	canon := canonicalize(prefixes)
	if len(canon) == 0 {
		// Zero-prefix HTTP-200: suspect. Retain last-good rather than installing
		// an empty set that would fail-open an enforced denylist.
		return fetchResult{}, fmt.Errorf("feed returned no usable prefixes")
	}

	return fetchResult{
		prefixes:      canon,
		hash:          hashPrefixes(canon),
		invalidLines:  invalidLines,
		invalidSample: invalidSample,
	}, nil
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
	fs.invalidLines = res.invalidLines
	fs.invalidSample = res.invalidSample
	m.mu.Unlock()

	slog.Info("dynamic-address: feed updated",
		"name", fs.name, "prefixes", len(res.prefixes), "previous", oldCount,
		"changed", changed, "invalid_lines", res.invalidLines)

	// A degraded install (some published lines skipped) is loud, but only on a
	// content change so a persistently-malformed-but-stable feed does not flood
	// the journal on every refresh tick (#2993). The per-fetch invalid count is
	// always carried in the Info line above and surfaced via FeedInfo.
	if changed && res.invalidLines > 0 {
		slog.Warn("dynamic-address: feed installed a PARTIAL set — skipped invalid lines (degraded)",
			"name", fs.name, "prefixes", len(res.prefixes),
			"invalid_lines", res.invalidLines, "invalid_sample", res.invalidSample)
	}

	if changed && m.onUpdate != nil {
		m.onUpdate()
	}
}

// recordFailure handles a failed fetch under the retain-last-good policy:
//   - records LastError (does NOT stamp lastFetch/lastSuccess),
//   - if a good snapshot is being retained, sets StaleSince on the first
//     failure (the feed ENTERING stale) and keeps the snapshot,
//   - by DEFAULT (holdInterval == retainForever) the snapshot is retained
//     INDEFINITELY — never auto-dropped to empty, because a stale-but-enforced
//     denylist beats a fail-OPEN empty one (#2050 operator decision),
//   - ONLY when an explicit positive hold-interval is configured AND it has
//     elapsed (measured from StaleSince) is the snapshot dropped to empty
//     (fail-closed) with an onUpdate so enforcement sees the now-empty set;
//     StaleSince is then cleared (no snapshot is retained as stale anymore,
//     Copilot #2).
//
// A one-time slog.Warn fires when the feed first ENTERS the stale state, not
// on every failing tick, so a persistently-down feed does not flood the log.
func (m *Manager) recordFailure(fs *feedState, ferr error) {
	m.mu.Lock()
	now := m.now()
	fs.lastError = ferr.Error()

	enteredStale := false
	dropped := false
	if fs.hasSnapshot && len(fs.prefixes) > 0 {
		if fs.staleSince.IsZero() {
			fs.staleSince = now
			enteredStale = true
		}
		// retainForever (the default) never drops; only an explicit positive
		// hold-interval arms the timed drop-to-empty.
		if fs.holdInterval > 0 && now.Sub(fs.staleSince) >= fs.holdInterval {
			fs.prefixes = nil
			fs.hash = [32]byte{}
			fs.hasSnapshot = false
			// Copilot #2: no snapshot is retained as stale anymore — clear
			// StaleSince so FeedInfo.StaleSince matches its docstring.
			fs.staleSince = time.Time{}
			// No snapshot remains, so its parse-quality is meaningless — clear
			// the degraded markers too (#2993).
			fs.invalidLines = 0
			fs.invalidSample = nil
			dropped = true
		}
	}
	m.mu.Unlock()

	switch {
	case dropped:
		slog.Warn("dynamic-address: hold interval elapsed, dropping stale feed to empty",
			"name", fs.name, "err", ferr, "hold", fs.holdInterval)
		if m.onUpdate != nil {
			m.onUpdate()
		}
	case enteredStale:
		// One-time loud warning on entry to the stale state. Subsequent
		// failing ticks are logged at Debug to avoid flooding the journal for
		// a persistently-down feed.
		slog.Warn("dynamic-address: feed entered STALE — fetch failed, retaining last-good snapshot",
			"name", fs.name, "err", ferr, "retain",
			func() string {
				if fs.holdInterval > 0 {
					return fs.holdInterval.String()
				}
				return "forever"
			}())
	default:
		slog.Debug("dynamic-address: fetch failed, retaining last-good",
			"name", fs.name, "err", ferr)
	}
}
