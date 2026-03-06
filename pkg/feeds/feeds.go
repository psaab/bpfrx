// Package feeds implements dynamic address feed fetching and management.
package feeds

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
)

// Manager manages dynamic address feed servers and their periodic updates.
type Manager struct {
	mu      sync.RWMutex
	feeds   map[string]*feedState // keyed by feed-name (or feed-server name for single-feed servers)
	client  *http.Client
	onUpdate func() // callback when feeds are updated
}

type feedState struct {
	name     string // feed-name or server name
	url      string // fully resolved URL
	prefixes []string // currently fetched CIDRs
	lastFetch time.Time
	cancel   context.CancelFunc
}

// New creates a new feed manager.
// onUpdate is called whenever a feed refresh produces new prefixes.
func New(onUpdate func()) *Manager {
	return &Manager{
		feeds: make(map[string]*feedState),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		onUpdate: onUpdate,
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
					name:   fe.Name,
					url:    feedURL,
					cancel: cancel,
				}
				m.feeds[fe.Name] = fs
				go m.refreshLoop(feedCtx, fs, interval)
				slog.Info("dynamic address feed started",
					"name", fe.Name, "server", fsCfg.Name, "url", feedURL, "interval", interval)
			}
		} else {
			// Single feed (backward compat): keyed by FeedName or server name
			key := fsCfg.FeedName
			if key == "" {
				key = fsCfg.Name
			}
			feedCtx, cancel := context.WithCancel(ctx)
			fs := &feedState{
				name:   key,
				url:    baseURL,
				cancel: cancel,
			}
			m.feeds[key] = fs
			go m.refreshLoop(feedCtx, fs, interval)
			slog.Info("dynamic address feed started",
				"name", key, "url", baseURL, "interval", interval)
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

// GetPrefixes returns the current prefixes for a named feed.
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
			URL:       fs.url,
			Prefixes:  len(fs.prefixes),
			LastFetch: fs.lastFetch,
		}
	}
	return result
}

// FeedInfo holds display information about a feed.
type FeedInfo struct {
	URL       string
	Prefixes  int
	LastFetch time.Time
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

func (m *Manager) fetchFeed(ctx context.Context, fs *feedState) {
	req, err := http.NewRequestWithContext(ctx, "GET", fs.url, nil)
	if err != nil {
		slog.Warn("dynamic-address: invalid URL", "name", fs.name, "err", err)
		return
	}

	resp, err := m.client.Do(req)
	if err != nil {
		slog.Warn("dynamic-address: fetch failed", "name", fs.name, "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("dynamic-address: unexpected status",
			"name", fs.name, "status", resp.StatusCode)
		return
	}

	var prefixes []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// Validate as CIDR or plain IP
		if _, _, err := net.ParseCIDR(line); err == nil {
			prefixes = append(prefixes, line)
		} else if ip := net.ParseIP(line); ip != nil {
			if ip.To4() != nil {
				prefixes = append(prefixes, fmt.Sprintf("%s/32", line))
			} else {
				prefixes = append(prefixes, fmt.Sprintf("%s/128", line))
			}
		}
	}

	m.mu.Lock()
	oldCount := len(fs.prefixes)
	fs.prefixes = prefixes
	fs.lastFetch = time.Now()
	m.mu.Unlock()

	slog.Info("dynamic-address: feed updated",
		"name", fs.name, "prefixes", len(prefixes), "previous", oldCount)

	if m.onUpdate != nil && len(prefixes) != oldCount {
		m.onUpdate()
	}
}
