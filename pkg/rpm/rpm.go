// Package rpm implements Real-time Performance Monitoring probes.
package rpm

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
	"golang.org/x/sys/unix"
)

// vrfDialer returns a net.Dialer bound to a VRF device via SO_BINDTODEVICE.
// The VRF device name is "vrf-" + routing instance name.
func vrfDialer(timeout time.Duration, sourceAddr string, vrfDevice string) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if sourceAddr != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(sourceAddr)}
	}
	if vrfDevice != "" {
		d.Control = func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET,
					syscall.SO_BINDTODEVICE, vrfDevice)
			})
			return err
		}
	}
	return d
}

// vrfDeviceName returns the VRF device name for a routing instance.
func vrfDeviceName(ri string) string {
	if ri == "" {
		return ""
	}
	return "vrf-" + ri
}

// ProbeResult holds the current state of a single RPM test.
type ProbeResult struct {
	ProbeName    string
	TestName     string
	ProbeType    string
	Target       string
	LastRTT      time.Duration
	MinRTT       time.Duration
	MaxRTT       time.Duration
	AvgRTT       time.Duration
	Jitter       time.Duration // running absolute deviation from average
	LastStatus   string        // "pass" or "fail"
	SuccFail     int           // consecutive failures
	TotalSent    int64
	TotalRecv    int64
	LastProbeAt  time.Time
}

// Event represents an RPM event for event-options matching.
type Event struct {
	Name      string // "ping_test_failed", "ping_probe_failed", "ping_test_completed"
	TestOwner string // probe name (matches attributes-match test-owner)
	TestName  string // test name (matches attributes-match test-name)
}

// EventCallback is called when RPM probes generate events.
type EventCallback func(Event)

// Manager runs RPM probes and tracks their results.
type Manager struct {
	mu      sync.RWMutex
	results map[string]*ProbeResult // key: "probe/test"
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	onEvent EventCallback
}

// SetEventCallback registers a callback for RPM events.
func (m *Manager) SetEventCallback(fn EventCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onEvent = fn
}

func (m *Manager) fireEvent(name, owner, testName string) {
	m.mu.RLock()
	fn := m.onEvent
	m.mu.RUnlock()
	if fn != nil {
		fn(Event{Name: name, TestOwner: owner, TestName: testName})
	}
}

// New creates a new RPM manager.
func New() *Manager {
	return &Manager{
		results: make(map[string]*ProbeResult),
	}
}

// Apply starts probes from the given RPM config.
func (m *Manager) Apply(ctx context.Context, cfg *config.RPMConfig) {
	m.StopAll()

	if cfg == nil || len(cfg.Probes) == 0 {
		return
	}

	probeCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	for _, probe := range cfg.Probes {
		for _, test := range probe.Tests {
			key := probe.Name + "/" + test.Name
			m.mu.Lock()
			m.results[key] = &ProbeResult{
				ProbeName:  probe.Name,
				TestName:   test.Name,
				ProbeType:  test.ProbeType,
				Target:     test.Target,
				LastStatus: "unknown",
			}
			m.mu.Unlock()

			m.wg.Add(1)
			go func(p *config.RPMProbe, t *config.RPMTest, k string) {
				defer m.wg.Done()
				m.runProbeLoop(probeCtx, p, t, k)
			}(probe, test, key)
		}
	}
}

// StopAll stops all running probes.
func (m *Manager) StopAll() {
	if m.cancel != nil {
		m.cancel()
		m.wg.Wait()
		m.cancel = nil
	}
	m.mu.Lock()
	m.results = make(map[string]*ProbeResult)
	m.mu.Unlock()
}

// Results returns a snapshot of all probe results, sorted by key.
func (m *Manager) Results() []*ProbeResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]string, 0, len(m.results))
	for k := range m.results {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]*ProbeResult, 0, len(keys))
	for _, k := range keys {
		r := m.results[k]
		cp := *r
		out = append(out, &cp)
	}
	return out
}

func (m *Manager) runProbeLoop(ctx context.Context, probe *config.RPMProbe, test *config.RPMTest, key string) {
	interval := time.Duration(test.TestInterval) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}

	probeInterval := time.Duration(test.ProbeInterval) * time.Second
	if probeInterval <= 0 {
		probeInterval = 5 * time.Second
	}

	probeCount := test.ProbeCount
	if probeCount <= 0 {
		probeCount = 1
	}

	threshold := test.ThresholdSuccessive
	if threshold <= 0 {
		threshold = 3
	}

	slog.Info("RPM probe started",
		"probe", probe.Name, "test", test.Name,
		"type", test.ProbeType, "target", test.Target,
		"interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run first probe immediately
	m.runSingleTest(ctx, probe.Name, test, key, probeCount, probeInterval, threshold)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.runSingleTest(ctx, probe.Name, test, key, probeCount, probeInterval, threshold)
		}
	}
}

func (m *Manager) runSingleTest(ctx context.Context, probeName string, test *config.RPMTest, key string, probeCount int, probeInterval time.Duration, threshold int) {
	var successes, failures int
	probeLimit := test.ProbeLimit // 0 = unlimited

	for i := 0; i < probeCount; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(probeInterval):
			}
		}

		rtt, err := m.executeProbe(ctx, test)

		m.mu.Lock()
		r := m.results[key]
		if r == nil {
			m.mu.Unlock()
			return
		}
		r.TotalSent++
		r.LastProbeAt = time.Now()
		prevStatus := r.LastStatus
		if err != nil {
			failures++
			r.SuccFail++
			if r.SuccFail >= threshold {
				r.LastStatus = "fail"
			}
			// Check probe-limit: stop test cycle when reached
			hitLimit := probeLimit > 0 && r.SuccFail >= probeLimit
			m.mu.Unlock()
			// Fire probe-level failure event
			m.fireEvent("ping_probe_failed", probeName, test.Name)
			// Fire test-level failure on transition
			if r.SuccFail == threshold && prevStatus != "fail" {
				m.fireEvent("ping_test_failed", probeName, test.Name)
			}
			if hitLimit {
				break
			}
		} else {
			successes++
			r.TotalRecv++
			// Track min/max/avg RTT and jitter
			if r.MinRTT == 0 || rtt < r.MinRTT {
				r.MinRTT = rtt
			}
			if rtt > r.MaxRTT {
				r.MaxRTT = rtt
			}
			prevAvg := r.AvgRTT
			if r.TotalRecv == 1 {
				r.AvgRTT = rtt
			} else {
				// Exponential moving average (alpha = 1/8 like TCP RTT)
				r.AvgRTT = prevAvg + (rtt-prevAvg)/8
			}
			// Jitter: smoothed absolute deviation (RFC 3550 style)
			diff := rtt - prevAvg
			if diff < 0 {
				diff = -diff
			}
			if r.TotalRecv == 1 {
				r.Jitter = 0
			} else {
				r.Jitter = r.Jitter + (diff-r.Jitter)/16
			}
			r.LastRTT = rtt
			r.SuccFail = 0
			r.LastStatus = "pass"
			m.mu.Unlock()
		}
	}

	// Fire test completed if all probes passed
	if failures == 0 && successes > 0 {
		m.fireEvent("ping_test_completed", probeName, test.Name)
	}
}

func (m *Manager) executeProbe(ctx context.Context, test *config.RPMTest) (time.Duration, error) {
	switch test.ProbeType {
	case "icmp-ping":
		return m.probeICMP(ctx, test)
	case "tcp-ping":
		return m.probeTCP(ctx, test)
	case "http-get":
		return m.probeHTTP(ctx, test)
	default:
		return m.probeICMP(ctx, test) // default to ICMP
	}
}

func (m *Manager) probeICMP(ctx context.Context, test *config.RPMTest) (time.Duration, error) {
	// Use TCP dial to port 7 (echo) as a simple reachability check.
	// Full ICMP requires raw sockets (CAP_NET_RAW); TCP connect is a
	// reasonable proxy that works without elevated privileges.
	target := test.Target
	start := time.Now()
	dialer := vrfDialer(3*time.Second, test.SourceAddress, vrfDeviceName(test.RoutingInstance))
	conn, err := dialer.DialContext(ctx, "ip4:icmp", target)
	if err != nil {
		// Fallback: try UDP dial which succeeds if host is reachable
		conn2, err2 := dialer.DialContext(ctx, "udp4", net.JoinHostPort(target, "33434"))
		if err2 != nil {
			return 0, fmt.Errorf("probe failed: %w", err)
		}
		conn2.Close()
		return time.Since(start), nil
	}
	conn.Close()
	return time.Since(start), nil
}

func (m *Manager) probeTCP(ctx context.Context, test *config.RPMTest) (time.Duration, error) {
	port := test.DestPort
	if port == 0 {
		port = 80
	}
	addr := net.JoinHostPort(test.Target, fmt.Sprintf("%d", port))
	dialer := vrfDialer(5*time.Second, test.SourceAddress, vrfDeviceName(test.RoutingInstance))

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("TCP connect failed: %w", err)
	}
	rtt := time.Since(start)
	conn.Close()
	return rtt, nil
}

func (m *Manager) probeHTTP(ctx context.Context, test *config.RPMTest) (time.Duration, error) {
	target := test.Target
	if target == "" {
		return 0, fmt.Errorf("no target specified")
	}
	// If target doesn't look like a URL, make it one
	url := target
	if len(url) > 0 && url[0] != 'h' {
		url = "http://" + target
	}

	dialer := vrfDialer(10*time.Second, test.SourceAddress, vrfDeviceName(test.RoutingInstance))
	transport := &http.Transport{
		DialContext: dialer.DialContext,
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("HTTP request error: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("HTTP GET failed: %w", err)
	}
	resp.Body.Close()
	rtt := time.Since(start)

	if resp.StatusCode >= 400 {
		return rtt, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return rtt, nil
}
