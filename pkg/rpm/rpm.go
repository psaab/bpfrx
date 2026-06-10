// Package rpm implements Real-time Performance Monitoring probes.
package rpm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"golang.org/x/sys/unix"
)

// probeDialer returns a net.Dialer carrying the per-test socket options:
// optional source address, SO_BINDTODEVICE (destination-interface, or
// the "vrf-"+instance VRF device fallback), and SO_MARK for
// next-hop-pinned tests (#1827).
func probeDialer(timeout time.Duration, sourceAddr string, opts probeSockOpts) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if sourceAddr != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(sourceAddr)}
	}
	if opts.BindDevice != "" || opts.Mark != 0 {
		d.Control = func(network, address string, c syscall.RawConn) error {
			var cerr error
			err := c.Control(func(fd uintptr) {
				if opts.BindDevice != "" {
					cerr = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET,
						syscall.SO_BINDTODEVICE, opts.BindDevice)
					if cerr != nil {
						return
					}
				}
				if opts.Mark != 0 {
					cerr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET,
						unix.SO_MARK, int(opts.Mark))
				}
			})
			if err != nil {
				err = fmt.Errorf("%w: socket control: %v", ErrProbeSetup, err)
			} else if cerr != nil {
				// Socket-option failures (SO_BINDTODEVICE EPERM/ENODEV,
				// SO_MARK EPERM) are environment/capability errors, not
				// path health: mark them ErrProbeSetup so tcp-ping and
				// http-get hold state exactly like icmp-ping (Codex PR
				// #1843 HIGH-2). The sentinel survives the net.OpError /
				// url.Error wrapping on the dial path, so the probe
				// loop's errors.Is check catches it for all three probe
				// types. Genuine dial outcomes (refused, timeout,
				// unreachable) never pass through this callback and stay
				// path signals — ambiguous dial errnos deliberately
				// default to PATH (conservative for detection).
				err = fmt.Errorf("%w: socket option: %v", ErrProbeSetup, cerr)
			}
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
	ProbeName   string
	TestName    string
	ProbeType   string
	Target      string
	LastRTT     time.Duration
	MinRTT      time.Duration
	MaxRTT      time.Duration
	AvgRTT      time.Duration
	Jitter      time.Duration // running absolute deviation from average
	LastStatus  string        // "pass" or "fail"
	SuccFail    int           // consecutive failures
	TotalSent   int64
	TotalRecv   int64
	LastProbeAt time.Time
}

// Event represents an RPM event for event-options matching.
type Event struct {
	Name      string // "ping_test_failed", "ping_probe_failed", "ping_test_completed"
	TestOwner string // probe name (matches attributes-match test-owner)
	TestName  string // test name (matches attributes-match test-name)
}

// EventCallback is called when RPM probes generate events.
type EventCallback func(Event)

// Transition reports a per-test pass/fail status transition together
// with a current-state snapshot of all probe results (#1827 PR-1a §4.2
// item 6). It is the sensor input for the ip-monitoring engine; the
// coarser Event/EventCallback surface stays intact for eventengine.
type Transition struct {
	ProbeName string
	TestName  string
	Status    string // new status: "pass" or "fail"
	Results   []*ProbeResult
}

// TransitionCallback is called on per-test status transitions.
type TransitionCallback func(Transition)

// Manager runs RPM probes and tracks their results.
type Manager struct {
	mu           sync.RWMutex
	results      map[string]*ProbeResult // key: "probe/test"
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	onEvent      EventCallback
	onTransition TransitionCallback

	// rethMap translates Junos RETH names to physical members for
	// destination-interface resolution (set by the daemon in cluster
	// mode before Apply).
	rethMap map[string]string

	// marks maps "probe/test" to the probe fwmark for next-hop-pinned
	// tests, derived in Apply from the same deterministic assignment
	// pkg/routing programs (routing.BuildProbePins).
	marks map[string]uint32

	// icmpListen is the injectable raw-socket seam for the ICMP echo
	// prober. nil = realICMPListen.
	icmpListen icmpListenFunc
}

// SetEventCallback registers a callback for RPM events.
func (m *Manager) SetEventCallback(fn EventCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onEvent = fn
}

// SetTransitionCallback registers a callback for per-test pass/fail
// status transitions.
func (m *Manager) SetTransitionCallback(fn TransitionCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onTransition = fn
}

// SetRethMap supplies the RETH → physical member translation used when
// resolving destination-interface names. Call before Apply.
func (m *Manager) SetRethMap(rethMap map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rethMap = rethMap
}

func (m *Manager) fireEvent(name, owner, testName string) {
	m.mu.RLock()
	fn := m.onEvent
	m.mu.RUnlock()
	if fn != nil {
		fn(Event{Name: name, TestOwner: owner, TestName: testName})
	}
}

func (m *Manager) fireTransition(owner, testName, status string) {
	m.mu.RLock()
	fn := m.onTransition
	m.mu.RUnlock()
	if fn != nil {
		fn(Transition{
			ProbeName: owner,
			TestName:  testName,
			Status:    status,
			Results:   m.Results(),
		})
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

	// Derive the per-test fwmark assignment from the SAME deterministic
	// function pkg/routing uses to program the pin rules, so socket
	// SO_MARK and kernel fwmark rule can never disagree (#1827).
	m.mu.Lock()
	m.marks = make(map[string]uint32)
	for _, pin := range routing.BuildProbePins(cfg, m.rethMap) {
		m.marks[pin.TestKey] = pin.Mark
	}
	m.mu.Unlock()

	probeCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	for _, probe := range cfg.Probes {
		for _, test := range probe.Tests {
			key := probe.Name + "/" + test.Name
			m.mu.Lock()
			m.results[key] = &ProbeResult{
				ProbeName:  probe.Name,
				TestName:   test.Name,
				ProbeType:  test.EffectiveProbeType(),
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
	interval := time.Duration(test.EffectiveTestInterval()) * time.Second
	probeInterval := time.Duration(test.EffectiveProbeInterval()) * time.Second
	probeCount := test.EffectiveProbeCount()
	threshold := test.EffectiveSuccessiveLossThreshold()

	slog.Info("RPM probe started",
		"probe", probe.Name, "test", test.Name,
		"type", test.EffectiveProbeType(), "target", test.Target,
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
	setupWarned := false

	for i := 0; i < probeCount; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(probeInterval):
			}
		}

		rtt, err := m.executeProbe(ctx, test, key)

		// ErrProbeSetup = environment/capability failure (raw socket
		// open denied, marshal): the probe never reached the wire, so
		// it carries NO path-health signal. Hold the test's current
		// state completely — no counters, no status change, no
		// events, no Transition — so ip-monitoring can never actuate
		// routes off a capability regression (AGY PR #1843 F2). Log
		// loudly but rate-limited (once per test cycle, i.e. at most
		// once per test-interval).
		if errors.Is(err, ErrProbeSetup) {
			if !setupWarned {
				setupWarned = true
				slog.Warn("RPM probe setup failed — holding test state (environment error, not path health)",
					"probe", probeName, "test", test.Name, "err", err)
			}
			continue
		}

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
				m.fireTransition(probeName, test.Name, "fail")
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
			if prevStatus != "pass" {
				m.fireTransition(probeName, test.Name, "pass")
			}
		}
	}

	// Fire test completed if all probes passed
	if failures == 0 && successes > 0 {
		m.fireEvent("ping_test_completed", probeName, test.Name)
	}
}

// probeOpts derives the per-test socket options: destination-interface
// (resolved through the RETH map) takes precedence over the
// routing-instance VRF device for SO_BINDTODEVICE; next-hop-pinned
// tests carry their probe fwmark for SO_MARK.
func (m *Manager) probeOpts(test *config.RPMTest, key string) probeSockOpts {
	m.mu.RLock()
	mark := m.marks[key]
	rethMap := m.rethMap
	m.mu.RUnlock()

	bindDev := routing.ResolveProbeInterface(test.DestinationInterface, rethMap)
	if bindDev == "" {
		bindDev = vrfDeviceName(test.RoutingInstance)
	}
	return probeSockOpts{BindDevice: bindDev, Mark: mark}
}

func (m *Manager) executeProbe(ctx context.Context, test *config.RPMTest, key string) (time.Duration, error) {
	opts := m.probeOpts(test, key)
	switch test.EffectiveProbeType() {
	case "icmp-ping":
		return m.probeICMP(ctx, test, opts)
	case "tcp-ping":
		return m.probeTCP(ctx, test, opts)
	case "http-get":
		return m.probeHTTP(ctx, test, opts)
	default:
		return m.probeICMP(ctx, test, opts)
	}
}

func (m *Manager) probeTCP(ctx context.Context, test *config.RPMTest, opts probeSockOpts) (time.Duration, error) {
	port := test.EffectiveDestinationPort()
	addr := net.JoinHostPort(test.Target, fmt.Sprintf("%d", port))
	dialer := probeDialer(5*time.Second, test.SourceAddress, opts)

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("TCP connect failed: %w", err)
	}
	rtt := time.Since(start)
	conn.Close()
	return rtt, nil
}

func (m *Manager) probeHTTP(ctx context.Context, test *config.RPMTest, opts probeSockOpts) (time.Duration, error) {
	target := test.Target
	if target == "" {
		return 0, fmt.Errorf("no target specified")
	}
	// If target doesn't look like a URL, make it one
	url := target
	if len(url) > 0 && url[0] != 'h' {
		url = "http://" + target
	}

	dialer := probeDialer(10*time.Second, test.SourceAddress, opts)
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
