// Package rpm implements Real-time Performance Monitoring probes.
package rpm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
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
//
// A NON-EMPTY but unparseable source-address is a setup error, not a
// path signal (#2492): net.ParseIP returns nil, and a TCPAddr{IP:nil}
// silently degrades to a wildcard/kernel-chosen source bind — the probe
// would then measure the DEFAULT uplink instead of the source-specific
// path the operator pinned, publishing PASS/FAIL for the wrong path.
// The commit-time validator (validateRPMSourceAddressStrict) rejects
// this on the strict path, but a leniently-loaded or externally-built
// config can still reach here, so guard defensively and surface
// ErrProbeSetup. The ICMP path already fails closed via its real
// listen error; tcp-ping/http-get had no such backstop. An EMPTY
// source-address stays legitimate (means "default source"): only a
// non-empty value that will not parse is the error.
func probeDialer(timeout time.Duration, sourceAddr string, opts probeSockOpts) (*net.Dialer, error) {
	d := &net.Dialer{Timeout: timeout}
	if sourceAddr != "" {
		ip := net.ParseIP(sourceAddr)
		if ip == nil {
			return nil, fmt.Errorf("%w: invalid source-address %q (would bind wildcard source)",
				ErrProbeSetup, sourceAddr)
		}
		d.LocalAddr = &net.TCPAddr{IP: ip}
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
	return d, nil
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

	// pinFailed maps "probe/test" to the kernel install error for pins
	// whose fwmark rule / pinned route failed to program (#1895), as
	// reported by routing.Manager.ApplyProbePins and threaded in by the
	// daemon via SetPinInstallResults. A test with a failed pin never
	// probes (executeProbe returns ErrProbeSetup before any socket is
	// opened) — an unbacked SO_MARK would fall through to the main
	// table and measure the default path, turning a dead pinned uplink
	// into a false PASS that suppresses ip-monitoring failover.
	pinFailed map[string]error

	// icmpListen is the injectable raw-socket seam for the ICMP echo
	// prober. nil = realICMPListen.
	icmpListen icmpListenFunc

	// probeFn, when non-nil, replaces executeProbe — the injectable
	// seam for unit-testing the per-cycle pass/fail transition logic
	// with a scripted probe-result sequence (#2527). It is set once
	// before the manager runs and never mutated concurrently.
	probeFn func(ctx context.Context, test *config.RPMTest, key string) (time.Duration, error)

	// resolveTarget is the injectable hostname-resolution seam (#2493).
	// nil = resolveProbeTarget (process-default resolver via
	// net.ResolveIPAddr). The default resolver is NOT VRF/device-scoped,
	// so a SCOPED test (routing-instance / destination-interface /
	// next-hop) against a hostname would resolve out-of-context. The
	// scoped-hostname combination is rejected at commit
	// (validateRPMScopedHostnameStrict) and held via ErrProbeSetup in
	// executeProbe before any resolution runs, so this seam is consulted
	// only for unscoped / IP-literal probes today. It exists so a future
	// VRF-aware resolver can be slotted in (and so a test can assert the
	// guard short-circuits a scoped hostname before the default resolver
	// is reached). Returns *net.IPAddr so the IPv6 link-local zone is
	// preserved through to the send path (#2494).
	resolveTarget func(target string) (*net.IPAddr, error)
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

// SetPinInstallResults supplies the per-test probe-pin install
// failures from the most recent routing.Manager.ApplyProbePins (keys
// "probe/test", values the install error; nil/empty = all pins
// installed). The map is replaced wholesale, so a successful re-apply
// clears earlier failures and live probe loops resume on their next
// tick — no probe restart required. On a config change the daemon
// publishes AFTER Apply (the HoldPinsForReprogram union covers the
// interim); on a hash-gated pin retry it publishes immediately
// (#1895).
func (m *Manager) SetPinInstallResults(failed map[string]error) {
	cp := make(map[string]error, len(failed))
	for k, v := range failed {
		cp[k] = v
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pinFailed = cp
}

// HoldPinsForReprogram replaces the pin-failure map with one that
// holds EVERY currently-marked (live) pinned test PLUS the supplied
// new pin keys, all with cause. Called by the daemon immediately
// before the kernel pin band is cleared-and-reprogrammed: live probe
// goroutines — including ones whose keys are absent from the new pin
// set, or whose deterministic mark is about to change — must not send
// an SO_MARK probe against a band in flux (a stale mark can match
// another test's new fwmark rule and measure the wrong uplink; Codex
// PR #1899 r2). The caller publishes the real install results via
// SetPinInstallResults once the reprogram (and, on a config change,
// the probe re-Apply) has completed.
func (m *Manager) HoldPinsForReprogram(newPinKeys []string, cause error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	held := make(map[string]error, len(m.marks)+len(newPinKeys))
	for k := range m.marks {
		held[k] = cause
	}
	for _, k := range newPinKeys {
		held[k] = cause
	}
	m.pinFailed = held
}

// PinInstallFailureCount reports how many next-hop probe pins are
// currently failed-to-install (backs the
// xpf_rpm_probe_pin_install_failures gauge, #1895).
func (m *Manager) PinInstallFailureCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.pinFailed)
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
		// Clear the mark assignment too: stale marks would otherwise
		// inflate later HoldPinsForReprogram unions (#1895 hygiene —
		// no goroutines exist after StopAll, so this is cosmetic).
		m.mu.Lock()
		m.marks = nil
		m.mu.Unlock()
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

	// The per-test pass/fail status is a per-cycle aggregate, like
	// Junos RPM/ip-monitoring: the successive-loss threshold is
	// evaluated across the WHOLE probe set and the test transitions AT
	// MOST once per cycle — never per probe. Capture the pre-cycle
	// status ONCE; evolve `status` locally through the cycle (so the
	// cross-cycle consecutive-failure counter r.SuccFail keeps its
	// meaning); publish r.LastStatus and fire the transition only after
	// the loop. Firing inside the loop let a single transient mid-cycle
	// success flip fail->pass->fail and flap static-route preference in
	// services ip-monitoring (#2527).
	m.mu.Lock()
	r0 := m.results[key]
	if r0 == nil {
		m.mu.Unlock()
		return
	}
	prevStatus := r0.LastStatus
	m.mu.Unlock()
	status := prevStatus

	for i := 0; i < probeCount; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(probeInterval):
			}
		}

		rtt, err := m.runProbe(ctx, test, key)

		// ErrProbeSetup = environment/capability failure (raw socket
		// open denied, marshal, probe pin not installed #1895): the
		// probe never reached the wire — or must not be sent at all
		// because its kernel pin is unbacked — so it carries NO
		// path-health signal. Hold the test's current
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
		if err != nil {
			failures++
			r.SuccFail++
			// Successive-loss trip: once `threshold` consecutive
			// probes are lost the test is failed. r.SuccFail carries
			// across cycles, so a fail run spanning a cycle boundary
			// still trips. The status is only PUBLISHED after the loop.
			if r.SuccFail >= threshold {
				status = "fail"
			}
			// Check probe-limit: stop test cycle when reached
			hitLimit := probeLimit > 0 && r.SuccFail >= probeLimit
			m.mu.Unlock()
			// Probe-level failure event stays per-probe — it is an
			// eventengine signal and does not drive ip-monitoring
			// routes (which key off fireTransition only).
			m.fireEvent("ping_probe_failed", probeName, test.Name)
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
			// A success clears the successive-loss run. The status is
			// only PUBLISHED after the loop.
			status = "pass"
			m.mu.Unlock()
		}
	}

	// Publish the per-cycle status decision: compare the aggregate
	// end-of-cycle status to the pre-cycle status and fire AT MOST one
	// transition. This is the single ip-monitoring sensor edge per test
	// cycle (#2527). A below-threshold cycle that never reached "fail"
	// and saw no success leaves `status == prevStatus` (e.g. the
	// initial "unknown" state holds), so no spurious transition fires.
	if status != prevStatus {
		m.mu.Lock()
		if r := m.results[key]; r != nil {
			r.LastStatus = status
		}
		m.mu.Unlock()
		if status == "fail" {
			m.fireEvent("ping_test_failed", probeName, test.Name)
		}
		m.fireTransition(probeName, test.Name, status)
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

// pinInstallError gates next-hop-pinned tests on their kernel pin
// actually being installed (#1895). A pin that failed to program —
// or a next-hop test that never received a pin slot at all
// (band-exhaustion belt-and-braces; commit validation caps this on
// the strict path) — returns an ErrProbeSetup-wrapped error so the
// probe loop holds the test's state. The probe must NOT be sent: an
// unbacked SO_MARK falls through to the main table and measures the
// default path instead of the pinned uplink (false PASS).
func (m *Manager) pinInstallError(test *config.RPMTest, key string) error {
	if test.NextHop == "" {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if cause, ok := m.pinFailed[key]; ok {
		return fmt.Errorf("%w: probe pin not installed: %v", ErrProbeSetup, cause)
	}
	if m.marks[key] == 0 {
		return fmt.Errorf("%w: no probe pin slot assigned for next-hop test", ErrProbeSetup)
	}
	return nil
}

// scopedHostnameError holds a VRF/device-scoped test whose target is a
// hostname (#2493). The probe DATA socket is bound to a specific VRF /
// egress device (SO_BINDTODEVICE) or path (SO_MARK), but DNS resolution
// runs through the process-default resolver / table / source — the bind is
// applied in the per-connection Control hook, which fires AFTER name
// resolution — so a scoped probe against a hostname resolves
// out-of-context and measures resolver health rather than the scoped
// path. The commit-time validator (validateRPMScopedHostnameStrict)
// rejects this combination on the strict path; a leniently-loaded or
// peer-synced config can still reach here, so hold state via ErrProbeSetup
// (the probe loop holds, exactly like a failed source bind) instead of
// actuating ip-monitoring failover off a mis-scoped measurement. Returns
// nil for IP-literal targets (no resolution) and unscoped tests (resolve
// in the same context they probe). A future VRF-aware resolver would lift
// this guard.
func scopedHostnameError(test *config.RPMTest) error {
	if test == nil || !test.IsScoped() {
		return nil
	}
	if test.Target == "" || net.ParseIP(test.Target) != nil {
		return nil
	}
	return fmt.Errorf("%w: scoped RPM test target %q is a hostname; DNS is not VRF/device-scoped "+
		"(resolves out-of-context) — use an IP-literal target", ErrProbeSetup, test.Target)
}

// runProbe dispatches a single probe through the test seam when one is
// installed, otherwise the real executeProbe path.
func (m *Manager) runProbe(ctx context.Context, test *config.RPMTest, key string) (time.Duration, error) {
	if m.probeFn != nil {
		return m.probeFn(ctx, test, key)
	}
	return m.executeProbe(ctx, test, key)
}

func (m *Manager) executeProbe(ctx context.Context, test *config.RPMTest, key string) (time.Duration, error) {
	if err := scopedHostnameError(test); err != nil {
		return 0, err
	}
	if err := m.pinInstallError(test, key); err != nil {
		return 0, err
	}
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
	dialer, err := probeDialer(5*time.Second, test.SourceAddress, opts)
	if err != nil {
		return 0, err
	}

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("TCP connect failed: %w", err)
	}
	rtt := time.Since(start)
	conn.Close()
	return rtt, nil
}

// canonicalizeHTTPTarget turns an http-get probe target into a fully
// schemed URL suitable for http.NewRequestWithContext.
//
// A bare hostname, IP literal, or host:port (no "://" separator) gets
// the default "http://" scheme prepended. This replaces the fragile
// first-char heuristic (`url[0] != 'h'`) that decided whether a scheme
// was already present by looking at the first byte: a bare hostname
// starting with 'h' (host.example.com, h2.lan) was wrongly assumed to
// be already-schemed, so no prefix was added and the schemeless URL was
// rejected by http.NewRequestWithContext before any packet was sent —
// a healthy h-host probe never ran (#2495). The "://" containment test
// is the correct scheme detector: a bare "host:port" has no "://", so
// it is treated as schemeless (url.Parse would otherwise mistake "host"
// for a scheme).
//
// A target that already carries a scheme must be http or https; any
// other scheme (ftp://, gopher://, …) is rejected, since only http and
// https make sense for an http-get probe.
func canonicalizeHTTPTarget(target string) (string, error) {
	if target == "" {
		return "", fmt.Errorf("no target specified")
	}
	if !strings.Contains(target, "://") {
		return "http://" + target, nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("invalid http-get target URL %q: %w", target, err)
	}
	switch u.Scheme {
	case "http", "https":
		return target, nil
	default:
		return "", fmt.Errorf("unsupported http-get target scheme %q (want http or https): %q", u.Scheme, target)
	}
}

func (m *Manager) probeHTTP(ctx context.Context, test *config.RPMTest, opts probeSockOpts) (time.Duration, error) {
	url, err := canonicalizeHTTPTarget(test.Target)
	if err != nil {
		return 0, err
	}

	dialer, err := probeDialer(10*time.Second, test.SourceAddress, opts)
	if err != nil {
		return 0, err
	}
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
