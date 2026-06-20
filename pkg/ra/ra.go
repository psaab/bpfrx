// Package ra implements an embedded Router Advertisement sender using
// mdlayher/ndp. It replaces the external radvd binary with per-interface
// sender goroutines that build and send RA packets directly.
//
// Shutdown contract (#2033): each interface has at most ONE live NDP
// connection at any time. A sender being withdrawn/stopped moves to a DRAINING
// TOMBSTONE (m.draining) under m.mu while it joins OUTSIDE the lock, so a
// concurrent Apply/WithdrawOnce never starts a second sender on the same
// interface (which would race the goodbye or collide on ndp.Listen). All RA
// emission — including the lifetime-0 goodbye — is performed by the per-sender
// owner goroutine (see sender.run / finishShutdown), so a normal RA can never
// follow the goodbye on the wire.
package ra

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// claimWaitPoll is how often a deferred Apply re-checks whether a draining
// tombstone (or WithdrawOnce claim) for an interface has cleared.
const claimWaitPoll = 5 * time.Millisecond

// claimWaitTimeout bounds how long a deferred Apply waits for a draining
// tombstone to clear before giving up on that interface (the standalone
// goodbye / graceful join is ~100 ms, so this is generous).
const claimWaitTimeout = 5 * time.Second

// Manager manages per-interface RA sender goroutines.
type Manager struct {
	mu      sync.Mutex
	senders map[string]*sender // active senders, keyed by Linux interface name

	// draining holds interfaces whose senders are tearing down (graceful
	// withdraw or hard stop). The entry is a tombstone: while present, the
	// interface is NOT absent — a concurrent Apply/WithdrawOnce must treat it
	// as a claim and defer rather than start a new sender (#2033 I16). It is
	// removed once the sender's goroutine has joined.
	draining map[string]struct{}

	// epoch is bumped on every state-mutating call (Apply, Withdraw,
	// WithdrawInterfaces, WithdrawOnce, Clear). A deferred Apply captures the
	// epoch before releasing m.mu and ABORTS its deferred start if the epoch
	// changed — a newer call (e.g. a BACKUP transition) superseded it (#2033
	// I16b). This prevents a stale Apply from starting RA on a demoted node.
	epoch uint64
}

// New creates a new RA manager.
func New() *Manager {
	return &Manager{
		senders:  make(map[string]*sender),
		draining: make(map[string]struct{}),
	}
}

// bumpEpoch increments the manager epoch. Callers must hold m.mu.
func (m *Manager) bumpEpoch() { m.epoch++ }

// interfaceBusy reports whether the named interface currently has an active
// sender or a draining tombstone. Callers must hold m.mu.
func (m *Manager) interfaceBusy(name string) bool {
	if _, ok := m.senders[name]; ok {
		return true
	}
	_, ok := m.draining[name]
	return ok
}

// Apply diffs the current senders against the desired set and starts/stops/
// updates as needed. Unchanged configs are left running without RA gap.
//
// Interfaces that are currently DRAINING (a graceful withdraw or hard stop is
// in flight, or a WithdrawOnce goodbye holds a claim) are NOT started in this
// pass — that would race a second NDP connection against the one tearing down.
// Instead they are deferred: Apply releases m.mu, waits (bounded) for the
// tombstone to clear, then re-acquires m.mu and starts them — but ONLY if the
// manager epoch has not changed in the meantime (a newer Withdraw/Clear would
// have superseded this Apply; starting here would re-arm RA on a demoted node).
func (m *Manager) Apply(configs []*config.RAInterfaceConfig) error {
	m.mu.Lock()

	m.bumpEpoch()

	if len(configs) == 0 {
		err := m.clearLocked()
		m.mu.Unlock()
		return err
	}

	// Build desired map.
	desired := make(map[string]*config.RAInterfaceConfig, len(configs))
	for _, cfg := range configs {
		desired[cfg.Interface] = cfg
	}

	// Remove senders not in the desired set (hard stop, no goodbye — a config
	// change must not blackhole hosts).
	var toStop []*sender
	for name, s := range m.senders {
		if _, ok := desired[name]; !ok {
			slog.Info("ra: removing sender", "interface", name)
			toStop = append(toStop, s)
			delete(m.senders, name)
		}
	}

	// Add or update senders.
	var firstErr error
	var deferred []*config.RAInterfaceConfig // interfaces blocked by a tombstone
	for name, cfg := range desired {
		existing, ok := m.senders[name]
		if ok && configEqual(existing.cfg, cfg) {
			continue // No change — keep running, no RA gap.
		}

		// Changed config: hard-stop the old sender, then (re)start.
		if ok {
			slog.Info("ra: restarting sender", "interface", name)
			toStop = append(toStop, existing)
			delete(m.senders, name)
		}

		// If a tombstone is present (a prior withdraw/stop or a WithdrawOnce
		// claim is still tearing down), defer — do not start a second conn.
		if _, draining := m.draining[name]; draining {
			deferred = append(deferred, cfg)
			continue
		}

		if err := m.startLocked(cfg); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	epoch := m.epoch
	m.mu.Unlock()

	// Hard-stop removed/changed senders OUTSIDE the lock (#2033 I16): a stop
	// joins the owner (~best-effort) and we must not hold m.mu across it.
	for _, s := range toStop {
		s.stop()
	}

	// Second pass for interfaces that were draining when we held the lock.
	if len(deferred) > 0 {
		if err := m.applyDeferred(deferred, epoch); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// applyDeferred waits (bounded) for each deferred interface's tombstone to
// clear, then re-acquires m.mu and starts it — but only if the manager epoch
// still matches startEpoch (else a newer call superseded this Apply, #2033
// I16b). It must be called WITHOUT m.mu held.
func (m *Manager) applyDeferred(configs []*config.RAInterfaceConfig, startEpoch uint64) error {
	var firstErr error
	for _, cfg := range configs {
		if !m.waitTombstoneClear(cfg.Interface) {
			slog.Warn("ra: deferred Apply timed out waiting for drain",
				"interface", cfg.Interface)
			continue
		}

		m.mu.Lock()
		if m.epoch != startEpoch {
			// A newer Withdraw/Clear/Apply superseded this start; abort.
			slog.Debug("ra: deferred Apply superseded by newer epoch, skipping",
				"interface", cfg.Interface)
			m.mu.Unlock()
			continue
		}
		if m.interfaceBusy(cfg.Interface) {
			// Something else (re)claimed it; do not double-start.
			m.mu.Unlock()
			continue
		}
		err := m.startLocked(cfg)
		m.mu.Unlock()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// waitTombstoneClear polls until the interface has no draining tombstone, up to
// claimWaitTimeout. Returns true if it cleared, false on timeout.
func (m *Manager) waitTombstoneClear(name string) bool {
	deadline := time.Now().Add(claimWaitTimeout)
	for {
		m.mu.Lock()
		_, draining := m.draining[name]
		m.mu.Unlock()
		if !draining {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(claimWaitPoll)
	}
}

// startLocked starts a sender for cfg and records it in m.senders. Callers must
// hold m.mu.
func (m *Manager) startLocked(cfg *config.RAInterfaceConfig) error {
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		slog.Warn("ra: interface not found, skipping",
			"interface", cfg.Interface, "err", err)
		return fmt.Errorf("interface %s: %w", cfg.Interface, err)
	}

	s := newSender(cfg, iface)
	if err := s.start(); err != nil {
		slog.Warn("ra: failed to start sender",
			"interface", cfg.Interface, "err", err)
		return fmt.Errorf("start %s: %w", cfg.Interface, err)
	}

	m.senders[cfg.Interface] = s
	slog.Info("ra: sender started", "interface", cfg.Interface,
		"prefixes", len(cfg.Prefixes))
	return nil
}

// Withdraw sends goodbye RAs (lifetime=0) on all interfaces, then stops all
// senders. This tells hosts to immediately remove this router as a default
// gateway. The goodbye is the LAST RA each sender emits (owner-emitted on
// exit), so a normal RA can never follow it.
func (m *Manager) Withdraw() error {
	m.mu.Lock()
	m.bumpEpoch()
	var names []string
	for name := range m.senders {
		names = append(names, name)
	}
	m.mu.Unlock()
	m.withdrawNamesGraceful(names)
	return nil
}

// WithdrawInterfaces sends goodbye RAs and stops senders only for the named
// interfaces. Other senders are left running.
func (m *Manager) WithdrawInterfaces(names []string) {
	m.mu.Lock()
	m.bumpEpoch()
	m.mu.Unlock()
	m.withdrawNamesGraceful(names)
}

// withdrawNamesGraceful moves each named sender to a draining tombstone under
// m.mu, releases the lock, then joins each (emitting its goodbye) OUTSIDE the
// lock (#2033 I16) so multi-interface demotion does not stall Status/Apply on
// the failover hot path. The tombstone is removed when the join completes.
func (m *Manager) withdrawNamesGraceful(names []string) {
	type pending struct {
		name string
		s    *sender
	}
	var ps []pending

	m.mu.Lock()
	for _, name := range names {
		s, ok := m.senders[name]
		if !ok {
			continue
		}
		slog.Info("ra: sending goodbye RA", "interface", name)
		delete(m.senders, name)
		m.draining[name] = struct{}{}
		s.signalStop(modeGraceful)
		ps = append(ps, pending{name, s})
	}
	m.mu.Unlock()

	for _, p := range ps {
		<-p.s.stopped // owner emits the goodbye then closes the conn
		m.mu.Lock()
		delete(m.draining, p.name)
		m.mu.Unlock()
	}
}

// ResendBurst tells all running senders to re-send their startup burst. Used
// after RETH MAC link cycles that kill the NDP socket — the sender restarts but
// the original startup burst was lost during the link DOWN. The re-burst is
// routed through the owner goroutine (non-blocking) so it serializes with the
// owner's other writes (#2033 S2/I8) instead of racing a second writer.
func (m *Manager) ResendBurst() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, s := range m.senders {
		slog.Info("ra: re-sending startup burst after link cycle", "interface", name)
		s.requestBurst()
	}
}

// WithdrawOnce sends a one-shot goodbye RA (router lifetime=0) on the given
// interfaces. Used on startup when a node boots as secondary to withdraw stale
// RA routes from a previous primary run. Unlike Withdraw(), this does NOT
// require a running sender — it opens a temporary NDP connection, sends the
// goodbye, and closes it WITHOUT launching a sender goroutine or a startup
// burst (so it never re-advertises the router it is withdrawing — #2033 S1).
//
// It claims the interface via a draining tombstone under m.mu so a concurrent
// Apply does NOT start a real sender mid-goodbye (#2033 I4); the Apply defers
// and starts after the claim clears (it must WAIT, not skip — dropping a MASTER
// Apply would leave the interface with no sender). Interfaces with a live
// sender (VRRP MASTER already won) or an existing tombstone are skipped — a
// goodbye must not clobber a live primary.
func (m *Manager) WithdrawOnce(configs []*config.RAInterfaceConfig) {
	m.mu.Lock()
	m.bumpEpoch()
	type claimed struct {
		cfg *config.RAInterfaceConfig
	}
	var toGoodbye []claimed
	for _, cfg := range configs {
		if m.interfaceBusy(cfg.Interface) {
			slog.Debug("ra: WithdrawOnce: interface busy, skipping",
				"interface", cfg.Interface)
			continue
		}
		// Claim the interface so a concurrent Apply defers instead of starting
		// a real sender during the goodbye.
		m.draining[cfg.Interface] = struct{}{}
		toGoodbye = append(toGoodbye, claimed{cfg})
	}
	m.mu.Unlock()

	for _, c := range toGoodbye {
		m.sendOneGoodbye(c.cfg)
		m.mu.Lock()
		delete(m.draining, c.cfg.Interface)
		m.mu.Unlock()
	}
}

// sendOneGoodbye opens a temporary sender for cfg, emits the standalone goodbye
// (no burst, no link toggle — #2033 I12), and closes. m.mu must NOT be held.
func (m *Manager) sendOneGoodbye(cfg *config.RAInterfaceConfig) {
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		slog.Debug("ra: WithdrawOnce: interface not found",
			"interface", cfg.Interface, "err", err)
		return
	}
	s := newSender(cfg, iface)
	if err := s.sendGoodbyeStandalone(); err != nil {
		slog.Debug("ra: WithdrawOnce: failed to send goodbye",
			"interface", cfg.Interface, "err", err)
	}
}

// Clear stops all senders without sending goodbye RAs.
func (m *Manager) Clear() error {
	m.mu.Lock()
	m.bumpEpoch()
	err := m.clearLocked()
	m.mu.Unlock()
	return err
}

// clearLocked hard-stops all active senders without a goodbye. Callers must
// hold m.mu; it moves senders to draining tombstones, releases the lock to
// join, then re-acquires — so it returns with m.mu held (matching its
// callers). No goodbye is emitted (modeHard).
func (m *Manager) clearLocked() error {
	if len(m.senders) == 0 {
		return nil
	}
	type pending struct {
		name string
		s    *sender
	}
	var ps []pending
	for name, s := range m.senders {
		delete(m.senders, name)
		m.draining[name] = struct{}{}
		s.signalStop(modeHard)
		ps = append(ps, pending{name, s})
	}

	// Join outside the lock so Clear of many interfaces does not stall other
	// callers; re-acquire before returning (caller expects m.mu held).
	m.mu.Unlock()
	for _, p := range ps {
		<-p.s.stopped
	}
	m.mu.Lock()
	for _, p := range ps {
		delete(m.draining, p.name)
	}
	return nil
}

// SenderInfo holds per-interface RA sender status for display.
type SenderInfo struct {
	Interface   string
	SrcAddr     string
	Prefixes    []string
	DNSServers  []string
	NAT64Prefix string
	Preference  string
	Lifetime    int // router lifetime in seconds
	MaxInterval int
	MinInterval int
	LinkMTU     int
	Managed     bool
	Other       bool
	LastRA      string // time since last RA
	// State is "active" for a running sender or "draining" for an interface
	// whose sender is tearing down / emitting its goodbye (#2033). A draining
	// interface is deliberately reported as distinct from active so operators
	// do not read a withdrawing router as still advertising.
	State string
}

// Status returns information about all RA senders, including interfaces that
// are currently draining (their State is "draining").
func (m *Manager) Status() []SenderInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []SenderInfo
	for _, s := range m.senders {
		info := SenderInfo{
			Interface:   s.cfg.Interface,
			SrcAddr:     s.srcAddr.String(),
			Lifetime:    s.cfg.DefaultLifetime,
			MaxInterval: s.cfg.MaxAdvInterval,
			MinInterval: s.cfg.MinAdvInterval,
			LinkMTU:     s.cfg.LinkMTU,
			Managed:     s.cfg.ManagedConfig,
			Other:       s.cfg.OtherStateful,
			Preference:  s.cfg.Preference,
			NAT64Prefix: s.cfg.NAT64Prefix,
			State:       "active",
		}
		if info.Lifetime <= 0 {
			info.Lifetime = defaultRouterLifetime
		}
		if info.MaxInterval <= 0 {
			info.MaxInterval = defaultMaxAdvInterval
		}
		if info.MinInterval <= 0 {
			info.MinInterval = info.MaxInterval / 3
		}
		if info.Preference == "" {
			info.Preference = "medium"
		}
		for _, pfx := range s.cfg.Prefixes {
			info.Prefixes = append(info.Prefixes, pfx.Prefix)
		}
		info.DNSServers = s.cfg.DNSServers
		if last := s.getLastRA(); !last.IsZero() {
			info.LastRA = fmt.Sprintf("%.0fs ago", time.Since(last).Seconds())
		} else {
			info.LastRA = "never"
		}
		result = append(result, info)
	}

	// Surface draining interfaces so a withdrawing router is not silently
	// invisible (it is no longer "active" but not yet gone).
	for name := range m.draining {
		result = append(result, SenderInfo{
			Interface: name,
			State:     "draining",
			LastRA:    "n/a",
		})
	}
	return result
}

// configEqual compares two RA configs for equality.
func configEqual(a, b *config.RAInterfaceConfig) bool {
	if a.Interface != b.Interface ||
		a.ManagedConfig != b.ManagedConfig ||
		a.OtherStateful != b.OtherStateful ||
		a.Preference != b.Preference ||
		a.DefaultLifetime != b.DefaultLifetime ||
		a.MaxAdvInterval != b.MaxAdvInterval ||
		a.MinAdvInterval != b.MinAdvInterval ||
		a.LinkMTU != b.LinkMTU ||
		a.NAT64Prefix != b.NAT64Prefix ||
		a.NAT64PrefixLife != b.NAT64PrefixLife ||
		a.SourceLinkLocal != b.SourceLinkLocal {
		return false
	}

	if len(a.Prefixes) != len(b.Prefixes) {
		return false
	}
	for i := range a.Prefixes {
		if a.Prefixes[i].Prefix != b.Prefixes[i].Prefix ||
			a.Prefixes[i].OnLink != b.Prefixes[i].OnLink ||
			a.Prefixes[i].Autonomous != b.Prefixes[i].Autonomous ||
			a.Prefixes[i].ValidLifetime != b.Prefixes[i].ValidLifetime ||
			a.Prefixes[i].PreferredLife != b.Prefixes[i].PreferredLife {
			return false
		}
	}

	if len(a.DNSServers) != len(b.DNSServers) {
		return false
	}
	for i := range a.DNSServers {
		if a.DNSServers[i] != b.DNSServers[i] {
			return false
		}
	}

	return true
}
