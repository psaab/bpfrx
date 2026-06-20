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
	// withdraw or hard stop) or are otherwise claimed (a WithdrawOnce goodbye,
	// or an Apply restart between stop-old and start-new). The entry is a
	// tombstone: while present, the interface is NOT absent — a concurrent
	// Apply/WithdrawOnce must treat it as a claim and defer rather than start a
	// new sender (#2033 I16). The value is the draining *sender when one exists
	// (so a later graceful Withdraw can UPGRADE a still-draining hard stop to
	// emit a goodbye — #2033 MAJOR 2), or nil for a claim with no live sender
	// (WithdrawOnce, or after the sender has joined). It is removed once the
	// sender's goroutine has joined.
	draining map[string]*sender

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
		draining: make(map[string]*sender),
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
// INVARIANT (#2033 MAJOR 1): at no point are two live NDP conns present for one
// interface. Every transition that replaces or removes a sender installs a
// draining tombstone for that interface BEFORE releasing m.mu and stops the old
// sender (closing its conn) BEFORE any replacement conn is opened. The
// tombstone covers the whole stop→start window, so a concurrent
// Apply/Withdraw/WithdrawOnce that sees it defers instead of opening a second
// conn. A CHANGED config is a hard replace (no goodbye — the router is not
// going away); a REMOVED config is a hard stop (no goodbye).
//
// Interfaces that are ALREADY draining when this Apply runs (a prior
// withdraw/stop or a WithdrawOnce claim still tearing down) are NOT started in
// this pass — that would race a second conn against the one tearing down.
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

	// A pending stop. tomb=true means a tombstone was installed for the
	// interface and must be cleared after the join (removal) or after the
	// replacement starts (restart).
	type stopReq struct {
		name string
		s    *sender
	}
	var toStop []stopReq

	// Remove senders not in the desired set (hard stop, no goodbye — a config
	// change must not blackhole hosts). Install a tombstone so a concurrent
	// WithdrawOnce/Apply does not start a sender on the same interface while the
	// old one is still tearing down.
	for name, s := range m.senders {
		if _, ok := desired[name]; !ok {
			slog.Info("ra: removing sender", "interface", name)
			delete(m.senders, name)
			m.draining[name] = s
			s.signalStop(modeHard)
			toStop = append(toStop, stopReq{name, s})
		}
	}

	// Classify desired interfaces: unchanged (left running), changed (hard
	// replace — tombstone + stop old, defer the start), or already-draining /
	// new (deferred or started directly).
	var firstErr error
	var deferred []*config.RAInterfaceConfig // already-draining when we held the lock
	var toRestart []*config.RAInterfaceConfig // changed config: old stopped, start after join
	for name, cfg := range desired {
		existing, ok := m.senders[name]
		if ok && configEqual(existing.cfg, cfg) {
			continue // No change — keep running, no RA gap.
		}

		// Changed config: hard-replace. Install a tombstone, stop the old
		// sender, and DEFER the start until the old conn is closed (the
		// tombstone covers the whole window). Never open the new conn while the
		// old one is live (#2033 MAJOR 1).
		if ok {
			slog.Info("ra: restarting sender", "interface", name)
			delete(m.senders, name)
			m.draining[name] = existing
			existing.signalStop(modeHard)
			toStop = append(toStop, stopReq{name, existing})
			toRestart = append(toRestart, cfg)
			continue
		}

		// New interface. If a tombstone is already present (a prior withdraw/
		// stop or a WithdrawOnce claim is still tearing down), defer — do not
		// start a second conn.
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

	// Join the stopped (removed + changed) senders OUTSIDE the lock (#2033 I16):
	// a stop joins the owner and we must not hold m.mu across it. The conn is
	// closed by the owner in finishShutdown before stop() returns.
	for _, req := range toStop {
		<-req.s.stopped
	}

	// Now every old conn is closed. Clear the REMOVAL tombstones (their
	// interfaces have no replacement); restart tombstones stay until the
	// replacement starts.
	if len(toStop) > 0 {
		restartSet := make(map[string]struct{}, len(toRestart))
		for _, cfg := range toRestart {
			restartSet[cfg.Interface] = struct{}{}
		}
		m.mu.Lock()
		for _, req := range toStop {
			if _, isRestart := restartSet[req.name]; !isRestart {
				delete(m.draining, req.name)
			}
		}
		m.mu.Unlock()
	}

	// Start the replacements for changed configs now that the old conns are
	// closed. Epoch-guarded: a concurrent Withdraw/Clear that bumped the epoch
	// wins (it will have already moved/handled the interface), so we abort the
	// stale restart and clear our tombstone.
	for _, cfg := range toRestart {
		m.mu.Lock()
		if m.epoch != epoch {
			// Superseded — a newer call owns this interface now. Drop our
			// restart tombstone only if no newer owner re-installed it; the
			// newer call manages its own tombstone, so only remove ours if it
			// is still the placeholder we set and no sender exists.
			delete(m.draining, cfg.Interface)
			m.mu.Unlock()
			slog.Debug("ra: restart superseded by newer epoch, skipping",
				"interface", cfg.Interface)
			continue
		}
		err := m.startLocked(cfg)
		delete(m.draining, cfg.Interface)
		m.mu.Unlock()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Second pass for interfaces that were ALREADY draining when we held the
	// lock (not our own restart tombstones — those are handled above).
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

// drainingSender pairs a draining interface name with its sender for the
// join-outside-the-lock phase.
type drainingSender struct {
	name string
	s    *sender
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
	// Also include interfaces already DRAINING (e.g. a Clear acquired m.mu
	// first and hard-stopped them). claimGracefulLocked UPGRADES any such
	// hard-draining sender to graceful so a "withdraw everything" still emits
	// every goodbye (#2033 MAJOR 2); nil-sender claims (WithdrawOnce) are
	// no-ops there.
	for name := range m.draining {
		names = append(names, name)
	}
	// Record the graceful intent ATOMICALLY with the epoch bump and the
	// snapshot (#2033 MAJOR 2): tombstone + signalStop(modeGraceful) happen
	// under the SAME m.mu hold, so a racing Clear that acquires m.mu afterward
	// sees the sender already draining-graceful and cannot drop the goodbye
	// (signalStop is idempotent + graceful never downgrades to hard).
	ps := m.claimGracefulLocked(names)
	m.mu.Unlock()
	m.joinDraining(ps)
	return nil
}

// WithdrawInterfaces sends goodbye RAs and stops senders only for the named
// interfaces. Other senders are left running.
func (m *Manager) WithdrawInterfaces(names []string) {
	m.mu.Lock()
	m.bumpEpoch()
	ps := m.claimGracefulLocked(names)
	m.mu.Unlock()
	m.joinDraining(ps)
}

// claimGracefulLocked, under m.mu, moves each named active sender to a graceful
// draining tombstone and signals it to emit its goodbye on exit. Doing the
// tombstone install AND signalStop(modeGraceful) under the lock makes the
// graceful intent atomic (#2033 MAJOR 2) — a later Clear cannot delete the
// sender and install a hard tombstone in a gap, because by the time the lock is
// released the sender is already gone from m.senders and already modeGraceful.
// Callers must hold m.mu. Returns the senders to join outside the lock.
func (m *Manager) claimGracefulLocked(names []string) []drainingSender {
	var ps []drainingSender
	for _, name := range names {
		if s, ok := m.senders[name]; ok {
			slog.Info("ra: sending goodbye RA", "interface", name)
			delete(m.senders, name)
			m.draining[name] = s
			s.signalStop(modeGraceful)
			ps = append(ps, drainingSender{name, s})
			continue
		}
		// Not active. If a sender is already DRAINING (e.g. a Clear acquired
		// m.mu first and set a hard tombstone), UPGRADE it to graceful so the
		// goodbye is still emitted (#2033 MAJOR 2). signalStop is idempotent and
		// graceful never downgrades; the existing Clear/Apply join will emit the
		// upgraded goodbye, so we do NOT add it to our own join list (avoid a
		// double <-stopped on the same sender).
		if s := m.draining[name]; s != nil {
			slog.Info("ra: upgrading draining sender to graceful goodbye",
				"interface", name)
			s.signalStop(modeGraceful)
		}
	}
	return ps
}

// joinDraining joins each draining sender (emitting its goodbye) OUTSIDE m.mu
// (#2033 I16) so multi-interface demotion does not stall Status/Apply on the
// failover hot path, then removes each tombstone when its join completes.
func (m *Manager) joinDraining(ps []drainingSender) {
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
		// a real sender during the goodbye. nil sender: the standalone goodbye
		// is emitted synchronously below, there is no run() loop to upgrade.
		m.draining[cfg.Interface] = nil
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
		// Store the sender (not nil) so a racing graceful Withdraw can UPGRADE
		// this hard stop to emit a goodbye (#2033 MAJOR 2). signalStop is
		// idempotent; graceful never downgrades.
		m.draining[name] = s
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
