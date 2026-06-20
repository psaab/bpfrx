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
// tombstone to clear, and how long releaseDrain waits to join a sender before
// giving up (the standalone goodbye / graceful join is ~100 ms, so this is
// generous). A package var so the timeout-arm test can shorten it.
var claimWaitTimeout = 5 * time.Second

// drainEntry is the single atomic claim-and-hold for a draining interface
// (#2033, structural fix for the three standalone-goodbye races). Its presence
// in m.draining is a tombstone: while it exists the interface is NOT absent, so
// a concurrent Apply/WithdrawOnce/Withdraw treats it as a claim and defers
// instead of opening a second NDP conn. ALL fields are read/written ONLY under
// m.mu. The entry is owned (created and eventually removed) by exactly ONE
// goroutine — the one that joins its sender (or the WithdrawOnce/standalone
// claimant). That single owner is the SOLE emitter of any standalone goodbye,
// and it HOLDS the entry across the whole emit, so:
//   - the owner is the only one that can take the goodbye (no double-send),
//   - the entry blocks any concurrent Apply for the entire emit (no clobber of
//     a re-claimed live sender, ≤1 live conn preserved),
//   - the goodbye decision reads sender.goodbyeEmitted only AFTER <-stopped
//     (happens-before), never on the timeout path.
type drainEntry struct {
	sender        *sender                   // draining sender; nil for a standalone-only claim
	cfg           *config.RAInterfaceConfig // config for a standalone goodbye, if owed
	goodbyeWanted bool                      // a graceful Withdraw targeted this interface
	goodbyeClaimed bool                     // the owner has taken responsibility to emit it
}

// Manager manages per-interface RA sender goroutines.
type Manager struct {
	mu      sync.Mutex
	senders map[string]*sender // active senders, keyed by Linux interface name

	// draining holds the per-interface claim-and-hold tombstones (see
	// drainEntry). While an entry is present the interface is claimed; a
	// concurrent Apply/WithdrawOnce/Withdraw must defer rather than start a new
	// sender (#2033 I16). The owner removes it (under m.mu) only AFTER any
	// standalone goodbye it claimed has fully completed.
	draining map[string]*drainEntry

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
		draining: make(map[string]*drainEntry),
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

// releaseDrain is the SINGLE exit path for a draining sender, used by Withdraw,
// Clear, Apply removal AND Apply's changed-config restart (#2033 structural fix;
// round-4 unification). The caller is the sole owner of name's drainEntry and
// has just signalled the sender to stop. releaseDrain owns the whole
// "stop the old sender (join-or-timeout) → optionally emit exactly-once →
// optionally start a replacement on PROVEN-close → release tombstone" sequence,
// so no divergent inline copy of these rules can drift (closes round-4 MAJOR
// 1 + 2). Must be called WITHOUT m.mu held.
//
//   - onProvenClose, if non-nil, is the changed-config replacement starter. It
//     runs ONLY on the proven-closed (<-stopped) arm, while the tombstone is
//     still HELD (a concurrent Apply defers), and ONLY if no graceful withdraw
//     superseded the replace (epoch unchanged AND no goodbye wanted). It opens
//     the replacement conn — guaranteed AFTER the old conn is proven closed
//     (≤1 live conn). It runs under m.mu and returns any start error.
//   - startEpoch is the manager epoch captured by the caller when it claimed the
//     interface; a changed epoch means a newer Withdraw/Clear/Apply superseded
//     this op, so the replacement is aborted.
//
// Timeout discipline (closes race 2 AND round-4 MAJOR 1/2): goodbyeEmitted is
// read ONLY after a successful <-stopped. On a join TIMEOUT (owner wedged
// despite bounded SetWriteDeadline) releaseDrain does NOT read goodbyeEmitted,
// does NOT emit a standalone, and does NOT start the replacement — the old conn
// may still be live, so opening a replacement would break ≤1-conn and an emit
// would be unordered. It LEAVES the tombstone in place (so any future
// Apply/reconcile defers — never 2 conns) and starts a detached reclaimer that
// removes the tombstone once the wedged owner finally exits. The degraded
// state is "old sender lingers, no replacement, tombstone held" — never 2
// conns, never an unordered emit, never a dropped-into-double goodbye.
func (m *Manager) releaseDrain(name string, s *sender, startEpoch uint64, onProvenClose func() error) error {
	if s != nil {
		select {
		case <-s.stopped:
			// proven closed — fall through to the ordered decision below.
		case <-time.After(claimWaitTimeout):
			slog.Warn("ra: timed out joining draining sender; not emitting a "+
				"standalone goodbye and not starting a replacement (owner may "+
				"still hold a live conn); leaving tombstone held", "interface", name)
			m.reclaimTombstoneWhenStopped(name, s)
			return nil
		}
	}

	// Proven closed (or s==nil). Decide the goodbye claim-once under m.mu.
	m.mu.Lock()
	e := m.draining[name]
	if e == nil {
		m.mu.Unlock()
		return nil // defensive; owner holds it
	}
	emit := false
	if e.goodbyeWanted && !e.goodbyeClaimed && s != nil && !s.goodbyeEmitted.Load() {
		e.goodbyeClaimed = true
		emit = true
	}
	cfg := e.cfg
	// A replacement starts ONLY if nothing superseded the replace: epoch
	// unchanged AND no goodbye was wanted (a graceful withdraw overrides a
	// replace — the route is being withdrawn, not replaced).
	superseded := m.epoch != startEpoch
	startReplacement := onProvenClose != nil && !superseded && !e.goodbyeWanted
	m.mu.Unlock()

	if emit {
		slog.Info("ra: emitting standalone goodbye (owner exited without one; "+
			"claim held across emit)", "interface", name)
		if cfg != nil {
			m.sendOneGoodbye(cfg) // entry still held → Apply defers, no clobber
		}
	}

	var startErr error
	m.mu.Lock()
	if startReplacement {
		// Old conn is PROVEN closed and the tombstone is still held → safe to
		// open the replacement (≤1 live conn) before releasing.
		startErr = onProvenClose()
	}
	delete(m.draining, name)
	m.mu.Unlock()
	return startErr
}

// reclaimTombstoneWhenStopped detaches a goroutine that waits for a wedged
// owner to finally exit, then removes its tombstone under m.mu. This self-heals
// the degraded "tombstone held forever after a join timeout" state without ever
// opening a second conn while the old one may be live. No goodbye and no
// replacement are emitted/started here — the timeout already declined both.
func (m *Manager) reclaimTombstoneWhenStopped(name string, s *sender) {
	go func() {
		<-s.stopped
		m.mu.Lock()
		// Only remove if it is still the SAME entry we left (a newer call may
		// have replaced it; that newer owner manages its own lifecycle).
		if e := m.draining[name]; e != nil && e.sender == s {
			delete(m.draining, name)
			slog.Info("ra: reclaimed tombstone after wedged owner finally exited",
				"interface", name)
		}
		m.mu.Unlock()
	}()
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
	// change must not blackhole hosts). Install a drainEntry so a concurrent
	// WithdrawOnce/Apply defers, and a racing graceful Withdraw can flip
	// goodbyeWanted on it (the release path then emits the standalone).
	for name, s := range m.senders {
		if _, ok := desired[name]; !ok {
			slog.Info("ra: removing sender", "interface", name)
			delete(m.senders, name)
			m.draining[name] = &drainEntry{sender: s, cfg: s.cfg}
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
			m.draining[name] = &drainEntry{sender: existing, cfg: existing.cfg}
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

	restartSet := make(map[string]*config.RAInterfaceConfig, len(toRestart))
	for _, cfg := range toRestart {
		restartSet[cfg.Interface] = cfg
	}

	// All stopped (removal AND changed-config restart) senders go through the
	// SAME releaseDrain discipline (round-4 unification): join-or-timeout →
	// exactly-once goodbye if owed → for a restart, start the replacement ONLY
	// on the proven-closed arm while the tombstone is held (≤1 live conn) and
	// only if a graceful withdraw did not supersede the replace. A removal
	// passes onProvenClose=nil (no replacement).
	for _, req := range toStop {
		name := req.name
		var onProvenClose func() error
		if cfg, isRestart := restartSet[name]; isRestart {
			cfg := cfg // capture
			onProvenClose = func() error {
				// Runs under m.mu, tombstone held, old conn proven closed.
				if err := m.startLocked(cfg); err != nil {
					return err
				}
				return nil
			}
		}
		if err := m.releaseDrain(name, req.s, epoch, onProvenClose); err != nil && firstErr == nil {
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

// ownedDrain is an interface whose draining sender THIS graceful Withdraw owns
// the join+release for (the active-sender case). The single owner runs
// releaseDrain, which is the sole emitter of any standalone goodbye and holds
// the entry across the emit.
type ownedDrain struct {
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
	// first and hard-stopped them, or a changed-config restart is mid stop->
	// start). claimGracefulLocked flips goodbyeWanted on those entries; their
	// existing owner's release path emits the standalone if owed.
	for name := range m.draining {
		names = append(names, name)
	}
	owned := m.claimGracefulLocked(names)
	epoch := m.epoch
	m.mu.Unlock()
	for _, o := range owned {
		// nil onProvenClose: a withdraw never starts a replacement.
		m.releaseDrain(o.name, o.s, epoch, nil)
	}
	return nil
}

// WithdrawInterfaces sends goodbye RAs and stops senders only for the named
// interfaces. Other senders are left running.
func (m *Manager) WithdrawInterfaces(names []string) {
	m.mu.Lock()
	m.bumpEpoch()
	owned := m.claimGracefulLocked(names)
	epoch := m.epoch
	m.mu.Unlock()
	for _, o := range owned {
		m.releaseDrain(o.name, o.s, epoch, nil)
	}
}

// claimGracefulLocked records the graceful withdrawal intent for each named
// interface UNDER m.mu, and returns only the interfaces THIS Withdraw owns the
// join+release for. Per interface (atomic under m.mu — #2033 MAJOR 2):
//   - active sender: move it to a NEW drainEntry{goodbyeWanted:true},
//     signalStop(graceful), and OWN the release (returned in ownedDrain). The
//     owner emits the goodbye on exit; releaseDrain's standalone backstop
//     covers the lost-upgrade case.
//   - already draining (Clear/restart/WithdrawOnce owns it): just flip
//     goodbyeWanted=true on the existing entry and upgrade the live sender (if
//     any) via signalStop(graceful). We do NOT own its release; the existing
//     owner's release path (releaseDrain / Apply restart) emits the standalone
//     if owed — claim-once via goodbyeClaimed guarantees no double-send even if
//     several Withdraws flip the same entry.
// Callers must hold m.mu.
func (m *Manager) claimGracefulLocked(names []string) []ownedDrain {
	var owned []ownedDrain
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, dup := seen[name]; dup {
			continue // dedup within this call
		}
		seen[name] = struct{}{}
		if s, ok := m.senders[name]; ok {
			slog.Info("ra: sending goodbye RA", "interface", name)
			delete(m.senders, name)
			m.draining[name] = &drainEntry{sender: s, cfg: s.cfg, goodbyeWanted: true}
			s.signalStop(modeGraceful)
			owned = append(owned, ownedDrain{name: name, s: s})
			continue
		}
		if e := m.draining[name]; e != nil {
			// Another caller (Clear / changed-config restart / WithdrawOnce)
			// owns this entry's release. Flip goodbyeWanted so that owner emits
			// the standalone if owed, and upgrade the still-running sender (if
			// any) so it may emit the goodbye itself. We do NOT take the release.
			e.goodbyeWanted = true
			if e.cfg == nil {
				e.cfg = m.cfgForName(name)
			}
			if e.sender != nil {
				slog.Info("ra: upgrading draining sender to graceful goodbye",
					"interface", name)
				e.sender.signalStop(modeGraceful)
			}
			continue
		}
		// No sender and no tombstone: nothing to withdraw (already fully gone).
	}
	return owned
}

// cfgForName returns a config to build a standalone goodbye from for name, when
// an existing drainEntry was a nil-cfg claim (e.g. a WithdrawOnce entry). Best
// effort: a WithdrawOnce entry carries no cfg, so a graceful Withdraw that
// races it cannot synthesize one — return nil and rely on the WithdrawOnce's
// own goodbye (it emits exactly one). Callers hold m.mu.
func (m *Manager) cfgForName(string) *config.RAInterfaceConfig { return nil }

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
	var toGoodbye []*config.RAInterfaceConfig
	for _, cfg := range configs {
		if m.interfaceBusy(cfg.Interface) {
			slog.Debug("ra: WithdrawOnce: interface busy, skipping",
				"interface", cfg.Interface)
			continue
		}
		// Claim the interface (sender:nil — no run() loop) and pre-mark the
		// goodbye as CLAIMED: WithdrawOnce emits exactly one goodbye below, so a
		// racing graceful Withdraw that flips goodbyeWanted must NOT also emit.
		// The entry is HELD across the emit so a concurrent Apply defers.
		m.draining[cfg.Interface] = &drainEntry{cfg: cfg, goodbyeClaimed: true}
		toGoodbye = append(toGoodbye, cfg)
	}
	m.mu.Unlock()

	for _, cfg := range toGoodbye {
		m.sendOneGoodbye(cfg)
		m.mu.Lock()
		delete(m.draining, cfg.Interface)
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
// hold m.mu; it moves senders to drainEntry tombstones, releases the lock to
// join+release each, then re-acquires — so it returns with m.mu held (matching
// its callers). No goodbye is emitted for a pure Clear (modeHard); but if a
// racing graceful Withdraw flipped goodbyeWanted on an entry, clearLocked's
// release path emits the standalone goodbye (claim-once, held across the emit).
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
		// drainEntry with the sender so a racing graceful Withdraw can flip
		// goodbyeWanted + upgrade the live sender (#2033 MAJOR 2).
		m.draining[name] = &drainEntry{sender: s, cfg: s.cfg}
		s.signalStop(modeHard)
		ps = append(ps, pending{name, s})
	}
	epoch := m.epoch

	// Join + release each OUTSIDE the lock so Clear of many interfaces does not
	// stall other callers; re-acquire before returning (caller expects m.mu
	// held). releaseDrain handles the claim-once + held-across-emit standalone
	// goodbye if a racing Withdraw wanted one. nil onProvenClose: Clear never
	// starts a replacement.
	m.mu.Unlock()
	for _, p := range ps {
		m.releaseDrain(p.name, p.s, epoch, nil)
	}
	m.mu.Lock()
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
