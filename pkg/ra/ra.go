// Package ra implements an embedded Router Advertisement sender using
// mdlayher/ndp. It replaces the external radvd binary with per-interface
// sender goroutines that build and send RA packets directly.
package ra

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
)

// Manager manages per-interface RA sender goroutines.
type Manager struct {
	mu      sync.Mutex
	senders map[string]*sender // keyed by Linux interface name
}

// New creates a new RA manager.
func New() *Manager {
	return &Manager{
		senders: make(map[string]*sender),
	}
}

// Apply diffs the current senders against the desired set and starts/stops/
// updates as needed. Unchanged configs are left running without RA gap.
func (m *Manager) Apply(configs []*config.RAInterfaceConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(configs) == 0 {
		return m.clearLocked()
	}

	// Build desired map.
	desired := make(map[string]*config.RAInterfaceConfig, len(configs))
	for _, cfg := range configs {
		desired[cfg.Interface] = cfg
	}

	// Remove senders not in the desired set.
	for name, s := range m.senders {
		if _, ok := desired[name]; !ok {
			slog.Info("ra: removing sender", "interface", name)
			s.stop()
			delete(m.senders, name)
		}
	}

	// Add or update senders.
	var firstErr error
	for name, cfg := range desired {
		existing, ok := m.senders[name]
		if ok && configEqual(existing.cfg, cfg) {
			continue // No change.
		}

		// Changed config or new interface — stop old, start new.
		if ok {
			slog.Info("ra: restarting sender", "interface", name)
			existing.stop()
			delete(m.senders, name)
		}

		iface, err := net.InterfaceByName(name)
		if err != nil {
			slog.Warn("ra: interface not found, skipping",
				"interface", name, "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("interface %s: %w", name, err)
			}
			continue
		}

		s := newSender(cfg, iface)
		if err := s.start(); err != nil {
			slog.Warn("ra: failed to start sender",
				"interface", name, "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("start %s: %w", name, err)
			}
			continue
		}

		m.senders[name] = s
		slog.Info("ra: sender started", "interface", name,
			"prefixes", len(cfg.Prefixes))
	}

	return firstErr
}

// Withdraw sends goodbye RAs (lifetime=0) on all interfaces, then stops
// all senders. This tells hosts to immediately remove this router as a
// default gateway.
func (m *Manager) Withdraw() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, s := range m.senders {
		slog.Info("ra: sending goodbye RA", "interface", name)
		s.sendGoodbyeRA()
		s.stop()
	}

	m.senders = make(map[string]*sender)
	return nil
}

// WithdrawInterfaces sends goodbye RAs and stops senders only for the
// named interfaces. Other senders are left running.
func (m *Manager) WithdrawInterfaces(names []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, name := range names {
		if s, ok := m.senders[name]; ok {
			slog.Info("ra: sending goodbye RA (per-RG)", "interface", name)
			s.sendGoodbyeRA()
			s.stop()
			delete(m.senders, name)
		}
	}
}

// WithdrawOnce sends a one-shot goodbye RA (router lifetime=0) on the given
// interfaces. This is used on startup when a node boots as secondary to
// withdraw stale RA routes from a previous primary run. Unlike Withdraw(),
// this does NOT require a running sender — it creates a temporary NDP
// connection, sends the goodbye RA, and closes it.
//
// Skips interfaces that already have a running sender (the sender goroutine
// handles its own RA lifecycle, and a goodbye RA would kill a live primary).
func (m *Manager) WithdrawOnce(configs []*config.RAInterfaceConfig) {
	for _, cfg := range configs {
		// Skip if a sender is already running (means VRRP MASTER won the
		// race and started real RAs — don't clobber with lifetime=0).
		m.mu.Lock()
		_, running := m.senders[cfg.Interface]
		m.mu.Unlock()
		if running {
			slog.Debug("ra: WithdrawOnce: sender already running, skipping", "interface", cfg.Interface)
			continue
		}

		iface, err := net.InterfaceByName(cfg.Interface)
		if err != nil {
			slog.Debug("ra: WithdrawOnce: interface not found", "interface", cfg.Interface, "err", err)
			continue
		}
		s := newSender(cfg, iface)
		if err := s.start(); err != nil {
			slog.Debug("ra: WithdrawOnce: failed to start", "interface", cfg.Interface, "err", err)
			continue
		}
		s.sendGoodbyeRA()
		s.stop()
	}
}

// Clear stops all senders without sending goodbye RAs.
func (m *Manager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clearLocked()
}

func (m *Manager) clearLocked() error {
	for _, s := range m.senders {
		s.stop()
	}
	m.senders = make(map[string]*sender)
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
}

// Status returns information about all active RA senders.
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
		if !s.lastRA.IsZero() {
			info.LastRA = fmt.Sprintf("%.0fs ago", time.Since(s.lastRA).Seconds())
		} else {
			info.LastRA = "never"
		}
		result = append(result, info)
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
		a.NAT64PrefixLife != b.NAT64PrefixLife {
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
