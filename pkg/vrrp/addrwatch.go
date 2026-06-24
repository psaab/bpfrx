package vrrp

import (
	"log/slog"

	"github.com/vishvananda/netlink"
)

// Source-address watcher (#2528). VRRP advert source addresses
// (localIP/localIPv6) were resolved once per instance at openSocket() time
// and never invalidated. If the interface's IPv4 or link-local IPv6 changed
// during operation — most acutely the RETH MAC reprogram cycle
// (programRethMAC: link DOWN -> set MAC -> UP flushes ALL kernel addresses;
// networkd KeepConfiguration=static restores them, but with a 30ms-1s window
// against the next 30ms advert) — the instance kept advertising from the
// stale source: the kernel silently rejects the send AND self-filtering in
// handleMasterRx misclassifies our own adverts as a peer's -> false master
// conflict / split-brain. This singleton goroutine subscribes to netlink
// ADDRESS updates and re-resolves the source on any add/del affecting an
// interface a VRRP instance is bound to. It complements the link-watcher
// (track.go), which handles tracked-interface priority demotion — a different
// concern on a different latch.

// ensureAddrWatcherLocked starts the singleton address-watcher goroutine.
// Caller MUST hold m.mu so addrWatcherRunning latches atomically — repeated
// UpdateInstances churn can never spawn a second watcher.
func (m *Manager) ensureAddrWatcherLocked() {
	if m.addrWatcherRunning {
		return
	}
	m.addrWatcherRunning = true
	m.addrWatcherStarts++
	go m.runAddrWatcher()
}

// runAddrWatcher subscribes to netlink address updates and re-resolves the
// advert source for every instance bound to the changed interface. The
// ifindex -> instances mapping is re-read under lock on EVERY event so
// instance churn (UpdateInstances rebinds, #2294 ifindex drift) is never
// captured stale. Cancellation follows the shared m.watcherStop done-channel
// (closed by Manager.Stop; the netlink subscription observes the same
// channel).
//
// Unlike the link-watcher there is no poll fallback: address re-resolution is
// an OPTIMIZATION that closes the stale-NON-nil source window. The
// sendPacket()/sendPacketIPv6() lazy path still recovers a nil (invalidated)
// source on the next advert, and the 2s reconcile rebuilds instances, so a
// subscribe failure degrades to pre-#2528 behavior rather than breaking
// correctness. On subscribe failure or an unexpected subscription close the
// latch is cleared so a later UpdateInstances can retry the subscribe
// (self-healing, one short-lived goroutine per ~2s reconcile at worst).
func (m *Manager) runAddrWatcher() {
	ch := make(chan netlink.AddrUpdate, 64)
	if err := m.subscribeAddrs(ch, m.watcherStop); err != nil {
		slog.Warn("vrrp: address subscribe failed, advert source will not auto-refresh on address change", "err", err)
		m.clearAddrWatcherLatch()
		return
	}
	slog.Info("vrrp: address watcher started (advert source re-resolution)")
	for {
		select {
		case <-m.watcherStop:
			return
		case u, ok := <-ch:
			if !ok {
				select {
				case <-m.watcherStop:
					return
				default:
				}
				slog.Warn("vrrp: address subscription closed, advert source will not auto-refresh on address change")
				m.clearAddrWatcherLatch()
				return
			}
			m.reresolveAddrFor(u.LinkIndex)
		}
	}
}

// clearAddrWatcherLatch resets the singleton latch so a future
// UpdateInstances can re-start the watcher after a subscribe failure or a
// subscription close.
func (m *Manager) clearAddrWatcherLatch() {
	m.mu.Lock()
	m.addrWatcherRunning = false
	m.mu.Unlock()
}

// reresolveAddrFor re-resolves the advert source for every instance bound to
// the given kernel ifindex. Takes only the manager read lock; the
// per-instance setLocalIP/setLocalIPv6 stores are atomic (#2258), so no
// per-instance lock is needed and no lock-order inversion with m.mu exists
// (instances never take m.mu). Filtering by ifindex ensures churn on an
// interface no VRRP instance uses is ignored.
func (m *Manager) reresolveAddrFor(ifindex int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, vi := range m.instances {
		if vi.iface != nil && vi.iface.Index == ifindex {
			vi.reresolveLocalAddrs()
		}
	}
}
