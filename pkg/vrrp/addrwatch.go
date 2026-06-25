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
//
// Recreated-link robustness (#2707): the fast path matches on the cached
// vi.iface.Index. When a VLAN/GRE/WireGuard sub-interface is deleted and
// recreated (config change, driver restart, link-cycle recovery) the kernel
// assigns a NEW ifindex, so an address event on the recreated link no longer
// matches any cached ifindex and would be silently dropped until the ~2s
// UpdateInstances reconcile noticed the drift — leaving the instance
// advertising from a stale source (or off a stale socket) for that whole
// window. On a cached-ifindex MISS we therefore resolve the event ifindex back
// to its current link NAME (a single syscall, ONLY on a miss — the common
// unchanged-ifindex path stays syscall-free) and re-match instances by their
// STABLE configured interface name. A match whose cached ifindex differs is a
// recreated link: re-resolving its source against the stale vi.iface would
// query the wrong/absent ifindex (net.Interface.Addrs filters by Index), so
// instead we trigger an immediate reconcile (onEventDrop) which rebuilds the
// instance with a fresh socket bound to the new ifindex AND a fresh source —
// the same restart UpdateInstances would do, but event-driven rather than
// ~2s-deferred. Mutating vi.iface here would race the run-loop reads in
// sendPacket/sendPacketIPv6, so we deliberately do not; the reconcile owns the
// rebind.
func (m *Manager) reresolveAddrFor(ifindex int) {
	m.mu.RLock()
	matched := false
	for _, vi := range m.instances {
		if vi.iface != nil && vi.iface.Index == ifindex {
			vi.reresolveLocalAddrs()
			matched = true
		}
	}
	if matched {
		m.mu.RUnlock()
		return
	}

	// Cached-ifindex miss: the event may be for a recreated link whose name
	// still matches a configured instance but whose ifindex drifted. Resolve
	// the event ifindex -> current name and re-match by the stable name.
	resolve := m.resolveLinkName
	onDrop := m.onEventDrop
	m.mu.RUnlock()
	if resolve == nil {
		return
	}
	name, err := resolve(ifindex)
	if err != nil || name == "" {
		return // ifindex gone (pure delete) or unresolvable — nothing to rebind
	}

	m.mu.RLock()
	driftDetected := false
	for _, vi := range m.instances {
		if vi.iface != nil && vi.cfg.Interface == name && vi.iface.Index != ifindex {
			driftDetected = true
			slog.Info("vrrp: address event on recreated link, scheduling reconcile",
				"key", vi.key(), "interface", name,
				"old_ifindex", vi.iface.Index, "new_ifindex", ifindex)
		}
	}
	m.mu.RUnlock()

	if driftDetected && onDrop != nil {
		// Reuse the immediate-reconcile lever (the daemon wires onEventDrop to
		// schedule a reconcile pass). UpdateInstances then rebinds the drifted
		// instance to the new ifindex and re-resolves the source.
		onDrop()
	}
}

// netlinkLinkName is the production resolveLinkName seam (#2707): map a kernel
// ifindex to its current link name. Returns an error if the ifindex no longer
// exists (a pure delete with no recreate) — the caller treats that as "nothing
// to rebind".
func netlinkLinkName(ifindex int) (string, error) {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return "", err
	}
	return link.Attrs().Name, nil
}
