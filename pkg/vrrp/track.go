package vrrp

import (
	"log/slog"
	"net"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"
)

// Interface tracking (#1814). Single-interface tracking per VRRP group
// lowers the advertised priority while the tracked link is down so a
// healthy peer can take over. This file owns both the per-instance
// effective-priority primitives and the manager-side singleton
// link-watcher / poller that feeds link state into tracking instances.

// getPriority returns the effective advertised priority (#1814).
//   - cfg.Priority 0 is the resignation sentinel (ResignRG / shutdown
//     burst) and passes through UNCHANGED — the tracking clamp must
//     never apply to it.
//   - cfg.Priority 255 is the IP address owner: tracking is ignored
//     (an owner stepping down while still holding the address invites
//     duplicate-IP conflicts; the compiler warns at commit).
//   - Otherwise, while the tracked interface is down, TrackPriorityCost
//     is subtracted and the result clamped to [1, 254] so tracking can
//     never fabricate the priority-0 resignation sentinel.
//
// The no-track path returns cfg.Priority unchanged. Called from the
// advert path and masterDownInterval computation — keep it lock-cheap.
func (vi *vrrpInstance) getPriority() int {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	p := vi.cfg.Priority
	if p == 0 || p == 255 {
		return p
	}
	if vi.trackDown && vi.cfg.TrackInterface != "" {
		p -= vi.cfg.TrackPriorityCost
		if p < 1 {
			p = 1
		} else if p > 254 {
			p = 254
		}
	}
	return p
}

// setTrackDown records the tracked interface's link state. Logs only on
// transition — never per-event.
//
// The state machine needs no kick. A MASTER keeps advertising at the
// new (lower) effective priority via getPriority(); a preempt-enabled
// backup hearing that LOWER advert IGNORES it and lets its masterDown
// timer expire (handleBackupRx tail — instance.go:737 at plan time:
// "If preempt is true and incoming priority < ours, ignore — let timer
// expire"). So takeover after a tracked-link demotion lands in
// ~masterDownInterval (3×advert+skew: ≈97ms at 30ms adverts, ≈3.3s at
// 1s adverts) — RFC 5798 behavior, no forced abdication.
func (vi *vrrpInstance) setTrackDown(down bool) {
	vi.mu.Lock()
	changed := vi.trackDown != down
	vi.trackDown = down
	trackIface := vi.cfg.TrackInterface
	vi.mu.Unlock()
	if changed && trackIface != "" {
		slog.Info("vrrp: tracked interface state change",
			"key", vi.key(), "track_interface", trackIface,
			"down", down, "effective_priority", vi.getPriority())
	}
}

// trackedInterface returns the tracked Linux interface name, or "" when
// tracking is not configured.
func (vi *vrrpInstance) trackedInterface() string {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.cfg.TrackInterface
}

// ensureLinkWatcherLocked starts the singleton link-watcher goroutine.
// Caller MUST hold m.mu: watcherRunning latches under the manager mutex
// so UpdateInstances churn can never spawn a second watcher (#1814).
func (m *Manager) ensureLinkWatcherLocked() {
	if m.watcherRunning {
		return
	}
	m.watcherRunning = true
	m.watcherStarts++
	go m.runLinkWatcher()
}

// runLinkWatcher is the singleton tracked-link watcher (#1814). It
// subscribes to netlink link updates and pushes trackDown into every
// instance tracking the affected interface. The tracked-ifname →
// instance mapping is re-read from the manager under lock on EVERY
// event — instance churn is never captured stale. Cancellation follows
// the done-channel pattern (pkg/daemon/daemon_flow.go): m.watcherStop
// is closed from Manager.Stop and the netlink subscription observes the
// same channel. On subscribe failure (or unexpected subscription close)
// it degrades to a 1 s poll that runs only while tracked instances
// exist.
func (m *Manager) runLinkWatcher() {
	ch := make(chan netlink.LinkUpdate, 64)
	if err := m.subscribeLinks(ch, m.watcherStop); err != nil {
		slog.Warn("vrrp: link subscribe failed, falling back to 1s link polling", "err", err)
		m.runLinkPoller()
		return
	}
	slog.Info("vrrp: link watcher started (interface tracking)")
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
				slog.Warn("vrrp: link subscription closed, falling back to 1s link polling")
				m.runLinkPoller()
				return
			}
			attrs := u.Attrs()
			if attrs == nil {
				continue
			}
			up := u.Header.Type != unix.RTM_DELLINK && linkAttrsUp(attrs)
			m.applyTrackedLinkState(attrs.Name, up)
		}
	}
}

// runLinkPoller is the subscribe-failure fallback: poll tracked link
// state at 1 s. pollTrackedLinks performs no netlink queries while no
// instance tracks an interface.
func (m *Manager) runLinkPoller() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.watcherStop:
			return
		case <-ticker.C:
			m.pollTrackedLinks()
		}
	}
}

// pollTrackedLinks queries link state once for each distinct tracked
// interface and applies it to the tracking instances.
func (m *Manager) pollTrackedLinks() {
	m.mu.RLock()
	tracked := make(map[string][]*vrrpInstance)
	for _, vi := range m.instances {
		if name := vi.trackedInterface(); name != "" {
			tracked[name] = append(tracked[name], vi)
		}
	}
	m.mu.RUnlock()
	for name, vis := range tracked {
		up, err := m.linkState(name)
		down := err != nil || !up
		for _, vi := range vis {
			vi.setTrackDown(down)
		}
	}
}

// applyTrackedLinkState updates trackDown on every instance tracking
// ifName. Takes only the manager read lock; setTrackDown takes the
// per-instance lock (no reverse ordering exists — instances never take
// m.mu).
func (m *Manager) applyTrackedLinkState(ifName string, up bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, vi := range m.instances {
		if vi.trackedInterface() == ifName {
			vi.setTrackDown(!up)
		}
	}
}

// seedTrackState initializes an instance's trackDown from current
// kernel link state at instance create/update time (the netlink
// subscription only streams future updates). A missing tracked
// interface counts as down.
func (m *Manager) seedTrackState(vi *vrrpInstance, trackIface string) {
	if trackIface == "" {
		vi.setTrackDown(false)
		return
	}
	up, err := m.linkState(trackIface)
	if err != nil {
		slog.Warn("vrrp: tracked interface lookup failed, treating as down",
			"key", vi.key(), "track_interface", trackIface, "err", err)
		vi.setTrackDown(true)
		return
	}
	vi.setTrackDown(!up)
}

// netlinkLinkState is the production linkState seam: report whether the
// named link is operationally up.
func netlinkLinkState(name string) (bool, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return false, err
	}
	return linkAttrsUp(link.Attrs()), nil
}

// linkAttrsUp interprets link operational state. OperUnknown is common
// on virtual devices that report no carrier state — fall back to the
// IFF_UP admin flag there.
func linkAttrsUp(attrs *netlink.LinkAttrs) bool {
	switch attrs.OperState {
	case netlink.OperUp:
		return true
	case netlink.OperUnknown:
		return attrs.Flags&net.FlagUp != 0
	default:
		return false
	}
}
