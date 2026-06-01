package routing

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// linkOps is the narrow netlink surface the interface domains
// (tunnel, xfrm, bond, reth) use for link/address lifecycle. Satisfied
// by *netlink.Handle in production; tests substitute a fake.
type linkOps interface {
	LinkByName(name string) (netlink.Link, error)
	LinkAdd(netlink.Link) error
	LinkDel(netlink.Link) error
	LinkSetUp(netlink.Link) error
	LinkSetDown(netlink.Link) error
	LinkSetMaster(netlink.Link, netlink.Link) error
	LinkSetMTU(netlink.Link, int) error
	LinkList() ([]netlink.Link, error)
	AddrAdd(netlink.Link, *netlink.Addr) error
	AddrDel(netlink.Link, *netlink.Addr) error
	AddrList(netlink.Link, int) ([]netlink.Addr, error)
}

// vrfBinder is the cross-domain dependency tunnel apply needs to bind a
// tunnel interface to a routing-instance VRF. Satisfied by *vrfManager.
// BindInterfaceToVRF takes no lock, so calling it while holding the
// tunnel lock introduces no lock-ordering cycle (see vrf.go).
type vrfBinder interface {
	BindInterfaceToVRF(ifaceName, instanceName string) error
}

// KeepaliveState tracks the status of a GRE tunnel keepalive probe.
type KeepaliveState struct {
	mu          sync.Mutex
	Up          bool // true if tunnel is considered up
	Failures    int  // consecutive probe failures
	LastSuccess time.Time
	LastFailure time.Time
	RemoteAddr  string // remote endpoint being probed
	Interval    int    // probe interval in seconds
	MaxRetries  int    // failures before declaring down
}

// keepaliveRunner manages the goroutine for a single tunnel's keepalive.
//
// #848: `done` is closed by keepaliveLoop just before it returns.
// Close() / stopAll drain on this channel so the netlink handle is not
// closed while a keepalive goroutine is still in flight (use-after-close
// on the shared netlink handle).
type keepaliveRunner struct {
	cancel context.CancelFunc
	state  *KeepaliveState
	done   chan struct{}
}

// TunnelStatus holds the status of a tunnel interface.
type TunnelStatus struct {
	Name          string
	Source        string
	Destination   string
	State         string // "up" or "down"
	Addresses     []string
	KeepaliveUp   *bool  // nil if no keepalive configured
	KeepaliveInfo string // human-readable keepalive status
}

// tunnelManager owns GRE/IPIP tunnel lifecycle and per-tunnel keepalive
// goroutines. The mu field replaces the tunnel slice of the former
// shared Manager.ifaceMu; keepalives belong to this domain (their only
// user is tunnel apply/clear), so mu protects both tunnels and the
// keepalives map as one cohesive critical section.
type tunnelManager struct {
	ops       linkOps
	vrfBinder vrfBinder

	mu         sync.Mutex
	tunnels    []string                    // currently created tunnel interface names
	keepalives map[string]*keepaliveRunner // tunnel name -> runner
}

// Apply creates GRE tunnel interfaces, brings them up, and assigns
// addresses. Previous tunnels are removed first. Starts keepalive
// probes for tunnels that have keepalive configured.
func (t *tunnelManager) Apply(tunnels []*config.TunnelConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.clearLocked(); err != nil {
		slog.Warn("failed to clear previous tunnels", "err", err)
	}

	for _, tc := range tunnels {
		// WireGuard TUNs are persistent (#1432 S2a, AGY Hazard B): never
		// delete-and-recreate on reload — that would flap wgN and destroy
		// its addresses + FRR routes every commit. applyWireguardTunLocked
		// reuses an existing wgN in place.
		if tc.Mode == "wireguard" {
			if err := t.applyWireguardTunLocked(tc); err != nil {
				slog.Warn("failed to apply wireguard tunnel",
					"name", tc.Name, "err", err)
			}
			continue
		}
		if existing, err := t.ops.LinkByName(tc.Name); err == nil {
			if err := t.ops.LinkDel(existing); err != nil {
				slog.Warn("failed to replace existing tunnel link",
					"name", tc.Name, "existing_type", existing.Type(), "err", err)
				continue
			}
			slog.Info("removed existing tunnel link before apply",
				"name", tc.Name, "existing_type", existing.Type())
		}

		if tc.AnchorOnly {
			anchor := &netlink.Tuntap{
				LinkAttrs:  netlink.LinkAttrs{Name: tc.Name},
				Mode:       netlink.TUNTAP_MODE_TUN,
				Flags:      netlink.TUNTAP_NO_PI | netlink.TUNTAP_ONE_QUEUE,
				Queues:     1,
				NonPersist: false,
			}
			if err := t.ops.LinkAdd(anchor); err != nil {
				// Handle upgrade from dummy-anchor to TUN: if a link with
				// this name already exists, check if it's already a TUN.
				// If it's a different type (e.g. dummy), delete and recreate.
				if existing, lookupErr := t.ops.LinkByName(tc.Name); lookupErr == nil {
					if existingTun, isTun := existing.(*netlink.Tuntap); isTun {
						slog.Info("tunnel anchor already exists as TUN, reusing",
							"name", tc.Name)
						// Operate on the kernel-fetched link (which carries
						// the real ifindex and attributes) rather than the
						// freshly-constructed, ifindex-less anchor. The
						// subsequent LinkSetUp/AddrAdd would otherwise rely
						// on the netlink library re-resolving the index by
						// name (ensureIndex) while still reading stale
						// non-index LinkAttrs off the fresh struct.
						// existingTun.Fds is nil on a kernel-fetched Tuntap,
						// so closeTuntapFiles below is a safe no-op.
						anchor = existingTun
						goto anchorReady
					}
					slog.Info("replacing non-TUN tunnel anchor",
						"name", tc.Name, "type", existing.Type())
					_ = t.ops.LinkDel(existing)
					if retryErr := t.ops.LinkAdd(anchor); retryErr != nil {
						slog.Warn("failed to recreate tunnel anchor",
							"name", tc.Name, "err", retryErr)
						continue
					}
				} else {
					slog.Warn("failed to create tunnel anchor",
						"name", tc.Name, "err", err)
					continue
				}
			}
		anchorReady:
			closeTuntapFiles(anchor.Fds)
			if err := t.ops.LinkSetUp(anchor); err != nil {
				slog.Warn("failed to bring up tunnel anchor",
					"name", tc.Name, "err", err)
			}
			for _, addrStr := range tc.Addresses {
				addr, err := netlink.ParseAddr(addrStr)
				if err != nil {
					slog.Warn("invalid tunnel anchor address",
						"name", tc.Name, "addr", addrStr, "err", err)
					continue
				}
				if err := t.ops.AddrAdd(anchor, addr); err != nil {
					slog.Warn("failed to add tunnel anchor address",
						"name", tc.Name, "addr", addrStr, "err", err)
				}
			}
			if tc.RoutingInstance != "" {
				if err := t.vrfBinder.BindInterfaceToVRF(tc.Name, tc.RoutingInstance); err != nil {
					slog.Warn("failed to bind tunnel anchor to VRF",
						"name", tc.Name, "vrf", tc.RoutingInstance, "err", err)
				}
			}
			slog.Info("tunnel anchor created", "name", tc.Name, "mode", "tun")
			t.tunnels = append(t.tunnels, tc.Name)
			continue
		}

		localIP := net.ParseIP(tc.Source)
		remoteIP := net.ParseIP(tc.Destination)
		if localIP == nil || remoteIP == nil {
			slog.Warn("invalid tunnel endpoints",
				"name", tc.Name, "src", tc.Source, "dst", tc.Destination)
			continue
		}

		ttl := tc.TTL
		if ttl == 0 {
			ttl = 64
		}

		isIPv6 := localIP.To4() == nil

		var tunnelLink netlink.Link
		switch tc.Mode {
		case "ipip":
			if isIPv6 {
				// IPIP over IPv6: use ip6tnl with IPPROTO_IPIP
				tunnelLink = &netlink.Ip6tnl{
					LinkAttrs: netlink.LinkAttrs{Name: tc.Name},
					Local:     localIP,
					Remote:    remoteIP,
					Ttl:       uint8(ttl),
					Proto:     4, // IPPROTO_IPIP
				}
			} else {
				tunnelLink = &netlink.Iptun{
					LinkAttrs: netlink.LinkAttrs{Name: tc.Name},
					Local:     localIP,
					Remote:    remoteIP,
					Ttl:       uint8(ttl),
				}
			}
		default: // "gre" or ""
			// Gretun.Type() auto-detects IPv6 → returns "ip6gre"
			greLink := &netlink.Gretun{
				LinkAttrs: netlink.LinkAttrs{Name: tc.Name},
				Local:     localIP,
				Remote:    remoteIP,
				Ttl:       uint8(ttl),
			}
			if tc.Key > 0 {
				greLink.IKey = tc.Key
				greLink.OKey = tc.Key
			}
			tunnelLink = greLink
		}

		if err := t.ops.LinkAdd(tunnelLink); err != nil {
			slog.Warn("failed to create tunnel",
				"name", tc.Name, "mode", tc.Mode, "err", err)
			continue
		}

		// IPv6 GRE: disable encaplimit to avoid adding an IPv6
		// Destination Options extension header.  Many transit networks
		// drop IPv6 packets with extension headers (RFC 7872).
		if isIPv6 && (tc.Mode == "gre" || tc.Mode == "") {
			if out, err := exec.Command("ip", "link", "set", tc.Name,
				"type", "ip6gre", "encaplimit", "none").CombinedOutput(); err != nil {
				slog.Warn("failed to set tunnel encaplimit",
					"name", tc.Name, "err", err, "output", string(out))
			}
		}

		if err := t.ops.LinkSetUp(tunnelLink); err != nil {
			slog.Warn("failed to bring up tunnel",
				"name", tc.Name, "err", err)
		}

		// Assign IP addresses
		for _, addrStr := range tc.Addresses {
			addr, err := netlink.ParseAddr(addrStr)
			if err != nil {
				slog.Warn("invalid tunnel address",
					"name", tc.Name, "addr", addrStr, "err", err)
				continue
			}
			if err := t.ops.AddrAdd(tunnelLink, addr); err != nil {
				slog.Warn("failed to add tunnel address",
					"name", tc.Name, "addr", addrStr, "err", err)
			}
		}

		// Bind tunnel to VRF if routing-instance is configured.
		if tc.RoutingInstance != "" {
			if err := t.vrfBinder.BindInterfaceToVRF(tc.Name, tc.RoutingInstance); err != nil {
				slog.Warn("failed to bind tunnel to VRF",
					"name", tc.Name, "vrf", tc.RoutingInstance, "err", err)
			}
		}

		slog.Info("tunnel created", "name", tc.Name,
			"src", tc.Source, "dst", tc.Destination)
		t.tunnels = append(t.tunnels, tc.Name)

		// Start keepalive probe if configured
		if tc.Keepalive > 0 {
			t.startKeepalive(tc.Name, tc.Destination, tc.Keepalive, tc.KeepaliveRetry)
		}
	}

	return nil
}

// WG per-packet outer overhead (must mirror userspace-dp
// afxdp/wg/mod.rs WG_OVERHEAD_V4/V6): outer IP + UDP(8) + WG data
// header(16) + Poly1305 tag(16). Plus up to 15 bytes of §5.4.6 pad.
const (
	wgOverheadV4 = 20 + 8 + 16 + 16 // 60
	wgOverheadV6 = 40 + 8 + 16 + 16 // 80
	wgPadWorst   = 15
)

// wgTunMTUForEndpoint computes the inner (wgN) MTU cap (#1432 S2a, AGY
// Hazard A / H2). The kernel must never hand the WG control thread a
// plaintext packet that, once encapped with the worst-case overhead
// plus §5.4.6 pad, exceeds the outer MTU and forces outer IP
// fragmentation. The overhead depends on the outer IP family (the WG
// peer endpoint address): IPv6-outer is 20 bytes larger. The outer MTU
// is assumed to be a standard 1500 (S2a single-tunnel); the control
// thread also enforces an exact pad-aware guard (wg_control.rs), so this
// is the first line, not the only one.
func wgTunMTUForEndpoint(tc *config.TunnelConfig) int {
	const outerMTU = 1500
	// A configured v4 endpoint uses the v4 overhead; a v6 endpoint (or a
	// responder-only/roaming endpoint with no configured address, which
	// the Rust control thread may LEARN as v6 — Codex r4 MAJOR) uses the
	// larger v6 overhead so the kernel never hands the control thread an
	// inner packet that the v6-aware encap guard would then drop.
	overhead := wgOverheadV6
	if tc.WgEndpoint != "" {
		if host, _, err := net.SplitHostPort(tc.WgEndpoint); err == nil {
			if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
				overhead = wgOverheadV4
			}
		}
	}
	return outerMTU - overhead - wgPadWorst
}

// applyWireguardTunLocked creates (or reuses) the persistent wgN TUN
// netdev for a WireGuard tunnel endpoint and configures its MTU,
// addresses, and VRF binding. The device is intentionally NOT tracked
// in t.tunnels: clearLocked must not delete it on reload (AGY Hazard B
// — flapping wgN destroys its addresses and FRR routes every commit).
//
// Known S2a limitation (AGY M1): because the device is untracked, a WG
// tunnel REMOVED from the config is not torn down by clearLocked and
// leaks until `ip link del` or daemon restart. S2a single-tunnel scope
// accepts this in exchange for reload stability; multi-instance teardown
// is owned by the S6 grammar work (#1434).
//
// The Rust control thread (coordinator/wg_control.rs) attaches to this
// persistent device by name.
func (t *tunnelManager) applyWireguardTunLocked(tc *config.TunnelConfig) error {
	mtu := wgTunMTUForEndpoint(tc)
	link, err := t.ops.LinkByName(tc.Name)
	// Copilot C3: only reuse an existing link if it is actually a TUN/TAP.
	// A name collision with some other interface type (e.g. a leftover
	// dummy) must be deleted and recreated, not mutated — otherwise we'd
	// bring up + address + VRF-bind the wrong device, and the Rust side's
	// open_tun on the same name would then fail.
	mustCreate := err != nil
	if err == nil {
		tt, isTuntap := link.(*netlink.Tuntap)
		if !isTuntap || tt.Mode != netlink.TUNTAP_MODE_TUN {
			// Not a TUN (a TAP, or some other type entirely). The Rust
			// side opens it with IFF_TUN, so a TAP would fail there;
			// delete + recreate as a TUN rather than mutate the wrong
			// device (Codex r3 MINOR).
			slog.Info("replacing non-TUN link before wireguard tun create",
				"name", tc.Name, "type", link.Type())
			if delErr := t.ops.LinkDel(link); delErr != nil {
				return fmt.Errorf("replace non-tun wireguard link %s: %w", tc.Name, delErr)
			}
			mustCreate = true
		}
	}
	if mustCreate {
		// Create a persistent TUN. NonPersist:false keeps the netdev
		// alive after the creating fd closes, so a reload that does not
		// touch this device leaves it (and its routes) intact.
		tun := &netlink.Tuntap{
			LinkAttrs:  netlink.LinkAttrs{Name: tc.Name, MTU: mtu},
			Mode:       netlink.TUNTAP_MODE_TUN,
			Flags:      netlink.TUNTAP_NO_PI,
			Queues:     1,
			NonPersist: false,
		}
		if addErr := t.ops.LinkAdd(tun); addErr != nil {
			return fmt.Errorf("create wireguard tun %s: %w", tc.Name, addErr)
		}
		closeTuntapFiles(tun.Fds)
		link = tun
		// vishvananda/netlink creates a TUN via TUNSETIFF and may return
		// before the generic LinkAttrs.MTU is applied, leaving the kernel
		// device at its default MTU on first apply (Codex r4 MAJOR).
		// Set the MTU explicitly after create so the inner cap is live
		// immediately, not only after a later reload.
		if mtuErr := t.ops.LinkSetMTU(link, mtu); mtuErr != nil {
			slog.Warn("failed to set wireguard tun mtu on create",
				"name", tc.Name, "mtu", mtu, "err", mtuErr)
		}
		slog.Info("wireguard tun created", "name", tc.Name, "mtu", mtu)
	} else {
		// Reuse in place; reconcile the MTU if the config changed it
		// (AGY M4 / Copilot C4 — a stale MTU on reuse, including a
		// pre-created device, would otherwise persist).
		if link.Attrs().MTU != mtu {
			if mtuErr := t.ops.LinkSetMTU(link, mtu); mtuErr != nil {
				slog.Warn("failed to update wireguard tun mtu",
					"name", tc.Name, "mtu", mtu, "err", mtuErr)
			} else {
				slog.Info("wireguard tun mtu updated", "name", tc.Name, "mtu", mtu)
			}
		}
		slog.Debug("wireguard tun reused", "name", tc.Name)
	}

	if err := t.ops.LinkSetUp(link); err != nil {
		slog.Warn("failed to bring up wireguard tun", "name", tc.Name, "err", err)
	}

	// Symmetric address reconciliation (Copilot C5): because the device
	// is persistent and never recreated, addresses removed from the config
	// would otherwise survive every reload and keep being routed. Add
	// configured addresses not yet present, and delete present addresses
	// not in the config — while preserving the device itself.
	want := make(map[string]bool, len(tc.Addresses))
	for _, addrStr := range tc.Addresses {
		addr, parseErr := netlink.ParseAddr(addrStr)
		if parseErr != nil {
			slog.Warn("invalid wireguard tun address",
				"name", tc.Name, "addr", addrStr, "err", parseErr)
			continue
		}
		want[addr.IPNet.String()] = true
	}
	existing := map[string]bool{}
	if addrs, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL); listErr == nil {
		for i := range addrs {
			a := addrs[i]
			key := a.IPNet.String()
			existing[key] = true
			// Skip link-local (fe80::) — the kernel manages it.
			if !want[key] && a.IP != nil && !a.IP.IsLinkLocalUnicast() {
				if delErr := t.ops.AddrDel(link, &a); delErr != nil {
					slog.Warn("failed to remove stale wireguard tun address",
						"name", tc.Name, "addr", key, "err", delErr)
				} else {
					slog.Info("removed stale wireguard tun address",
						"name", tc.Name, "addr", key)
				}
			}
		}
	}
	for _, addrStr := range tc.Addresses {
		addr, parseErr := netlink.ParseAddr(addrStr)
		if parseErr != nil {
			continue
		}
		if existing[addr.IPNet.String()] {
			continue
		}
		if addErr := t.ops.AddrAdd(link, addr); addErr != nil {
			slog.Warn("failed to add wireguard tun address",
				"name", tc.Name, "addr", addrStr, "err", addErr)
		}
	}

	if tc.RoutingInstance != "" {
		if bindErr := t.vrfBinder.BindInterfaceToVRF(tc.Name, tc.RoutingInstance); bindErr != nil {
			slog.Warn("failed to bind wireguard tun to VRF",
				"name", tc.Name, "vrf", tc.RoutingInstance, "err", bindErr)
		}
	}
	return nil
}

// closeTuntapFiles closes the file descriptors returned by a Tuntap
// LinkAdd so they are not leaked.
func closeTuntapFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

// stopAll cancels all running keepalive goroutines and waits for them
// to exit. Acquires mu.
//
// #848: draining (not just cancelling) is required because
// keepaliveLoop touches the netlink handle on bring-up/down. The
// façade Close() then closes the handle, so any in-flight tick that
// hadn't yet checked ctx.Done() would use-after-close. The done
// channel makes the drain explicit.
func (t *tunnelManager) stopAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopAllKeepalivesLocked()
}

// stopAllKeepalivesLocked cancels all keepalive goroutines and waits
// for them to exit. Caller MUST hold mu.
func (t *tunnelManager) stopAllKeepalivesLocked() {
	runners := t.keepalives
	t.keepalives = make(map[string]*keepaliveRunner)
	for name, runner := range runners {
		runner.cancel()
		<-runner.done
		slog.Debug("stopped keepalive", "tunnel", name)
	}
}

// startKeepalive starts a keepalive probe goroutine for a tunnel.
// Caller MUST hold mu.
func (t *tunnelManager) startKeepalive(tunnelName, remoteAddr string, interval, maxRetries int) {
	// Stop existing keepalive for this tunnel if any. Drain on done
	// so the replacement doesn't race the old goroutine on the handle.
	if runner, ok := t.keepalives[tunnelName]; ok {
		runner.cancel()
		<-runner.done
	}

	if maxRetries <= 0 {
		maxRetries = 3
	}

	state := &KeepaliveState{
		Up:         true,
		RemoteAddr: remoteAddr,
		Interval:   interval,
		MaxRetries: maxRetries,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.keepalives[tunnelName] = &keepaliveRunner{
		cancel: cancel,
		state:  state,
		done:   done,
	}

	go t.keepaliveLoop(ctx, done, tunnelName, state)
	slog.Info("started keepalive", "tunnel", tunnelName,
		"remote", remoteAddr, "interval", interval, "retries", maxRetries)
}

// keepaliveLoop runs periodic ICMP probes to the tunnel remote endpoint.
// Closes `done` when it returns so stopAll can drain.
func (t *tunnelManager) keepaliveLoop(ctx context.Context, done chan struct{}, tunnelName string, state *KeepaliveState) {
	defer close(done)
	ticker := time.NewTicker(time.Duration(state.Interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ok := probeICMP(state.RemoteAddr)
			state.mu.Lock()
			if ok {
				state.LastSuccess = time.Now()
				if !state.Up {
					slog.Info("tunnel keepalive recovered", "tunnel", tunnelName,
						"remote", state.RemoteAddr)
					state.Up = true
					state.Failures = 0
					// Bring tunnel back up
					if link, err := t.ops.LinkByName(tunnelName); err == nil {
						t.ops.LinkSetUp(link)
					}
				}
				state.Failures = 0
			} else {
				state.Failures++
				state.LastFailure = time.Now()
				if state.Up && state.Failures >= state.MaxRetries {
					slog.Warn("tunnel keepalive failed, marking down",
						"tunnel", tunnelName, "remote", state.RemoteAddr,
						"failures", state.Failures)
					state.Up = false
					// Bring tunnel down
					if link, err := t.ops.LinkByName(tunnelName); err == nil {
						t.ops.LinkSetDown(link)
					}
				}
			}
			state.mu.Unlock()
		}
	}
}

// probeICMP sends a single ICMP echo request and returns true if the host responds.
func probeICMP(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}

	network := "ip4:icmp"
	if ip.To4() == nil {
		network = "ip6:ipv6-icmp"
	}

	conn, err := net.DialTimeout(network, addr, 3*time.Second)
	if err != nil {
		// Fallback: use UDP dial as a reachability check when raw socket
		// is not available (no CAP_NET_RAW). A successful UDP dial only
		// means the route exists, but for keepalive purposes this is
		// close enough. ping utility would be better but adds exec overhead.
		conn2, err2 := net.DialTimeout("udp", net.JoinHostPort(addr, "1"), 3*time.Second)
		if err2 != nil {
			return false
		}
		conn2.Close()
		return true
	}
	conn.Close()
	return true
}

// GetKeepaliveState returns the keepalive state for a tunnel, or nil
// if no keepalive is configured.
//
// #848: mu protects the keepalives map against concurrent
// startKeepalive / stopAll mutations from Apply / Clear. The returned
// *KeepaliveState pointer is safe to dereference outside the lock —
// Go GC keeps the value alive even if a subsequent stopAll removes it
// from the map.
func (t *tunnelManager) GetKeepaliveState(tunnelName string) *KeepaliveState {
	t.mu.Lock()
	defer t.mu.Unlock()
	runner, ok := t.keepalives[tunnelName]
	if !ok {
		return nil
	}
	return runner.state
}

// Clear removes all previously created tunnel interfaces.
func (t *tunnelManager) Clear() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.clearLocked()
}

// clearLocked is the lock-free body of Clear. Caller must hold mu.
// Used internally by Apply which already holds the lock.
func (t *tunnelManager) clearLocked() error {
	t.stopAllKeepalivesLocked()
	for _, name := range t.tunnels {
		link, err := t.ops.LinkByName(name)
		if err != nil {
			continue // already gone
		}
		if err := t.ops.LinkDel(link); err != nil {
			slog.Warn("failed to delete tunnel", "name", name, "err", err)
		} else {
			slog.Info("tunnel removed", "name", name)
		}
	}
	t.tunnels = nil
	return nil
}

// GetStatus returns the status of managed tunnel interfaces.
func (t *tunnelManager) GetStatus() ([]TunnelStatus, error) {
	// #848: snapshot tunnel names under mu, then iterate without the
	// lock so a long netlink probe can't block applyConfig.
	t.mu.Lock()
	names := append([]string(nil), t.tunnels...)
	t.mu.Unlock()

	var result []TunnelStatus
	for _, name := range names {
		ts := TunnelStatus{Name: name, State: "down"}

		link, err := t.ops.LinkByName(name)
		if err != nil {
			ts.State = "not found"
			result = append(result, ts)
			continue
		}

		if link.Attrs().Flags&net.FlagUp != 0 {
			ts.State = "up"
		}

		switch tun := link.(type) {
		case *netlink.Gretun:
			ts.Source = tun.Local.String()
			ts.Destination = tun.Remote.String()
		case *netlink.Iptun:
			ts.Source = tun.Local.String()
			ts.Destination = tun.Remote.String()
		case *netlink.Ip6tnl:
			ts.Source = tun.Local.String()
			ts.Destination = tun.Remote.String()
		}

		addrs, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
		if err == nil {
			for _, a := range addrs {
				ts.Addresses = append(ts.Addresses, a.IPNet.String())
			}
		}

		// Add keepalive info
		if ks := t.GetKeepaliveState(name); ks != nil {
			ks.mu.Lock()
			up := ks.Up
			ts.KeepaliveUp = &up
			if up {
				ts.KeepaliveInfo = fmt.Sprintf("up (interval %ds, %d retries)",
					ks.Interval, ks.MaxRetries)
			} else {
				ts.KeepaliveInfo = fmt.Sprintf("down (%d consecutive failures)",
					ks.Failures)
			}
			ks.mu.Unlock()
		}

		result = append(result, ts)
	}
	return result, nil
}
