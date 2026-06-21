// Package dhcprelay implements a DHCP relay agent (RFC 3046) that forwards
// DHCPv4 packets between clients on local interfaces and remote DHCP servers.
// It inserts Option 82 (Relay Agent Information) with the circuit-id sub-option
// set to the receiving interface name, allowing servers to identify the origin.
package dhcprelay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"

	"github.com/psaab/xpf/pkg/config"
)

// relayPort is the standard DHCP server/relay port.
const relayPort = 67

// clientPort is the standard DHCP client port.
const clientPort = 68

// startupRetryInterval is how long runRelay waits between attempts to resolve
// the interface and its IPv4 address (giaddr) at startup. Apply runs once at
// daemon boot, so an interface that is not yet ready (carrier wait, late link
// bring-up, DHCP-learned address not yet bound, or a not-yet-created dynamic
// VLAN/tunnel) must be retried rather than failing the relay permanently. The
// retry loop is ctx-cancelable so Stop() unwinds it promptly.
const startupRetryInterval = 5 * time.Second

// option82 is the DHCP Relay Agent Information option (RFC 3046).
const option82 = dhcpv4.OptionRelayAgentInformation

// suboption1CircuitID is the circuit-id sub-option within Option 82.
const suboption1CircuitID byte = 1

// RelayStats holds per-interface relay statistics.
type RelayStats struct {
	Interface        string
	RequestsRelayed  uint64
	RepliesForwarded uint64

	// Reply-delivery breakdown (#2076). These distinguish WHY a reply was
	// broadcast vs L2-unicast so an L2/CAP_NET_RAW/driver/MTU regression is
	// observable in operations. RepliesBroadcastL2Fallback is the one to
	// alert on: it means the raw-L2 path failed and the relay had to
	// degrade to broadcast.
	RepliesL2Unicast           uint64 // flag-clear reply delivered via raw L2
	RepliesUnicastCiaddr       uint64 // flag-clear reply UDP-unicast to ciaddr
	RepliesBroadcastFlag1      uint64 // client set the broadcast flag
	RepliesBroadcastForced     uint64 // overrides always-broadcast
	RepliesBroadcastNoTarget   uint64 // no routable target (yiaddr==0,ciaddr==0)
	RepliesBroadcastL2Fallback uint64 // raw-L2 path failed → degraded
}

// l2Replier is the raw-L2 unicast seam. *l2Sender implements it in production;
// tests inject a fake to exercise the dst-decision matrix and fallback without
// CAP_NET_RAW or real NICs.
type l2Replier interface {
	sendReply(dstMAC net.HardwareAddr, srcIP, dstIP net.IP, payload []byte) error
	Close() error
}

// interfaceRelay represents a relay goroutine bound to one interface.
type interfaceRelay struct {
	ifaceName        string
	cancel           context.CancelFunc
	done             chan struct{}
	requestsRelayed  atomic.Uint64
	repliesForwarded atomic.Uint64

	// alwaysBroadcast forces every reply to broadcast (overrides
	// always-broadcast). Set once at start; read-only thereafter.
	alwaysBroadcast bool

	// Reply-delivery counters (#2076).
	repliesL2Unicast           atomic.Uint64
	repliesUnicastCiaddr       atomic.Uint64
	repliesBroadcastFlag1      atomic.Uint64
	repliesBroadcastForced     atomic.Uint64
	repliesBroadcastNoTarget   atomic.Uint64
	repliesBroadcastL2Fallback atomic.Uint64
}

// packetConnFactory creates a UDP packet connection with the relay's required
// socket options applied before bind(2). It is a seam so lifecycle tests can
// inject fake connections (no root, no real NICs).
//
//   - ifaceName: when non-empty, SO_BINDTODEVICE binds the socket to that
//     interface (required on the client conn so REUSEPORT fanout is filtered
//     per-interface). Empty for the server conn (which binds a unique giaddr
//     ephemeral port and needs no device binding).
//   - reusePort: when true, SO_REUSEADDR+SO_REUSEPORT are set so multiple
//     client listeners coexist on 0.0.0.0:67.
//   - broadcast: when true, SO_BROADCAST is set so the socket can send to
//     255.255.255.255 (the client conn's broadcast reply path).
//   - bindAddr: the local address to bind.
type packetConnFactory func(ctx context.Context, ifaceName string,
	reusePort, broadcast bool, bindAddr *net.UDPAddr) (net.PacketConn, error)

// ifaceResolver resolves the giaddr for an interface by name. It wraps both
// the interface lookup and the IPv4-address selection so the startup-retry
// loop (Axis C1) can cover a not-yet-created dynamic interface as well as a
// not-yet-addressed one. It is a seam so the retry behavior is testable.
type ifaceResolver func(ifaceName string) (net.IP, error)

// Manager manages per-interface DHCP relay goroutines.
type Manager struct {
	mu     sync.Mutex
	relays map[string]*interfaceRelay // keyed by interface name

	// Injectable seams (defaulted in NewManager; overridden by tests).
	newConn       packetConnFactory
	resolveGIAddr ifaceResolver
	retryInterval time.Duration
	// newL2 opens the raw-L2 unicast sender for an interface (#2076). It is
	// a seam so tests can inject a fake or force open failure. The default
	// returns (nil, err) → fail-soft to the broadcast path; the production
	// implementation is defaultL2SenderFactory.
	newL2 l2SenderFactory
}

// l2SenderFactory opens a raw-L2 reply sender bound to ifaceName. On error the
// caller records a nil sender and every flag-clear reply takes the broadcast
// fallback — the relay stays up (fail-soft).
type l2SenderFactory func(ifaceName string) (l2Replier, error)

// NewManager creates a new DHCP relay Manager.
func NewManager() *Manager {
	return &Manager{
		relays:        make(map[string]*interfaceRelay),
		newConn:       defaultPacketConnFactory,
		resolveGIAddr: defaultIfaceResolver,
		retryInterval: startupRetryInterval,
		newL2:         defaultL2SenderFactory,
	}
}

// defaultL2SenderFactory opens a real AF_PACKET sender. Returning a typed-nil
// *l2Sender through the l2Replier interface would defeat the `== nil` guard, so
// on error it returns a nil interface value explicitly.
func defaultL2SenderFactory(ifaceName string) (l2Replier, error) {
	s, err := newL2Sender(ifaceName)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// defaultPacketConnFactory builds a real UDP packet connection, setting
// SO_REUSEADDR/SO_REUSEPORT, SO_BINDTODEVICE, and SO_BROADCAST inside the
// ListenConfig.Control hook (i.e. BEFORE bind(2)). This mirrors the in-repo
// vrfListenConfig precedent (pkg/cluster/heartbeat_manager.go). It returns the
// net.PacketConn as-is — no *net.UDPConn type assertion — so the runtime
// programs to the interface and stays mockable.
func defaultPacketConnFactory(ctx context.Context, ifaceName string,
	reusePort, broadcast bool, bindAddr *net.UDPAddr) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var ctrlErr error
			err := c.Control(func(fd uintptr) {
				if reusePort {
					if ctrlErr = setReusePort(fd); ctrlErr != nil {
						return
					}
				}
				if ifaceName != "" {
					if ctrlErr = setBindToDevice(fd, ifaceName); ctrlErr != nil {
						return
					}
				}
				if broadcast {
					if ctrlErr = setBroadcast(fd); ctrlErr != nil {
						return
					}
				}
			})
			if err != nil {
				return err
			}
			return ctrlErr
		},
	}
	return lc.ListenPacket(ctx, "udp4", bindAddr.String())
}

// defaultIfaceResolver looks up the interface and returns its first
// non-loopback IPv4 address (the giaddr).
func defaultIfaceResolver(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface lookup: %w", err)
	}
	return interfaceIPv4(iface)
}

// Apply starts relay goroutines according to the provided configuration.
// It stops any previously running relays before starting new ones.
func (m *Manager) Apply(ctx context.Context, cfg *config.DHCPRelayConfig) {
	m.Stop()

	if cfg == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, group := range cfg.Groups {
		sgName := group.ActiveServerGroup
		sg, ok := cfg.ServerGroups[sgName]
		if !ok {
			slog.Warn("dhcp-relay: server group not found",
				"group", group.Name, "server_group", sgName)
			continue
		}
		if len(sg.Servers) == 0 {
			slog.Warn("dhcp-relay: server group has no servers",
				"group", group.Name, "server_group", sgName)
			continue
		}

		// Resolve server addresses once at apply time.
		serverAddrs := make([]*net.UDPAddr, 0, len(sg.Servers))
		for _, s := range sg.Servers {
			ip := net.ParseIP(s)
			if ip == nil {
				slog.Warn("dhcp-relay: invalid server IP",
					"group", group.Name, "server", s)
				continue
			}
			serverAddrs = append(serverAddrs, &net.UDPAddr{IP: ip, Port: relayPort})
		}
		if len(serverAddrs) == 0 {
			continue
		}

		for _, ifaceName := range group.Interfaces {
			if _, exists := m.relays[ifaceName]; exists {
				slog.Warn("dhcp-relay: interface already has relay, skipping",
					"interface", ifaceName, "group", group.Name)
				continue
			}

			rctx, cancel := context.WithCancel(ctx)
			ir := &interfaceRelay{
				ifaceName:       ifaceName,
				cancel:          cancel,
				done:            make(chan struct{}),
				alwaysBroadcast: group.AlwaysBroadcast,
			}
			m.relays[ifaceName] = ir

			go func(relay *interfaceRelay, servers []*net.UDPAddr) {
				defer close(relay.done)
				m.runRelay(rctx, cancel, relay, servers)
			}(ir, serverAddrs)

			slog.Info("dhcp-relay: started",
				"interface", ifaceName,
				"group", group.Name,
				"servers", sg.Servers)
		}
	}
}

// Stats returns per-interface relay statistics.
func (m *Manager) Stats() []RelayStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	stats := make([]RelayStats, 0, len(m.relays))
	for _, ir := range m.relays {
		stats = append(stats, RelayStats{
			Interface:                  ir.ifaceName,
			RequestsRelayed:            ir.requestsRelayed.Load(),
			RepliesForwarded:           ir.repliesForwarded.Load(),
			RepliesL2Unicast:           ir.repliesL2Unicast.Load(),
			RepliesUnicastCiaddr:       ir.repliesUnicastCiaddr.Load(),
			RepliesBroadcastFlag1:      ir.repliesBroadcastFlag1.Load(),
			RepliesBroadcastForced:     ir.repliesBroadcastForced.Load(),
			RepliesBroadcastNoTarget:   ir.repliesBroadcastNoTarget.Load(),
			RepliesBroadcastL2Fallback: ir.repliesBroadcastL2Fallback.Load(),
		})
	}
	return stats
}

// Stop stops all running relay goroutines and waits for them to finish.
func (m *Manager) Stop() {
	m.mu.Lock()
	relays := make(map[string]*interfaceRelay, len(m.relays))
	for k, v := range m.relays {
		relays[k] = v
	}
	m.relays = make(map[string]*interfaceRelay)
	m.mu.Unlock()

	for _, ir := range relays {
		ir.cancel()
		<-ir.done
	}
}

// runRelay is the main loop for a single interface relay. It resolves the
// interface giaddr (with bounded ctx-cancelable retry for boot races), opens a
// client-facing listener on 0.0.0.0:67 bound to the interface and a server
// conn bound to giaddr, then relays client requests to the configured servers
// and forwards server responses back to clients.
//
// Lifecycle invariants (see docs/research/1915-relay-socket-lifecycle/plan.md):
//   - Both conns are net.PacketConn (ReadFrom/WriteTo) — no *net.UDPConn
//     assertion — which keeps the factory mockable.
//   - A close-on-cancel watcher is started LAST (after both conns exist) and
//     closes BOTH conns so a blocked ReadFrom returns net.ErrClosed.
//   - Both loops cancel the shared ctx on exit BEFORE the runner joins, so a
//     one-sided exit cannot hang wg.Wait(). The main loop runs in an inner
//     func whose `defer cancel()` fires before the outer wg.Wait().
func (m *Manager) runRelay(ctx context.Context, cancel context.CancelFunc,
	ir *interfaceRelay, servers []*net.UDPAddr) {
	ifaceName := ir.ifaceName

	// Axis C1: resolve giaddr with bounded, ctx-cancelable retry. Re-resolve
	// the interface every attempt so a dynamic interface recreated under the
	// same name (new Index) is picked up, and so a not-yet-created interface
	// does not permanently kill the relay.
	giaddr, ok := m.resolveGIAddrWithRetry(ctx, ifaceName)
	if !ok {
		return // ctx cancelled during retry; nothing created yet.
	}

	// Client-facing listener: 0.0.0.0:67, REUSEPORT (coexist with other
	// interfaces), SO_BINDTODEVICE (per-interface isolation under REUSEPORT),
	// SO_BROADCAST (deliver broadcast OFFER/ACK to 255.255.255.255:68).
	conn, err := m.newConn(ctx, ifaceName, true, true,
		&net.UDPAddr{IP: net.IPv4zero, Port: relayPort})
	if err != nil {
		slog.Error("dhcp-relay: listen failed",
			"interface", ifaceName, "err", err)
		return
	}
	defer conn.Close()

	// Server conn: bound to giaddr ephemeral port. No REUSEPORT, no
	// BINDTODEVICE (unique port), no broadcast.
	serverConn, err := m.newConn(ctx, "", false, false,
		&net.UDPAddr{IP: giaddr, Port: 0})
	if err != nil {
		slog.Error("dhcp-relay: server conn failed",
			"interface", ifaceName, "err", err)
		return
	}
	defer serverConn.Close()

	// Open the raw-L2 unicast sender (#2076), fail-soft: a nil sender means
	// every flag-clear reply takes the broadcast fallback and the relay stays
	// up (e.g. no CAP_NET_RAW). It is opened AFTER both UDP conns succeed and
	// BEFORE the cancel watcher. It is TX-only — it is deliberately NOT closed
	// by the watcher (it never blocks a read); it is closed by the idempotent
	// l2.Close() in a defer that runs only after wg.Wait() below, so every
	// sendReply caller has joined first (preserves the #1915 invariants).
	var l2 l2Replier
	if ir.alwaysBroadcast {
		slog.Info("dhcp-relay: overrides always-broadcast set, raw-L2 disabled",
			"interface", ifaceName)
	} else {
		l2, err = m.newL2(ifaceName)
		if err != nil {
			slog.Warn("dhcp-relay: raw-L2 sender unavailable, "+
				"flag-clear replies will broadcast",
				"interface", ifaceName, "err", err)
			l2 = nil
		}
	}
	defer func() {
		if l2 != nil {
			_ = l2.Close()
		}
	}()

	slog.Info("dhcp-relay: listening",
		"interface", ifaceName, "giaddr", giaddr,
		"always_broadcast", ir.alwaysBroadcast, "raw_l2", l2 != nil)

	// Both the cancel watcher and the server-response goroutine are tracked by
	// the WaitGroup so the runner's wg.Wait() is a true join of every spawned
	// goroutine — runRelay does not return (and ir.done does not close) until
	// the watcher's two Close() calls have completed.
	var wg sync.WaitGroup

	// Cancel watcher — started LAST, after BOTH conns exist. Closing both is
	// REQUIRED for the wg.Wait() liveness chain: it unblocks both ReadFrom
	// calls. Double-close (here + the defers) is an idempotent no-op.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = conn.Close()
		_ = serverConn.Close()
	}()

	// Track the server-response goroutine so the runner joins it. Its exit
	// cancels the shared ctx (cross-cancellation) so the watcher closes both
	// conns and the main loop unblocks too.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		handleServerResponses(ctx, serverConn, conn, ir, l2, giaddr)
	}()

	// Main read loop in its OWN func scope so its `defer cancel()` fires on
	// THIS func's return — BEFORE the outer wg.Wait() below. A function-scope
	// defer cancel() would run only after wg.Wait() and hang (Codex r3 BLOCKER).
	func() {
		defer cancel()
		buf := make([]byte, 1500)
		for {
			n, srcAddr, err := conn.ReadFrom(buf)
			if err != nil {
				// Exit ONLY on cancel or socket-close; a transient read error
				// is logged and the loop continues (a single bad datagram must
				// not kill the relay). Returning on ErrClosed too prevents a
				// hot-spin if the socket is closed while ctx.Err() is still nil.
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				slog.Warn("dhcp-relay: read error",
					"interface", ifaceName, "err", err)
				continue
			}

			pkt, err := dhcpv4.FromBytes(buf[:n])
			if err != nil {
				slog.Debug("dhcp-relay: invalid DHCP packet",
					"interface", ifaceName, "src", srcAddr, "err", err)
				continue
			}

			// Only relay client -> server messages (BOOTREQUEST).
			if pkt.OpCode != dhcpv4.OpcodeBootRequest {
				continue
			}

			msgType := pkt.MessageType()
			if !clientRequestRelayable(msgType) {
				continue
			}

			slog.Debug("dhcp-relay: received client request",
				"interface", ifaceName,
				"type", msgType,
				"client_mac", pkt.ClientHWAddr,
				"src", srcAddr)

			// Set giaddr to our interface IP so the server knows where to reply.
			pkt.GatewayIPAddr = giaddr

			// Increment hop count.
			pkt.HopCount++
			if pkt.HopCount > 16 {
				slog.Warn("dhcp-relay: hop count exceeded, dropping",
					"interface", ifaceName, "hops", pkt.HopCount)
				continue
			}

			// Add Option 82 (Relay Agent Information) with circuit-id sub-option.
			addOption82(pkt, ifaceName)

			// Unicast the modified packet to each server in the active group.
			relayData := pkt.ToBytes()
			for _, srv := range servers {
				if _, err := serverConn.WriteTo(relayData, srv); err != nil {
					slog.Warn("dhcp-relay: send to server failed",
						"interface", ifaceName,
						"server", srv, "err", err)
				}
			}
			ir.requestsRelayed.Add(1)
		}
	}()

	// Safe now: the inner func's defer cancel() has fired, so the watcher has
	// closed both conns and the response goroutine's ReadFrom is unblocked.
	wg.Wait()
}

// resolveGIAddrWithRetry resolves the interface giaddr, retrying on a bounded
// ctx-cancelable interval until it succeeds. Returns (giaddr, true) on success
// or (nil, false) if ctx was cancelled first. The resolver re-looks-up the
// interface every attempt (no stale cached Index).
func (m *Manager) resolveGIAddrWithRetry(ctx context.Context, ifaceName string) (net.IP, bool) {
	warned := false
	for {
		giaddr, err := m.resolveGIAddr(ifaceName)
		if err == nil {
			return giaddr, true
		}
		if !warned {
			slog.Warn("dhcp-relay: interface not ready, retrying",
				"interface", ifaceName, "err", err,
				"interval", m.retryInterval)
			warned = true
		} else {
			slog.Debug("dhcp-relay: interface still not ready",
				"interface", ifaceName, "err", err)
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(m.retryInterval):
		}
	}
}

// handleServerResponses reads DHCP replies from servers on the serverConn
// and forwards them back to clients on the client-facing conn.
//
// Reply delivery honors the RFC 2131 §4.1 broadcast flag (#2076):
//
//	overrides always-broadcast        -> broadcast (operator override wins)
//	broadcast flag set                -> broadcast (existing path)
//	flag clear, yiaddr real           -> raw-L2 unicast to chaddr+yiaddr
//	flag clear, yiaddr 0, ciaddr real -> UDP-unicast to ciaddr (client has IP)
//	flag clear, yiaddr 0, ciaddr 0    -> broadcast (nothing routable)
//	raw-L2 path fails                 -> broadcast fallback (+ counter)
//
// srcIP is the saved interface giaddr (the IPv4 source the server saw in the
// relayed request); it MUST come from the caller, not from pkt.GatewayIPAddr,
// which is zeroed below before sending.
func handleServerResponses(ctx context.Context, serverConn, clientConn net.PacketConn,
	ir *interfaceRelay, l2 l2Replier, srcIP net.IP) {
	ifaceName := ir.ifaceName
	buf := make([]byte, 1500)
	for {
		n, srcAddr, err := serverConn.ReadFrom(buf)
		if err != nil {
			// Exit ONLY on cancel or socket-close (see runRelay main loop).
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Warn("dhcp-relay: server read error",
				"interface", ifaceName, "err", err)
			continue
		}

		pkt, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			slog.Debug("dhcp-relay: invalid server DHCP packet",
				"interface", ifaceName, "src", srcAddr, "err", err)
			continue
		}

		// Only process server -> client messages (BOOTREPLY).
		if pkt.OpCode != dhcpv4.OpcodeBootReply {
			continue
		}

		msgType := pkt.MessageType()
		if msgType != dhcpv4.MessageTypeOffer && msgType != dhcpv4.MessageTypeAck {
			continue
		}

		slog.Debug("dhcp-relay: received server reply",
			"interface", ifaceName,
			"type", msgType,
			"server", srcAddr,
			"client_mac", pkt.ClientHWAddr,
			"yiaddr", pkt.YourIPAddr)

		// Strip Option 82 before forwarding to the client.
		stripOption82(pkt)

		// Clear giaddr since we are the last relay hop. The L2 source IP
		// comes from the saved giaddr (srcIP), NOT this field.
		pkt.GatewayIPAddr = net.IPv4zero

		replyData := pkt.ToBytes()
		if deliverReply(ir, clientConn, l2, srcIP, pkt, replyData) {
			ir.repliesForwarded.Add(1)
		}
	}
}

// deliverReply applies the #2076 reply-destination matrix and sends the reply.
// It returns true if the reply was delivered (any path that issued a successful
// send), false on a hard send failure. It increments the per-reason counters.
func deliverReply(ir *interfaceRelay, clientConn net.PacketConn, l2 l2Replier,
	srcIP net.IP, pkt *dhcpv4.DHCPv4, replyData []byte) bool {
	yiaddr := pkt.YourIPAddr.To4()
	yiaddrReal := yiaddr != nil && !yiaddr.Equal(net.IPv4zero)
	ciaddr := pkt.ClientIPAddr.To4()
	ciaddrReal := ciaddr != nil && !ciaddr.Equal(net.IPv4zero)

	switch {
	case ir.alwaysBroadcast:
		ir.repliesBroadcastForced.Add(1)
		return broadcastReply(ir, clientConn, replyData)

	case pkt.IsBroadcast():
		ir.repliesBroadcastFlag1.Add(1)
		return broadcastReply(ir, clientConn, replyData)

	case yiaddrReal:
		// Flag clear with a real offered address: RFC-correct raw-L2
		// unicast to chaddr+yiaddr. Fall back to broadcast on any L2
		// failure or when no raw-L2 sender is available.
		if l2 != nil && l2Eligible(pkt) {
			err := l2.sendReply(pkt.ClientHWAddr, srcIP, yiaddr, replyData)
			if err == nil {
				ir.repliesL2Unicast.Add(1)
				return true
			}
			slog.Warn("dhcp-relay: raw-L2 unicast failed, broadcasting",
				"interface", ir.ifaceName,
				"client_mac", pkt.ClientHWAddr,
				"yiaddr", yiaddr, "err", err)
		}
		ir.repliesBroadcastL2Fallback.Add(1)
		return broadcastReply(ir, clientConn, replyData)

	case ciaddrReal:
		// Flag clear, no yiaddr, but the client already owns ciaddr
		// (DHCPINFORM / REBINDING ACK) — it answers ARP, so a normal UDP
		// unicast is deliverable.
		dst := &net.UDPAddr{IP: ciaddr, Port: clientPort}
		if _, err := clientConn.WriteTo(replyData, dst); err != nil {
			slog.Warn("dhcp-relay: unicast to ciaddr failed",
				"interface", ir.ifaceName, "dst", dst, "err", err)
			return false
		}
		ir.repliesUnicastCiaddr.Add(1)
		return true

	default:
		// Flag clear, no yiaddr, no ciaddr: nothing routable. Broadcast.
		ir.repliesBroadcastNoTarget.Add(1)
		return broadcastReply(ir, clientConn, replyData)
	}
}

// broadcastReply sends the reply to 255.255.255.255:68 on the client conn.
func broadcastReply(ir *interfaceRelay, clientConn net.PacketConn, replyData []byte) bool {
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: clientPort}
	if _, err := clientConn.WriteTo(replyData, dst); err != nil {
		slog.Warn("dhcp-relay: broadcast to client failed",
			"interface", ir.ifaceName, "dst", dst, "err", err)
		return false
	}
	return true
}

// clientRequestRelayable reports whether a client-originated BOOTREQUEST of the
// given DHCP message type must be relayed to the configured servers.
//
// Per RFC 2131 §3.4 a relay agent forwards all client-originated requests that
// carry server-bound options, not just lease acquisition (DISCOVER) and
// lease (re)negotiation (REQUEST):
//
//   - DISCOVER / REQUEST — lease acquisition and renewal/rebinding.
//   - INFORM — a client that already holds an address (statically configured,
//     or post-lease) asking only for supplemental parameters (DNS servers,
//     domain search, NTP, etc.). Dropping it leaves such clients without
//     central configuration; the server answers an INFORM with an ACK, which
//     the reply path already forwards (see deliverReply: the flag-clear,
//     yiaddr==0, real-ciaddr case unicasts to the client's ciaddr).
//
// DECLINE and RELEASE are intentionally not relayed here: they are handled by
// the client directly to the server it is bound to and carry no relay-agent
// obligation in this agent's model (matching the pre-#2153 behavior, which
// only relayed DISCOVER/REQUEST).
func clientRequestRelayable(msgType dhcpv4.MessageType) bool {
	switch msgType {
	case dhcpv4.MessageTypeDiscover,
		dhcpv4.MessageTypeRequest,
		dhcpv4.MessageTypeInform:
		return true
	default:
		return false
	}
}

// l2Eligible reports whether a reply can be sent via the raw-L2 path: the
// client must use a 6-byte Ethernet hardware address. Non-Ethernet htype or a
// non-6-byte chaddr falls back to broadcast (the L2 frame would be malformed).
func l2Eligible(pkt *dhcpv4.DHCPv4) bool {
	return pkt.HWType == iana.HWTypeEthernet && len(pkt.ClientHWAddr) == 6
}

// addOption82 inserts or replaces the Relay Agent Information option (82)
// with sub-option 1 (circuit-id) set to the interface name.
func addOption82(pkt *dhcpv4.DHCPv4, ifaceName string) {
	// Build the sub-option TLV: type(1) + length + value.
	circuitID := []byte(ifaceName)
	subopt := make([]byte, 0, 2+len(circuitID))
	subopt = append(subopt, suboption1CircuitID)
	subopt = append(subopt, byte(len(circuitID)))
	subopt = append(subopt, circuitID...)

	// Remove any existing Option 82 first.
	pkt.Options.Del(option82)

	// Add the new Option 82.
	pkt.Options.Update(dhcpv4.OptGeneric(option82, subopt))
}

// stripOption82 removes the Relay Agent Information option (82) from the packet.
func stripOption82(pkt *dhcpv4.DHCPv4) {
	pkt.Options.Del(option82)
}

// interfaceIPv4 returns the first non-loopback IPv4 address on the interface.
func interfaceIPv4(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("list addresses: %w", err)
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 != nil && !ip4.IsLoopback() {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address on %s", iface.Name)
}
