// Package dhcprelay implements a DHCP relay agent (RFC 3046) that forwards
// DHCPv4 packets between clients on local interfaces and remote DHCP servers.
// It inserts Option 82 (Relay Agent Information) with the circuit-id sub-option
// set to the receiving interface name, allowing servers to identify the origin.
package dhcprelay

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/psaab/xpf/pkg/config"
)

// relayPort is the standard DHCP server/relay port.
const relayPort = 67

// clientPort is the standard DHCP client port.
const clientPort = 68

// option82 is the DHCP Relay Agent Information option (RFC 3046).
const option82 = dhcpv4.OptionRelayAgentInformation

// suboption1CircuitID is the circuit-id sub-option within Option 82.
const suboption1CircuitID byte = 1

// RelayStats holds per-interface relay statistics.
type RelayStats struct {
	Interface        string
	RequestsRelayed  uint64
	RepliesForwarded uint64
}

// interfaceRelay represents a relay goroutine bound to one interface.
type interfaceRelay struct {
	ifaceName        string
	cancel           context.CancelFunc
	done             chan struct{}
	requestsRelayed  atomic.Uint64
	repliesForwarded atomic.Uint64
}

// Manager manages per-interface DHCP relay goroutines.
type Manager struct {
	mu     sync.Mutex
	relays map[string]*interfaceRelay // keyed by interface name
}

// NewManager creates a new DHCP relay Manager.
func NewManager() *Manager {
	return &Manager{
		relays: make(map[string]*interfaceRelay),
	}
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
				ifaceName: ifaceName,
				cancel:    cancel,
				done:      make(chan struct{}),
			}
			m.relays[ifaceName] = ir

			go func(relay *interfaceRelay, servers []*net.UDPAddr) {
				defer close(relay.done)
				runRelay(rctx, relay, servers)
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
			Interface:        ir.ifaceName,
			RequestsRelayed:  ir.requestsRelayed.Load(),
			RepliesForwarded: ir.repliesForwarded.Load(),
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

// runRelay is the main loop for a single interface relay. It listens on
// UDP port 67 bound to the interface for client broadcasts, relays them to
// the configured servers, and forwards server responses back to clients.
func runRelay(ctx context.Context, ir *interfaceRelay, servers []*net.UDPAddr) {
	ifaceName := ir.ifaceName
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		slog.Error("dhcp-relay: interface lookup failed",
			"interface", ifaceName, "err", err)
		return
	}

	// Determine the relay's IPv4 address on this interface for giaddr.
	giaddr, err := interfaceIPv4(iface)
	if err != nil {
		slog.Error("dhcp-relay: no IPv4 address on interface",
			"interface", ifaceName, "err", err)
		return
	}

	// Listen on UDP port 67 bound to this interface for broadcast DHCP requests.
	listenAddr := &net.UDPAddr{IP: net.IPv4zero, Port: relayPort}
	conn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		slog.Error("dhcp-relay: listen failed",
			"interface", ifaceName, "addr", listenAddr, "err", err)
		return
	}
	defer conn.Close()

	// Bind to interface so we only receive packets from this specific interface.
	rawConn, err := conn.SyscallConn()
	if err != nil {
		slog.Error("dhcp-relay: syscall conn failed",
			"interface", ifaceName, "err", err)
		return
	}
	if err := bindToDevice(rawConn, ifaceName); err != nil {
		slog.Error("dhcp-relay: SO_BINDTODEVICE failed",
			"interface", ifaceName, "err", err)
		return
	}

	// Create a separate connection for sending unicast replies to servers
	// and receiving server responses.
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: giaddr, Port: 0})
	if err != nil {
		slog.Error("dhcp-relay: server conn failed",
			"interface", ifaceName, "err", err)
		return
	}
	defer serverConn.Close()

	slog.Info("dhcp-relay: listening",
		"interface", ifaceName, "giaddr", giaddr)

	// Start server response listener in a separate goroutine.
	go func() {
		handleServerResponses(ctx, serverConn, conn, ir)
	}()

	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, srcAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
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
		if msgType != dhcpv4.MessageTypeDiscover && msgType != dhcpv4.MessageTypeRequest {
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
			if _, err := serverConn.WriteToUDP(relayData, srv); err != nil {
				slog.Warn("dhcp-relay: send to server failed",
					"interface", ifaceName,
					"server", srv, "err", err)
			}
		}
		ir.requestsRelayed.Add(1)
	}
}

// handleServerResponses reads DHCP replies from servers on the serverConn
// and forwards them back to clients on the client-facing conn.
func handleServerResponses(ctx context.Context, serverConn, clientConn *net.UDPConn, ir *interfaceRelay) {
	ifaceName := ir.ifaceName
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, srcAddr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
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

		// Clear giaddr since we are the last relay hop.
		pkt.GatewayIPAddr = net.IPv4zero

		// Determine destination: if the broadcast flag is set, broadcast;
		// otherwise unicast to the assigned address.
		var dst *net.UDPAddr
		if pkt.IsBroadcast() || pkt.YourIPAddr == nil || pkt.YourIPAddr.Equal(net.IPv4zero) {
			dst = &net.UDPAddr{IP: net.IPv4bcast, Port: clientPort}
		} else {
			dst = &net.UDPAddr{IP: pkt.YourIPAddr, Port: clientPort}
		}

		replyData := pkt.ToBytes()
		if _, err := clientConn.WriteToUDP(replyData, dst); err != nil {
			slog.Warn("dhcp-relay: send to client failed",
				"interface", ifaceName,
				"dst", dst, "err", err)
		} else {
			ir.repliesForwarded.Add(1)
		}
	}
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

// bindToDevice sets SO_BINDTODEVICE on the socket so it only receives
// packets from the specified interface.
func bindToDevice(rawConn interface{ Control(func(fd uintptr)) error }, ifaceName string) error {
	var seterr error
	err := rawConn.Control(func(fd uintptr) {
		seterr = setBindToDevice(fd, ifaceName)
	})
	if err != nil {
		return err
	}
	return seterr
}
