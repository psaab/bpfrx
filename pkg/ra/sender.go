package ra

import (
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
)

const (
	// Default RA timing per RFC 4861.
	defaultMaxAdvInterval = 600  // seconds
	defaultRouterLifetime = 1800 // seconds

	// RFC 4861 §6.2.6: minimum delay between multicast RAs triggered by RS.
	minRAMulticastDelay = 3 * time.Second

	// Maximum random delay before responding to an RS.
	maxRSDelay = 500 * time.Millisecond

	// Number of goodbye RAs to send (for reliability).
	goodbyeCount = 3
	// Delay between goodbye RAs.
	goodbyeDelay = 50 * time.Millisecond
	// Number of startup RAs to send so hosts quickly relearn a default router
	// after daemon restart, failover, or link flap.
	startupBurstCount = 3
	// Delay between startup RAs.
	startupBurstDelay = 100 * time.Millisecond

	// Default prefix lifetimes per RFC 4861.
	defaultValidLifetime    = 2592000 // 30 days
	defaultPreferredLifetime = 604800  // 7 days
)

// sender is a per-interface RA sender goroutine.
type sender struct {
	cfg     *config.RAInterfaceConfig
	iface   *net.Interface
	conn    *ndp.Conn
	srcAddr netip.Addr
	stopCh  chan struct{}
	stopped chan struct{}
	lastRA  time.Time // rate-limit RS responses
}

func newSender(cfg *config.RAInterfaceConfig, iface *net.Interface) *sender {
	return &sender{
		cfg:    cfg,
		iface:  iface,
		stopCh: make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

// start opens the NDP connection and launches the sender goroutine.
// Ensures a link-local address exists (RETH interfaces suppress auto
// link-local via addr_gen_mode=1, so we add one explicitly with NODAD).
func (s *sender) start() error {
	if err := ensureLinkLocal(s.iface); err != nil {
		slog.Warn("ra: failed to ensure link-local", "interface", s.iface.Name, "err", err)
	}

	// Determine NDP bind address: use explicitly configured link-local if set,
	// otherwise default to any link-local on the interface.
	var bindAddr ndp.Addr = ndp.LinkLocal
	if s.cfg.SourceLinkLocal != "" {
		bindAddr = ndp.Addr(s.cfg.SourceLinkLocal)
	}

	var conn *ndp.Conn
	var srcAddr netip.Addr
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		conn, srcAddr, err = ndp.Listen(s.iface, bindAddr)
		if err == nil {
			break
		}
		// Re-read interface (link-local may appear after addr add).
		time.Sleep(200 * time.Millisecond)
		if iface, e := net.InterfaceByName(s.iface.Name); e == nil {
			s.iface = iface
		}
	}
	if err != nil {
		return err
	}
	s.conn = conn
	s.srcAddr = srcAddr

	// Join all-routers multicast to receive Router Solicitations.
	allRouters := netip.MustParseAddr("ff02::2")
	if err := s.conn.JoinGroup(allRouters); err != nil {
		slog.Warn("ra: failed to join all-routers group",
			"interface", s.cfg.Interface, "err", err)
	}

	// Set ICMPv6 filter to accept only Router Solicitations (type 133).
	var f ipv6Filter
	f.setAllowRS()
	if err := s.conn.SetICMPFilter(f.filter()); err != nil {
		slog.Warn("ra: failed to set ICMPv6 filter",
			"interface", s.cfg.Interface, "err", err)
	}

	go s.run()
	return nil
}

// stop signals the sender goroutine to exit and waits.
func (s *sender) stop() {
	close(s.stopCh)
	if s.conn != nil {
		s.conn.Close()
	}
	<-s.stopped
}

// run is the main sender loop.
func (s *sender) run() {
	defer close(s.stopped)

	// Send an initial burst so hosts do not wait for the periodic timer to
	// relearn a default router after xpfd restarts or HA role changes.
	s.sendStartupBurst()

	advTimer := time.NewTimer(s.randomAdvInterval())
	defer advTimer.Stop()

	// Receiver goroutine forwards RS events.
	rsCh := make(chan netip.Addr, 8)
	go s.rsReceiver(rsCh)

	for {
		select {
		case <-s.stopCh:
			return

		case <-advTimer.C:
			s.sendRA()
			advTimer.Reset(s.randomAdvInterval())

		case _, ok := <-rsCh:
			if !ok {
				return
			}
			// Rate-limit multicast RA responses per RFC 4861 §6.2.6.
			if time.Since(s.lastRA) < minRAMulticastDelay {
				continue
			}
			// Random delay before responding.
			delay := time.Duration(rand.IntN(int(maxRSDelay)))
			time.Sleep(delay)
			// Re-check after delay.
			select {
			case <-s.stopCh:
				return
			default:
			}
			s.sendRA()
			// Reset periodic timer after RS-triggered RA.
			advTimer.Reset(s.randomAdvInterval())
		}
	}
}

func (s *sender) sendStartupBurst() {
	for i := 0; i < startupBurstCount; i++ {
		s.sendRA()
		if i < startupBurstCount-1 {
			time.Sleep(startupBurstDelay)
		}
	}
}

// rsReceiver reads Router Solicitations and forwards them to the channel.
func (s *sender) rsReceiver(ch chan<- netip.Addr) {
	defer close(ch)
	for {
		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		msg, _, src, err := s.conn.ReadFrom()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				continue
			}
		}

		if _, ok := msg.(*ndp.RouterSolicitation); !ok {
			continue
		}

		select {
		case ch <- src:
		default:
		}
	}
}

// sendRA sends a Router Advertisement to all-nodes multicast (ff02::1).
func (s *sender) sendRA() {
	ra := s.buildRA()
	allNodes := netip.MustParseAddr("ff02::1")
	if err := s.conn.WriteTo(ra, nil, allNodes); err != nil {
		slog.Warn("ra: failed to send RA",
			"interface", s.cfg.Interface, "err", err)
		return
	}
	s.lastRA = time.Now()
	slog.Debug("ra: sent RA", "interface", s.cfg.Interface)
}

// sendGoodbyeRA sends goodbye RAs (lifetime=0) multiple times for reliability.
func (s *sender) sendGoodbyeRA() {
	ra := s.buildRA()
	ra.RouterLifetime = 0
	allNodes := netip.MustParseAddr("ff02::1")

	for i := 0; i < goodbyeCount; i++ {
		if err := s.conn.WriteTo(ra, nil, allNodes); err != nil {
			slog.Warn("ra: failed to send goodbye RA",
				"interface", s.cfg.Interface, "err", err)
			return
		}
		if i < goodbyeCount-1 {
			time.Sleep(goodbyeDelay)
		}
	}
	slog.Info("ra: goodbye RA sent (lifetime=0)", "interface", s.cfg.Interface)
}

// buildRA constructs a Router Advertisement from the config.
func (s *sender) buildRA() *ndp.RouterAdvertisement {
	lifetime := s.cfg.DefaultLifetime
	if lifetime <= 0 {
		lifetime = defaultRouterLifetime
	}

	ra := &ndp.RouterAdvertisement{
		CurrentHopLimit:      64,
		ManagedConfiguration: s.cfg.ManagedConfig,
		OtherConfiguration:   s.cfg.OtherStateful,
		RouterLifetime:       time.Duration(lifetime) * time.Second,
	}

	// Router selection preference.
	switch s.cfg.Preference {
	case "high":
		ra.RouterSelectionPreference = ndp.High
	case "low":
		ra.RouterSelectionPreference = ndp.Low
	default:
		ra.RouterSelectionPreference = ndp.Medium
	}

	// Source link-layer address (includes RETH virtual MAC).
	ra.Options = append(ra.Options, &ndp.LinkLayerAddress{
		Direction: ndp.Source,
		Addr:      s.iface.HardwareAddr,
	})

	// Prefix Information options.
	for _, pfx := range s.cfg.Prefixes {
		prefix, err := netip.ParsePrefix(pfx.Prefix)
		if err != nil {
			slog.Warn("ra: invalid prefix, skipping",
				"prefix", pfx.Prefix, "err", err)
			continue
		}

		validLife := pfx.ValidLifetime
		if validLife <= 0 {
			validLife = defaultValidLifetime
		}
		prefLife := pfx.PreferredLife
		if prefLife <= 0 {
			prefLife = defaultPreferredLifetime
		}

		ra.Options = append(ra.Options, &ndp.PrefixInformation{
			PrefixLength:                   uint8(prefix.Bits()),
			OnLink:                         pfx.OnLink,
			AutonomousAddressConfiguration: pfx.Autonomous,
			ValidLifetime:                  time.Duration(validLife) * time.Second,
			PreferredLifetime:              time.Duration(prefLife) * time.Second,
			Prefix:                         prefix.Masked().Addr(),
		})
	}

	// Recursive DNS Servers.
	if len(s.cfg.DNSServers) > 0 {
		var servers []netip.Addr
		for _, dns := range s.cfg.DNSServers {
			addr, err := netip.ParseAddr(dns)
			if err != nil {
				slog.Warn("ra: invalid DNS server address",
					"addr", dns, "err", err)
				continue
			}
			servers = append(servers, addr)
		}
		if len(servers) > 0 {
			ra.Options = append(ra.Options, &ndp.RecursiveDNSServer{
				Lifetime: time.Duration(lifetime) * time.Second,
				Servers:  servers,
			})
		}
	}

	// PREF64 (NAT64 prefix).
	if s.cfg.NAT64Prefix != "" {
		prefix, err := netip.ParsePrefix(s.cfg.NAT64Prefix)
		if err == nil {
			pref64Life := s.cfg.NAT64PrefixLife
			if pref64Life <= 0 {
				pref64Life = lifetime
			}
			ra.Options = append(ra.Options, &ndp.PREF64{
				Lifetime: time.Duration(pref64Life) * time.Second,
				Prefix:   prefix,
			})
		} else {
			slog.Warn("ra: invalid NAT64 prefix",
				"prefix", s.cfg.NAT64Prefix, "err", err)
		}
	}

	// Link MTU.
	if s.cfg.LinkMTU > 0 {
		ra.Options = append(ra.Options, ndp.NewMTU(uint32(s.cfg.LinkMTU)))
	}

	return ra
}

// randomAdvInterval returns a random duration between MinRtrAdvInterval and
// MaxRtrAdvInterval per RFC 4861.
func (s *sender) randomAdvInterval() time.Duration {
	maxI := s.cfg.MaxAdvInterval
	if maxI <= 0 {
		maxI = defaultMaxAdvInterval
	}
	minI := s.cfg.MinAdvInterval
	if minI <= 0 {
		minI = maxI / 3
	}
	if minI >= maxI {
		minI = maxI / 3
	}

	interval := minI + rand.IntN(maxI-minI+1)
	return time.Duration(interval) * time.Second
}

// ensureLinkLocal checks whether the interface has a link-local IPv6 address.
// RETH interfaces have addr_gen_mode=1 (stable-privacy) set to suppress
// automatic link-local generation, but the RA sender needs one for its NDP
// socket. If no link-local exists, this computes one via EUI-64 from the
// interface MAC and adds it with IFA_F_NODAD.
func ensureLinkLocal(iface *net.Interface) error {
	link, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return err
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if a.IP.IsLinkLocalUnicast() {
			return nil // already have one
		}
	}

	// No link-local. Set addr_gen_mode=0 (EUI-64) so kernel generates one
	// on next link toggle, then toggle the link.
	addrGenPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/addr_gen_mode", iface.Name)
	if err := os.WriteFile(addrGenPath, []byte("0"), 0644); err != nil {
		return fmt.Errorf("set addr_gen_mode=0: %w", err)
	}

	// Disable DAD for the link-local — virtual MAC may conflict with peer.
	dadPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", iface.Name)
	os.WriteFile(dadPath, []byte("0"), 0644)

	// Toggle link to trigger link-local generation.
	netlink.LinkSetDown(link)
	time.Sleep(50 * time.Millisecond)
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}

	// Wait for kernel to assign the address (may take >500ms on some systems).
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		addrs, _ = netlink.AddrList(link, netlink.FAMILY_V6)
		for _, a := range addrs {
			if a.IP.IsLinkLocalUnicast() {
				// Mark it NODAD to avoid MLDv2 DAD probes.
				if a.Flags&unix.IFA_F_NODAD == 0 {
					netlink.AddrDel(link, &a)
					a.Flags = unix.IFA_F_NODAD
					netlink.AddrAdd(link, &a)
				}
				slog.Info("ra: added link-local for RA sender",
					"interface", iface.Name, "addr", a.IP)
				return nil
			}
		}
	}

	return fmt.Errorf("link-local did not appear after addr_gen_mode=0 + link toggle")
}
