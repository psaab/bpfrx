package ra

import (
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/psaab/bpfrx/pkg/config"
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
func (s *sender) start() error {
	conn, srcAddr, err := ndp.Listen(s.iface, ndp.LinkLocal)
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

	// Send initial RA immediately.
	s.sendRA()

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
