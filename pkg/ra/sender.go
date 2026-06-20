package ra

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv6"
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
	defaultValidLifetime     = 2592000 // 30 days
	defaultPreferredLifetime = 604800  // 7 days

	// writeDeadline bounds every owner WriteTo so a stuck socket cannot wedge
	// withdrawal (#2033 I18 / Codex r3 MODERATE #4). Because the owner always
	// returns promptly, owner-performs-the-close (I17) is safe for both modes.
	writeDeadline = 1 * time.Second

	// rsReadDeadline bounds each rsReceiver ReadFrom so it can observe stopCh.
	rsReadDeadline = 1 * time.Second
	// rsErrBackoff is applied after a persistent (non-deadline) read error so
	// rsReceiver cannot hot-loop at 100% CPU if the interface dies while stopCh
	// is still open (#2033 I10 / AGY r4 MINOR #4).
	rsErrBackoff = 200 * time.Millisecond
)

// shutdownMode is the arbitrated teardown intent for a sender. It is set
// (atomically) BEFORE stopCh is closed, so any owner wakeup that observes the
// closed channel also observes the mode. graceful UPGRADES hard (never the
// reverse) — see signalStop (#2033 I13/I17).
type shutdownMode int32

const (
	modeNone     shutdownMode = iota // running
	modeHard                         // stop without a goodbye (Clear / Apply-remove)
	modeGraceful                     // emit the lifetime-0 goodbye as the final write
)

// ndpConn is the minimal subset of *ndp.Conn that sender uses. It exists as a
// compile-time seam so tests can substitute a recorder/injector (fakeConn)
// without a live NDP socket. The signatures MUST match mdlayher/ndp v1.1.0
// exactly: ndp.Message + *ipv6.ControlMessage + netip.Addr on WriteTo/ReadFrom,
// *ipv6.ICMPFilter on SetICMPFilter, netip.Addr group on JoinGroup. Do not
// widen this interface beyond what sender needs.
type ndpConn interface {
	WriteTo(m ndp.Message, cm *ipv6.ControlMessage, dst netip.Addr) error
	ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error)
	Close() error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	JoinGroup(group netip.Addr) error
	SetICMPFilter(f *ipv6.ICMPFilter) error
}

// listenFn opens an ndpConn for the interface. Overridable in tests; defaults
// to the real mdlayher/ndp Listen.
var listenFn = func(iface *net.Interface, addr ndp.Addr) (ndpConn, netip.Addr, error) {
	return ndp.Listen(iface, addr)
}

// ensureLinkLocalFn lets tests stub the link-local setup (a pure netlink
// AddrAdd after #2034) so the goodbye-only WithdrawOnce path can be asserted to
// SKIP it entirely (#2033 I12 — it must not even attempt to add a link-local on
// a demoting interface). Defaults to the real implementation.
var ensureLinkLocalFn = ensureLinkLocal

// sender is a per-interface RA sender goroutine.
//
// Single-owner contract (#2033, Path A): run() is the SOLE writer/closer of the
// NDP connection — startup burst, periodic RAs, RS-triggered RAs AND the
// goodbye all flow through it. No other goroutine calls conn.WriteTo or
// conn.Close. Shutdown is signalled via signalStop (sets mode, closes stopCh
// once); the owner reads mode after waking and, on modeGraceful, emits the
// lifetime-0 goodbye as its FINAL action in finishShutdown — guaranteeing no
// lifetime>0 RA follows the goodbye on the wire.
type sender struct {
	cfg     *config.RAInterfaceConfig
	iface   *net.Interface
	conn    ndpConn
	srcAddr netip.Addr

	mode     atomic.Int32 // shutdownMode; set BEFORE close(stopCh)
	stopOnce sync.Once    // guards close(stopCh)
	stopCh   chan struct{}
	stopped  chan struct{}
	burstCh  chan struct{} // buffered(1): request a re-burst (ResendBurst)

	// goodbyeEmitted records whether finishShutdown actually emitted the
	// lifetime-0 goodbye. The manager reads it AFTER the join (<-stopped) to
	// decide whether it still OWES a standalone goodbye for a graceful
	// withdrawal that lost the upgrade race (the owner already read modeHard
	// and exited before the graceful upgrade landed — a dead sender cannot be
	// resurrected). This makes "exactly one goodbye per withdrawn interface" a
	// post-mortem fact, not a timing gamble (#2033 MAJOR 2 / restart window).
	goodbyeEmitted atomic.Bool

	lastRAMu sync.Mutex
	lastRA   time.Time // rate-limit RS responses; owner writes, Status reads
}

func newSender(cfg *config.RAInterfaceConfig, iface *net.Interface) *sender {
	return &sender{
		cfg:     cfg,
		iface:   iface,
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
		burstCh: make(chan struct{}, 1),
	}
}

// start opens the NDP connection and launches the sender goroutine.
// Ensures a link-local address exists (RETH interfaces suppress auto
// link-local via addr_gen_mode=1, so we add one explicitly with NODAD).
func (s *sender) start() error {
	if err := ensureLinkLocalFn(s.iface); err != nil {
		slog.Warn("ra: failed to ensure link-local", "interface", s.iface.Name, "err", err)
	}

	conn, srcAddr, err := s.listen()
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

// sendGoodbyeStandalone is the WithdrawOnce goodbye-only entry point. It opens
// a connection, emits the lifetime-0 goodbye, and closes — WITHOUT launching
// run() and WITHOUT the startup burst (so it never re-advertises the router it
// is withdrawing — fixes S1). Per #2033 I12 it MUST NOT toggle the link: if no
// usable link-local exists, ndp.Listen fails and the goodbye is skipped
// best-effort rather than cycling a demoting interface (which may be mid-RETH-
// MAC-cycle). Returns an error only when the conn could not be opened so the
// caller can log; a goodbye is otherwise emitted and the conn closed here.
func (s *sender) sendGoodbyeStandalone() error {
	conn, srcAddr, err := s.listen()
	if err != nil {
		return err
	}
	s.conn = conn
	s.srcAddr = srcAddr
	defer s.conn.Close()
	s.sendGoodbyeRA()
	return nil
}

// listen opens the NDP connection with the configured bind address, retrying
// while the link-local address settles after ensureLinkLocal.
func (s *sender) listen() (ndpConn, netip.Addr, error) {
	var bindAddr ndp.Addr = ndp.LinkLocal
	if s.cfg.SourceLinkLocal != "" {
		bindAddr = ndp.Addr(s.cfg.SourceLinkLocal)
	}

	var conn ndpConn
	var srcAddr netip.Addr
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		conn, srcAddr, err = listenFn(s.iface, bindAddr)
		if err == nil {
			return conn, srcAddr, nil
		}
		// Re-read interface (link-local may appear after addr add).
		time.Sleep(200 * time.Millisecond)
		if iface, e := net.InterfaceByName(s.iface.Name); e == nil {
			s.iface = iface
		}
	}
	return nil, netip.Addr{}, err
}

// signalStop publishes the teardown intent then closes stopCh exactly once.
//
// The mode store happens-before the close (which in turn happens-before the
// owner's wakeup on the closed channel — Go memory model), so the owner that
// observes the closed stopCh also observes the mode.
//
// GRACEFUL UPGRADES HARD (#2033 I13/I17): in cluster mode a demotion Withdraw
// (VRRP-event goroutine, no applySem) can race a config-apply Clear for the
// same sender — pkg/ra's m.mu is the ONLY serialization. First-writer-wins
// would let a benign Clear drop the demotion goodbye (the exact bug). So a
// graceful request wins over a hard one: graceful is stored unconditionally,
// hard only if nothing was set yet. NEVER downgrade graceful->hard. Because
// the owner performs conn.Close AFTER emitting the goodbye (finishShutdown,
// I17), a racing hard close can never kill the upgraded goodbye. The only
// residual is the sub-microsecond window where the owner already read modeHard
// before the upgrade store — accepted as best-effort (the new primary's RA is
// the real recovery).
func (s *sender) signalStop(m shutdownMode) {
	if m == modeGraceful {
		s.mode.Store(int32(modeGraceful))
	} else {
		s.mode.CompareAndSwap(int32(modeNone), int32(modeHard))
	}
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// stop tears the sender down WITHOUT a goodbye (Clear / Apply-remove). The
// owner closes the conn in finishShutdown.
func (s *sender) stop() { s.signalStop(modeHard); <-s.stopped }

// withdrawAndStop tears the sender down emitting the lifetime-0 goodbye as the
// final write (graceful demotion).
func (s *sender) withdrawAndStop() { s.signalStop(modeGraceful); <-s.stopped }

// requestBurst asks the owner to re-emit the startup burst (after a RETH MAC
// link cycle killed the socket). Non-blocking: if a burst is already queued or
// the sender is draining, the request is dropped.
func (s *sender) requestBurst() {
	if s.draining() {
		return
	}
	select {
	case s.burstCh <- struct{}{}:
	default:
	}
}

// draining reports whether a shutdown has been signalled. It is a best-effort
// early-out for the burst/RS paths; the correctness mechanism is that the
// goodbye is owner-emitted on exit (so any in-flight normal RA necessarily
// PRECEDES it).
func (s *sender) draining() bool { return s.mode.Load() != int32(modeNone) }

// run is the single-owner sender loop. It is the ONLY goroutine that writes or
// closes the connection.
func (s *sender) run() {
	defer close(s.stopped)

	// Interruptible startup burst so a withdraw during startup cannot leave a
	// normal RA after the goodbye.
	s.burstInterruptible()
	if s.draining() {
		s.finishShutdown()
		return
	}

	advTimer := time.NewTimer(s.randomAdvInterval())
	defer advTimer.Stop()

	rsCh := make(chan netip.Addr, 8)
	go s.rsReceiver(rsCh)

	for {
		select {
		case <-s.stopCh:
			s.finishShutdown()
			return

		case <-s.burstCh:
			s.burstInterruptible()

		case <-advTimer.C:
			s.sendRA()
			advTimer.Reset(s.randomAdvInterval())

		case _, ok := <-rsCh:
			if !ok {
				// rsReceiver only closes rsCh after observing stopCh (I14),
				// so this implies shutdown is already in progress.
				s.finishShutdown()
				return
			}
			// Rate-limit multicast RA responses per RFC 4861 §6.2.6.
			if time.Since(s.getLastRA()) < minRAMulticastDelay {
				continue
			}
			// Random delay before responding, interruptible by shutdown.
			t := time.NewTimer(time.Duration(rand.IntN(int(maxRSDelay))))
			select {
			case <-s.stopCh:
				t.Stop()
				s.finishShutdown()
				return
			case <-t.C:
			}
			s.sendRA()
			advTimer.Reset(s.randomAdvInterval())
		}
	}
}

// finishShutdown is the ONLY place the goodbye is emitted AND the ONLY place
// the conn is closed (#2033 I17). It runs on the owner after the loop is gone,
// so no normal RA can follow the goodbye. The mode is re-read here, honoring a
// graceful upgrade that landed before the owner woke. The conn is closed AFTER
// the goodbye, which also unblocks the detached rsReceiver's ReadFrom (I10).
func (s *sender) finishShutdown() {
	if shutdownMode(s.mode.Load()) == modeGraceful {
		s.sendGoodbyeRA()
		// Record the fact for the manager's post-join owes-a-goodbye check.
		// Set AFTER the send and BEFORE close(s.stopped) (the caller's defer),
		// so a manager that observes <-stopped also observes this store.
		s.goodbyeEmitted.Store(true)
	}
	if s.conn != nil {
		s.conn.Close()
	}
}

// burstInterruptible emits the startup burst (startupBurstCount normal RAs),
// checking draining()/stopCh between sends so a concurrent withdraw stops the
// burst immediately. A legitimate start emits all RAs (I3); a draining sender
// short-circuits (I11/I15).
func (s *sender) burstInterruptible() {
	for i := 0; i < startupBurstCount; i++ {
		if s.draining() {
			return
		}
		s.sendRA()
		if i < startupBurstCount-1 {
			t := time.NewTimer(startupBurstDelay)
			select {
			case <-s.stopCh:
				t.Stop()
				return
			case <-t.C:
			}
		}
	}
}

// rsReceiver reads Router Solicitations and forwards them to the channel. It is
// a detached goroutine bounded by the owner's conn.Close (I10): the owner exits
// on stopCh regardless of rsCh state, then closes the conn, which unblocks this
// ReadFrom within one deadline at worst. It backs off on a persistent
// non-deadline read error so it cannot hot-loop if the interface dies while
// stopCh is still open (I10 / AGY r4 MINOR #4). It returns (closing rsCh) ONLY
// after observing stopCh (I14), so the owner's "rsCh closed" branch always
// implies shutdown is already in progress.
func (s *sender) rsReceiver(ch chan<- netip.Addr) {
	defer close(ch)
	for {
		s.conn.SetReadDeadline(time.Now().Add(rsReadDeadline))
		msg, _, src, err := s.conn.ReadFrom()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
			}
			// Not shutting down: a deadline timeout is the expected poll
			// signal; any other persistent error must not hot-loop.
			if !isTimeout(err) {
				t := time.NewTimer(rsErrBackoff)
				select {
				case <-s.stopCh:
					t.Stop()
					return
				case <-t.C:
				}
			}
			continue
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

// isTimeout reports whether err is an i/o deadline timeout (the expected
// rsReceiver poll signal) rather than a genuine socket error.
func isTimeout(err error) bool {
	type timeout interface{ Timeout() bool }
	te, ok := err.(timeout)
	return ok && te.Timeout()
}

// getLastRA returns the last-RA timestamp under lastRAMu.
func (s *sender) getLastRA() time.Time {
	s.lastRAMu.Lock()
	defer s.lastRAMu.Unlock()
	return s.lastRA
}

// setLastRA records the last-RA timestamp under lastRAMu.
func (s *sender) setLastRA(t time.Time) {
	s.lastRAMu.Lock()
	s.lastRA = t
	s.lastRAMu.Unlock()
}

// sendRA sends a normal Router Advertisement to all-nodes multicast (ff02::1).
// Owner-only.
func (s *sender) sendRA() {
	ra := s.buildRA()
	allNodes := netip.MustParseAddr("ff02::1")
	s.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
	if err := s.conn.WriteTo(ra, nil, allNodes); err != nil {
		slog.Warn("ra: failed to send RA",
			"interface", s.cfg.Interface, "err", err)
		return
	}
	s.setLastRA(time.Now())
	slog.Debug("ra: sent RA", "interface", s.cfg.Interface)
}

// sendGoodbyeRA sends goodbye RAs (lifetime=0) multiple times for reliability.
// Owner-only — emitted as the final write in finishShutdown.
func (s *sender) sendGoodbyeRA() {
	ra := s.buildRA()
	ra.RouterLifetime = 0
	allNodes := netip.MustParseAddr("ff02::1")

	for i := 0; i < goodbyeCount; i++ {
		s.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
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

// eui64LinkLocal derives the EUI-64 IPv6 link-local address (fe80::/64) from a
// 6-byte MAC. It returns nil if the MAC is not exactly 6 bytes. This mirrors
// the daemon's ensureRethLinkLocal (pkg/daemon/daemon_reth.go) so the RA sender
// and the apply path converge on one well-reviewed derivation. Kept as a pure
// function so the byte math is unit-testable without a netlink socket.
func eui64LinkLocal(mac net.HardwareAddr) net.IP {
	if len(mac) != 6 {
		return nil
	}
	return net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]}
}

// ensureLinkLocal makes sure the interface has an IPv6 link-local address for
// the RA sender's NDP socket. RETH members run with addr_gen_mode=1
// (stable-privacy) to suppress kernel EUI-64 auto-generation and the MLDv2
// noise it creates (pkg/daemon setRethIPv6Knobs), so on those interfaces no
// link-local may exist yet when the sender starts.
//
// If a link-local is already present (a daemon-managed stable or EUI-64 LLA, or
// a kernel-generated one on a non-suppressed interface), this returns early. If
// none exists, it adds the EUI-64 link-local directly via netlink with
// IFA_F_NODAD — the same primitive the daemon uses in ensureRethLinkLocal /
// addStableLLToInterface. It never mutates addr_gen_mode and never cycles the
// link: addr_gen_mode=1 is a contract the apply path sets deliberately, and an
// out-of-band link DOWN/UP from inside the RA manager would un-reconcile VIPs /
// stable LLAs and race the AF_XDP dataplane rebind.
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

	// No link-local. Synthesize the EUI-64 fe80::/64 from the MAC and add it
	// with NODAD — the same primitive the daemon uses for RETH link-locals
	// (ensureRethLinkLocal / addStableLLToInterface). NODAD is set for
	// consistency with that apply path and to suppress the DAD / MLDv2 solicit
	// noise on addr_gen_mode=1 interfaces; it is not required to avoid a
	// peer collision here, because the EUI-64 derivation folds in the RETH
	// virtual MAC's node_id byte (RethMAC -> 02:bf:72:CC:RR:NN), so each node
	// derives a distinct LLA. (The address that *is* shared across nodes is
	// the daemon's stable fe80::bf:72:CC:RR LLA, which carries no node_id and
	// is added NODAD for exactly that reason — a different address than this
	// fallback.)
	ll := eui64LinkLocal(iface.HardwareAddr)
	if ll == nil {
		return fmt.Errorf("ensure link-local: interface %s has no usable MAC", iface.Name)
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{IP: ll, Mask: net.CIDRMask(64, 128)},
		Flags: unix.IFA_F_NODAD,
	}
	logAdded, err := classifyAddrAddResult(netlink.AddrAdd(link, addr))
	if err != nil {
		return fmt.Errorf("add link-local %s on %s: %w", ll, iface.Name, err)
	}
	if logAdded {
		slog.Info("ra: added link-local for RA sender",
			"interface", iface.Name, "addr", ll)
	}
	return nil
}

// classifyAddrAddResult interprets the result of netlink.AddrAdd for the RA
// link-local fallback. ensureLinkLocal already lists existing IPv6 link-locals
// before attempting the add, but another goroutine or process can still win the
// race between the list and the add. A nil error is a genuine add (log it). An
// EEXIST means the address is already present — a silent success: do NOT log
// "added", since claiming a new address was created makes the RA startup trace
// inaccurate during debugging. Any other error is a real failure.
func classifyAddrAddResult(addErr error) (logAdded bool, err error) {
	switch {
	case addErr == nil:
		return true, nil
	case errors.Is(addErr, syscall.EEXIST):
		return false, nil
	default:
		return false, addErr
	}
}
