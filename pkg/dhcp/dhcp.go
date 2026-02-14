// Package dhcp implements DHCPv4 and DHCPv6 clients for obtaining
// addresses on firewall interfaces configured with "family inet { dhcp; }"
// or "family inet6 { dhcpv6; }".
package dhcp

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/nclient6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/vishvananda/netlink"
)

// AddressFamily selects DHCPv4 or DHCPv6.
type AddressFamily int

const (
	AFInet  AddressFamily = 4
	AFInet6 AddressFamily = 6
)

// Lease holds the result of a DHCP negotiation.
type Lease struct {
	Interface string
	Family    AddressFamily
	Address   netip.Prefix
	Gateway   netip.Addr
	DNS       []netip.Addr
	LeaseTime time.Duration
	Obtained  time.Time
}

type clientKey struct {
	iface  string
	family AddressFamily
}

type dhcpClient struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// DHCPv4Options holds client behavior options for DHCPv4.
type DHCPv4Options struct {
	LeaseTime              int  // requested lease time in seconds (0 = server default)
	RetransmissionAttempt  int  // max retransmission attempts (0 = unlimited)
	RetransmissionInterval int  // base interval in seconds between retransmissions (0 = 1s default)
	ForceDiscover          bool // always start with DISCOVER (skip REQUEST for renewal)
}

// DHCPv6Options holds client behavior options for DHCPv6.
type DHCPv6Options struct {
	IATypes    []string // "ia-na", "ia-pd" — which IA types to request
	PDPrefLen  int      // preferred prefix length hint for IA_PD (0 = no hint)
	PDSubLen   int      // sub-prefix length for deriving /64s (0 = not set)
	ReqOptions []string // additional options to request: "dns-server", "domain-name"
	RAIface    string   // interface to update with RA prefix from delegated prefix
}

// DelegatedPrefix holds a prefix received via DHCPv6 Prefix Delegation.
type DelegatedPrefix struct {
	Interface         string
	Prefix            netip.Prefix
	PreferredLifetime time.Duration
	ValidLifetime     time.Duration
	Obtained          time.Time
}

// Manager manages DHCP clients for multiple interfaces.
type Manager struct {
	mu              sync.Mutex
	clients         map[clientKey]*dhcpClient
	leases          map[clientKey]*Lease
	delegatedPDs    map[string][]DelegatedPrefix // interface name -> delegated prefixes
	duids           map[string]dhcpv6.DUID       // interface name -> cached DUID
	duidTypes       map[string]string            // interface name -> "duid-ll" or "duid-llt"
	v4opts          map[string]*DHCPv4Options    // interface name -> DHCPv4 options
	v6opts          map[string]*DHCPv6Options    // interface name -> DHCPv6 options
	onAddressChange func()
	nlHandle        *netlink.Handle
	recompileTimer  *time.Timer
	stateDir        string
}

// New creates a DHCP manager. stateDir is where DUID files are persisted.
// The onAddressChange callback is called (debounced by 2 seconds) when a
// lease changes an interface address.
func New(stateDir string, onAddressChange func()) (*Manager, error) {
	nlh, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("netlink handle: %w", err)
	}
	return &Manager{
		clients:         make(map[clientKey]*dhcpClient),
		leases:          make(map[clientKey]*Lease),
		delegatedPDs:    make(map[string][]DelegatedPrefix),
		duids:           make(map[string]dhcpv6.DUID),
		duidTypes:       make(map[string]string),
		v4opts:          make(map[string]*DHCPv4Options),
		v6opts:          make(map[string]*DHCPv6Options),
		onAddressChange: onAddressChange,
		nlHandle:        nlh,
		stateDir:        stateDir,
	}, nil
}

// SetDUIDType configures the DUID type for an interface's DHCPv6 client.
// Must be called before Start(). Valid types: "duid-ll", "duid-llt".
func (m *Manager) SetDUIDType(ifaceName, duidType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.duidTypes[ifaceName] = duidType
}

// SetDHCPv4Options configures DHCPv4 client behavior for an interface.
// Must be called before Start().
func (m *Manager) SetDHCPv4Options(ifaceName string, opts *DHCPv4Options) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.v4opts[ifaceName] = opts
}

// SetDHCPv6Options configures DHCPv6 client behavior for an interface.
// Must be called before Start().
func (m *Manager) SetDHCPv6Options(ifaceName string, opts *DHCPv6Options) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.v6opts[ifaceName] = opts
}

// DelegatedPrefixes returns a snapshot of all delegated prefixes from DHCPv6 PD.
func (m *Manager) DelegatedPrefixes() []DelegatedPrefix {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []DelegatedPrefix
	for _, pds := range m.delegatedPDs {
		result = append(result, pds...)
	}
	return result
}

// PDRAMapping holds a delegated prefix and the downstream interface
// where it should be advertised via Router Advertisement.
type PDRAMapping struct {
	DelegatedPrefix
	RAIface    string // downstream interface for RA
	SubPrefLen int    // sub-prefix length (0 = use delegated prefix as-is)
}

// DelegatedPrefixesForRA returns delegated prefixes that have an RA target
// interface configured, along with the target interface and sub-prefix length.
func (m *Manager) DelegatedPrefixesForRA() []PDRAMapping {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []PDRAMapping
	for ifName, pds := range m.delegatedPDs {
		opts := m.v6opts[ifName]
		if opts == nil || opts.RAIface == "" {
			continue
		}
		for _, dp := range pds {
			result = append(result, PDRAMapping{
				DelegatedPrefix: dp,
				RAIface:         opts.RAIface,
				SubPrefLen:      opts.PDSubLen,
			})
		}
	}
	return result
}

// Start begins a DHCP client for the given interface and address family.
func (m *Manager) Start(ctx context.Context, ifaceName string, af AddressFamily) {
	key := clientKey{iface: ifaceName, family: af}

	m.mu.Lock()
	if _, exists := m.clients[key]; exists {
		m.mu.Unlock()
		return
	}

	// Use an independent context so DHCP clients are decoupled from the
	// daemon lifecycle. Only explicit StopAll() triggers lease release and
	// address removal. During graceful restart (SIGTERM), the process exits
	// without calling StopAll(), so addresses stay on interfaces for the
	// next daemon to reuse.
	cctx, cancel := context.WithCancel(context.Background())
	dc := &dhcpClient{
		cancel: cancel,
		done:   make(chan struct{}),
	}
	m.clients[key] = dc
	m.mu.Unlock()

	go func() {
		defer close(dc.done)
		switch af {
		case AFInet:
			m.runDHCPv4(cctx, ifaceName)
		case AFInet6:
			m.runDHCPv6(cctx, ifaceName)
		}
	}()
}

// Renew restarts the DHCP client for the specified interface and address
// family, causing it to go through a fresh DISCOVER/REQUEST cycle.
// Returns an error if no DHCP client is running for the interface.
func (m *Manager) Renew(ifaceName string) error {
	// Try both v4 and v6
	renewed := false
	for _, af := range []AddressFamily{AFInet, AFInet6} {
		key := clientKey{iface: ifaceName, family: af}
		m.mu.Lock()
		dc, exists := m.clients[key]
		if exists {
			delete(m.clients, key)
		}
		m.mu.Unlock()

		if !exists {
			continue
		}

		// Stop existing client
		dc.cancel()
		<-dc.done
		renewed = true

		// Restart
		m.Start(context.Background(), ifaceName, af)
		slog.Info("DHCP client renewed", "interface", ifaceName, "family", af)
	}
	if !renewed {
		return fmt.Errorf("no DHCP client running on interface %s", ifaceName)
	}
	return nil
}

// StopAll stops all running DHCP clients and releases leases.
func (m *Manager) StopAll() {
	m.mu.Lock()
	clients := make(map[clientKey]*dhcpClient, len(m.clients))
	for k, v := range m.clients {
		clients[k] = v
	}
	m.mu.Unlock()

	for _, dc := range clients {
		dc.cancel()
		<-dc.done
	}

	m.mu.Lock()
	if m.recompileTimer != nil {
		m.recompileTimer.Stop()
		m.recompileTimer = nil
	}
	m.mu.Unlock()
}

// Close releases the netlink handle.
func (m *Manager) Close() {
	if m.nlHandle != nil {
		m.nlHandle.Close()
	}
}

// DUIDInfo holds information about a DHCPv6 DUID for display.
type DUIDInfo struct {
	Interface string
	Type      string // "DUID-LL" or "DUID-LLT"
	HexBytes  string
	Display   string
}

// DUIDs returns information about all configured/persisted DHCPv6 DUIDs.
func (m *Manager) DUIDs() []DUIDInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []DUIDInfo
	for ifName := range m.duidTypes {
		duid := m.duids[ifName]
		if duid == nil {
			// Try loading from disk
			if d, err := m.loadDUID(ifName); err == nil {
				duid = d
			}
		}
		if duid != nil {
			result = append(result, DUIDInfo{
				Interface: ifName,
				Type:      duid.DUIDType().String(),
				HexBytes:  hex.EncodeToString(duid.ToBytes()),
				Display:   duid.String(),
			})
		}
	}
	return result
}

// ClearDUID removes the persisted DUID for an interface. The next DHCPv6
// request will generate a fresh DUID.
func (m *Manager) ClearDUID(ifaceName string) error {
	m.mu.Lock()
	delete(m.duids, ifaceName)
	m.mu.Unlock()

	path := m.duidPath(ifaceName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	slog.Info("DHCPv6: DUID cleared", "interface", ifaceName)
	return nil
}

// ClearAllDUIDs removes all persisted DUIDs.
func (m *Manager) ClearAllDUIDs() {
	m.mu.Lock()
	ifaces := make([]string, 0, len(m.duids))
	for k := range m.duids {
		ifaces = append(ifaces, k)
	}
	m.mu.Unlock()

	for _, ifName := range ifaces {
		m.ClearDUID(ifName)
	}
}

// getDUID returns the DUID for an interface, loading from disk or generating
// a new one as needed. The result is cached in memory and persisted.
func (m *Manager) getDUID(ifaceName string) (dhcpv6.DUID, error) {
	m.mu.Lock()
	if d, ok := m.duids[ifaceName]; ok {
		m.mu.Unlock()
		return d, nil
	}
	duidType := m.duidTypes[ifaceName]
	m.mu.Unlock()

	// Try loading persisted DUID
	if d, err := m.loadDUID(ifaceName); err == nil {
		m.mu.Lock()
		m.duids[ifaceName] = d
		m.mu.Unlock()
		slog.Info("DHCPv6: loaded persisted DUID",
			"interface", ifaceName, "duid", d)
		return d, nil
	}

	// Generate new DUID
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface lookup for DUID: %w", err)
	}

	var duid dhcpv6.DUID
	switch duidType {
	case "duid-llt":
		// Time-based — stable only via persistence
		epoch := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
		duid = &dhcpv6.DUIDLLT{
			HWType:        iana.HWTypeEthernet,
			Time:          uint32(time.Since(epoch).Seconds()),
			LinkLayerAddr: iface.HardwareAddr,
		}
	default: // "duid-ll" or empty (default to LL)
		duid = &dhcpv6.DUIDLL{
			HWType:        iana.HWTypeEthernet,
			LinkLayerAddr: iface.HardwareAddr,
		}
	}

	// Persist
	if err := m.saveDUID(ifaceName, duid); err != nil {
		slog.Warn("DHCPv6: failed to persist DUID",
			"interface", ifaceName, "err", err)
	}

	m.mu.Lock()
	m.duids[ifaceName] = duid
	m.mu.Unlock()

	slog.Info("DHCPv6: generated DUID",
		"interface", ifaceName, "duid", duid)
	return duid, nil
}

func (m *Manager) duidPath(ifaceName string) string {
	return filepath.Join(m.stateDir, "dhcpv6-duid-"+ifaceName)
}

func (m *Manager) loadDUID(ifaceName string) (dhcpv6.DUID, error) {
	data, err := os.ReadFile(m.duidPath(ifaceName))
	if err != nil {
		return nil, err
	}
	return dhcpv6.DUIDFromBytes(data)
}

func (m *Manager) saveDUID(ifaceName string, duid dhcpv6.DUID) error {
	if err := os.MkdirAll(m.stateDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(m.duidPath(ifaceName), duid.ToBytes(), 0644)
}

// Leases returns a snapshot of all current DHCP leases.
func (m *Manager) Leases() []*Lease {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]*Lease, 0, len(m.leases))
	for _, l := range m.leases {
		lc := *l
		result = append(result, &lc)
	}
	return result
}

// LeaseFor returns the current lease for a specific interface/family, or nil.
func (m *Manager) LeaseFor(ifaceName string, af AddressFamily) *Lease {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, ok := m.leases[clientKey{iface: ifaceName, family: af}]
	if !ok {
		return nil
	}
	lc := *l
	return &lc
}

// runDHCPv4 runs the DHCPv4 DORA cycle with retries and renewal.
func (m *Manager) runDHCPv4(ctx context.Context, ifaceName string) {
	key := clientKey{iface: ifaceName, family: AFInet}

	m.mu.Lock()
	opts := m.v4opts[ifaceName]
	m.mu.Unlock()

	baseBackoff := time.Second
	if opts != nil && opts.RetransmissionInterval > 0 {
		baseBackoff = time.Duration(opts.RetransmissionInterval) * time.Second
	}
	maxAttempts := 0 // unlimited
	if opts != nil && opts.RetransmissionAttempt > 0 {
		maxAttempts = opts.RetransmissionAttempt
	}

	backoff := baseBackoff
	attempt := 0

	for {
		if ctx.Err() != nil {
			return
		}

		slog.Info("DHCPv4: starting discovery", "interface", ifaceName)

		lease, err := m.doDHCPv4(ctx, ifaceName)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			attempt++
			if maxAttempts > 0 && attempt >= maxAttempts {
				slog.Warn("DHCPv4: max retransmission attempts reached",
					"interface", ifaceName, "attempts", attempt)
				return
			}
			slog.Warn("DHCPv4: discovery failed, retrying",
				"interface", ifaceName, "err", err, "backoff", backoff,
				"attempt", attempt)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = min(backoff*2, 60*time.Second)
			continue
		}

		backoff = baseBackoff // reset on success
		attempt = 0

		// Apply address
		if err := m.applyAddress(ifaceName, lease); err != nil {
			slog.Warn("DHCPv4: failed to apply address",
				"interface", ifaceName, "err", err)
			continue
		}

		m.mu.Lock()
		m.leases[key] = lease
		m.mu.Unlock()

		m.scheduleRecompile()

		slog.Info("DHCPv4: lease obtained",
			"interface", ifaceName,
			"address", lease.Address,
			"gateway", lease.Gateway,
			"lease_time", lease.LeaseTime)

		// Wait for T1 (50% of lease time) for renewal
		t1 := lease.LeaseTime / 2
		if t1 < 30*time.Second {
			t1 = 30 * time.Second
		}

		select {
		case <-time.After(t1):
			slog.Info("DHCPv4: T1 expired, renewing", "interface", ifaceName)
		case <-ctx.Done():
			// Release lease
			m.removeAddress(ifaceName, lease)
			m.mu.Lock()
			delete(m.leases, key)
			m.mu.Unlock()
			return
		}
	}
}

// doDHCPv4 performs a single DORA exchange.
func (m *Manager) doDHCPv4(ctx context.Context, ifaceName string) (*Lease, error) {
	client, err := nclient4.New(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("create DHCPv4 client: %w", err)
	}
	defer client.Close()

	// Use a timeout context for the exchange
	exCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Build modifiers from per-interface DHCPv4 options
	var mods []dhcpv4.Modifier
	m.mu.Lock()
	opts := m.v4opts[ifaceName]
	m.mu.Unlock()
	if opts != nil && opts.LeaseTime > 0 {
		mods = append(mods, dhcpv4.WithLeaseTime(uint32(opts.LeaseTime)))
	}

	dhcpLease, err := client.Request(exCtx, mods...)
	if err != nil {
		return nil, fmt.Errorf("DHCPv4 request: %w", err)
	}

	ack := dhcpLease.ACK

	// Extract lease info
	yourIP := ack.YourIPAddr
	if yourIP == nil || yourIP.IsUnspecified() {
		return nil, fmt.Errorf("no IP in DHCP ACK")
	}

	// Subnet mask
	mask := ack.SubnetMask()
	if mask == nil {
		mask = net.CIDRMask(24, 32) // fallback
	}
	ones, _ := net.IPMask(mask).Size()

	addr, ok := netip.AddrFromSlice(yourIP.To4())
	if !ok {
		return nil, fmt.Errorf("invalid IP in DHCP ACK: %v", yourIP)
	}

	lease := &Lease{
		Interface: ifaceName,
		Family:    AFInet,
		Address:   netip.PrefixFrom(addr, ones),
		Obtained:  time.Now(),
	}

	// Gateway
	routers := ack.Router()
	if len(routers) > 0 {
		if gw, ok := netip.AddrFromSlice(routers[0].To4()); ok {
			lease.Gateway = gw
		}
	}

	// DNS
	dnsServers := ack.DNS()
	for _, dns := range dnsServers {
		if a, ok := netip.AddrFromSlice(dns.To4()); ok {
			lease.DNS = append(lease.DNS, a)
		}
	}

	// Lease time
	lt := ack.IPAddressLeaseTime(3600 * time.Second) // default 1 hour
	lease.LeaseTime = lt

	return lease, nil
}

// runDHCPv6 runs the DHCPv6 solicit/request cycle with retries and renewal.
func (m *Manager) runDHCPv6(ctx context.Context, ifaceName string) {
	key := clientKey{iface: ifaceName, family: AFInet6}
	backoff := time.Second

	// Wait for link-local address
	if err := m.waitForLinkLocal(ctx, ifaceName, 30*time.Second); err != nil {
		slog.Warn("DHCPv6: no link-local address, aborting",
			"interface", ifaceName, "err", err)
		return
	}

	for {
		if ctx.Err() != nil {
			return
		}

		slog.Info("DHCPv6: starting solicit", "interface", ifaceName)

		result, err := m.doDHCPv6(ctx, ifaceName)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("DHCPv6: solicit failed, retrying",
				"interface", ifaceName, "err", err, "backoff", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = min(backoff*2, 60*time.Second)
			continue
		}

		backoff = time.Second
		lease := result.lease

		if lease.Address.IsValid() {
			if err := m.applyAddress(ifaceName, lease); err != nil {
				slog.Warn("DHCPv6: failed to apply address",
					"interface", ifaceName, "err", err)
				continue
			}
		}

		m.mu.Lock()
		m.leases[key] = lease
		if len(result.prefixes) > 0 {
			m.delegatedPDs[ifaceName] = result.prefixes
		}
		m.mu.Unlock()

		m.scheduleRecompile()

		slog.Info("DHCPv6: lease obtained",
			"interface", ifaceName,
			"address", lease.Address,
			"delegated_prefixes", len(result.prefixes),
			"lease_time", lease.LeaseTime)

		// Wait for T1
		t1 := lease.LeaseTime / 2
		if t1 < 30*time.Second {
			t1 = 30 * time.Second
		}

		select {
		case <-time.After(t1):
			slog.Info("DHCPv6: T1 expired, renewing", "interface", ifaceName)
		case <-ctx.Done():
			if lease.Address.IsValid() {
				m.removeAddress(ifaceName, lease)
			}
			m.mu.Lock()
			delete(m.leases, key)
			delete(m.delegatedPDs, ifaceName)
			m.mu.Unlock()
			return
		}
	}
}

// dhcpv6Result holds results from a DHCPv6 exchange including both IA_NA and IA_PD.
type dhcpv6Result struct {
	lease      *Lease
	prefixes   []DelegatedPrefix
}

// doDHCPv6 performs a single DHCPv6 solicit/request exchange.
func (m *Manager) doDHCPv6(ctx context.Context, ifaceName string) (*dhcpv6Result, error) {
	client, err := nclient6.New(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("create DHCPv6 client: %w", err)
	}
	defer client.Close()

	exCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	m.mu.Lock()
	v6opts := m.v6opts[ifaceName]
	m.mu.Unlock()

	// Build modifiers — use persistent DUID if configured
	mods := m.buildDHCPv6Modifiers(ifaceName, v6opts)

	adv, err := client.RapidSolicit(exCtx, mods...)
	if err != nil {
		return nil, fmt.Errorf("DHCPv6 solicit: %w", err)
	}

	result := &dhcpv6Result{}
	now := time.Now()

	// Determine which IA types to look for
	wantNA := true
	wantPD := false
	if v6opts != nil && len(v6opts.IATypes) > 0 {
		wantNA = false
		for _, t := range v6opts.IATypes {
			switch t {
			case "ia-na":
				wantNA = true
			case "ia-pd":
				wantPD = true
			}
		}
	}

	// Extract IA_NA addresses
	var addr netip.Addr
	var validLT time.Duration

	if wantNA {
		for _, opt := range adv.Options.Options {
			if ianaOpt, ok := opt.(*dhcpv6.OptIANA); ok {
				for _, subOpt := range ianaOpt.Options.Options {
					if iaaddr, ok := subOpt.(*dhcpv6.OptIAAddress); ok {
						if a, ok2 := netip.AddrFromSlice(iaaddr.IPv6Addr); ok2 {
							addr = a
							validLT = iaaddr.ValidLifetime
						}
					}
				}
			}
		}
	}

	// Extract IA_PD delegated prefixes
	if wantPD {
		result.prefixes = extractDelegatedPrefixes(adv, ifaceName, now)
		for _, dp := range result.prefixes {
			slog.Info("DHCPv6: received delegated prefix",
				"interface", ifaceName,
				"prefix", dp.Prefix,
				"preferred", dp.PreferredLifetime,
				"valid", dp.ValidLifetime)
		}
	}

	// If we wanted IA_NA but didn't get an address, check if PD-only is OK
	if wantNA && !addr.IsValid() && !wantPD {
		return nil, fmt.Errorf("no IA_NA address in DHCPv6 reply")
	}
	if wantNA && !addr.IsValid() && wantPD && len(result.prefixes) == 0 {
		return nil, fmt.Errorf("no IA_NA address or IA_PD prefix in DHCPv6 reply")
	}

	lease := &Lease{
		Interface: ifaceName,
		Family:    AFInet6,
		Obtained:  now,
	}

	if addr.IsValid() {
		lease.Address = netip.PrefixFrom(addr, 128)
		lease.LeaseTime = validLT
	} else if len(result.prefixes) > 0 {
		// PD-only mode: use the first prefix's lifetime for renewal
		lease.LeaseTime = result.prefixes[0].ValidLifetime
	}

	if lease.LeaseTime == 0 {
		lease.LeaseTime = 3600 * time.Second
	}

	// Extract DNS
	if dnsOpt := adv.Options.DNS(); len(dnsOpt) > 0 {
		for _, dns := range dnsOpt {
			if a, ok := netip.AddrFromSlice(dns); ok {
				lease.DNS = append(lease.DNS, a)
			}
		}
	}

	// DHCPv6 doesn't provide a default router — discover it from the
	// kernel's IPv6 neighbor table (entries learned via Router Advertisements).
	if gw := m.discoverIPv6Router(ifaceName); gw.IsValid() {
		lease.Gateway = gw
	}

	result.lease = lease
	return result, nil
}

// buildDHCPv6Modifiers constructs DHCPv6 message modifiers from interface options.
func (m *Manager) buildDHCPv6Modifiers(ifaceName string, opts *DHCPv6Options) []dhcpv6.Modifier {
	var mods []dhcpv6.Modifier

	// Use persistent DUID if configured
	if duid, err := m.getDUID(ifaceName); err == nil {
		mods = append(mods, dhcpv6.WithClientID(duid))
	}

	if opts == nil {
		return mods
	}

	// Add IA_PD if requested
	for _, iaType := range opts.IATypes {
		if iaType == "ia-pd" {
			var hintPrefix *dhcpv6.OptIAPrefix
			if opts.PDPrefLen > 0 {
				hintPrefix = &dhcpv6.OptIAPrefix{
					Prefix: &net.IPNet{
						IP:   net.IPv6zero,
						Mask: net.CIDRMask(opts.PDPrefLen, 128),
					},
				}
			}
			iaid := [4]byte{0, 0, 0, 1} // default IAID for PD
			if hintPrefix != nil {
				mods = append(mods, dhcpv6.WithIAPD(iaid, hintPrefix))
			} else {
				mods = append(mods, dhcpv6.WithIAPD(iaid))
			}
		}
	}

	// Add requested options (ORO)
	var oroCodes []dhcpv6.OptionCode
	for _, opt := range opts.ReqOptions {
		switch opt {
		case "dns-server":
			oroCodes = append(oroCodes, dhcpv6.OptionDNSRecursiveNameServer)
		case "domain-name":
			oroCodes = append(oroCodes, dhcpv6.OptionDomainSearchList)
		}
	}
	if len(oroCodes) > 0 {
		mods = append(mods, dhcpv6.WithRequestedOptions(oroCodes...))
	}

	return mods
}

// extractDelegatedPrefixes parses IA_PD options from a DHCPv6 reply.
func extractDelegatedPrefixes(msg *dhcpv6.Message, ifaceName string, now time.Time) []DelegatedPrefix {
	var result []DelegatedPrefix
	for _, opt := range msg.Options.Options {
		iapdOpt, ok := opt.(*dhcpv6.OptIAPD)
		if !ok {
			continue
		}
		for _, prefix := range iapdOpt.Options.Prefixes() {
			if prefix.Prefix == nil {
				continue
			}
			ones, _ := prefix.Prefix.Mask.Size()
			ip, ok := netip.AddrFromSlice(prefix.Prefix.IP)
			if !ok {
				continue
			}
			result = append(result, DelegatedPrefix{
				Interface:         ifaceName,
				Prefix:            netip.PrefixFrom(ip, ones),
				PreferredLifetime: prefix.PreferredLifetime,
				ValidLifetime:     prefix.ValidLifetime,
				Obtained:          now,
			})
		}
	}
	return result
}

// discoverIPv6Router finds the link-local address of an IPv6 router on the
// given interface by inspecting the kernel neighbor table for entries with
// the NTF_ROUTER flag (learned from Router Advertisements).
// Retries a few times since RAs may not have been processed yet.
func (m *Manager) discoverIPv6Router(ifaceName string) netip.Addr {
	link, err := m.nlHandle.LinkByName(ifaceName)
	if err != nil {
		return netip.Addr{}
	}

	for attempt := 0; attempt < 10; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Second)
		}

		neighbors, err := m.nlHandle.NeighList(link.Attrs().Index, netlink.FAMILY_V6)
		if err != nil {
			continue
		}

		for _, n := range neighbors {
			// NTF_ROUTER = 0x80 (linux/neighbour.h)
			if n.Flags&0x80 != 0 && n.IP.IsLinkLocalUnicast() {
				if a, ok := netip.AddrFromSlice(n.IP); ok {
					return a
				}
			}
		}
	}

	slog.Warn("DHCPv6: no IPv6 router found in neighbor table",
		"interface", ifaceName)
	return netip.Addr{}
}

// waitForLinkLocal waits until the interface has a link-local IPv6 address.
func (m *Manager) waitForLinkLocal(ctx context.Context, ifaceName string, timeout time.Duration) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timeout waiting for link-local on %s", ifaceName)
		case <-ticker.C:
			iface, err := net.InterfaceByName(ifaceName)
			if err != nil {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipNet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				if ipNet.IP.To4() == nil && ipNet.IP.IsLinkLocalUnicast() {
					return nil
				}
			}
		}
	}
}

// applyAddress sets the DHCP-obtained address on the interface via netlink,
// and installs a default route via the gateway if provided.
func (m *Manager) applyAddress(ifaceName string, lease *Lease) error {
	link, err := m.nlHandle.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("link lookup %s: %w", ifaceName, err)
	}

	addr := &netlink.Addr{
		IPNet: prefixToIPNet(lease.Address),
	}

	if err := m.nlHandle.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("addr replace: %w", err)
	}

	// Routes are programmed via FRR by the daemon's recompile callback.

	return nil
}

// removeAddress removes the DHCP address and default route from the interface.
func (m *Manager) removeAddress(ifaceName string, lease *Lease) {
	link, err := m.nlHandle.LinkByName(ifaceName)
	if err != nil {
		return
	}

	addr := &netlink.Addr{
		IPNet: prefixToIPNet(lease.Address),
	}
	if err := m.nlHandle.AddrDel(link, addr); err != nil {
		slog.Warn("DHCP: failed to remove address",
			"interface", ifaceName, "address", lease.Address, "err", err)
	}

	// Routes are cleaned up via FRR config removal.
}

// scheduleRecompile debounces address change notifications.
func (m *Manager) scheduleRecompile() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.recompileTimer != nil {
		m.recompileTimer.Stop()
	}
	m.recompileTimer = time.AfterFunc(2*time.Second, func() {
		if m.onAddressChange != nil {
			m.onAddressChange()
		}
	})
}

// DeriveSubPrefix derives a sub-prefix from a delegated prefix for RA advertisement.
// If subPrefLen is 0 or equal to the delegated prefix length, the prefix is returned as-is.
// Otherwise, the first sub-prefix of the requested length is derived (e.g., /48 → first /64).
// Returns an invalid prefix if the sub-prefix length is shorter than the delegated prefix.
func DeriveSubPrefix(delegated netip.Prefix, subPrefLen int) netip.Prefix {
	bits := delegated.Bits()
	if subPrefLen == 0 || subPrefLen == bits {
		return delegated
	}
	if subPrefLen < bits {
		// Can't derive a shorter prefix from a longer one
		return netip.Prefix{}
	}
	// Mask the address to the delegated prefix boundary, then re-prefix at subPrefLen.
	// This gives us the first sub-prefix (e.g., 2001:db8:1000::/48 → 2001:db8:1000::/64).
	masked := delegated.Masked()
	return netip.PrefixFrom(masked.Addr(), subPrefLen)
}

// prefixToIPNet converts netip.Prefix to *net.IPNet.
func prefixToIPNet(p netip.Prefix) *net.IPNet {
	addr := p.Addr()
	bits := p.Bits()
	if addr.Is4() {
		return &net.IPNet{
			IP:   addr.AsSlice(),
			Mask: net.CIDRMask(bits, 32),
		}
	}
	return &net.IPNet{
		IP:   addr.AsSlice(),
		Mask: net.CIDRMask(bits, 128),
	}
}
