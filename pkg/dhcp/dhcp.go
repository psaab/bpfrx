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
	"github.com/psaab/xpf/pkg/fsatomic"
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

	// serverID is the DHCPv4 server-identifier (option 54) from the ACK
	// that granted this lease. It is the unicast destination for the
	// RFC 2131 §4.3.6 RENEWING DHCPREQUEST at T1. Unexported: internal
	// renewal state, not part of the public lease surface and never
	// compared by leaseContentChanged (#2994).
	serverID netip.Addr

	// v6ServerDUID is the DHCPv6 Server-Identifier (DUID) from the Reply
	// that granted this lease, echoed in the RFC 8415 §18.2.4 RENEW so
	// the original server matches the binding. Unexported (#2994).
	v6ServerDUID dhcpv6.DUID
}

// dhcpExchangeMode selects which RFC exchange a renewal cycle step runs.
// The pre-#2994 client ran a full DISCOVER/Rapid-Solicit (exchangeAcquire)
// at every T1/T2; the fix sends a true unicast RENEW at T1 and a broadcast
// REBIND at T2, falling back to a full acquisition only on lease expiry.
type dhcpExchangeMode int

const (
	exchangeAcquire dhcpExchangeMode = iota // DHCPv4 DISCOVER / DHCPv6 SOLICIT
	exchangeRenew                           // T1: unicast REQUEST(RENEW) / RENEW
	exchangeRebind                          // T2: broadcast REQUEST(REBIND) / REBIND
)

func (mode dhcpExchangeMode) String() string {
	switch mode {
	case exchangeRenew:
		return "renew"
	case exchangeRebind:
		return "rebind"
	default:
		return "acquire"
	}
}

type clientKey struct {
	iface  string
	family AddressFamily
}

type dhcpClient struct {
	cancel context.CancelFunc
	done   chan struct{}
	// fingerprint is the client's config identity (options/DUID type)
	// captured at Start time. Reconcile compares it against the
	// fingerprint of the newly committed config to decide whether the
	// client must be restarted. It NEVER includes lease or address
	// state — see Reconcile.
	fingerprint string
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
	Stateless bool // true = send Information-Request only (no IA_NA/IA_PD)
	// UpdateDNS retired (#1715): the DHCP client no longer writes
	// /etc/resolv.conf. The daemon's reconcileDNS always merges
	// DHCP-learned servers (from Leases()) with static config regardless
	// of any per-client flag, so the box is never resolver-less.
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
	// onGatewayChange fires whenever the gateway-relevant lease state
	// of any interface changes (#1844): a lease committed with a
	// new/changed gateway, a first lease acquired, or a lease record
	// removed on client termination. Immutable after New (a setter on
	// a live manager would be a data race — client goroutines read
	// this outside m.mu) and ALWAYS fired outside m.mu, so the
	// consumer (the ipmon engine's NotifyNextHopChange, whose resolver
	// calls back into LeaseFor under Engine.mu → dhcp.mu) can never
	// deadlock against us. Bounded-blocking: the hook may wait on
	// Engine.mu held across an overlay build.
	onGatewayChange func()
	nlHandle        *netlink.Handle
	recompileTimer  *time.Timer
	stateDir        string

	// runClientForTest replaces the per-family run goroutine body in
	// tests so reconcile/registry behavior can be exercised without
	// real DHCP traffic. nil in production.
	runClientForTest func(ctx context.Context, ifaceName string, af AddressFamily)

	// Renewal seams (#2994). When non-nil they replace the real wire
	// exchange / the renewal wait so the run-loop state machine (the
	// DISCOVER→RENEW→REBIND→re-acquire transitions) is unit-testable
	// without sockets or the 30 s T1 clamp. nil in production.
	doV4ExchangeForTest func(ctx context.Context, ifaceName string, mode dhcpExchangeMode, prev *Lease) (*Lease, error)
	doV6ExchangeForTest func(ctx context.Context, ifaceName string, mode dhcpExchangeMode, prev *Lease, prevPDs []DelegatedPrefix) (*dhcpv6Result, error)
	afterForTest        func(d time.Duration) <-chan time.Time
	// waitLinkLocalForTest replaces the DHCPv6 link-local wait so the v6
	// run loop is drivable without a real interface. nil in production.
	waitLinkLocalForTest func(ctx context.Context, ifaceName string, timeout time.Duration) error
}

// New creates a DHCP manager. stateDir is where DUID files are persisted.
// The onAddressChange callback is called (debounced by 2 seconds) when a
// lease changes an interface address. The onGatewayChange callback (#1844,
// may be nil) fires — undebounced, outside m.mu — whenever gateway-relevant
// lease state changes: first lease, gateway delta on commit, or lease
// record removal on client termination; see the Manager field doc.
func New(stateDir string, onAddressChange, onGatewayChange func()) (*Manager, error) {
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
		onGatewayChange: onGatewayChange,
		nlHandle:        nlh,
		stateDir:        stateDir,
	}, nil
}

// fireGatewayChange invokes the optional gateway-change hook. Callers
// must NOT hold m.mu (the hook's consumer takes Engine.mu and its
// resolver re-enters LeaseFor — firing under m.mu would invert the
// one-way Engine.mu → dhcp.mu lock order).
func (m *Manager) fireGatewayChange() {
	if m.onGatewayChange != nil {
		m.onGatewayChange()
	}
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
// Start reports whether a client for the key is registered when it
// returns: true if this call started one or one was already running,
// false if the key has no option state (the desired-config signal —
// SetDHCPv*Options/Reconcile install it, Reconcile prunes it for
// removed clients). The membership check lives INSIDE the registration
// lock so check-and-register is atomic: a Renew racing a removal
// Reconcile cannot observe membership, lose the lock, and register a
// client for a key the Reconcile just deconfigured (Codex review on
// PR #1815, round 5).
func (m *Manager) Start(ctx context.Context, ifaceName string, af AddressFamily) bool {
	key := clientKey{iface: ifaceName, family: af}

	m.mu.Lock()
	if _, exists := m.clients[key]; exists {
		m.mu.Unlock()
		return true
	}
	desired := false
	switch af {
	case AFInet:
		_, desired = m.v4opts[ifaceName]
	case AFInet6:
		_, desired = m.v6opts[ifaceName]
	}
	if !desired {
		m.mu.Unlock()
		slog.Info("DHCP: start refused; no option state for client",
			"interface", ifaceName, "family", af)
		return false
	}

	// Use an independent context so DHCP clients are decoupled from the
	// daemon lifecycle. Only an explicit stop (Reconcile removal, Renew,
	// StopAll) cancels a client. During graceful restart (SIGTERM), the
	// process exits without calling StopAll(), so addresses stay on
	// interfaces for the next daemon to reuse.
	cctx, cancel := context.WithCancel(context.Background())
	dc := &dhcpClient{
		cancel:      cancel,
		done:        make(chan struct{}),
		fingerprint: m.configFingerprintLocked(key),
	}
	m.clients[key] = dc
	runFn := m.runClientForTest
	m.mu.Unlock()

	slog.Info("DHCP: starting client", "interface", ifaceName, "family", af)

	go func() {
		// Defer order matters: finishClient (deregister + lease/address
		// cleanup) runs BEFORE close(done), so anyone waiting on done
		// observes a clean registry. The deregistration covers ALL
		// terminal exits (#1793) — cancellation, DHCPv4 max
		// retransmissions, DHCPv6 link-local abort — not just Renew,
		// so a future Start for this key is never a permanent no-op.
		defer close(dc.done)
		defer m.finishClient(key, dc)
		if runFn != nil {
			runFn(cctx, ifaceName, af)
			return
		}
		switch af {
		case AFInet:
			m.runDHCPv4(cctx, ifaceName)
		case AFInet6:
			m.runDHCPv6(cctx, ifaceName)
		}
	}()
	return true
}

// finishClient runs in the client goroutine's defer on every exit path.
// It deregisters the registry entry (only if it still maps to this exact
// client — Renew deletes/re-adds entries, so a pointer compare guards
// against clobbering a successor) and cleans up any lease record and
// interface address the run loop left behind (some cancellation
// interleavings exit the run loop without hitting its own ctx.Done
// cleanup branches).
//
// #1844: this is the lease-record removal owner — it covers the
// terminal exits the run-loop ctx.Done branches never see (cancel
// mid-exchange, DHCPv4 max-retransmission, DHCPv6 link-local abort) —
// so the gateway-change hook fires here unconditionally on the real
// cleanup path. Firing only from the run-loop inline delete sites
// would leave a stale gateway in the ip-monitoring overlay after such
// an exit (a silent blackhole). The successor-guard early return does
// NOT fire (this call changed no lease state). If lease expiry is ever
// implemented per RFC 2131 §4.4.5, the record removal must keep
// routing through a hook-firing path so the overlay withdraws in
// lock-step with the address.
func (m *Manager) finishClient(key clientKey, dc *dhcpClient) {
	m.mu.Lock()
	cur, ok := m.clients[key]
	if !ok || cur != dc {
		// A successor client already replaced (or removed) this key.
		// Its lease / delegated-PD records belong to the successor —
		// a delayed defer from the OLD client must not delete them
		// (AGY review on PR #1815: unguarded cleanup let a slow old
		// defer clobber the new client's lease).
		m.mu.Unlock()
		return
	}
	delete(m.clients, key)
	lease := m.leases[key]
	delete(m.leases, key)
	if key.family == AFInet6 {
		delete(m.delegatedPDs, key.iface)
	}
	m.mu.Unlock()

	if lease != nil && lease.Address.IsValid() {
		m.removeAddress(key.iface, lease)
	}
	m.fireGatewayChange()
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
		m.mu.Unlock()

		if !exists {
			continue
		}

		// Stop the existing client. Do NOT pre-delete the registry
		// entry: finishClient owns deregistration and the lease /
		// delegated-PD / address cleanup, and its pointer guard
		// early-returns when the entry is already gone — a pre-delete
		// here would skip that cleanup entirely when cancellation
		// lands mid-exchange (Codex review on PR #1815). Waiting on
		// done guarantees finishClient has completed before restart.
		dc.cancel()
		<-dc.done

		// Restart. Renew is reachable from gRPC outside applySem, so a
		// concurrent Reconcile may have removed this client from
		// config after we captured dc above; Start performs the
		// desired-set membership check atomically with registration
		// (under m.mu) and refuses to resurrect a deconfigured client
		// — a check here would go stale before Start takes the lock
		// (Codex review on PR #1815, rounds 3-5).
		if !m.Start(context.Background(), ifaceName, af) {
			slog.Info("DHCP: renew skipped restart; client removed from config",
				"interface", ifaceName, "family", af)
			continue
		}
		renewed = true
		slog.Info("DHCP client renewed", "interface", ifaceName, "family", af)
	}
	if !renewed {
		return fmt.Errorf("no DHCP client running on interface %s", ifaceName)
	}
	return nil
}

// StopAll stops all running DHCP clients and releases leases. Registry
// entries are cleared by each client's finishClient defer, which runs
// before its done channel closes, so the registry is empty when StopAll
// returns.
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
	// Durable creation (#1894 code-r1): the state dir's own entry must
	// be made durable on first creation or the DUID file can be lost
	// with the whole directory after a power cut.
	if err := fsatomic.MkdirAllDurable(m.stateDir, 0755); err != nil {
		return err
	}
	// DurableState (#1894): the DUID is the client's stable DHCPv6
	// identity — losing it to a power cut changes the identity the
	// server knows us by across reboot (new leases, stale bindings).
	return fsatomic.WriteFileDurable(m.duidPath(ifaceName), duid.ToBytes(), 0644)
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

// #1715: the DHCP client no longer writes /etc/resolv.conf. DNS
// ownership moved to the daemon's single applySem-locked reconcileDNS,
// which reads DHCP-learned servers from Leases() (lease.DNS is populated
// for both families) and merges them with static `system name-server`.
// The client only stores the lease and fires the debounced
// onAddressChange callback (scheduleRecompile), which the daemon routes
// to reconcileDNSFromDHCP. The former installDNS file write — which
// wrote through the dangling resolv.conf symlink and failed silently,
// and which clobbered the other family's servers with no merge — is
// removed.

// runDHCPv4 runs the DHCPv4 acquisition and renewal cycle. The initial
// acquisition is a full DORA (Discover→Offer→Request→Ack). At T1 the
// loop sends a true RFC 2131 §4.3.6 RENEWING DHCPREQUEST — unicast to
// the granting server (the stored server-identifier), ciaddr set to the
// current address, NO DISCOVER — and at T2 a REBINDING broadcast
// DHCPREQUEST (#2994). A successful renew/rebind commits via commitLease
// and returns to the T1 wait (#1777); only when both fail (lease
// expiry) does the loop fall back to a fresh full DORA acquisition.
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

	// committed is the lease currently applied to the interface (nil
	// until the first successful acquisition). commitLease compares
	// against it to detect address moves and content changes.
	var committed *Lease

	for {
		if ctx.Err() != nil {
			return
		}

		slog.Info("DHCPv4: starting discovery", "interface", ifaceName)

		lease, err := m.v4Exchange(ctx, ifaceName, exchangeAcquire, nil)
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

		if err := m.commitLease(key, lease, committed, nil, nil); err != nil {
			slog.Warn("DHCPv4: failed to apply address",
				"interface", ifaceName, "err", err)
			continue
		}
		committed = lease

		slog.Info("DHCPv4: lease obtained",
			"interface", ifaceName,
			"address", lease.Address,
			"gateway", lease.Gateway,
			"lease_time", lease.LeaseTime)

		// Renewal cycle: stay in this loop while T1 renews / T2 rebinds
		// keep succeeding; break out only to re-acquire from scratch.
		for {
			t1, t2Remaining := renewalTimers(committed.LeaseTime)

			// Wait for T1 (50% of lease time) for renewal
			select {
			case <-m.after(t1):
				slog.Info("DHCPv4: T1 expired, renewing", "interface", ifaceName)
			case <-ctx.Done():
				m.removeAddress(ifaceName, committed)
				m.mu.Lock()
				delete(m.leases, key)
				m.mu.Unlock()
				return
			}

			// T1 renewal attempt — unicast RENEW to the granting server,
			// NOT a fresh DISCOVER (#2994).
			renewed, rerr := m.v4Exchange(ctx, ifaceName, exchangeRenew, committed)
			if rerr == nil {
				if cerr := m.commitLease(key, renewed, committed, nil, nil); cerr != nil {
					slog.Warn("DHCPv4: failed to apply renewed lease, re-acquiring",
						"interface", ifaceName, "err", cerr)
					break
				}
				committed = renewed
				slog.Info("DHCPv4: lease renewed",
					"interface", ifaceName, "address", renewed.Address,
					"lease_time", renewed.LeaseTime)
				continue
			}
			slog.Warn("DHCPv4: T1 renewal failed, waiting for T2",
				"interface", ifaceName, "err", rerr)

			// Wait for T2 (87.5% of lease) — remaining time after T1
			select {
			case <-m.after(t2Remaining):
			case <-ctx.Done():
				m.removeAddress(ifaceName, committed)
				m.mu.Lock()
				delete(m.leases, key)
				m.mu.Unlock()
				return
			}

			// T2 rebind attempt — broadcast REBIND (#2994).
			renewed, rerr = m.v4Exchange(ctx, ifaceName, exchangeRebind, committed)
			if rerr == nil {
				if cerr := m.commitLease(key, renewed, committed, nil, nil); cerr != nil {
					slog.Warn("DHCPv4: failed to apply rebound lease, re-acquiring",
						"interface", ifaceName, "err", cerr)
					break
				}
				committed = renewed
				slog.Info("DHCPv4: lease rebound",
					"interface", ifaceName, "address", renewed.Address,
					"lease_time", renewed.LeaseTime)
				continue
			}
			slog.Warn("DHCPv4: T2 rebind failed, lease will expire, re-acquiring",
				"interface", ifaceName, "err", rerr)
			break // fall back to a fresh DORA
		}
	}
}

// doDHCPv4 performs a single DHCPv4 exchange for the given mode:
// exchangeAcquire runs a full DORA; exchangeRenew sends a unicast
// RENEWING DHCPREQUEST to the server that granted prev; exchangeRebind
// sends a broadcast REBINDING DHCPREQUEST (#2994). prev is the currently
// committed lease (nil only for acquire).
func (m *Manager) doDHCPv4(ctx context.Context, ifaceName string, mode dhcpExchangeMode, prev *Lease) (*Lease, error) {
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

	var ack *dhcpv4.DHCPv4
	switch mode {
	case exchangeRenew, exchangeRebind:
		if prev == nil || !prev.Address.IsValid() {
			return nil, fmt.Errorf("DHCPv4 renew without a prior lease")
		}
		rebind := mode == exchangeRebind
		req, err := buildV4RenewRequest(client.InterfaceAddr(), prev, mods)
		if err != nil {
			return nil, fmt.Errorf("DHCPv4 build renew request: %w", err)
		}
		dest := v4RenewDest(prev, rebind)
		resp, err := client.SendAndRead(exCtx, dest, req,
			nclient4.IsMessageType(dhcpv4.MessageTypeAck, dhcpv4.MessageTypeNak))
		if err != nil {
			return nil, fmt.Errorf("DHCPv4 %s: %w", mode, err)
		}
		if resp.MessageType() == dhcpv4.MessageTypeNak {
			return nil, fmt.Errorf("DHCPv4 %s: server sent NAK", mode)
		}
		ack = resp
	default:
		dhcpLease, err := client.Request(exCtx, mods...)
		if err != nil {
			return nil, fmt.Errorf("DHCPv4 request: %w", err)
		}
		ack = dhcpLease.ACK
	}

	return leaseFromACKv4(ifaceName, ack)
}

// leaseFromACKv4 parses a DHCPv4 ACK into a Lease, capturing the
// server-identifier needed to unicast a later RENEW (#2994). Shared by
// the acquire, renew, and rebind paths.
func leaseFromACKv4(ifaceName string, ack *dhcpv4.DHCPv4) (*Lease, error) {
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

	// Server identifier — the unicast destination for the next RENEW.
	if sid := ack.ServerIdentifier(); sid != nil {
		if s, ok := netip.AddrFromSlice(sid.To4()); ok {
			lease.serverID = s
		}
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

// runDHCPv6 runs the DHCPv6 solicit/request cycle with retries and
// renewal. Initial acquisition is a Rapid-Solicit (or Information-Request
// in stateless mode). At T1 the loop sends an RFC 8415 §18.2.4 RENEW to
// the granting server (echoing the assigned IA_NA / IA_PD with the
// server's DUID) and at T2 an §18.2.5 REBIND (multicast, no server DUID)
// — NOT a fresh Solicit (#2994). A successful renew/rebind commits the
// renewed lease (and any delegated prefixes) via commitLease and returns
// to the T1 wait (#1777); only when both attempts fail (lease expiry)
// does the loop fall back to a fresh solicit. Stateless mode has no
// binding, so every refresh is an Information-Request regardless of mode.
func (m *Manager) runDHCPv6(ctx context.Context, ifaceName string) {
	key := clientKey{iface: ifaceName, family: AFInet6}
	backoff := time.Second

	m.mu.Lock()
	v6opts := m.v6opts[ifaceName]
	m.mu.Unlock()

	stateless := v6opts != nil && v6opts.Stateless

	// Wait for link-local address
	if err := m.waitLinkLocal(ctx, ifaceName, 30*time.Second); err != nil {
		slog.Warn("DHCPv6: no link-local address, aborting",
			"interface", ifaceName, "err", err)
		return
	}

	// committed / committedPDs track the lease and delegated prefixes
	// currently applied (nil/empty until the first success). In
	// stateless mode the lease never carries an address, so commitLease
	// skips the address apply/remove paths via Address.IsValid().
	var (
		committed    *Lease
		committedPDs []DelegatedPrefix
	)

	for {
		if ctx.Err() != nil {
			return
		}

		if stateless {
			slog.Info("DHCPv6: starting information-request", "interface", ifaceName)
		} else {
			slog.Info("DHCPv6: starting solicit", "interface", ifaceName)
		}

		result, err := m.v6Exchange(ctx, ifaceName, exchangeAcquire, nil, nil)
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

		// #1715: DNS install is not done here. lease.DNS is stored by
		// commitLease and the daemon's reconcileDNS reads it from
		// Leases(); the debounced onAddressChange callback (fired by
		// commitLease when lease content changed) drives the reconcile.
		if err := m.commitLease(key, result.lease, committed, result.prefixes, committedPDs); err != nil {
			slog.Warn("DHCPv6: failed to apply address",
				"interface", ifaceName, "err", err)
			continue
		}
		committed = result.lease
		if len(result.prefixes) > 0 {
			committedPDs = result.prefixes
		}

		if stateless {
			slog.Info("DHCPv6: stateless options obtained",
				"interface", ifaceName,
				"dns", committed.DNS)
		} else {
			slog.Info("DHCPv6: lease obtained",
				"interface", ifaceName,
				"address", committed.Address,
				"delegated_prefixes", len(result.prefixes),
				"lease_time", committed.LeaseTime)
		}

		// Renewal cycle: stay in this loop while T1 renews / T2 rebinds
		// keep succeeding; break out only to re-acquire from scratch.
		for {
			t1, t2Remaining := renewalTimers(committed.LeaseTime)

			// Wait for T1
			select {
			case <-m.after(t1):
				slog.Info("DHCPv6: T1 expired, renewing", "interface", ifaceName)
			case <-ctx.Done():
				if committed.Address.IsValid() {
					m.removeAddress(ifaceName, committed)
				}
				m.mu.Lock()
				delete(m.leases, key)
				delete(m.delegatedPDs, ifaceName)
				m.mu.Unlock()
				return
			}

			// T1 renewal attempt — RENEW to the granting server, NOT a
			// fresh Solicit (#2994).
			renewed, rerr := m.v6Exchange(ctx, ifaceName, exchangeRenew, committed, committedPDs)
			if rerr == nil {
				if cerr := m.commitLease(key, renewed.lease, committed, renewed.prefixes, committedPDs); cerr != nil {
					slog.Warn("DHCPv6: failed to apply renewed lease, re-acquiring",
						"interface", ifaceName, "err", cerr)
					break
				}
				committed = renewed.lease
				if len(renewed.prefixes) > 0 {
					committedPDs = renewed.prefixes
				}
				slog.Info("DHCPv6: lease renewed",
					"interface", ifaceName,
					"address", committed.Address,
					"delegated_prefixes", len(renewed.prefixes),
					"lease_time", committed.LeaseTime)
				continue
			}
			slog.Warn("DHCPv6: T1 renewal failed, waiting for T2",
				"interface", ifaceName, "err", rerr)

			// Wait for T2 (87.5% of lease) — remaining time after T1
			select {
			case <-m.after(t2Remaining):
			case <-ctx.Done():
				if committed.Address.IsValid() {
					m.removeAddress(ifaceName, committed)
				}
				m.mu.Lock()
				delete(m.leases, key)
				delete(m.delegatedPDs, ifaceName)
				m.mu.Unlock()
				return
			}

			// T2 rebind attempt — REBIND (multicast, no server DUID) (#2994).
			renewed, rerr = m.v6Exchange(ctx, ifaceName, exchangeRebind, committed, committedPDs)
			if rerr == nil {
				if cerr := m.commitLease(key, renewed.lease, committed, renewed.prefixes, committedPDs); cerr != nil {
					slog.Warn("DHCPv6: failed to apply rebound lease, re-acquiring",
						"interface", ifaceName, "err", cerr)
					break
				}
				committed = renewed.lease
				if len(renewed.prefixes) > 0 {
					committedPDs = renewed.prefixes
				}
				slog.Info("DHCPv6: lease rebound",
					"interface", ifaceName,
					"address", committed.Address,
					"delegated_prefixes", len(renewed.prefixes),
					"lease_time", committed.LeaseTime)
				continue
			}
			slog.Warn("DHCPv6: T2 rebind failed, lease will expire, re-acquiring",
				"interface", ifaceName, "err", rerr)
			break // fall back to a fresh solicit
		}
	}
}

// dhcpv6Result holds results from a DHCPv6 exchange including both IA_NA and IA_PD.
type dhcpv6Result struct {
	lease    *Lease
	prefixes []DelegatedPrefix
}

// doDHCPv6 performs a single DHCPv6 exchange for the given mode.
// exchangeAcquire runs a Rapid-Solicit (or Information-Request in
// stateless mode); exchangeRenew sends an RFC 8415 §18.2.4 RENEW to the
// granting server (server DUID echoed) and exchangeRebind an §18.2.5
// REBIND (no server DUID), both echoing the assigned IA_NA / IA_PD from
// prev / prevPDs (#2994). Stateless mode ignores the mode (no binding to
// renew — every refresh is an Information-Request).
func (m *Manager) doDHCPv6(ctx context.Context, ifaceName string, mode dhcpExchangeMode, prev *Lease, prevPDs []DelegatedPrefix) (*dhcpv6Result, error) {
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

	stateless := v6opts != nil && v6opts.Stateless

	// Stateless mode: send Information-Request (no IA_NA/IA_PD). There is
	// no lease binding, so renew/rebind collapse to the same refresh.
	if stateless {
		msg, err := dhcpv6.NewMessage()
		if err != nil {
			return nil, fmt.Errorf("DHCPv6 new message: %w", err)
		}
		msg.MessageType = dhcpv6.MessageTypeInformationRequest
		// Apply modifiers (DUID, ORO options)
		for _, mod := range mods {
			mod(msg)
		}
		// Always request DNS
		oro := msg.Options.RequestedOptions()
		hasDNS := false
		for _, code := range oro {
			if code == dhcpv6.OptionDNSRecursiveNameServer {
				hasDNS = true
				break
			}
		}
		if !hasDNS {
			dhcpv6.WithRequestedOptions(dhcpv6.OptionDNSRecursiveNameServer)(msg)
		}

		resp, err := client.SendAndRead(exCtx, nclient6.AllDHCPRelayAgentsAndServers, msg, nil)
		if err != nil {
			return nil, fmt.Errorf("DHCPv6 information-request: %w", err)
		}

		lease := &Lease{
			Interface: ifaceName,
			Family:    AFInet6,
			Obtained:  time.Now(),
			LeaseTime: 3600 * time.Second, // 1-hour refresh for stateless
		}
		if dnsOpt := resp.Options.DNS(); len(dnsOpt) > 0 {
			for _, dns := range dnsOpt {
				if a, ok := netip.AddrFromSlice(dns); ok {
					lease.DNS = append(lease.DNS, a)
				}
			}
		}
		return &dhcpv6Result{lease: lease}, nil
	}

	var adv *dhcpv6.Message
	switch mode {
	case exchangeRenew, exchangeRebind:
		rebind := mode == exchangeRebind
		// Renew/rebind echo the actual held IA_NA/IA_PD, so use only the
		// client-id + ORO modifiers — NOT the acquisition IA_PD hint
		// (which would merge a hint prefix into our real IA_PD).
		renewMods := m.buildDHCPv6RenewModifiers(ifaceName, v6opts)
		msg, err := buildV6RenewMessage(client.InterfaceAddr(), prev, prevPDs, rebind, renewMods)
		if err != nil {
			return nil, fmt.Errorf("DHCPv6 build %s: %w", mode, err)
		}
		adv, err = client.SendAndRead(exCtx, nclient6.AllDHCPRelayAgentsAndServers, msg,
			nclient6.IsMessageType(dhcpv6.MessageTypeReply))
		if err != nil {
			return nil, fmt.Errorf("DHCPv6 %s: %w", mode, err)
		}
	default:
		adv, err = client.RapidSolicit(exCtx, mods...)
		if err != nil {
			return nil, fmt.Errorf("DHCPv6 solicit: %w", err)
		}
	}

	return m.parseV6Reply(ctx, ifaceName, adv, v6opts)
}

// parseV6Reply extracts the lease (IA_NA address, lifetime, DNS, gateway)
// and any delegated prefixes (IA_PD) from a DHCPv6 Reply/Advertise. It is
// shared by the solicit, renew, and rebind paths (#2994); the server DUID
// is captured so the next RENEW can echo it.
func (m *Manager) parseV6Reply(ctx context.Context, ifaceName string, adv *dhcpv6.Message, v6opts *DHCPv6Options) (*dhcpv6Result, error) {
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

	// Server identifier (DUID) — echoed in the next RENEW so the original
	// server matches our binding (#2994).
	lease.v6ServerDUID = adv.Options.ServerID()

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
	if gw := m.discoverIPv6Router(ctx, ifaceName); gw.IsValid() {
		lease.Gateway = gw
	}

	result.lease = lease
	return result, nil
}

// buildDHCPv6RenewModifiers constructs the modifiers for a RENEW/REBIND
// message: the persistent client-id and the requested-option list, but
// NOT the IA_NA/IA_PD options (the renew echoes the held bindings, which
// buildV6RenewMessage adds explicitly). Reusing buildDHCPv6Modifiers here
// would merge the acquisition IA_PD hint into our real IA_PD (#2994).
func (m *Manager) buildDHCPv6RenewModifiers(ifaceName string, opts *DHCPv6Options) []dhcpv6.Modifier {
	var mods []dhcpv6.Modifier
	if duid, err := m.getDUID(ifaceName); err == nil {
		mods = append(mods, dhcpv6.WithClientID(duid))
	}
	if opts == nil {
		return mods
	}
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

// buildDHCPv6Modifiers constructs DHCPv6 message modifiers from interface options.
func (m *Manager) buildDHCPv6Modifiers(ifaceName string, opts *DHCPv6Options) []dhcpv6.Modifier {
	if opts == nil {
		return nil
	}

	var mods []dhcpv6.Modifier

	// Use persistent DUID if configured
	if duid, err := m.getDUID(ifaceName); err == nil {
		mods = append(mods, dhcpv6.WithClientID(duid))
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
func (m *Manager) discoverIPv6Router(ctx context.Context, ifaceName string) netip.Addr {
	link, err := m.nlHandle.LinkByName(ifaceName)
	if err != nil {
		return netip.Addr{}
	}

	for attempt := 0; attempt < 10; attempt++ {
		if attempt > 0 {
			// Context-aware: Reconcile cancels clients and waits on
			// done while applyConfigLocked holds applySem — a blind
			// 10x1s sleep here wedged every commit for up to 10s
			// (AGY review on PR #1815).
			select {
			case <-ctx.Done():
				return netip.Addr{}
			case <-time.After(time.Second):
			}
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
	if m.nlHandle == nil {
		return nil // test-constructed Manager without netlink
	}
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
	if m.nlHandle == nil {
		return // test-constructed Manager without netlink
	}
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
