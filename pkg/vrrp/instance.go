package vrrp

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/vishvananda/netlink"
)

// VRRPState represents the VRRPv3 state machine state.
type VRRPState int

const (
	StateInitialize VRRPState = iota
	StateBackup
	StateMaster
)

// addressOwnerPriority is the VRRP priority reserved for the IP address owner
// (RFC 5798 §5.2.4). An instance configured with this priority owns the virtual
// address and, per RFC 5798 §6.1, MUST preempt a lower-priority master
// "irrespective of the setting of" the preempt flag — the owner always reclaims
// mastership. See getPreempt / shouldPreemptObservedMaster (owner-preempt), and
// getPriority (track.go — the owner is also exempt from track-down demotion).
const addressOwnerPriority = 255

// minLearnedMasterAdverInterval is the absolute lower bound applied to a
// Master_Adver_Interval learned from a peer advertisement (recordMasterAdvert,
// #4548). It matches the schema minimum for `chassis cluster
// reth-advertise-interval` (10 ms; pkg/config/schema_chassis.go) — the smallest
// cadence the system will ever legitimately run at. It is only the backstop for
// the degenerate case where the local configured interval is somehow unset; the
// primary floor is the node's own configured advertise interval (see
// masterAdverFloor). RFC 5798 §6.1/§6.4.2 requires a BACKUP to time its master
// out on the master's advertised cadence, but a buggy or misconfigured peer that
// advertises Max Adver Int=1 (10 ms) must not be allowed to drive a 30 ms RETH
// node's Master_Down_Interval down to ~30 ms and flap mastership on ordinary
// scheduling/network jitter.
const minLearnedMasterAdverInterval = 10 * time.Millisecond

func (s VRRPState) String() string {
	switch s {
	case StateInitialize:
		return "INIT"
	case StateBackup:
		return "BACKUP"
	case StateMaster:
		return "MASTER"
	default:
		return "UNKNOWN"
	}
}

// VRRPEvent is emitted when a VRRP instance changes state.
type VRRPEvent struct {
	Interface string
	Family    string
	GroupID   int
	State     VRRPState
	VIPs      []string
}

// vrrpInstance is a per-VRRP-group state machine goroutine.
type vrrpInstance struct {
	mu               sync.RWMutex
	cfg              Instance
	desiredPreempt   bool // configured preempt value (may differ from cfg.Preempt during sync hold)
	forcePreemptOnce bool // one-shot preempt override from ForceRGMaster (auto-cleared after use)
	// skipNextPreemptHold makes the next masterDownTimer expiry promote
	// immediately, bypassing the preempt hold-time (#2850). Set when the
	// master resigns (priority-0) so a graceful, planned failover is never
	// delayed by the hold-time — there is no live master to blackhole.
	// One-shot: cleared by the masterDownTimer.C handler. Guarded by mu.
	skipNextPreemptHold bool

	// preemptHoldArmed tracks whether the preempt hold-time countdown (#2850)
	// is currently running (#2900). It is set when stepBackup arms the
	// preemptHoldTimer and cleared whenever the timer is stopped or fires. A
	// config update arriving during the hold window (updateConfig → the
	// configUpdatedCh case in stepBackup) reads this flag to decide whether an
	// in-flight hold must be torn down because the new config no longer
	// warrants it (preempt disabled, priority demoted, or hold-time changed).
	// Mutated only by the run-loop goroutine (arm/disarm helpers); read under
	// mu so a future cross-goroutine reader stays race-clean. Guarded by mu.
	preemptHoldArmed bool

	trackDown bool // tracked interface (cfg.TrackInterface) is down (#1814); guarded by mu

	// Last-seen master advertisement (#2082). Recorded by handleBackupRx /
	// handleMasterRx for every non-zero-priority advert from a peer, and read
	// by shouldPreemptObservedMaster to gate the non-force sync-hold preempt
	// shortcut on a strictly-higher effective priority (RFC 5798 §6.4.2). Both
	// writers and the gate reader run in the run-loop goroutine, so they are
	// already serialized with respect to each other; mu makes the writes/reads
	// race-clean for any future cross-goroutine reader. Priority-0
	// (resignation) adverts are NOT recorded — post-resign takeover flows
	// through the ungated masterDownTimer path. Guarded by mu.
	lastMasterPriority int       // last non-zero peer advert priority
	lastMasterSeen     time.Time // when lastMasterPriority was recorded

	// masterAdverInterval is the advertisement interval LEARNED from the
	// current master's advertisement — RFC 5798 §6.1/§6.4.2 Master_Adver_Interval
	// — derived from the received advert's Max Adver Int field (centiseconds on
	// the wire, 10 ms units, converted to a Duration). A BACKUP must compute its
	// Master_Down_Interval + Skew_Time from the MASTER's advertised cadence, NOT
	// its own locally-configured cfg.AdvertiseInterval: when the master and
	// backup are configured with different intervals (a rolling change or a
	// misconfig), timing the master out on the local interval fails over too
	// early (shorter local interval → flapping) or too late (longer → traffic
	// loss). Recorded by recordMasterAdvert for every non-zero-priority advert,
	// alongside lastMasterPriority/lastMasterSeen. 0 = none learned yet
	// (cold-start / pre-first-advert), in which case the local interval is the
	// fallback. Guarded by mu.
	masterAdverInterval time.Duration

	state   VRRPState
	iface   *net.Interface
	eventCh chan<- VRRPEvent

	// localIP / localIPv6 are our IPv4 address (for filtering self-sent
	// adverts) and our link-local IPv6 address (source for IPv6 VRRP
	// adverts). They are resolved once at openSocket() time, BEFORE any
	// goroutine is started — but that resolution can come back empty (no
	// IPv4 address assigned yet, or IPv6 DAD still running). In that case
	// sendPacket()/sendPacketIPv6() perform a one-shot lazy resolve from
	// the run-loop goroutine. Meanwhile the receiver goroutines
	// (receiver/receiverIPv6/parseAfPacketIPv4/parseAfPacketIPv6) read
	// these fields to filter self-sent packets. The lazy-resolve write
	// thus races the receiver reads (#2258), so the fields are
	// atomic.Pointer[net.IP] accessed only via getLocalIP/setLocalIP and
	// getLocalIPv6/setLocalIPv6. A nil pointer means unresolved; the
	// resolve semantics are preserved (the address still becomes available
	// once resolvable). Mirrors the lastDropWarn atomic pattern (#2225).
	localIP   atomic.Pointer[net.IP] // our IPv4 address on this interface
	localIPv6 atomic.Pointer[net.IP] // our link-local IPv6 address

	// #7334: the receive-path self-frame check's address SETS. See
	// isLocalAddr (instance_addr.go) for why these differ from the send
	// sources above and why an unresolved set fails OPEN.
	localAddrSet   atomic.Pointer[[]string]
	localAddrSetV6 atomic.Pointer[[]string]

	// Per-instance raw socket and receiver.
	conn    net.PacketConn
	rawConn *ipv4.RawConn

	// IPv6 raw socket for sending VRRPv3 advertisements.
	// nil when no IPv6 VIPs are configured.
	ipv6Conn net.PacketConn
	ipv6FD   int // raw fd for setsockopt (hop limit, multicast)

	// ipv6Send is the seam used by sendPacketIPv6 to write an IPv6 advert
	// with an explicit IPV6_PKTINFO control message. The control message
	// pins the OUTER IPv6 source to the same link-local address the
	// pseudo-header checksum was computed over (#2644). Without it the
	// kernel performs independent RFC 6724 source selection on the
	// wildcard-bound (`::`) socket; with more than one link-local on the
	// interface it can pick a different source than the checksum used, so
	// the receiver's pseudo-header checksum mismatches and the advert is
	// silently dropped -> dual-master split-brain. Defaults to a wrapper
	// over ipv6.NewPacketConn(ipv6Conn).WriteTo; overridden in tests to
	// capture the control message.
	ipv6Send func(data []byte, cm *ipv6.ControlMessage, dst net.Addr) error

	// ipv6Recv is the seam used by receiverIPv6 to read an IPv6 advert together
	// with its arrival interface and IPv6 hop limit (the per-packet control
	// message). It returns the byte count, the arrival ifindex (0 if the
	// platform did not report one), the received hop limit (0 if the platform
	// did not report one), and the source address. Production leaves it nil and
	// receiverIPv6 lazily builds a wrapper over ipv6.NewPacketConn(ipv6Conn)
	// with FlagInterface and FlagHopLimit enabled; tests override it to inject
	// synthetic adverts with a chosen arrival ifindex and hop limit (the #2886
	// cross-VLAN filter seam and the GTSM hop-limit gate). Capturing the arrival
	// ifindex is required because the IPv6 raw socket on a VLAN sub-interface is
	// wildcard-bound (no SO_BINDTODEVICE — see manager.go), so the kernel fans a
	// proto-112 frame out to every sibling-VLAN socket; the VRID/hop-limit/self
	// gates alone let same-VRID siblings cross-process (#2886). Capturing the
	// hop limit is required to enforce RFC 5798 §5.1.2.3 (hop limit MUST be 255)
	// — the kernel strips the IPv6 header on a raw ip6:112 socket, so the value
	// is only reachable via the IPV6_RECVHOPLIMIT control message (#4549 F8).
	ipv6Recv func(buf []byte) (n int, ifindex int, hopLimit int, src net.Addr, err error)

	// AF_PACKET socket for receiving on VLAN sub-interfaces.
	// Raw IP sockets don't reliably receive multicast on VLAN
	// sub-interfaces (kernel limitation). AF_PACKET captures at
	// the link layer and works correctly. -1 means not used.
	afPacketFD int

	preemptNowCh    chan struct{} // signals coordinated preemption from ReleaseSyncHold
	resignCh        chan struct{} // signals forced resignation (manual failover)
	configUpdatedCh chan struct{} // signals updateConfig mutated cfg (#2900 hold re-validate)

	rxCh    chan *VRRPPacket
	stopCh  chan struct{}
	stopped chan struct{}

	// RX backpressure counters (atomic).
	rxDrops    atomic.Uint64 // packets dropped due to full rxCh
	rxReceived atomic.Uint64 // total packets delivered to rxCh
	// lastDropWarn is the Unix-nanos timestamp of the last drop warning we
	// logged (rate-limited). It is an atomic.Int64 because warnRXDrop is
	// called concurrently from both receiver() and receiverIPv6() on the
	// AF_PACKET-fallback path (#2225); a plain time.Time would be a data
	// race. Mirrors the lastGARPTime atomic pattern below.
	lastDropWarn atomic.Int64

	// GARP suppression for strict-vip-ownership mode.
	suppressGARP    atomic.Bool   // when true, becomeMaster() skips GARP/NA
	garpEpoch       atomic.Uint64 // incremented on each becomeMaster()/ReconcileVIPs transition
	lastGARPEpoch   atomic.Uint64 // epoch of last completed sendGARP()
	lastGARPTime    atomic.Int64  // Unix nanos of last GARP send (dampens routine GARP only; forced sends bypass — see garpSendAllowed)
	garpClampWarned atomic.Bool   // #5695: guards a once-per-instance warn when a configured GARPCount is clamped (never per-send)

	// ownerGen is the identity of the current Master/Backup ownership tenure
	// (#5082). setState bumps it whenever the state actually changes, so every
	// state transition begins a fresh generation. Code that actuates the VIP
	// set via netlink (becomeMaster, ReconcileVIPs) captures the generation
	// before the netlink op and revalidates it afterward: if a demotion raced
	// in and bumped ownerGen, the actuation is stale — roll back the added VIPs
	// and do NOT advertise/emit/GARP for a tenure we have already left. Atomic
	// so log/test readers stay lock-free; the load-bearing check-then-act runs
	// under vipMu below.
	ownerGen atomic.Uint64

	// vipMu serializes VIP netlink actuation (addVIPs/removeVIPs) plus the
	// ownership-generation revalidation across the two goroutines that touch
	// VIPs: the run-loop (becomeMaster/becomeBackup) and the manager's
	// ReconcileVIPs. Holding vipMu across "read gen + actuate + revalidate"
	// makes the check-then-act atomic so a demotion cannot interleave a
	// ReconcileVIPs re-add and strand a BACKUP announcing VIPs (#5082). The
	// lock is uncontended on the normal failover path (ReconcileVIPs is a rare
	// post-programRethMAC reconcile), so it adds no latency to ~60ms failover.
	vipMu sync.Mutex

	// VIP/role divergence accounting for the BACKUP side (#5482). becomeMaster
	// is already fail-closed (#5082): it refuses to publish MASTER when the VIP
	// add fails. The symmetric BACKUP hazard remained: becomeBackup published the
	// BACKUP role via emitEvent even when removeVIPs failed, so a swallowed
	// netlink error left this now-BACKUP node still answering ARP for a VIP it no
	// longer owns (duplicate-address hazard against the new master). We must still
	// publish BACKUP (we ARE stepping down — refusing to emit risks split-brain),
	// so instead of hiding the failure we surface it: vipRemoveFailures is a
	// monotonic count of BACKUP transitions whose synchronous VIP removal failed,
	// and vipDiverged flags that a stale VIP may still be on the wire (cleared once
	// an async reconcile removes it). Atomic so log/test readers stay lock-free.
	vipRemoveFailures atomic.Uint64
	vipDiverged       atomic.Bool

	// vipReconcileBackoff overrides the spacing between stale-VIP remove-reconcile
	// retries (#5482). Zero ⇒ defaultVIPReconcileBackoff. A per-instance field
	// (not a package var) so unit tests shorten it without a shared-global data
	// race against another instance's still-running reconcile goroutine. Set once
	// before the reconcile goroutine starts; the goroutine only reads it.
	vipReconcileBackoff time.Duration

	// netlink seams for VIP actuation. Production leaves them nil and the
	// helpers call netlink live; unit tests inject them to drive addVIPs down
	// a chosen success/failure path without a real kernel interface (#5082).
	linkByNameFn func(name string) (netlink.Link, error)
	addrAddFn    func(link netlink.Link, addr *netlink.Addr) error
	addrDelFn    func(link netlink.Link, addr *netlink.Addr) error

	// onEventDrop is called when an event is dropped due to a full eventCh.
	// Set by the manager to trigger immediate reconciliation.
	onEventDrop func()

	// addrsFn, when non-nil, overrides interface address enumeration. Unit
	// tests inject it to simulate an address change without a real kernel
	// interface (#2528). Production leaves it nil and interfaceAddrs() queries
	// vi.iface.Addrs() live on every resolve.
	addrsFn func() ([]net.Addr, error)

	// resignAckMu guards resignAcks: the set of #6177 ResignBarriers waiting
	// for THIS instance to finish RELEASING its virtual addresses after a
	// forced resignation. A barrier is armed by the manager BEFORE
	// triggerResign, and reported to from the sites that actually complete a
	// VIP release, so a waiter can never be told "released" by a code path
	// that only signalled the resignation.
	//
	// Arming does NOT shortcut on state: reading "already BACKUP" and
	// completing the barrier immediately would be wrong exactly when it
	// matters, because becomeBackup publishes BACKUP (setState) BEFORE it
	// runs removeVIPs — the VIP can still be on the wire while the state
	// already reads BACKUP. Instead the BACKUP arm of the run loop consumes
	// the resign token and reports there, so a genuinely already-resigned
	// instance completes the barrier on the next loop hop rather than
	// stalling it.
	resignAckMu sync.Mutex
	resignAcks  []*ResignBarrier

	// advertCapacityErr is non-nil when this instance's configured VIP set
	// cannot produce a legal VRRPv3 advertisement, so becomeMaster must not
	// claim ownership (#6779). Computed once by instanceAdvertCapacityErr
	// (advert_capacity.go); read-only after construction.
	advertCapacityErr error
}

func newInstance(cfg Instance, iface *net.Interface, eventCh chan<- VRRPEvent, onEventDrop func()) *vrrpInstance {
	capErr := instanceAdvertCapacityErr(cfg) // #6779, advert_capacity.go
	return &vrrpInstance{
		cfg:               cfg,
		desiredPreempt:    cfg.Preempt,
		state:             StateInitialize,
		iface:             iface,
		eventCh:           eventCh,
		afPacketFD:        -1,
		ipv6FD:            -1,
		preemptNowCh:      make(chan struct{}, 1),
		resignCh:          make(chan struct{}, 1),
		configUpdatedCh:   make(chan struct{}, 1),
		rxCh:              make(chan *VRRPPacket, 64),
		stopCh:            make(chan struct{}),
		stopped:           make(chan struct{}),
		onEventDrop:       onEventDrop,
		advertCapacityErr: capErr,
	}
}

func (vi *vrrpInstance) key() string {
	return StateKey(vi.cfg.Interface, vi.cfg.GroupID, vi.cfg.Family)
}

// updateConfig updates priority, preempt, interface-tracking,
// advertise-interval, and gratuitous-ARP-count config in-place without
// restarting.
//
// It runs on the manager goroutine, NOT the run-loop goroutine that owns the
// preemptHoldTimer (#2900). It therefore mutates cfg under mu and then signals
// the run loop via configUpdatedCh rather than touching the timer directly —
// the run loop tears down an in-flight hold whose premise the new config has
// invalidated (preempt disabled, priority demoted, or hold-time changed). This
// keeps all preemptHoldTimer Stop/Reset calls on the single run-loop goroutine.
//
// AdvertiseInterval and GARPCount are copied so a day-2 change reaches the
// running instance (#5087). Both are re-read from cfg by the run loop and the
// failover path, so no explicit timer poke is needed: the MASTER advert timer
// re-arms via advertTimer.Reset(vi.advertInterval()) on its next fire, the
// BACKUP master-down horizon re-reads cfg.AdvertiseInterval via
// masterDownInterval(), and the next failover's sendGARP re-reads
// cfg.GARPCount. Before this copy a commit changing only
// reth-advertise-interval or gratuitous-arp-count left the running instance at
// its stale value until an unrelated restart.
func (vi *vrrpInstance) updateConfig(cfg Instance) {
	vi.mu.Lock()
	vi.cfg.Priority = cfg.Priority
	vi.cfg.Preempt = cfg.Preempt
	vi.cfg.PreemptHoldTime = cfg.PreemptHoldTime
	vi.cfg.AdvertiseInterval = cfg.AdvertiseInterval
	vi.cfg.GARPCount = cfg.GARPCount
	vi.cfg.TrackInterface = cfg.TrackInterface
	vi.cfg.TrackPriorityCost = cfg.TrackPriorityCost
	vi.desiredPreempt = cfg.Preempt
	vi.mu.Unlock()

	// Wake the BACKUP select so an armed preempt hold-time can be re-validated
	// against the new config. Non-blocking: a coalesced pending signal is fine
	// (the handler re-reads the current cfg, not a per-update delta).
	select {
	case vi.configUpdatedCh <- struct{}{}:
	default:
	}
}

// suppressPreempt forces effective preempt to false while preserving the
// configured desiredPreempt value for later restore.
func (vi *vrrpInstance) suppressPreempt() {
	vi.mu.Lock()
	vi.cfg.Preempt = false
	vi.mu.Unlock()
}

// setDesiredPreempt updates the configured preempt value that should be
// restored when sync hold is released.
func (vi *vrrpInstance) setDesiredPreempt(preempt bool) {
	vi.mu.Lock()
	vi.desiredPreempt = preempt
	vi.mu.Unlock()
}

// restorePreempt sets cfg.Preempt to the configured (desired) value.
// Called when sync hold is released to re-enable preemption.
func (vi *vrrpInstance) restorePreempt() {
	vi.mu.Lock()
	vi.cfg.Preempt = vi.desiredPreempt
	vi.mu.Unlock()
}

// triggerPreemptNow signals the run loop to attempt immediate preemption.
// Non-blocking: if a signal is already pending it is silently dropped.
func (vi *vrrpInstance) triggerPreemptNow() {
	select {
	case vi.preemptNowCh <- struct{}{}:
	default:
	}
}

// triggerResign signals the run loop to resign from MASTER by sending
// priority-0 adverts and transitioning to BACKUP. Non-blocking.
func (vi *vrrpInstance) triggerResign() {
	select {
	case vi.resignCh <- struct{}{}:
	default:
	}
}

// armResignAck registers b as a waiter for this instance's next VIP release.
// The manager calls it BEFORE triggerResign so the run loop cannot complete the
// release between the arm and the trigger and leave the waiter unreported.
func (vi *vrrpInstance) armResignAck(b *ResignBarrier) {
	if b == nil {
		return
	}
	vi.resignAckMu.Lock()
	vi.resignAcks = append(vi.resignAcks, b)
	vi.resignAckMu.Unlock()
}

// notifyResigned reports outcome err to every barrier armed on this instance
// and clears the list, so each registration is reported exactly once and a
// later release cannot double-report an already-completed barrier. err is the
// VIP-removal outcome: nil means the addresses are off the wire.
func (vi *vrrpInstance) notifyResigned(err error) {
	vi.resignAckMu.Lock()
	waiters := vi.resignAcks
	vi.resignAcks = nil
	vi.resignAckMu.Unlock()
	for _, b := range waiters {
		b.report(err)
	}
}

// staleVIPResignErr converts a lingering VIP divergence (#5482) into a resign
// verdict. An instance that is already BACKUP has no VIP tenure to tear down —
// unless a previous removal FAILED and its async reconcile has not yet cleared
// the address, in which case this node may still be answering ARP for the VIP
// and must not report a clean release to a two-owner fence (#6177 item 1).
func (vi *vrrpInstance) staleVIPResignErr() error {
	if vi.vipDiverged.Load() {
		return fmt.Errorf("%w: instance %s", ErrStaleVIPOnBackup, vi.key())
	}
	return nil
}

// getPreempt reports the EFFECTIVE preempt mode. It is the configured
// cfg.Preempt OR-ed with the address-owner override: an instance whose
// configured priority is 255 (the IP address owner) always preempts,
// irrespective of the no-preempt flag or a sync-hold suppression of
// cfg.Preempt (RFC 5798 §6.1: "a Backup MUST preempt when it is the IP address
// owner ... irrespective of the setting of this flag"). Without this override
// an owner configured with `no-preempt` that returns after a peer took over
// would reset its master-down timer on every lower-priority advert
// (handleBackupRx) and stay BACKUP forever, though it OWNS the VIP (#4116).
//
// The override keys on cfg.Priority (the configured value), not the effective
// tracked priority: an owner is track-exempt (getPriority never demotes 255),
// so the configured 255 is authoritative here. It is a no-op for every
// non-owner instance, so cluster RETH failover (weight-based priorities < 255)
// is unaffected.
func (vi *vrrpInstance) getPreempt() bool {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.cfg.Preempt || vi.cfg.Priority == addressOwnerPriority
}

// shouldPreemptObservedMaster decides whether the non-force sync-hold preempt
// shortcut (the preemptNowCh case in run) may transition this BACKUP instance
// to MASTER (#2082). It encodes RFC 5798 §6.4.2 preemption: a BACKUP preempts
// only on a STRICTLY higher priority than the currently-observed master. It
// returns true iff:
//
//   - preempt is effective — either configured, OR this instance is the IP
//     address owner (priority 255), which always preempts irrespective of the
//     no-preempt flag (RFC 5798 §6.1, #4116). A non-owner non-preempting node
//     never preempts on the shortcut, AND
//   - either no live master has been observed recently (lastMasterSeen is zero
//     or older than masterDownInterval — the cold-start / peer-down /
//     silent-master-death rescue, where becoming MASTER is correct), OR a
//     recent master was observed AND our effective priority is strictly greater
//     than its last advertised priority.
//
// Equal priority returns false (RFC 5798 §6.4.2 — an equal-priority BACKUP does
// not preempt; the address tie-break in handleMasterRx resolves a MASTER-MASTER
// collision, a different state than preemption). The ForceRGMaster path
// (force=true) is gated OUTSIDE this helper (the run-loop short-circuits it),
// so cluster-authoritative promotion is unaffected.
//
// Lock discipline (BINDING — Go's sync.RWMutex is non-reentrant): this helper
// snapshots everything it needs under ONE vi.mu.RLock(), releases, then
// computes the effective priority and the staleness horizon from the locals.
// It MUST NOT call getPriority()/getPreempt()/masterDownInterval() (each of
// which RLocks vi.mu) while holding the lock. RLock (not Lock) is used so it
// never blocks concurrent external readers such as Status().
func (vi *vrrpInstance) shouldPreemptObservedMaster() bool {
	vi.mu.RLock()
	preempt := vi.cfg.Preempt
	priority := vi.cfg.Priority
	trackDown := vi.trackDown
	trackIface := vi.cfg.TrackInterface
	trackCost := vi.cfg.TrackPriorityCost
	advertMS := vi.cfg.AdvertiseInterval
	masterAdver := vi.masterAdverInterval
	lastMasterPriority := vi.lastMasterPriority
	lastMasterSeen := vi.lastMasterSeen
	vi.mu.RUnlock()

	// The IP address owner (priority 255) always preempts, irrespective of the
	// no-preempt flag or a sync-hold suppression of cfg.Preempt (RFC 5798 §6.1,
	// #4116) — mirrors getPreempt(). This is a no-op for every non-owner
	// instance, so the cluster RETH sync-hold gate (#2082) is unchanged.
	if !preempt && priority != addressOwnerPriority {
		return false
	}

	// Effective advertised priority — replicates getPriority() (track.go)
	// from the snapshot: priority 0/255 pass through unchanged; otherwise
	// while the tracked link is down, TrackPriorityCost is subtracted and
	// clamped to [1, 254].
	effective := priority
	if priority != 0 && priority != 255 && trackDown && trackIface != "" {
		effective -= trackCost
		if effective < 1 {
			effective = 1
		} else if effective > 254 {
			effective = 254
		}
	}

	// masterDownInterval staleness horizon — replicates masterDownInterval()
	// (3*advert + skew) from the snapshot using the effective priority AND the
	// master's LEARNED advertised interval (RFC 5798 §6.1/§6.4.2), so the
	// "is the observed master still live" horizon matches the master's cadence,
	// not the local config, exactly as masterDownInterval() now does.
	advert := effectiveAdvertInterval(advertMS, masterAdver)
	skew := time.Duration(256-effective) * advert / 256
	masterDown := 3*advert + skew

	// No live master observed (cold-start) or the last advert is older than
	// the master-down horizon (silent death / peer-down) → no master to
	// respect, becoming MASTER is correct.
	if lastMasterSeen.IsZero() || time.Since(lastMasterSeen) > masterDown {
		return true
	}

	// A live master was observed — preempt only on STRICTLY higher priority.
	return effective > lastMasterPriority
}

func (vi *vrrpInstance) getState() VRRPState {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.state
}

func (vi *vrrpInstance) setState(s VRRPState) {
	vi.mu.Lock()
	changed := vi.state != s
	vi.state = s
	vi.mu.Unlock()
	// A real state change starts a new ownership tenure. Bump the generation
	// so any in-flight VIP actuation (becomeMaster/ReconcileVIPs) that captured
	// the prior generation revalidates as stale and rolls back instead of
	// advertising/GARPing for a tenure we have left (#5082). ownerGen is atomic
	// and independent of vi.mu, so a concurrent ReconcileVIPs holding vipMu
	// still observes this bump when it rechecks after its netlink add.
	if changed {
		vi.ownerGen.Add(1)
	}
}

// advertInterval returns the advertisement interval as a Duration.
// AdvertiseInterval is in milliseconds. The cfg field is snapshotted under
// vi.mu.RLock() — mirroring the other config accessors (masterDownInterval,
// preemptHoldDuration) — so a concurrent locked config update cannot race the
// read that go test -race would otherwise flag (#6230). The lock is released
// before the Duration math, matching the masterDownInterval idiom.
//
// Callers that ALREADY hold vi.mu (masterAdverFloor, reached from
// recordMasterAdvert under vi.mu.Lock) MUST use advertIntervalLocked instead:
// re-taking the RLock while the write lock is held would deadlock.
func (vi *vrrpInstance) advertInterval() time.Duration {
	vi.mu.RLock()
	ms := vi.cfg.AdvertiseInterval
	vi.mu.RUnlock()
	return advertIntervalFromMS(ms)
}

// advertIntervalLocked returns the advertisement interval as a Duration for
// callers that already hold vi.mu (read or write). It performs the same read as
// advertInterval WITHOUT taking the lock, for paths that run under vi.mu.Lock
// (recordMasterAdvert → masterAdverFloor); calling advertInterval there would
// deadlock on the RLock (#6230).
func (vi *vrrpInstance) advertIntervalLocked() time.Duration {
	return advertIntervalFromMS(vi.cfg.AdvertiseInterval)
}

// advertIntervalFromMS converts a configured advertise interval in
// milliseconds (0 or negative → the 1000 ms default) to a Duration.
func advertIntervalFromMS(ms int) time.Duration {
	if ms <= 0 {
		ms = 1000
	}
	return time.Duration(ms) * time.Millisecond
}

// effectiveAdvertInterval picks the advertisement interval that drives the
// Master_Down_Interval / Skew_Time computation. Per RFC 5798 §6.1/§6.4.2 a
// BACKUP times the master out on the interval the MASTER advertises
// (Master_Adver_Interval, learned from the received advert's Max Adver Int),
// falling back to the locally-configured interval only before any advert has
// been heard (cold-start). localMS is cfg.AdvertiseInterval in milliseconds;
// learned is the last value recorded by recordMasterAdvert (0 = none yet).
func effectiveAdvertInterval(localMS int, learned time.Duration) time.Duration {
	if learned > 0 {
		return learned
	}
	if localMS <= 0 {
		return 1000 * time.Millisecond
	}
	return time.Duration(localMS) * time.Millisecond
}

// masterDownInterval returns the master-down timer value.
// Per RFC 5798: Master_Down_Interval = (3 * Master_Adver_Interval) + Skew_Time
// Skew_Time = ((256 - priority) * Master_Adver_Interval) / 256
//
// Master_Adver_Interval is the interval ADVERTISED BY THE CURRENT MASTER
// (learned from the received advert's Max Adver Int, §6.4.2), NOT this node's
// own configured AdvertiseInterval. Before any advert has been heard
// (masterAdverInterval == 0) the local interval is the fallback. The local
// priority is used for Skew_Time (RFC 5798 §6.1).
func (vi *vrrpInstance) masterDownInterval() time.Duration {
	vi.mu.RLock()
	localMS := vi.cfg.AdvertiseInterval
	learned := vi.masterAdverInterval
	vi.mu.RUnlock()
	advert := effectiveAdvertInterval(localMS, learned)
	skew := time.Duration(256-vi.getPriority()) * advert / 256
	return 3*advert + skew
}

// preemptHoldDuration returns the configured preempt hold-time as a Duration,
// or 0 when no hold-time is configured (immediate preemption — today's
// behavior). cfg.PreemptHoldTime is in seconds (Junos `preempt hold-time`).
func (vi *vrrpInstance) preemptHoldDuration() time.Duration {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	if vi.cfg.PreemptHoldTime <= 0 {
		return 0
	}
	return time.Duration(vi.cfg.PreemptHoldTime) * time.Second
}

// preemptingLiveLowerMaster reports whether the masterDownTimer expiry that is
// firing right now represents PREEMPTION of a still-live lower-priority master
// (as opposed to takeover of a dead/silent master). It returns true iff a
// non-zero-priority master advert was observed within the master-down horizon
// AND its last advertised priority is strictly below our effective priority.
//
// This is the ONLY case the preempt hold-time delays (#2850): RFC 5798 / Junos
// `preempt hold-time` defers a higher-priority node reclaiming mastership from
// a working lower-priority master until routing converges. A genuinely dead
// master (no recent advert) is NOT delayed — there is nothing forwarding to
// blackhole, so takeover stays immediate.
//
// Reuses the same lastMaster* snapshot + effective-priority + master-down
// staleness math as shouldPreemptObservedMaster (#2082); kept as a sibling so
// the two preempt paths agree on what "a live lower master" means.
func (vi *vrrpInstance) preemptingLiveLowerMaster() bool {
	vi.mu.RLock()
	priority := vi.cfg.Priority
	trackDown := vi.trackDown
	trackIface := vi.cfg.TrackInterface
	trackCost := vi.cfg.TrackPriorityCost
	advertMS := vi.cfg.AdvertiseInterval
	masterAdver := vi.masterAdverInterval
	lastMasterPriority := vi.lastMasterPriority
	lastMasterSeen := vi.lastMasterSeen
	vi.mu.RUnlock()

	effective := priority
	if priority != 0 && priority != 255 && trackDown && trackIface != "" {
		effective -= trackCost
		if effective < 1 {
			effective = 1
		} else if effective > 254 {
			effective = 254
		}
	}

	// Master-down staleness horizon from the master's LEARNED interval (RFC
	// 5798 §6.1/§6.4.2), matching masterDownInterval(); falls back to the local
	// interval before any advert is heard.
	advert := effectiveAdvertInterval(advertMS, masterAdver)
	skew := time.Duration(256-effective) * advert / 256
	masterDown := 3*advert + skew

	// No recent live master → this is a dead-master takeover, not preemption.
	if lastMasterSeen.IsZero() || time.Since(lastMasterSeen) > masterDown {
		return false
	}
	// A live master was observed — only its STRICTLY lower priority is a
	// preemption we should hold.
	return effective > lastMasterPriority
}

// heldMasterIsStale reports whether the lower-priority master that an armed
// preempt hold-time (#2850) is currently deferring to has gone SILENT — its
// last advert is older than the master-down horizon (or none was ever seen).
// It is the #4584 liveness-watchdog predicate: while the hold is armed the
// masterDownTimer is repurposed as a watchdog (armPreemptHold), and on its fire
// a stale held master means the VIP-owning master DIED mid-hold and must be
// taken over immediately (dead master → immediate takeover), whereas a
// still-live master (recent advert, lastMasterSeen fresh) keeps deferring to
// the natural hold expiry.
//
// Unlike preemptingLiveLowerMaster/shouldPreemptObservedMaster this checks ONLY
// staleness, deliberately NOT the effective>lastMasterPriority comparison: a
// track-interface demotion that drops us below a STILL-LIVE master must NOT
// trigger a watchdog takeover (that live master is still forwarding). The
// natural hold-expiry re-validation (shouldPreemptObservedMaster, #2900) owns
// the demotion case. Uses the same master-down staleness horizon (3*advert +
// skew on the master's learned interval) as the sibling preempt helpers so all
// agree on what "silent" means.
//
// Lock discipline mirrors shouldPreemptObservedMaster: snapshot under ONE
// RLock, then compute from the locals (never call an RLocking accessor while
// holding the lock).
func (vi *vrrpInstance) heldMasterIsStale() bool {
	vi.mu.RLock()
	priority := vi.cfg.Priority
	trackDown := vi.trackDown
	trackIface := vi.cfg.TrackInterface
	trackCost := vi.cfg.TrackPriorityCost
	advertMS := vi.cfg.AdvertiseInterval
	masterAdver := vi.masterAdverInterval
	lastMasterSeen := vi.lastMasterSeen
	vi.mu.RUnlock()

	effective := priority
	if priority != 0 && priority != 255 && trackDown && trackIface != "" {
		effective -= trackCost
		if effective < 1 {
			effective = 1
		} else if effective > 254 {
			effective = 254
		}
	}

	advert := effectiveAdvertInterval(advertMS, masterAdver)
	skew := time.Duration(256-effective) * advert / 256
	masterDown := 3*advert + skew

	return lastMasterSeen.IsZero() || time.Since(lastMasterSeen) > masterDown
}

// stopAndDrainTimer stops t and drains a pending fire from its channel so a
// subsequent Reset arms a clean interval. Safe on an already-stopped or
// already-drained timer.
func stopAndDrainTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

// armPreemptHold (re)arms the preempt hold-time countdown (#2850) for `hold`
// and records that it is running (#2900). Called only from the run-loop
// goroutine; the preemptHoldArmed flag is mu-guarded for external readers.
//
// It ALSO (re)arms masterDownTimer for masterDownInterval as a liveness
// watchdog (#4584). Without this the masterDownTimer would sit IDLE for the
// entire hold: it already fired to reach this arming point, and handleBackupRx
// never resets it for a persisting lower-priority advert. A held (VIP-owning)
// lower-priority master that DIES mid-hold would then go undetected until the
// (possibly very long) hold-time elapsed — up to ~holdTime of VIP blackhole for
// a dead master, violating the "dead master → immediate takeover" invariant.
// stepBackup's masterDownTimer.C case treats a fire while preemptHoldArmed as
// this watchdog: a stale held master triggers immediate takeover, a still-live
// one re-arms the watchdog and defers to the natural hold expiry.
func (vi *vrrpInstance) armPreemptHold(masterDownTimer, preemptHoldTimer *time.Timer, hold time.Duration) {
	stopAndDrainTimer(preemptHoldTimer)
	preemptHoldTimer.Reset(hold)
	stopAndDrainTimer(masterDownTimer)
	masterDownTimer.Reset(vi.masterDownInterval())
	vi.mu.Lock()
	vi.preemptHoldArmed = true
	vi.mu.Unlock()
}

// disarmPreemptHold stops a (possibly) armed preempt hold-time countdown and
// clears the armed flag (#2900). Safe on an already-stopped timer. Called only
// from the run-loop goroutine.
func (vi *vrrpInstance) disarmPreemptHold(preemptHoldTimer *time.Timer) {
	stopAndDrainTimer(preemptHoldTimer)
	vi.mu.Lock()
	vi.preemptHoldArmed = false
	vi.mu.Unlock()
}

// stepBackup runs one iteration of the StateBackup select. It is called by the
// run loop AND directly by unit tests (the run() preamble unconditionally
// spawns a receiver goroutine that nil-derefs vi.conn on a test instance, so
// tests must not call run() — they drive this seam instead). It returns true
// when the instance has been told to stop (the caller's run loop should
// return).
//
// preemptHoldTimer carries the optional `preempt hold-time` delay (#2850): when
// the masterDownTimer fires while a live lower-priority master is still
// present and a hold-time is configured, the promotion is deferred by arming
// preemptHoldTimer instead of becoming MASTER immediately. handleBackupRx
// cancels the armed hold if a >= -priority master returns.
//
// While the hold is armed, armPreemptHold ALSO keeps masterDownTimer running as
// a liveness watchdog (#4584): a fire while preemptHoldArmed means the held
// master may have gone silent. The masterDownTimer.C case checks
// heldMasterIsStale() — a stale (dead) held master triggers immediate takeover,
// a still-live one re-arms the watchdog and lets the hold run to natural
// expiry — so a held VIP-owning master that dies mid-hold no longer blackholes
// for the full hold-time.
func (vi *vrrpInstance) stepBackup(masterDownTimer, advertTimer, preemptHoldTimer *time.Timer) (stop bool) {
	select {
	case <-vi.stopCh:
		return true
	case pkt := <-vi.rxCh:
		vi.handleBackupRx(pkt, masterDownTimer, preemptHoldTimer)
	case <-masterDownTimer.C:
		// If a preempt hold-time is currently armed, this masterDownTimer fire
		// is the #4584 liveness watchdog, NOT a fresh master-down. armPreemptHold
		// re-armed the timer so a held VIP-owning lower-priority master that DIES
		// mid-hold is detected within one master-down horizon instead of only
		// when the (possibly long) hold-time elapses.
		vi.mu.RLock()
		holdArmed := vi.preemptHoldArmed
		vi.mu.RUnlock()
		if holdArmed {
			if vi.heldMasterIsStale() {
				// The held lower-priority master went SILENT (died) during the
				// hold — nothing is forwarding, so restore the "dead master →
				// immediate takeover" invariant: disarm the hold and become
				// MASTER now instead of blackholing the VIP until the hold
				// expires.
				slog.Info("vrrp: held master silent during preempt hold-time, immediate takeover",
					"key", vi.key())
				vi.disarmPreemptHold(preemptHoldTimer)
				if vi.becomeMaster() {
					advertTimer.Reset(vi.advertInterval())
				} else {
					vi.rearmForRetry(masterDownTimer)
				}
			} else {
				// The held master is still alive (adverts keep arriving and
				// refreshing lastMasterSeen). Preserve the preempt-hold intent:
				// re-arm the watchdog and let the hold run to its natural expiry.
				stopAndDrainTimer(masterDownTimer)
				masterDownTimer.Reset(vi.masterDownInterval())
			}
			return false
		}
		// Master timed out. If this is preemption of a still-live
		// lower-priority master AND a preempt hold-time is configured,
		// defer the takeover by arming the hold timer rather than
		// becoming MASTER now (#2850). Otherwise (no hold-time, the
		// master is genuinely gone, or the one-shot resign bypass is
		// set) become MASTER immediately — today's behavior, unchanged.
		vi.mu.Lock()
		skipHold := vi.skipNextPreemptHold
		vi.skipNextPreemptHold = false
		vi.mu.Unlock()
		if hold := vi.preemptHoldDuration(); !skipHold && hold > 0 && vi.preemptingLiveLowerMaster() {
			slog.Info("vrrp: preempt deferred by hold-time",
				"key", vi.key(), "hold", hold)
			vi.armPreemptHold(masterDownTimer, preemptHoldTimer, hold)
			return false
		}
		if vi.becomeMaster() {
			advertTimer.Reset(vi.advertInterval())
		} else {
			vi.rearmForRetry(masterDownTimer)
		}
	case <-preemptHoldTimer.C:
		// The preempt hold-time elapsed (#2850). The hold is no longer
		// armed; clear the flag before deciding (#2900).
		vi.mu.Lock()
		vi.preemptHoldArmed = false
		vi.mu.Unlock()
		// RE-VALIDATE before taking over (#2900). A >= -priority master
		// returning during the hold would have re-armed masterDownTimer and
		// stopped this timer (handleBackupRx), but two state changes during
		// the hold window are NOT seen on the wire and so do not cancel it:
		// preempt being disabled, or our effective priority being demoted
		// below the live master by a track-interface link-down. Re-running
		// the same gate the force/sync-hold path uses
		// (shouldPreemptObservedMaster) honours both: preempt must still be
		// enabled AND, when a live master is still present, our effective
		// priority must be strictly higher than its last advert (RFC 5798
		// §6.4.2). A master that went silent during the hold reads as stale
		// (beyond the master-down horizon) and the gate returns true, so a
		// genuine dead-master takeover is still immediate.
		if vi.shouldPreemptObservedMaster() {
			slog.Info("vrrp: preempt hold-time elapsed, taking over",
				"key", vi.key())
			if vi.becomeMaster() {
				advertTimer.Reset(vi.advertInterval())
				masterDownTimer.Stop()
			} else {
				vi.rearmForRetry(masterDownTimer)
			}
		} else {
			// Preemption is no longer warranted — do NOT become MASTER.
			// Return to a normal BACKUP tenure by re-arming masterDownTimer
			// so a later silent-master death still triggers takeover. A
			// still-present live master's adverts will keep resetting it
			// (handleBackupRx), so we stay BACKUP as long as it forwards.
			slog.Info("vrrp: preempt hold-time elapsed but preemption no longer valid, staying BACKUP",
				"key", vi.key())
			stopAndDrainTimer(masterDownTimer)
			masterDownTimer.Reset(vi.masterDownInterval())
		}
	case <-vi.resignCh:
		// #6177 item 1: a forced resignation arrived while this instance is
		// ALREADY BACKUP — a cluster demotion for an RG whose VRRP tenure had
		// already ended (peer preempted us, a link-down demotion landed first,
		// a reconcile-driven re-resign). There is no MASTER tenure to tear
		// down, so nothing more will remove VIPs on our behalf and the token
		// would otherwise sit unread in resignCh forever, stalling the fence
		// barrier until its timeout and downgrading a clean failover to a hold.
		//
		// Consume it here and report the honest verdict: a clean release
		// unless a PREVIOUS removal failed and its #5482 reconcile has not yet
		// cleared the address, in which case a VIP may still be answering ARP
		// and this is not a two-owner-safe resignation.
		vi.notifyResigned(vi.staleVIPResignErr())
	case <-vi.configUpdatedCh:
		// A config update landed (updateConfig) while this BACKUP select was
		// running (#2900). If a preempt hold-time is armed, the new config may
		// have invalidated its premise — preempt disabled, priority demoted so
		// we no longer outrank the live master, or a changed hold-time. The
		// simplest correct response is to tear the in-flight hold down and
		// re-arm masterDownTimer: the next expiry re-evaluates against the
		// fresh config (preemptingLiveLowerMaster + the current hold-time) and
		// either re-arms the hold with the NEW duration, takes over, or stays
		// BACKUP. This never silently keeps a stale duration or a stale
		// preempt decision.
		vi.mu.RLock()
		armed := vi.preemptHoldArmed
		vi.mu.RUnlock()
		if armed {
			slog.Info("vrrp: config update during preempt hold — re-validating",
				"key", vi.key())
			vi.disarmPreemptHold(preemptHoldTimer)
			stopAndDrainTimer(masterDownTimer)
			masterDownTimer.Reset(vi.masterDownInterval())
		}
	case <-vi.preemptNowCh:
		// Coordinated preemption from ReleaseSyncHold or forced transition
		// from ForceRGMaster. The forcePreemptOnce flag allows a one-shot
		// preemption even when preempt=false, without leaking into the
		// configured preempt value.
		//
		// force=true (ForceRGMaster) is cluster-authoritative and bypasses
		// the peer-priority gate unconditionally. The non-force sync-hold
		// path is gated on shouldPreemptObservedMaster (#2082): a
		// lower-priority preempt-enabled node no longer transiently becomes
		// a second MASTER while a higher-priority peer is legitimately MASTER.
		vi.mu.Lock()
		force := vi.forcePreemptOnce
		vi.forcePreemptOnce = false
		vi.mu.Unlock()
		if force || vi.shouldPreemptObservedMaster() {
			if vi.becomeMaster() {
				advertTimer.Reset(vi.advertInterval())
				masterDownTimer.Stop()
				// A coordinated/forced promotion supersedes any pending
				// preempt hold-time countdown (#2850).
				vi.disarmPreemptHold(preemptHoldTimer)
			} else {
				vi.rearmForRetry(masterDownTimer)
			}
		}
	}
	return false
}

// run is the main state machine loop. Must be called as a goroutine.
func (vi *vrrpInstance) run() {
	defer close(vi.stopped)

	slog.Info("vrrp: instance starting",
		"key", vi.key(),
		"interface", vi.cfg.Interface,
		"vrid", vi.cfg.GroupID,
		"priority", vi.cfg.Priority,
		"preempt", vi.cfg.Preempt)

	// Start per-instance receiver goroutine.
	// AF_PACKET captures at the link layer before generic XDP, ensuring
	// reliable multicast reception on all interface types.
	if vi.afPacketFD >= 0 {
		go vi.receiverAfPacket()
	} else {
		// Start one raw receiver per configured family. A family-specific
		// generic instance must never feed the other family's adverts into its
		// state machine; an empty-family RETH instance has both sockets and keeps
		// the historical dual-stack behavior.
		if vi.rawConn != nil {
			go vi.receiver()
		}
		if vi.ipv6Conn != nil {
			slog.Warn("vrrp: af_packet unavailable, using separate IPv6 raw socket fallback",
				"key", vi.key())
			go vi.receiverIPv6()
		}
	}

	// Transition to Backup state.
	// Remove any stale VIPs that may be on the interface from a previous
	// daemon run or config apply. This ensures BACKUP nodes don't have VIPs.
	// setState precedes surfaceStaleVIP so the async reconcile's state guard sees
	// BACKUP; a swallowed removal failure here would start us as a BACKUP still
	// answering ARP for a stale VIP (#5482).
	staleErr := vi.removeVIPs()
	vi.setState(StateBackup)
	vi.surfaceStaleVIP(staleErr, "run-startup")
	vi.emitEvent()

	// Use an extended initial masterDown timer when preempt is disabled
	// (either from config or sync hold). With short RETH intervals (30ms),
	// the normal masterDown timer (~97ms) can fire before the AF_PACKET
	// receiver starts capturing peer adverts — causing the returning node
	// to erroneously become MASTER. A 3s initial timer gives enough time
	// for the receiver to initialize and for the cluster election to
	// determine our role. After the first received advert, handleBackupRx
	// resets the timer to the normal short interval.
	initialMasterDown := vi.masterDownInterval()
	if !vi.getPreempt() {
		initialMasterDown = 3 * time.Second
	}
	masterDownTimer := time.NewTimer(initialMasterDown)
	defer masterDownTimer.Stop()

	// Not used until we become Master.
	advertTimer := time.NewTimer(0)
	advertTimer.Stop()
	defer advertTimer.Stop()

	// Preempt hold-time timer (#2850): armed only when the masterDownTimer
	// fires while a live lower-priority master is present and a hold-time is
	// configured. Idle otherwise.
	preemptHoldTimer := time.NewTimer(0)
	preemptHoldTimer.Stop()
	stopAndDrainTimer(preemptHoldTimer)
	defer preemptHoldTimer.Stop()

	for {
		state := vi.getState()

		switch state {
		case StateBackup:
			if vi.stepBackup(masterDownTimer, advertTimer, preemptHoldTimer) {
				return
			}

		case StateMaster:
			select {
			case <-vi.stopCh:
				// Send burst of priority-0 advertisements to signal resignation.
				// Multiple adverts improve reliability if one is lost on the wire.
				for i := 0; i < 3; i++ {
					vi.sendAdvert(0)
				}
				// Best-effort at process exit: log a removal failure but do not
				// schedule a reconcile (stopCh is closed, the run-loop is ending).
				err := vi.removeVIPs()
				if err != nil {
					slog.Warn("vrrp: VIP removal failed during resignation shutdown",
						"key", vi.key(), "err", err)
				}
				// #6177: the run loop is ending, so this is the last VIP
				// release it will ever perform. Report it rather than
				// stranding a barrier armed just before the shutdown.
				vi.notifyResigned(err)
				return
			case pkt := <-vi.rxCh:
				vi.handleMasterRx(pkt, masterDownTimer, advertTimer)
			case <-advertTimer.C:
				vi.sendAdvert(vi.getPriority())
				advertTimer.Reset(vi.advertInterval())
			case <-vi.resignCh:
				// Forced resignation (manual failover / cluster Primary→Secondary).
				slog.Info("vrrp: forced resignation", "key", vi.key())
				for i := 0; i < 3; i++ {
					vi.sendAdvert(0)
				}
				vi.becomeBackup(masterDownTimer, advertTimer)
				// Use an extended safety-net timer instead of stopping entirely.
				// With short RETH intervals (30ms), masterDownInterval() at
				// priority 0 is only ~120ms, which re-elects the resigned node
				// before the peer can take over. We use 3× the normal
				// masterDownInterval to give the peer time to become MASTER
				// and start advertising, while still providing a recovery path
				// if the peer crashes without sending priority-0.
				//
				// Normal recovery paths (faster than the safety timer):
				//   - preemptNowCh (cluster ForceRGMaster after failover reset)
				//   - priority-0 from peer (peer resigning) → 1ms takeover
				//   - peer advert received → resets timer to masterDownInterval
				//
				// The safety timer only fires if the peer is completely gone
				// (crash without priority-0, network partition).
				safetyTimeout := 3 * vi.masterDownInterval()
				if safetyTimeout < 500*time.Millisecond {
					safetyTimeout = 500 * time.Millisecond
				}
				masterDownTimer.Reset(safetyTimeout)
			}
		}
	}
}

// recordMasterAdvert records a peer's last advertised priority for the
// sync-hold preempt gate (#2082). Priority-0 (resignation) adverts are NOT
// recorded — leaving a stale lastMasterPriority is safe because post-resign
// takeover flows through the ungated masterDownTimer path, not the gated
// preemptNowCh shortcut. Called from handleBackupRx/handleMasterRx, which run
// in the run-loop goroutine; mu only guards external readers.
func (vi *vrrpInstance) recordMasterAdvert(pkt *VRRPPacket) {
	if pkt.Priority == 0 {
		return
	}
	vi.mu.Lock()
	vi.lastMasterPriority = int(pkt.Priority)
	vi.lastMasterSeen = time.Now()
	// Adopt the master's advertised interval (RFC 5798 §6.1/§6.4.2
	// Master_Adver_Interval). Max Adver Int is centiseconds on the wire (10 ms
	// units); convert to a Duration. A zero/absent field is ignored so
	// masterDownInterval falls back to the local interval rather than computing
	// a zero (flapping) master-down timer from a malformed advert.
	if pkt.MaxAdvertInt > 0 {
		learned := time.Duration(pkt.MaxAdvertInt) * 10 * time.Millisecond
		// Clamp a pathologically-low learned interval up to a safe floor
		// (#4548). A BACKUP must never time its master out FASTER than its own
		// configured advertise cadence: a buggy or misconfigured peer that
		// advertises Max Adver Int=1 (10 ms) would otherwise collapse
		// masterDownInterval (and the preempt-gate staleness horizons) to
		// ~30 ms (3*10ms + skew) on a 30 ms RETH node and flap mastership on
		// ordinary jitter. The floor is the node's own configured advertise
		// interval; a SLOWER master (learned >= floor, the #4061
		// anti-premature-failover case) is adopted unchanged — only the low
		// side is clamped, so the 30 ms RETH fast-failover default is preserved
		// exactly (floor == 30 ms == learned → no change).
		if floor := vi.masterAdverFloor(); learned < floor {
			learned = floor
		}
		vi.masterAdverInterval = learned
	}
	vi.mu.Unlock()
}

// masterAdverFloor is the minimum interval a learned Master_Adver_Interval may
// take (#4548). It is the node's own configured advertise interval
// (cfg.AdvertiseInterval, defaulting to 1000 ms when unset — see advertInterval)
// with an absolute minLearnedMasterAdverInterval backstop. Its sole caller,
// recordMasterAdvert, already holds vi.mu.Lock, so it reads the interval via
// advertIntervalLocked — calling the RLock-taking advertInterval here would
// self-deadlock against the held write lock (#6230).
func (vi *vrrpInstance) masterAdverFloor() time.Duration {
	floor := vi.advertIntervalLocked()
	if floor < minLearnedMasterAdverInterval {
		floor = minLearnedMasterAdverInterval
	}
	return floor
}

// handleBackupRx processes a received advertisement while in Backup state.
//
// preemptHoldTimer is the optional `preempt hold-time` countdown (#2850). A
// resigning (priority-0) master or a returning >= -priority master cancels any
// in-flight hold: the first because takeover becomes immediate, the second
// because there is no longer a lower-priority master to preempt. A persisting
// lower-priority master leaves an armed hold running (this path intentionally
// does not reset masterDownTimer on a lower advert). recordMasterAdvert still
// refreshes lastMasterSeen from every non-zero advert, which is what keeps the
// #4584 masterDownTimer liveness watchdog (armed by armPreemptHold) reading the
// held master as alive; if the adverts stop, the watchdog observes the staleness
// and takes over.
func (vi *vrrpInstance) handleBackupRx(pkt *VRRPPacket, masterDownTimer, preemptHoldTimer *time.Timer) {
	vi.recordMasterAdvert(pkt)
	pri := vi.getPriority()
	if pkt.Priority == 0 {
		// Master is explicitly resigning — become Master immediately.
		// RFC 5798 says use skew timer, but with only 2 HA nodes there's
		// no contention risk, and immediate transition gives zero-delay
		// planned failover (systemctl stop on primary). A pending preempt
		// hold-time is irrelevant once the master has resigned: there is
		// no live master left to blackhole. Cancel any in-flight hold and
		// arm a one-shot bypass so the imminent 1ms masterDownTimer expiry
		// promotes immediately instead of re-arming the hold (#2850). The
		// last-seen master record is intentionally left untouched — the
		// #2082 recordMasterAdvert contract owns it.
		slog.Info("vrrp: peer resigned (priority 0), immediate takeover",
			"key", vi.key())
		vi.disarmPreemptHold(preemptHoldTimer)
		vi.mu.Lock()
		vi.skipNextPreemptHold = true
		vi.mu.Unlock()
		masterDownTimer.Reset(time.Millisecond)
		return
	}

	// If we don't preempt, or the incoming priority is >= ours, accept it:
	// reset the master-down timer and abort any pending preempt hold-time —
	// a worthy master is present, so there is nothing to preempt (#2850).
	// getPreempt() returns true for the IP address owner (priority 255)
	// irrespective of the no-preempt flag, so an owner hearing a LOWER-priority
	// advert does NOT reset the timer here — the timer expires and the owner
	// reclaims MASTER (RFC 5798 §6.1, #4116).
	// Also clear the one-shot resign bypass: it was armed by a prior
	// priority-0 resign to make the imminent 1ms masterDownTimer expiry
	// promote immediately, but a worthy master returning before that fire
	// supersedes the resign. Tying the bypass's lifetime to the same
	// condition that drains the hold prevents it leaking to a LATER
	// legitimate masterDownTimer expiry where it would wrongly skip the
	// hold once.
	if !vi.getPreempt() || int(pkt.Priority) >= pri {
		masterDownTimer.Reset(vi.masterDownInterval())
		vi.disarmPreemptHold(preemptHoldTimer)
		vi.mu.Lock()
		vi.skipNextPreemptHold = false
		vi.mu.Unlock()
	}
	// If preempt is true and incoming priority < ours, ignore — let the
	// master-down timer expire (and, if a hold is armed, let it run).
}

// handleMasterRx processes a received advertisement while in Master state.
// Per RFC 5798 §6.4.3: if priority is higher, step down. If equal,
// the node with the higher source IP stays Master (tie-breaking).
func (vi *vrrpInstance) handleMasterRx(pkt *VRRPPacket, masterDownTimer, advertTimer *time.Timer) {
	vi.recordMasterAdvert(pkt)
	pri := vi.getPriority()
	if pkt.Priority == 0 {
		// Peer resigning — send immediate advert and stay Master.
		vi.sendAdvert(pri)
		advertTimer.Reset(vi.advertInterval())
		return
	}

	pktPri := int(pkt.Priority)
	if pktPri > pri {
		// Higher priority — step down unconditionally.
		vi.becomeBackup(masterDownTimer, advertTimer)
	} else if pktPri == pri && pkt.SrcIP != nil {
		// Equal priority — RFC 5798 §6.4.3 tie-break: higher source IP wins.
		// The comparison is anchored to ONE address family so both nodes
		// decide off the SAME ordering (#4376) — see resolveEqualPriorityMaster.
		vi.resolveEqualPriorityMaster(pkt, masterDownTimer, advertTimer)
	}
	// Lower priority, or equal with our IP higher: stay Master.
}

// resolveEqualPriorityMaster runs the RFC 5798 §6.4.3 MASTER-MASTER tie-break
// for an equal-priority peer advert while we are MASTER.
//
// A single instance is genuinely dual-stack: CollectRethInstances puts all of a
// unit's v4+v6 addresses on ONE instance, and sendAdvert emits BOTH a v4 advert
// (from getLocalIP, the lowest primary v4) and a v6 advert (from getLocalIPv6,
// the link-local) from two UNRELATED sources. If the tie-break keyed off
// whichever family happened to arrive, two equal-priority nodes with DISAGREEING
// v4-vs-v6 orderings (A: higher-v4/lower-LL, B: lower-v4/higher-LL) would each
// step down on the other family's advert — both go BACKUP, both masterDown
// timers expire, both re-elect: permanent no-master oscillation (#4376).
//
// Fix: anchor the tie-break to ONE family so both nodes compare the SAME pair of
// addresses. A v4-bearing instance (dual-stack or v4-only, i.e. it advertises a
// v4 VIP) decides ONLY off v4 adverts and ignores the peer's v6-family advert;
// a v6-only instance decides off the link-local v6 advert. The classifier keys
// off the configured VIP families (immutable per instance), NOT the resolved
// local address, so a transient address flush cannot flip a dual-stack instance
// to the v6 ordering and reintroduce the split.
func (vi *vrrpInstance) resolveEqualPriorityMaster(pkt *VRRPPacket, masterDownTimer, advertTimer *time.Timer) {
	peerV4 := pkt.SrcIP.To4() != nil

	var localCmp, peerCmp net.IP
	if vi.hasIPv4VIP() {
		// v4-bearing: anchor on v4. Ignore the peer's v6-family advert — the
		// peer's v4 advert drives the symmetric decision on both nodes.
		if !peerV4 {
			return
		}
		localCmp, peerCmp = vi.getLocalIP().To4(), pkt.SrcIP.To4()
	} else {
		// v6-only: anchor on the link-local v6 address.
		if peerV4 {
			return
		}
		if lip6 := vi.getLocalIPv6(); lip6 != nil {
			localCmp = lip6.To16()
		}
		peerCmp = pkt.SrcIP.To16()
	}

	if localCmp == nil {
		// Unresolved local advert source: we cannot run the tie-break and must
		// NOT treat that as "we win" (#4376 secondary defect — the old code let
		// peerHigher stay false and stay MASTER by default). Yield to the
		// actively advertising equal-priority peer. This does NOT oscillate: a
		// node that cannot determine its own source address cannot put a valid
		// advert of this family on the wire (sendPacket errors), so the peer
		// never receives a same-family advert from it and only one side steps
		// down. The address re-resolves on the advert-send path and a healthy
		// node re-elects cleanly.
		slog.Info("vrrp: equal priority tie-break, local source unresolved — stepping down",
			"key", vi.key(), "peer_ip", pkt.SrcIP, "priority", vi.getPriority())
		vi.becomeBackup(masterDownTimer, advertTimer)
		return
	}

	if bytes.Compare(peerCmp, localCmp) > 0 {
		slog.Info("vrrp: equal priority tie-break, peer IP is higher — stepping down",
			"key", vi.key(), "our_ip", localCmp, "peer_ip", pkt.SrcIP,
			"priority", vi.getPriority())
		vi.becomeBackup(masterDownTimer, advertTimer)
	}
	// Peer lower/equal: stay Master.
}

// hasIPv4VIP reports whether this instance advertises at least one IPv4 virtual
// address (dual-stack or IPv4-only). It anchors the equal-priority MASTER-MASTER
// tie-break to the v4 family so both nodes decide off the same ordering (#4376).
// cfg.VirtualAddresses is immutable per instance (VIP changes rebuild the
// instance), so no lock is needed — same rationale as vipAddrSet.
func (vi *vrrpInstance) hasIPv4VIP() bool {
	hasIPv4, _ := vi.vipFamilies()
	return hasIPv4
}

// vipFamilies reports which IP families have at least one parseable virtual
// address. Instance VIPs are immutable after construction, so callers may use
// it without locking.
func (vi *vrrpInstance) vipFamilies() (hasIPv4, hasIPv6 bool) {
	for _, vip := range vi.cfg.VirtualAddresses {
		addr := vip
		if idx := strings.Index(addr, "/"); idx >= 0 {
			addr = addr[:idx]
		}
		if ip := net.ParseIP(addr); ip != nil {
			if ip.To4() != nil {
				hasIPv4 = true
			} else {
				hasIPv6 = true
			}
		}
	}
	return hasIPv4, hasIPv6
}

// becomeMaster transitions to Master state: add VIPs, and — only if the
// required VIP set actually actuated in the kernel — send advert, emit event,
// then send GARP/NA asynchronously. The critical path is addVIPs (kernel needs
// VIP addresses for bpf_fib_lookup) + sendAdvert (tells peer to step down).
// GARP only updates L2 switch/router MAC tables and runs in the background.
//
// Fail-closed ownership (#5082): a transient netlink failure must NOT let the
// peer and dependent services trust an owner that cannot receive VIP traffic.
// addVIPs now returns a structured result; if any required VIP failed to
// actuate (or a concurrent demotion superseded this tenure), becomeMaster rolls
// back any partial adds, reverts to BACKUP, and returns false WITHOUT
// advertising or emitting a MASTER event. The caller re-arms the master-down
// timer so the election retries on the next horizon. On the clean success path
// nothing is added versus before (the vipMu lock is uncontended), so the ~60ms
// failover timing is preserved.
//
// Returns true iff ownership was claimed (VIP set actuated and advert/event
// published).
func (vi *vrrpInstance) becomeMaster() bool {
	// #6779: refuse ownership we cannot advertise — #5082's "do not claim what
	// you cannot back" applied to the advert. Before setState/addVIPs so there
	// is nothing to roll back. Rationale + log-rate note: advert_capacity.go.
	if vi.advertCapacityErr != nil {
		slog.Debug("vrrp: cannot build a legal advertisement, not claiming ownership (fail-closed)",
			"key", vi.key(), "err", vi.advertCapacityErr)
		return false
	}
	pri := vi.getPriority()
	slog.Info("vrrp: transitioning to MASTER",
		"key", vi.key(), "priority", pri)
	vi.setState(StateMaster)
	gen := vi.ownerGen.Load()

	vi.vipMu.Lock()
	res := vi.addVIPsLocked()
	superseded := vi.ownerGen.Load() != gen
	if !res.ok() || superseded {
		// Fail-closed: the required VIP set did not actuate, or a newer
		// transition superseded this one while we were in netlink. Roll back
		// any partially-added VIPs, revert to a BACKUP tenure, and do NOT claim
		// ownership. Reverting to StateBackup (an existing state) integrates
		// with the run-loop's masterDownTimer retry — no parallel state system.
		// (superseded is captured before the setState bump below so the log
		// reflects the true reason, not the revert's own generation bump.)
		// Rollback is best-effort — a failure is reported by the fail-closed Error
		// log below (applied/failed lists) and we are already reverting to BACKUP,
		// so there is no control-flow decision to make on it.
		_ = vi.removeVIPsLocked(res.applied)
		vi.setState(StateBackup)
		vi.vipMu.Unlock()
		slog.Error("vrrp: VIP actuation failed, not claiming ownership (fail-closed)",
			"key", vi.key(), "failed", res.failed, "applied", res.applied,
			"link_err", res.linkErr, "superseded", superseded)
		// Publish the honest BACKUP state so dependent services never trust an
		// ownership we could not back.
		vi.emitEvent()
		return false
	}
	vi.vipMu.Unlock()

	vi.sendAdvert(pri)
	vi.emitEvent()
	vi.garpEpoch.Add(1)
	if !vi.suppressGARP.Load() {
		// Non-forced: a routine MASTER transition is rate-limited by the
		// 500ms dampener (the epoch dedup still guarantees one burst per
		// transition). Post-MAC-change reconcile uses the forced path.
		go vi.sendGARP(false)
	} else {
		slog.Info("vrrp: GARP suppressed (strict-vip-ownership)",
			"key", vi.key())
	}
	return true
}

// rearmForRetry re-arms the master-down timer after a failed Master promotion
// (VIP actuation failure in becomeMaster reverted us to BACKUP) so the election
// retries on the next master-down horizon instead of leaving the instance idle.
// Used by the run-loop's becomeMaster call sites (#5082).
func (vi *vrrpInstance) rearmForRetry(masterDownTimer *time.Timer) {
	stopAndDrainTimer(masterDownTimer)
	masterDownTimer.Reset(vi.masterDownInterval())
}

// becomeBackup transitions to Backup state: remove VIPs, reset timers.
//
// Verified BACKUP ownership (#5482): the BACKUP-side symmetry of the #5082
// fail-closed MASTER path. We ARE stepping down (a superior/equal master is
// taking over), so publishing BACKUP is the honest role — refusing to emit would
// risk split-brain. But the pre-#5482 code called the VOID removeVIPs and emitted
// BACKUP unconditionally, so a swallowed netlink removal failure left this
// now-BACKUP node still answering ARP for the VIP (duplicate-address hazard vs
// the new master). surfaceStaleVIP records the divergence loudly and schedules an
// async reconcile so the stale VIP clears without a silent hazard, while
// emitEvent still publishes the true BACKUP state.
func (vi *vrrpInstance) becomeBackup(masterDownTimer, advertTimer *time.Timer) {
	slog.Info("vrrp: transitioning to BACKUP",
		"key", vi.key())
	vi.setState(StateBackup)
	removeErr := vi.removeVIPs()
	vi.surfaceStaleVIP(removeErr, "becomeBackup")
	advertTimer.Stop()
	masterDownTimer.Reset(vi.masterDownInterval())
	// A MASTER stepping down to a worthy higher/tie-break master begins a
	// fresh BACKUP tenure with no pending resign decision — clear the
	// one-shot preempt-hold bypass so a stale flag from an earlier resign
	// cannot leak into the next masterDownTimer expiry (#2850).
	vi.mu.Lock()
	vi.skipNextPreemptHold = false
	vi.mu.Unlock()
	vi.emitEvent()
	// #6177 item 1: the VIPs are now physically off the interface (or
	// removeErr says why they are not). Report to every resign barrier armed
	// on this instance so a fenced remote failover releases its applied-ack on
	// VIP REMOVAL, not merely on "resignation signalled + priority 0". This is
	// the last statement in the function on purpose: a waiter that observes the
	// completion must not be able to observe it before the removal ran.
	vi.notifyResigned(removeErr)
}

// stop signals the instance goroutine to stop and waits for it to finish.
func (vi *vrrpInstance) stop() {
	close(vi.stopCh)

	// Close descriptors to unblock receiver syscalls, but keep the pointer/fd
	// fields stable for the retired instance's lifetime. The receiver goroutines
	// are not separately joined; clearing these fields would race receiver()'s
	// vi.conn and receiverAfPacket()'s vi.afPacketFD reads.
	vi.closeSocketDescriptors()
	<-vi.stopped
	// #6177: the run loop has exited. Anything armed after its final release
	// (or armed against an instance that was never MASTER) will never be
	// reported by the loop, so report it here rather than leaving the caller's
	// fence to burn its timeout. The instance is retired: it holds no VIP
	// tenure, so a clean verdict is honest unless a removal is known to have
	// failed and not been reconciled.
	vi.notifyResigned(vi.staleVIPResignErr())
}
