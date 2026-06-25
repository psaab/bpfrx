package routing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// errWGIncompatibleLinkRetained is returned by applyWireguardTunLocked
// ONLY when a same-name link of the WRONG type (a non-TUN: GRE/IPIP/TAP/
// dummy) is present and its replacement LinkDel failed — so a stale
// NON-WG kernel link remains under the WG name. Apply uses this sentinel
// (and only this one) to re-retain the name in ownedNames for non-WG
// removal-retry (#1919 r5/r6): every OTHER applyWireguardTunLocked error
// (transient lookup, failed create) either leaves no link or leaves a
// HEALTHY persistent WG link, which must stay untracked (#1432 S2a).
var errWGIncompatibleLinkRetained = errors.New("wireguard tun: stale incompatible link retained for retry")

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
	LinkSetNoMaster(netlink.Link) error
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
	RemoteAddr  string // underlay remote endpoint being probed
	SourceAddr  string // tunnel local endpoint IP bound for the probe (§5c)
	Interval    int    // probe interval in seconds
	MaxRetries  int    // failures before declaring down

	// #1918 hold-on-unknown bookkeeping. When the prober cannot perform a
	// probe (ProbeUnsupported), the loop holds the prior Up value and
	// reports the link liveness as unknown (KeepaliveUp == nil) rather
	// than tearing the link down for a self-inflicted reason.
	//   Unknown       — last tick could not probe (status renders "unknown").
	//   UnknownKind   — structural (hold indefinitely) vs transient.
	//   UnknownErrno  — human errno string for the escalated status.
	//   unknownStreak — consecutive unknown ticks; gates transient
	//                   escalation after MaxRetries consecutive ticks.
	//   warnedUnknown — one-shot guard for the structural slog.Warn.
	Unknown       bool
	UnknownKind   UnsupportedKind
	UnknownErrno  string
	unknownStreak int
	warnedUnknown bool

	// seq is the monotonic 16-bit ICMP echo sequence counter (§5a). Each
	// probe increments it; the reply must match Seq AND the per-probe
	// Data-nonce.
	seq int
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

	// Config identity at start time (#1884 A.7): the reconcile keeps an
	// unchanged runner alive across applies instead of restarting it
	// (which would reset probe state every commit).
	remote     string
	source     string // tunnel local endpoint IP probed-from (#1918 §5c)
	interval   int
	maxRetries int // normalized: <=0 config value stored as 3

	// linkGen is the per-tunnel generation token captured at start
	// (#1918 §6 Axis D, defense-in-depth). The runner reads it LOCK-FREE
	// (.Load()) before each netlink op and drops the action if it no
	// longer matches the manager's current generation — so a stale runner
	// cannot down/up a recreated link. The runner NEVER takes t.mu (AGY
	// r5 deadlock note: a tick blocked on t.mu while Apply blocks on the
	// drain would deadlock).
	linkGen  *atomic.Uint64
	startGen uint64
}

// matches reports whether the runner's identity equals the config's
// NORMALIZED keepalive parameters. KeepaliveRetry <= 0 normalizes to 3
// BEFORE comparison (#1884 r1 Codex F5: comparing a raw config 0
// against the stored default 3 would restart the runner every apply).
// The tunnel SOURCE is part of the identity (#1918 §5c): a source-only
// change must restart the runner so the probe binds the new endpoint.
func (r *keepaliveRunner) matches(tc *config.TunnelConfig) bool {
	retries := tc.KeepaliveRetry
	if retries <= 0 {
		retries = 3
	}
	return r.remote == tc.Destination &&
		r.source == tc.Source &&
		r.interval == tc.Keepalive &&
		r.maxRetries == retries
}

// TunnelStatus holds the status of a tunnel interface.
type TunnelStatus struct {
	Name        string
	Source      string
	Destination string
	State       string // "up" or "down"
	Addresses   []string
	// KeepaliveUp is tri-state (#1918): non-nil true/false when liveness is
	// KNOWN (probe succeeded/failed), and nil when EITHER no keepalive is
	// configured OR liveness is currently UNKNOWN (ProbeUnsupported —
	// hold-on-unknown). The two nil cases are distinguished by
	// KeepaliveInfo: "" → not configured; "unknown (...)" → configured but
	// liveness unknown.
	KeepaliveUp   *bool
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

	// prober performs the keepalive ICMP echo. nil → the production
	// icmpProber (lazily resolved by keepaliveProber). Tests inject a
	// deterministic fake (#1918).
	prober tunnelProber

	mu         sync.Mutex
	tunnels    []string                    // tunnels successfully applied this round (GetStatus source)
	keepalives map[string]*keepaliveRunner // tunnel name -> runner

	// linkGen is the per-tunnel monotonic generation counter (#1918 §6
	// Axis D, defense-in-depth recreate guard). The MAP structure is
	// mutated only under mu (by Apply, via bumpLinkGenLocked); the counter
	// values are *atomic.Uint64 so a keepalive runner can Load() them
	// lock-free at tick time without ever taking mu (AGY r5 deadlock
	// note). Apply bumps the counter on a tunnel link create/recreate so a
	// stale runner captured at the old generation drops its LinkSet*.
	linkGen map[string]*atomic.Uint64

	// Reconcile-in-place state (#1884). All lazily initialized by Apply.
	//
	// ownedNames: ALL non-WireGuard tunnel names from the LAST Apply's
	// DESIRED set (plus names whose removal LinkDel failed, retained for
	// retry). The removal diff and the adoption decision both key off
	// this — NOT off the success-tracked t.tunnels, whose
	// failure-continue paths can leave a live kernel link untracked.
	ownedNames map[string]bool
	// appliedAddrs: per tunnel, the address set this manager itself
	// ensured (successful adds + present-and-wanted + link-local whose
	// stale-delete failed). Gates stale LINK-LOCAL deletion: a
	// configured fe80 we applied is removable; the kernel's autoconf
	// fe80 is never touched.
	appliedAddrs map[string]map[string]bool
	// appliedRI: per tunnel, the routing-instance whose VRF this
	// manager successfully bound — or directly OBSERVED as the link's
	// master for a step-0a `routing-instances <ri> interface` list
	// bind. Invariant (#1884 r6-r8): a claim is only ever written from
	// a successful bind or a master observation, never an intent.
	// Unbind on config-wants-none is identity-gated against
	// vrf-<claim>.
	appliedRI map[string]string
	// wgConfigured: WireGuard tunnel names configured at the LAST Apply
	// (plus names whose address prune left residual tracked addresses,
	// retained for retry). NEVER feeds the LinkDel removal loop — WG
	// links persist (#1432 S2a). Drives the WG address-prune-on-removal
	// diff (#1919): a WG tunnel removed from config keeps its persistent
	// wgN link but has the kernel addresses this manager applied pruned
	// away, so they no longer route. The link-itself diff still excludes
	// WG (the link is kept); this set exists solely so removal can find
	// the now-absent WG name and reconcile its addresses to empty.
	wgConfigured map[string]bool
}

// ensureReconcileStateLocked lazily initializes the reconcile maps so
// directly-constructed managers (tests, façade) need no constructor
// changes. Caller MUST hold mu.
func (t *tunnelManager) ensureReconcileStateLocked() {
	if t.ownedNames == nil {
		t.ownedNames = map[string]bool{}
	}
	if t.appliedAddrs == nil {
		t.appliedAddrs = map[string]map[string]bool{}
	}
	if t.appliedRI == nil {
		t.appliedRI = map[string]string{}
	}
	if t.wgConfigured == nil {
		t.wgConfigured = map[string]bool{}
	}
	if t.keepalives == nil {
		t.keepalives = map[string]*keepaliveRunner{}
	}
	if t.linkGen == nil {
		t.linkGen = map[string]*atomic.Uint64{}
	}
}

// linkGenForLocked returns the (lazily created) generation counter for a
// tunnel name. Caller MUST hold mu.
func (t *tunnelManager) linkGenForLocked(name string) *atomic.Uint64 {
	g, ok := t.linkGen[name]
	if !ok {
		g = &atomic.Uint64{}
		t.linkGen[name] = g
	}
	return g
}

// bumpLinkGenLocked advances a tunnel's generation token. Called by
// Apply whenever it CREATES or RECREATES the kernel link for a tunnel,
// so any keepalive runner still holding the previous generation drops
// its netlink op (#1918 §6 Axis D defense-in-depth). Caller MUST hold
// mu.
func (t *tunnelManager) bumpLinkGenLocked(name string) {
	t.linkGenForLocked(name).Add(1)
}

// keepaliveProber resolves the prober used by keepalive goroutines: the
// injected test fake when set, else the production datagram-ICMP prober.
func (t *tunnelManager) keepaliveProber() tunnelProber {
	if t.prober != nil {
		return t.prober
	}
	return icmpProber{}
}

// Apply reconciles the kernel tunnel devices against the desired
// config WITHOUT the historical clear-all + delete-and-recreate
// (#1884): an untouched tunnel keeps its netdev (stable ifindex — no
// FRR route churn, no userspace-dp TUN-reader death per commit, see
// #1881), tunnels removed from config are deleted via a set-diff
// against the previous desired set, and a device is recreated only
// when the existing kernel link is genuinely incompatible. Keepalive
// probes (legacy non-anchor branch only) are reconciled by identity
// instead of being restarted every apply.
func (t *tunnelManager) Apply(tunnels []*config.TunnelConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensureReconcileStateLocked()

	desired := make(map[string]bool, len(tunnels))
	wgDesired := map[string]bool{}
	for _, tc := range tunnels {
		// WireGuard TUNs stay untracked/persistent (#1432 S2a, AGY
		// Hazard B) and are excluded from the removal diff.
		if tc.Mode == "wireguard" {
			wgDesired[tc.Name] = true
		} else {
			desired[tc.Name] = true
		}
	}

	// oldOwned is the ENTRY-TIME ownership snapshot — the adoption
	// authority for the per-tunnel loop below (#1884 r2 Codex F1: the
	// rewritten set would mark every desired tunnel "owned" and make
	// adoption unreachable). next starts as the desired set; removal
	// failures retain their names so the next Apply retries instead of
	// orphaning a live link (r2 Codex F5).
	oldOwned := t.ownedNames
	next := make(map[string]bool, len(desired))
	for name := range desired {
		next[name] = true
	}
	for name := range oldOwned {
		if desired[name] {
			continue
		}
		if wgDesired[name] {
			// Same-name non-WG→WG transition: this name is being (re)claimed
			// as a persistent WireGuard tunnel by the apply loop below. WG
			// links are intentionally untracked in ownedNames and must NEVER
			// be torn by the removal diff (#1432 S2a). Hand off WITHOUT
			// deleting the link AND WITHOUT retaining ownedNames — retaining
			// would leave the active WG link in ownedNames and let a later
			// Apply LinkDel it (Codex r3 inverse-handoff hole).
			//
			// PRESERVE appliedAddrs (Codex r4): applyWireguardTunLocked's
			// reconcile needs the applied set to gate LINK-LOCAL deletion —
			// a configured fe80 this manager applied as the anchor must be
			// deletable by the WG reconcile (it is absent from the new WG
			// desired set), not re-classified as foreign and leaked. This
			// mirrors the forward WG→non-WG handoff, which also keeps
			// appliedAddrs. Drop only appliedRI: the GRE/anchor VRF claim is
			// no longer valid (WG binds VRF directly, never via appliedRI).
			t.stopKeepaliveLocked(name)
			delete(t.appliedRI, name)
			continue
		}
		t.stopKeepaliveLocked(name)
		if link, err := t.ops.LinkByName(name); err == nil {
			if delErr := t.ops.LinkDel(link); delErr != nil {
				slog.Warn("failed to delete removed tunnel",
					"name", name, "err", delErr)
				next[name] = true // retain ownership; retry next apply
				continue
			}
			slog.Info("tunnel removed", "name", name)
		} else if !isLinkNotFound(err) {
			// Transient LinkByName error (EBUSY/netlink/timeout): we have
			// NOT proven the device gone and have NOT deleted it. Retain
			// ownership so the next Apply retries the LinkDel — dropping it
			// here would orphan a live link (and any stale addresses on it)
			// with no state left to clean it up. A genuine not-found falls
			// through to drop tracking. (#1919 r2 Codex: closes the
			// WG→non-WG-handoff + transient-removal leak chain; also hardens
			// the pre-existing GRE/anchor removal path against transient
			// lookup errors, mirroring the WG prune loop's isLinkNotFound
			// discipline below.)
			slog.Warn("failed to look up removed tunnel for deletion",
				"name", name, "err", err)
			next[name] = true
			continue
		}
		delete(t.appliedAddrs, name)
		delete(t.appliedRI, name)
	}
	t.ownedNames = next
	t.tunnels = nil // success-tracked (GetStatus); rebuilt below

	// WireGuard address-prune-on-removal diff (#1919). WG links persist
	// (#1432 S2a) and are deliberately excluded from `desired`/ownedNames
	// above, so the GRE removal loop never visits them and the per-tunnel
	// apply loop below only reconciles addresses for STILL-configured WG.
	// A WG tunnel removed from config therefore leaks the kernel addresses
	// this manager applied to its persistent wgN device. wgConfigured
	// records the WG names tracked at the last Apply; here we prune the
	// addresses of any that disappeared while KEEPING the link.
	// (wgDesired is computed once at the top of Apply.)
	oldWG := t.wgConfigured
	nextWG := make(map[string]bool, len(wgDesired))
	for name := range wgDesired {
		nextWG[name] = true
	}
	for name := range oldWG {
		if wgDesired[name] {
			continue // still configured as WG; reconciled by the apply loop below
		}
		if desired[name] {
			// Same-name WG→non-WG mode transition (e.g. wg0 reconfigured as
			// a GRE/anchor tunnel of the same name). The name is now owned by
			// the non-WG apply path, which reconciles its addresses itself
			// (reconcileLinkAddrsLocked deletes the stale WG addresses against
			// the new desired set). Running the WG prune here would race that
			// path and could delete the newly-configured non-WG address, or —
			// on a prune AddrDel retry — persist in nextWG and prune the
			// active tunnel on a later Apply (Codex r1 MAJOR). Hand ownership
			// to the non-WG path: drop from WG tracking, keep appliedAddrs so
			// the non-WG reconcile can still gate its link-locals correctly.
			continue
		}
		link, err := t.ops.LinkByName(name)
		if err != nil {
			if isLinkNotFound(err) {
				// Device genuinely gone (manual `ip link del`, or never
				// existed). Nothing to prune; drop tracking.
				delete(t.appliedAddrs, name)
			} else {
				// Transient lookup error (EBUSY/netlink/timeout): we cannot
				// conclude the device is clean. Retain the name AND its
				// tracked address set so the next Apply retries the prune —
				// dropping here would forget a still-leaked address forever
				// (#1919 r1 Codex/AGY MAJOR).
				slog.Warn("failed to look up wireguard tun for address prune",
					"name", name, "err", err)
				nextWG[name] = true
			}
			continue
		}
		failed, retry := t.pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])
		if retry {
			// Could not prove the device clean (an AddrDel failed, or
			// AddrList itself failed). Carry the residual set forward (it
			// gates link-local deletion next pass) and retry next Apply.
			t.appliedAddrs[name] = failed
			nextWG[name] = true
			continue
		}
		// Proven clean: drop tracking so the next Apply is a no-op for this
		// name (idempotent — it is in neither wgDesired nor nextWG).
		delete(t.appliedAddrs, name)
	}
	t.wgConfigured = nextWG

	for _, tc := range tunnels {
		// WireGuard TUNs are persistent (#1432 S2a, AGY Hazard B): never
		// delete-and-recreate on reload — that would flap wgN and destroy
		// its addresses + FRR routes every commit. applyWireguardTunLocked
		// reuses an existing wgN in place.
		if tc.Mode == "wireguard" {
			if err := t.applyWireguardTunLocked(tc); err != nil {
				slog.Warn("failed to apply wireguard tunnel",
					"name", tc.Name, "err", err)
				// Re-retain ownedNames ONLY when a stale NON-WG link remains
				// under this name (incompatible same-name link whose
				// replacement LinkDel failed — errWGIncompatibleLinkRetained).
				// The inverse-handoff guard above dropped the name from
				// ownedNames, and the WG prune path only touches addresses,
				// never the link, so without this the stale non-WG link would
				// be orphaned (Codex r5). A future Apply then retries the
				// non-WG cleanup (LinkDel on config-remove or WG re-replace).
				//
				// Do NOT re-retain on any OTHER error (transient lookup,
				// failed create): those either left no link or left a HEALTHY
				// persistent WG link, which must stay untracked — re-adding it
				// would let a later removal LinkDel the live wgN (#1432 S2a,
				// Codex r6 create-failure counterexample).
				if errors.Is(err, errWGIncompatibleLinkRetained) {
					t.ownedNames[tc.Name] = true
				}
			}
			continue
		}
		// Adoption = this manager did NOT own the name at the last
		// apply (daemon restart, wireguard→gre same-name flip, foreign
		// but compatible TUN). Decided from the entry-time snapshot for
		// BOTH the plain-reuse and the LinkAdd-EEXIST paths.
		adopting := !oldOwned[tc.Name]
		if tc.AnchorOnly {
			t.applyAnchorLocked(tc, adopting)
			continue
		}
		t.applyKernelTunnelLocked(tc)
	}

	return nil
}

// anchorReusable reports whether an existing link can serve as the
// userspace-dp TUN anchor in place (#1884 A.3): it must be a TUN (not
// TAP/dummy/gre), carry NO_PI (the Rust side opens IFF_TUN|IFF_NO_PI —
// userspace-dp/src/slowpath.rs; a PI-enabled foreign TUN would break
// attach where recreate heals it), and be persistent (a non-persistent
// TUN held alive only by a foreign fd would evaporate when that fd
// closes). Kernel readback reconstructs Mode/NO_PI/persist via
// IFLA_TUN_*; the obsolete ONE_QUEUE flag is not reported and not
// checked.
func anchorReusable(link netlink.Link) bool {
	tt, ok := link.(*netlink.Tuntap)
	if !ok || tt.Mode != netlink.TUNTAP_MODE_TUN {
		return false
	}
	if tt.Flags&netlink.TUNTAP_NO_PI == 0 {
		return false
	}
	return !tt.NonPersist
}

// applyAnchorLocked reconciles one AnchorOnly TUN device (the
// production userspace-dp path). Caller MUST hold mu.
func (t *tunnelManager) applyAnchorLocked(tc *config.TunnelConfig, adopting bool) {
	// A leftover keepalive runner (legacy→anchor mode change) must not
	// keep probing: anchors never run keepalives (probes LinkSetDown
	// the device on failure — a behavior the anchor path never had).
	t.stopKeepaliveLocked(tc.Name)

	var link netlink.Link
	created := false
	if existing, lookupErr := t.ops.LinkByName(tc.Name); lookupErr == nil {
		if anchorReusable(existing) {
			// Operate on the kernel-fetched link (real ifindex and
			// attributes), never a fresh ifindex-less struct (#1706).
			link = existing
			slog.Debug("tunnel anchor reused", "name", tc.Name)
		} else {
			slog.Info("replacing non-TUN tunnel anchor",
				"name", tc.Name, "type", existing.Type())
			if delErr := t.ops.LinkDel(existing); delErr != nil {
				slog.Warn("failed to replace tunnel anchor",
					"name", tc.Name, "err", delErr)
				return
			}
		}
	}
	if link == nil {
		anchor := &netlink.Tuntap{
			LinkAttrs:  netlink.LinkAttrs{Name: tc.Name},
			Mode:       netlink.TUNTAP_MODE_TUN,
			Flags:      netlink.TUNTAP_NO_PI | netlink.TUNTAP_ONE_QUEUE,
			Queues:     1,
			NonPersist: false,
		}
		if addErr := t.ops.LinkAdd(anchor); addErr != nil {
			// LinkAdd-EEXIST / transient-lookup race (#1706): exactly
			// ONE re-lookup; a compatible TUN is adopted via the
			// KERNEL-FETCHED link (its Fds is nil, so the
			// closeTuntapFiles below is skipped with it); anything else
			// fails this apply (no unbounded retry).
			existing, lkErr := t.ops.LinkByName(tc.Name)
			if lkErr != nil || !anchorReusable(existing) {
				slog.Warn("failed to create tunnel anchor",
					"name", tc.Name, "err", addErr)
				return
			}
			slog.Info("tunnel anchor already exists as TUN, reusing",
				"name", tc.Name)
			link = existing
		} else {
			closeTuntapFiles(anchor.Fds)
			link = anchor
			created = true
			if tc.MTU > 0 {
				// TUNSETIFF may ignore LinkAttrs.MTU (#1432 Codex r4
				// precedent), and the compiler MTU stage restores only
				// ZONED interfaces — set explicitly so a configured MTU
				// on an unzoned tunnel is live too (#1884 r2/r4).
				if mtuErr := t.ops.LinkSetMTU(link, tc.MTU); mtuErr != nil {
					slog.Warn("failed to set tunnel anchor mtu",
						"name", tc.Name, "mtu", tc.MTU, "err", mtuErr)
				}
			}
			slog.Info("tunnel anchor created", "name", tc.Name, "mode", "tun")
		}
	}
	if !created {
		t.reconcileAnchorMTULocked(tc, link, adopting)
	}
	t.finishTunnelLocked(tc, link, false, "tunnel anchor")
}

// reconcileAnchorMTULocked applies the #1884 MTU ownership rule to a
// reused/adopted anchor:
//   - tc.MTU > 0: the config value is reconciled on EVERY reuse. The
//     compiler stage restores MTU only through the zone interface
//     path, so an UNZONED tunnel's configured MTU has no other writer;
//     for zoned tunnels both writers derive the same value from the
//     same config and both guard with !=, so there is no fighting.
//   - tc.MTU == 0 && adopting: one-time normalization to the TUN
//     default 1500 — repairs the wireguard→gre same-name flip, where
//     the leftover WG device carries the reduced WG MTU that the
//     userspace snapshot would otherwise publish into tunnel
//     endpoints.
//   - tc.MTU == 0 && owned: never touched.
func (t *tunnelManager) reconcileAnchorMTULocked(tc *config.TunnelConfig, link netlink.Link, adopting bool) {
	want := 0
	switch {
	case tc.MTU > 0:
		want = tc.MTU
	case adopting:
		want = 1500
	default:
		return
	}
	if link.Attrs().MTU == want {
		return
	}
	if mtuErr := t.ops.LinkSetMTU(link, want); mtuErr != nil {
		slog.Warn("failed to set tunnel anchor mtu",
			"name", tc.Name, "mtu", want, "err", mtuErr)
		return
	}
	slog.Info("tunnel anchor mtu set", "name", tc.Name, "mtu", want)
}

// buildKernelTunnelLink constructs the desired netlink link for the
// legacy (non-anchor) kernel tunnel branch.
func buildKernelTunnelLink(tc *config.TunnelConfig, localIP, remoteIP net.IP, ttl uint8, isIPv6 bool) netlink.Link {
	switch tc.Mode {
	case "ipip":
		if isIPv6 {
			// IPIP over IPv6: use ip6tnl with IPPROTO_IPIP
			return &netlink.Ip6tnl{
				LinkAttrs: netlink.LinkAttrs{Name: tc.Name},
				Local:     localIP,
				Remote:    remoteIP,
				Ttl:       ttl,
				Proto:     4, // IPPROTO_IPIP
			}
		}
		return &netlink.Iptun{
			LinkAttrs: netlink.LinkAttrs{Name: tc.Name},
			Local:     localIP,
			Remote:    remoteIP,
			Ttl:       ttl,
		}
	default: // "gre" or ""
		// Gretun.Type() auto-detects IPv6 → returns "ip6gre"
		greLink := &netlink.Gretun{
			LinkAttrs: netlink.LinkAttrs{Name: tc.Name},
			Local:     localIP,
			Remote:    remoteIP,
			Ttl:       ttl,
		}
		if tc.Key > 0 {
			greLink.IKey = tc.Key
			greLink.OKey = tc.Key
		}
		return greLink
	}
}

// ipEqual is net.IP.Equal with nil-tolerance. The kernel returns
// 4-byte v4 slices while net.ParseIP yields 16-byte forms — never
// compare these bytewise.
func ipEqual(a, b net.IP) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(b)
}

// legacyTunnelMatches reports whether an existing kernel tunnel link
// already matches the desired one, comparing ONLY the config-driven
// attributes: concrete type + Type() string (catches v4↔v6 family
// flips — both "gre" and "ip6gre" deserialize to *Gretun with a
// family-derived Type()), endpoints, defaulted TTL, GRE keys, and the
// ip6tnl Proto. Kernel-populated or post-create-mutated fields (PMtu,
// Tos, flags, encap-limit — mutated by the `ip ... encaplimit none`
// exec) are deliberately NOT compared: a false "changed" verdict would
// silently restore the per-commit flap this code removes (#1884 A.6).
func legacyTunnelMatches(existing, desired netlink.Link) bool {
	switch d := desired.(type) {
	case *netlink.Gretun:
		e, ok := existing.(*netlink.Gretun)
		return ok && e.Type() == d.Type() &&
			ipEqual(e.Local, d.Local) && ipEqual(e.Remote, d.Remote) &&
			e.Ttl == d.Ttl && e.IKey == d.IKey && e.OKey == d.OKey
	case *netlink.Iptun:
		e, ok := existing.(*netlink.Iptun)
		return ok && ipEqual(e.Local, d.Local) &&
			ipEqual(e.Remote, d.Remote) && e.Ttl == d.Ttl
	case *netlink.Ip6tnl:
		e, ok := existing.(*netlink.Ip6tnl)
		return ok && ipEqual(e.Local, d.Local) &&
			ipEqual(e.Remote, d.Remote) && e.Ttl == d.Ttl &&
			e.Proto == d.Proto
	default:
		return false
	}
}

// applyKernelTunnelLocked reconciles one legacy (non-anchor) kernel
// GRE/IPIP tunnel device, reachable only via the standalone-CLI apply
// path (the daemon always sets AnchorOnly). Compare-then-decide:
// identical config-driven attrs reuse the device in place; any real
// change is a legitimate delete+recreate. Caller MUST hold mu.
func (t *tunnelManager) applyKernelTunnelLocked(tc *config.TunnelConfig) {
	localIP := net.ParseIP(tc.Source)
	remoteIP := net.ParseIP(tc.Destination)
	if localIP == nil || remoteIP == nil {
		slog.Warn("invalid tunnel endpoints",
			"name", tc.Name, "src", tc.Source, "dst", tc.Destination)
		return
	}

	ttl := tc.TTL
	if ttl == 0 {
		ttl = 64
	}
	isIPv6 := localIP.To4() == nil
	desired := buildKernelTunnelLink(tc, localIP, remoteIP, uint8(ttl), isIPv6)

	// #1918 §6 Axis D F7 — drain-before-recreate. Decide up front whether
	// this apply will recreate (delete + re-add) the kernel link. If so,
	// CANCEL + DRAIN any existing keepalive runner BEFORE the LinkDel /
	// LinkAdd, so no stale runner goroutine can be mid-LinkSet* while the
	// link is recreated and the kernel reuses its ifindex (the F7
	// counterexample). The drain is the real serializer; it already
	// existed inside startKeepalive but ran AFTER the recreate. After the
	// drain the old runner's goroutine has returned and cannot issue any
	// further LinkSet*. linkGen is the defense-in-depth backstop.
	//
	// A lookup error must be classified (Codex PR #1947 r1 HIGH): only a
	// genuine NOT-FOUND means "absent → create". Any OTHER lookup error
	// (EBUSY / transport hiccup) is TRANSIENT — it does NOT mean the link
	// is gone, so we must NOT drain the live keepalive runner and must NOT
	// fall through to a LinkAdd that would EEXIST. Abort and retry next
	// apply, exactly like a transient LinkDel failure below.
	willRecreate := false
	var existing netlink.Link
	e, lookupErr := t.ops.LinkByName(tc.Name)
	switch {
	case lookupErr == nil:
		existing = e
		willRecreate = !legacyTunnelMatches(e, desired)
	case isLinkNotFound(lookupErr):
		// Absent → the LinkAdd below is a (re)create.
		willRecreate = true
	default:
		// Transient lookup error: leave the runner and any live link
		// untouched; retry on the next apply.
		slog.Warn("tunnel lookup failed transiently; deferring apply",
			"name", tc.Name, "err", lookupErr)
		return
	}
	if willRecreate {
		// Drain the stale runner first; bump the generation so any runner
		// that somehow survives (future code paths) drops its netlink op.
		t.stopKeepaliveLocked(tc.Name)
		t.bumpLinkGenLocked(tc.Name)
	}

	var link netlink.Link
	created := false
	if existing != nil {
		if !willRecreate {
			link = existing // kernel-fetched, real ifindex (#1706)
			slog.Debug("tunnel reused", "name", tc.Name)
		} else {
			if delErr := t.ops.LinkDel(existing); delErr != nil {
				slog.Warn("failed to replace existing tunnel link",
					"name", tc.Name, "existing_type", existing.Type(), "err", delErr)
				// The recreate failed but the OLD link is still live. We
				// already drained its keepalive runner before the LinkDel
				// (F7 ordering). Restart it against the surviving link so a
				// transient LinkDel failure does not silently leave the
				// tunnel running with NO keepalive until the next successful
				// apply (Copilot PR #1947 r3). Safe because the link was NOT
				// recreated — the restarted runner captures the just-bumped
				// generation and probes the same device.
				if tc.Keepalive > 0 {
					t.startKeepalive(tc.Name, tc.Source, tc.Destination, tc.Keepalive, tc.KeepaliveRetry)
				}
				return
			}
			slog.Info("replaced tunnel link with changed parameters",
				"name", tc.Name, "existing_type", existing.Type())
		}
	}
	if link == nil {
		if addErr := t.ops.LinkAdd(desired); addErr != nil {
			slog.Warn("failed to create tunnel",
				"name", tc.Name, "mode", tc.Mode, "err", addErr)
			return
		}
		link = desired
		created = true

		// IPv6 GRE: disable encaplimit to avoid adding an IPv6
		// Destination Options extension header. Many transit networks
		// drop IPv6 packets with extension headers (RFC 7872). Runs
		// only on a real (re)create — it is a per-create device attr
		// and the 15s-bounded exec must not run per commit (#1884).
		if isIPv6 && (tc.Mode == "gre" || tc.Mode == "") {
			// Timeout-bounded (#1794/#1800): Apply runs under
			// applyConfigLocked's applySem (daemon_apply.go
			// ApplyTunnels), so a wedged `ip` would block every commit.
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			ipCmd := exec.CommandContext(ctx, "ip", "link", "set", tc.Name,
				"type", "ip6gre", "encaplimit", "none")
			// WaitDelay caps the post-SIGKILL pipe-drain window.
			ipCmd.WaitDelay = 5 * time.Second
			out, err := ipCmd.CombinedOutput()
			cancel()
			if err != nil {
				slog.Warn("failed to set tunnel encaplimit",
					"name", tc.Name, "err", err, "output", string(out))
			}
		}
		if tc.MTU > 0 {
			if mtuErr := t.ops.LinkSetMTU(link, tc.MTU); mtuErr != nil {
				slog.Warn("failed to set tunnel mtu",
					"name", tc.Name, "mtu", tc.MTU, "err", mtuErr)
			}
		}
		slog.Info("tunnel created", "name", tc.Name,
			"src", tc.Source, "dst", tc.Destination)
	} else if tc.MTU > 0 && link.Attrs().MTU != tc.MTU {
		// Config-owned MTU reconcile on reuse (#1884 r5). No
		// adoption-default normalization here: kernel GRE/IPIP devices
		// have protocol-specific default MTUs (1476/1462/...), not the
		// TUN 1500.
		if mtuErr := t.ops.LinkSetMTU(link, tc.MTU); mtuErr != nil {
			slog.Warn("failed to set tunnel mtu",
				"name", tc.Name, "mtu", tc.MTU, "err", mtuErr)
		}
	}

	// Keepalive reconcile (#1884 A.7, LEGACY BRANCH ONLY — anchors
	// never run probes). Identity-unchanged runners are retained so
	// probe state survives commits; the retained-and-DOWN case must
	// skip LinkSetUp below: keepaliveLoop's down-transition is gated
	// on state.Up==true, so re-upping the link here would strand it
	// admin UP forever while probes keep failing (r1 Codex F1 + AGY
	// converged trace).
	runner, hasRunner := t.keepalives[tc.Name]
	restartKA := tc.Keepalive > 0 && (!hasRunner || created || !runner.matches(tc))
	skipUp := false
	if tc.Keepalive > 0 && hasRunner && !restartKA {
		runner.state.mu.Lock()
		skipUp = !runner.state.Up
		runner.state.mu.Unlock()
	}

	t.finishTunnelLocked(tc, link, skipUp, "tunnel")

	if tc.Keepalive > 0 {
		if restartKA {
			// startKeepalive stops+drains any predecessor itself;
			// runs AFTER a recreate so the fresh runner probes the
			// new device. tc.Source is the bind endpoint (#1918 §5c).
			t.startKeepalive(tc.Name, tc.Source, tc.Destination, tc.Keepalive, tc.KeepaliveRetry)
		}
	} else if hasRunner {
		t.stopKeepaliveLocked(tc.Name)
	}
}

// finishTunnelLocked is the shared apply tail: admin-up (unless a
// retained keepalive runner holds the tunnel down), symmetric address
// reconciliation, VRF claim reconcile, and success tracking. Caller
// MUST hold mu; link is the kernel-fetched (or just-created) device.
func (t *tunnelManager) finishTunnelLocked(tc *config.TunnelConfig, link netlink.Link, skipUp bool, kind string) {
	if skipUp {
		slog.Debug("skipping link up: keepalive holds tunnel down",
			"name", tc.Name)
	} else if err := t.ops.LinkSetUp(link); err != nil {
		slog.Warn("failed to bring up "+kind, "name", tc.Name, "err", err)
	}
	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
		link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], kind)
	t.reconcileVRFClaimLocked(tc, link)
	t.tunnels = append(t.tunnels, tc.Name)
}

// reconcileLinkAddrsLocked symmetrically reconciles a link's addresses
// against the configured set: add configured-but-missing, delete
// present-but-unconfigured — EXCEPT link-local addresses, which are
// deleted only when this manager itself applied them (`applied`
// gate). The kernel's autoconf fe80 must never be deleted, while a
// CONFIGURED fe80 removed from config must not leak forever (#1884 r1
// Codex F2; extended to the WG branch in #1905). applied == nil (the
// first apply for a link this manager has not tracked yet — restart
// adoption) means no link-local deletion at all.
//
// Returns the new applied set: successful adds + present-and-wanted +
// link-local addresses whose stale-delete FAILED (kept tracked so the
// next apply retries — r2 Codex F4).
func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
	want := make(map[string]bool, len(addrs))
	for _, addrStr := range addrs {
		addr, parseErr := netlink.ParseAddr(addrStr)
		if parseErr != nil {
			slog.Warn("invalid "+kind+" address",
				"name", name, "addr", addrStr, "err", parseErr)
			continue
		}
		want[addr.IPNet.String()] = true
	}
	newApplied := make(map[string]bool, len(want))
	existing := map[string]bool{}
	list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL)
	if listErr != nil {
		// Cannot enumerate: we cannot classify present addresses this pass,
		// so we delete nothing AND must NOT lose link-local OWNERSHIP. A
		// configured fe80 we previously applied that is absent from `want`
		// (mid-removal) would otherwise fall to the AddrAdd branch below
		// (returns EEXIST in real netlink), leave newApplied empty, and so
		// be re-classified as foreign on the next pass — permanently leaking
		// it on a later WG removal prune (Codex #1919 r1 MAJOR). Carry the
		// prior applied link-locals forward so the gate stays correct.
		// Non-link-local ownership is not gated by `applied`, so it need not
		// be preserved here.
		slog.Warn("failed to list "+kind+" addresses for reconcile",
			"name", name, "err", listErr)
		for key := range applied {
			if addr, err := netlink.ParseAddr(key); err == nil &&
				addr.IP != nil && addr.IP.IsLinkLocalUnicast() {
				newApplied[key] = true
			}
		}
	}
	if listErr == nil {
		for i := range list {
			a := list[i]
			key := a.IPNet.String()
			existing[key] = true
			if want[key] {
				continue
			}
			if a.IP == nil {
				// Defensive: the pre-#1884 WG block only deleted
				// addresses with a non-nil IP; keep that byte-identical
				// (and never delete something we cannot classify).
				continue
			}
			if a.IP.IsLinkLocalUnicast() && (applied == nil || !applied[key]) {
				// Kernel-managed or foreign link-local: never delete.
				continue
			}
			if delErr := t.ops.AddrDel(link, &a); delErr != nil {
				slog.Warn("failed to remove stale "+kind+" address",
					"name", name, "addr", key, "err", delErr)
				if a.IP != nil && a.IP.IsLinkLocalUnicast() {
					newApplied[key] = true // retry next apply
				}
			} else {
				slog.Info("removed stale "+kind+" address",
					"name", name, "addr", key)
			}
		}
	}
	for _, addrStr := range addrs {
		addr, parseErr := netlink.ParseAddr(addrStr)
		if parseErr != nil {
			continue
		}
		key := addr.IPNet.String()
		if existing[key] {
			newApplied[key] = true
			continue
		}
		if addErr := t.ops.AddrAdd(link, addr); addErr != nil {
			if errors.Is(addErr, unix.EEXIST) {
				// The address is already present — idempotent success, not a
				// failure. This is the common outcome after an AddrList
				// enumeration failure above (we could not see it in
				// `existing`, so it fell through to this add). Track it as
				// applied and log at Debug to avoid misleading Warn noise
				// (Copilot PR #1950).
				newApplied[key] = true
				slog.Debug("'"+kind+"' address already present",
					"name", name, "addr", addrStr)
			} else {
				slog.Warn("failed to add "+kind+" address",
					"name", name, "addr", addrStr, "err", addErr)
			}
		} else {
			newApplied[key] = true
		}
	}
	return newApplied
}

// pruneAppliedAddrsLocked deletes the addresses on a WG link being pruned
// (config-removal of a persistent wgN, #1919), KEEPING the link itself
// (#1432 S2a invariant — never LinkDel a wgN here). It deletes every
// present non-link-local address (the manager owns the device's
// non-link-local address set, identical to reconcileLinkAddrsLocked's
// steady-state semantics) plus configured/applied link-locals; the
// kernel autoconf / foreign fe80 is never touched (same gate as
// reconcileLinkAddrsLocked at the link-local check).
//
// It returns (failed, retry):
//   - failed: addresses whose AddrDel FAILED, across ALL families. This
//     is carried forward as the new appliedAddrs[name] so the link-local
//     gate stays correct on the retry pass.
//   - retry:  true when the device could NOT be proven clean this pass —
//     either an AddrDel failed OR AddrList itself failed. AddrList failure
//     means we cannot enumerate, hence cannot conclude clean, so we retry
//     unconditionally even when the prior applied set was empty (#1919 r2
//     Codex MAJOR: an empty applied with a real stale address must still
//     retry). The caller retains the name in wgConfigured on retry, NOT on
//     len(failed)>0 — decoupling enumerate-failed from delete-failed.
//
// Distinct from reconcileLinkAddrsLocked (left untouched, frozen #1884
// contract): that function only records a FAILED non-link-local delete
// when the address is link-local, so its return cannot drive a
// non-link-local retry signal (#1919 r1 MAJOR). This helper records every
// family's failed delete.
//
// Caller MUST hold mu.
func (t *tunnelManager) pruneAppliedAddrsLocked(link netlink.Link, name string, applied map[string]bool) (map[string]bool, bool) {
	list, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		// Cannot enumerate ⇒ cannot conclude the device is clean. Keep the
		// existing tracked set (so the link-local gate stays correct next
		// pass) and signal retry unconditionally — even if applied is empty.
		slog.Warn("failed to list wireguard tun addresses for prune",
			"name", name, "err", err)
		return applied, true
	}
	failed := map[string]bool{}
	for i := range list {
		a := list[i]
		if a.IP == nil {
			continue // unclassifiable: never delete (parity with reconcile)
		}
		key := a.IPNet.String()
		if a.IP.IsLinkLocalUnicast() && (applied == nil || !applied[key]) {
			continue // kernel autoconf / foreign link-local: never delete
		}
		if delErr := t.ops.AddrDel(link, &a); delErr != nil {
			slog.Warn("failed to prune wireguard tun address",
				"name", name, "addr", key, "err", delErr)
			failed[key] = true // ALL families (the #1919 r1 MAJOR fix)
		} else {
			slog.Info("pruned wireguard tun address (removed from config)",
				"name", name, "addr", key)
		}
	}
	return failed, len(failed) > 0
}

// reconcileVRFClaimLocked runs the #1884 A.5 ordered claim procedure.
// The claim invariant (r6-r8): t.appliedRI[name] is only ever written
// from a SUCCESSFUL BindInterfaceToVRF or a direct observation of the
// link's master — never from intent — so the identity-gated unbind
// below can neither strand a master we own nor touch one we do not.
//
//  1. stanza RI nonempty: bind; on success claim = stanza RI (stanza
//     wins over a coexisting 0a list bind — today's effective apply
//     order); on failure fall through to observation.
//  2. stanza failed or empty, RIListMember nonempty: never unbind (0a
//     owns list binds — the VETO); claim transfers to the list RI only
//     when the observed master IS vrf-<RIListMember>, else the prior
//     claim is retained.
//  3. config wants no RI: identity-gated unbind of vrf-<claim>. Claim
//     clears on successful unbind / identity mismatch (master not
//     ours) / VRF device not-found (kernel already freed the slaves);
//     it is RETAINED on transient errors so the next apply retries.
//
// Caller MUST hold mu.
func (t *tunnelManager) reconcileVRFClaimLocked(tc *config.TunnelConfig, link netlink.Link) {
	name := tc.Name
	if tc.RoutingInstance != "" {
		if err := t.vrfBinder.BindInterfaceToVRF(name, tc.RoutingInstance); err != nil {
			slog.Warn("failed to bind tunnel to VRF",
				"name", name, "vrf", tc.RoutingInstance, "err", err)
			// r7/r8: a FAILED bind must not blind-write the claim (the
			// kernel may still carry the previous master, or a 0a list
			// bind). Observation may take the claim; else retain.
			t.observeListClaimLocked(tc, link)
			return
		}
		t.appliedRI[name] = tc.RoutingInstance
		return
	}
	if tc.RIListMember != "" {
		// Unbind VETO: a stanza→list move must never strip the 0a
		// bind (r4 convergent counterexample).
		t.observeListClaimLocked(tc, link)
		return
	}

	claim := t.appliedRI[name]
	if claim == "" {
		return
	}
	master := link.Attrs().MasterIndex
	if master == 0 {
		// Nothing is bound — whatever we once bound is already gone.
		delete(t.appliedRI, name)
		return
	}
	vrf, err := t.ops.LinkByName("vrf-" + claim)
	if err != nil {
		if isLinkNotFound(err) {
			// The VRF device is gone; deleting a master frees its
			// slaves, so the current master cannot be ours.
			delete(t.appliedRI, name)
			return
		}
		// Transient lookup error: retain the claim, retry next apply.
		return
	}
	if vrf.Attrs().Index != master {
		// Master is not the VRF we bound (someone else's bind).
		delete(t.appliedRI, name)
		return
	}
	if err := t.ops.LinkSetNoMaster(link); err != nil {
		slog.Warn("failed to unbind tunnel from VRF",
			"name", name, "vrf", claim, "err", err)
		return // retain claim; retry next apply
	}
	slog.Info("tunnel unbound from routing-instance",
		"name", name, "vrf", claim)
	delete(t.appliedRI, name)
}

// observeListClaimLocked transfers the appliedRI claim to the
// routing-instance list member ONLY when the link's current master is
// OBSERVED to be that RI's VRF device (#1884 r6/r8: a blind transfer
// after a failed 0a bind would record an RI the kernel never took and
// later strand the real master on a mismatch-clear). On any
// non-observation the previous nonempty claim is retained. Caller MUST
// hold mu.
func (t *tunnelManager) observeListClaimLocked(tc *config.TunnelConfig, link netlink.Link) {
	if tc.RIListMember == "" {
		return
	}
	master := link.Attrs().MasterIndex
	if master == 0 {
		return // 0a bind absent or failed: no observation, retain prior
	}
	vrf, err := t.ops.LinkByName("vrf-" + tc.RIListMember)
	if err != nil {
		return // retain prior claim
	}
	if vrf.Attrs().Index == master {
		t.appliedRI[tc.Name] = tc.RIListMember
	}
}

// WG per-packet outer overhead (must mirror userspace-dp
// afxdp/wg/mod.rs WG_OVERHEAD_V4/V6): outer IP + UDP(8) + WG data
// header(16) + Poly1305 tag(16). Plus up to 15 bytes of §5.4.6 pad.
const (
	wgOverheadV4 = 20 + 8 + 16 + 16 // 60
	wgOverheadV6 = 40 + 8 + 16 + 16 // 80
	wgPadWorst   = 15
)

// wgEngineMaxInnerMTU is the largest INNER IP packet (pre-§5.4.6 padding)
// the WireGuard engine can encrypt in one transport message. It MUST mirror
// userspace-dp afxdp/wg/engine.rs WG_ENGINE_MAX_INNER_MTU
// (= PADDED_PLAINTEXT_MAX = 4096). The engine rejects an inner whose
// 16-byte-padded length exceeds PADDED_PLAINTEXT_MAX; because
// PADDED_PLAINTEXT_MAX is itself a 16-multiple, the largest accepted unpadded
// inner length is exactly 4096.
//
// #2457: the configured / derived wgN inner MTU MUST be clamped to this
// ceiling. Without the clamp, an operator who sets `mtu 9000` on a wgN
// interface (or a jumbo underlay deriving a >4096 inner budget) hands the
// engine plaintext above its encryptable maximum, so every oversized packet
// is silently dropped at the encap `padded_len > PADDED_PLAINTEXT_MAX` guard
// (`encap_mtu_drops`). Clamping makes the advertised/configured inner MTU
// match what the engine actually accepts.
const wgEngineMaxInnerMTU = 4080 + 16 // 4096

// wgDefaultOuterMTU is the assumed underlay (outer-link) MTU used to
// derive the wgN inner MTU when the operator has not set an explicit
// `mtu` on the tunnel (#2300). It mirrors the Rust control-thread
// fallback (coordinator/wg_control.rs WG_DEFAULT_OUTER_MTU) so both
// sides share ONE outer-MTU model. The control thread is additionally
// handed the REAL resolved underlay-egress MTU at spawn, and the
// transit-egress encap reads the real egress MTU per packet, so on a
// non-1500 underlay the Rust guard is authoritative even when this
// Go-side default cannot see the route. An operator who must lower the
// wgN MTU for a sub-1500 underlay (PPPoE 1492, cloud overlays ~1450)
// sets `set interfaces wgN unit U family inet mtu <n>` — that override
// wins (see wgTunMTUForEndpoint).
const wgDefaultOuterMTU = 1500

// wgTunMTUForEndpoint computes the inner (wgN) MTU cap (#1432 S2a, AGY
// Hazard A / H2). The kernel must never hand the WG control thread a
// plaintext packet that, once encapped with the worst-case overhead
// plus §5.4.6 pad, exceeds the outer MTU and forces outer IP
// fragmentation. The overhead depends on the outer IP family (the WG
// peer endpoint address): IPv6-outer is 20 bytes larger.
//
// #2300 MTU model: an operator-set `tc.MTU > 0` is the inner wgN MTU
// directly (the supported sub-1500 / jumbo path — it is the owning
// interface's `mtu` statement, carried by collectAppliedTunnels). With
// no operator MTU the cap derives from `wgDefaultOuterMTU` minus the
// family overhead. The control thread enforces an exact pad-aware guard
// against the REAL underlay-egress MTU (wg_control.rs), so this is the
// first line, not the only one — and on a non-1500 underlay the Rust
// guard catches what this default-derived value over-permits.
func wgTunMTUForEndpoint(tc *config.TunnelConfig) int {
	// Operator override: a configured `mtu` on the tunnel interface is
	// the inner wgN MTU. This is the divergence #2300 closes — the prior
	// code ignored tc.MTU entirely and always derived from 1500, so a
	// lowered-underlay deployment could not set a smaller wgN MTU.
	//
	// #2457: clamp the override to the engine's encryptable ceiling. An
	// operator who sets `mtu 9000` on a jumbo wgN device would otherwise
	// have the kernel hand the WG engine plaintext above
	// wgEngineMaxInnerMTU (4096), which the encap guard silently drops
	// (`encap_mtu_drops`). Clamping keeps the configured device MTU at or
	// below what the engine can actually encrypt.
	if tc.MTU > 0 {
		return min(tc.MTU, wgEngineMaxInnerMTU)
	}
	// A configured v4 endpoint uses the v4 overhead; a v6 endpoint (or a
	// responder-only/roaming endpoint with no configured address, which
	// the Rust control thread may LEARN as v6 — Codex r4 MAJOR) uses the
	// larger v6 overhead so the kernel never hands the control thread an
	// inner packet that the v6-aware encap guard would then drop. With
	// multi-peer (#1434) the outer family is a TUNNEL-level property (one
	// UDP socket); WgOuterFamilyV6 resolves it from the peer(s) that
	// declare an endpoint (validateWireguardPeers rejects mixed-family).
	overhead := wgOverheadV6
	if !tc.WgOuterFamilyV6() && tc.WgHasEndpoint() {
		overhead = wgOverheadV4
	}
	// #2457: the default-derived value also clamps to the engine ceiling
	// so a jumbo wgDefaultOuterMTU (were it ever raised) cannot derive an
	// inner budget the engine cannot encrypt. At the shipped 1500 default
	// this is a no-op.
	return min(wgDefaultOuterMTU-overhead-wgPadWorst, wgEngineMaxInnerMTU)
}

// applyWireguardTunLocked creates (or reuses) the persistent wgN TUN
// netdev for a WireGuard tunnel endpoint and configures its MTU,
// addresses, and VRF binding. The device is intentionally NOT tracked
// in t.tunnels: clearLocked must not delete it on reload (AGY Hazard B
// — flapping wgN destroys its addresses and FRR routes every commit).
//
// On config removal the persistent wgN LINK is intentionally kept (S2a:
// tearing it would flap the device and destroy the live peer/session),
// but the kernel ADDRESSES this manager applied are now pruned away by
// Apply's WG-removal diff (#1919): wgConfigured records the WG names from
// the last Apply, and a name that disappears has pruneAppliedAddrsLocked
// reconcile its addresses to empty while keeping the link. So a removed WG
// tunnel no longer leaks its addresses (or the kernel connected route the
// address auto-installs, removed by the kernel on AddrDel — and hence any
// FRR direct→connected redistribution of it).
//
// Remaining boundaries (#1434 scope): (1) a WG tunnel removed while the
// daemon was DOWN is not in wgConfigured on the next start, so it is not
// pruned (restart-adoption limitation shared by the whole manager — it
// only prunes what it tracked applying); (2) the wgN link and its live
// Rust-attached peer/session are kept (not torn) by design; (3) VRF
// membership is NOT unbound on removal (WG binds VRF directly, bypassing
// the appliedRI claim machinery, so there is no identity-gated unbind —
// the same root cause as the no-unbind-on-routing-instance-removal gap
// for a still-configured WG tunnel).
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
				// A stale NON-WG link remains under this name. Wrap with the
				// sentinel so Apply re-retains ownedNames for non-WG cleanup
				// retry (#1919 r5/r6) — distinct from a create failure that
				// may leave a healthy WG link.
				return fmt.Errorf("replace non-tun wireguard link %s: %w: %w",
					tc.Name, delErr, errWGIncompatibleLinkRetained)
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
	// would otherwise survive every reload and keep being routed. Shared
	// helper (#1884) with the per-link applied-address record (#1905) —
	// the same configured-vs-autoconf link-local split as the GRE/IPIP
	// branch: a CONFIGURED fe80 later removed from config is deleted
	// (this manager applied it), while the kernel's autoconf fe80 — and
	// any fe80 already present before this daemon's first apply
	// (restart adoption pass, applied == nil) — is never touched.
	// On config REMOVAL the wgN link persists (S2a) but its addresses are
	// now pruned by Apply's WG-removal diff (#1919, see the function doc
	// above); the appliedAddrs entry is dropped once the device is proven
	// clean, so a later re-add starts tracking fresh.
	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
		link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")

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

// stopKeepaliveLocked cancels, drains, and REMOVES the keepalive
// runner for one tunnel, if any. Removing the map entry matters
// (#1884 SMR2-2): a cancelled runner left behind would make
// GetKeepaliveState report a dead probe and would let the apply
// reconcile "retain" a corpse. Caller MUST hold mu.
func (t *tunnelManager) stopKeepaliveLocked(name string) {
	runner, ok := t.keepalives[name]
	if !ok {
		return
	}
	runner.cancel()
	<-runner.done
	delete(t.keepalives, name)
	slog.Debug("stopped keepalive", "tunnel", name)
}

// startKeepalive starts a keepalive probe goroutine for a tunnel.
// source is the tunnel local endpoint IP the probe binds to (#1918
// §5c); "" → wildcard. Caller MUST hold mu.
func (t *tunnelManager) startKeepalive(tunnelName, source, remoteAddr string, interval, maxRetries int) {
	// Stop existing keepalive for this tunnel if any. Drain on done
	// so the replacement doesn't race the old goroutine on the handle.
	t.stopKeepaliveLocked(tunnelName)

	if maxRetries <= 0 {
		maxRetries = 3
	}

	state := &KeepaliveState{
		Up:         true,
		RemoteAddr: remoteAddr,
		SourceAddr: source,
		Interval:   interval,
		MaxRetries: maxRetries,
	}

	// Capture the current generation token (#1918 §6 Axis D
	// defense-in-depth). The runner reads it LOCK-FREE — it never takes
	// t.mu — so an Apply blocked on the drain can never deadlock a tick.
	gen := t.linkGenForLocked(tunnelName)
	startGen := gen.Load()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.keepalives[tunnelName] = &keepaliveRunner{
		cancel:     cancel,
		state:      state,
		done:       done,
		remote:     remoteAddr,
		source:     source,
		interval:   interval,
		maxRetries: maxRetries,
		linkGen:    gen,
		startGen:   startGen,
	}

	prober := t.keepaliveProber()
	go t.keepaliveLoop(ctx, done, tunnelName, state, prober, gen, startGen)
	slog.Info("started keepalive", "tunnel", tunnelName,
		"source", source, "remote", remoteAddr, "interval", interval, "retries", maxRetries)
}

// keepaliveProbeDeadline returns the per-probe round-trip budget: a
// fraction of the interval, capped at 800ms (R5). Keeps the probe well
// inside the tick so a slow/lost reply cannot overrun the next tick.
func keepaliveProbeDeadline(intervalSec int) time.Duration {
	const maxDeadline = 800 * time.Millisecond
	half := time.Duration(intervalSec) * time.Second / 2
	if half <= 0 || half > maxDeadline {
		return maxDeadline
	}
	return half
}

// keepaliveLoop runs periodic ICMP echo probes to the tunnel underlay
// endpoint and drives the link admin state off REAL liveness (#1918).
// Closes `done` when it returns so stopAll can drain.
//
// Tick body is the §6 Axis D COMMIT-AFTER-SUCCESS sequence:
//  1. Under state.mu: classify the probe; commit pure counters
//     (Failures/LastSuccess/LastFailure/unknown bookkeeping); compute
//     the transition INTENT (wantUp/wantDown) WITHOUT writing Up; Unlock.
//     A racing GetStatus/Apply therefore never observes an uncommitted Up.
//  2. No intent → done (no netlink, no Up write).
//  3. LinkByName; on error do nothing (Up unchanged → retried next tick).
//  4. Lock-free gen.Load() guard: if the generation changed, the link
//     was recreated under us → DROP the action (do not down/up the
//     replacement). Never takes t.mu (AGY r5).
//  5. The single LinkSetUp/LinkSetDown, OUTSIDE state.mu, capturing err.
//  6. Commit Up ONLY on netlink success; on error leave Up unchanged so
//     the transition retries.
func (t *tunnelManager) keepaliveLoop(ctx context.Context, done chan struct{}, tunnelName string, state *KeepaliveState, prober tunnelProber, gen *atomic.Uint64, startGen uint64) {
	defer close(done)
	ticker := time.NewTicker(time.Duration(state.Interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.keepaliveTick(tunnelName, state, prober, gen, startGen)
		}
	}
}

// keepaliveTick runs one §6 Axis D commit-after-success probe cycle. It
// is the per-tick body of keepaliveLoop, extracted so tests can drive a
// single deterministic tick without a real ticker. It NEVER takes t.mu
// (AGY r5): only state.mu (two short sections) and a lock-free gen.Load().
func (t *tunnelManager) keepaliveTick(tunnelName string, state *KeepaliveState, prober tunnelProber, gen *atomic.Uint64, startGen uint64) {
	deadline := keepaliveProbeDeadline(state.Interval)
	seq := nextSeq(state)
	nonce := makeNonce()
	result, kind, reason := prober.Probe(state.SourceAddr, state.RemoteAddr, seq, nonce, deadline)

	// ---- Step 1: classify + commit counters, compute intent ----
	state.mu.Lock()
	var wantUp, wantDown bool
	switch result {
	case ProbeAlive:
		state.LastSuccess = time.Now()
		state.clearUnknownLocked()
		if !state.Up {
			wantUp = true // recovery edge
		}
		state.Failures = 0
	case ProbeDead:
		state.LastFailure = time.Now()
		state.clearUnknownLocked()
		state.Failures++
		if state.Up && state.Failures >= state.MaxRetries {
			wantDown = true
		}
	case ProbeUnsupported:
		// Hold-on-unknown (§6 Axis C, C1): do NOT touch Failures,
		// do NOT transition the link. Surface as unknown; escalate a
		// sustained TRANSIENT unknown after MaxRetries ticks. The prober's
		// reason (real syscall/config detail) is recorded so the status and
		// escalation log are actionable (Copilot PR #1947).
		detail := reason
		if detail == "" {
			detail = classifyErrnoString(kind)
		}
		state.markUnknownLocked(tunnelName, kind, detail)
	}
	state.mu.Unlock()

	// ---- Step 2: no transition intent → nothing to do ----
	if !wantUp && !wantDown {
		return
	}

	// ---- Step 3: resolve the link; error → retry next tick ----
	link, err := t.ops.LinkByName(tunnelName)
	if err != nil {
		// Do NOT write Up; the guard in step 1 fires again next
		// tick (Up unchanged). No spurious latch from a transient
		// netlink lookup hiccup (§4.6).
		slog.Debug("keepalive transition deferred: link lookup failed",
			"tunnel", tunnelName, "err", err)
		return
	}

	// ---- Step 4: lock-free generation guard (defense-in-depth) --
	if gen.Load() != startGen {
		// The link was recreated by Apply since this runner started.
		// Drop the action so we never down/up the replacement link.
		slog.Debug("keepalive transition dropped: link generation changed",
			"tunnel", tunnelName)
		return
	}

	// ---- Step 5: the single netlink op, OUTSIDE state.mu --------
	var nlErr error
	if wantUp {
		nlErr = t.ops.LinkSetUp(link)
	} else {
		nlErr = t.ops.LinkSetDown(link)
	}

	// ---- Step 6: commit Up only on netlink success -------------
	if nlErr != nil {
		// Up retains its pre-transition value → the transition is
		// retried next tick until the kernel op succeeds. Never a
		// lost transition (Codex r3 counterexample).
		slog.Warn("keepalive netlink transition failed; will retry",
			"tunnel", tunnelName, "want_up", wantUp, "err", nlErr)
		return
	}
	state.mu.Lock()
	if wantUp {
		state.Up = true
		state.Failures = 0
		slog.Info("tunnel keepalive recovered", "tunnel", tunnelName,
			"remote", state.RemoteAddr)
	} else {
		state.Up = false
		slog.Warn("tunnel keepalive failed, marking down",
			"tunnel", tunnelName, "remote", state.RemoteAddr,
			"failures", state.Failures)
	}
	state.mu.Unlock()
}

// nextSeq returns a fresh monotonic 16-bit sequence number for a probe
// (§5a). Wraps at 0xffff; the per-probe nonce disambiguates a wrapped
// collision. Mutates Failures-adjacent state under its own lock.
func nextSeq(state *KeepaliveState) int {
	state.mu.Lock()
	state.seq = (state.seq + 1) & 0xffff
	s := state.seq
	state.mu.Unlock()
	return s
}

// clearUnknownLocked resets the hold-on-unknown bookkeeping after a
// definitive Alive/Dead probe. Caller MUST hold state.mu.
func (s *KeepaliveState) clearUnknownLocked() {
	s.Unknown = false
	s.UnknownKind = UnsupportedNone
	s.UnknownErrno = ""
	s.unknownStreak = 0
	s.warnedUnknown = false
}

// markUnknownLocked records a ProbeUnsupported tick. Structural emits a
// one-shot Warn and holds indefinitely; transient holds but escalates to
// slog.Error after MaxRetries consecutive unknown ticks (§6 Axis C,
// transient escalation). Never changes Up or Failures. Caller MUST hold
// state.mu.
func (s *KeepaliveState) markUnknownLocked(tunnelName string, kind UnsupportedKind, errStr string) {
	s.Unknown = true
	s.UnknownKind = kind
	s.UnknownErrno = errStr
	s.unknownStreak++
	switch kind {
	case UnsupportedStructural:
		if !s.warnedUnknown {
			s.warnedUnknown = true
			slog.Warn("tunnel keepalive cannot probe (ICMP unavailable); holding prior state",
				"tunnel", tunnelName, "remote", s.RemoteAddr,
				"hint", "set net.ipv4.ping_group_range or grant CAP_NET_RAW")
		}
	case UnsupportedTransient:
		if s.unknownStreak >= s.MaxRetries && !s.warnedUnknown {
			s.warnedUnknown = true
			slog.Error("tunnel keepalive probe failing on local resource error; cannot verify peer liveness",
				"tunnel", tunnelName, "remote", s.RemoteAddr,
				"errno", errStr, "consecutive", s.unknownStreak)
		}
	}
}

// classifyErrnoString renders a short label for the unknown kind used in
// the status string.
func classifyErrnoString(kind UnsupportedKind) string {
	switch kind {
	case UnsupportedTransient:
		return "probe socket error"
	case UnsupportedStructural:
		return "ICMP probe unavailable"
	default:
		return "unknown"
	}
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
// Apply no longer uses it (#1884 reconcile-in-place); it remains the
// explicit delete-everything path for ClearTunnels. It deletes the
// UNION of the success-tracked list and the ownership set: a
// per-tunnel apply failure leaves the name in ownedNames but not in
// t.tunnels (failure-continue before finishTunnelLocked), and the
// delete-everything contract must still cover that live link (Codex
// PR #1903 r1 MINOR).
func (t *tunnelManager) clearLocked() error {
	t.stopAllKeepalivesLocked()
	names := make(map[string]bool, len(t.tunnels)+len(t.ownedNames))
	for _, name := range t.tunnels {
		names[name] = true
	}
	for name := range t.ownedNames {
		names[name] = true
	}
	for name := range names {
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
	// Reset the reconcile state with the devices: a post-Clear Apply
	// adopts whatever survives instead of trusting stale ownership.
	t.ownedNames = nil
	t.appliedAddrs = nil
	t.appliedRI = nil
	// Reset the WG-removal-prune tracking too (#1919). ClearTunnels does
	// NOT delete WG links (they are persistent and not in tunnels/
	// ownedNames) — only the tracking map is dropped so a post-Clear Apply
	// re-adopts cleanly. Whether ClearTunnels should also flush WG
	// addresses is deferred to #1434 (full teardown grammar).
	t.wgConfigured = nil
	// clearLocked drains every keepalive runner first
	// (stopAllKeepalivesLocked above), so no live runner holds a stale
	// linkGen pointer; dropping the map is safe and prevents removed names
	// from leaking generation counters (#1918).
	t.linkGen = nil
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

		// Add keepalive info.
		if ks := t.GetKeepaliveState(name); ks != nil {
			ks.mu.Lock()
			switch {
			case ks.Unknown:
				// Hold-on-unknown (#1918 §6 Axis C): the prober could not
				// verify liveness. KeepaliveUp stays nil ("liveness
				// unknown") — never reported up — and the info string tells
				// the operator why so they can fix the sysctl/caps. A
				// sustained transient unknown carries the escalated errno.
				ts.KeepaliveUp = nil
				switch {
				case ks.UnknownKind == UnsupportedTransient:
					ts.KeepaliveInfo = fmt.Sprintf(
						"unknown (%s; %d consecutive)",
						ks.UnknownErrno, ks.unknownStreak)
				case ks.UnknownErrno != "":
					// Structural with a captured reason (the real syscall/config
					// detail): show it so the operator can fix the root cause.
					ts.KeepaliveInfo = fmt.Sprintf(
						"unknown (ICMP probe unavailable: %s)", ks.UnknownErrno)
				default:
					ts.KeepaliveInfo = "unknown (ICMP probe unavailable)"
				}
			default:
				up := ks.Up
				ts.KeepaliveUp = &up
				if up {
					ts.KeepaliveInfo = fmt.Sprintf("up (interval %ds, %d retries)",
						ks.Interval, ks.MaxRetries)
				} else {
					ts.KeepaliveInfo = fmt.Sprintf("down (%d consecutive failures)",
						ks.Failures)
				}
			}
			ks.mu.Unlock()
		}

		result = append(result, ts)
	}
	return result, nil
}
