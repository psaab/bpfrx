package ddns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// surface_a.go: the Surface A router/interface-address DDNS engine (#2691 P2,
// plan §2.1, §5.3, §5.5). Surface A publishes the firewall's OWN address — an
// interface/unit/family's learned WAN address (DHCP lease, static, netlink) —
// as a single A/AAAA record at a configured FQDN through an external DNS
// provider. It is the classic "dyndns client on the CPE" surface.
//
// REUSE, DO NOT FORK THE SPINE: Surface A drives the SAME Backend (DNSUpdater)
// interface, the SAME record construction (buildHostRecord → LeaseDNSRecord),
// the SAME RFC 2136 backend (newRFC2136Updater, with self-ownership semantics:
// no DHCID/ClientID, so sendAddOwned uses the name-not-in-use / refresh-owned
// prerequisite), the SAME ScopeKey ownership primitive (plan §5.4), and the
// SAME durable-fsync state store pattern (state.go ddnsState shape) — only the
// state FILE differs (interface-ddns-state.json, plan §5.5). The ONLY thing
// Surface A adds on top of the spine is the update ENGINE discipline the
// DHCP-lease reconciler does not need: per-scope change detection, a
// forced-refresh wire floor decoupled from the poll cadence, and flat error
// backoff (ban-avoidance) — the inadyn ideas #4/#7/#8 (plan §3.3/§5.5).
//
// HA (plan §5.6 / #2664): a router record on a reth/virtual interface is
// published only by the node that masters its scope's RG. The SurfaceAManager
// takes the SAME per-scope ScopeGate the lease reconciler does; a gated-out
// scope is stop-writing, never-withdraw (the peer RG master refreshes; a
// withdraw race would blackhole). A standalone (nil gate) always publishes.

// defaultSurfaceAStatePath is the on-disk location of the Surface A
// last-published / ownership store (plan §5.5). Distinct from the Surface B
// lease ownership store (defaultDDNSStatePath) so the two surfaces never
// collide on a record key and either can be reset independently.
const defaultSurfaceAStatePath = "/var/lib/xpf/interface-ddns-state.json"

// defaultForcedRefresh is the wire-update floor for an UNCHANGED address
// (inadyn idea #7, plan §5.5). The reconcile loop re-asserts desired state
// every 30s, but a wire UPDATE for an unchanged address fires at most once per
// forced-refresh interval — proving liveness to the provider / resisting record
// reaping without per-poll traffic. 24h matches the plan default.
const defaultForcedRefresh = 24 * time.Hour

// defaultErrorBackoffMax caps the per-scope error backoff (inadyn idea #8,
// flat — not exponential beyond the cap; plan §5.5). On a transient failure a
// scope backs off from the reconcile interval up to this cap so a failing
// provider is not hammered at the poll cadence (ban-avoidance).
const defaultErrorBackoffMax = time.Hour

// surfaceABaseBackoff is the first error-backoff step (the reconcile cadence).
// A scope that keeps failing doubles up to defaultErrorBackoffMax.
const surfaceABaseBackoff = 30 * time.Second

// AddressSource selects where an interface scope's current address is observed
// (plan §5.3). Ordered-fallback observation lives in the daemon's
// AddressObserver; this enum is the per-scope operator selection.
type AddressSource string

const (
	// AddressSourceInterface reads the address from the interface (netlink /
	// configured static) — the default. The firewall is the router, so it
	// usually knows its own public address directly (plan §7 fork 4).
	AddressSourceInterface AddressSource = "interface"
	// AddressSourceDHCP reads the address from the DHCP client lease
	// (pkg/dhcp.Manager.LeaseFor) — the authoritative learned WAN address.
	AddressSourceDHCP AddressSource = "dhcp"
)

// SurfaceAScope is the resolved, runtime-shaped configuration for ONE
// interface/unit/family Surface A binding (plan §5.9). It is derived from the
// per-interface `dynamic-dns` config + the referenced provider-catalog entry at
// reconcile time so the manager never holds a stale captured cfg.
type SurfaceAScope struct {
	// Key is the ownership/scope key (plan §5.4). For Surface A it is keyed on
	// {Family, Interface, Unit, RGOwner} — RoutingInstance/PolicyID round out
	// the transport + provider attribution. The interface+unit+family triple is
	// unique per binding.
	Key ScopeKey
	// FQDN is the forward name to publish (already an operator-supplied FQDN;
	// finalizeFQDN normalizes it against an empty zone so a dotted name is kept
	// verbatim, a bare label is published as-is).
	FQDN string
	// TTL is the record TTL in seconds (defaultDDNSTTL when unset).
	TTL int
	// Source selects the address-observation source for this scope.
	Source AddressSource
	// Provider is the resolved provider-catalog entry (backend + credentials +
	// transport binding) this scope publishes through.
	Provider *config.DDNSProvider
	// ForcedRefresh is the wire-update floor for an unchanged address; 0 ⇒
	// defaultForcedRefresh.
	ForcedRefresh time.Duration
	// ErrorBackoffMax caps the per-scope error backoff; 0 ⇒
	// defaultErrorBackoffMax.
	ErrorBackoffMax time.Duration
}

// scopeID is the stable string id for a Surface A scope (its ScopeKey prefix),
// used as the map key in the manager's per-scope runtime state and the
// observation request. Two scopes with the same interface/unit but different
// families are distinct.
func (s SurfaceAScope) scopeID() string { return s.Key.scopePrefix() }

// AddressObservation is the result of observing a scope's current address
// (plan §5.3). Addr.IsValid()==false means "no address right now" (the
// interface is down / has no lease for this family) — the engine withdraws a
// previously-published record for a scope that loses its address.
type AddressObservation struct {
	Addr   netip.Addr
	Source AddressSource
}

// AddressObserver observes the current address for a Surface A scope (plan
// §5.3). The daemon supplies it (it reads netlink / pkg/dhcp.LeaseFor). The
// engine never reads netlink/DHCP directly — keeping pkg/ddns free of those
// dependencies, exactly as the LeaseParser seam keeps it free of the Kea
// memfile parser. ok=false means the address could not be observed this cycle
// (transient) — the engine then leaves the scope untouched (no withdraw on a
// transient observation failure, the never-blackhole rule).
type AddressObserver func(scope SurfaceAScope) (AddressObservation, bool)

// surfaceAState is the per-scope runtime engine state (plan §5.5): the
// last-published address + time (change-detection + forced-refresh) and the
// error-backoff schedule. It is kept in memory alongside the durable ownership
// record (the durable store proves ownership for cleanup; this drives the wire
// cadence). lastErr surfaces the last failure for observability.
type surfaceAState struct {
	lastAddr      netip.Addr
	lastPublished time.Time
	// nextEligible is the earliest time the scope may attempt a wire op again
	// after a failure (error backoff). Zero ⇒ eligible now.
	nextEligible time.Time
	backoff      time.Duration
	lastErr      string
	lastErrAt    time.Time
}

// SurfaceAStatusView is a read-only projection of one Surface A scope's
// current publish state, for the operator surfaces (CLI/gRPC/REST). It exposes
// what is currently published, the last-published time, and the last error.
type SurfaceAStatusView struct {
	Interface     string
	Unit          int
	Family        int
	FQDN          string
	Provider      string
	Published     string // current published address ("" = none)
	LastPublished time.Time
	LastError     string
	LastErrorAt   time.Time
}

// SurfaceAManager owns the Surface A reconcile + the per-scope last-published
// cache + ownership store (plan §5.5/§5.6). It is a SEPARATE manager from the
// DHCP-lease Manager (different ownership semantics — self-owned vs DHCID — and
// a different state file), but it drives the SAME Backend interface and the
// SAME record/scope/durability primitives.
type SurfaceAManager struct {
	mu    sync.Mutex
	state *ddnsState // durable ownership store (interface-ddns-state.json)

	// runtime is the per-scope engine state (change-detect / forced-refresh /
	// backoff), keyed by scopeID. NOT persisted: it is rebuilt on restart from
	// the durable store (seedFromStore) so a restart does not blast a redundant
	// update for an unchanged address (inadyn idea #5, plan §5.5).
	runtime map[string]*surfaceAState

	// newBackend resolves the live Backend for a provider at reconcile time
	// (resolve-per-Reconcile, plan §6 fork 1). When nil (tests injecting a fixed
	// backend) the static `backend` field is used for every scope.
	newBackend func(p *config.DDNSProvider, fqdn string, ttl int) (DNSUpdater, error)
	backend    DNSUpdater // static fallback / test injection

	now func() time.Time

	// counters (observability, plan §5.5).
	upsertOK   uint64
	upsertFail uint64
	deleteOK   uint64
	deleteFail uint64
	skipped    uint64 // unchanged-and-not-yet-forced skips
	backedOff  uint64 // scopes skipped this pass because still in error backoff
	// skippedNoBackend counts scopes skipped because the provider resolved to the
	// no-op backend (a half-configured HTTP provider whose constructor errored on
	// a missing credential — newSurfaceAHTTP degrades to nopUpdater{}). Such a
	// scope publishes NOTHING to any wire, so it must NOT count as an upsertOK,
	// must NOT write-ahead phantom ownership, and must NOT advance the
	// last-published cache — so it re-attempts every cycle once the operator adds
	// the credential (mirrors manager.go upsertLocked's skippedNoBackend, #2691
	// P3 review MAJOR).
	skippedNoBackend uint64
}

// NewSurfaceAManager constructs the production Surface A manager (plan §5.5). It
// loads the durable ownership store from defaultSurfaceAStatePath (a corrupt
// store is reset to empty, fail-open) and resolves the live RFC 2136 backend
// per provider at reconcile time. The runtime cache is seeded from the durable
// store so a restart does not republish an unchanged address.
func NewSurfaceAManager() *SurfaceAManager {
	st, err := loadDDNSState(defaultSurfaceAStatePath)
	if err != nil {
		slog.Warn("ddns surface-a: ownership state load failed; starting empty", "err", err)
	}
	m := &SurfaceAManager{
		state:      st,
		runtime:    map[string]*surfaceAState{},
		newBackend: productionSurfaceABackend,
		now:        time.Now,
	}
	m.seedFromStore()
	return m
}

// newSurfaceAManagerForTesting builds a manager with an in-memory state file
// path, an injected backend, and an injectable clock — no real /var/lib path,
// no network. Used by surface_a_test.go.
func newSurfaceAManagerForTesting(statePath string, backend DNSUpdater, now func() time.Time) *SurfaceAManager {
	st, _ := loadDDNSState(statePath)
	m := &SurfaceAManager{
		state:   st,
		runtime: map[string]*surfaceAState{},
		backend: backend,
		now:     now,
	}
	m.seedFromStore()
	return m
}

// productionSurfaceABackend resolves a provider-catalog entry into a live
// Backend (plan §5.2). The rfc2136 backend (P2) and the HTTP backends — dyndns2,
// cloudflare, route53, generic (P3) — are all siblings behind the SAME
// DNSUpdater interface, so the Surface A engine drives every one identically. A
// backend whose required fields are missing (or an unknown backend token)
// resolves to the no-op (logged) so a half-configured provider degrades safely
// at runtime instead of wedging — the commit warning already told the operator.
func productionSurfaceABackend(p *config.DDNSProvider, fqdn string, _ int) (DNSUpdater, error) {
	if p == nil {
		return nopUpdater{}, nil
	}
	switch p.Backend {
	case "rfc2136", "":
		if p.UpdateServer == "" {
			return nopUpdater{}, nil
		}
		return newSurfaceARFC2136(p, fqdn)
	case "dyndns2":
		return newSurfaceAHTTP(p, func() (DNSUpdater, error) { return newDyndns2Backend(p) })
	case "cloudflare":
		return newSurfaceAHTTP(p, func() (DNSUpdater, error) { return newCloudflareBackend(p) })
	case "route53":
		return newSurfaceAHTTP(p, func() (DNSUpdater, error) { return newRoute53Backend(p) })
	case "generic":
		return newSurfaceAHTTP(p, func() (DNSUpdater, error) { return newGenericBackend(p) })
	default:
		slog.Warn("ddns surface-a: unknown provider backend; publishing nothing",
			"provider", p.Name, "backend", p.Backend)
		return nopUpdater{}, nil
	}
}

// newSurfaceAHTTP adapts an HTTP-backend constructor to the
// productionSurfaceABackend contract: a construction error (missing credential /
// endpoint) degrades to the no-op (logged + the commit warning already fired)
// rather than failing the whole reconcile pass, matching the rfc2136 fail-open
// posture. The returned backend's UpsertLease/DeleteLease are then driven by the
// engine exactly like rfc2136.
func newSurfaceAHTTP(p *config.DDNSProvider, build func() (DNSUpdater, error)) (DNSUpdater, error) {
	u, err := build()
	if err != nil {
		slog.Warn("ddns surface-a: HTTP provider not usable; publishing nothing",
			"provider", p.Name, "backend", p.Backend, "err", err)
		return nopUpdater{}, nil
	}
	return u, nil
}

// newSurfaceARFC2136 builds the live RFC 2136 backend for a Surface A provider.
// It reuses the SAME rfc2136Updater the lease path uses, in SELF-OWNED mode:
// a router record has NO ClientID/DHCID (the firewall is the authoritative owner
// of its OWN configured FQDN), so the forward ADD is an atomic IN-PLACE REPLACE
// of our record type (rfc2136Updater.selfOwned → sendAddSelfOwned), NOT the
// lease path's name-not-in-use / DHCID-match prerequisite. This is what lets an
// address change and a forced-refresh of an EXISTING name succeed — without
// selfOwned, the no-DHCID lease path would REFUSE the pre-existing name and pin
// the record at its first address forever. The provider's transport binding
// (source-address / dest-interface / VRF) is honored via the shared
// resolveBindConfig→dialer path by reusing DHCPDynamicDNSConfig as the carrier.
func newSurfaceARFC2136(p *config.DDNSProvider, _ string) (DNSUpdater, error) {
	if p == nil {
		return nil, errors.New("ddns surface-a: nil provider")
	}
	// Reuse the lease-path policy + config shape so the rfc2136 backend builds
	// identically (server, TSIG, source binding). conflict-policy is replace-
	// owned but the selfOwned flag (set below) overrides the forward-add path to
	// the in-place replace — the conflict-policy value only governs the unused
	// PTR path for a self record.
	pol := ddnsPolicy{
		domain:         "", // the FQDN is absolute; no domain suffixing
		conflictPolicy: "replace-owned",
		backend:        "rfc2136",
	}
	c := &config.DHCPDynamicDNSConfig{
		UpdateServer:         p.UpdateServer,
		TSIGKeyName:          p.TSIGKeyName,
		TSIGAlgorithm:        p.TSIGAlgorithm,
		TSIGSecret:           p.TSIGSecret,
		SourceAddress:        p.SourceAddress,
		DestinationInterface: p.DestinationInterface,
		RoutingInstance:      p.RoutingInstance,
	}
	u, err := newRFC2136Updater(pol, c, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	u.selfOwned = true
	return u, nil
}

// seedFromStore rebuilds the in-memory runtime cache from the durable ownership
// store (inadyn idea #5, plan §5.5): a restart must not blast a redundant
// update for an address that has not changed. Each owned record seeds
// lastAddr; lastPublished is left zero so the FIRST post-restart reconcile,
// if the address is unchanged, still satisfies change-detection (addr matches)
// and the forced-refresh floor is measured from the restart (a benign at-most-
// one wire refresh on the first forced interval after a restart). Caller need
// not hold the mutex (constructor-only).
func (m *SurfaceAManager) seedFromStore() {
	for _, r := range m.state.all() {
		a, err := netip.ParseAddr(r.Address)
		if err != nil {
			continue
		}
		m.runtime[r.scopeOf().scopePrefix()] = &surfaceAState{lastAddr: a.Unmap()}
	}
}

// Reconcile drives one Surface A reconcile pass over the configured scopes
// (plan §5.5/§5.6). For each scope it: observes the current address; applies
// the per-RG HA gate; runs change-detection + forced-refresh + error backoff;
// and publishes/withdraws through the resolved Backend. A scope present in the
// durable store but ABSENT from `scopes` (binding removed from config) is
// WITHDRAWN (turn-off cleanup), provided this node may write its scope.
//
// gate is the SAME per-RG ScopeGate the lease reconciler uses (#2664). A nil
// gate (standalone) admits every scope. A gated-out scope is stop-writing,
// never-withdraw (the peer RG master refreshes it).
func (m *SurfaceAManager) Reconcile(ctx context.Context, scopes []SurfaceAScope, observe AddressObserver, gate ScopeGate, catalog map[string]*config.DDNSProvider) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	var firstErr error
	noteErr := func(e error) {
		if e != nil && firstErr == nil {
			firstErr = e
		}
	}

	admit := func(s ScopeKey) bool {
		if gate == nil {
			return true
		}
		return gate(s)
	}

	// desired[scopeID] = the configured scope. Used to find owned records that
	// are no longer configured (withdraw), and to drive the per-scope publish.
	desired := map[string]SurfaceAScope{}
	for _, sc := range scopes {
		desired[sc.scopeID()] = sc
	}

	// Pass 1 — publish / refresh / withdraw-on-address-loss each configured
	// scope.
	for _, sc := range scopes {
		if !admit(sc.Key) {
			// Per-RG gate closed: stop writing, never withdraw (plan §5.6). The
			// peer that masters this RG owns the refresh.
			slog.Debug("ddns surface-a: scope not writable from this node (per-RG gate closed); not publishing, not withdrawing",
				"fqdn", sc.FQDN, "rg", sc.Key.RGOwner, "iface", sc.Key.Interface)
			continue
		}
		noteErr(m.reconcileScopeLocked(ctx, sc, observe, now))
	}

	// Pass 2 — withdraw scopes whose binding was removed from config. A record
	// owned for a scope NOT in `desired` is withdrawn (turn-off cleanup), gated
	// by the same per-RG writer gate (never withdraw a scope this node does not
	// master). The live backend is REBUILT from the owned record's provider
	// attribution (scope.PolicyID → the provider catalog) — the same backend the
	// publish used — so the withdraw actually reaches the wire even though the
	// SurfaceAScope is gone (#2691 P2 MAJOR-2 fix: a removed-binding withdraw
	// MUST send a real DNS DELETE, not silently drop ownership and orphan the RR).
	for _, owned := range m.state.all() {
		sid := owned.scopeOf().scopePrefix()
		if _, stillConfigured := desired[sid]; stillConfigured {
			continue
		}
		if !admit(owned.scopeOf()) {
			continue
		}
		backend, err := m.backendForOwned(owned, catalog)
		if err != nil {
			noteErr(err)
			continue
		}
		noteErr(m.withdrawOwnedLocked(ctx, owned, backend))
	}

	if err := m.state.save(); err != nil {
		slog.Warn("ddns surface-a: persist ownership state failed", "err", err)
		noteErr(err)
	}
	return firstErr
}

// reconcileScopeLocked is the per-scope engine (plan §5.5): observe → change
// detection → forced-refresh → error backoff → publish/withdraw. Caller holds
// m.mu.
func (m *SurfaceAManager) reconcileScopeLocked(ctx context.Context, sc SurfaceAScope, observe AddressObserver, now time.Time) error {
	sid := sc.scopeID()
	rt := m.runtime[sid]
	if rt == nil {
		rt = &surfaceAState{}
		m.runtime[sid] = rt
	}

	// Error backoff (inadyn idea #8): a scope still in its backoff window is
	// skipped this pass so a failing provider is not hammered (ban-avoidance).
	if !rt.nextEligible.IsZero() && now.Before(rt.nextEligible) {
		m.backedOff++
		slog.Debug("ddns surface-a: scope in error backoff; skipping this pass",
			"fqdn", sc.FQDN, "next-eligible", rt.nextEligible)
		return nil
	}

	obs, ok := observe(sc)
	if !ok {
		// Transient observation failure: leave the scope untouched (never
		// withdraw on a transient — the never-blackhole rule, plan §8.2).
		slog.Debug("ddns surface-a: address observation failed (transient); leaving scope untouched", "fqdn", sc.FQDN)
		return nil
	}

	if !obs.Addr.IsValid() {
		// The scope lost its address (interface down / lease gone). If we own a
		// record for it, withdraw it (the address really is gone — this is the
		// authoritative "no address", not a transient observation failure). We
		// still have the live SurfaceAScope here, so resolve its provider backend
		// directly — the withdraw reaches the wire (the address-loss half of the
		// #2691 P2 MAJOR-2 fix; backendForOwned is only needed for the gone-from-
		// config Pass 2 withdraw where the scope no longer exists).
		if owned, exists := m.state.get(sc.Key, surfaceAIdentity, ""); exists {
			backend, err := m.backendFor(sc)
			if err != nil {
				m.deleteFail++
				return err
			}
			if err := m.withdrawOwnedLocked(ctx, owned, backend); err != nil {
				return err
			}
			delete(m.runtime, sid)
		}
		return nil
	}

	addr := obs.Addr.Unmap()

	// Change detection + forced-refresh (inadyn ideas #4/#7): fire a wire
	// UPDATE when the address changed OR the forced-refresh floor elapsed since
	// the last successful publish. An unchanged address inside the floor is a
	// counted skip (no wire traffic).
	forced := sc.ForcedRefresh
	if forced <= 0 {
		forced = defaultForcedRefresh
	}
	changed := addr != rt.lastAddr
	_, owned := m.state.get(sc.Key, surfaceAIdentity, "")
	refreshDue := rt.lastPublished.IsZero() || now.Sub(rt.lastPublished) >= forced
	if owned && !changed && !refreshDue {
		m.skipped++
		slog.Debug("ddns surface-a: address unchanged and forced-refresh not due; skipping",
			"fqdn", sc.FQDN, "addr", addr.String())
		return nil
	}

	if err := m.publishLocked(ctx, sc, addr, now); err != nil {
		if errors.Is(err, errSurfaceANoBackend) {
			// No live backend (half-configured provider): nothing was attempted on
			// the wire. Do NOT arm error backoff and do NOT advance the
			// last-published cache — leave rt untouched so the scope re-attempts
			// every cycle once the operator adds the credential. Swallow the
			// sentinel (not a pass error).
			return nil
		}
		m.recordScopeError(rt, sc, err, now)
		return err
	}
	// Success: clear backoff, update the last-published cache.
	rt.lastAddr = addr
	rt.lastPublished = now
	rt.nextEligible = time.Time{}
	rt.backoff = 0
	rt.lastErr = ""
	return nil
}

// surfaceAIdentity is the fixed ownership "identity" for every Surface A record
// — a router record is keyed on its SCOPE + FQDN, not a client identity (there
// is no DHCP client). Using a constant identity keeps the ownedRecordKey shape
// shared with the lease store (scopePrefix + identity + "|" + address) while
// the scope (interface/unit/family) is the real discriminator. Address is "" in
// the key so a scope owns at most ONE record and an address change REPLACES it
// in place (no stale old-address entry, never a withdraw-then-add gap).
const surfaceAIdentity = "router-self"

// errSurfaceANoBackend is returned by publishLocked when the scope's provider
// resolved to the no-op backend (a half-configured HTTP provider). It is NOT a
// failure to back off on — nothing was attempted on the wire — and NOT a success
// (no ownership, no last-published advance). reconcileScopeLocked treats it as a
// counted no-backend skip that re-attempts next cycle (#2691 P3 review MAJOR).
var errSurfaceANoBackend = errors.New("ddns surface-a: no live backend for provider")

// publishLocked publishes the scope's record through the resolved Backend and
// records ownership write-ahead (the same durability discipline as the lease
// path, #2662). The ownership key fixes Address="" so a scope owns exactly one
// record: an address change REPLACES the rdata via the backend's atomic
// in-place self-owned replace (rfc2136Updater.sendAddSelfOwned: a single UPDATE
// that delete-RRsets our forward type then inserts the new rdata), never a
// withdraw-then-add that would blackhole. Caller holds m.mu.
func (m *SurfaceAManager) publishLocked(ctx context.Context, sc SurfaceAScope, addr netip.Addr, now time.Time) error {
	backend, err := m.backendFor(sc)
	if err != nil {
		m.upsertFail++
		return err
	}
	if isNopUpdater(backend) {
		// The provider degraded to the no-op backend (a half-configured HTTP
		// provider whose constructor errored on a missing credential, e.g.
		// `backend cloudflare` with no api-token). Publishing NOTHING to any wire:
		// do NOT write-ahead ownership (it would be phantom — an RR that does not
		// exist), do NOT count an upsertOK (the counter would lie), and signal the
		// caller (errSurfaceANoBackend) so it leaves the last-published cache
		// untouched and re-attempts next cycle once the credential is added. This
		// mirrors manager.go upsertLocked's skippedNoBackend handling. The commit
		// warning already told the operator the provider is incomplete.
		m.skippedNoBackend++
		slog.Debug("ddns surface-a: provider resolved to no-op backend; skipping publish (no ownership, will re-attempt)",
			"fqdn", sc.FQDN, "provider", sc.Key.PolicyID)
		return errSurfaceANoBackend
	}
	ttl := sc.TTL
	if ttl <= 0 {
		ttl = defaultDDNSTTL
	}
	rec, err := buildHostRecord(sc.FQDN, addr, ttl)
	if err != nil {
		m.upsertFail++
		return err
	}

	prevOwned, hadPrev := m.state.get(sc.Key, surfaceAIdentity, "")
	prevAddr := ""
	if hadPrev {
		prevAddr = prevOwned.Address
	}

	// Write-ahead the ownership intent BEFORE the wire add (#2662): a crash
	// after the add finds the record owned and the next reconcile converges it.
	ow := ownedRecord{
		Family:      familyInt(addr),
		Identity:    surfaceAIdentity,
		Address:     "", // key on scope+FQDN; rdata lives in AddrText below
		FQDN:        rec.FQDN,
		ForwardType: rec.ForwardType,
		PTRName:     "",
		TTL:         ttl,
		AddrText:    addr.String(),
	}.withScope(sc.Key)
	m.state.put(ow)
	if err := m.state.save(); err != nil {
		// Could not durably record ownership: do NOT publish. Roll back to the
		// previous durable state.
		if hadPrev {
			m.state.put(prevOwned)
		} else {
			m.state.delete(sc.Key, surfaceAIdentity, "")
		}
		m.upsertFail++
		return fmt.Errorf("ddns surface-a: cannot durably record ownership before publish: %w", err)
	}

	if err := backend.UpsertLease(ctx, rec); err != nil {
		// Hard add failure: the record is NOT live with the new rdata. Restore
		// the previous durable ownership (the old address is still live) so we
		// do not claim an address we failed to publish. A conflict refusal
		// (name owned by another party) also lands here — Surface A does not
		// adopt a third party's name.
		if hadPrev {
			m.state.put(prevOwned)
		} else {
			m.state.delete(sc.Key, surfaceAIdentity, "")
		}
		_ = m.state.save()
		m.upsertFail++
		if errors.Is(err, errDDNSConflictRefused) {
			return fmt.Errorf("ddns surface-a: %s is owned by another party (refused): %w", rec.FQDN, err)
		}
		return fmt.Errorf("ddns surface-a: publish %s %s=%s: %w", rec.ForwardType, rec.FQDN, addr, err)
	}

	// Success. If the address CHANGED (replace), the self-owned add already
	// updated the rdata in place at the server (sendAddSelfOwned's atomic
	// delete-RRset + insert), so there is no separate withdraw of the old
	// address — the never-blackhole replace. Log the transition for observability.
	if prevAddr != "" && prevAddr != addr.String() {
		slog.Info("ddns surface-a: replaced record address",
			"fqdn", rec.FQDN, "old", prevAddr, "new", addr.String())
	} else if !hadPrev {
		slog.Info("ddns surface-a: published record", "fqdn", rec.FQDN, "addr", addr.String())
	}
	m.upsertOK++
	return nil
}

// withdrawOwnedLocked removes the firewall's own record for an owned scope
// (binding removed, or address lost) through the GIVEN backend, then drops the
// ownership entry. Caller holds m.mu and is responsible for resolving the LIVE
// backend (Pass 1 from the live scope via backendFor, Pass 2 from the provider
// catalog via backendForOwned) so the delete actually reaches the wire — a nil/
// no-op backend would orphan the RR (#2691 P2 MAJOR-2). A delete is re-derived
// from the EXACT owned tuple (the sole-delete-authority boundary, shared with
// the lease path): Surface A never deletes a name it did not record.
//
// Observability honesty (#2691 P2 MINOR M1): the ownership entry is dropped only
// AFTER a successful wire delete; a failed delete increments deleteFail (not
// deleteOK) and leaves the entry so the next reconcile retries. A no-op backend
// (provider unresolvable) is treated as a FAILURE — it did NOT remove the RR, so
// it must not report success nor drop ownership (which would orphan the RR).
func (m *SurfaceAManager) withdrawOwnedLocked(ctx context.Context, owned ownedRecord, backend DNSUpdater) error {
	a, err := netip.ParseAddr(owned.AddrText)
	if err != nil {
		// Stored rdata no longer parses (should not happen): drop the entry to
		// avoid wedging, but issue no delete with a guessed address.
		slog.Warn("ddns surface-a: owned record has unparseable address; dropping entry",
			"fqdn", owned.FQDN, "addr", owned.AddrText, "err", err)
		m.state.delete(owned.scopeOf(), owned.Identity, owned.Address)
		delete(m.runtime, owned.scopeOf().scopePrefix())
		return nil
	}
	if isNopUpdater(backend) {
		// No live backend resolved (provider gone from the catalog): the RR
		// cannot be withdrawn. Do NOT claim success or drop ownership — leaving
		// the entry keeps the RR cleanable once the provider is reconfigured, and
		// keeps the deleteOK counter honest (#2691 P2 MINOR M1).
		m.deleteFail++
		slog.Warn("ddns surface-a: cannot withdraw record — no live backend for its provider; keeping ownership for retry",
			"fqdn", owned.FQDN, "addr", owned.AddrText, "provider", owned.scopeOf().PolicyID)
		return fmt.Errorf("ddns surface-a: no live backend to withdraw %s", owned.FQDN)
	}
	rec, err := buildHostRecord(owned.FQDN, a, owned.TTL)
	if err != nil {
		m.deleteFail++
		return err
	}
	if err := backend.DeleteLease(ctx, rec); err != nil {
		m.deleteFail++
		return fmt.Errorf("ddns surface-a: withdraw %s %s: %w", owned.ForwardType, owned.FQDN, err)
	}
	m.deleteOK++
	m.state.delete(owned.scopeOf(), owned.Identity, owned.Address)
	delete(m.runtime, owned.scopeOf().scopePrefix())
	slog.Info("ddns surface-a: withdrew record", "fqdn", owned.FQDN, "addr", owned.AddrText)
	return nil
}

// backendFor resolves the live Backend for a scope's provider (resolve-per-
// Reconcile). The static `backend` field (test injection) wins when set.
func (m *SurfaceAManager) backendFor(sc SurfaceAScope) (DNSUpdater, error) {
	if m.newBackend == nil {
		if m.backend != nil {
			return m.backend, nil
		}
		return nopUpdater{}, nil
	}
	return m.newBackend(sc.Provider, sc.FQDN, sc.TTL)
}

// backendForOwned resolves the live Backend for a WITHDRAW of an owned record
// whose binding was REMOVED from config, so there is no live SurfaceAScope to
// read the provider from (#2691 P2 MAJOR-2). It REBUILDS the SAME backend the
// publish used by looking the owned record's provider (scope.PolicyID) up in the
// still-committed provider catalog and feeding it through newBackend — so a
// removed-binding withdraw sends a real DNS DELETE instead of orphaning the RR.
// The static `backend` field (test injection) wins when set; when no factory and
// no static backend are available the no-op is returned (and withdrawOwnedLocked
// treats it as a failure that keeps ownership for retry, never a false success).
func (m *SurfaceAManager) backendForOwned(owned ownedRecord, catalog map[string]*config.DDNSProvider) (DNSUpdater, error) {
	if m.backend != nil {
		return m.backend, nil
	}
	if m.newBackend == nil {
		return nopUpdater{}, nil
	}
	policyID := owned.scopeOf().PolicyID
	prov := catalog[policyID]
	if prov == nil {
		// The provider was removed alongside the binding: no credentials/server
		// to rebuild the backend, so the RR cannot be withdrawn this cycle.
		slog.Warn("ddns surface-a: owned record's provider is no longer in the catalog; cannot withdraw",
			"fqdn", owned.FQDN, "provider", policyID)
		return nopUpdater{}, nil
	}
	return m.newBackend(prov, owned.FQDN, owned.TTL)
}

// recordScopeError records a failure on a scope and advances its flat error
// backoff (inadyn idea #8): nextEligible = now + backoff, doubling from
// surfaceABaseBackoff up to the cap. Surfaced via lastErr for observability.
func (m *SurfaceAManager) recordScopeError(rt *surfaceAState, sc SurfaceAScope, err error, now time.Time) {
	maxBackoff := sc.ErrorBackoffMax
	if maxBackoff <= 0 {
		maxBackoff = defaultErrorBackoffMax
	}
	if rt.backoff <= 0 {
		rt.backoff = surfaceABaseBackoff
	} else {
		rt.backoff *= 2
	}
	if rt.backoff > maxBackoff {
		rt.backoff = maxBackoff
	}
	rt.nextEligible = now.Add(rt.backoff)
	rt.lastErr = err.Error()
	rt.lastErrAt = now
	slog.Warn("ddns surface-a: scope publish failed; backing off",
		"fqdn", sc.FQDN, "backoff", rt.backoff, "err", err)
}

// StatusViews returns a stable-ordered snapshot of every Surface A scope's
// current publish state for the operator surfaces (plan §5.5 observability). It
// merges the durable ownership store (what is published) with the in-memory
// runtime state (last-published time + last error).
func (m *SurfaceAManager) StatusViews() []SurfaceAStatusView {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SurfaceAStatusView, 0, len(m.state.records))
	for _, r := range m.state.all() {
		sc := r.scopeOf()
		v := SurfaceAStatusView{
			Interface: sc.Interface,
			Unit:      sc.Unit,
			Family:    int(sc.Family),
			FQDN:      r.FQDN,
			Provider:  sc.PolicyID,
			Published: r.AddrText,
		}
		if rt := m.runtime[sc.scopePrefix()]; rt != nil {
			v.LastPublished = rt.lastPublished
			v.LastError = rt.lastErr
			v.LastErrorAt = rt.lastErrAt
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FQDN != out[j].FQDN {
			return out[i].FQDN < out[j].FQDN
		}
		return out[i].Family < out[j].Family
	})
	return out
}

// SurfaceAStats is the counter snapshot for `show` + Prometheus (plan §5.5).
type SurfaceAStats struct {
	Scopes           int
	UpsertOK         uint64
	UpsertFail       uint64
	DeleteOK         uint64
	DeleteFail       uint64
	Skipped          uint64
	BackedOff        uint64
	SkippedNoBackend uint64
}

// Stats returns the current Surface A counters.
func (m *SurfaceAManager) Stats() SurfaceAStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return SurfaceAStats{
		Scopes:           len(m.state.records),
		UpsertOK:         m.upsertOK,
		UpsertFail:       m.upsertFail,
		DeleteOK:         m.deleteOK,
		DeleteFail:       m.deleteFail,
		Skipped:          m.skipped,
		BackedOff:        m.backedOff,
		SkippedNoBackend: m.skippedNoBackend,
	}
}

// buildHostRecord constructs the forward-only A/AAAA record for a Surface A
// router record (no PTR — Surface A publishes the firewall's forward name; PTR
// for the firewall's own address is an operator/ISP concern, not auto-managed).
// The FQDN is normalized against an EMPTY zone (finalizeFQDN keeps a dotted
// operator-supplied name verbatim, a bare label as-is) so an absolute name like
// wan.example.net is published exactly.
func buildHostRecord(fqdn string, addr netip.Addr, ttl int) (LeaseDNSRecord, error) {
	// Surface A operator FQDNs are ABSOLUTE (the operator picks the full name,
	// unlike the DHCP-lease path where the client picks the host part and the
	// firewall picks the zone). finalizeFQDN("",...) would reduce a dotted name
	// to its first label, which is wrong for "wan.example.net" — so use a
	// dotted-structure-preserving per-label sanitize instead.
	name := surfaceAName(fqdn)
	if name == "" {
		return LeaseDNSRecord{}, fmt.Errorf("ddns surface-a: hostname %q sanitizes to empty", fqdn)
	}
	a := addr.Unmap()
	if ttl <= 0 {
		ttl = defaultDDNSTTL
	}
	rec := LeaseDNSRecord{
		FQDN: name,
		Addr: a,
		TTL:  ttl,
	}
	if a.Is4() {
		rec.ForwardType = "A"
	} else if a.Is6() {
		rec.ForwardType = "AAAA"
	} else {
		return LeaseDNSRecord{}, fmt.Errorf("ddns surface-a: record %q has an unspecified address", fqdn)
	}
	return rec, nil
}

// surfaceAName normalizes an operator-supplied Surface A hostname. Unlike the
// DHCP-lease path (where the CLIENT supplies the name and the FIREWALL picks the
// zone), the OPERATOR supplies the full FQDN here, so the name is honored
// verbatim after a per-label LDH sanitize that preserves the dotted structure
// (so wan.example.net stays wan.example.net), trimming a trailing dot. An empty
// result ("" — the input had no usable label) is returned so the caller errors
// rather than publishing junk.
func surfaceAName(fqdn string) string {
	return sanitizeFQDN(fqdn)
}

// familyInt returns the engine family int (4/6) for an address.
func familyInt(a netip.Addr) int {
	if a.Unmap().Is4() {
		return 4
	}
	return 6
}
