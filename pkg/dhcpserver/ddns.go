package dhcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// ddns.go: the DHCP dynamic-DNS manager + reconciler core (#1387,
// increment 1 per docs/research/1387-dhcp-ddns/plan.md). This is the
// fully-unit-testable slice: config-driven policy, the state-aware lease
// parser, the never-delete-non-owned ownership store, and the
// build-desired / diff-owned / transition reconcile algorithm driven
// through a pluggable DNSUpdater. Tests drive reconcileOnce directly with
// synthetic leases and a fakeUpdater (zero network/DNS dependency).
//
// DELIBERATELY OUT OF SCOPE for increment 1 (deferred, see plan §12):
//   - the LIVE rfc2136 DNSUpdater backend (lab-gated increment 2);
//   - HA ownership coupling to VRRP MASTER/BACKUP (test-failover-gated
//     increment 3);
//   - the Kea D2 backend (reserved enum; increment 4);
//   - Prometheus emission through pkg/api (the API collector is a CHECKED
//     collector — declaring a desc without emitting it breaks the
//     descriptor-coverage canary; counters live here and surface via
//     Stats() until a value source on the server exists in increment 2).
//
// When DynamicDNS is nil or disabled the manager does nothing — net
// behaviour change for existing users is zero.

// ddnsPolicy is the resolved, runtime-shaped DDNS configuration the
// reconciler consumes. It is derived from config.DHCPDynamicDNSConfig at
// reconcile time so the reconciler never holds a stale captured cfg
// (plan §5 invariant 1).
type ddnsPolicy struct {
	enabled        bool
	domain         string
	ttl            int
	hostnameSource string
	conflictPolicy string
	backend        string
}

// policyFromConfig resolves a typed config block into a runtime policy,
// applying defaults. A nil or disabled block yields enabled=false.
func policyFromConfig(c *config.DHCPDynamicDNSConfig) ddnsPolicy {
	if c == nil {
		return ddnsPolicy{}
	}
	p := ddnsPolicy{
		enabled:        c.Enabled,
		domain:         c.Domain,
		ttl:            c.TTLSeconds,
		hostnameSource: c.HostnameSource,
		conflictPolicy: c.ConflictPolicy,
		backend:        c.Backend,
	}
	if p.ttl <= 0 {
		p.ttl = defaultDDNSTTL
	}
	if p.backend == "" {
		p.backend = "rfc2136"
	}
	if p.conflictPolicy == "" {
		p.conflictPolicy = "replace-owned"
	}
	return p
}

// DDNSStats is the observable counter snapshot surfaced by `show` (and,
// in increment 2, the Prometheus collector). All counters are monotonic.
type DDNSStats struct {
	Enabled        bool
	Backend        string
	UpsertOK       uint64
	UpsertFail     uint64
	DeleteOK       uint64
	DeleteFail     uint64
	SkippedNoName  uint64
	OwnedRecords   int
	LastReconcile  time.Time
	LastReconcileN int // active leases seen on the last reconcile
}

// DDNSManager owns the DDNS reconcile loop and the ownership store. It is
// a SEPARATE type from the Kea Manager (plan §7) so the generation-
// ordered Kea applier is not perturbed.
type DDNSManager struct {
	mu      sync.Mutex
	state   *ddnsState
	updater DNSUpdater

	// nodeID is the deterministic-owner-id seed (plan §5 invariant 2):
	// the owner watermark is derived from the lease identity so EITHER HA
	// node computes the same value, keeping cleanup safe across failover.
	// The HA emission gating itself is increment 3; the watermark is
	// laid down now so the state store is forward-compatible.
	nodeID string

	// lease file paths (overridable for tests).
	leasePath4 string
	leasePath6 string

	// now is injectable for deterministic expiry tests.
	now func() time.Time

	// counters
	upsertOK      atomic.Uint64
	upsertFail    atomic.Uint64
	deleteOK      atomic.Uint64
	deleteFail    atomic.Uint64
	skippedNoName atomic.Uint64

	lastReconcile  atomic.Int64 // unix nanos
	lastReconcileN atomic.Int64

	// last resolved policy (for Stats()).
	lastPolicy atomic.Pointer[ddnsPolicy]
}

// NewDDNSManager constructs a DDNS manager with the given updater backend
// and node id. The ownership store is loaded from defaultDDNSStatePath; a
// corrupt store is reset to empty (fail-open) and the error logged.
func NewDDNSManager(updater DNSUpdater, nodeID string) *DDNSManager {
	st, err := loadDDNSState(defaultDDNSStatePath)
	if err != nil {
		slog.Warn("ddns: ownership state load failed; starting empty", "err", err)
	}
	return &DDNSManager{
		state:      st,
		updater:    updater,
		nodeID:     nodeID,
		leasePath4: "/var/lib/kea/kea-leases4.csv",
		leasePath6: "/var/lib/kea/kea-leases6.csv",
		now:        time.Now,
	}
}

// newDDNSManagerForTesting builds a manager with an in-memory state store
// at statePath and injectable lease paths / clock. Exported-for-test via
// test_seams.go.
func newDDNSManagerForTesting(updater DNSUpdater, statePath, leasePath4, leasePath6, nodeID string, now func() time.Time) *DDNSManager {
	st, _ := loadDDNSState(statePath)
	return &DDNSManager{
		state:      st,
		updater:    updater,
		nodeID:     nodeID,
		leasePath4: leasePath4,
		leasePath6: leasePath6,
		now:        now,
	}
}

// ownerWatermark is the deterministic, node-stable owner id for a lease
// identity (plan §5 invariant 2). It is a hash of identity+address so
// either HA node derives the same value; the node id is folded in only as
// a TXT-marker hint (increment 3), NOT into the delete-matching key.
func (m *DDNSManager) ownerWatermark(identity, address string) string {
	h := sha256.Sum256([]byte(identity + "|" + address))
	return "xpf-dhcp-ddns:" + hex.EncodeToString(h[:8])
}

// Reconcile resolves the policy from cfg and runs one reconcile pass over
// the current lease files. It is the production entry point (the loop and
// HA gating that call it are increment 2/3). A nil/disabled policy is a
// no-op except for one-time cleanup of any previously-owned records when
// the feature is turned OFF (so disabling DDNS withdraws its records).
func (m *DDNSManager) Reconcile(ctx context.Context, cfg *config.DHCPServerConfig) error {
	var ddns *config.DHCPDynamicDNSConfig
	if cfg != nil {
		ddns = cfg.DynamicDNS
	}
	pol := policyFromConfig(ddns)
	m.lastPolicy.Store(&pol)

	m.mu.Lock()
	defer m.mu.Unlock()

	if !pol.enabled {
		return m.withdrawAllLocked(ctx)
	}

	now := m.now()
	leases4, err4 := parseActiveLeases4(m.leasePath4, now)
	if err4 != nil {
		slog.Warn("ddns: parse v4 leases failed", "err", err4)
	}
	leases6, err6 := parseActiveLeases6(m.leasePath6, now)
	if err6 != nil {
		slog.Warn("ddns: parse v6 leases failed", "err", err6)
	}
	leases := append(leases4, leases6...)
	return m.reconcileOnceLocked(ctx, pol, leases)
}

// reconcileOnceLocked is the pure reconcile algorithm (plan §4.5): build
// the desired DNS state from active leases, diff against owned state, and
// apply add / move / reassign / expire transitions — each reconciled
// against owned state so the never-delete-non-owned boundary holds. Caller
// holds m.mu. Exposed (unexported) so tests drive it with synthetic
// leases + a fakeUpdater.
func (m *DDNSManager) reconcileOnceLocked(ctx context.Context, pol ddnsPolicy, leases []ddnsLease) error {
	source := hostnameSourceFor(&pol)
	blockedIdentity := map[string]struct{}{}
	blockedAddress := map[string]struct{}{}
	blockedFQDN := map[string]struct{}{}

	// desired[key] = the record we want owned for that identity+address.
	type desired struct {
		rec  LeaseDNSRecord
		ow   ownedRecord
		seen bool
	}
	want := map[string]*desired{}
	// addrOwner tracks which identity currently wants a given address, so
	// a reassignment (new client, same address) cleans the old owner.
	for _, l := range leases {
		fqdn, err := deriveFQDN(l.HostName, l.ClientFQDN, l.Identity, pol.domain, source)
		if err != nil {
			m.skippedNoName.Add(1)
			slog.Debug("ddns: skipping lease with no publishable name",
				"address", l.Address, "err", err)
			continue
		}
		rec, err := buildLeaseRecord(fqdn, l.Address, pol.ttl)
		if err != nil {
			slog.Warn("ddns: skipping lease with invalid address", "err", err)
			continue
		}
		identity := l.Identity
		if identity == "" {
			// No stable identity: key ownership on the address alone so
			// reassignment still cleans (the address is the reverse key).
			identity = "addr:" + l.Address
		}
		ow := ownedRecord{
			Family:      l.Family,
			Identity:    identity,
			SubnetID:    l.SubnetID,
			Address:     l.Address,
			FQDN:        rec.FQDN,
			ForwardType: rec.ForwardType,
			PTRName:     rec.PTRName,
			TTL:         rec.TTL,
			OwnerID:     m.ownerWatermark(identity, l.Address),
		}
		want[ownedRecordKey(identity, l.Address)] = &desired{rec: rec, ow: ow}
	}

	var firstErr error
	noteErr := func(e error) {
		if e != nil && firstErr == nil {
			firstErr = e
		}
	}

	// Pass 1 — expire / reassign: delete every owned record that is NOT
	// in the desired set, OR whose desired record set changed (address
	// moved, name changed). Cleaning before adding is what makes
	// reassignment safe (delete the old owner first).
	for _, owned := range m.state.all() {
		key := ownedRecordKey(owned.Identity, owned.Address)
		d, stillWanted := want[key]
		if stillWanted && recordsEqual(owned, d.ow) {
			d.seen = true // unchanged; no add needed below
			continue
		}
		// Owned but not wanted (expired/released) OR wanted differently
		// (the desired pass below re-adds the new form). Delete only the
		// EXACT owned tuple — never anything not in the store.
		if err := m.deleteOwnedLocked(ctx, owned); err != nil {
			noteErr(err)
			blockedIdentity[owned.Identity] = struct{}{}
			blockedAddress[owned.Address] = struct{}{}
			blockedFQDN[owned.FQDN] = struct{}{}
			// leave it in the store so a later reconcile retries the
			// delete (bounded by the loop cadence; never wedges).
			continue
		}
	}

	// Pass 2 — add / move: upsert every desired record not already owned
	// in its current exact form.
	for _, d := range want {
		if d.seen {
			continue
		}
		if _, blocked := blockedIdentity[d.ow.Identity]; blocked {
			continue
		}
		if _, blocked := blockedAddress[d.ow.Address]; blocked {
			continue
		}
		if _, blocked := blockedFQDN[d.ow.FQDN]; blocked {
			continue
		}
		if err := m.upsertLocked(ctx, d.rec, d.ow); err != nil {
			noteErr(err)
			continue
		}
	}

	if err := m.state.save(); err != nil {
		slog.Warn("ddns: persist ownership state failed", "err", err)
		noteErr(err)
	}
	m.lastReconcile.Store(m.now().UnixNano())
	m.lastReconcileN.Store(int64(len(leases)))
	return firstErr
}

// withdrawAllLocked deletes every owned record (feature disabled / config
// removed) so turning DDNS off cleans the operator's zone. Records that
// fail to delete stay in the store for a later retry. Caller holds m.mu.
func (m *DDNSManager) withdrawAllLocked(ctx context.Context) error {
	owned := m.state.all()
	if len(owned) == 0 {
		return nil
	}
	var firstErr error
	for _, r := range owned {
		if err := m.deleteOwnedLocked(ctx, r); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := m.state.save(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// upsertLocked publishes a record and records ownership on success.
func (m *DDNSManager) upsertLocked(ctx context.Context, rec LeaseDNSRecord, ow ownedRecord) error {
	if err := m.updater.UpsertLease(ctx, rec); err != nil {
		m.upsertFail.Add(1)
		return err
	}
	m.upsertOK.Add(1)
	m.state.put(ow)
	return nil
}

// deleteOwnedLocked re-derives the EXACT record from owned state and
// deletes it, removing the ownership entry on success. This is the sole
// delete authority — it never constructs a delete from anything but the
// store, so a record xpf did not create can never be deleted.
func (m *DDNSManager) deleteOwnedLocked(ctx context.Context, owned ownedRecord) error {
	rec, err := buildLeaseRecord(owned.FQDN, owned.Address, owned.TTL)
	if err != nil {
		// The stored address no longer parses (should not happen): drop
		// the entry to avoid wedging, but do NOT issue a delete with a
		// guessed name.
		slog.Warn("ddns: owned record has unparseable address; dropping entry",
			"address", owned.Address, "err", err)
		m.state.delete(owned.Identity, owned.Address)
		return nil
	}
	// Force the stored forward type / PTR name (re-derived above should
	// match, but the store is authoritative for what was written).
	rec.ForwardType = owned.ForwardType
	rec.PTRName = owned.PTRName
	if err := m.updater.DeleteLease(ctx, rec); err != nil {
		m.deleteFail.Add(1)
		return err
	}
	m.deleteOK.Add(1)
	m.state.delete(owned.Identity, owned.Address)
	return nil
}

// recordsEqual reports whether two owned records describe the same
// published DNS state (name + type + address + ttl). Identity/subnet
// metadata changes alone do not require a DNS re-write.
func recordsEqual(a, b ownedRecord) bool {
	return a.FQDN == b.FQDN &&
		a.ForwardType == b.ForwardType &&
		a.Address == b.Address &&
		a.PTRName == b.PTRName &&
		a.TTL == b.TTL
}

// Stats returns the current observable counters for `show ... dynamic-dns`.
func (m *DDNSManager) Stats() DDNSStats {
	m.mu.Lock()
	n := len(m.state.records)
	m.mu.Unlock()

	st := DDNSStats{
		UpsertOK:       m.upsertOK.Load(),
		UpsertFail:     m.upsertFail.Load(),
		DeleteOK:       m.deleteOK.Load(),
		DeleteFail:     m.deleteFail.Load(),
		SkippedNoName:  m.skippedNoName.Load(),
		OwnedRecords:   n,
		LastReconcileN: int(m.lastReconcileN.Load()),
	}
	if ns := m.lastReconcile.Load(); ns > 0 {
		st.LastReconcile = time.Unix(0, ns)
	}
	if p := m.lastPolicy.Load(); p != nil {
		st.Enabled = p.enabled
		st.Backend = p.backend
	}
	return st
}
