package dhcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
// since increment 2, the Prometheus collector). All counters are monotonic.
type DDNSStats struct {
	Enabled          bool
	Backend          string
	UpsertOK         uint64
	UpsertFail       uint64
	DeleteOK         uint64
	DeleteFail       uint64
	SkippedNoName    uint64
	SkippedNoBackend uint64 // records skipped because no live backend is wired
	// SkippedPTRNotAuth counts reverse-zone PTR updates skipped because the
	// authoritative server returned NOTAUTH/REFUSED for the reverse zone —
	// a reverse zone we do not own (e.g. delegated to an ISP). The forward
	// A/AAAA add still succeeded; the lease's reconcile is not failed
	// (#1387 inc-2, plan §11 Q6).
	SkippedPTRNotAuth uint64
	// SkippedConflict counts adds skipped under conflict-policy skip-existing
	// because the exact RR already existed at the server (plan §4.1).
	SkippedConflict uint64
	// PTRDeferred counts upserts where the forward A/AAAA published but the
	// reverse PTR add failed with a non-skippable (transient) error: ownership
	// is recorded for the live forward (never orphaned) and the PTR is retried
	// on the next reconcile (#2661).
	PTRDeferred uint64
	// ReconcileOK / ReconcileFail count whole reconcile passes by outcome
	// (a pass is "fail" when at least one record op errored this cycle).
	ReconcileOK    uint64
	ReconcileFail  uint64
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

	// newUpdater resolves the live DNS-update backend from the policy +
	// config resolved at the start of each Reconcile (plan §6 fork 1:
	// resolve-per-Reconcile). When nil (tests that inject a fixed updater,
	// or the always-on idle-when-disabled production manager before its
	// first enabled reconcile) the manager uses the static `updater` field.
	// Resolving per cycle means a backend-config change at commit takes
	// effect on the next reconcile with no swap race and no stale capture;
	// it also lets ONE always-constructed manager serve both the disabled
	// (nopUpdater) and enabled (rfc2136Updater) states so enabled→disabled
	// still runs withdrawAllLocked through a live backend (plan §4.2).
	newUpdater func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error)

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
	upsertOK          atomic.Uint64
	upsertFail        atomic.Uint64
	deleteOK          atomic.Uint64
	deleteFail        atomic.Uint64
	skippedNoName     atomic.Uint64
	skippedNoBackend  atomic.Uint64 // upsert/delete skipped: no live backend wired
	skippedPTRNotAuth atomic.Uint64 // reverse-zone PTR skipped (NOTAUTH/REFUSED)
	skippedConflict   atomic.Uint64 // add skipped: exact RR already exists
	ptrDeferred       atomic.Uint64 // forward published, PTR add failed (retry next cycle)
	reconcileOK       atomic.Uint64 // reconcile passes with no record-op error
	reconcileFail     atomic.Uint64 // reconcile passes with >=1 record-op error

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
	if updater == nil {
		// Increment 1 defers the live backend: a nil updater becomes a
		// logged no-op rather than a nil-pointer panic on first publish or
		// withdraw. The reconciler stays nil-safe end to end.
		slog.Info("ddns: no DNS-update backend wired; running in no-op mode " +
			"(record reconcile logged-and-skipped until a backend exists)")
		updater = nopUpdater{}
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

// NewProductionDDNSManager constructs the always-on production manager
// (#1387 increment 2, plan §4.2). It is built UNCONDITIONALLY at daemon
// start regardless of whether DDNS is currently enabled, and resolves the
// live RFC 2136 backend from the policy at the START OF EACH Reconcile so a
// commit-time backend-config change takes effect on the next cycle, and so
// the SAME manager can withdraw records when DDNS is turned off (it always
// has a running loop). When the active config has no usable backend the
// manager resolves to the nopUpdater and keeps reconciling (idle).
func NewProductionDDNSManager(nodeID string) *DDNSManager {
	m := NewDDNSManager(nopUpdater{}, nodeID)
	m.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		// Only the live rfc2136 backend is wired in inc-2 (kea-d2 reserved).
		if pol.backend != "rfc2136" {
			return nopUpdater{}, nil
		}
		if c == nil || c.UpdateServer == "" {
			// Enabled but nothing to update — stay no-op (the commit warning
			// already told the operator). Counts as no-backend skips.
			return nopUpdater{}, nil
		}
		return newRFC2136Updater(pol, c, nil,
			func() { m.skippedPTRNotAuth.Add(1) },
			func() { m.skippedConflict.Add(1) })
	}
	return m
}

// newDDNSManagerForTesting builds a manager with an in-memory state store
// at statePath and injectable lease paths / clock. Exported-for-test via
// test_seams.go.
func newDDNSManagerForTesting(updater DNSUpdater, statePath, leasePath4, leasePath6, nodeID string, now func() time.Time) *DDNSManager {
	st, _ := loadDDNSState(statePath)
	if updater == nil {
		updater = nopUpdater{}
	}
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

	// Resolve the live backend from the policy resolved THIS cycle (plan §6
	// fork 1: resolve-per-Reconcile). A nil factory keeps the static updater
	// (tests inject a fixed fakeUpdater). A factory error (bad TSIG /
	// unusable policy) falls back to the no-op so reconcile never wedges and
	// a malformed backend cannot crash the loop — it is logged + counted as
	// a no-backend cycle. This MUST run even when disabled so a turn-off
	// resolves the live backend that published the records and can withdraw
	// them (else the static nop would silently no-op the withdraw).
	if m.newUpdater != nil {
		up, err := m.newUpdater(pol, ddns)
		if err != nil {
			slog.Warn("ddns: cannot build DNS-update backend; staying no-op this cycle", "err", err)
			up = nopUpdater{}
		}
		// Do NOT replace a LIVE updater with a nop while owned records still
		// need withdrawing. The whole-stanza removal (DynamicDNS=nil) resolves
		// the factory to a nopUpdater (no update-server/TSIG left to build the
		// live backend from), and the !pol.enabled branch below would then run
		// withdrawAllLocked THROUGH the nop — dropping ownership entries while
		// sending no real DNS delete, orphaning the records this firewall
		// published. Keep the existing live updater for THIS withdraw cycle so
		// the backend that published the records also withdraws them; the swap
		// to nop happens on the next cycle once nothing is owned. (Disable via
		// Enabled=false while keeping the backend config still resolves a live
		// updater here, so that path is unaffected.)
		if isNopUpdater(up) && !isNopUpdater(m.updater) && len(m.state.records) > 0 {
			slog.Debug("ddns: keeping live updater this cycle to withdraw owned records " +
				"before swapping to no-op")
		} else {
			m.updater = up
		}
	}

	if !pol.enabled {
		err := m.withdrawAllLocked(ctx)
		m.recordReconcilePass(err)
		return err
	}

	now := m.now()
	leases4, err4 := parseActiveLeases4(m.leasePath4, now)
	if err4 != nil {
		slog.Warn("ddns: parse v4 leases failed; suppressing v4 deletes this cycle", "err", err4)
	}
	leases6, err6 := parseActiveLeases6(m.leasePath6, now)
	if err6 != nil {
		slog.Warn("ddns: parse v6 leases failed; suppressing v6 deletes this cycle", "err", err6)
	}
	leases := append(leases4, leases6...)

	// Fail-safe: when a family's lease CSV cannot be read/parsed, its lease
	// set is unreliable (nil/partial) and EVERY owned record of that family
	// would look expired -> eligible for deletion. We must never delete owned
	// records on the basis of an unreadable source of truth, so mark that
	// family as untrusted and the reconciler skips its destructive diff this
	// cycle. The error is surfaced to the caller so the loop logs/counts it.
	untrusted := map[int]bool{}
	if err4 != nil {
		untrusted[4] = true
	}
	if err6 != nil {
		untrusted[6] = true
	}
	recErr := m.reconcileOnceLocked(ctx, pol, leases, untrusted)
	// A reconcile pass "fails" when any record op errored OR a family's lease
	// CSV was unreadable (its destructive diff was suppressed — an incomplete
	// pass). Surface the first error to the loop for logging.
	passErr := recErr
	if passErr == nil {
		if err4 != nil {
			passErr = err4
		} else if err6 != nil {
			passErr = err6
		}
	}
	m.recordReconcilePass(passErr)
	return passErr
}

// recordReconcilePass tallies a whole reconcile pass by outcome (plan §4.4
// reconcile_runs_total{result}). A nil err is an "ok" pass; a non-nil err
// (record-op failure or an unreadable lease family) is a "fail" pass.
func (m *DDNSManager) recordReconcilePass(err error) {
	if err != nil {
		m.reconcileFail.Add(1)
		return
	}
	m.reconcileOK.Add(1)
}

// reconcileOnceLocked is the pure reconcile algorithm (plan §4.5): build
// the desired DNS state from active leases, diff against owned state, and
// apply add / move / reassign / expire transitions — each reconciled
// against owned state so the never-delete-non-owned boundary holds. Caller
// holds m.mu. Exposed (unexported) so tests drive it with synthetic
// leases + a fakeUpdater.
// untrusted maps a lease family (4 or 6) to true when that family's lease
// CSV could not be read/parsed this cycle. The reconciler skips the
// destructive diff (deletes) for an untrusted family so a transient
// malformed lease file can never mass-delete that family's owned records.
// A nil map means all families are trusted.
func (m *DDNSManager) reconcileOnceLocked(ctx context.Context, pol ddnsPolicy, leases []ddnsLease, untrusted map[int]bool) error {
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
	// Reassignment (a new client taking over an address a different client
	// held) is cleaned by the owned-state delete pass below, NOT a separate
	// tracker: the old owner's (identity,address) key is no longer in `want`
	// (the new client has a different identity), so Pass 1 deletes the old
	// owned record before Pass 2 adds the new one (delete-before-add on a
	// shared address; a failed delete blocks the add via the blocked maps).
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
		// Carry the lease identity onto the published record so the live
		// backend can derive the RFC 4701 DHCID ownership marker. The
		// address-fallback identity ("addr:<addr>") is intentionally NOT a
		// DHCID source — only a real client identity proves ownership — so the
		// raw lease identity (possibly empty) is what the backend hashes.
		rec.ClientID = l.Identity
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
			ClientID:    l.Identity,
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
			// The published forward/reverse tuple is unchanged. If the owned
			// record still owes its reverse PTR (#2661 partial success), leave it
			// owned (do NOT delete the live forward) but do NOT mark it settled —
			// fall through so Pass 2 re-runs the upsert and re-attempts the PTR
			// (the forward re-add is an idempotent no-op).
			if !owned.PTRPending {
				d.seen = true // fully published; no add needed below
			}
			continue
		}
		// Fail-safe (#1387 MAJOR-4): if this owned record's family had an
		// unreadable/partial lease CSV this cycle, its "expired" appearance
		// is untrustworthy — skip the delete entirely. Mark the record as
		// seen so the add pass does not re-publish it either; leave the
		// ownership entry intact for a later, trustworthy reconcile.
		if untrusted[owned.Family] {
			if stillWanted {
				d.seen = true
			}
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

// upsertLocked publishes a record and records ownership on success. With no
// live backend (nopUpdater), the upsert is a logged no-op AND ownership is
// deliberately NOT recorded: recording ownership for a record that never
// reached a real backend would (a) leave the store claiming records that do
// not exist in DNS and (b) cause a later real backend to skip them as
// "already owned". So the no-op path counts the skip and returns success
// (reconcile must not wedge) without mutating the ownership store.
//
// REPLACE-OWNED REFUSAL (#2648 MAJOR-1): a replace-owned add that REFUSES a
// name owned by another party returns errDDNSConflictRefused. That is neither
// a success nor a hard failure — it means "someone else owns this name". It is
// classified like the nop-skip: NO ownership is recorded and the reconcile is
// NOT marked failed. Recording phantom ownership for a refused add would let a
// later release delete a record xpf did not create (for a no-identity lease,
// whose delete has no DHCID-match guard, that delete actually fires).
func (m *DDNSManager) upsertLocked(ctx context.Context, rec LeaseDNSRecord, ow ownedRecord) error {
	if err := m.updater.UpsertLease(ctx, rec); err != nil {
		if errors.Is(err, errDDNSConflictRefused) {
			// Refused (name owned by another party): count it as a conflict
			// skip already done by the backend; record NO ownership and do not
			// fail the reconcile pass.
			return nil
		}
		if errors.Is(err, errDDNSPTRPending) {
			// PARTIAL SUCCESS (#2661): the forward A/AAAA is LIVE in DNS but the
			// reverse PTR add failed with a non-skippable (transient) error. We
			// MUST record ownership of the forward so it is tracked + cleanable —
			// recording NO ownership here (the pre-#2661 behavior) would orphan a
			// live forward record. Record ownership with PTRPending set so the
			// next reconcile re-runs UpsertLease (an idempotent forward re-add)
			// and re-attempts the still-missing PTR. The PTR failure is counted
			// and logged so it is observable; the reconcile pass is NOT failed
			// (the forward succeeded and the PTR retry converges on its own), the
			// same non-fatal treatment as a NOTAUTH skip.
			m.ptrDeferred.Add(1)
			slog.Warn("ddns: forward published but reverse PTR add failed; "+
				"recording ownership with PTR pending for retry next cycle",
				"fqdn", rec.FQDN, "ptr", rec.PTRName, "err", err)
			ow.PTRPending = true
			m.upsertOK.Add(1)
			m.state.put(ow)
			return nil
		}
		m.upsertFail.Add(1)
		return err
	}
	if isNopUpdater(m.updater) {
		m.skippedNoBackend.Add(1)
		return nil
	}
	m.upsertOK.Add(1)
	// A fully-successful upsert settles any prior pending-PTR state.
	ow.PTRPending = false
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
	// Replay the EXACT client identity the record was published with so the
	// backend recomputes the same RFC 4701 DHCID — the delete prerequisite
	// then proves xpf owns the record before removing it.
	rec.ClientID = owned.ClientID
	if err := m.updater.DeleteLease(ctx, rec); err != nil {
		m.deleteFail.Add(1)
		return err
	}
	if isNopUpdater(m.updater) {
		// No live backend: the delete was a logged no-op. Still drop the
		// ownership entry. For increment 1 this is CORRECT: nopUpdater never
		// published anything, so there is nothing in DNS to orphan by
		// forgetting ownership. CAVEAT (increment 2+): if a real backend is
		// ever wired, publishes records, and is later removed (a downgrade
		// back to no-backend), dropping ownership here would orphan those
		// previously-published records in DNS. Handling that downgrade is an
		// increment-2 concern; there is NO logic change for inc-1, where the
		// store can only ever hold records nopUpdater "wrote" (i.e. none).
		m.skippedNoBackend.Add(1)
		m.state.delete(owned.Identity, owned.Address)
		return nil
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

// DDNSOwnedRecordView is a read-only projection of one owned record for
// `show ... dynamic-dns detail`. It deliberately omits the owner watermark
// (an internal hash) and exposes only the published tuple.
type DDNSOwnedRecordView struct {
	Family      int
	FQDN        string
	ForwardType string
	Address     string
	PTRName     string
	TTL         int
}

// OwnedRecordViews returns a stable-ordered snapshot of the records this
// node currently owns (published into DNS). Used by the show command.
func (m *DDNSManager) OwnedRecordViews() []DDNSOwnedRecordView {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := m.state.all()
	out := make([]DDNSOwnedRecordView, 0, len(all))
	for _, r := range all {
		out = append(out, DDNSOwnedRecordView{
			Family:      r.Family,
			FQDN:        r.FQDN,
			ForwardType: r.ForwardType,
			Address:     r.Address,
			PTRName:     r.PTRName,
			TTL:         r.TTL,
		})
	}
	return out
}

// Stats returns the current observable counters for `show ... dynamic-dns`.
func (m *DDNSManager) Stats() DDNSStats {
	m.mu.Lock()
	n := len(m.state.records)
	m.mu.Unlock()

	st := DDNSStats{
		UpsertOK:          m.upsertOK.Load(),
		UpsertFail:        m.upsertFail.Load(),
		DeleteOK:          m.deleteOK.Load(),
		DeleteFail:        m.deleteFail.Load(),
		SkippedNoName:     m.skippedNoName.Load(),
		SkippedNoBackend:  m.skippedNoBackend.Load(),
		SkippedPTRNotAuth: m.skippedPTRNotAuth.Load(),
		SkippedConflict:   m.skippedConflict.Load(),
		PTRDeferred:       m.ptrDeferred.Load(),
		ReconcileOK:       m.reconcileOK.Load(),
		ReconcileFail:     m.reconcileFail.Load(),
		OwnedRecords:      n,
		LastReconcileN:    int(m.lastReconcileN.Load()),
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
