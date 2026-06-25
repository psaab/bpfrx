package ddns

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

// manager.go (moved verbatim from pkg/dhcpserver/ddns.go in #2691 P1a): the
// DHCP dynamic-DNS manager + reconciler core (#1387, per
// docs/research/1387-dhcp-ddns/plan.md). This is the config-driven policy,
// the never-delete-non-owned ownership store, and the build-desired /
// diff-owned / transition reconcile algorithm driven through a pluggable
// DNSUpdater. The state-aware Kea-memfile lease parser stays in
// pkg/dhcpserver (ddns_leases.go) and is injected as a LeaseParser seam.
// Tests drive reconcileOnce directly with synthetic Leases and a fakeUpdater
// (zero network/DNS dependency).
//
// SHIPPED (no longer deferred):
//   - the LIVE rfc2136 DNSUpdater backend (#1387 inc-2; see
//     ddns_rfc2136.go) — records are published to and withdrawn from the
//     authoritative server over real RFC 2136 UPDATE;
//   - the always-on daemon reconcile loop with the HA writer gate
//     (pkg/daemon/daemon_ddns.go) — a node only publishes when it is the
//     cluster writer (standalone, or MASTER for >=1 redundancy group);
//   - Prometheus emission through pkg/api (the xpf_dhcp_ddns_* counters
//     are exported from Stats()).
//
// SHIPPED in #2691 P1b (this phase):
//   - ScopeKey on ownership records + per-family INDEPENDENT v4/v6 policy
//     (#2663): ReconcileScoped resolves a policy + backend PER FAMILY;
//   - per-RG HA writer gate (#2664): a ScopeGate/ScopeResolver gates the
//     publish decision PER redundancy-group (stop-writing-never-withdraw on a
//     partial demotion), wired from pkg/daemon (ddnsReconcileOptions);
//   - source / interface / VRF binding for the RFC 2136 update socket (#2665,
//     backend_bind.go).
//
// STILL DEFERRED:
//   - the Kea D2 backend (reserved enum; not in the image — bake.py);
//   - router/interface-address publish (Surface A) + the HTTP provider
//     backends (dyndns2/Cloudflare/Route53/generic) — the #2691 world-class
//     redesign phases P2-P3.
//
// When DynamicDNS is nil or disabled the manager does nothing except a
// one-time withdraw of any previously-owned records (turn-off cleanup) —
// net behaviour change for existing users is zero.

// Lease is the reconcile-relevant view of one active DHCP lease the engine
// consumes (#2691 P1a). It is the DDNS subset of the Kea-memfile lease record
// (pkg/dhcpserver.ddnsLease): the fields the reconciler keys ownership and
// naming on. The full memfile record (v6 lease-type / prefix-len fields used
// only by the lease-sync fallback) stays in pkg/dhcpserver; its parser
// converts each row into this struct at the LeaseParser boundary. Fields are
// a 1:1 copy of the previously-internal ddnsLease fields the reconciler read.
type Lease struct {
	Family     int    // 4 or 6
	Address    string // textual leased address
	Identity   string // v4: client-id||hwaddr ; v6: DUID/IAID
	SubnetID   string // pool/subnet metadata
	HostName   string // host-name option
	ClientFQDN string // client-supplied FQDN option (fqdn_fwd implied)
}

// LeaseParser reads a family's (4 or 6) active leases from a Kea memfile path
// as of now. It is the seam through which pkg/dhcpserver's Kea-memfile parser
// feeds the engine (#2691 P1a). An error means the family's lease set is
// unreliable this cycle; the reconciler then marks the family untrusted and
// skips its destructive diff (the mass-delete fail-safe).
type LeaseParser func(path string, family int, now time.Time) ([]Lease, error)

// ddnsPolicy is the resolved, runtime-shaped DDNS configuration the
// reconciler consumes. It is derived from config.DHCPDynamicDNSConfig at
// reconcile time so the reconciler never holds a stale captured cfg
// (plan §5 invariant 1).
//
// #2691 P1b — one ddnsPolicy is resolved PER FAMILY (#2663 independent v4/v6
// policy). The v4 and v6 lease sets are now reconciled with their OWN policy +
// own backend, so a v4 conflict, a v4 backend failure, or a v4 turn-off can
// never affect v6 publishing (and vice-versa).
type ddnsPolicy struct {
	enabled        bool
	domain         string
	ttl            int
	hostnameSource string
	conflictPolicy string
	backend        string
}

// ScopeGate decides whether THIS node may publish records for a given scope
// (#2691 P1b / #2664 the per-RG HA writer gate). It returns true when the
// scope is writable from here: standalone always true; in a cluster, true IFF
// the local node is the MASTER for scope.RGOwner. A nil gate (the standalone
// Reconcile entry point and existing tests) means "every scope is writable".
//
// FAIL-CLOSED CONTRACT (#2664): the daemon's gate returns FALSE for any scope
// whose RG ownership is uncertain (a lease whose address falls in no
// master-owned subnet, or whose RG cannot be attributed). A scope the gate
// rejects is NOT published — but it is also NOT withdrawn (stop-writing, never
// withdraw: the peer that became MASTER for that RG refreshes the record; a
// withdraw race would blackhole, plan §5.6 / risk R3). The reconciler enforces
// this by treating a gated-out OWNED record exactly like an untrusted family:
// it is left in the store, never deleted, and never re-published from here.
type ScopeGate func(ScopeKey) bool

// ScopeResolver attributes a lease to the redundancy group (and, in later
// phases, the interface/unit/routing-instance) that OWNS it (#2691 P1b). The
// daemon supplies it from the committed DHCP config: a lease address is mapped
// to its pool subnet → group → interface → redundancy-group (stable CIDR
// membership, NOT the per-render-unstable Kea subnet_id, plan §6 fork 2). It
// returns the scope's RG owner and ok=false when the lease cannot be attributed
// to any known scope — which the gate then treats as fail-closed (not
// published). A nil resolver (standalone / tests) yields the zero scope for the
// family (RGOwner 0), which a nil gate always admits.
type ScopeResolver func(l Lease) (ScopeKey, bool)

// ReconcileOptions carries the HA scope wiring for one reconcile pass (#2691
// P1b). All fields are optional; the zero value is the standalone behaviour
// (every scope writable, leases keyed by family only). The daemon populates
// Gate + Resolver so the per-RG writer gate and per-family/per-RG ownership
// scoping take effect.
type ReconcileOptions struct {
	// Gate is the per-scope HA writer gate (#2664). Nil ⇒ all scopes writable.
	Gate ScopeGate
	// Resolver attributes each lease to its owning scope (RG etc., #2664). Nil
	// ⇒ leases get the zero scope for their family (standalone Surface B).
	Resolver ScopeResolver
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

// Stats is the observable counter snapshot surfaced by `show` (and,
// since increment 2, the Prometheus collector). All counters are monotonic.
type Stats struct {
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

// Manager owns the DDNS reconcile loop and the ownership store. It is
// a SEPARATE type from the Kea Manager (plan §7) so the generation-
// ordered Kea applier is not perturbed.
type Manager struct {
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
	// The HA emission gating (the writer gate in pkg/daemon/daemon_ddns.go)
	// is live; the watermark is node-stable so a failed-over node can clean
	// up records its peer published.
	nodeID string

	// leaseParser reads a family's active-lease set from a Kea memfile path
	// (#2691 P1a). The Kea-memfile parser stays in pkg/dhcpserver
	// (ddns_leases.go — it is entangled with the lease-sync fallback), so the
	// caller injects it here, inverting the dependency: pkg/ddns defines the
	// Lease record + the engine; pkg/dhcpserver supplies the parser. The
	// reconciler treats a parser error for a family as "untrusted" and skips
	// that family's destructive diff (the mass-delete fail-safe). When nil,
	// every family reads empty + trusted (the spine has no leases of its own).
	leaseParser LeaseParser

	// lease file paths (overridable for tests). Passed to leaseParser per
	// reconcile and surfaced via DDNSLeasePaths for cross-package tests.
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

// NewManager constructs a DDNS manager with the given lease parser, updater
// backend, and node id. The ownership store is loaded from
// defaultDDNSStatePath; a corrupt store is reset to empty (fail-open) and the
// error logged. The parser is the LeaseParser seam (the Kea-memfile parser
// lives in pkg/dhcpserver — #2691 P1a); a nil parser means the manager reads
// no leases (every family trusted-empty).
func NewManager(parser LeaseParser, updater DNSUpdater, nodeID string) *Manager {
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
	return &Manager{
		state:       st,
		updater:     updater,
		nodeID:      nodeID,
		leaseParser: parser,
		leasePath4:  "/var/lib/kea/kea-leases4.csv",
		leasePath6:  "/var/lib/kea/kea-leases6.csv",
		now:         time.Now,
	}
}

// NewProductionManager constructs the always-on production manager
// (#1387 increment 2, plan §4.2). It is built UNCONDITIONALLY at daemon
// start regardless of whether DDNS is currently enabled, and resolves the
// live RFC 2136 backend from the policy at the START OF EACH Reconcile so a
// commit-time backend-config change takes effect on the next cycle, and so
// the SAME manager can withdraw records when DDNS is turned off (it always
// has a running loop). When the active config has no usable backend the
// manager resolves to the nopUpdater and keeps reconciling (idle). The parser
// is the Kea-memfile LeaseParser seam injected by pkg/dhcpserver (#2691 P1a).
func NewProductionManager(parser LeaseParser, nodeID string) *Manager {
	m := NewManager(parser, nopUpdater{}, nodeID)
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

// newManagerForTesting builds a manager with an in-memory state store
// at statePath and injectable lease parser / paths / clock. Exported to other
// packages' tests via pkg/dhcpserver's test seam.
func newManagerForTesting(parser LeaseParser, updater DNSUpdater, statePath, leasePath4, leasePath6, nodeID string, now func() time.Time) *Manager {
	st, _ := loadDDNSState(statePath)
	if updater == nil {
		updater = nopUpdater{}
	}
	return &Manager{
		state:       st,
		updater:     updater,
		nodeID:      nodeID,
		leaseParser: parser,
		leasePath4:  leasePath4,
		leasePath6:  leasePath6,
		now:         now,
	}
}

// NewManagerForTesting builds a Manager with injectable lease parser, state +
// lease paths, clock, and a per-Reconcile updater factory. It is the exported
// seam OTHER packages' tests use (via pkg/dhcpserver.NewDDNSManagerForTesting)
// to drive the resolve-per-Reconcile manager without real /var/lib paths.
// updater is the fixed fallback used when newUpdater is nil; newUpdater, when
// non-nil, is the resolve-per-Reconcile factory (the policy is not exposed to
// the caller — only the raw config, matching the pre-#2691-P1a seam shape).
// Moved from pkg/dhcpserver/test_seams.go in #2691 P1a.
func NewManagerForTesting(
	parser LeaseParser,
	updater DNSUpdater,
	statePath, leasePath4, leasePath6, nodeID string,
	now func() time.Time,
	newUpdater func(c *config.DHCPDynamicDNSConfig) (DNSUpdater, error),
) *Manager {
	m := newManagerForTesting(parser, updater, statePath, leasePath4, leasePath6, nodeID, now)
	if newUpdater != nil {
		m.newUpdater = func(_ ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
			return newUpdater(c)
		}
	}
	return m
}

// ownerWatermark is the deterministic, node-stable owner id for a lease
// identity (plan §5 invariant 2). It is a hash of identity+address ONLY —
// the receiver's nodeID is DELIBERATELY NOT folded in — so EITHER HA node
// derives the SAME value for the same lease.
//
// Today this value is an INFORMATIONAL marker only (stored as the
// ownership record's OwnerID); it is NOT the delete-matching key. Record
// cleanup matches on identity+address plus the reconstructed RFC 4701
// DHCID, which is already node-independent, so OwnerID is never compared
// across nodes at present. Keeping the watermark node-independent is
// intentional regardless: it avoids surprises if a future phase ever does
// compare it across nodes (folding nodeID would make the two HA nodes
// disagree for the same lease). (#2691 P0 / #2667: the prior comment
// wrongly claimed nodeID was "folded in as a TXT-marker hint"; it never
// was — the code below is correct, the comment was stale.)
func (m *Manager) ownerWatermark(identity, address string) string {
	h := sha256.Sum256([]byte(identity + "|" + address))
	return "xpf-dhcp-ddns:" + hex.EncodeToString(h[:8])
}

// Reconcile resolves the policy from cfg and runs one reconcile pass over
// the current lease files. It is the production entry point; the always-on
// reconcile loop and the HA writer gate that call it are live in
// pkg/daemon/daemon_ddns.go. A nil/disabled policy is a no-op except for
// one-time cleanup of any previously-owned records when the feature is
// turned OFF (so disabling DDNS withdraws its records).
func (m *Manager) Reconcile(ctx context.Context, cfg *config.DHCPServerConfig) error {
	return m.ReconcileScoped(ctx, cfg, ReconcileOptions{})
}

// reconcileEnv is the per-pass, per-family resolved environment the reconcile
// algorithm + the upsert/delete helpers consume (#2691 P1b). It carries each
// family's INDEPENDENT policy + backend (#2663), plus the HA scope gate +
// resolver (#2664). The helpers select the family slice by a record's Family.
type reconcileEnv struct {
	pol     [2]ddnsPolicy // [0]=v4, [1]=v6
	updater [2]DNSUpdater // [0]=v4, [1]=v6 (resolve-per-Reconcile per family)
	gate    ScopeGate     // per-scope HA writer gate (#2664); nil ⇒ all writable
	res     ScopeResolver // lease→scope attribution (#2664); nil ⇒ zero scope
}

// famIdx maps an engine family int (4/6) to the [2] env slot.
func famIdx(family int) int {
	if family == 6 {
		return 1
	}
	return 0
}

// updaterFor returns the resolved backend for a record's family.
func (e *reconcileEnv) updaterFor(family int) DNSUpdater { return e.updater[famIdx(family)] }

// polFor returns the resolved policy for a family.
func (e *reconcileEnv) polFor(family int) ddnsPolicy { return e.pol[famIdx(family)] }

// scopeAdmits reports whether THIS node may publish records for a scope under
// the gate (#2664). A nil gate admits everything (standalone). Fail-closed is
// the daemon's gate's responsibility (it returns false for an uncertain RG).
func (e *reconcileEnv) scopeAdmits(s ScopeKey) bool {
	if e.gate == nil {
		return true
	}
	return e.gate(s)
}

// scopeFor attributes a lease to its owning scope (#2664). With no resolver
// (standalone / tests) the scope is just the family — the zero-scope global
// lease path, byte-for-byte the pre-P1b ownership key. The resolver's ok=false
// (lease attributable to no known scope) returns the family-only scope with
// admit=false so the caller fail-closes (does not publish), without losing the
// family tag that keeps v4/v6 ownership independent.
func (e *reconcileEnv) scopeFor(l Lease) (scope ScopeKey, admit bool) {
	if e.res == nil {
		// Standalone / no-resolver: the ZERO scope for BOTH families — the
		// global lease key, byte-for-byte the pre-P1b "identity|address"
		// ownership key (no migration, no churn). A v4 and a v6 record never
		// collide on this key because their ADDRESSES differ (an address is
		// either v4 or v6), so the family need not be folded into the key here;
		// per-family POLICY independence (#2663) is delivered by the per-family
		// policy + backend resolution, not by the ownership key. The record's
		// own Family field stays authoritative for the wire op.
		return ScopeKey{}, e.scopeAdmits(ScopeKey{})
	}
	s, ok := e.res(l)
	if !ok {
		// Unattributable lease: fail-closed (#2664). Use a non-zero family-only
		// scope so the gated-out record cannot alias a real global-scope entry;
		// it is dropped (admit=false), so it is never stored anyway.
		return ScopeKey{Family: familyOf(l.Family)}, false
	}
	return s, e.scopeAdmits(s)
}

// ReconcileScoped is the per-family / per-scope reconcile entry point (#2691
// P1b). It resolves an INDEPENDENT policy + backend for the v4 and the v6
// family (#2663), tags every desired record with its ScopeKey (#2664), and
// applies the per-scope HA writer gate (opts.Gate / opts.Resolver). Reconcile
// is the nil-options (standalone, all-scopes-writable) wrapper.
func (m *Manager) ReconcileScoped(ctx context.Context, cfg *config.DHCPServerConfig, opts ReconcileOptions) error {
	var ddns4, ddns6 *config.DHCPDynamicDNSConfig
	if cfg != nil {
		ddns4 = cfg.DynamicDNS
		ddns6 = cfg.DynamicDNSv6
	}
	// BACKWARD COMPATIBILITY (#2663 + plan §5.9): a pre-P1b config carried a
	// SINGLE dynamic-dns block under ONE family that applied to BOTH families
	// (the reconciler walked both lease sets with one policy). To keep those
	// committed configs working byte-for-byte, when only ONE family's block is
	// present the OTHER family INHERITS it. The moment BOTH families set their
	// own block they are fully INDEPENDENT (the #2663 fix). This preserves the
	// single-family case AND delivers per-family independence for the two-block
	// case, with no silent loss of v6 publishing for existing single-block
	// configs.
	if ddns4 == nil && ddns6 != nil {
		ddns4 = ddns6
	} else if ddns6 == nil && ddns4 != nil {
		ddns6 = ddns4
	}
	pol4 := policyFromConfig(ddns4)
	pol6 := policyFromConfig(ddns6)
	// lastPolicy surfaces an aggregate for Stats(): enabled if EITHER family is
	// enabled; backend is the v4 backend when v4 is configured, else v6's.
	agg := pol4
	if !agg.enabled {
		agg = pol6
	}
	if ddns4 == nil && ddns6 != nil {
		agg = pol6
	}
	m.lastPolicy.Store(&agg)

	m.mu.Lock()
	defer m.mu.Unlock()

	env := reconcileEnv{
		pol:     [2]ddnsPolicy{pol4, pol6},
		updater: [2]DNSUpdater{m.updater, m.updater},
		gate:    opts.Gate,
		res:     opts.Resolver,
	}

	// Resolve each family's live backend from THIS cycle's policy (plan §6
	// fork 1: resolve-per-Reconcile, now PER FAMILY — #2663). A nil factory
	// keeps the static updater (tests inject a fixed fakeUpdater). A factory
	// error (bad TSIG / unusable policy) for one family falls back to that
	// family's no-op WITHOUT affecting the other family — independence (#2663).
	if m.newUpdater != nil {
		env.updater[0] = m.resolveFamilyUpdater(pol4, ddns4)
		env.updater[1] = m.resolveFamilyUpdater(pol6, ddns6)
		// Keep the LIVE-updater-for-withdraw guard, now per family: if a family
		// resolved to nop but still owns records (turn-off), keep the prior live
		// updater for THIS withdraw cycle so the backend that published also
		// withdraws (else the nop silently drops ownership, orphaning the live
		// RR — the same hazard the single-family path guards, plan §4.2).
		if isNopUpdater(env.updater[0]) && !isNopUpdater(m.updater) && m.familyOwnsRecords(4) {
			env.updater[0] = m.updater
			slog.Debug("ddns: keeping live v4 updater this cycle to withdraw owned records")
		}
		if isNopUpdater(env.updater[1]) && !isNopUpdater(m.updater) && m.familyOwnsRecords(6) {
			env.updater[1] = m.updater
			slog.Debug("ddns: keeping live v6 updater this cycle to withdraw owned records")
		}
		// Track a single representative live updater for the next-cycle
		// withdraw guard (m.updater is the "last live backend seen" anchor).
		if !isNopUpdater(env.updater[0]) {
			m.updater = env.updater[0]
		} else if !isNopUpdater(env.updater[1]) {
			m.updater = env.updater[1]
		}
	}

	now := m.now()
	untrusted := map[int]bool{}
	var leases []Lease
	var err4, err6 error

	// Per-family enable: a disabled family withdraws ITS OWN records only
	// (#2663 independence — disabling v4 must not touch v6). A family that is
	// enabled feeds its leases into the shared desired set.
	if pol4.enabled {
		l4, e4 := m.parseLeases(m.leasePath4, 4, now)
		err4 = e4
		if e4 != nil {
			slog.Warn("ddns: parse v4 leases failed; suppressing v4 deletes this cycle", "err", e4)
			untrusted[4] = true
		}
		leases = append(leases, l4...)
	} else {
		// v4 disabled: withdraw v4-owned records through the resolved v4
		// updater. Leaving v4 out of `leases` would make Pass 1 try to delete
		// every v4 record anyway, but routing the withdraw explicitly keeps the
		// family-scoped semantics clear and uses the v4 backend.
		untrusted[4] = false
	}
	if pol6.enabled {
		l6, e6 := m.parseLeases(m.leasePath6, 6, now)
		err6 = e6
		if e6 != nil {
			slog.Warn("ddns: parse v6 leases failed; suppressing v6 deletes this cycle", "err", e6)
			untrusted[6] = true
		}
		leases = append(leases, l6...)
	} else {
		untrusted[6] = false
	}

	// disabledFamilies tells the reconciler to WITHDRAW (delete-owned) a
	// family's records rather than skip them: a family that is not enabled has
	// no desired set, so Pass 1 deletes its owned records (turn-off cleanup),
	// while an ENABLED family with an unreadable CSV is untrusted (skip the
	// destructive diff). The two must not be conflated.
	disabled := map[int]bool{4: !pol4.enabled, 6: !pol6.enabled}

	recErr := m.reconcileOnceLocked(ctx, &env, leases, untrusted, disabled)
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

// resolveFamilyUpdater resolves one family's backend from its policy + config,
// falling back to the no-op (logged, counted) on a factory error so one
// family's malformed backend cannot wedge the loop or affect the other family.
func (m *Manager) resolveFamilyUpdater(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) DNSUpdater {
	up, err := m.newUpdater(pol, c)
	if err != nil {
		slog.Warn("ddns: cannot build DNS-update backend; staying no-op this cycle for this family", "err", err)
		return nopUpdater{}
	}
	return up
}

// familyOwnsRecords reports whether the ownership store holds any record of the
// given family — used to keep a live updater for a turn-off withdraw cycle.
func (m *Manager) familyOwnsRecords(family int) bool {
	for _, r := range m.state.records {
		if r.Family == family {
			return true
		}
	}
	return false
}

// parseLeases reads a family's active leases via the injected LeaseParser
// (#2691 P1a). A nil parser (the spine constructed without a Kea-memfile
// parser) yields an empty, trusted lease set — identical to a healthy memfile
// with no active leases. The parser's error is propagated unchanged so the
// caller's untrusted-family fail-safe behaves exactly as before the extraction.
func (m *Manager) parseLeases(path string, family int, now time.Time) ([]Lease, error) {
	if m.leaseParser == nil {
		return nil, nil
	}
	return m.leaseParser(path, family, now)
}

// recordReconcilePass tallies a whole reconcile pass by outcome (plan §4.4
// reconcile_runs_total{result}). A nil err is an "ok" pass; a non-nil err
// (record-op failure or an unreadable lease family) is a "fail" pass.
func (m *Manager) recordReconcilePass(err error) {
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
func (m *Manager) reconcileOnceLocked(ctx context.Context, env *reconcileEnv, leases []Lease, untrusted, disabled map[int]bool) error {
	blockedIdentity := map[string]struct{}{}
	blockedAddress := map[string]struct{}{}
	blockedFQDN := map[string]struct{}{}

	// gatedScope[scopePrefix] = true marks a scope this node may NOT publish
	// for (the per-RG HA writer gate is CLOSED for it, #2664). An owned record
	// in a gated scope is treated EXACTLY like an untrusted family in Pass 1:
	// it is NEVER deleted (stop-writing, never withdraw — the peer MASTER for
	// that RG refreshes it; a withdraw race would blackhole, plan §5.6) and
	// never re-published from here. Tracked by scope-prefix so the Pass-1
	// owned-record loop can ask "is this record's scope gated?" without a
	// resolver (the owned record carries its scope).
	gatedScope := map[string]bool{}

	// desired[key] = the record we want owned for that scope+identity+address.
	type desired struct {
		rec  LeaseDNSRecord
		ow   ownedRecord
		seen bool
	}
	want := map[string]*desired{}
	// Reassignment (a new client taking over an address a different client
	// held) is cleaned by the owned-state delete pass below, NOT a separate
	// tracker: the old owner's (scope,identity,address) key is no longer in
	// `want` (the new client has a different identity), so Pass 1 deletes the
	// old owned record before Pass 2 adds the new one (delete-before-add on a
	// shared address; a failed delete blocks the add via the blocked maps).
	for _, l := range leases {
		pol := env.polFor(l.Family)
		source := hostnameSourceFor(&pol)
		// Resolve the lease's scope + the per-RG HA gate decision (#2664). A
		// gated-out scope is recorded so Pass 1 protects its owned records from
		// deletion, and the desired record is NOT added (stop-writing).
		scope, admit := env.scopeFor(l)
		if !admit {
			gatedScope[scope.scopePrefix()] = true
			slog.Debug("ddns: scope not writable from this node (per-RG gate closed); "+
				"not publishing, not withdrawing",
				"address", l.Address, "rg", scope.RGOwner, "family", l.Family)
			continue
		}
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
		}.withScope(scope)
		want[ownedRecordKey(scope, identity, l.Address)] = &desired{rec: rec, ow: ow}
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
		key := ownedRecordKey(owned.scopeOf(), owned.Identity, owned.Address)
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
		// HA per-RG gate (#2664): if this owned record's scope is gated CLOSED
		// from this node (we are not the MASTER for its RG), STOP WRITING but
		// NEVER WITHDRAW — leave it in the store untouched. The peer that is
		// MASTER for that RG owns the refresh; a withdraw here would race the
		// peer and blackhole (plan §5.6 / risk R3). This is the load-bearing
		// #2664 invariant: a node that loses one RG must not delete that RG's
		// records.
		if gatedScope[owned.scopeOf().scopePrefix()] {
			if stillWanted {
				d.seen = true
			}
			continue
		}
		// Fail-safe (#1387 MAJOR-4): if this owned record's family had an
		// unreadable/partial lease CSV this cycle, its "expired" appearance
		// is untrustworthy — skip the delete entirely. Mark the record as
		// seen so the add pass does not re-publish it either; leave the
		// ownership entry intact for a later, trustworthy reconcile. A DISABLED
		// family (disabled[family]) is NOT untrusted — it has no desired set on
		// purpose, so its owned records SHOULD be withdrawn (turn-off cleanup),
		// so disabled does not protect from delete here.
		if untrusted[owned.Family] && !disabled[owned.Family] {
			if stillWanted {
				d.seen = true
			}
			continue
		}
		// Owned but not wanted (expired/released) OR wanted differently
		// (the desired pass below re-adds the new form). Delete only the
		// EXACT owned tuple — never anything not in the store.
		if err := m.deleteOwnedLocked(ctx, env.updaterFor(owned.Family), owned); err != nil {
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
		if err := m.upsertLocked(ctx, env.updaterFor(d.ow.Family), d.rec, d.ow); err != nil {
			noteErr(err)
			continue
		}
	}

	// End-of-pass durability backstop. Adds are already durable via the
	// per-record write-ahead in upsertLocked (#2662), so this no longer
	// covers the crash-after-add orphan window; it persists the ownership
	// REMOVALS done by deleteOwnedLocked in Pass 1 (a delete drops the
	// in-memory entry but does not self-save). A delete leaves "ownership
	// without a live RR", never an orphaned live RR — so the residual window
	// here is self-healing (a crash before this save replays the idempotent
	// re-delete next pass), not an orphan. The save is still issued so the
	// store converges promptly.
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
func (m *Manager) withdrawAllLocked(ctx context.Context) error {
	owned := m.state.all()
	if len(owned) == 0 {
		return nil
	}
	var firstErr error
	for _, r := range owned {
		if err := m.deleteOwnedLocked(ctx, m.updater, r); err != nil && firstErr == nil {
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
// WRITE-AHEAD OWNERSHIP (#2662): the durable ownership record is persisted
// BEFORE the DNS add, not at the end of the reconcile pass. The previous
// shape (in-memory put per record, ONE state.save() after all I/O) left a
// per-PASS orphan window: a crash / kill / disk-full / WriteFileDurable
// failure after a successful DNS add but before the end-of-pass save left a
// LIVE DNS RR with NO durable ownership record — on restart the manager
// loaded the pre-add store and had no authority to ever clean that RR (the
// stale-record class #1387 set out to prevent). Write-ahead closes the
// window: the intent is durable BEFORE the wire add, so a crash anywhere
// after the add finds the ownership already recorded and a later reconcile
// re-adds (idempotent) or release deletes it. The pre-add intent carries
// PTRPending=true (the published tuple is not yet confirmed settled); a
// fully-successful add clears it via a confirm save. If the durable
// pre-write FAILS the add does NOT run and the record is reported "not
// safely owned" (the error is surfaced) — we never publish a RR we could not
// first record ownership for.
//
// REFUSED-ADD REMOVES THE INTENT (#2648 MAJOR-1 + #2662): a replace-owned /
// skip-existing add that REFUSES a name owned by another party returns
// errDDNSConflictRefused. The wire add did NOT happen, so the pre-written
// intent is phantom ownership and is REMOVED (delete + save) — leaving it
// would let a later release delete a record xpf did not create (for a
// no-identity lease, whose delete has no DHCID-match guard, that delete
// actually fires). Deleting an intent for a RR that was never created is
// safe: the #2648 DHCID-match / exact-RR delete prerequisite fails on a
// non-existent RR, so the wire delete is a harmless no-op.
func (m *Manager) upsertLocked(ctx context.Context, updater DNSUpdater, rec LeaseDNSRecord, ow ownedRecord) error {
	if isNopUpdater(updater) {
		// No live backend: nothing is published, so record NO ownership and
		// do not write-ahead an intent (an intent for a record nopUpdater
		// never wrote would be phantom). Count the skip and return success so
		// the reconcile does not wedge.
		if err := updater.UpsertLease(ctx, rec); err != nil {
			m.upsertFail.Add(1)
			return err
		}
		m.skippedNoBackend.Add(1)
		return nil
	}

	// WRITE-AHEAD: persist the ownership intent durably BEFORE the wire add.
	// PTRPending=true until a fully-successful add confirms it; a crash after
	// the add (but before any confirm) therefore finds the record owned and
	// the next reconcile converges it.
	intent := ow
	intent.PTRPending = true
	m.state.put(intent)
	if err := m.state.save(); err != nil {
		// Could not durably record ownership: do NOT publish. Roll the
		// in-memory intent back so the store matches what is durable, surface
		// the failure as "record not safely owned", and let the next
		// reconcile retry.
		m.state.delete(intent.scopeOf(), intent.Identity, intent.Address)
		m.upsertFail.Add(1)
		slog.Warn("ddns: cannot durably record ownership before add; skipping publish",
			"fqdn", rec.FQDN, "err", err)
		return err
	}

	if err := updater.UpsertLease(ctx, rec); err != nil {
		// ORDER MATTERS (#2676): check errDDNSPTRPending BEFORE
		// errDDNSConflictRefused. errDDNSPTRPending is returned ONLY after the
		// forward A/AAAA add SUCCEEDED, so its presence proves the forward is
		// LIVE and ownership MUST be recorded — it must never fall into the
		// no-ownership (intent-removal) branch below. The backend (#2676) no
		// longer wraps a PTR-side conflict-refusal into a chain carrying BOTH
		// sentinels, but this defensive ordering guarantees a
		// forward-published error can never orphan the forward even if some
		// future path produces a chain with both sentinels.
		if errors.Is(err, errDDNSPTRPending) {
			// PARTIAL SUCCESS (#2661): the forward A/AAAA is LIVE in DNS but the
			// reverse PTR add failed with a non-skippable (transient) error. The
			// pre-written intent already records ownership with PTRPending=true,
			// which is exactly the state we want to keep — the next reconcile
			// re-runs UpsertLease (an idempotent forward re-add) and re-attempts
			// the still-missing PTR. The forward is durably owned (never
			// orphaned). The PTR failure is counted and logged so it is
			// observable; the reconcile pass is NOT failed (the forward succeeded
			// and the PTR retry converges on its own), the same non-fatal
			// treatment as a NOTAUTH skip. No re-save needed: the durable intent
			// already carries PTRPending=true.
			m.ptrDeferred.Add(1)
			slog.Warn("ddns: forward published but reverse PTR add failed; "+
				"ownership recorded with PTR pending for retry next cycle",
				"fqdn", rec.FQDN, "ptr", rec.PTRName, "err", err)
			m.upsertOK.Add(1)
			return nil
		}
		if errors.Is(err, errDDNSConflictRefused) {
			// Refused (name owned by another party): the FORWARD wire add did not
			// happen (errDDNSConflictRefused is propagated unwrapped by the
			// backend only from the forward add, and a PTR-side conflict-refusal
			// is now classified as a permanent skip that returns nil — #2676), so
			// REMOVE the pre-written intent (no phantom ownership) and persist the
			// removal. Count it as a conflict skip already done by the backend; do
			// not fail the reconcile pass.
			m.state.delete(intent.scopeOf(), intent.Identity, intent.Address)
			if serr := m.state.save(); serr != nil {
				// The intent is removed in memory but the removal is not durable.
				// Surface it so the pass is marked failed and retried; a stale
				// durable intent is safe (its delete is a no-op on a non-existent
				// RR) and self-heals on the next successful save.
				slog.Warn("ddns: cannot persist removal of refused-add intent",
					"fqdn", rec.FQDN, "err", serr)
				return serr
			}
			return nil
		}
		// Hard add failure: the wire add did not succeed. Remove the
		// pre-written intent so the store does not claim a record that is not
		// in DNS, and persist the removal so a later release cannot fire a
		// (no-op) delete against a non-existent RR forever. A save failure here
		// is non-fatal beyond the add error already returned: a stale durable
		// intent's delete is a harmless no-op and self-heals on the next save.
		m.state.delete(intent.scopeOf(), intent.Identity, intent.Address)
		if serr := m.state.save(); serr != nil {
			slog.Warn("ddns: cannot persist removal of failed-add intent",
				"fqdn", rec.FQDN, "err", serr)
		}
		m.upsertFail.Add(1)
		return err
	}

	// Fully-successful add: confirm by clearing PTRPending and persisting the
	// settled record. A confirm-save failure is non-fatal — the durable
	// intent (PTRPending=true) already owns the live record, so it is
	// cleanable; the only cost is the next reconcile re-running the idempotent
	// forward add to clear the pending flag.
	m.upsertOK.Add(1)
	ow.PTRPending = false
	m.state.put(ow)
	if err := m.state.save(); err != nil {
		slog.Warn("ddns: cannot persist settled ownership after add (record still owned via write-ahead intent)",
			"fqdn", rec.FQDN, "err", err)
	}
	return nil
}

// deleteOwnedLocked re-derives the EXACT record from owned state and
// deletes it, removing the ownership entry on success. This is the sole
// delete authority — it never constructs a delete from anything but the
// store, so a record xpf did not create can never be deleted.
func (m *Manager) deleteOwnedLocked(ctx context.Context, updater DNSUpdater, owned ownedRecord) error {
	rec, err := buildLeaseRecord(owned.FQDN, owned.Address, owned.TTL)
	if err != nil {
		// The stored address no longer parses (should not happen): drop
		// the entry to avoid wedging, but do NOT issue a delete with a
		// guessed name.
		slog.Warn("ddns: owned record has unparseable address; dropping entry",
			"address", owned.Address, "err", err)
		m.state.delete(owned.scopeOf(), owned.Identity, owned.Address)
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
	if err := updater.DeleteLease(ctx, rec); err != nil {
		m.deleteFail.Add(1)
		return err
	}
	if isNopUpdater(updater) {
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
		m.state.delete(owned.scopeOf(), owned.Identity, owned.Address)
		return nil
	}
	m.deleteOK.Add(1)
	m.state.delete(owned.scopeOf(), owned.Identity, owned.Address)
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

// OwnedRecordView is a read-only projection of one owned record for
// `show ... dynamic-dns detail`. It deliberately omits the owner watermark
// (an internal hash) and exposes only the published tuple.
type OwnedRecordView struct {
	Family      int
	FQDN        string
	ForwardType string
	Address     string
	PTRName     string
	TTL         int
}

// OwnedRecordViews returns a stable-ordered snapshot of the records this
// node currently owns (published into DNS). Used by the show command.
func (m *Manager) OwnedRecordViews() []OwnedRecordView {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := m.state.all()
	out := make([]OwnedRecordView, 0, len(all))
	for _, r := range all {
		out = append(out, OwnedRecordView{
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
func (m *Manager) Stats() Stats {
	m.mu.Lock()
	n := len(m.state.records)
	m.mu.Unlock()

	st := Stats{
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

// DDNSLeasePaths returns the manager's lease CSV paths so a cross-package
// test can write synthetic memfiles the reconcile loop will read. Moved
// verbatim from pkg/dhcpserver/test_seams.go in #2691 P1a (the method name is
// kept so pkg/daemon's tests need no change).
func (m *Manager) DDNSLeasePaths() (leasePath4, leasePath6 string) {
	return m.leasePath4, m.leasePath6
}

// OwnedForTesting reports whether the ownership store holds a record for the
// given identity+address IN ANY SCOPE. Test-only accessor for cross-package
// tests (the pkg/dhcpserver real-parser→engine integration tests) that
// previously reached into the unexported state store directly (#2691 P1a). It
// matches scope-agnostically (#2691 P1b) so the existing seam callers — which
// publish on the zero/global lease scope — keep working unchanged. Not for
// production use.
func (m *Manager) OwnedForTesting(identity, address string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.state.records {
		if r.Identity == identity && r.Address == address {
			return true
		}
	}
	return false
}

// OwnedKeysForTesting returns the identity|address keys of every owned record,
// for diagnostic assertions in cross-package tests. Test-only (#2691 P1a).
func (m *Manager) OwnedKeysForTesting() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.state.records))
	for k := range m.state.records {
		out = append(out, k)
	}
	return out
}
