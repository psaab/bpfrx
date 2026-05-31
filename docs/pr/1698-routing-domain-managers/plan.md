# #1698 — `pkg/routing/routing.go` domain-manager split (re-attempt post-#1544-kill)

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude-SMR)

## 1. Issue framing

`pkg/routing/routing.go` is 2085 LOC and is the #1 `[REFACTOR]` entry in
`docs/refactoring-audit-current.txt`. It bundles unrelated control-plane
domains behind a single `*routing.Manager`: VRF lifecycle, static-route
reads + Junos route formatters, GRE tunnel apply/clear + keepalive
goroutines, XFRM/IPsec interface lifecycle, next-table / rib-group /
PBR ip-rule programming, bond lifecycle, RETH stubs, and
interface-monitor status.

#1698 asks for **real domain managers with narrow netlink-facing
interfaces and per-domain testability** — NOT lines-N-to-M file motion.

## 2. Why this is NOT the #1544-killed approach

#1544 was PLAN-KILLED (both Codex + Gemini, round 1) because it was
**pure file-motion**: nine sibling `.go` files where *every method stayed
on `*Manager`*, no narrowed interface, no per-domain state ownership. The
kill comment is explicit about what a successor must do
(quoted verbatim from the #1544 issue thread):

> **Introduce per-domain ops interfaces (minimum) or unexported domain
> structs (preferred), with `*Manager` as façade.** … each domain file
> owns an unexported `vrfManager`/`tunnelManager`/`pbrManager`/etc.
> struct holding a reference to the shared `*netlink.Handle` and its own
> sub-state; `*Manager` becomes a coordinator that delegates from
> existing public methods to the domain. Achievable as code-motion plus
> mechanical method-receiver rewrite, but it IS more than file-motion.

This plan implements **exactly that prescribed successor design**:
unexported per-domain structs that each own their sub-state + their own
lock, holding a shared `*netlink.Handle`. `*Manager` becomes a thin
façade that constructs the domains and delegates every existing public
method. This is a structural change with narrowed surfaces and
per-domain testability — the seam #1544 explicitly said it lacked.

The kill comment also fixed three boundary errors a successor must avoid;
all three are addressed below:

1. **No file-motion-only.** Addressed: domain structs + receiver rewrite.
2. **Drop the bogus `test-failover` HA claim.** Addressed: §7 — the only
   live HA signal in this manager is the interface-monitor path
   (`ApplyInterfaceMonitors` → cluster weight). This refactor does not
   change that path's behavior, only moves it onto a `monitorManager`
   struct behind the same façade method. `ApplyRethInterfaces` /
   `RethNames` are confirmed no-op stubs (routing.go:1996, 2028) with
   zero callers; real RETH MAC/VIP lives in `pkg/cluster/reth.go`. No
   `test-failover` is required; a route-correctness smoke is run only if
   the runtime apply path is touched (it is moved, not changed — see §9).
3. **next-table / rib-group / PBR are three concerns.** Addressed: §5 —
   they get three files (`nexttable.go`, `ribgroup.go`, `pbr.go`), not
   one `pbr.go` dumping-ground. They share no `Manager` state (verified:
   they touch only `m.nlHandle` + reconcile kernel ip-rules directly), so
   they become three small domain structs over the shared handle.

## 3. Honest scope / value framing

This is a **maintainability** refactor, not a perf change. The win:

- Drops the #1 audit `[REFACTOR]` file off the >2000-LOC list. The
  façade `routing.go` lands well under 1500 LOC; each domain file is
  ~100–400 LOC.
- **Per-domain testability** — the issue's core acceptance criterion.
  Today the rib-group test cannot exercise ip-rule creation without
  netlink, and tunnel-keepalive tests cannot run without dragging the
  whole `Manager`. After the split each domain struct has a single,
  small responsibility and (for VRF) an injectable ops interface; the
  rule domains become independently constructible over a shared handle.
- **Lock-scope clarity** — today one `ifaceMu` serializes four unrelated
  domains (tunnels, xfrmis, bonds, keepalives). After the split each
  domain owns its own mutex. Verified safe (§7): **no current method
  holds `ifaceMu` across more than one of those domains**, so there is no
  cross-domain atomic section to preserve. Splitting the lock is
  behavior-preserving, not a concurrency redesign.

There is no measurable runtime perf delta — this is control-plane apply
code that runs on config commit, not the packet hot path.

**If reviewers conclude the churn is not justified by the maintainability
win, or that the lock-split introduces a behavioral risk that outweighs
it, PLAN-KILL is an acceptable verdict.** This is a re-attempt of a
killed issue; a second kill on sound grounds is a legitimate outcome.

## 4. What already exists / constraints to compose with

- **Standing layout rule (caller-set, overrides issue body):** sibling
  `.go` files inside `pkg/routing/`, NOT sub-packages, NOT a
  `routing_<prefix>` name-mangle. Domain structs stay in
  `package routing`, unexported, in sibling files.
- **One `*netlink.Handle`** on `Manager` (routing.go:44). All domains
  share it. It must stay singly-owned and singly-closed — `Close()`
  closes it exactly once *after* keepalive goroutines drain (#848).
- **`vrfOps` interface** (routing.go:143) already exists for VRF
  testability; it moves with the VRF domain unchanged.
- **Daemon apply ordering** (`pkg/daemon/daemon_apply.go`): VRF →
  BindInterfaceToVRF → Tunnels → Xfrmi → Bonds → … → NextTable →
  RibGroup → PBR → Monitors. This ordering is enforced by the *caller*
  via sequential public-method calls; the façade preserves it because
  the public method names and signatures are unchanged.

## 5. Concrete design

`package routing` keeps a single facade `Manager`. Each domain becomes an
unexported struct in its own sibling file, constructed by `New()` and
holding a copy of the shared `*netlink.Handle` (plus its own sub-state +
lock). Every existing **public method keeps its exact signature** and
becomes a one-line delegation to the owning domain.

### File layout (sibling files, `package routing`)

| File | Domain struct | Owns | Public methods delegated |
|------|---------------|------|--------------------------|
| `routing.go` (façade) | `Manager` | `nlHandle` (sole owner), domain refs | `New`, `Close` |
| `vrf.go` | `vrfManager` | `vrfsMu`, `vrfs`, `vrfOps` | `CreateVRF`, `IsManagedVRF`, `ReconcileVRFs`, `BindInterfaceToVRF` |
| `routes.go` | `routeReader` | (stateless; holds `nlHandle`) | `GetRoutes`, `GetRoutesForTable`, `GetVRFRoutes`, `GetTableRoutes`, `GetAllTableRoutes` |
| `routeformat.go` | (free fns only) | — | `FormatRouteTerse`, `FormatRouteDestination`, `FormatRouteSummary`, `FormatAllRoutes` + helpers |
| `tunnel.go` | `tunnelManager` | `ifaceMu`-replacement `tunMu`, `tunnels`, `keepalives` | `ApplyTunnels`, `ClearTunnels`, `GetTunnelStatus`, `GetKeepaliveState` |
| `xfrm.go` | `xfrmManager` | `xfrmMu`, `xfrmis` | `ApplyXfrmi`, `ClearXfrmi` |
| `nexttable.go` | `nextTableManager` | (stateless; `nlHandle`) | `ApplyNextTableRules` |
| `ribgroup.go` | `ribGroupManager` | (stateless; `nlHandle`) | `ApplyRibGroupRules` |
| `pbr.go` | `pbrManager` | (stateless; `nlHandle`) | `ApplyPBRRules` + `BuildPBRRules` free fn |
| `bond.go` | `bondManager` | `bondMu`, `bonds` | `ApplyBonds`, `ClearBonds` |
| `reth.go` | `rethManager` | (stub) | `ApplyRethInterfaces`, `ClearRethInterfaces`, `RethNames` |
| `monitor.go` | `monitorManager` | `monMu`, `monitorStatus` | `ApplyInterfaceMonitors`, `InterfaceMonitorStatuses` |

Type defs move next to their domain: `KeepaliveState` + `keepaliveRunner`
→ `tunnel.go`; `TunnelStatus` → `tunnel.go`; `RouteEntry` + `TableRoutes`
→ `routes.go`; `PBRRule` → `pbr.go`; `InterfaceMonitorStatus` →
`monitor.go`; `VRFSpec` + `vrfOps` → `vrf.go`.

### Façade sketch

```go
type Manager struct {
    nlHandle *netlink.Handle // sole owner; closed exactly once in Close()
    vrf      *vrfManager
    routes   *routeReader
    tunnel   *tunnelManager
    xfrm     *xfrmManager
    nextTbl  *nextTableManager
    ribGroup *ribGroupManager
    pbr      *pbrManager
    bond     *bondManager
    reth     *rethManager
    monitor  *monitorManager
}

func New() (*Manager, error) {
    h, err := netlink.NewHandle()
    if err != nil { return nil, fmt.Errorf("netlink handle: %w", err) }
    m := &Manager{nlHandle: h}
    m.vrf      = &vrfManager{nl: h}
    m.routes   = &routeReader{nl: h}
    m.tunnel   = &tunnelManager{nl: h, keepalives: map[string]*keepaliveRunner{}}
    m.xfrm     = &xfrmManager{nl: h}
    m.nextTbl  = &nextTableManager{nl: h}
    m.ribGroup = &ribGroupManager{nl: h}
    m.pbr      = &pbrManager{nl: h}
    m.bond     = &bondManager{nl: h}
    m.reth     = &rethManager{}
    m.monitor  = &monitorManager{monitorStatus: map[int][]InterfaceMonitorStatus{}}
    return m, nil
}

// Example delegation (signature byte-identical to today):
func (m *Manager) ApplyTunnels(t []*config.TunnelConfig) error { return m.tunnel.Apply(t) }
func (m *Manager) ReconcileVRFs(d []VRFSpec) error             { return m.vrf.Reconcile(d) }

func (m *Manager) Close() error {
    m.tunnel.stopAll() // drains keepalive goroutines under tunnel lock (#848)
    if m.nlHandle != nil { m.nlHandle.Close() }
    return nil
}
```

The domain structs hold `nl *netlink.Handle` (a **borrowed** reference,
not an owner — only the façade closes it). Domain-internal methods are
the existing private bodies with `m.nlHandle` → `d.nl` and
`m.ifaceMu`/`m.vrfsMu`/`m.mu` → the domain's own mutex. Method *bodies*
are otherwise moved verbatim.

## 6. Public API preservation

All 26 public methods + 4 exported free functions keep byte-identical
signatures and observable behavior. External callers
(`pkg/daemon/daemon_apply.go`, `pkg/grpcapi/server_*.go`,
`pkg/daemon/daemon_run.go`) call `m.ApplyTunnels(...)` etc. unchanged;
zero call-site edits outside `pkg/routing/`. Exported types
(`Manager`, `VRFSpec`, `RouteEntry`, `TableRoutes`, `TunnelStatus`,
`PBRRule`, `KeepaliveState`, `InterfaceMonitorStatus`) keep their names
and package path.

Full preserved-signature list (verbatim): `New`, `Close`, `CreateVRF`,
`IsManagedVRF`, `ReconcileVRFs`, `BindInterfaceToVRF`,
`GetRoutesForTable`, `GetRoutes`, `GetVRFRoutes`, `GetTableRoutes`,
`GetAllTableRoutes`, `ApplyTunnels`, `ClearTunnels`, `GetTunnelStatus`,
`GetKeepaliveState`, `ApplyXfrmi`, `ClearXfrmi`, `ApplyNextTableRules`,
`ApplyRibGroupRules`, `ApplyPBRRules`, `ApplyBonds`, `ClearBonds`,
`ApplyRethInterfaces`, `ClearRethInterfaces`, `RethNames`,
`ApplyInterfaceMonitors`, `InterfaceMonitorStatuses`; free fns
`FormatRouteTerse`, `FormatRouteDestination`, `FormatRouteSummary`,
`FormatAllRoutes`, `BuildPBRRules`.

(Note: API accounting corrected from #1544's wrong "16 methods + 12 free
fns". Verified count: 26 methods + exported free fns above.)

## 7. Hidden invariants the change must preserve

1. **Single netlink handle, single close (#848).** Domains borrow
   `nl`; only `Manager.Close()` closes it, and only after
   `tunnel.stopAll()` drains keepalive goroutines (use-after-close
   hazard). Preserved by construction.
2. **No cross-domain atomic section under one lock.** VERIFIED: no method
   holds the current `ifaceMu` across more than one of
   {tunnels, xfrmis, bonds, keepalives}. `GetTunnelStatus` snapshots only
   `tunnels`; `ApplyXfrmi`/`ApplyBonds`/`ApplyTunnels` each touch only
   their own slice. Therefore splitting `ifaceMu` into per-domain
   `tunMu`/`xfrmMu`/`bondMu` cannot break an existing invariant — there
   is no observable interleaving today that the shared lock prevents.
   The keepalives map moves with the tunnel domain (its only user).
3. **VRF ownership / orphan-reap semantics** (`reconcileVRFs`,
   #847/#844). Body moved verbatim onto `vrfManager`; `vrfsMu` →
   `vrf.mu`. The `vrfOps` injectable interface is preserved so all VRF
   tests run unchanged.
4. **Daemon apply ordering** (VRF→bind→tunnel→xfrm→bond→rules→monitor).
   Enforced by the caller's sequential public-method invocations;
   façade delegation does not reorder anything.
5. **Rule reconcile semantics** (next-table/rib-group/PBR clear-then-add
   against live kernel ip-rules). Bodies moved verbatim; they were
   already `Manager`-stateless, so moving onto stateless domain structs
   over the shared handle is a no-op behaviorally.
6. **Interface-monitor HA signal.** `monMu` + `monitorStatus` map moved
   onto `monitorManager`; `ApplyInterfaceMonitors` /
   `InterfaceMonitorStatuses` bodies verbatim. The cluster-weight
   consumer (`daemon_apply.go:948-956`, `cluster/election.go`) reads
   through the unchanged façade method — same data, same shape.

## 8. Risk assessment

| Class | Rating | Rationale |
|-------|--------|-----------|
| Behavioral regression | LOW | Method bodies moved verbatim; only receiver + field/lock names rewritten mechanically. Public signatures byte-identical. |
| Lifetime / ownership (Go) | LOW–MED | Shared `*netlink.Handle` borrowed by domains; sole close in façade after keepalive drain. The one real hazard is double-close / close-before-drain — explicitly preserved in `Close()` ordering. |
| Concurrency (lock split) | LOW | Verified no cross-domain critical section exists today (§7.2). Per-domain locks are strictly finer-grained; cannot introduce a new race because no domain reads another domain's state. |
| Performance regression | NONE | Control-plane apply path; not the packet hot path. One extra pointer-hop per public call, on config-commit frequency. |
| Architectural mismatch (#961 / #946-Phase-2 / #1544 file-motion) | LOW | This is the exact successor design the #1544 kill comment prescribed; it adds narrowed surfaces + per-domain testability, the criteria #1544 lacked. |

## 9. Test plan

- `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./pkg/routing/...`
  — all 20 existing routing tests pass unchanged (they call exported
  methods + the `vrfOps` fake, which both survive).
- Full Go suite `go test ./...` — green (no call-site edits outside
  `pkg/routing/`, so no downstream package changes expected).
- 5× flake loop on `TestReconcileVRFs` and `TestMultiVRFRibGroupLeaking`
  (the most state-sensitive tests).
- `make audit-check` will go stale (routing.go drops off [REFACTOR]); regen
  `docs/refactoring-audit-current.txt` in its own commit.
- **Route-correctness smoke** on `loss:xpf-userspace-fw0/fw1` (FIFO via
  `AWAITING-SMOKE`, contends with #1697): verify routes/VRF/route-leak
  still program correctly after a config commit — `show route`,
  `show route table`, rib-group leak presence. The runtime apply path is
  *moved, not changed*, so this is a confirmation smoke, not a perf gate.
  Per skill: v4+v6, push+reverse, CoS-off+CoS-on connectivity unaffected.
- `make test-failover` is **NOT required** — no live failover/VRRP path
  is touched (kill-comment finding #2 honored).

## 10. Out of scope (explicitly)

- `#1163` recursive string-based `next_table` lookup perf — unchanged.
- Any change to VRF/route-leak *semantics* — bodies are verbatim.
- Splitting `routeformat.go` further or de-duplicating the Junos
  formatters — they stay together as a cohesive formatting unit.
- Introducing public sub-packages — forbidden by the standing layout
  rule; domains stay unexported in `package routing`.
- Lock-granularity *tuning* beyond the mechanical 1→N split (no new
  RWMutex, no lock-free snapshots beyond what exists).

## 11. Open questions for adversarial review (each may justify PLAN-KILL)

1. **Is the lock split actually safe?** I assert no method crosses
   {tunnels, xfrmis, bonds} under one `ifaceMu`. Find a counter-example
   (a current or near-future call path that needs an atomic cross-domain
   transition) — if one exists, the shared `ifaceMu` is load-bearing and
   the per-domain split is wrong; keep a single shared lock instead.
2. **Does borrowing `*netlink.Handle` into 11 structs create a
   close-ordering hazard** beyond the keepalive drain? Is there any
   domain goroutine other than keepalive that could touch `nl` after
   `Close()`? (I found only keepalive — verify.)
3. **Is this materially different from #1544, or is it file-motion with
   extra structs?** The bar: narrowed surface + per-domain testability.
   If a reviewer judges the per-domain structs add no real testability
   over today's exported-method + `vrfOps` surface, that's a KILL.
4. **Three rule files vs one.** I split next-table/ribgroup/pbr three
   ways per the kill comment. Is that over-fragmentation given they're
   all stateless ip-rule reconcilers sharing helpers
   (`resolveRibTable`, `dscpToTOS`)? Would a single neutral `rules.go`
   be the better boundary? (Pick one and justify — do not paper over,
   per #1544 reviewer-disagreement note.)
5. **Is the maintainability win worth the churn** for a control-plane
   file that is not perf-critical and whose tests already pass? If the
   answer is no, PLAN-KILL.
6. **Façade pointer-hop / API drift:** any public method whose behavior
   subtly changes when its state moves off `Manager` (e.g. a method that
   today reads two of the soon-to-be-split mutexes)? Verify each of the
   26 methods touches exactly one domain's state.
