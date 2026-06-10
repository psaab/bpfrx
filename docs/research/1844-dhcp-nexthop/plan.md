# #1844 ip-monitoring: DHCP-learned-uplink support for preferred-route next-hops

**Status:** DRAFT v2 — folds all round-1 findings (Claude SMR + Codex +
AGY, all PLAN-NEEDS-REVISION, docs beside this file). Headline folds:
(1) lease-delete hook fire site corrected to `finishClient` (the real
cleanup owner — SMR-1/Codex-1/AGY-1 convergent, Codex with a verified
cancel-mid-exchange counterexample); (2) hook becomes an immutable
`dhcp.New` constructor argument (AGY-2 setter data race); (3)
`PublishRouteOverlaySnapshot` return contract distinguishes
published-vs-skipped so a same-content actuation no longer bumps FIB
generation (Codex-2); (4) spelling/normalization + mgmt-interface
rejection pinned down (SMR-3/SMR-4); (5) helper type fixed to
`*InterfaceUnit` (AGY-3); plus the Low/doc folds (Renew transient,
RFC 2131 note, PolicyStatus.UnresolvedRoutes, gauge purity,
bounded-blocking wording).

**Base:** this plan targets the post-#1843 tree. It is written and
verified against `origin/engineer/1827-ipmon-pr1` @ `d18071d5c` (the
#1827 PR-1 head). Implementation is pre-authorized by the dispatch but
**sequenced strictly after PR #1843 merges**; if #1843 changes under
review, the file/line references here must be re-anchored before
`/engineer 1844`.

---

## 1. Issue framing

#1827 PR-1b shipped `services ip-monitoring`: while a matched RPM probe
is FAILED, the policy's preferred routes are injected (distance-1
statics in FRR + whole-entry replacement in the dataplane snapshot,
both fed from the engine's winner-resolved overlay). The next-hop of a
preferred route is a **static IP literal** — `validateIPMonitoringStrict`
(`pkg/config/compiler_services.go:378`) hard-rejects anything that is
not `net.ParseIP`-valid.

That makes the single most common edge failover shape unconfigurable:
a backup uplink whose gateway is DHCP-learned (cable modem, LTE dongle,
upstream CPE). The operator cannot write the next-hop because they do
not know it; it can also change at any lease renewal. The #1827 plan
(§3, §10) declared this an explicit v1 limitation, documented it in
`docs/multi-wan.md` ("ip-monitoring next-hops are explicit by design.
DHCP-uplink…"), and filed this issue as the follow-up. The issue body
names the #1777 commit-lease path as the natural re-resolution hook.

## 2. Honest scope/value framing

**Value:** DHCP-addressed WAN uplinks are the dominant consumer/SOHO
backup pattern — exactly the dual-uplink edge deployment #1389/#1827
target. Without this, ip-monitoring covers only dual-static-IP
deployments. The limitation is operator-visible (commit error) and
documented; closing it completes the PR-1 story for the common case.

**What this does and does NOT enable.** The dataplane FIB is
config-derived and carries no DHCP-learned routes (`collectDHCPRoutes`
feeds FRR only — `pkg/daemon/daemon_flow.go:23`). This plan makes a
DHCP uplink usable **as the failover target**: the injected overlay
route carries an explicit (resolved) next-hop into BOTH FRR and the
snapshot, so fast-path transit fails over onto the DHCP uplink
correctly. It does NOT make a DHCP uplink usable as the *primary*
fast-path uplink without a static default — that pre-existing,
independent limitation (dp FIB has no DHCP routes at baseline) stays
documented in `docs/multi-wan.md` and is out of scope here.

**Cost:** ~300–450 LOC including tests, across `pkg/config`,
`pkg/ipmon`, `pkg/dhcp`, `pkg/daemon`, docs. Zero Rust changes, zero
wire-protocol changes (this is load-bearing — see the v4-only scope cut
in §4.5), zero hot-path changes, no new control-socket traffic class
(actuations ride the existing debounce+throttle).

**PLAN-KILL invitation:** kill if reviewers conclude (a) the
stale-gateway semantics (§4.5) make a DHCP-tracked failover route
untrustworthy enough to be a footgun, or (b) a cross-package
lease-event hook is too much machinery for the niche. The honest
counter: the niche is the common case for edge boxes, the hook is one
optional callback mirroring the existing `onAddressChange` pattern, and
the stale-gateway behavior exactly matches what FRR's DHCP default
route already does on this box.

## 3. Survey — what exists on the post-#1843 tree (verified @ d18071d5c)

| Area | State | Evidence |
|------|-------|----------|
| ipmon engine | Single-goroutine run loop owns debounce (1 s) + throttle (3 s) + at-most-one-actuation; `markDirtyLocked`+`kickLoop` is the only trigger surface; actuator reads `ActiveOverlay()` itself (last-writer-wins) | `pkg/ipmon/ipmon.go:405-448, 390-401` |
| Winner resolution | `activeOverlayLocked`: per `(routing-instance, canonical prefix)`, lowest preferred-metric, tie-break policy name; only FAILED policies contribute | `pkg/ipmon/ipmon.go:219-271` |
| Overlay consumers | Full apply: `SetRouteOverlay(d.ipmonActiveOverlay())` (`daemon_apply.go:446`) + `assembleFRRConfig(cfg, d.ipmonActiveOverlay())` (`daemon_apply.go:737`) — **two separate overlay reads in one apply** (see §4.4 hardening). Actuator: ONE read feeds both consumers (`daemon_ipmon.go:164-190`) | |
| Actuator ordering | FRR render → `PublishRouteOverlaySnapshot` → only-on-success `BumpFIBGeneration` (AGY r2-1 ordering, load-bearing) | `pkg/daemon/daemon_ipmon.go:164-190` |
| Commit checks | next-hop must be a literal IP, family-matched to destination; forwarding-type RI rejected | `pkg/config/compiler_services.go:378-427` |
| DHCP lease model | `Lease{Interface, Family, Address, Gateway netip.Addr, …}` keyed by `clientKey{iface(Linux name), family}`; `LeaseFor(iface, af)` returns a copy under `m.mu` | `pkg/dhcp/dhcp.go:34-47, 540-550` |
| #1777 commit path | `commitLease` is the single commit path (initial + T1 + T2); fires debounced (2 s) `onAddressChange` only on content change — **Gateway is content** (`leaseContentChanged`, `commit.go:56-60`) | `pkg/dhcp/commit.go:110-132` |
| Lease lifecycle | Lease record deleted ONLY on client stop (`ctx.Done` branches of both run loops; Reconcile stop = cancel→same path). On T2-rebind failure the loop falls back to fresh DORA but the **stale lease record + address remain** until replaced | `pkg/dhcp/dhcp.go:570-700` |
| Lease→FRR precedent | `collectDHCPRoutes` maps `Leases()`→`frr.DHCPRoute{Gateway, Interface, IsIPv6}` (AD 200); keeps rendering the stale gateway during re-acquisition; v6 gateways are RA-discovered link-locals and need the Interface field | `pkg/daemon/daemon_flow.go:23-44`, `pkg/frr/manager.go:86-91` |
| onAddressChange → daemon | `onDHCPAddressChange` re-enters **full `applyConfig`** when a dataplane-relevant DHCP interface exists (`dhcpLeaseChangeRequiresRecompile`) | `pkg/daemon/daemon_dhcp.go:72-98, 130-160` |
| Lease key derivation | `buildDHCPClientSpecs`: `config.LinuxIfName(ifName)` + `".<vlan>"` when `unit.VlanID > 0` — the canonical config→lease-key mapping | `pkg/daemon/daemon_dhcp.go:19-36` |
| Snapshot route shape | `RouteSnapshot{Table, Family, Destination, NextHops []string, …}` — **no device/interface field**; a link-local v6 next-hop is interface-ambiguous to the dp; the struct is the wire contract (`protocol.go` + `protocol.rs`) | `pkg/dataplane/userspace/protocol.go:499-506` |
| Reconcile identity rule | DHCP client reconcile keys STRICTLY on config identity, never lease state (#1793) — any new config field must not perturb fingerprints | `pkg/dhcp/reconcile.go:50-75` |
| Test seams | ipmon: injectable `now`, actuate func, pure `evaluateLocked`; dhcp: `runClientForTest`, directly-testable `commitLease`/helpers; daemon: `actuateRouteOverlayLocked` split for ordering tests | `pkg/ipmon/ipmon.go:89-115`, `pkg/dhcp/dhcp.go:106-112`, `pkg/daemon/daemon_ipmon.go:161-164` |

**Junos reality check (honest):** Junos `ip-monitoring … then
preferred-route route <prefix>` takes a literal `next-hop` address;
there is no DHCP-tracking next-hop in the Junos schema — this exact gap
is a long-standing SRX operator complaint (worked around with
event-scripts). So *any* spelling here is an extension beyond Junos;
the design constraint from the project charter is to pick the spelling
that **reads as Junos** rather than inventing a new subsystem. That
drives Fork 1 in §11.

## 4. Concrete design

### 4.1 Config surface — interface-valued `next-hop` (Fork 1 Path A)

```
set interfaces ge-0/0/3 unit 0 family inet dhcp
set services rpm probe WAN test wan-a target address 1.1.1.1
set services rpm probe WAN test wan-a next-hop 172.16.50.1          # probe pins to PRIMARY uplink
set services ip-monitoring policy wan-failover match rpm-probe WAN
set services ip-monitoring policy wan-failover then preferred-route route 0.0.0.0/0 next-hop ge-0/0/3.0
```

The existing `next-hop` leaf (schema node unchanged: `args: 1`,
`pkg/config/schema.go` ip-monitoring subtree) accepts EITHER a literal
IP (today's behavior, untouched) OR an interface unit reference
`<ifd>.<unit>`. Junos operators already write interface-valued
next-hops in static routes (`next-hop ge-0/0/0.0` on p2p links); the
natural reading — "egress via this interface using its learned
gateway" — is exactly the semantics implemented. VLAN units use the
same spelling (`ge-0/0/3.50` ⇒ Linux `ge-0-0-3.50` when the unit has
`vlan-id 50`).

**Typed model** (`pkg/config/types_system.go`):

```go
type PreferredRoute struct {
    RoutingInstance string
    Destination     string // CIDR
    NextHop         string // literal IP ("" when interface-typed)
    // NextHopInterface is the resolved Linux lease key
    // (LinuxIfName + optional ".<vlan>") when the configured
    // next-hop names a DHCP-enabled interface unit. Mutually
    // exclusive with NextHop. Compile-time derived; config
    // identity only, never lease state.
    NextHopInterface string
    PreferredMetric  int
}
```

**Compile/commit checks** (extend `compileIPMonitoring` +
`validateIPMonitoringStrict`):

1. Value parses as IP → literal path, all existing checks unchanged.
   (Degenerate corner, accepted: an interface hypothetically named so
   that `<ifd>.<unit>` forms a dotted-quad would parse as the IP
   literal — no such names exist in the vSRX naming scheme; AGY r1
   ratified this as a non-issue.)
2. Otherwise the value must split (at the LAST `.`) into
   `<ifd>.<unit-number>` where `<ifd>` is **exactly an interface name
   as configured under `interfaces`** (Junos form, e.g. `ge-0/0/3`) and
   `<unit-number>` is a configured unit of it. Normalization rules
   (SMR r1-3): the dashed Linux form is NOT accepted; a bare ifd
   without `.unit` gets a distinct error ("interface-typed next-hop
   requires <ifd>.<unit>"); anything else falls to "not a valid IP
   address or DHCP interface unit".
3. The destination family must be **inet** (v4). `inet6` destinations
   with an interface-typed next-hop are commit-rejected with a pointer
   to the follow-up (§4.5 rationale: DHCPv6 gateways are RA-derived
   link-locals; `RouteSnapshot` has no device field; supporting it is a
   wire-protocol change).
4. The named unit must have `family inet dhcp` (`unit.DHCP`) — the
   route tracks a DHCP gateway by definition; a static-addressed unit
   is rejected ("interface-typed next-hop requires family inet dhcp on
   <unit>"). No extra tunnel/loopback rejection needed: such units
   cannot have `unit.DHCP` (Codex r1 Q1, SMR r1 Q1 concur).
5. The lease key stored in `NextHopInterface` is derived by a **shared
   helper** extracted from `buildDHCPClientSpecs`'s inline logic —
   `config.DHCPLeaseIfName(ifName string, unit *InterfaceUnit) string`
   (`LinuxIfName(ifName)` + `".<VlanID>"` when `unit.VlanID > 0`;
   type per AGY r1-3) — used by BOTH the spec builder and the compiler
   so the two derivations can never drift. (The helper lives in
   `pkg/config` because the compiler cannot import `pkg/daemon`;
   `buildDHCPClientSpecs` switches to it in the same commit.) Note the
   operator writes the **unit number**; the lease-key suffix is the
   unit's **vlan-id** — distinct concepts, bridged only inside the
   helper (SMR r1-3c). The v1 example holds because that unit's
   vlan-id is 50.
6. Interface-typed next-hops naming **management interfaces**
   (`fxp*`, `em*`, `fab*` — the same name classes the daemon binds to
   the mgmt VRF) are commit-rejected (SMR r1-4): `collectDHCPRoutes`
   deliberately excludes mgmt-VRF leases from FRR
   (`daemon_flow.go:31-33`); an overlay route resolved through the
   mgmt gateway would leak management routing into the default table.

Schema: no structural change; the `next-hop` desc string gains "…or
DHCP interface unit". `docs/multi-wan.md` limitation paragraph is
rewritten to describe the new behavior (and to keep the
*baseline*-DHCP-fast-path limitation, which stays true).

### 4.2 Resolution point — inside the engine, pre-winner-selection

The next-hop must resolve **before** winner resolution: if the winning
candidate for a prefix is interface-typed and currently unresolvable
(no lease), the losing candidate (e.g. a static next-hop from another
FAILED policy) must win instead — otherwise the prefix gets no injected
route even though a usable one exists. Resolving after winner selection
gets this wrong by construction.

`pkg/ipmon` therefore gains an injected resolver (engine stays free of
any `pkg/dhcp` import — dependency direction remains daemon → {ipmon,
dhcp}):

```go
// NextHopResolver resolves an interface-typed preferred-route
// next-hop (Linux lease key) to its current DHCP-learned gateway.
// ok=false ⇒ the candidate is skipped (no lease / no gateway).
type NextHopResolver func(leaseIface string) (gw string, ok bool)

func (e *Engine) SetNextHopResolver(r NextHopResolver) // before Start()
```

In `activeOverlayLocked`, a candidate with `NextHopInterface != ""`
calls the resolver; on `ok` the emitted `RouteOverlayEntry.NextHop` is
the resolved gateway (the overlay entry stays a plain resolved IP —
**zero changes** to `RouteOverlayEntry`, the FRR render
(`renderPreferredRoutes`), `applyRouteOverlay`, or
`PublishRouteOverlaySnapshot`); on `!ok` the candidate is skipped
before the `best[key]` comparison. Nil resolver ⇒ interface-typed
candidates always skip (defensive; the daemon always wires it).

Because every consumer obtains the overlay through `ActiveOverlay()`
(actuator, `daemon_apply.go:446` and `:737`), resolution at this single
point guarantees FRR and the snapshot always see the same resolved
next-hop *within one read* — and the actuator's single read feeds both
consumers, so one actuation is internally consistent by construction
(unchanged from #1827).

**Lock order (one-way, documented):** `Engine.mu` → `dhcp.Manager.mu`
(the resolver calls `LeaseFor`, which takes `dhcp.mu` briefly).
`pkg/dhcp` must NEVER call into the engine while holding `dhcp.mu` —
the new hook in §4.3 fires outside the lock, mirroring how
`scheduleRecompile`'s timer callback already runs detached.

**Display:** `PolicyStatus.Routes` carries resolved entries, so `show
services ip-monitoring status` shows the live gateway. An
interface-typed route that is currently unresolvable does not appear in
`Routes`; `PolicyStatus` gains `UnresolvedRoutes []string` (destination
prefixes whose candidate was skipped), populated in `Status()`, so
`display.go` stays dumb (SMR r1-6). New gauge
`xpf_ipmon_unresolved_next_hops`: the skip count is a **return value**
of the overlay computation (keeping `activeOverlayLocked` pure, SMR
r1-7), refreshed by any caller — `Status()`/`RoutesApplied()` included
— so a metrics scrape never needs an actuation to be current.

### 4.3 The re-resolution trigger — narrow hook, NOT applyConfig

The #1844 body names the #1777 commit-lease path as the hook; the
#1827 plan's hard rule is that route actuation must ride the
routes-only actuator, never a full apply. Both are satisfied with one
optional callback on `dhcp.Manager`, passed as an **immutable
constructor argument** (AGY r1-2: a `SetGatewayChangeHook` setter on a
live manager is a data race — client goroutines read the hook pointer
outside `m.mu`; the constructor argument matches how `onAddressChange`
is already wired at `dhcp.go:116`):

```go
// onGatewayChange (third dhcp.New argument; may be nil) is fired
// whenever the gateway-relevant lease state of any interface
// changes: lease committed with a new/changed gateway, first lease
// acquired, or lease record removed (client terminated). Always
// fired outside m.mu.
func New(stateDir string, onAddressChange, onGatewayChange func()) (*Manager, error)
```

Fire sites — exactly **two** (corrected in v2; r1 convergent finding
SMR-1/Codex-1/AGY-1):

1. `commitLease` — after the store + before returning, when
   `prev == nil || prev.Gateway != lease.Gateway` (strictly narrower
   than `leaseContentChanged`; address/DNS-only changes do not fire).
2. `finishClient` (`dhcp.go:274-305`) — fired unconditionally after
   `m.mu.Unlock()`. This is the REAL lease-cleanup owner: it runs in
   the client goroutine's defer on **every** terminal exit, including
   the paths the run-loop `ctx.Done()` branches never see —
   cancellation mid-exchange (Codex r1's verified counterexample:
   T2 fails → fresh DORA in `doDHCPv4` → cancel → loop returns via the
   error path, only `finishClient` deletes the lease), DHCPv4
   max-retransmission exit, DHCPv6 link-local abort. Firing only from
   inline run-loop delete sites (the v1 design) would leave a stale
   gateway in the overlay after such an exit — a silent blackhole.
   The run-loop inline deletes stay untouched (their redundancy with
   finishClient is pre-existing); the unconditional fire is absorbed
   by the engine gate. v1's `removeLeaseAndNotify` helper is dropped.

Daemon wiring: `d.ipmon` is constructed before the first applyConfig
(`daemon_run.go:244`, by design comment), and the DHCP manager is
created lazily inside an apply (`daemon_dhcp.go:119`), so ordering is
safe today — but the hook is wired as a **nil-guarded closure**, not a
method value, so it stays safe under future reordering (SMR r1-2):

```go
dm, err := dhcp.New(stateDir, d.onDHCPAddressChange, func() {
    if e := d.ipmon; e != nil {
        e.NotifyNextHopChange()
    }
})
...
d.ipmon.SetNextHopResolver(d.resolveDHCPNextHop) // LeaseFor(key, AFInet).Gateway; nil-checks d.dhcp
```

Engine entry point:

```go
// NotifyNextHopChange marks the overlay dirty when any currently
// FAILED policy has an interface-typed preferred route, and kicks
// the run loop. Cheap: O(policies×routes) under mu, no resolution.
func (e *Engine) NotifyNextHopChange()
```

The gate ("any FAILED policy with an interface-typed route") bounds
actuations: lease churn on a box with no ip-monitoring DHCP routes, or
with all policies healthy, never actuates. When it does fire, the
normal debounce (1 s) + throttle (3 s) coalesce it with any concurrent
probe-driven transitions, and `frr-reload.py`'s diffing makes the FRR
side of a same-gateway re-actuation cheap.

**Publish/bump contract fix (Codex r1-2, folded):** v1 claimed the
snapshot side of a same-content actuation was also cheap via
`PublishRouteOverlaySnapshot`'s content-hash skip — but the skip
returns `nil` (`manager.go:846`) and `actuateRouteOverlayLocked`
unconditionally calls `BumpFIBGeneration()` after any nil publish
(`daemon_ipmon.go:180-188`), so a same-content actuation still
invalidates every cached flow route and emits a control message. Fix
shipped WITH this PR: `PublishRouteOverlaySnapshot` (manager + legacy
adapter + the `routeOverlayPublisher` interface in `daemon_ipmon.go`)
returns `(published bool, err error)`; the actuator bumps FIB
generation **only when `published`**. This preserves the load-bearing
publish-before-bump ordering (a skipped publish means the helper
already has these exact routes — no re-resolution needed) and turns
the duplicate-actuation cost into a no-op. Named test: duplicate
overlay publish ⇒ no `bump_fib_generation` message.

**Blocking honesty (Codex r1-3, reworded from v1):** the hook is NOT
"never blocking" — `NotifyNextHopChange` takes `Engine.mu`, which
`ActiveOverlay()`/`Status()` hold for a whole overlay build (including
resolver calls into `dhcp.mu`). It is **bounded** blocking with no
deadlock: the hook's caller never holds `dhcp.mu` (both fire sites are
post-unlock), so the `Engine.mu → dhcp.mu` order stays acyclic. A
`-race` contention test drives concurrent `Status()` + gateway hooks +
`commitLease`.

**What still happens in parallel (pre-existing, unchanged):** a gateway
change is lease *content* change, so `commitLease` also fires the
debounced (2 s) `onAddressChange` → full `applyConfig` (needed for FRR
`DHCPRoutes`, DNS, addresses). That full apply consumes
`ipmonActiveOverlay()` and therefore also carries the freshly resolved
overlay. The narrow hook is still required: it is what makes the
*engine* re-actuate (1 s debounce, routes-only, FIB-gen bump) without
depending on the full apply's breadth, and it covers the case where the
full apply is skipped (management-only branch of
`onDHCPAddressChange`) — irrelevant for overlay routes in practice, but
the engine must not silently depend on a side path. Both run under
`applySem`, so they serialize; both read live lease state at run time,
so either order converges to the same result.

### 4.4 Staleness/ordering analysis (dispatch question c)

- **Serialization:** `NotifyNextHopChange` enters the SAME dirty-bit →
  single-run-loop → `actuateRouteOverlay` queue as probe transitions
  and `Apply`. There is no second actuation path. A lease change racing
  a probe-driven failover collapses into one actuation that reads the
  freshest overlay (probe state under `Engine.mu`, lease state under
  `dhcp.mu` via the resolver) — last-writer-wins, the established #1827
  property.
- **Torn reads:** `commitLease` stores the lease under `dhcp.mu` and
  fires the hook after unlock. An actuation already in flight may
  resolve either the old or the new gateway — but the hook guarantees a
  subsequent actuation (dirty bit re-set) that resolves the new one.
  No ABA hazard: the resolver reads current state, not an event
  payload.
- **Within-one-apply consistency (small hardening, fold into this
  PR):** `applyConfigLocked` currently reads `ipmonActiveOverlay()`
  TWICE (`daemon_apply.go:446` for the snapshot setter, `:737` for
  FRR). With static next-hops the divergence window was probe-
  transition-sized; lease resolution widens it slightly. Capture the
  overlay ONCE into a local at the top of the apply's routing phase and
  pass it to both consumers. (Divergence was always self-healing via
  the next actuation, but one-read-per-apply makes it structural.)
- **Bounded actuation churn:** worst case is a pathological DHCP server
  re-gatewaying every renewal with a FAILED policy active: one
  routes-only actuation per throttle window (3 s) — same bound as a
  sustained probe flapper, already accepted in #1827 §4.3.

### 4.5 Withdrawal semantics (dispatch question d)

- **Lease record removed** (unit's dhcp stanza deleted, client stopped):
  delete-site hook fires → resolver returns `!ok` → candidate skipped →
  next actuation withdraws the route from FRR and the snapshot and
  bumps FIB generation. If no other candidate exists for the prefix,
  the config baseline (whatever static/Generate routes say) is
  re-exposed — never a stale hop.
- **No lease yet** (client started, not yet acquired): candidate skipped
  from the start; first `commitLease` fires the hook → route injected
  if the policy is FAILED. (Covered by the dirty-gate: FAILED policy
  with interface-typed route.)
- **Re-acquisition window** (T2 rebind failed, fresh DORA in progress):
  the lease record — and the kernel address — intentionally persist
  (#1777 behavior), so the resolver keeps returning the last-known
  gateway. This is **deliberate parity** with `collectDHCPRoutes`,
  which keeps the AD-200 FRR default pointing at the same gateway in
  the same window: DHCP-server unreachability does not imply the
  gateway is dead, and withdrawing the failover route while the lease
  address is still plumbed would break working traffic. Lease-expiry-
  driven withdrawal (compare `Obtained+LeaseTime` and wake the engine
  at expiry — the engine's `nextWakeLocked` could carry it) is listed
  as an open question (§12 Q2), NOT silently included: it adds timer
  machinery for a window in which the box-wide behavior (address +
  DHCP default route) is already "keep last known". All three r1
  reviewers ratified keep-last-known; AGY r1-4 adds the honest caveat
  that retaining an expired lease violates RFC 2131 §4.4.5 box-wide —
  **coupling rule, documented in `pkg/dhcp/README.md`:** if `pkg/dhcp`
  is ever fixed to expire addresses per the RFC, that change must
  route the lease-record removal through a path that fires the
  gateway-change hook (`finishClient` already does), so the overlay
  withdraws in lock-step with the address.
- **Manual renew transient (SMR r1-5):** `request dhcp client renew`
  → `Renew` cancels the client → `finishClient` removes lease AND
  address → fresh DORA. While a policy is FAILED, this produces a
  withdraw-then-reinject pair if re-acquisition outlasts the debounce.
  Correct (the uplink address itself is gone during the window) but
  operator-visible; documented in `docs/multi-wan.md`.
- **v6 exclusion:** DHCPv6 `Lease.Gateway` is an RA-discovered
  link-local (`discoverIPv6Router`); FRR statics need the interface for
  link-local next-hops (`DHCPRoute.Interface` exists for exactly this)
  and `RouteSnapshot` has **no device field** — adding one is a
  both-sides wire change (`protocol.go` + `protocol.rs`) with Rust FIB
  semantics work. Commit-rejected (§4.1 check 3) with a clear error;
  noted in docs. The v4-only cut matches the actual demand shape
  (consumer modem backup) and keeps this PR at zero wire changes. If
  reviewers judge v6 in-scope, the right answer is a separate issue
  after #1827 PR-2 (which already owns dp FIB table-semantics work).

### 4.6 Blast radius

`pkg/config` (compiler_services parse+validate, types_system field,
shared lease-key helper, schema desc), `pkg/ipmon` (resolver type +
SetNextHopResolver + NotifyNextHopChange + skip-unresolvable in
activeOverlayLocked + PolicyStatus.UnresolvedRoutes), `pkg/dhcp`
(`New` third argument + two fire sites: commitLease, finishClient),
`pkg/daemon` (resolveDHCPNextHop, closure wiring,
buildDHCPClientSpecs switches to shared helper, single-capture
hardening in applyConfigLocked, `routeOverlayPublisher` interface +
actuator bump-on-published-only), `pkg/dataplane/userspace`
(`PublishRouteOverlaySnapshot` returns `(published bool, err error)` —
manager + legacy adapter; Go-only, snapshot wire format untouched),
`pkg/api` (one gauge), docs (`docs/multi-wan.md`, `pkg/ipmon/README.md`,
`pkg/dhcp/README.md`). **Zero Rust. Zero wire protocol. Zero hot
path. No new goroutines** (the hook rides existing run-loop/timer
contexts; the engine loop is unchanged).

## 5. Staging

Single PR, gated on **PR #1843 merged** (this plan reads the tree as it
lands there). No sub-staging: the feature is one coherent seam
(config → resolver → trigger), and each piece is independently
unit-tested. PLAN-KILL tripwire during implementation: if wiring the
hook through the lazy DHCP-manager creation or the lock-order contract
turns out to require restructuring `pkg/dhcp`'s callback model (rather
than adding one optional hook), stop and re-plan — that would signal
the notification belongs at the daemon layer (wrapping
`onDHCPAddressChange`) instead, which is Fork 2 Path B (§11).

## 6. Public API / compatibility

- Config back-compat: literal-IP next-hops parse and validate exactly
  as today; the new form is additive. No schema node changes ⇒ no
  completion-behavior change (value slot already free-form).
- `pkg/dhcp` exported surface: `New` gains a third (nil-able)
  parameter — a deliberate signature change (single in-tree caller at
  `daemon_dhcp.go:119` + tests), chosen over a setter to make the hook
  immutable (AGY r1-2); `ClientSpec`/fingerprints untouched — the
  #1793 config-identity rule is preserved (NextHopInterface lives in
  `PreferredRoute`, which never feeds Reconcile).
- `pkg/ipmon` exported surface: `SetNextHopResolver`,
  `NotifyNextHopChange`, `NextHopResolver` type,
  `PolicyStatus.UnresolvedRoutes`. `New` signature unchanged.
- `PublishRouteOverlaySnapshot` return type changes to
  `(published bool, err error)` on the userspace Manager, the legacy
  adapter, and the `routeOverlayPublisher` interface (Codex r1-2) —
  in-tree consumers only.
- `RouteOverlayEntry`, FRR `FullConfig`, `RouteSnapshot`: unchanged.
- HA/config-sync: `NextHopInterface` is config (syncs normally); the
  resolved gateway is runtime state inside the overlay (never syncs) —
  same split as #1827. Standby publishes baseline regardless
  (`publishEnabled` gate unchanged). Note: a DHCP client on a
  VIP-owned/RETH uplink in a cluster has pre-existing semantics
  questions (who holds the lease) that are NOT introduced or changed
  here; the overlay only ever publishes on the primary.

## 7. Hidden invariants the change must preserve

1. **No actuation outside the engine loop** — the hook only marks
   dirty + kicks; `actuateRouteOverlay` remains the engine's single
   actuation callsite, under `applySem`.
2. **Publish-before-bump ordering** — preserved, with one refinement:
   the bump now fires only on `published == true` (a skipped publish
   means the helper already holds these exact routes, so skipping the
   bump cannot strand a flow on stale routes — Codex r1-2 worked
   trace).
3. **One-way lock order** `Engine.mu → dhcp.Manager.mu`; the dhcp hook
   fires outside `dhcp.mu`; the resolver never calls back into ipmon.
   The hook is bounded-blocking, not non-blocking (Codex r1-3): it may
   wait on `Engine.mu` held across an overlay build; acyclic by the
   fire-outside-`dhcp.mu` rule; `-race` contention test required.
4. **Reconcile keys on config identity only** (#1793) — no new
   fingerprint inputs.
5. **commitLease single-commit-path** (#1777) — the hook is added
   inside it, not as a new parallel path; the debounced
   `onAddressChange` semantics are untouched.
6. **Engine purity** — `pkg/ipmon` imports neither `pkg/dhcp` nor
   netlink; resolution is an injected func (testable with fakes).
7. **Winner-resolution determinism** — skip-unresolvable happens before
   the `best[key]` comparison; with a fixed resolver the overlay is a
   pure function of (policy state, lease state).
8. **Control-socket budget** — no new message classes; actuation rate
   still bounded by throttle.
9. **Logging rules** — gateway-change re-actuations log at Info only on
   actual overlay change (the engine's existing transition logs);
   per-lease hook firing is Debug.

## 8. Risk assessment

| Class | Risk | Notes |
|-------|------|-------|
| Behavioral regression | LOW | Literal-IP path untouched (validated by existing tests); new path is additive and default-off (requires new config). |
| Deadlock/lock-order | LOW-MED | The one genuinely new cross-package edge (engine→dhcp under Engine.mu). Mitigated: documented one-way order, hook fires outside dhcp.mu, no reverse call path exists; a targeted test exercises hook-during-ActiveOverlay concurrency under `-race`. |
| Stale next-hop | MED (accepted, documented) | Re-acquisition window keeps last-known gateway — parity with FRR DHCP default (§4.5); expiry refinement is §12 Q2. |
| HA | LOW | Publication gating unchanged; resolved state never syncs. |
| Performance | NONE | Control plane only; resolver is two map lookups under a mutex, called only at overlay computation. |
| Architectural | LOW | Works with the established single-decision-point overlay; no second actuation path is created. |

## 9. Test & smoke plan (dispatch question e)

**Unit/CI (the seams are already injectable):**

- Compiler: flat-set (`ParseSetCommand()`+`SetPath()` loop) AND
  hierarchical parses of interface-typed next-hop; commit checks —
  unknown unit, non-DHCP unit, inet6 destination, VLAN unit key
  derivation; literal-IP regression suite unchanged.
- Shared helper: `DHCPLeaseIfName` equals what `buildDHCPClientSpecs`
  produces for plain/VLAN units (differential test over the spec
  builder).
- Engine (fake resolver + fake clock): (1) unresolvable winner ⇒
  losing static candidate wins (the §4.2 pre-winner-selection
  property, the load-bearing test of this plan); (2) resolver flips
  ok→!ok ⇒ next overlay omits the route (withdrawal); (3)
  `NotifyNextHopChange` gate — fires dirty only with a FAILED
  interface-typed policy; healthy policies/lease churn ⇒ no actuation;
  (4) gateway value change ⇒ exactly one actuation per
  debounce+throttle window (coalescing with a simultaneous probe
  transition); (5) nil-resolver defensive skip.
- dhcp: `commitLease` hook firing matrix — first lease fires, renewal
  with same gateway does NOT fire, gateway change fires, address-only
  change does NOT fire; `finishClient` fires on EVERY terminal exit —
  including Codex r1-1's cancel-mid-exchange counterexample and the
  max-retransmission exit (via `runClientForTest` seam); hook fired
  outside `m.mu` (deadlock test: hook calls `LeaseFor`); `-race`
  contention test driving concurrent `Status()` + hooks + commits.
- Daemon: `resolveDHCPNextHop` nil-dhcp safety; single-capture apply
  hardening (one `ipmonActiveOverlay` read per apply — assert via a
  counting fake); actuator ordering test extended: duplicate overlay
  publish (content-hash skip) ⇒ NO `BumpFIBGeneration`; changed
  publish ⇒ bump strictly after publish success (Codex r1-2).
- `make test` full suite green.

**Smoke (loss userspace cluster + standalone VM, honest about what each
proves):**

- Loss cluster: re-run the #1843 ip-monitoring smoke unchanged
  (regression: literal next-hop failover still flips end-to-end), plus
  `make test-failover` (cluster-adjacent code touched: daemon wiring).
- DHCP scenario (standalone test VM): `dnsmasq` on an incus test
  bridge serving a gateway option to a dedicated unit; configure the
  policy with the interface-typed next-hop; verify in order: lease
  acquired → policy forced FAILED (blackhole the probe target) →
  injected route shows the DHCP gateway in FRR + kernel +
  `show services ip-monitoring status` → change dnsmasq's
  router option + force renew (`request dhcp client renew`) → injected
  route re-points within debounce+throttle without daemon restart or
  full-apply log line from the engine path → delete the dhcp stanza →
  route withdraws.
- What this does NOT prove: real modem/CPE behavior, v6 (excluded),
  DHCP-on-RETH cluster semantics (pre-existing, out of scope).

## 10. Out of scope (explicitly)

- inet6 / DHCPv6 (RA-gateway) tracked next-hops — commit-rejected;
  needs a `RouteSnapshot` device field = wire change (§4.5).
- DHCP routes in the *baseline* dp FIB (DHCP uplink as primary
  fast-path uplink) — independent pre-existing limitation, stays in
  `docs/multi-wan.md`.
- Lease-expiry-driven withdrawal (§12 Q2 — decision requested, default
  out).
- PPPoE/static-with-RA or any non-DHCP learned gateways.
- #1827 PR-2 (FBF), PR-3 (NAT), PR-4 (load-share) — untouched.
- eventengine, config-sync changes.

## 11. Path options (the real forks)

**Fork 1 — config spelling:**

- **Path A (RECOMMENDED): interface-valued `next-hop`** —
  `next-hop ge-0/0/3.0`. Reads as Junos (operators write interface
  next-hops in static routes today), zero schema-shape change, one
  token expresses one concept, flat-set delete/merge semantics
  identical to the literal form. Resolution rule is explicit via
  commit checks (unit must be `family inet dhcp`), so there is no
  silent "interface route" ambiguity.
- **Path B: bare `next-hop dhcp` keyword** — requires inferring WHICH
  uplink (from the probe's `destination-interface`? from the only DHCP
  unit?), an implicit coupling that breaks with multiple DHCP units or
  multi-interface probes. Rejected.
- **Path C: sibling leaf `interface <name>`** under `route` — splits
  one concept across two mutually-exclusive leaves, needs new schema
  nodes + exclusivity validation, and reads like an invented subsystem
  knob. Rejected.

**Fork 2 — where the lease-change notification enters:**

- **Path A (RECOMMENDED): `pkg/dhcp` constructor-arg hook → engine**
  (§4.3, revised per AGY r1-2). Fires on exactly the state that
  matters (gateway delta at commitLease + terminal cleanup at
  finishClient), independent of the daemon's full-apply debounce; the
  engine's gate keeps it quiet.
- **Path B: daemon-level — piggyback `onDHCPAddressChange`** (call
  `NotifyNextHopChange` next to `applyConfig`). Less new API, but:
  inherits the 2 s content-change debounce (fires on DNS/address-only
  changes too — gate still saves us), MISSES the lease-delete path
  entirely (client stop does not go through `onAddressChange`;
  withdrawal would silently wait for the next unrelated actuation —
  disqualifying for §4.5), and couples the engine's trigger to the
  full-apply path the #1827 plan explicitly walls off. Fallback only
  (named as the §5 tripwire pivot, with an explicit delete-path shim
  if ever taken).
- **Path C: resolve at compile/apply time, store resolved IP in
  config** — turns lease state into config (violates the #1827
  runtime-state-never-config rule and the #1793 identity rule), goes
  stale between applies. Rejected.

**Fork 3 — resolution point:**

- **Path A (RECOMMENDED): in-engine, pre-winner-selection,** injected
  resolver (§4.2). Correct winner semantics; testable; single point.
- **Path B: daemon-side post-processing of `ActiveOverlay()`** — keeps
  ipmon dependency-free without injection, but resolves AFTER winner
  selection (wrong when an unresolvable winner shadows a resolvable
  loser) and scatters resolution across the accessor wrapper. Rejected
  on the correctness corner alone.

## 12. Open questions — RESOLVED in round 1

1. **Spelling:** ratified by all three. No parse ambiguity (no valid
   interface name parses as an IP; AGY's degenerate dotted-quad-name
   corner accepted as a non-issue); no tunnel rejection beyond
   `unit.DHCP` (Codex, SMR concur). Normalization pinned in §4.1
   check 2 (SMR r1-3).
2. **Lease-expiry withdrawal:** keep-last-known ratified by all three;
   no expiry timers in this PR (Codex explicit). RFC 2131 coupling
   rule documented instead (AGY r1-4, §4.5).
3. **Gate sufficiency:** sufficient ONLY with the publish/bump
   contract fix (Codex r1-2, folded into §4.3); with it, a duplicate
   actuation is a no-op end-to-end. Per-key resolved-gateway caching
   rejected as premature by all three.
4. **v4-only:** ratified by all three with independent verification of
   the `RouteSnapshot`-device-field wire constraint.
5. **Hook shape:** aggregate `func()` ratified (Codex: contingent on
   the Q3 fix, which is folded).

---

*Round-1 verdicts: Claude SMR PLAN-NEEDS-REVISION
(`claude-smr-plan-r1.md`, 7 findings), Codex PLAN-NEEDS-REVISION
(`codex-plan-r1.md`, task-mq8jm9hz-g87plf, 3 findings), AGY
PLAN-NEEDS-REVISION (`agy-plan-r1.md`,
adversarial-review-mq8jmtlt-vq5w6c, 4 findings). No architectural
objection from any reviewer; every finding folded into v2 (see Status
header). Reviewer IDs in `reviewer-ids.md`.*
