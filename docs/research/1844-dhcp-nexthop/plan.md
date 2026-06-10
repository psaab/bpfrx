# #1844 ip-monitoring: DHCP-learned-uplink support for preferred-route next-hops

**Status:** DRAFT v1 — research round 1

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
2. Otherwise it must parse as `<ifd>.<unit>` where the unit exists in
   `cfg.Interfaces` — else the existing "not a valid IP address" error
   is extended to "…not a valid IP address or DHCP interface unit".
3. The destination family must be **inet** (v4). `inet6` destinations
   with an interface-typed next-hop are commit-rejected with a pointer
   to the follow-up (§4.5 rationale: DHCPv6 gateways are RA-derived
   link-locals; `RouteSnapshot` has no device field; supporting it is a
   wire-protocol change).
4. The named unit must have `family inet dhcp` (`unit.DHCP`) — the
   route tracks a DHCP gateway by definition; a static-addressed unit
   is rejected ("interface-typed next-hop requires family inet dhcp on
   <unit>").
5. The lease key stored in `NextHopInterface` is derived by a **shared
   helper** extracted from `buildDHCPClientSpecs`'s inline logic —
   `config.DHCPLeaseIfName(ifName string, unit *UnitConfig) string`
   (LinuxIfName + vlan suffix) — used by BOTH the spec builder and the
   compiler so the two derivations can never drift. (The helper lives
   in `pkg/config` because the compiler cannot import `pkg/daemon`;
   `buildDHCPClientSpecs` switches to it in the same commit.)

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
`Routes`; `display.go` adds an "unresolved (no DHCP lease)" annotation
per policy by diffing `cfg`-declared routes against resolved ones (kept
cosmetic; not a state-machine input). New gauge
`xpf_ipmon_unresolved_next_hops` (count of skipped candidates at last
overlay computation) for alerting.

### 4.3 The re-resolution trigger — narrow hook, NOT applyConfig

The #1844 body names the #1777 commit-lease path as the hook; the
#1827 plan's hard rule is that route actuation must ride the
routes-only actuator, never a full apply. Both are satisfied with one
optional callback on `dhcp.Manager`:

```go
// SetGatewayChangeHook registers a callback fired whenever the
// gateway-relevant lease state of any interface changes: lease
// committed with a new/changed gateway, first lease acquired, or
// lease record removed (client stopped). Fired outside m.mu.
func (m *Manager) SetGatewayChangeHook(hook func())
```

Fire sites (all already exist as state-mutation points):

1. `commitLease` — after the store + before returning, when
   `prev == nil || prev.Gateway != lease.Gateway` (strictly narrower
   than `leaseContentChanged`; address/DNS-only changes do not fire).
2. The lease-delete paths — the `ctx.Done()` branches of `runDHCPv4` /
   `runDHCPv6` that `delete(m.leases, key)` (this is also the Reconcile
   stop path: Reconcile cancels the client context, and the run loop's
   own goroutine performs the delete). One helper
   `removeLeaseAndNotify(key)` replaces the four inline delete sites so
   a future fifth site cannot forget the hook.

Daemon wiring (`daemon_run.go`, next to the existing
`ipmon.New(d.actuateRouteOverlay)` at line 244):

```go
d.ipmon.SetNextHopResolver(d.resolveDHCPNextHop) // LeaseFor(iface, AFInet).Gateway
d.dhcp.SetGatewayChangeHook(d.ipmon.NotifyNextHopChange) // at dhcp.New time, daemon_dhcp.go:119
```

(The DHCP manager is created lazily in `reconcileDHCPClients`; the hook
is registered immediately after `dhcp.New` there, and `d.ipmon` is
constructed earlier in `Run`, so ordering is safe. `d.resolveDHCPNextHop`
nil-checks `d.dhcp` — resolver calls can arrive before any DHCP client
exists.)

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
probe-driven transitions, and `PublishRouteOverlaySnapshot`'s
content-hash skip plus `frr-reload.py`'s diffing make a same-gateway
re-actuation cheap. The hook itself never blocks: it takes `Engine.mu`
briefly and pokes the non-blocking `kick` channel.

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
  DHCP default route) is already "keep last known".
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
activeOverlayLocked + display annotation), `pkg/dhcp`
(SetGatewayChangeHook + fire sites + removeLeaseAndNotify helper),
`pkg/daemon` (resolveDHCPNextHop, hook wiring, buildDHCPClientSpecs
switches to shared helper, single-capture hardening in
applyConfigLocked), `pkg/api` (one gauge), docs (`docs/multi-wan.md`,
`pkg/ipmon/README.md`, `pkg/dhcp/README.md`). **Zero Rust. Zero wire
protocol. Zero hot path. No new goroutines** (the hook rides existing
run-loop/timer contexts; the engine loop is unchanged).

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
- `pkg/dhcp` exported surface: one new optional setter; existing
  callers (daemon) unaffected; `ClientSpec`/fingerprints untouched —
  the #1793 config-identity rule is preserved (NextHopInterface lives
  in `PreferredRoute`, which never feeds Reconcile).
- `pkg/ipmon` exported surface: `SetNextHopResolver`,
  `NotifyNextHopChange`, `NextHopResolver` type. `New` signature
  unchanged.
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
2. **Publish-before-bump ordering** — untouched
   (`actuateRouteOverlayLocked` body unchanged).
3. **One-way lock order** `Engine.mu → dhcp.Manager.mu`; the dhcp hook
   fires outside `dhcp.mu`; the resolver never calls back into ipmon.
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
  change does NOT fire; delete-site helper fires on client stop (via
  `runClientForTest` seam); hook fired outside `m.mu` (deadlock test:
  hook calls `LeaseFor`).
- Daemon: `resolveDHCPNextHop` nil-dhcp safety; single-capture apply
  hardening (one `ipmonActiveOverlay` read per apply — assert via a
  counting fake); actuator ordering test unchanged (re-run).
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

- **Path A (RECOMMENDED): `pkg/dhcp` hook → engine** (§4.3). Fires on
  exactly the state that matters (gateway delta + lease delete), at the
  single commit path (#1777), independent of the daemon's full-apply
  debounce; the engine's gate keeps it quiet.
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

## 12. Open questions for adversarial review (round 1)

1. **Spelling ratification (Fork 1):** does `next-hop <ifd>.<unit>`
   carry hidden parse ambiguity anywhere (interface names that parse as
   IPs do not exist, but reviewers should hunt counter-examples —
   e.g. weird unit syntax, RETH names, `st0.0`-style tunnels)? Should
   tunnel/non-Ethernet units be explicitly rejected beyond the
   `unit.DHCP` check (which already excludes them)?
2. **Lease-expiry withdrawal:** keep last-known gateway through the
   re-acquisition window (recommended, parity with the FRR DHCP
   default) — or withdraw at `Obtained+LeaseTime` expiry via an engine
   wake? Concrete operator scenario where parity is wrong is the bar
   for adding the timer machinery.
3. **Gate sufficiency (§4.3):** "any FAILED policy with interface-typed
   route" can produce a same-content actuation (gateway unchanged but
   lease re-committed after client restart). Acceptable (content-hash +
   frr-reload diff make it cheap, bounded by throttle), or should the
   engine cache the last-resolved gateway per key and compare?
4. **v4-only cut:** any reviewer sees near-term demand for v6
   interface-typed next-hops strong enough to justify pulling the
   wire-protocol device-field work forward?
5. **Hook shape:** is a single aggregate `func()` hook (re-resolve
   everything) right, or should it carry the affected lease key? The
   aggregate is simpler and the resolver re-reads everything anyway;
   per-key adds payload with no consumer.

---

*Round-1 verdicts: pending (Claude SMR + Codex + AGY docs beside this
file). Reviewer task IDs in `reviewer-ids.md`.*
