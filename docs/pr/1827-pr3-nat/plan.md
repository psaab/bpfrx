# #1827 PR-3 — NAT interplay: mini-plan + session-transition semantics review

Status: adjudicated in this PR's quad-review round (the §5 staging row's
"semantics mini-review"). Program plan:
`docs/research/1827-multiwan/plan.md` @ origin/research/1827-multiwan.

Staging row under review:

> **PR-3** | NAT interplay: per-uplink SNAT pools (verify existing
> zone/rule-set matchers suffice), defined session behavior on uplink
> transition (fib-generation re-resolution + invalidation of sessions
> whose SNAT binding references the failed uplink, via existing filtered
> session-clear), counters + show reason | Gate: PR-2 merged; semantics
> mini-review in its PR plan | Kill: if NAT-binding-keyed invalidation
> needs per-packet hot-path state the dp doesn't carry — fallback is
> Junos-like timeout behavior (document, don't build).

Verdict up front: **the stage-local PLAN-KILL is NOT triggered.** No
per-packet hot-path state is needed anywhere in this scope. PR-3 shrinks
to (a) verification + docs for per-uplink SNAT (existing matchers
suffice), and (b) Junos-parity operator tooling for session invalidation
(`source-nat-pool` show/clear filter) plus repair of the existing
filtered-clear path it rides on. Zero hot-path Rust changes, zero wire
protocol (`protocol.go`/`protocol.rs`) changes, zero config-schema
changes.

## Part A — per-uplink SNAT pools: existing matchers SUFFICE

Question the row asks: can an operator give each uplink its own SNAT
pool with the matchers we already have, under both failover (PR-1b route
flip) and per-policy steering (PR-2 FBF)?

**Yes.** Evidence trail (all on current master):

1. SNAT rule-set selection is keyed on the **zone pair**, and the
   to-zone is derived from the **resolved egress interface** of each new
   flow — not from static config:
   `userspace-dp/src/afxdp/poll_descriptor/mod.rs:689`
   (`zone_pair_ids_for_flow_with_override(..., resolution.egress_ifindex)`)
   feeds `source_nat_decision_for_flow` →
   `match_source_nat_result_for_tuple`. When ip-monitoring flips the
   preferred route (or an FBF term steers a flow into an uplink's
   routing-instance/table), the resolution lands on the other uplink's
   interface, the to-zone follows it, and the other rule-set's pool is
   chosen. There is nothing to build.
2. `SourceNatRule::matches` (`userspace-dp/src/nat/source.rs:151`)
   honors `from_zone`/`to_zone` with empty-string wildcards — the
   per-zone rule-set boundary is already enforced per-flow.
3. Interface-mode SNAT (`then source-nat interface`) translates to the
   **resolved egress interface's primary address**
   (`userspace-dp/src/nat/source.rs`, `interface_mode` branch using
   `egress.primary_v4/primary_v6`) — per-uplink by construction, even
   when both uplinks share one zone.

**Supported recipes (documented in `docs/multi-wan.md`):**

- *Zone-per-uplink* (recommended): `untrust-a` / `untrust-b` zones, one
  rule-set per zone (`from zone trust to zone untrust-a → pool isp-a`),
  one pool per uplink. Works for pool-mode SNAT under both failover and
  FBF steering.
- *Interface SNAT*: `then source-nat interface` follows the resolved
  egress automatically; works even with a single shared uplink zone.

**Documented limitation (not built):** Junos additionally allows source
NAT rule-sets scoped `to interface <if>` / `to routing-instance <ri>`.
xpf's `NATRuleSet` carries only `FromZone`/`ToZone`
(`pkg/config/types_security.go:266`). Pool-mode SNAT with **both uplinks
in one zone** therefore has no per-uplink rule-set discriminator today.
The recipes above cover the standard dual-WAN deployments; adding
`to interface` rule-set matching would touch the Rust matcher + snapshot
wire shape for a configuration that has a clean zone-based equivalent —
deliberately out of PR-3's smallest defensible unit. Follow-up issue
only if demand materializes.

**Verification shipped in this PR:** Rust test (test-only change) in
`userspace-dp/src/nat/tests.rs`: two rules identical except `to_zone`
(`untrust-a`→pool A, `untrust-b`→pool B); assert the translated source
flips with the to-zone, both families. Plus a Go snapshot test in
`pkg/dataplane/userspace` asserting two rule-sets with distinct ToZones
compile into ordered `SourceNATRuleSnapshot`s carrying their own pool
addresses.

## Part B — defined session behavior on uplink transition

### B.1 The semantics (worked trace, verified against source — REVISED in r1)

> r1 revision (Codex High, verified): v1 of this trace claimed the
> FIB-generation bump makes established flows re-resolve and egress
> the surviving uplink. The source does not support that for
> locally-created sessions; the corrected trace below is what the dp
> actually does.

1. Policy FAILs → ipmon actuator publishes the overlay snapshot, then
   `BumpFIBGeneration()` (PR-1b, order load-bearing).
2. The bump updates only validation state: workers invalidate
   flow-cache entries stamped with the old generation
   (`coordinator/mod.rs` `bump_fib_generation`; `flow_cache.rs:626`
   stamp check). The session table is untouched.
3. The next packet of an established flow misses the flow cache and
   takes the session-hit path — which for **locally-created sessions**
   prefers the session's **stored** forwarding resolution over a fresh
   FIB lookup: `lookup_forwarding_resolution_for_session` passes
   `allow_cached_fast_path = true` (`session_glue/mod.rs:65-77`) and
   `cached_session_resolution` (`session_glue/mod.rs:18-42,104-107`)
   returns the stored egress/neighbor whenever it is a usable
   ForwardCandidate. The flow cache is then re-populated with the OLD
   resolution under the NEW generation.
4. ⇒ **Established locally-created sessions stay pinned to the failed
   uplink entirely** — old egress interface, old neighbor MAC, old NAT
   binding (`NATSrcIP/NATSrcPort` fixed at install,
   `pkg/dataplane/types.go:33`). Their traffic keeps leaving the dead
   path and blackholes until the inactivity timeout or an operator
   clear. New flows resolve via the overlay and are correct
   immediately.
5. Asymmetry worth knowing: **peer-synced sessions** resolve
   lookup-first (`lookup_forwarding_resolution_for_synced_session`,
   `allow_cached_fast_path = false`) and fall back to the stored
   resolution only on NoRoute/MissingNeighbor — those DO re-resolve
   onto the injected route.

This is Junos parity in substance: SRX likewise does not re-route or
re-NAT established sessions on a route change by default; they age out
unless cleared. Junos ip-monitoring has **no** session-clear action.

**Divergence from the program-plan row, surfaced by this mini-review:**
the row's wording ("fib-generation re-resolution + invalidation of
sessions whose SNAT binding references the failed uplink") assumed
established flows re-resolve their route and only the NAT binding pins.
The dp's actual contract is stronger pinning — stored-resolution reuse
for local sessions — which makes the operator clear **the** mechanism
for moving established flows to the surviving uplink, not merely a NAT-
correctness aid. It also means the zone/interface clear filters remain
accurate for pinned sessions (the stored EgressZone/FibIfindex never
silently change). No code change required; the defined behavior is
documented in `docs/multi-wan.md`.

### B.2 Decision: no automatic invalidation; Junos-parity operator clear

Automatic clearing on FAIL transition was considered and **rejected**:

- Junos parity: ip-monitoring never touches the session table.
- Flap safety: a flapping probe would mass-clear sessions every
  transition; hold-down damps recovery only, not fail.
- The binding→uplink mapping (which pool belongs to which uplink) is
  operator knowledge, not config the engine can see.

What Junos gives the operator instead — and what this PR ships — is the
**`source-nat-pool` session filter** (`clear security flow session
source-nat-pool <pool>`, Junos 23.4R1; same filter on `show security
flow session`): "invalidate sessions whose SNAT binding references the
failed uplink, via existing filtered session-clear", exactly as the
staging row words it.

- Membership predicate (control-plane only, evaluated during the
  existing session-table iteration): `Flags&SessFlagSNAT != 0` AND
  translated source `NATSrcIP` ∈ the named pool's compiled address set
  (`cfg.Security.NAT.SourcePools[name]` — ranges are pre-expanded at
  compile time). Junos matches the actual pool binding; address
  membership is equivalent unless pools overlap, which is itself a
  misconfiguration — documented.
- Unknown pool name is an error, never an empty filter (an empty filter
  must not degrade into clear-all).
- Surfaces: local CLI, remote CLI, gRPC (`GetSessionsRequest` +
  `ClearSessionsRequest` new fields — additive protobuf, NOT the dp wire
  protocol), cmdtree completion over configured pool names, HA peer
  forwarding.

### B.3 Repairs to the path the recipe rides on (found during survey)

The row says "via existing filtered session-clear" — that path has
latent defects that would make the recipe silently wrong, so fixing them
is in-scope:

1. **Peer-forwarded clear drops filters → peer clears ALL sessions.**
   `pkg/cli/cli_clear.go:274` forwards only
   src/dst-prefix/proto/ports/application. A local
   `clear security flow session interface ge-0-0-2` (or zone / nat-only
   filtered clear) forwards an **empty** `ClearSessionsRequest`, and the
   peer's gRPC handler treats no-filters as clear-all
   (`pkg/grpcapi/server_sessions.go:645`). On an HA pair the operator
   recipe would wipe the peer's whole session table. Fix: carry
   zone/interface/nat-only/source-nat-pool in `ClearSessionsRequest` and
   forward them.
2. **Local-CLI `clear ... interface <if>` matches nothing.**
   `clearFilteredSessions` evaluates `sessionFilter.matchesV4/V6` with
   `zoneIfaces`/`egressIfacesMap` unpopulated (only the show path
   populates them, `cli_show_flow.go:254`) — the cmdtree-advertised
   interface filter clears 0 sessions. Fix: populate both maps in the
   clear path.
3. **Port filters compare network-order key ports to host-order
   values.** `pkg/cli/session_filter.go` (`key.SrcPort != f.srcPort`)
   and the gRPC `ClearSessions` inline filter
   (`server_sessions.go:731-737`) both skip `ntohs`; the server-side
   *show* filter does it correctly (`matchV4`, `server_sessions.go:368`).
   Port-filtered show (local CLI) and clear (both) match only
   byte-palindromic ports today. Fix: `ntohs` at the comparison; the
   gRPC `ClearSessions` handler is rebuilt on the same `sessionFilter`
   matcher the show path uses, so show and clear can never diverge
   again.

### B.4 Counters + show reason

- `clear security flow session ...` already reports per-family cleared
  counts; the new filter inherits that.
- "How many sessions are pinned to the failed uplink?" =
  `show security flow session source-nat-pool <pool>` (filtered
  listing; the local CLI's `summary` composes with filters for a
  filtered count — the remote CLI's `summary` keyword bypasses filters,
  a pre-existing behavior for every filter). Computed on demand from
  the same session iteration. **No periodic scan** is
  added (session dumps ride the shared control socket; a per-poll-tick
  pinned-session gauge would violate the control-socket budget rule), so
  no new Prometheus series.
- "Why did the policy fail / what was applied" already ships in
  `show services ip-monitoring status` (failing tests, applied routes,
  unresolved next-hops, transition count — PR-1b/#1844). No change.

### B.5 Operator runbook (lands in `docs/multi-wan.md`)

1. `show services ip-monitoring status` — confirm FAIL + applied routes.
2. `show security flow session source-nat-pool isp-a-pool summary` —
   count pinned sessions.
3. `clear security flow session source-nat-pool isp-a-pool` — pinned
   flows re-establish via the surviving uplink and match the new
   egress zone's rule-set/pool. (Or do nothing: Junos-parity timeout.)

## Scope summary

| Touched | What |
|---------|------|
| `proto/xpf/v1/xpf.proto` (+regen) | `ClearSessionsRequest`: interface/nat_only/source_nat_pool; `GetSessionsRequest`: source_nat_pool. Additive field numbers. |
| `pkg/config` | `SourceNATPoolNets` helper (pool name → `[]*net.IPNet`). |
| `pkg/grpcapi` | filter predicate; `ClearSessions` rebuilt on the shared matcher; B.3 fixes. |
| `pkg/cli` | filter parse/match + B.3 fixes + peer forwarding. |
| `cmd/cli` | parse/send new filters for show + clear. |
| `pkg/cmdtree` | `source-nat-pool` completion (show + clear), pool-name DynamicFn. |
| `userspace-dp/src/nat/tests.rs` | test-only: to-zone pool selection. |
| docs | `docs/multi-wan.md` PR-3 section; touched-package READMEs. |

Not touched: dp wire protocol, session structs, Rust hot path, config
schema/parser, ipmon engine, HA sync.

## Kill-criterion check

Per-packet hot-path state for NAT-binding-keyed invalidation: **not
needed**. Invalidation is operator-triggered, control-plane-iterated,
and uses session fields (`Flags`, `NATSrcIP`) that already exist in the
dump. The fallback ("document timeout behavior, don't build") is
partially adopted anyway: timeout remains the default, documented
behavior; the clear filter is the optional operator path the row itself
named.
