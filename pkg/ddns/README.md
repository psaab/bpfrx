# pkg/ddns — Dynamic DNS spine

`pkg/ddns` is the provider-neutral Dynamic DNS spine extracted from
`pkg/dhcpserver` in **#2691 phase P1a** (a verbatim, no-behavior-change code
move; see `docs/research/ddns-world-class/plan.md` §9). It owns the reconcile
engine, the ownership state store, the RFC 2136 backend, and the DNS record /
hostname helpers. `pkg/dhcpserver` is now a *caller* of this spine.

This extraction is the foundation the #2691 world-class redesign (ScopeKey,
per-RG HA gate, source binding, router/interface-address publish, HTTP provider
backends) builds on in phases P1b–P3. P1a changes **no behavior** — every test
moved with its assertions intact.

## What lives here

| File | Contents |
|------|----------|
| `manager.go` | `Manager` (the DDNS reconcile engine — moved from `dhcpserver/ddns.go`): `policyFromConfig`, `Reconcile`, `reconcileOnceLocked`, `upsertLocked`/`deleteOwnedLocked`, `withdrawAllLocked`, `ownerWatermark`, `Stats`, `OwnedRecordView(s)`, the write-ahead durability + never-delete-non-owned boundary. Also the `Lease` record + `LeaseParser` seam. |
| `state.go` | Ownership state store (`ownedRecord`, `ddnsState`, `loadDDNSState`, durable `save` via `fsatomic.WriteFileDurable`) — moved from `dhcpserver/ddns_state.go`. |
| `backend.go` | `DNSUpdater` interface, `LeaseDNSRecord`, `nopUpdater`, the record + reverse-PTR-name helpers — moved from `dhcpserver/ddns_dns.go`. |
| `backend_rfc2136.go` | The LIVE RFC 2136 backend (`rfc2136Updater`): exact-RR adds/deletes, TSIG, RFC 4701 DHCID + RFC 4703 replace-owned two-attempt, the `errDDNSConflictRefused` / `errDDNSPTRPending` sentinels — moved from `dhcpserver/ddns_rfc2136.go`. |
| `hostname.go` | Deterministic hostname → DNS-label normalization (pure) — moved from `dhcpserver/ddns_hostname.go`. |

Tests moved with the code: `manager_test.go` (engine + state-store + hostname),
`backend_rfc2136_test.go` (backend, drives a real in-process miekg/dns server),
`durability_test.go` (#2662 write-ahead), `manager_inc2_test.go`
(manager + live backend integration).

## The package boundary (why a `LeaseParser` seam)

The Kea-memfile lease parser (`parseActiveLeases`, `ddnsLease`, `identity4/6`,
the `keaLeaseType*` constants) **stays in `pkg/dhcpserver`** (`ddns_leases.go`):
it is entangled with the lease-sync memfile fallback (`lease_sync.go`,
#2239/#2262), which is DHCP-server-specific, not DDNS-specific. To keep
`pkg/dhcpserver`'s parser as the lease source **without an import cycle**, the
engine reads leases through an injected seam:

```go
type Lease struct { Family int; Address, Identity, SubnetID, HostName, ClientFQDN string }
type LeaseParser func(path string, family int, now time.Time) ([]Lease, error)
```

`pkg/dhcpserver` supplies the parser (`keaLeaseParser`, which calls
`parseActiveLeases` and projects each `ddnsLease` onto `ddns.Lease`) when it
constructs the manager. The dependency is one-way: **`pkg/ddns` never imports
`pkg/dhcpserver`.** `pkg/ddns` imports only `pkg/config` (for the typed
`DHCPDynamicDNSConfig` the policy/backend factory consume) and `pkg/fsatomic`.

## Cross-package surface (used via `pkg/dhcpserver` aliases)

`pkg/daemon`, `pkg/grpcapi`, `pkg/cli`, and `pkg/api` keep referring to these
through `dhcpserver.*` type aliases (`DDNSManager`, `DNSUpdater`,
`LeaseDNSRecord`, `DDNSStats`, `DDNSOwnedRecordView`) so the P1a move required
no change in those packages:

| `pkg/ddns` | `pkg/dhcpserver` alias / wrapper |
|---|---|
| `Manager` | `DDNSManager` |
| `DNSUpdater` | `DNSUpdater` |
| `LeaseDNSRecord` | `LeaseDNSRecord` |
| `Stats` | `DDNSStats` |
| `OwnedRecordView` | `DDNSOwnedRecordView` |
| `NewManager(parser, updater, nodeID)` | `NewDDNSManager(updater, nodeID)` (wires `keaLeaseParser`) |
| `NewProductionManager(parser, nodeID)` | `NewProductionDDNSManager(nodeID)` (wires `keaLeaseParser`) |
| `NewManagerForTesting(...)` | `NewDDNSManagerForTesting(...)` (wires `keaLeaseParser`) |

## Invariants preserved (do not weaken)

- **Never delete a record xpf did not create** — the state store is the sole
  delete authority; `deleteOwnedLocked` re-derives the exact tuple from owned
  state. Reinforced on the wire by the DHCID-match-guarded delete.
- **Write-ahead ownership durability (#2662)** — the ownership intent is
  persisted (`PTRPending=true`) BEFORE the wire add; a crash after the add finds
  the record owned. A refused add removes the phantom intent.
- **Sentinel ordering (#2676)** — `upsertLocked` checks `errDDNSPTRPending`
  BEFORE `errDDNSConflictRefused`, so a forward-published-but-PTR-failed record
  is never orphaned.
- **Mass-delete fail-safe** — a family whose `LeaseParser` errors is marked
  untrusted and its destructive diff is skipped.
- **No secret in any error string** (TSIG secret revealed only at construction).

The HA writer gate (`ddnsWriterGateOpen`) stays in `pkg/daemon/daemon_ddns.go`
(it reads cluster RG state); P1a did not move or change it.

## Phase P1b — ScopeKey, per-family policy, per-RG HA gate, source binding

P1b (closes **#2663, #2664, #2665**) builds on the P1a spine:

- **ScopeKey (`state.go`, #2663/#2664, plan §5.4)** — the unifying ownership
  primitive `{Family, Interface, Unit, RoutingInstance, RGOwner, PolicyID}`.
  Ownership records are now keyed by `{ScopeKey, identity, address}`. The ZERO
  scope reproduces the pre-P1b `identity|address` key byte-for-byte (the `scope`
  JSON field is a `*ScopeKey`, omitted for the global lease scope), so a pre-P1b
  store loads with **no migration**. Two scopes for the same name+address (a v4
  vs v6 publish, or an RG0-owned vs RG1-owned publish) are DISTINCT entries.
- **Independent v4/v6 policy (#2663)** — `Reconcile` →
  `ReconcileScoped` resolves an INDEPENDENT policy + backend PER FAMILY
  (`reconcileEnv.pol[2]`/`updater[2]`) from `DHCPServerConfig.DynamicDNS` (v4)
  and `.DynamicDNSv6` (v6). A v4 conflict, a v4 backend error, or a v4 turn-off
  never affects v6. Single-block backward compat: if only one family's block is
  set, the other inherits it at reconcile time.
- **Per-RG HA writer gate (#2664)** — `ReconcileScoped` takes a
  `ScopeGate`/`ScopeResolver` (built in `pkg/daemon/daemon_ddns.go`
  `ddnsReconcileOptions`). The resolver attributes each lease to its owning RG
  by STABLE pool-subnet CIDR membership (not the per-render-unstable Kea
  subnet_id); the gate admits a scope IFF this node is MASTER for its RG. A
  gated-out scope is **stop-writing, never-withdraw**: its owned records are left
  untouched (the peer MASTER for that RG refreshes them — a withdraw would
  blackhole, plan §5.6). Pass 1 protects an owned record by re-consulting the
  SAME gate on the record's STORED scope (`env.scopeAdmits(owned.scopeOf())`),
  NOT only via the current-lease-derived `gatedScope` set — so a STEADY-STATE
  partial demotion, where the demoted RG's leases have aged out of the parsed
  set, still does not withdraw the demoted RG's records (#2664 review MAJOR;
  `TestPerRGGatePartialDemotionSteadyState`). Unattributable leases FAIL-CLOSED
  when RG-owned pools exist. Pool→RG attribution is sorted MOST-SPECIFIC-FIRST so
  overlapping cross-RG pools attribute deterministically across passes (the gate
  cannot flap). The daemon also nudges DDNS on a partial demotion
  (`clearRethServicesForRG`) so the gate change takes effect within one pass.
- **Source / VRF binding (#2665, `backend_bind.go`)** — the per-family
  `source-address` / `destination-interface` / `routing-instance` leaves build a
  custom `net.Dialer` (one `Control` hook: `unix.Bind` for the source IP +
  `SO_BINDTODEVICE` for the interface/VRF, working for both the UDP-first and
  TCP-retry exchange). Fail-open at runtime; an invalid source-address falls the
  family back to no-op.

**HA correctness:** the per-RG gate change MUST pass `make test-failover` (the
project rule for any gate / HA-path change). P1b adds the gate + the
partial-demotion nudge; reason about split-brain (uncertain RG → fail-closed)
and partial demotion (lose one RG, keep another → publish only the kept RG,
withdraw nothing) in `scope_test.go` / `daemon_ddns_scope_test.go`.
