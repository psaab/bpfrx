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
