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
| `manager.go` | `Manager` (the DDNS reconcile engine — moved from `dhcpserver/ddns.go`): `policyFromConfig`, `Reconcile`, `reconcileOnceLocked`, `upsertLocked`/`deleteOwnedLocked`, `withdrawAllLocked`, `ownerWatermark`, `dhcidSharedWithOther` (#2700 shared-DHCID guard), `Stats` (incl. `PTRPendingNow`, #2708), `OwnedRecordView(s)`, the `errDDNSNoBackendToWithdraw` keep-ownership sentinel (#2699), the write-ahead durability + never-delete-non-owned boundary. Also the `Lease` record + `LeaseParser` seam. |
| `state.go` | Ownership state store (`ownedRecord`, `ddnsState`, `loadDDNSState`, durable `save` via `fsatomic.WriteFileDurable`) — moved from `dhcpserver/ddns_state.go`. Also the fail-closed load classifiers `errDDNSStateCorrupt` / `errDDNSStateUnsupportedVersion` + `quarantineBadState` (#2650). |
| `backend.go` | `DNSUpdater` interface, `LeaseDNSRecord`, `nopUpdater`, the record + reverse-PTR-name helpers — moved from `dhcpserver/ddns_dns.go`. |
| `backend_rfc2136.go` | The LIVE RFC 2136 backend (`rfc2136Updater`): exact-RR adds/deletes, TSIG, RFC 4701 DHCID + RFC 4703 replace-owned two-attempt, the `errDDNSConflictRefused` / `errDDNSPTRPending` sentinels — moved from `dhcpserver/ddns_rfc2136.go`. `sendRemoveForward(..., keepDHCID)` keeps a shared DHCID on a partial dual-stack teardown (#2700); `dnsCanonicalFQDN` mirrors the DHCID FQDN canonicalization. |
| `hostname.go` | Deterministic hostname → DNS-label normalization (pure) — moved from `dhcpserver/ddns_hostname.go`. |
| `surface_a.go` | Surface A router/interface-address publish engine (`SurfaceAManager`): change-detection, forced-refresh wire floor, per-scope error backoff, per-RG HA gate, the backend factory `productionSurfaceABackend` (#2691 P2/P3). **Operator-hostname intent (#2779):** the publish path (`surfaceAName` → `sanitizeFQDN`) lower-cases + strips non-LDH characters + drops empty-sanitizing labels. For a *router-owned* Surface A record the hostname is operator intent (the operator types the exact public name), so a name that sanitization would STRUCTURALLY change is now a **commit error** (`config.ValidateDDNSHostname` on the typed `interfaces … dynamic-dns hostname` leaf) instead of a silent rewrite to a different DNS name — e.g. `wan_1.example.net` is rejected at commit rather than published as `wan1.example.net`. Case-folding and a single trailing dot are accepted (benign DNS canonicalizations). Every name that PASSES the commit check is a fixed point of `sanitizeFQDN` (cross-package contract test `surface_a_hostname_2779_test.go`), so the published name equals operator intent. |
| `backend_http.go` | Shared HTTP-backend discipline (#2691 P3): hardened `http.Client` (TLS-verified, bounded timeout), capped body read, `classifyHTTPStatus`, `queryEscape`, the `errHTTPAuth`/`errHTTPRateLimited` verdicts. **Source binding (#2846):** `newHTTPClientBound(bindConfig)` installs the SAME `backend_bind.go` source/interface/VRF `Dialer` (via `Transport.DialContext`) so the HTTP backends + checkip egress from the operator-configured `source-address` / `destination-interface` / `routing-instance` — not the kernel default route. `newHTTPClient()` is the no-bind alias (unbound default, behaviour unchanged). `resolveProviderBindConfig`/`newProviderHTTPClient` adapt a `config.DDNSProvider`'s leaves onto `resolveBindConfig`; a malformed `source-address` is a hard error so the backend constructor degrades to no-op (fail-open, mirrors rfc2136). |
| `backend_dyndns2.go` | dyndns2 backend (#2691 P3): one impl behind many provider names (`dyndns2Endpoints`), `good`/`nochg`/`badauth`/`abuse`/`911`/`nohost` verdict parsing. |
| `backend_cloudflare.go` | Cloudflare API backend (#2691 P3): Bearer token, zone-id resolve → find → PATCH/POST/DELETE record. **Withdraw is content-scoped (#2770):** `DeleteLease` lists EVERY record for the FQDN+type and deletes only the rows whose `content` equals the owned address (`rec.Addr.Unmap().String()`), removing ALL such duplicates. It never deletes a row with a different value (a human/automation changed it after xpf published — an ownership conflict that is a success no-op), honouring the Surface A sole-delete-authority boundary that Route 53 / RFC 2136 also enforce. `recs[0]` is an API-ordering artifact, not ownership. |
| `backend_dyndns2.go` | dyndns2 backend (#2691 P3): one impl behind many provider names (`dyndns2Endpoints`), `good`/`nochg`/`badauth`/`abuse`/`911`/`nohost` verdict parsing. **Withdraw (#2772):** `DeleteLease` issues the same update GET with `offline=YES` (the de-facto dyndns2 withdraw verb) and parses the body verdict; a provider failure returns a non-nil error so the engine keeps ownership for retry (was a silent no-op that orphaned the public record). |
| `backend_cloudflare.go` | Cloudflare API backend (#2691 P3): Bearer token, zone-id resolve → find → PATCH/POST/DELETE record. |
| `backend_route53.go` | Route 53 backend (#2691 P3): SigV4-signed `ChangeResourceRecordSets` UPSERT/DELETE change batch. |
| `sigv4.go` | Minimal self-contained AWS SigV4 signer for Route 53 (no AWS SDK dependency). |
| `backend_generic.go` | Generic templated backend (#2691 P3, inadyn "custom"): `%h/%i/%u/%p/%%` URL template + success-token matcher — config-only, no Go code per provider. **Success classification (#2838):** the 2xx body is matched by WHOLE TOKEN (`matchesGenericOK`), not raw `strings.Contains`. A default/`ok-response` token (`good`/`nochg`/`ok`/`true`/`updated`, case-insensitive) is a success only when it equals a trimmed response line or is the leading whitespace-delimited field of a line (so dyndns2-style `good <ip>` still passes). A body that merely *contains* a token — `not ok`, `error: ok token invalid`, `update not good`, or an HTML page with an `OK` button — is a FAILURE; the old substring matcher turned those explicit provider errors into false successes, after which Surface A recorded ownership and suppressed retry, leaving DNS stale while the router believed the address was published. **Withdraw (#2772):** a single update template has no portable delete verb and xpf exposes no delete template, so `DeleteLease` FAILS (`errGenericDeleteUnsupported`) rather than silently reporting success; the engine keeps ownership so the abandoned record stays operator-visible (was a silent no-op that dropped ownership while the record kept resolving). **Template validation (#2841):** `newGenericBackend` validates the `url-template` with `validateGenericURLTemplate` — the SAME discipline as checkip's `validateCheckIPURL` (a case-INSENSITIVE http(s) scheme per RFC 3986 §3.1 + a non-empty host), so a host-less (`https:///upd`) or wrong-scheme (`ftp://`) template fails closed at construction instead of accepting the backend and only failing at the first publish (the old check was a bare `HasPrefix("http(s)://")` with no host parse). It is deliberately TEMPLATE-AWARE and string-based, NOT `net/url`-based (like `RedactURL`, #2781): it extracts the scheme + host portion and tolerates the inadyn `%h/%i/%u/%p` specifiers and `{{...}}` placeholders anywhere in the userinfo/path/query — a credential embedded in the userinfo (`https://user:%p@host/upd`) makes `url.Parse` fail on the bare `%p`, so it must NOT be validated with `url.Parse`. A typo is also warned at commit by `config.validateSurfaceADDNSWarnings` (mirror `ddnsGenericURLTemplateValid`, RedactURL'd in the message), matching the checkip-url warning. |
| `checkip.go` | Opt-in external check-IP address source (#2691 P3): bogus-IP validity gate + allowlist (`IsPublicAddr`, `parseCheckIPBody`, `CheckIP`, `ParseAllowlist`). **Source binding (#2846):** `NewCheckIPClient(provider)` builds the checkip probe's `http.Client` bound to the provider's `source-address`/`destination-interface`/`routing-instance` so the external "what is my IP" query egresses from the configured source, not the default route (the daemon passes this bound client into `CheckIP`). `CheckIP` fails closed on a malformed `checkip-url` via `validateCheckIPURL` (http(s) scheme + host); a typo is also warned at commit by `config.validateSurfaceADDNSWarnings` so it cannot masquerade as a permanent transient observation failure (#2773). **Public-address gate (#2774, exported #2776):** `IsPublicAddr` accepts only a globally-routable unicast address and rejects the full IANA Special-Purpose Address Registry so a hostile/misconfigured checkip endpoint cannot get a martian/reserved address published as the router's A/AAAA record. It is exported (#2776) so the daemon's Surface A static-address fallback (`staticUnitAddr`) reuses the SAME predicate instead of a weaker partial filter. stdlib `netip` predicates cover unspecified, loopback, link-local (uni + multicast), multicast (incl. interface-local), and the RFC-1918 private ranges (`IsPrivate`: 10/8, 172.16/12, 192.168/16). The `specialPurposeV4`/`specialPurposeV6` prefix tables add the rest: **IPv4** 0.0.0.0/8 (this-network), 100.64/10 (CGNAT), 192.0.0/24 (IETF protocol assignments), 192.0.2/24 + 198.51.100/24 + 203.0.113/24 (TEST-NET-1/2/3 documentation), 192.88.99/24 (6to4 relay anycast), 198.18/15 (benchmarking), 240/4 (reserved), 255.255.255.255/32 (limited broadcast); **IPv6** ::ffff:0:0/96 (IPv4-mapped), 64:ff9b::/96 + 64:ff9b:1::/48 (NAT64), 100::/64 (discard-only), 100:0:0:1::/64 (dummy prefix, RFC 9780 — distinct from 100::/64), 2001::/23 (IETF protocol assignments), 2001:db8::/32 + 3fff::/20 (documentation, RFC 3849/9637), 2002::/16 (6to4), 5f00::/16 (SRv6 SIDs, RFC 9602), fc00::/7 (ULA). |
| `checkip.go` | Opt-in external check-IP address source (#2691 P3): bogus-IP validity gate + allowlist (`IsPublicAddr`, `parseCheckIPBody`, `CheckIP`, `ParseAllowlist`). `CheckIP` fails closed on a malformed `checkip-url` via `validateCheckIPURL` (http(s) scheme + host; the scheme check is case-INSENSITIVE per RFC 3986 §3.1, so `HTTPS://host` is accepted — #2842); a typo is also warned at commit by `config.validateSurfaceADDNSWarnings` so it cannot masquerade as a permanent transient observation failure (#2773). **Public-address gate (#2774, exported #2776):** `IsPublicAddr` accepts only a globally-routable unicast address and rejects the full IANA Special-Purpose Address Registry so a hostile/misconfigured checkip endpoint cannot get a martian/reserved address published as the router's A/AAAA record. It is exported (#2776) so the daemon's Surface A static-address fallback (`staticUnitAddr`) reuses the SAME predicate instead of a weaker partial filter. stdlib `netip` predicates cover unspecified, loopback, link-local (uni + multicast), multicast (incl. interface-local), and the RFC-1918 private ranges (`IsPrivate`: 10/8, 172.16/12, 192.168/16). The `specialPurposeV4`/`specialPurposeV6` prefix tables add the rest: **IPv4** 0.0.0.0/8 (this-network), 100.64/10 (CGNAT), 192.0.0/24 (IETF protocol assignments), 192.0.2/24 + 198.51.100/24 + 203.0.113/24 (TEST-NET-1/2/3 documentation), 192.88.99/24 (6to4 relay anycast), 198.18/15 (benchmarking), 240/4 (reserved), 255.255.255.255/32 (limited broadcast); **IPv6** ::ffff:0:0/96 (IPv4-mapped), 64:ff9b::/96 + 64:ff9b:1::/48 (NAT64), 100::/64 (discard-only), 100:0:0:1::/64 (dummy prefix, RFC 9780 — distinct from 100::/64), 2001::/23 (IETF protocol assignments), 2001:db8::/32 + 3fff::/20 (documentation, RFC 3849/9637), 2002::/16 (6to4), 5f00::/16 (SRv6 SIDs, RFC 9602), fc00::/7 (ULA). |

Tests moved with the code: `manager_test.go` (engine + state-store + hostname),
`backend_rfc2136_test.go` (backend, drives a real in-process miekg/dns server),
`durability_test.go` (#2662 write-ahead), `manager_inc2_test.go`
(manager + live backend integration). P2/P3 add `surface_a_test.go`,
`surface_a_rfc2136_test.go`, `surface_a_http_test.go` (engine-through-real-HTTP-
backend), `backend_http_test.go`, `backend_cloudflare_test.go`,
`backend_route53_test.go`, `sigv4_test.go`, `checkip_test.go` — all
mock-server-driven through the real backend impls (no protocol-bypassing fakes).

## HTTP provider backends (#2691 P3)

The HTTP backends are siblings of the RFC 2136 backend behind the SAME
`DNSUpdater` interface, so the Surface A engine drives them identically — only
the wire mechanism differs. `productionSurfaceABackend` (surface_a.go) is the
single resolution point keyed on `DDNSProvider.Backend`:

| backend | mechanism | required config | credential (config.Secret) |
|---|---|---|---|
| `dyndns2` | `GET /nic/update?hostname=&myip=` + Basic auth; body verdict | `server` or a known provider name | `password` |
| `cloudflare` | Bearer token; zone-id resolve → PATCH/POST DNS record | `api-token`, `zone` | `api-token` |
| `route53` | SigV4 `ChangeResourceRecordSets` UPSERT | `aws-access-key`, `aws-secret-key`, `hosted-zone-id` | `aws-secret-key` |
| `generic` | templated URL + success-token match (config-only) | `url-template` | `password` (optional) |

All credentials are `config.Secret` (revealed only at the transport boundary,
never logged); HTTP is HTTPS with system-trust cert+hostname verification, a
bounded request timeout, and a capped response body. The `generic` backend
additionally lets an operator embed a credential directly in the `url-template`
(userinfo `user:pass@host`, or a token in the query string via `%u`/`%p` or a
literal `?token=...`), and a `checkip-url` can carry an API key the same way —
neither is `config.Secret`-typed, so `DDNSProvider.String()`
(`pkg/config/types_system.go`, used by `%v`/`%s`/slog) runs `server`,
`url-template`, and `checkip-url` through `config.RedactURL`, which strips
userinfo and the entire query string while keeping the scheme/host/path for
diagnostics (#2781). A construction failure
(missing credential) degrades to the no-op backend (logged; the commit warning
already fired) — fail-open, matching the rfc2136 posture. Live-provider verify
is the deferred lab gate; the mock-server tests are the merge gate.

### Withdraw (DeleteLease) semantics per backend (#2772)

A withdraw is triggered when a Surface A scope shrinks, a binding is removed, or
the observed address is lost. `withdrawOwnedLocked` drops local ownership ONLY on
a nil-error `DeleteLease`; a non-nil error increments `deleteFail` and KEEPS the
ownership entry for retry. The HTTP backends therefore must never report a false
success for a withdraw they did not actually perform — doing so orphans the
public record while xpf believes it withdrawn (the #2772 bug, originally a no-op
that returned nil on both dyndns2 and generic).

| backend | withdraw mechanism |
|---|---|
| `dyndns2` | the same update GET with `offline=YES` (the de-facto dyndns2 withdraw — dyn/no-ip/dns-o-matic take the hostname offline). Body verdict parsed like an upsert; a provider failure → non-nil error → ownership kept for retry. |
| `cloudflare` | real DELETE of the record (zone-id resolve → find → DELETE). |
| `route53` | SigV4 `ChangeResourceRecordSets` DELETE change batch. |
| `rfc2136` | exact-RR delete (TTL=0 / CLASS=NONE), DHCID-match guarded. |
| `generic` | **no portable delete verb and no delete template → FAILS** (`errGenericDeleteUnsupported`). Ownership is kept so the abandoned record stays operator-visible; the operator clears it out of band (or uses a backend that supports a withdraw). |

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
- **No-backend withdraw keeps ownership (#2699)** — `deleteOwnedLocked` no
  longer drops the ownership entry when only the `nopUpdater` is wired. A record
  in the store was published by a real backend (the nop upsert path records no
  ownership), so forgetting it while the live RR persists would ORPHAN it (after
  a restart with DDNS disabled / no `update-server`, or a backend removal).
  Instead the no-op delete counts `deleteFail`, returns
  `errDDNSNoBackendToWithdraw`, and KEEPS ownership; a later reconcile with a
  live backend withdraws it for real. `reconcileOnceLocked` / `withdrawAllLocked`
  swallow the sentinel so a legitimate disabled-with-no-backend pass is not
  marked failed. Mirrors the Surface A `withdrawOwnedLocked` precedent.
- **Route 53 already-gone DELETE is idempotent (#2771)** — `backend_route53.go`
  `DeleteLease` treats a Route 53 DELETE of an already-absent record as success
  (nil), mirroring the rfc2136 backend's NXRRSET/NXDOMAIN handling
  (`sendRemove`). Route 53 reports an already-gone delete as HTTP 400
  `Code=InvalidChangeBatch` with a per-change message `... but it was not
  found`; `r53DeleteAlreadyGone` requires BOTH the `InvalidChangeBatch` code AND
  the "not found" marker, so a genuinely malformed/conflicting batch is NOT
  mistaken for a no-op. Without this, a withdraw against a manually-removed (or
  already-withdrawn-but-ack-lost) record returned non-nil forever; Surface A's
  `withdrawOwnedLocked` only drops ownership on a nil return, so the withdraw
  wedged and retried indefinitely while `show system services dynamic-dns`
  reported an owned record that no longer existed. Genuine
  transient/auth/throttle failures (`SignatureDoesNotMatch`, 5xx, 429, a
  non-"not found" `InvalidChangeBatch`) STILL return non-nil so the engine
  keeps retrying — only the already-gone case is swallowed.
- **Shared-DHCID partial dual-stack teardown (#2700)** — the RFC 4701 DHCID
  digest folds in `client-identity || FQDN` only (NOT the address), so a
  dual-stack client (an A + an AAAA under one FQDN, same client id) shares ONE
  DHCID. `deleteOwnedLocked` scans the store (`dhcidSharedWithOther`); when a
  sibling family still owns the same FQDN+ClientID it sets
  `LeaseDNSRecord.KeepForwardDHCID`, and `sendRemoveForward` then deletes only
  the A/AAAA and LEAVES the shared DHCID (the DHCID-match prerequisite is still
  sent, so the delete stays ownership-guarded). The DHCID is removed only with
  the LAST family's record, so a fully-released name leaves no orphan DHCID and
  a survivor is never left unprotected (no hijack window, no wire leak).
- **Unloadable ownership state fails CLOSED (#2650)** — a corrupt, unknown-
  future-version, or unreadable state file is NOT silently reset to an empty
  store. `loadDDNSState` returns the empty store plus a CLASSIFIED error
  (`errDDNSStateCorrupt` / `errDDNSStateUnsupportedVersion`); `loadStateOrDegrade`
  sets `Manager.degraded`, QUARANTINES a corrupt/unsupported file aside
  (`<path>.corrupt-<UTC-stamp>` — preserved, never overwritten by a later
  `save()`), and `ReconcileScoped` then refuses the WHOLE pass (no publish, no
  withdraw, counted as a reconcile failure) until the operator resolves it. Fail
  OPEN would forget every owned record (permanent stale-record leak — the cleanup
  half of the feature is lost) AND let a later publish re-claim a name a PEER
  owns, since the lost DHCID/ownership state can no longer veto it. The degraded
  state is surfaced as a `show ... dynamic-dns` ALARM and the
  `xpf_dhcp_ddns_degraded` Prometheus gauge so the lost cleanup authority is
  never silent.
- **No secret in any error string** (TSIG secret revealed only at construction).

The HA writer gate (`ddnsWriterGateOpen`) stays in `pkg/daemon/daemon_ddns.go`
(it reads cluster RG state); P1a did not move or change it.

## Observability — PTR-pending (#2708)

A record can be HALF-PUBLISHED: the forward A/AAAA is live but the reverse PTR
add failed with a non-skippable error (`ownedRecord.PTRPending=true`, #2661).
This condition is surfaced per record and as a current gauge so an operator can
identify the broken record and watch it recover:

- `OwnedRecordView.PTRPending` — exposed on every owned record (CLI + gRPC
  `show ... dynamic-dns detail` print a `Pending` column).
- `Stats.PTRPendingNow` — the CURRENT count of records pending a PTR, distinct
  from the cumulative lifetime `PTRDeferred` (which only ever increases). It
  falls back to 0 once every PTR finally publishes.
- Prometheus `xpf_dhcp_ddns_ptr_pending` (gauge) — current pending count, beside
  the existing `xpf_dhcp_ddns_skipped_total{reason="ptr-deferred"}` lifetime
  counter.

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
- **HTTP-transport + checkip source binding (#2846)** — originally only the RFC
  2136 backend honored the source binding; the HTTP backends
  (dyndns2/Cloudflare/Route53/generic) and the external checkip probe built a
  plain `newHTTPClient()` and left via the default route. #2846 wires the SAME
  `bindConfig.dialer()` into the HTTP client's `Transport.DialContext`
  (`newHTTPClientBound` in `backend_http.go`), so an HTTP DDNS update and a
  checkip query dial from the configured `source-address` /
  `destination-interface` / `routing-instance`. The provider catalog carries the
  binding leaves (`config.DDNSProvider`, #2780); `resolveProviderBindConfig`
  adapts them onto the same `resolveBindConfig` discipline. When no
  `source-address` is set the Transport gets no `DialContext` override — the
  default-route behaviour is byte-for-byte unchanged. A malformed `source-address`
  is a hard error so the backend constructor degrades to no-op (and the checkip
  client falls back to the unbound default + logs), matching the rfc2136
  fail-open posture.

**HA correctness:** the per-RG gate change MUST pass `make test-failover` (the
project rule for any gate / HA-path change). P1b adds the gate + the
partial-demotion nudge; reason about split-brain (uncertain RG → fail-closed)
and partial demotion (lose one RG, keep another → publish only the kept RG,
withdraw nothing) in `scope_test.go` / `daemon_ddns_scope_test.go`.

## Phase P2 — Surface A (router/interface-address publish)

P2 (partial **#2679**) adds the SECOND publish surface — the firewall publishing
its OWN learned address — on top of the SAME spine, without forking the engine.

- **`SurfaceAManager` (`surface_a.go`)** — a separate manager from the
  DHCP-lease `Manager` (different ownership semantics: self-owned, no DHCID; and
  a different durable state file, `interface-ddns-state.json`), but it drives the
  SAME `DNSUpdater` interface, the SAME RFC 2136 backend (`newRFC2136Updater`),
  the SAME `ScopeKey` ownership primitive, the SAME source/VRF binding
  (`backend_bind.go`, via `DHCPDynamicDNSConfig` as the transport carrier), and
  the SAME write-ahead durability discipline.
- **Self-owned forward ADD = atomic in-place replace** (`rfc2136Updater.selfOwned`
  → `sendAddSelfOwned`). A router record has NO DHCID (the firewall IS the
  authoritative owner of its OWN configured FQDN). The lease path's two
  prerequisites — name-not-in-use (Attempt A) and DHCID-match (Attempt B) — both
  REFUSE a pre-existing name when there is no DHCID, which would pin a self-record
  at its first address forever (the #2691 P2 MAJOR-1 bug). So a self-owned
  forward add is a SINGLE RFC 2136 UPDATE that, in one message, `RemoveRRset`s our
  forward type at our name (CLASS=ANY, our type only — co-resident records of a
  DIFFERENT type are never touched) and `Insert`s the new rdata. The server
  applies both atomically: a same-address forced-refresh deletes-then-re-adds the
  identical RR (a no-op net change that SUCCEEDS), and an address change replaces
  the rdata with NO withdraw-then-add blackhole gap. (Third-party case: the
  firewall owns the name; two firewalls pointed at the same self-record FQDN is an
  operator misconfig — the per-RG HA gate prevents the in-cluster two-writer case.)
- **Withdraw rebuilds the live backend** (the #2691 P2 MAJOR-2 fix). An
  address-loss withdraw (Pass 1) resolves the backend from the live
  `SurfaceAScope` (`backendFor`); a config-removal withdraw (Pass 2, where the
  binding — and thus the scope — is gone) REBUILDS the same backend the publish
  used by looking the owned record's provider (`scope.PolicyID`) up in the
  still-committed provider catalog passed into `Reconcile` (`backendForOwned` →
  `newBackend`). Production sets only `newBackend` (not the static `backend`
  field), so a withdraw that ignored `newBackend` would no-op and ORPHAN the RR —
  the bug this fixes. If the provider is also gone from the catalog the withdraw
  cannot reach the wire: it counts `deleteFail`, keeps ownership for retry, and
  surfaces an error (never a false `deleteOK`).
- **What the engine ADDS over the lease reconciler** (the inadyn ideas the
  DHCP-lease path does not need, plan §3.3/§5.5):
  - **change detection + last-published cache** — a wire UPDATE fires only when
    the observed address changed (or the forced-refresh floor elapsed). The
    cache is seeded from the durable store on restart (`seedFromStore`) so a
    restart does not blast a redundant update.
  - **forced-refresh** — a per-scope wire-update FLOOR (default 24h) decoupled
    from the 30s reconcile cadence, to prove liveness / resist record reaping
    without per-poll traffic.
  - **flat error backoff** — on a transient failure a scope backs off
    (30s → cap, default 1h) so a failing provider is not hammered (ban-avoidance).
  - **replace, never withdraw-then-add, on address change** — a scope owns
    exactly ONE record (keyed `{scope, "router-self", ""}`); an address change is
    the atomic self-owned in-place replace described above (no blackhole gap).
- **Ownership key.** A router record is keyed on its SCOPE + the fixed identity
  `router-self` + Address `""` (the published address lives in the new
  `ownedRecord.AddrText` field, JSON-omitted for lease records). So an interface
  unit/family owns at most one record and an address change replaces it in place.
- **Address observation** is the daemon's job (`pkg/daemon/daemon_ddns_surface_a.go`):
  `AddressObserver` reads netlink (interface source) or `pkg/dhcp.LeaseFor` (dhcp
  source). `ok=false` (transient read failure) → leave the scope untouched
  (never withdraw); a valid-but-Invalid `Addr` (interface down / lease gone) →
  withdraw. Keeping observation in the daemon keeps `pkg/ddns` free of
  netlink/DHCP deps, exactly like the `LeaseParser` seam for Surface B.
  **Transient link-read vs definitive-none (#2840):** `observeInterfaceAddr`
  carefully distinguishes a netlink READ FAILURE from a present-but-addressless
  interface. A `LinkByName`/`AddrList` ERROR (interface absent during a rename,
  reth/HA churn, a netlink hiccup) is TRANSIENT → it returns `(zero, false)` so
  the engine leaves the scope untouched and retries next pass. It does NOT fall
  back to the configured static on a read error — publishing a "configured"
  address that could not be confirmed "active" in the kernel data plane would
  point DNS at a possibly-stale address during a transient link outage. The
  netlink reads go through the `netlinkLinkByName`/`netlinkAddrList` seams so the
  transient-vs-definitive contract is unit-tested without a real kernel
  interface (`TestObserveInterfaceAddrTransientVsDefinitive`).
  **Static-address fallback is public-gated (#2776) and present-but-addressless
  only:** when the interface read SUCCEEDS but yields no usable dynamic address
  (the legitimate static-use case), `observeInterfaceAddr` falls back to the
  unit's configured static address via `staticUnitAddr`, which gates the
  candidate through the SAME `ddns.IsPublicAddr` predicate the netlink and
  checkip sources use (exported for this reuse, #2774). A mis-scoped static
  address (multicast, reserved, ULA, CGNAT, documentation, IANA
  special-purpose) is SKIPPED and surfaced at WARN rather than silently
  published as the router's A/AAAA record — the netlink and static paths no
  longer use divergent publishability predicates (the netlink path already
  rejected multicast; the fallback previously filtered only loopback/
  link-local-unicast/unspecified).
  **IPv6 address-lifetime-aware netlink selection (#2775):** the netlink
  selection (`selectInterfaceAddr`, the pure core of `observeInterfaceAddr`)
  now honors RFC 4862 address state instead of publishing the first
  non-link-local/loopback/multicast address. (1) It NEVER selects an address
  whose DAD has not succeeded — `IFA_F_TENTATIVE` (DAD in progress),
  `IFA_F_DADFAILED` (duplicate detected), or `IFA_F_OPTIMISTIC` (RFC 4429
  optimistic DAD, not yet DAD-confirmed) — publishing one risks a
  duplicate/black-holed answer. (2) It PREFERS an RFC 4862 `preferred` address
  over a `deprecated` one (`IFA_F_DEPRECATED`): a deprecated address is being
  phased out (renumber / PD churn / privacy-address rotation) and will soon be
  invalid, so publishing it black-holes inbound reachability. The first eligible
  preferred address wins; a deprecated address is used ONLY when no preferred
  address exists (never-blackhole — a still-valid deprecated address beats no
  answer). (3) Every candidate STILL passes `ddns.IsPublicAddr`, so a
  preferred-but-ULA (or otherwise reserved) address is rejected — the same gate
  as the static fallback (#2776) and the checkip source. The IFA_F_* flags are
  already parsed off the netlink `RTM_NEWADDR` message into
  `netlink.Addr.Flags` (no extra netlink plumbing was needed — they were simply
  ignored in selection before). A per-family `preferred-address` operator
  override for multi-address interfaces (the issue's secondary ask) remains a
  future refinement.
- **HA gate** is the SAME per-RG `ScopeGate` (a router record on a reth/virtual
  interface publishes only on the RG master; stop-writing-never-withdraw
  otherwise). Standalone (nil gate) always publishes.
- **Lock discipline — I/O is NEVER performed under the manager mutex (#2778).**
  `SurfaceAManager.mu` guards ALL manager state (the durable ownership store, the
  per-scope runtime cache, the counters), but it is RELEASED across every
  provider network call (`UpsertLease`/`DeleteLease`, which run with a 15s HTTP
  client timeout). A slow or hung provider must NOT block `StatusViews`/`Stats`
  (operator `show` + Prometheus scrapes) or other scopes' reconcile work — that
  would freeze the control plane for up to 15s exactly while the subsystem is
  unhealthy. The pattern (`providerIO`): under the lock, the pass snapshots the
  exact intent (resolved backend + record) and durably write-aheads the
  ownership BEFORE the wire op (so a crash in the unlocked window still finds the
  record owned and converges next pass); it then RELEASES the lock for the wire
  call and RE-ACQUIRES it to commit the result. The commit is guarded by a
  racing-op re-validation (CAS): if a concurrent op changed the scope's owned
  record while the lock was released, the stale wire result does NOT clobber the
  newer truth — a stale publish-rollback is skipped (the newer ownership wins,
  signalled via `errSurfaceAPublishRaced` so the runtime cache is not advanced),
  and a stale withdraw drops ownership only if the live entry is STILL the exact
  record it deleted (a concurrent re-publish with a new address keeps its
  ownership, never orphaned). The single-flight guard in the daemon
  (`surfaceAReconcileInFlight`) means two full passes never run concurrently, but
  the CAS keeps the contract correct regardless. Proven in
  `surface_a_lockio_test.go` (a blocking provider + a concurrent `StatusViews`
  that would hang if the lock were held; fail-on-revert).
- **Operator surfaces:** `show services dynamic-dns [detail]` (CLI + gRPC), the
  `xpf_ddns_surface_a_*` Prometheus family, and
  `SurfaceAManager.StatusViews(scopes)` (per-scope `State` + published address +
  last-published time + last error).
- **Status surfaces EVERY configured scope, not just the owned ones (#2843).**
  `StatusViews` takes the CURRENTLY configured scopes (materialized by the daemon
  from the committed config) and returns the UNION of: a row per configured scope
  (merged with its ownership record + runtime state) AND any ownership record for
  a scope no longer configured (a withdraw is pending). Each row carries a
  `State`: `published` (owns a record), `unpublished` (the provider resolved to
  the no-op backend — `errSurfaceANoBackend`, a half-configured provider; the
  reason is in `LastError`, no backoff armed), `error` (the last publish attempt
  failed; reason + backoff armed), `pending` (configured, not yet owned, no
  recorded error — never attempted or waiting on an address observation / backoff
  window), or `withdraw-pending` (owned but no longer configured). Before #2843
  the status was built from ownership records ONLY, so a scope that failed before
  its first publish — most acutely a half-configured provider whose
  `errSurfaceANoBackend` was swallowed without `recordScopeError` — was INVISIBLE
  in `show ... detail`, the opposite of what an operator needs during bring-up.
  The no-backend state now records a per-scope reason on the runtime cache
  (without arming retry backoff) so the row reports it. Proven (fail-on-revert)
  in `surface_a_http_test.go` (`TestStatusViewsSurfacesUnpublishedScopes`,
  `TestStatusViewsSurfacesPendingAndPublished`).
- **Tests through the REAL backend.** The self-owned replace, forced-refresh,
  and both withdraw paths are proven in `surface_a_rfc2136_test.go` against the
  stateful in-process fake DNS server (the `backend_rfc2136_test.go` harness) with
  PRODUCTION wiring (`newBackend` set, static `backend` nil) — asserting the
  actual zone state + the actual wire DELETE. `fakeUpdater` (`surface_a_test.go`)
  is kept only for backend-agnostic engine cadence (publish-once, skip-unchanged,
  forced-refresh-fires, transient-no-withdraw, backoff, status), because it models
  neither RFC 2136 prerequisites nor the production `newBackend` wiring and so
  cannot catch the two MAJORs above.

P3 (the rest of #2679) adds the HTTP provider backends
(dyndns2/Cloudflare/Route53/generic-template) + the checkip address source;
`productionSurfaceABackend` already routes an unknown backend to the no-op
(logged) so a P3-only provider config does not wedge P2.
