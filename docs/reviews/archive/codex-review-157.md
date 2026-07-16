# Codex Review Audit 157 - DDNS Surface A / Router-Interface DDNS

Scope: quota campaign focused on router/interface DDNS (Surface A), HTTP DDNS
backends, checkip, provider mutation, and DDNS operator observability.

Base checkout: `/home/ps/git/codex-bpfrx` at `fc6049c057d7`.

Duplicate suppression read:

- `/tmp/codex-review*.md`
- `/tmp/agy-review*.md`
- `docs/issues/issue-history.md`
- `docs/issues/pr-history.md`
- `docs/config-schema.md`
- `pkg/ddns/README.md`
- DDNS PR/issue references in `docs/pr/**`

Notable duplicate classes suppressed:

- DHCP DDNS base work (#1387)
- Surface A missing router/interface DDNS (#2679/#2691)
- FQDN-aware scope identity (#2903)
- public-address gate for interface/static/checkip (#2774/#2776/#2975)
- checkip uppercase scheme (#2842) - only checkip, not dyndns2 server
- source binding for HTTP/checkip (#2846)
- generic backend response-token matching (#2838)
- transient netlink read must not fall back to static (#2840)
- status rows for no-backend/unpublished scopes (#2843)
- DuckDNS dedicated backend and known dual-stack warning (#2960)
- HTTP client reuse and reaping (#2904/#2956)
- RG0 single-writer gating (#2972)
- degraded state load fail-closed (#2971)
- withdraw backoff/unsupported terminal (#2813)

Validation probes run and then removed:

```text
go test ./pkg/ddns -run 'TestCodexAudit' -count=1
```

The temporary probe reproduced:

- post-restart Surface A republishes an unchanged address immediately
- dyndns2 `Server: "HTTPS://..."` is treated as a bare host
- same `{FQDN,address}` provider rename drops old-provider ownership without a delete

The temporary file was deleted; the checkout was returned clean before this report.

## Module Checklist

1. `pkg/ddns/surface_a.go` state/reconcile/publish/withdraw
   - Correctness/security: stale-record paths found (H01, H02, H04, H07, M01, M02).
   - Feature completeness vs vSRX: provider mutation lacks provider-instance ownership (H02/H04).
   - Performance/latency: restart republish churn and pass-level backoff coupling (H05, M03).
   - Modularity/refactor: migration, provider ownership, publish, and withdraw are still one large state machine (L02).
   - Test gaps: no provider-rename/provider-mutation stale-record regression (H01/H02).

2. `pkg/daemon/daemon_ddns_surface_a.go` scope construction and observation
   - Correctness/security: DHCP source bypasses public gate; checkip fallback and context bugs found (H06, H08, H09, M04).
   - Feature completeness vs vSRX: no per-binding transport VRF/interface override beyond source-address (L04).
   - Performance/latency: checkip HTTP runs while Surface A manager mutex is held (H08).
   - Modularity/refactor: observer contract has no context parameter, forcing `context.Background()` (H09).
   - Test gaps: no checkip cancellation / lock-not-held tests.

3. `pkg/ddns/backend_dyndns2.go`
   - Correctness/security: uppercase explicit server URL misparsed (H10); host-level offline semantics not modeled (M06).
   - Feature completeness vs vSRX: provider IPv6 capability not represented (L07).
   - Performance/latency: no endpoint validation can waste cycles on malformed config at runtime (M05).
   - Modularity/refactor: endpoint resolution should be a validated URL parser, not prefix concatenation.
   - Test gaps: no uppercase `server` URL test, only checkip uppercase URL tests.

4. `pkg/ddns/backend_duckdns.go`
   - Correctness/security: per-family withdraw can clear sibling family (H11).
   - Feature completeness vs vSRX: known dual-stack clobber remains warning-only (L06).
   - Performance/latency: no coalesced dual-stack publish path.
   - Modularity/refactor: backend capability flags are comments/warnings, not engine-visible behavior.
   - Test gaps: no Surface A engine test for v4 loss while v6 DuckDNS scope remains configured.

5. `pkg/ddns/backend_cloudflare.go`
   - Correctness/security: upsert still patches `recs[0]` and can clobber a foreign/manual same-name record (H12).
   - Feature completeness vs vSRX: no explicit ownership tag/comment for Cloudflare records (L09).
   - Performance/latency: resolves zone on every op (L08).
   - Modularity/refactor: find/update/delete ownership semantics are backend-local and inconsistent with Route53/RFC2136.
   - Test gaps: delete content-scope is tested; upsert foreign-row preservation is not.

6. `pkg/ddns/backend_route53.go`
   - Correctness/security: UPSERT replaces the whole RRSet with one value (M07).
   - Feature completeness vs vSRX: no change-batch ownership metadata or TXT marker.
   - Performance/latency: no batching for multiple Surface A scopes in one hosted zone (L10).
   - Modularity/refactor: Route53 capability constraints are backend-local comments.
   - Test gaps: no multi-value RRSet clobber test.

7. `pkg/ddns/backend_rfc2136.go`
   - Correctness/security: self-owned `RemoveRRset` clobbers co-resident same-type values (M08).
   - Feature completeness vs vSRX: no opt-in DHCID/TXT owner marker for router records.
   - Performance/latency: one DNS UPDATE per scope, no zone batching.
   - Modularity/refactor: Surface A self-owned mode is a boolean on lease backend, not a separate router-record updater.
   - Test gaps: tests intentionally accept delete-RRset for self-owned path; no co-resident A/AAAA preservation test.

8. `pkg/config/compiler_validate_warn.go` and status surfaces
   - Correctness/security: warn-only behavior can commit known-clobber topologies (L06).
   - Feature completeness vs vSRX: status hides unresolved bindings skipped before scope materialization (M09).
   - Performance/latency: no issue.
   - Modularity/refactor: validation mirrors backend capability in ad hoc warnings (L12).
   - Test gaps: no status row for undefined-provider/missing-hostname bindings.

## High Confidence Findings

### H01 - Provider rename with the same FQDN/address orphans the old provider record

Evidence:

```go
// pkg/ddns/surface_a.go:650-654
liveRR := make(map[string]struct{}, len(desired))
for _, owned := range m.state.all() {
        if _, stillConfigured := desired[owned.scopeOf().scopePrefix()]; stillConfigured {
                liveRR[owned.FQDN+"|"+owned.AddrText] = struct{}{}
        }
}

// pkg/ddns/surface_a.go:673-681
if _, live := liveRR[owned.FQDN+"|"+owned.AddrText]; live {
        m.state.delete(owned.scopeOf(), owned.Identity, owned.Address)
        delete(m.runtime, owned.scopeOf().scopePrefix())
        continue
}
```

`ScopeKey` includes `PolicyID`, so provider A and provider B are distinct scopes:

```go
// pkg/ddns/state.go:119-126
type ScopeKey struct {
        Family          Family
        Interface       string
        Unit            int
        RoutingInstance string
        RGOwner         int
        PolicyID        string
        FQDN            string
}
```

Runtime trace:

1. Scope `pid=old-provider/fqdn=wan.example.net` owns `wan.example.net A 203.0.113.5` at provider A.
2. Operator changes only the binding provider to `new-provider`; the observed address stays `203.0.113.5`.
3. Pass 1 publishes `wan.example.net A 203.0.113.5` at provider B and records the new scope.
4. Pass 2 sees the old provider-A ownership as not configured, but `{FQDN,AddrText}` matches the new live record.
5. The adoption guard drops the old ownership without calling `backendForOwned` or `DeleteLease`.
6. Provider A's record remains live forever, and xpf has forgotten it.

Probe result:

```text
go test ./pkg/ddns -run 'TestCodexAuditSurfaceAProviderChangeSameRRDropsOldOwnershipWithoutDelete' -count=1
ok
```

Impact: stale public DNS records survive provider migration. This is the same stale-record class the Surface A closeout was supposed to prevent, but it is hidden by the FQDN-only migration guard.

Fix direction: the adoption skip should be constrained to the explicit legacy FQDN-less migration case, or at least include provider/backend identity in the live key. Provider changes must withdraw through the old provider before dropping old ownership, or keep old ownership visible when old provider credentials are gone.

### H02 - Provider catalog mutation under the same provider name can orphan the old backend

Evidence:

```go
// pkg/ddns/surface_a.go:1118-1120
return m.newBackend(sc.Provider, sc.FQDN, sc.TTL)

// pkg/ddns/surface_a.go:1138-1147
policyID := owned.scopeOf().PolicyID
prov := catalog[policyID]
...
return m.newBackend(prov, owned.FQDN, owned.TTL)
```

Owned state stores only `PolicyID`, not the backend/server/zone/source tuple:

```go
// pkg/ddns/state.go:119-126
type ScopeKey struct {
        ...
        PolicyID        string
        FQDN            string
}
```

Runtime trace:

1. Provider name `wan-ddns` points at dyndns2 server A; Surface A publishes and stores `PolicyID: "wan-ddns"`.
2. Operator changes `system services dynamic-dns provider wan-ddns` to Cloudflare, Route53, another server, or another zone.
3. The configured scope key is still `PolicyID: "wan-ddns"` unless routing-instance changes.
4. `publishLocked` upserts the new backend and overwrites the same durable ownership key.
5. No code has the old server/zone/credentials needed to delete the previous provider's RR.

Impact: changing provider configuration in place can leave stale DNS at the old provider even when the FQDN/address did not change. This is worse than H01 because no provider rename is required.

Fix direction: durable ownership needs a provider-instance fingerprint or backend delete descriptor. If that descriptor changes, reconcile should treat old ownership as a withdraw candidate against the old backend or keep it in a visible "manual cleanup needed" state.

### H03 - Removed-binding withdraw rebuilds the backend from the current provider catalog, not the provider that published the record

Evidence:

```go
// pkg/ddns/surface_a.go:1122-1127
// It REBUILDS the SAME backend the publish used by looking the owned record's
// provider (scope.PolicyID) up in the still-committed provider catalog

// pkg/ddns/surface_a.go:1138-1147
policyID := owned.scopeOf().PolicyID
prov := catalog[policyID]
...
return m.newBackend(prov, owned.FQDN, owned.TTL)
```

Runtime trace:

1. Old provider catalog entry `p` publishes `old.example.net`.
2. Operator edits provider `p`'s server/zone/credential and removes the interface binding in the same commit.
3. Pass 2 tries to withdraw the old ownership using the new provider catalog entry.
4. The delete goes to the wrong endpoint/zone or with wrong credentials.
5. If it fails, the status says withdraw pending but there is no stored old endpoint to retry correctly.

Impact: provider edits can make already-owned records uncleanable. vSRX-like router DDNS must preserve exact cleanup authority across config transitions.

Fix direction: store enough provider delete metadata in `ownedRecord` for Surface A, or make provider mutation a two-phase transition that withdraws before mutating the provider descriptor.

### H04 - Surface A restart cache does not suppress redundant post-restart updates

Evidence:

```go
// pkg/ddns/surface_a.go:513-519
// seedFromStore rebuilds the in-memory runtime cache from the durable ownership
// store ... a restart must not blast a redundant update for an address that has not changed.

// pkg/ddns/surface_a.go:521-528
for _, r := range m.state.all() {
        a, err := netip.ParseAddr(r.Address)
        if err != nil {
                continue
        }
        m.runtime[r.scopeOf().scopePrefix()] = &surfaceAState{lastAddr: a.Unmap()}
}
```

But Surface A stores the rdata in `AddrText`, not `Address`:

```go
// pkg/ddns/surface_a.go:943-952
ow := ownedRecord{
        Identity:    surfaceAIdentity,
        Address:     "", // key on scope+FQDN; rdata lives in AddrText below
        ...
        AddrText:    addr.String(),
}.withScope(key)
```

Even if the field were fixed, `refreshDue` is true after restart because `lastPublished` is zero:

```go
// pkg/ddns/surface_a.go:800-811
changed := addr != rt.lastAddr
...
refreshDue := force || rt.lastPublished.IsZero() || now.Sub(rt.lastPublished) >= forced
if owned && !changed && !refreshDue {
        m.skipped++
        return nil
}
```

Runtime trace:

1. Router publishes `wan.example.net A 203.0.113.5` and writes `AddrText`.
2. Daemon restarts.
3. `seedFromStore` tries to parse empty `Address`, skips the record, and leaves `lastAddr` unset.
4. First reconcile sees `changed=true` and `lastPublished.IsZero()`.
5. It re-updates the provider even though the address is unchanged and still inside the forced-refresh floor.

Probe result:

```text
go test ./pkg/ddns -run 'TestCodexAuditSurfaceARestartDoesNotSuppressRedundantUpdate' -count=1
ok
```

Impact: every daemon restart can generate a provider write storm proportional to Surface A scope count. For rate-limited providers and active/passive failover, this is exactly the kind of avoidable DDNS churn the cache was documented to prevent.

Fix direction: seed from `AddrText` for Surface A and record a restart baseline for `lastPublished` so unchanged records skip until the forced-refresh interval elapses from restart.

### H05 - `checkip` HTTP observation runs while `SurfaceAManager.mu` is held

Evidence:

```go
// pkg/ddns/surface_a.go:554-556
func (m *SurfaceAManager) Reconcile(...) error {
        m.mu.Lock()
        defer m.mu.Unlock()

// pkg/ddns/surface_a.go:637
noteErr(m.reconcileScopeLocked(ctx, sc, observe, now, force))

// pkg/ddns/surface_a.go:747
obs, ok := observe(sc)
```

For checkip, `observe(sc)` performs network I/O:

```go
// pkg/daemon/daemon_ddns_surface_a.go:254-283
ctx, cancel := context.WithTimeout(context.Background(), surfaceACheckIPTimeout)
...
client, berr := d.surfaceA.CheckIPClient(scope.Provider)
...
a, ok := ddns.CheckIP(ctx, client, scope.Provider.CheckIPURL, af4, allow)
```

Runtime trace:

1. Reconcile enters `m.mu`.
2. Scope uses `address-source checkip`.
3. The observer performs an external HTTP GET while the manager mutex is still held.
4. `StatusViews`, `Stats`, force state, other scopes, and any concurrent reconcile caller block on `m.mu`.
5. With N checkip scopes and a black-holed endpoint, the manager can be locked for roughly `N * 10s`.

Impact: this violates the same lock-discipline requirement that `providerIO` carefully enforces for provider updates. A slow checkip endpoint can wedge DDNS observability and make a reconcile pass exceed its intended 60s wall clock.

Fix direction: the observer must either run outside `m.mu`, or the engine should split observation from state mutation: collect observations with a context before taking the manager lock, then reconcile decisions under lock.

### H06 - Checkip ignores the reconcile/shutdown context

Evidence:

```go
// pkg/daemon/daemon_ddns_surface_a.go:108-120
rctx, cancel := context.WithTimeout(ctx, surfaceAReconcileTimeout)
...
if err := d.surfaceA.Reconcile(rctx, scopes, observe, gate, catalog); err != nil {

// pkg/daemon/daemon_ddns_surface_a.go:254
ctx, cancel := context.WithTimeout(context.Background(), surfaceACheckIPTimeout)
```

Runtime trace:

1. Daemon shutdown cancels the parent context, or the 60s reconcile pass deadline fires.
2. `surfaceAObserver` does not receive that context.
3. Each checkip probe derives from `context.Background()`.
4. The probe continues until its own 10s timeout, even if shutdown or the pass deadline has already fired.

Impact: a shutdown or failover can wait behind stale checkip probes, and a pass deadline does not bound the pass when multiple checkip scopes are slow.

Fix direction: add `context.Context` to `AddressObserver` or make checkip observation a pre-pass phase that accepts the reconcile context.

### H07 - DHCP address source lacks the public-address gate applied to interface/static/checkip sources

Evidence:

```go
// pkg/daemon/daemon_ddns_surface_a.go:297-307
lease := d.dhcp.LeaseFor(linuxName, af)
...
a := lease.Address.Addr().Unmap()
if !a.IsValid() {
        return ddns.AddressObservation{Source: ddns.AddressSourceDHCP}, true
}
return ddns.AddressObservation{Addr: a, Source: ddns.AddressSourceDHCP}, true
```

By contrast, interface/static/checkip sources use `IsPublicAddr`:

```go
// pkg/daemon/daemon_ddns_surface_a.go:455-459
if !ddns.IsPublicAddr(ip) {
        continue
}

// pkg/daemon/daemon_ddns_surface_a.go:501-504
if !ddns.IsPublicAddr(a) {
        slog.Warn("surface-a: skipping non-public static address", ...)
        continue
}

// pkg/ddns/checkip.go:94-96
if !IsPublicAddr(a) {
        continue
}
```

Runtime trace:

1. WAN obtains DHCP address `100.64.1.2`, `10.0.0.9`, ULA, documentation, or another special-purpose address.
2. Interface/static/checkip modes would reject it.
3. `address-source dhcp` returns it as a valid observation.
4. Surface A publishes it to public DNS.

Impact: per-interface router DDNS can publish unroutable or reserved addresses when using DHCP source, undermining the public-address safety invariant that earlier Surface A fixes explicitly established.

Fix direction: run DHCP lease observations through `ddns.IsPublicAddr` before returning a valid address. Non-public should be definitive no-publish or warning, matching static/interface behavior.

### H08 - `address-source checkip` silently falls back to interface observation when the provider lacks `checkip-url`

Evidence:

```go
// pkg/daemon/daemon_ddns_surface_a.go:168-179
src := ddns.AddressSourceInterface
switch b.AddressSource {
case string(ddns.AddressSourceDHCP):
        src = ddns.AddressSourceDHCP
case string(ddns.AddressSourceCheckIP):
        // checkip is opt-in and requires the provider to carry a checkip-url;
        // without it, fall back to interface observation
        if prov.CheckIPURL != "" {
                src = ddns.AddressSourceCheckIP
        }
}
```

Runtime trace:

1. Operator sets `interfaces ... dynamic-dns address-source checkip` for a behind-NAT WAN.
2. Provider has no `checkip-url`.
3. Scope silently becomes `AddressSourceInterface`.
4. The router publishes its interface address instead of staying unpublished/error.

Impact: this converts an explicit behind-NAT DDNS intent into a potentially wrong record. Commit warning helps only if the operator reads it; runtime status does not show "checkip requested but missing URL".

Fix direction: preserve the requested source in the scope and let the observer/status surface a no-publish error when `checkip-url` is missing.

### H09 - Dyndns2 explicit `server` URL scheme matching is case-sensitive and misparses valid URLs

Evidence:

```go
// pkg/ddns/backend_dyndns2.go:97-103
if s := strings.TrimSpace(p.Server); s != "" {
        if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
                return s, nil
        }
        // Bare host -> canonical dyndns2 path over HTTPS.
        return "https://" + s + "/nic/update", nil
}
```

Runtime trace:

1. Operator configures `server HTTPS://updates.example/nic/update`.
2. URL schemes are case-insensitive, and the checkip validator already fixed this class.
3. `resolveDyndns2Endpoint` misses the uppercase scheme and treats the full URL as a bare host.
4. It returns `https://HTTPS://updates.example/nic/update/nic/update`.
5. First publish fails at runtime.

Probe result:

```text
go test ./pkg/ddns -run 'TestCodexAuditDyndns2UppercaseHTTPSIsMisparsedAsBareHost' -count=1
ok
```

Impact: a valid URL shape that the rest of DDNS accepts fails for dyndns2 server config. This is not the closed checkip uppercase issue; it is a separate dyndns2 endpoint parser.

Fix direction: parse the URL and compare `Scheme` with `strings.EqualFold`, requiring host for full URLs.

### H10 - DuckDNS per-family withdraw can delete the sibling family that remains configured

Evidence:

```go
// pkg/ddns/backend_duckdns.go:367-379
// DuckDNS has no per-family clear: clear=true removes BOTH the A
// and the AAAA for the domain.
func (b *duckdnsBackend) DeleteLease(ctx context.Context, rec LeaseDNSRecord) error {
        q := url.Values{}
        q.Set("clear", "true")
        return b.update(ctx, rec.FQDN, q)
}
```

Surface A withdraws on per-family address loss:

```go
// pkg/ddns/surface_a.go:755-785
if !obs.Addr.IsValid() {
        if owned, exists := m.state.get(sc.effectiveKey(), surfaceAIdentity, ""); exists {
                ...
                return m.withdrawScopeLocked(ctx, owned, backend, rt, sc.FQDN, sc.ErrorBackoffMax, now)
        }
}
```

Runtime trace:

1. DuckDNS name is configured on both inet and inet6. The validator warns but allows commit.
2. IPv6 PD disappears; IPv4 still has a good address.
3. The inet6 Surface A scope withdraws.
4. DuckDNS `clear=true` removes both the A and AAAA for the domain.
5. The still-configured inet scope is blackholed until the next v4 publish, and if it is skipped/backed off the outage persists.

Impact: this is a concrete sibling-family blackhole path, not only the documented "two scopes fight on update" behavior.

Fix direction: DuckDNS dual-stack same-name should be a hard commit error, or the engine should coalesce both family states into one DuckDNS update/clear decision for a domain.

### H11 - Cloudflare upsert can clobber a foreign/manual same-name record

Evidence:

```go
// pkg/ddns/backend_cloudflare.go:197-216
func (b *cloudflareBackend) findRecord(... wantContent string) (cfRecord, bool, error) {
        ...
        for _, rec := range recs {
                if rec.Content == wantContent {
                        return rec, true, nil
                }
        }
        return recs[0], true, nil
}

// pkg/ddns/backend_cloudflare.go:242-249
if found {
        if existing.Content == content {
                return nil
        }
        _, err = b.do(ctx, http.MethodPatch, "/zones/"+zoneID+"/dns_records/"+existing.ID, payload)
        return err
}
```

Runtime trace:

1. Cloudflare already has `wan.example.net A 198.51.100.10`, created manually or by another system.
2. xpf wants `wan.example.net A 203.0.113.5`.
3. `findRecord` finds no record with `203.0.113.5` and returns `recs[0]`.
4. Upsert patches the foreign row to xpf's address.

Impact: the already-fixed Cloudflare delete path is content-scoped, but upsert is still ownership-blind. A router/firewall appliance should not silently rewrite a foreign record unless the operator has explicitly declared the name self-owned and understands this behavior.

Fix direction: add a provider-side ownership marker/comment when available, or change Cloudflare Surface A semantics to POST when no matching owned record exists and refuse/conflict when a different row already exists.

## Medium Confidence Findings

### M01 - Publish rollback ignores state-save failure after a failed wire update

Evidence:

```go
// pkg/ddns/surface_a.go:980-998
if wireErr != nil {
        if !stale {
                if hadPrev {
                        m.state.put(prevOwned)
                } else {
                        m.state.delete(key, surfaceAIdentity, "")
                }
                _ = m.state.save()
        }
        m.upsertFail++
        ...
}
```

Runtime trace:

1. Publish write-aheads new ownership and saves it durably.
2. Provider update fails, so the new RR is not live.
3. Code restores the previous in-memory ownership but ignores rollback `save()` failure.
4. If the process crashes before the end-of-pass save, disk can still claim ownership of a record that never published.

Impact: the write-ahead safety invariant is weakened on the failure rollback path. This needs validation against the final `Reconcile` save, but the ignored error is a real crash-window smell.

Fix direction: propagate rollback save failure or mark the manager degraded until the durable store is known to match the in-memory rollback.

### M02 - `prevAddr` reads `Address` instead of `AddrText`, so replacement logs never show old Surface A addresses

Evidence:

```go
// pkg/ddns/surface_a.go:935-939
prevOwned, hadPrev := m.state.get(key, surfaceAIdentity, "")
prevAddr := ""
if hadPrev {
        prevAddr = prevOwned.Address
}

// pkg/ddns/surface_a.go:1024-1027
if prevAddr != "" && prevAddr != addr.String() {
        slog.Info("ddns surface-a: replaced record address",
                "fqdn", rec.FQDN, "old", prevAddr, "new", addr.String())
}
```

Surface A stores rdata in `AddrText`:

```go
// pkg/ddns/surface_a.go:946-951
Address:     "",
...
AddrText:    addr.String(),
```

Runtime trace:

1. Surface A changes address.
2. `prevOwned.Address` is always empty.
3. Replacement log branch never fires; the code logs neither old nor new replacement as intended.

Impact: operational evidence for WAN renumbering is missing. This matters for DDNS troubleshooting and audit trails.

Fix direction: use `prevOwned.AddrText`.

### M03 - Error backoff is checked before observation, delaying withdraw after address loss

Evidence:

```go
// pkg/ddns/surface_a.go:738-745
if !rt.nextEligible.IsZero() && now.Before(rt.nextEligible) {
        m.backedOff++
        return nil
}

// pkg/ddns/surface_a.go:747-785
obs, ok := observe(sc)
...
if !obs.Addr.IsValid() {
        ... withdraw ...
}
```

Runtime trace:

1. Publish fails and arms backoff for up to one hour.
2. Before the backoff expires, the interface/DHCP address disappears.
3. Reconcile skips the scope before observation.
4. The stale public DNS record remains until backoff expires, even though local address loss is definitive.

Impact: ban-avoidance backoff can delay cleanup for an address that is no longer usable. That can route inbound users to a dead address for the full backoff window.

Fix direction: observe first. If the result is definitive no-address and ownership exists, allow withdraw attempts on their own withdraw backoff state rather than publish backoff.

### M04 - Checkip source-bind failure falls open to default route and can publish the wrong WAN address

Evidence:

```go
// pkg/ddns/backend_http.go:165-173
// bind-resolution error ... returned alongside the UNBOUND default client
if err != nil {
        return newHTTPClient(), err
}

// pkg/daemon/daemon_ddns_surface_a.go:278-283
client, berr := d.surfaceA.CheckIPClient(scope.Provider)
if berr != nil {
        slog.Warn("ddns surface-a: checkip source bind unusable; probing from default route", ...)
}
a, ok := ddns.CheckIP(ctx, client, scope.Provider.CheckIPURL, af4, allow)
```

Runtime trace:

1. Multi-WAN operator configures checkip source binding for WAN2.
2. The configured source-address is malformed or cannot bind.
3. Runtime logs a warning but sends the checkip request via default route, likely WAN1.
4. Checkip returns WAN1 public IP.
5. Scope publishes WAN1 as WAN2's DDNS address.

Impact: this reintroduces the wrong-WAN publication class that source binding was intended to close. A checkip source-bind failure should be a per-scope error, not a fallback to the default route.

Fix direction: for `AddressSourceCheckIP`, treat bind-resolution failure as `ok=false` or a visible no-publish error. The fail-open default may be acceptable for generic HTTP updates, but checkip is an address oracle and should be fail-closed.

### M05 - Dyndns2 explicit full URL lacks host/scheme validation

Evidence:

```go
// pkg/ddns/backend_dyndns2.go:97-103
if s := strings.TrimSpace(p.Server); s != "" {
        if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
                return s, nil
        }
        return "https://" + s + "/nic/update", nil
}
```

Runtime trace:

1. Operator configures `server http://` or `server https:///nic/update`.
2. Prefix check accepts it as a full URL.
3. Backend construction succeeds.
4. First update fails at request build time instead of warning/failing closed at commit/construction.

Impact: dyndns2 is inconsistent with checkip and generic URL validation, both of which now require a parsed http(s) URL with a host.

Fix direction: parse full URLs and validate scheme+host exactly like `validateCheckIPURL` / `validateGenericURLTemplate`.

### M06 - Dyndns2 withdraw is hostname-level but the engine models per-family ownership

Evidence:

```go
// pkg/ddns/backend_dyndns2.go:137-144
func (b *dyndns2Backend) DeleteLease(ctx context.Context, rec LeaseDNSRecord) error {
        q := url.Values{}
        q.Set("hostname", rec.FQDN)
        q.Set("myip", rec.Addr.Unmap().String())
        q.Set("offline", "YES")
        return b.update(ctx, q)
}
```

Runtime trace:

1. Same dyndns2 hostname is bound for inet and inet6.
2. One family loses address and Surface A withdraws that family.
3. The backend sends `offline=YES` for the hostname, not an exact A or AAAA delete.
4. Provider may take the whole hostname offline, affecting the sibling family.

Impact: DuckDNS has an explicit dual-stack warning because its API is not per-family. Dyndns2's `offline=YES` likely has the same host-level nature, but the validator has no equivalent warning.

Fix direction: add backend capability metadata and warn or reject dual-family same-name dyndns2 topologies unless the selected provider documents per-family behavior.

### M07 - Route53 UPSERT replaces the entire RRSet with a single value

Evidence:

```go
// pkg/ddns/backend_route53.go:132-149
c.Action = action
c.ResourceRecordSet.Name = strings.TrimSuffix(rec.FQDN, ".") + "."
c.ResourceRecordSet.Type = rec.ForwardType
...
c.ResourceRecordSet.ResourceRecords.ResourceRecord = append(... one value ...)

// pkg/ddns/backend_route53.go:190-193
func (b *route53Backend) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
        _, _, err := b.change(ctx, "UPSERT", rec)
        return err
}
```

Runtime trace:

1. Route53 has `wan.example.net A` RRSet with values from another appliance or manual config.
2. xpf Surface A performs UPSERT with one `ResourceRecord`.
3. Route53 replaces the full RRSet with exactly that one value.

Impact: Route53 Surface A is self-owned by convention only. The current implementation can clobber co-resident same-name/type records.

Fix direction: either declare and hard-document exclusive ownership of Surface A names, or introduce conflict detection/ownership markers before replacing existing non-owned RRSets.

### M08 - RFC2136 self-owned Surface A uses delete-RRset for the whole A/AAAA set at the name

Evidence:

```go
// pkg/ddns/backend_rfc2136.go:771-804
// deletes the existing RRset OF OUR TYPE at OUR name ...
m.RemoveRRset([]dns.RR{rr})
m.Insert([]dns.RR{rr})
```

Runtime trace:

1. Authoritative zone contains multiple A values at the same Surface A name.
2. xpf publishes its new A via self-owned RFC2136.
3. The update deletes the entire A RRSet and inserts one value.

Impact: this is documented as the self-owned contract, so confidence is medium rather than high. Still, for a router aspiring to vSRX-grade safety, "self-owned" should not be a silent same-type clobber without a guard or explicit commit-time exclusivity signal.

Fix direction: add optional self-owner TXT/DHCID-like marker or fail when the name already has non-owned same-type values.

### M09 - Undefined-provider or missing-hostname interface bindings disappear from runtime status

Evidence:

```go
// pkg/daemon/daemon_ddns_surface_a.go:154-161
if b.Hostname == "" || b.Provider == "" {
        return
}
prov, ok := catalog[b.Provider]
if !ok || prov == nil {
        slog.Debug("ddns surface-a: binding references undefined provider; skipping", ...)
        return
}

// pkg/daemon/daemon_ddns_surface_a.go:640-644
if cfg := d.store.ActiveConfig(); cfg != nil {
        scopes = d.buildSurfaceAScopes(cfg)
}
return d.surfaceA.StatusViews(scopes)
```

Runtime trace:

1. Config contains an interface dynamic-dns binding with a typo provider or missing hostname.
2. Commit warning may be emitted.
3. `buildSurfaceAScopes` omits the binding entirely.
4. Runtime `show`/status has no row for the broken configured binding.

Impact: #2843 fixed status rows for no-backend/error scopes that make it into `SurfaceAScope`, but broken bindings skipped before scope construction remain invisible to operators.

Fix direction: materialize invalid configured bindings into status rows with `State=unpublished/error` and reason, or add a separate config-error status surface.

### M10 - DHCP no-lease is treated as definitive address loss even during transient DHCP manager gaps

Evidence:

```go
// pkg/daemon/daemon_ddns_surface_a.go:289-301
case ddns.AddressSourceDHCP:
        if d.dhcp == nil {
                return ddns.AddressObservation{}, false
        }
        lease := d.dhcp.LeaseFor(linuxName, af)
        if lease == nil {
                // No lease for this family yet: definitively no address. Withdraw
                return ddns.AddressObservation{Source: ddns.AddressSourceDHCP}, true
        }
```

Runtime trace:

1. DHCP client manager exists but is restarting, has not loaded lease state yet, or briefly drops the lease during renew/rebind churn.
2. Surface A observes `lease == nil`.
3. Engine treats it as definitive address loss and withdraws public DNS.

Impact: transient DHCP-client state can become a DNS blackhole, unlike netlink read errors, which are explicitly modeled as transient.

Fix direction: carry lease freshness/manager state into `LeaseFor`, or require a grace period before withdrawing on missing DHCP source.

### M11 - Surface A status ordering is nondeterministic for duplicate FQDN/family rows

Evidence:

```go
// pkg/ddns/surface_a.go:1313-1318
sort.Slice(out, func(i, j int) bool {
        if out[i].FQDN != out[j].FQDN {
                return out[i].FQDN < out[j].FQDN
        }
        return out[i].Family < out[j].Family
})
```

Runtime trace:

1. Same FQDN/family appears in multiple RGs, routing instances, providers, or orphaned/configured rows.
2. Sort comparator returns false in both directions for ties.
3. Final row order depends on map iteration and append order.

Impact: status JSON/CLI output can flap across runs, making monitoring diffs noisy and hiding deterministic triage.

Fix direction: sort by FQDN, family, interface, unit, provider, routing-instance, RG, state.

### M12 - Reconcile order is map-order dependent

Evidence:

```go
// pkg/daemon/daemon_ddns_surface_a.go:205-215
for ifName, ifc := range cfg.Interfaces.Interfaces {
        ...
        for un, unit := range ifc.Units {
                ...
                add(ifName, ifc, un, ddns.FamilyV4, unit.DynamicDNSInet)
                add(ifName, ifc, un, ddns.FamilyV6, unit.DynamicDNSInet6)
        }
}
```

Runtime trace:

1. Go map iteration shuffles interface/unit order.
2. Surface A builds scopes in nondeterministic order.
3. Reconcile order, first error reported, and provider update order differ per run.

Impact: deterministic control-plane programming matters for reproducibility and failure triage. This can also make rate-limited provider behavior harder to reproduce.

Fix direction: sort interface names and unit numbers before building scopes, matching validator style in `compiler_validate_warn.go`.

## Low Confidence / Design Triage Findings

### L01 - Generic backend has no delete template, so generic Surface A teardown can never clean the provider

Evidence:

```go
// pkg/ddns/README.md:32
// a single update template has no portable delete verb and xpf exposes no delete template
```

Impact: generic providers can publish but not withdraw; ownership remains operator-visible, but "turn feature off cleans up DNS" is incomplete.

Suggested issue: add optional generic delete URL template and delete success-token semantics.

### L02 - Surface A state machine is too large and mixes migration, provider ownership, publish, withdraw, and status

Evidence: `pkg/ddns/surface_a.go` contains construction, backend resolution, migration adoption, publish, withdraw, status, stats, backoff, and force handling.

Impact: the provider-change stale-record bugs above are symptoms of hidden coupling.

Suggested issue: split into `surfacea/state`, `surfacea/plan`, `surfacea/provider`, `surfacea/status`, not `surface_a_foo.go` files.

### L03 - Provider capability is encoded as comments/warnings, not engine policy

Evidence:

```go
// pkg/config/compiler_validate_warn.go:1620-1642
// DuckDNS ... Warn (not hard-reject...)
```

Impact: known unsafe topologies remain valid config. As more backends are added, the warning-only matrix will drift.

Suggested issue: add backend capability descriptors: per-family update, per-family delete, multi-value ownership, source-bind required, IPv6 supported.

### L04 - Per-interface DDNS can override only provider `source-address`, not destination-interface or routing-instance per binding

Evidence:

```go
// pkg/daemon/daemon_ddns_surface_a.go:163-167
p := *prov
if b.SourceAddress != "" {
        p.SourceAddress = b.SourceAddress
}
```

Impact: a router with many WAN interfaces must duplicate providers just to change update VRF/interface. vSRX-style per-interface DDNS should let the binding own all egress selection.

Suggested issue: add per-binding `destination-interface` and `routing-instance` overrides, or explicitly document provider-per-egress as required.

### L05 - Checkip allowlist malformed-token handling is warn-and-shrink, not fail-closed

Evidence:

```go
// pkg/daemon/daemon_ddns_surface_a.go:256-268
allow, badAllow := ddns.ParseAllowlistChecked(...)
if len(badAllow) > 0 { slog.Warn(...) }
```

Impact: a typo in a safety allowlist silently reduces the bogus-IP shield after warning. For a security appliance, a malformed safety gate often should make the scope unpublished until corrected.

### L06 - DuckDNS dual-stack same-name is a warning despite documented clobber

Evidence:

```go
// pkg/config/compiler_validate_warn.go:1638-1642
"... is bound on BOTH inet and inet6: DuckDNS auto-detects and overwrites ..."
```

Impact: the compiler knows the topology clobbers records every reconcile, but still permits it.

Suggested issue: promote to hard validation or require an explicit unsafe override.

### L07 - Dyndns2 provider IPv6 capability is not modeled

Evidence:

```go
// pkg/ddns/backend_dyndns2.go:121-125
q.Set("hostname", rec.FQDN)
q.Set("myip", rec.Addr.Unmap().String())
```

Impact: some dyndns2 services have partial or provider-specific IPv6 behavior. The backend treats every endpoint as equally dual-stack capable.

Suggested issue: provider capability table and warnings for unsupported family/backend combinations.

### L08 - Cloudflare resolves the zone ID on every publish/delete

Evidence:

```go
// pkg/ddns/backend_cloudflare.go:157-174
func (b *cloudflareBackend) resolveZoneID(ctx context.Context) (string, error) {
        ... GET /zones?name=...
}

// pkg/ddns/backend_cloudflare.go:221-223
zoneID, err := b.resolveZoneID(ctx)
```

Impact: each DDNS action costs at least two API calls. With many scopes, forced refresh can waste API quota and latency.

Suggested issue: cache zone ID by provider identity with invalidation on provider config changes.

### L09 - Cloudflare/Route53 records lack ownership metadata

Impact: HTTP APIs do not have DHCID. Without a provider-side comment/TXT/tag marker, xpf cannot distinguish self-owned from foreign rows on initial adoption.

Suggested issue: store/use provider-supported metadata where possible, or require first publish to see no existing name unless explicit `replace-existing` is configured.

### L10 - Route53 changes are not batched by hosted zone

Evidence: `UpsertLease` and `DeleteLease` each send a one-change `ChangeResourceRecordSets` request.

Impact: large multi-interface routers can spend more API calls and latency than necessary during forced refresh/failover.

Suggested issue: optional per-zone batch planner for Surface A Route53 operations.

### L11 - RG0 fallback chooses node 0 when RG0 is untracked, which can suppress non-HA DDNS on surviving node 1

Evidence:

```go
// pkg/daemon/daemon_ddns_surface_a.go:548-563
// RG0 NOT tracked ... fall back to ... node 0
return d.cluster.NodeID() == 0
```

Impact: in a non-standard cluster without RG0 tracking, node1 will not publish non-HA scopes even if node0 is down. This is probably accepted design for #2972, but it is an availability tradeoff worth documenting.

### L12 - Surface A tests rely heavily on package-private fake updaters and do not have provider-transition integration tests

Impact: the stale-record provider transition bugs above crossed the boundary between state and backend selection. Unit tests that inject one static fake updater cannot catch "delete must go to old provider".

Suggested issue: add fake provider registry with named providers and assert which provider receives Upsert/Delete.

## Negative Results

- Checkip body parsing already rejects private, CGNAT, documentation, link-local, ULA, NAT64, benchmarking, and other special-purpose ranges for external checkip responses.
- Static and netlink interface observation both reuse `ddns.IsPublicAddr`; the missing public gate found here is specific to `AddressSourceDHCP`.
- Cloudflare delete is no longer the old `recs[0]` bug; this report's Cloudflare concern is only the upsert path.
- Generic backend response-token matching already avoids substring success; no duplicate finding filed there.
- HTTP clients are reused and reaped by binding key; no duplicate of the old transport churn issue.

## Suggested GitHub Issues

1. DDNS Surface A provider mutation must preserve old-provider cleanup authority.
2. DDNS Surface A provider-rename same `{FQDN,address}` adoption drops old-provider ownership without delete.
3. DDNS Surface A restart cache parses `Address` instead of `AddrText` and republish-suppression is ineffective.
4. DDNS checkip observation must not run network I/O under `SurfaceAManager.mu`.
5. DDNS checkip must inherit the reconcile/shutdown context.
6. DDNS DHCP address source must apply the same public-address gate as interface/static/checkip.
7. DDNS `address-source checkip` without `checkip-url` should fail visible/unpublished, not fall back to interface.
8. Dyndns2 explicit `server` URLs need parsed case-insensitive scheme/host validation.
9. DuckDNS per-family withdraw can clear the sibling family; dual-stack same-name should be hard-invalid or coalesced.
10. Cloudflare Surface A upsert should not patch a foreign/manual same-name row blindly.
11. Route53/RFC2136 Surface A self-owned semantics should expose/guard same-type co-resident RR clobber.
12. Surface A status should include invalid configured bindings skipped before scope materialization.
13. Surface A scope build and status sort should be deterministic.
14. Add backend capability descriptors for per-family update/delete, ownership, IPv6, and replacement semantics.
