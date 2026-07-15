# Codex Review Audit 161

## Base Commit Reviewed

`579768f06`

## Output Path

`/tmp/codex-review-161.md`

## Duplicate Suppression Summary

Read `/home/ps/git/agy-do-review-audit.txt`, refreshed the checkout with `git pull --rebase`, and scanned prior `/tmp/codex-review*.md`, `/tmp/agy-review*.md`, `docs/issues/issue-history.md`, `docs/issues/pr-history.md`, `docs/feature-gaps.md`, `docs/multi-wan.md`, `docs/userspace-dataplane-gaps.md`, and the Rust/Go forwarding docs.

Suppressed as duplicates or already-tracked:

- Generic malformed static route destination / next-hop acceptance is #2448 / PR #2752. I do not count "bad destination silently dropped" as a new finding.
- Connected route table scoping is #2388 / PR #2732.
- Local-delivery attribution for the same local IP in two routing instances is #3151 / PR history. I only report a narrower residual involving non-interface NAT/DNAT local-address entries.
- ECMP collapse and per-destination spread are #2389 / #2734.
- Static route preference being dropped was #2390.
- GRE performance acceleration is #3360 / PR #3454. It is documented as config-truth threading; actual GRE key/call-id tuple extraction is a deferred feature, so I do not re-file it.

## Module Checklist

1. `userspace-dp/src/server/handlers/snapshot.rs` - apply and bump control verbs.
2. `userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs` - same-plan runtime snapshot refresh.
3. `userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs` - full reconcile apply comparison.
4. `userspace-dp/src/afxdp/forwarding_build/fib.rs` - route, neighbor, fabric hydration.
5. `userspace-dp/src/afxdp/forwarding/mod.rs` - lookup, local delivery, next-table, ECMP.
6. `userspace-dp/src/afxdp/forwarding_build/interfaces.rs` - connected and local address population.
7. `pkg/dataplane/userspace/routes.go` - Go route snapshot and overlay builder.
8. `pkg/dataplane/userspace/protocol.go` and `userspace-dp/src/protocol/snapshot.rs` - wire fields.
9. `userspace-dp/src/afxdp/flow_cache.rs` - generation equality and stale cache behavior.
10. `userspace-dp/src/afxdp/forwarding/README.md` and issue history - stated invariants.

## Module-by-Module Inspection Log

### 1. Snapshot Handler

Inspected `apply_snapshot` and `bump_fib_generation`. Findings: same-plan refresh has no error return, bump lacks version/ordering guards, and bump changes in-memory state without persistence.

### 2. Runtime Snapshot Refresh

Inspected the same-plan refresh path. Findings: it mutates neighbor manager keys and coordinator validation before the fallible full forwarding build succeeds; on error it returns `()` and the caller still treats the apply as successful.

### 3. Full Reconcile

Compared with full reconcile, which uses a prebuilt forwarding state before validation and publish. Negative result: the full reconcile path is stronger and is used as the intended invariant for the same-plan refresh findings.

### 4. Rust FIB Builder

Inspected route/neighbor/fabric hydration. Findings: gateway inference remains global, neighbor/fabric input is still soft-skipped, and route family/table integrity is lenient beyond #2448's generic bad-route gate.

### 5. Rust Forwarding Lookup

Inspected local delivery, next-table recursion, ECMP selection, and cache-facing generation checks. Findings: non-interface local targets are globally gated, next-table names are not canonicalized on recursion, and stale generation rollback can revive old cache entries.

### 6. Interface Local Population

Inspected local/connected population. Finding: interface-local addresses are table-scoped via connected entries, but late NAT/DNAT local additions are global IP sets with no table attribution.

### 7. Go Route Snapshot Builder

Inspected static, connected, ip-rule leak, and ip-monitoring overlay snapshot generation. Findings: IPv6 route-leak next-table names are built as `.inet.0`, route dedupe drops preference/discard, overlay preferred routes lose preference, netlink rule errors are swallowed.

### 8. Wire Protocol

Inspected route and neighbor wire structs. Findings: route `family`, neighbor `family`, and route preference bounds are not enforced at the Rust boundary.

### 9. Flow Cache

Inspected generation stamp equality checks. Finding: accepting a regressed FIB generation can make old cached decisions eligible again because validation is equality based.

### 10. Documentation / Issues

Checked docs for known route/FIB issues. Findings below avoid already-closed #2388/#2389/#2390/#2448/#3151/#3360.

## High Confidence Findings

### H1. Same-plan `apply_snapshot` can accept and persist a snapshot that the dataplane rejected

Severity: Critical  
Confidence: High  
Labels: `bug`, `userspace-dp`, `snapshot-integrity`, `routing`

Evidence:

`userspace-dp/src/server/handlers/snapshot.rs:110-118`:

```rust
if should_run_afxdp(&guard.status) {
    guard.afxdp.refresh_runtime_snapshot(&snapshot);
} else {
    guard.afxdp.refresh_runtime_snapshot_disarmed(&snapshot);
}
guard.snapshot = Some(snapshot);
refresh_status(guard);
*persist_state = true;
```

`userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:134-147`:

```rust
let new_forwarding = match build_forwarding_state_with_policy_counters_and_previous(
    snapshot,
    &self.policy_counters,
    &self.nat_counters,
    Some(&self.forwarding),
) {
    Ok(fwd) => fwd,
    Err(err) => {
        eprintln!(
            "xpf-userspace-dp: snapshot integrity error during runtime-snapshot refresh: {} -- keeping previous forwarding state",
            err
        );
        return;
    }
};
```

Runtime trace:

1. A same-binding-plan config change arrives, so `apply_snapshot` uses `refresh_runtime_snapshot`.
2. The incoming snapshot has a non-policy integrity error, for example an invalid interface address, CoS queue, NAT64/NPTv6 rule, or any other `build_forwarding_state...` failure.
3. `refresh_runtime_snapshot_inner` logs the error and returns `()`.
4. The caller cannot observe the rejection because the method returns no `Result`.
5. `apply_snapshot` still sets `guard.snapshot = Some(snapshot)`, refreshes status, and sets `persist_state = true`.
6. The control response remains `ok=true` while live forwarding is still the previous state and persisted helper state is the rejected new snapshot.

Why it matters:

This breaks the fail-closed snapshot contract. Operators and the Go control plane see a successful apply while packets are enforced against old forwarding state. On restart, the persisted rejected snapshot can become the boot baseline.

Suggested fix:

Make `refresh_runtime_snapshot{,_disarmed}` return `Result<(), SnapshotIntegrityError>`. On error, leave `guard.snapshot`, status generation, and persisted state untouched and return a failed control response. Add a same-plan regression test using a snapshot that fails in `build_forwarding_state...` but passes policy preflight.

### H2. Runtime refresh mutates coordinator validation before the fallible forwarding build succeeds

Severity: High  
Confidence: High  
Labels: `bug`, `userspace-dp`, `flow-cache`, `snapshot-integrity`

Evidence:

`userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:121-147`:

```rust
let prior_snapshot_installed = self.validation.snapshot_installed;
self.validation = ValidationState {
    snapshot_installed: true,
    config_generation: snapshot.generation,
    fib_generation: snapshot.fib_generation,
};
let preserved_fabrics = self.forwarding.fabrics.clone();
let new_forwarding = match build_forwarding_state_with_policy_counters_and_previous(
    snapshot,
    &self.policy_counters,
    &self.nat_counters,
    Some(&self.forwarding),
) {
    Ok(fwd) => fwd,
    Err(err) => {
        eprintln!(...);
        return;
    }
};
```

Runtime trace:

1. A same-plan snapshot with generation `G2` fails the forwarding build.
2. `self.validation` has already been overwritten to `G2`.
3. The shared validation Arc is not stored on that error path, so workers may still hold `G1` for now.
4. A later `bump_fib_generation` mutates `self.validation.fib_generation` and stores the whole `self.validation` into `shared_validation`.
5. That publish can expose `config_generation=G2` even though the forwarding Arc is still the old `G1` forwarding table.
6. Packets stamped for `G2` can then be validated against old forwarding state, or old packets can be rejected inconsistently depending on the sequence.

Why it matters:

Generation metadata is the atomicity contract between XDP metadata, flow cache, and Rust forwarding state. Updating it before the forwarding build succeeds creates a split-brain internal state.

Suggested fix:

Keep `next_validation` local until after `new_forwarding` is built. Only assign `self.validation` immediately before `shared_validation.store`, together with `self.forwarding = new_forwarding`.

### H3. Runtime refresh deletes old dynamic neighbor manager keys before knowing the new snapshot is valid

Severity: High  
Confidence: High  
Labels: `bug`, `userspace-dp`, `neighbor`, `snapshot-integrity`

Evidence:

`userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:85-115`:

```rust
let next_manager_keys = snapshot
    .neighbors
    .iter()
    .filter_map(|neigh| { ... })
    .collect::<FastSet<_>>();
let old_manager_keys = if let Ok(mut manager_keys) = self.neighbors.manager_keys.lock() {
    let old = manager_keys.iter().copied().collect::<Vec<_>>();
    *manager_keys = next_manager_keys;
    old
} else {
    Vec::new()
};
self.neighbors.dynamic.with_all_shards(|bulk| {
    for key in &old_manager_keys {
        bulk.remove(key);
    }
});
```

The fallible build occurs later at `snapshot_refresh.rs:134-147`.

Runtime trace:

1. Old forwarding state has dynamic neighbor keys for next-hops that are currently in use.
2. Same-plan snapshot arrives with changed neighbor list plus a later build error.
3. The refresh path replaces `manager_keys` and removes every old key from the sharded dynamic neighbor map.
4. The forwarding build then fails and returns, leaving old forwarding state live.
5. Old forwarding still routes through those next-hops but its dynamic neighbor entries have been deleted.
6. Traffic falls into missing-neighbor or probe paths even though the snapshot was rejected and should have left all live state intact.

Why it matters:

This violates the "previous good state stays live" contract and creates transient or persistent blackholes on a rejected config.

Suggested fix:

Build forwarding first. Stage `next_manager_keys` locally, and swap/remove manager keys only after the forwarding build succeeds and right before the forwarding/validation store.

### H4. `bump_fib_generation` has no snapshot protocol-version gate

Severity: High  
Confidence: High  
Labels: `bug`, `userspace-dp`, `protocol`, `snapshot-integrity`

Evidence:

`userspace-dp/src/server/handlers/snapshot.rs:157-176`:

```rust
pub(super) fn bump_fib(
    guard: &mut ServerState,
    snapshot: Option<&ConfigSnapshot>,
    response: &mut ControlResponse,
) {
    let Some(snapshot) = snapshot else {
        response.ok = false;
        response.error = "missing snapshot".to_string();
        return;
    };
    guard.status.last_fib_generation = snapshot.fib_generation;
    if let Some(ref mut snap) = guard.snapshot {
        snap.fib_generation = snapshot.fib_generation;
    }
    guard.afxdp.bump_fib_generation(snapshot.fib_generation);
    refresh_status(guard);
}
```

`apply_snapshot` checks the protocol version at `snapshot.rs:25-32`; `bump_fib` does not.

Runtime trace:

1. A mixed-version or corrupt control client sends `bump_fib_generation` with `ConfigSnapshot.version=0`.
2. The helper accepts it because only payload presence is checked.
3. It updates status, stored snapshot memory, and worker validation FIB generation.
4. No decoder/contract compatibility gate runs.

Why it matters:

`bump_fib_generation` is a protocol message that mutates dataplane validation state. It should have the same version compatibility gate as `apply_snapshot`.

Suggested fix:

Reject `snapshot.version != CONFIG_SNAPSHOT_PROTOCOL_VERSION` in `bump_fib`, with a unit test mirroring the apply version test.

### H5. `bump_fib_generation` accepts generation rollback, which can revive stale flow-cache entries

Severity: High  
Confidence: High  
Labels: `bug`, `userspace-dp`, `flow-cache`, `routing`

Evidence:

`userspace-dp/src/afxdp/coordinator/mod.rs:803-808`:

```rust
pub fn bump_fib_generation(&mut self, fib_generation: u32) {
    self.validation.fib_generation = fib_generation;
    self.shared_validation.store(Arc::new(self.validation));
}
```

`userspace-dp/src/afxdp/flow_cache.rs` validates by equality against the current stamp; the design relies on generation inequality being authoritative.

Runtime trace:

1. Flow F is cached under config generation `C` and FIB generation `10`.
2. Route overlay changes bump the helper to FIB generation `11`; the old cache entry is stale.
3. A stale or buggy control message sends `bump_fib_generation` with generation `10`.
4. The helper accepts the rollback and publishes validation `(C, 10)`.
5. Flow F's old cache stamp now matches validation again.
6. Cached forwarding can be reused after a route withdrawal or failover route change.

Why it matters:

Flow-cache safety depends on monotonic or at least non-reused generation values. Equality-only validation cannot defend against generation rollback.

Suggested fix:

Reject a FIB bump lower than the current in-memory generation unless it is part of a full snapshot generation transition. Consider widening to `u64` or carrying a boot/session nonce in cache stamps.

### H6. IPv6 ip-rule route leaks point to `.inet.0`, so userspace IPv6 next-table lookups can miss the target VRF

Severity: High  
Confidence: High  
Labels: `bug`, `userspace-dp`, `routing`, `ipv6`, `vsrx-parity`

Evidence:

`pkg/dataplane/userspace/routes.go:108-138`:

```go
tableIDToName := make(map[int]string)
for _, inst := range cfg.RoutingInstances {
    if inst != nil && inst.TableID > 0 {
        tableIDToName[inst.TableID] = inst.Name + ".inet.0"
    }
}
for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
    rules, err := netlink.RuleList(family)
    if err != nil {
        continue
    }
    ...
    if family == syscall.AF_INET6 {
        familyStr = "inet6"
        mainTable = "inet6.0"
    }
    addSnapshot(RouteSnapshot{
        Table:       mainTable,
        Family:      familyStr,
        Destination: rule.Dst.String(),
        NextTable:   tableName,
    })
}
```

`tableName` is always `ri.Name + ".inet.0"` even in the `AF_INET6` loop.

Runtime trace:

1. Linux has an IPv6 ip rule that routes `2001:db8:1::/48` into routing instance `blue`.
2. `buildRouteSnapshots` emits a main-table IPv6 `RouteSnapshot` with `Table="inet6.0"`, `Family="inet6"`, `Destination=...`, but `NextTable="blue.inet.0"`.
3. Rust IPv6 lookup sees the next-table route and recurses using the raw next-table string.
4. `routes_v6` contains `blue.inet6.0`, not `blue.inet.0`.
5. The lookup misses and returns `NoRoute` even though the route exists in the VRF's IPv6 table.

Why it matters:

IPv6 rib-groups / next-table route leaking is a vSRX-class routing feature. The userspace dataplane can drop leaked IPv6 traffic while FRR/kernel routing works.

Suggested fix:

Track table ID to both family table names, or compute the next-table name inside the loop: `ri.Name + ".inet6.0"` for `AF_INET6`. Add Go and Rust integration tests for IPv6 ip-rule leaks.

### H7. Non-interface NAT/DNAT local addresses are globally local-delivered across routing tables

Severity: High  
Confidence: High  
Labels: `bug`, `userspace-dp`, `nat`, `vrf`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/forwarding_build/mod.rs:404-427`:

```rust
for ext_ip in state.static_nat.external_ips() {
    match ext_ip {
        std::net::IpAddr::V4(v4) => {
            state.local_v4.insert(*v4);
        }
        std::net::IpAddr::V6(v6) => {
            state.local_v6.insert(*v6);
        }
    }
}
for dst_ip in state.dnat_table.destination_ips() {
    match dst_ip {
        std::net::IpAddr::V4(v4) => {
            state.local_v4.insert(v4);
        }
        std::net::IpAddr::V6(v6) => {
            state.local_v6.insert(v6);
        }
    }
}
```

`userspace-dp/src/afxdp/forwarding/mod.rs:1139-1164`:

```rust
let table = table
    .map(|table| canonical_route_table(table, false))
    .unwrap_or_else(|| DEFAULT_V4_TABLE.to_string());
if state.local_v4.contains(&ip) {
    let local_ifindex = state
        .connected_v4
        .iter()
        .find(|entry| entry.table == table && entry.prefix.addr() == ip)
        .map(|entry| entry.ifindex)
        .unwrap_or(0);
    return ForwardingResolution {
        disposition: ForwardingDisposition::LocalDelivery,
        local_ifindex,
        egress_ifindex: local_ifindex,
```

Runtime trace:

1. Static NAT or DNAT publishes an external/destination IP in the global `local_v4`/`local_v6` set.
2. A packet in a different routing table is destined to that same IP.
3. The local shortcut checks the global set first and returns `LocalDelivery`.
4. The table-scoped connected scan cannot find a connected interface for that NAT-only IP and falls back to ifindex `0`.
5. The normal route lookup path is bypassed even though the current VRF may have a real route or should have no local NAT ownership.

Why it matters:

This is a cross-VRF local-delivery leak for NAT-owned addresses. It can mis-feed zone selection, HA RG ownership, and DNAT/static-NAT admission.

Suggested fix:

Carry table/VRF attribution for NAT local targets, or gate the local-delivery shortcut on either a table-scoped connected match or a table-scoped NAT ownership record. Avoid returning `LocalDelivery` with ifindex `0` unless a specific local subsystem owns that address in the current table.

### H8. Route snapshot dedupe ignores `Discard` and `Preference`, so one route can erase another distinct route

Severity: High  
Confidence: High  
Labels: `bug`, `userspace-dp`, `routing`

Evidence:

`pkg/dataplane/userspace/routes.go:23-31`:

```go
out := make([]RouteSnapshot, 0)
seen := make(map[string]struct{})
addSnapshot := func(snap RouteSnapshot) {
    key := snap.Table + "|" + snap.Family + "|" + snap.Destination + "|" + strings.Join(snap.NextHops, ",") + "|" + snap.NextTable
    if _, ok := seen[key]; ok {
        return
    }
    seen[key] = struct{}{}
    out = append(out, snap)
}
```

The key omits `Discard` and `Preference`.

Runtime trace:

1. Two route sources produce the same table/family/prefix/next-hop key but different `Preference`, or one is a discard route and one is forwarding route.
2. The first one inserted wins.
3. The second route is dropped before Rust sees it.
4. Rust's `sort_routes` cannot apply preference tie-breaks because the route was erased.

Why it matters:

This can silently alter route preference or blackhole semantics in the userspace dataplane while FRR/kernel route selection remains correct.

Suggested fix:

Include `Discard` and `Preference` in the dedupe key, or remove this dedupe and let Rust's stable preference sort own route selection. Add tests with same prefix and next-hop but different preference/discard.

## Medium Confidence Findings

### M1. Same-plan refresh error path does not set the control response to failed

Severity: Medium  
Confidence: Medium  
Labels: `bug`, `userspace-dp`, `control-plane`

Evidence:

`refresh_runtime_snapshot_inner` returns `()` on error (`snapshot_refresh.rs:141-147`), and `apply_snapshot` has no branch to set `response.ok=false` after calling it (`server/handlers/snapshot.rs:110-118`).

Runtime trace:

1. Same-plan snapshot fails full forwarding build.
2. Rust logs to stderr.
3. The control handler returns success because it never receives the error.
4. Go-side publish/retry logic treats the apply as successful.

Why it matters:

Even if H1's persisted-snapshot bug is fixed separately, the caller still needs a negative acknowledgement to retry or surface apply failure.

Suggested fix:

Return a typed error and thread it to `ControlResponse`.

### M2. `bump_fib_generation` mutates the stored snapshot in memory but does not persist it

Severity: Medium  
Confidence: Medium  
Labels: `bug`, `userspace-dp`, `restart`

Evidence:

`userspace-dp/src/server/handlers/snapshot.rs:171-176`:

```rust
guard.status.last_fib_generation = snapshot.fib_generation;
if let Some(ref mut snap) = guard.snapshot {
    snap.fib_generation = snapshot.fib_generation;
}
guard.afxdp.bump_fib_generation(snapshot.fib_generation);
refresh_status(guard);
```

The handler signature has no `persist_state` parameter, unlike `apply_snapshot`.

Runtime trace:

1. Helper applies snapshot with FIB generation `10`, persisted to disk.
2. Route-only overlay changes bump generation to `11`.
3. The handler rewrites `guard.snapshot.fib_generation` in RAM only.
4. The helper or host restarts before a full snapshot apply.
5. Persisted helper state still carries generation `10`.

Why it matters:

Restart behavior can observe an old FIB generation even though the control plane considered generation `11` applied. That weakens the route-overlay restart contract.

Suggested fix:

Either do not mutate stored snapshot on bump, or make bump persist state and add restart tests for route-only overlay bumps.

### M3. Static next-hop gateway inference is global, not route-table scoped

Severity: Medium  
Confidence: Medium  
Labels: `bug`, `userspace-dp`, `routing`, `vrf`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/forwarding_build/fib.rs:330-345`:

```rust
pub(in crate::afxdp) fn infer_connected_route_target_v4(
    state: &ForwardingState,
    ip: Ipv4Addr,
) -> Option<(i32, u16)> {
    // Gateway -> egress-interface inference at FIB-build time: "which
    // interface can reach this next-hop gateway IP". This is a global
    // connected-prefix match and is intentionally NOT table-scoped ...
    state
        .connected_v4
        .iter()
        .find(|entry| entry.prefix.contains(ip))
        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
}
```

Runtime trace:

1. VRF `blue` has a static route whose gateway address is only connected in VRF `red`.
2. The builder scans all connected routes globally.
3. It resolves the `blue` route's next-hop to `red`'s interface.
4. Traffic in `blue` can egress via `red`, bypassing VRF isolation.

Why it matters:

Junos/vSRX next-hop resolution is VRF/table scoped unless explicit route leaking is configured. The current behavior makes accidental or stale gateways dangerous.

Suggested fix:

Pass the route table into `resolve_next_hop_target_*` and restrict inference to connected routes in that table. Require explicit `@interface` or next-table/rib-group to cross VRFs.

### M4. `RouteSnapshot.family` is ignored at the Rust boundary

Severity: Medium  
Confidence: Medium  
Labels: `bug`, `userspace-dp`, `protocol`

Evidence:

`userspace-dp/src/protocol/snapshot.rs:153-166`:

```rust
pub(crate) struct RouteSnapshot {
    #[serde(default)]
    pub table: String,
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub destination: String,
```

`userspace-dp/src/afxdp/forwarding_build/fib.rs:42-83` decides family solely by parsing `route.destination` as `Ipv4Net` or `Ipv6Net`; `route.family` is not consulted.

Runtime trace:

1. A mixed-version or corrupt control client sends `family="inet6"` with an IPv4 destination.
2. Rust parses the destination as IPv4.
3. It installs the route into the IPv4 FIB anyway.
4. The declared family is ignored and no integrity error is raised.

Why it matters:

This is a protocol integrity gap. It is not #2448's malformed-route case because the prefix itself is valid; the family metadata is inconsistent.

Suggested fix:

Validate that `family` matches destination AF, accepting only the known compatibility cases if deliberately required. Add a source-level test for mismatched family.

### M5. Recursive `next_table` lookup uses raw table strings and does not canonicalize per address family

Severity: Medium  
Confidence: Medium  
Labels: `bug`, `userspace-dp`, `routing`, `ipv6`

Evidence:

`userspace-dp/src/afxdp/forwarding/mod.rs:1591-1616`:

```rust
if !route.next_table.is_empty() {
    let next_table_name = route.next_table.as_str();
    if next_table_name == table {
        return ForwardingResolution { disposition: ForwardingDisposition::NextTableUnsupported, ... };
    }
    let next_table_name = route.next_table.clone();
    return lookup_forwarding_resolution_v4(
        state,
        dynamic_neighbors,
        ip,
        &next_table_name,
        depth + 1,
        allow_tunnels,
        ecmp_flow_hash,
    );
}
```

The v6 branch is the same at `forwarding/mod.rs:1765-1789`.

Runtime trace:

1. A v6 route carries `next_table="blue.inet.0"` due to the Go builder bug in H6 or a mixed-version snapshot.
2. The v6 lookup recurses using the raw string.
3. `routes_v6` is keyed by `blue.inet6.0`.
4. The route leak misses instead of canonicalizing to the v6 sibling table.

Why it matters:

This compounds H6 and makes table-family drift fail closed in the data path instead of being caught at apply time.

Suggested fix:

Canonicalize recursive next-table names with the current address family before loop detection and recursion, or reject cross-family next-table strings during build.

### M6. `next-table` loop detection only catches direct self-loops

Severity: Medium  
Confidence: Medium  
Labels: `bug`, `userspace-dp`, `routing`, `test-gap`

Evidence:

`userspace-dp/src/afxdp/forwarding/mod.rs:1518-1526` and `1591-1616`:

```rust
if depth >= MAX_NEXT_TABLE_DEPTH {
    return ForwardingResolution {
        disposition: ForwardingDisposition::NextTableUnsupported,
        ...
    };
}
...
if next_table_name == table {
    return ForwardingResolution {
        disposition: ForwardingDisposition::NextTableUnsupported,
        ...
    };
}
```

Runtime trace:

1. Table A has a route to next-table B.
2. Table B has a route to next-table A.
3. Neither hop is a direct self-loop.
4. Lookup recurses until depth 8 and only then fails.

Why it matters:

This is bounded, not an infinite loop, but it burns extra work on every miss through a route-leak cycle and hides the exact configuration defect.

Suggested fix:

Carry a small visited table set or stack in recursion. Emit a specific cycle disposition/counter and add tests for A->B->A.

### M7. ip-monitoring overlay routes lose the documented preferred-route preference

Severity: Medium  
Confidence: Medium  
Labels: `bug`, `ip-monitoring`, `userspace-dp`, `routing`

Evidence:

`pkg/config/types_system.go` documents preferred routes as route preference 1:

```go
// routes (at route preference 1, Static/1 on SRX) while ANY test of the
// associated policy is down.
```

`pkg/dataplane/userspace/routes.go:173-178` builds the overlay route without `Preference`:

```go
replaced[key{table, family, dest}] = RouteSnapshot{
    Table:       table,
    Family:      family,
    Destination: dest,
    NextHops:    []string{entry.NextHop},
}
```

`RouteSnapshot.Preference` defaults to `0` on the Rust side.

Runtime trace:

1. IP monitoring injects a preferred route.
2. FRR/kernel side treats it as Static/1.
3. Userspace route overlay sends preference `0`.
4. Rust sorts lower preference as more preferred.
5. Userspace dataplane makes the failover route even more preferred than the documented SRX-compatible value.

Why it matters:

This can diverge from FRR/kernel tie-breaking when another route with preference 0 or 1 exists.

Suggested fix:

Set `Preference: 1` on overlay `RouteSnapshot`, or carry the exact `RouteOverlayEntry.Preference` explicitly.

### M8. `canonicalRoutePrefix` comment says malformed prefixes return empty, but code returns the raw malformed string

Severity: Medium  
Confidence: Medium  
Labels: `bug`, `ip-monitoring`, `routing`, `test-gap`

Evidence:

`pkg/dataplane/userspace/routes.go:209-216`:

```go
// canonicalRoutePrefix mask-normalizes a CIDR for overlay matching;
// returns "" for unparseable strings (left untouched).
func canonicalRoutePrefix(s string) string {
    _, n, err := net.ParseCIDR(s)
    if err != nil || n == nil {
        return s
    }
    return n.String()
}
```

Runtime trace:

1. A malformed internal overlay destination reaches `applyRouteOverlay`.
2. The comment implies it should return empty and be skipped.
3. The code returns the raw malformed string.
4. The malformed route enters the snapshot path.
5. Rust later ignores or mishandles it depending on #2448-era backstops.

Why it matters:

This is an internal invariant mismatch at the route-overlay boundary. The function name and caller at `routes.go:169-171` expect empty to mean skip.

Suggested fix:

Either return `""` on parse error and test it, or update the caller/comment and add an explicit error/counter for impossible overlay prefixes.

### M9. Netlink `RuleList` failures silently remove all userspace route-leak snapshots

Severity: Medium  
Confidence: Medium  
Labels: `bug`, `userspace-dp`, `routing`, `observability`

Evidence:

`pkg/dataplane/userspace/routes.go:114-118`:

```go
for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
    rules, err := netlink.RuleList(family)
    if err != nil {
        continue
    }
```

Runtime trace:

1. Netlink rule listing fails transiently or due to permissions/namespace state.
2. The builder silently skips that family.
3. Userspace route snapshots omit every route-leak synthetic route for that family.
4. The kernel/FRR route-leak path remains present, so userspace dataplane diverges.

Why it matters:

Route leaking is control-plane-critical. Losing it silently can produce blackholes or policy bypasses depending on fallback.

Suggested fix:

Return an error from route snapshot construction, or at least publish a structured warning/status field and keep the previous route snapshot on failure.

### M10. Route snapshot sort is unstable for equal table/family/destination, causing ECMP member churn

Severity: Medium  
Confidence: Medium  
Labels: `performance`, `userspace-dp`, `routing`, `latency`

Evidence:

`pkg/dataplane/userspace/routes.go:144-152`:

```go
sort.Slice(out, func(i, j int) bool {
    if out[i].Table != out[j].Table {
        return out[i].Table < out[j].Table
    }
    if out[i].Family != out[j].Family {
        return out[i].Family < out[j].Family
    }
    return out[i].Destination < out[j].Destination
})
```

Runtime trace:

1. Two or more equal-prefix routes differ only in next-hop or preference.
2. The comparator returns false for both orderings when table/family/destination match.
3. `sort.Slice` is not stable.
4. Incoming route order to Rust can change across applies.
5. Rust's stable sort preserves incoming order for same prefix/preference, and ECMP fallback/accessors use vector order.

Why it matters:

Unstable route order can churn ECMP member selection and route tie-breaks even when config did not semantically change.

Suggested fix:

Use `sort.SliceStable` and add next-hop, next-table, discard, and preference tie-breakers.

### M11. Neighbor snapshot `family` is ignored at the Rust boundary

Severity: Medium  
Confidence: Medium  
Labels: `bug`, `userspace-dp`, `neighbor`, `protocol`

Evidence:

`pkg/dataplane/userspace/protocol.go:1191-1195`:

```go
type NeighborSnapshot struct {
    Interface string `json:"interface,omitempty"`
    Ifindex   int    `json:"ifindex,omitempty"`
    Family    string `json:"family"`
    IP        string `json:"ip"`
```

`userspace-dp/src/afxdp/forwarding_build/fib.rs:112-126`:

```rust
for neigh in &snapshot.neighbors {
    if neigh.ifindex <= 0 || !neighbor_state_usable(&neigh.state) {
        continue;
    }
    let Ok(ip) = neigh.ip.parse::<IpAddr>() else {
        continue;
    };
    let Some(mac) = parse_mac(&neigh.mac) else {
        continue;
    };
    state.neighbors.insert((neigh.ifindex, ip), NeighborEntry { mac });
}
```

Runtime trace:

1. A mixed-version or corrupt snapshot sends `family="inet"` with an IPv6 `ip`.
2. Rust ignores `family` and parses the IP as IPv6.
3. The neighbor is installed anyway.
4. The wire-family invariant is not enforced.

Why it matters:

Neighbor family mismatch should be rejected at the snapshot boundary, not silently normalized.

Suggested fix:

Validate neighbor family against parsed IP family and fail the snapshot on mismatch.

### M12. Unknown neighbor states are treated usable by default

Severity: Medium  
Confidence: Medium  
Labels: `bug`, `userspace-dp`, `neighbor`

Evidence:

`userspace-dp/src/afxdp/forwarding/mod.rs:54-57`:

```rust
pub(super) fn neighbor_state_usable(state: &str) -> bool {
    let normalized = state.to_ascii_lowercase();
    !(normalized.contains("failed") || normalized.contains("incomplete"))
}
```

Runtime trace:

1. Kernel or Go emits an unexpected neighbor state string, such as empty, `none`, or a future state.
2. The string does not contain `failed` or `incomplete`.
3. Rust considers the neighbor usable if the IP/MAC parse.
4. A stale or semantically invalid MAC can be used for forwarding.

Why it matters:

For a router dataplane, neighbor liveness should be an allowlist, not a denylist over free-form strings.

Suggested fix:

Define explicit accepted states (`reachable`, `stale`, `delay`, `probe`, `permanent`, `noarp` if intended) and reject/ignore unknown states with a counter.

### M13. Fabric links are silently skipped when peer/local MAC or peer address is malformed

Severity: Medium  
Confidence: Medium  
Labels: `bug`, `userspace-dp`, `fabric`, `observability`

Evidence:

`userspace-dp/src/afxdp/forwarding_build/fib.rs:134-155`:

```rust
for fabric in &snapshot.fabrics {
    if fabric.parent_ifindex <= 0 {
        continue;
    }
    let Ok(peer_addr) = fabric.peer_address.parse::<IpAddr>() else {
        continue;
    };
    let local_mac = parse_mac(&fabric.local_mac)
        .or_else(|| iface_ctx.mac_by_ifindex.get(&fabric.parent_ifindex).copied());
    let Some(local_mac) = local_mac else {
        continue;
    };
    let peer_mac = parse_mac(&fabric.peer_mac).or_else(|| {
        ...
    });
    let Some(peer_mac) = peer_mac else {
        continue;
    };
```

Runtime trace:

1. A fabric peer has a malformed or unresolved MAC/address in the snapshot.
2. Rust silently skips the link.
3. No snapshot error, status reason, or metric identifies the missing fabric.
4. Fabric redirect eligibility changes without operator visibility.

Why it matters:

Fabric links affect HA and clustered dataplane behavior. Silent skip is acceptable only if paired with explicit status saying "fabric unresolved".

Suggested fix:

Classify skips into counters/status fields, or fail closed for malformed values while allowing a distinct unresolved-peer state.

## Low Confidence Findings

### L1. Route preference has no Rust-side range/backstop

Severity: Low  
Confidence: Low  
Labels: `hardening`, `userspace-dp`, `routing`

Evidence:

`RouteSnapshot.preference` is an `i32` in Rust and Go, and Rust sorts it ascending at `forwarding_build/fib.rs:94-108`.

Runtime trace:

1. A corrupt snapshot sends `preference=-2147483648`.
2. Rust accepts it.
3. It sorts ahead of all normal routes.

Why it matters:

Go likely validates normal config, so this is a helper-boundary hardening gap rather than a direct operator bug.

Suggested fix:

Validate preference range at both Go and Rust boundaries; define the accepted Junos-compatible range.

### L2. `canonical_route_table` silently rewrites cross-family table names instead of rejecting drift

Severity: Low  
Confidence: Low  
Labels: `hardening`, `userspace-dp`, `routing`

Evidence:

`userspace-dp/src/afxdp/forwarding/mod.rs:35-51`:

```rust
pub(super) fn canonical_route_table(table: &str, is_ipv6: bool) -> String {
    if is_ipv6 {
        if table == "inet.0" {
            return "inet6.0".to_string();
        }
        if let Some(prefix) = table.strip_suffix(".inet.0") {
            return format!("{prefix}.inet6.0");
        }
        return table.to_string();
    }
    if table == "inet6.0" {
        return "inet.0".to_string();
    }
```

Runtime trace:

1. A snapshot carries a v6 destination in `inet.0` or a v4 destination in `inet6.0`.
2. Rust silently moves it to the sibling family table.
3. No integrity error identifies the producer bug.

Why it matters:

Compatibility may require this today, but it hides future drift. At minimum, status should count normalized mixed-family routes.

Suggested fix:

Keep compatibility only behind a named migration comment/test; otherwise reject or warn on mixed-family table names.

### L3. IPv6 link-local next-hop syntax depends on `addr@interface`; `%iface` is not accepted

Severity: Low  
Confidence: Low  
Labels: `feature-gap`, `userspace-dp`, `ipv6`, `vsrx-parity`

Evidence:

`userspace-dp/src/afxdp/forwarding_build/fib.rs:300-317` splits next-hop strings only on `@` and parses the IP part as `Ipv6Addr`.

Runtime trace:

1. A route source emits a conventional scoped IPv6 string like `fe80::1%reth0`.
2. Rust does not split on `%`.
3. `Ipv6Addr` parsing fails and the next-hop becomes `None`.

Why it matters:

The Go emitter currently uses `addr@interface`, but external tooling or future route sources may use standard scoped IPv6 notation.

Suggested fix:

Normalize `%iface` and `@iface` at the Go boundary or reject `%` explicitly with a clear error.

### L4. `update_fabrics` refreshes runtime fabric links but does not persist any state

Severity: Low  
Confidence: Low  
Labels: `observability`, `userspace-dp`, `fabric`

Evidence:

`userspace-dp/src/server/handlers/mod.rs:136-141`:

```rust
"update_fabrics" => {
    if let Some(fabrics) = request.fabrics.as_ref() {
        guard.afxdp.refresh_fabric_links(fabrics);
        refresh_status(&mut guard);
    }
}
```

Runtime trace:

1. Fabric links become resolved after the main snapshot.
2. Go sends `update_fabrics`.
3. The helper updates runtime state and status.
4. No persisted snapshot/state records the resolved fabric data.
5. Restart loses it until the next update.

Why it matters:

This may be intentional for runtime MAC resolution, but restart behavior should be documented and visible.

Suggested fix:

Document that fabric updates are volatile, or persist the last resolved fabric set if restart continuity matters.

### L5. Local-delivery with ifindex 0 is not treated as an explicit invariant violation

Severity: Low  
Confidence: Low  
Labels: `hardening`, `userspace-dp`, `test-gap`

Evidence:

`forwarding/mod.rs:1153-1164` and `1188-1199` return `LocalDelivery` even when `local_ifindex` fell back to `0`.

Runtime trace:

1. `state.local_v4.contains(ip)` is true.
2. The table-scoped connected scan finds no interface.
3. The helper returns `LocalDelivery` with all ifindex fields `0`.
4. Downstream code must infer what a zero-local local delivery means.

Why it matters:

For a firewall/router, local delivery should have a known owning interface/zone/RG or an explicit "local owner unknown" disposition.

Suggested fix:

Add a debug/assertion test and a runtime counter for `LocalDelivery` with ifindex 0. Consider falling through to route lookup when no table-scoped local owner exists.

### L6. Route overlay replacement cannot express ECMP preferred routes

Severity: Low  
Confidence: Low  
Labels: `feature-gap`, `ip-monitoring`, `routing`, `vsrx-parity`

Evidence:

`pkg/dataplane/userspace/routes.go:156-179` stores exactly one `RouteSnapshot` per `(table,family,dest)` overlay key and sets `NextHops: []string{entry.NextHop}`.

Runtime trace:

1. An ip-monitoring policy wants a preferred route with multiple qualified next-hops.
2. The overlay type and replacement map collapse the entry to a single next-hop.
3. Rust cannot perform ECMP across preferred-route next-hops.

Why it matters:

This may be outside the current config model, but vSRX-style preferred routes can interact with multi-next-hop static routing.

Suggested fix:

If the config supports multiple preferred next-hops, carry `[]NextHops` and preference. If not, document the single-next-hop limitation.

## Suggested Issue Split

1. Critical: make same-plan runtime snapshot refresh fallible and atomic (`H1`, `H2`, `H3`, `M1`).
2. High: harden `bump_fib_generation` version, monotonicity, and persistence (`H4`, `H5`, `M2`).
3. High: fix userspace IPv6 route-leak next-table names (`H6`, `M5`).
4. High: table-scope NAT/DNAT local-delivery targets (`H7`, `L5`).
5. Medium: route snapshot dedupe/sort/preference correctness (`H8`, `M7`, `M10`, `L1`).
6. Medium: route-overlay input invariants and observability (`M8`, `M9`, `L6`).
7. Medium: helper-boundary protocol validation for route/neighbor family and neighbor state (`M4`, `M11`, `M12`).
8. Medium: fabric link skip observability and restart semantics (`M13`, `L4`).
9. Medium/low: route-table and next-hop hardening (`M3`, `M6`, `L2`, `L3`).
