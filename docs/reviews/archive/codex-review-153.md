# Codex Review 153 - Core Firewall Host-Inbound and Zone Identity Campaign

## 1. Base Commit Reviewed

- Base commit: `5d77dbde724c`
- `git pull --rebase`: already up to date.
- Output path: `/tmp/codex-review-153.md`
- Focus: core firewall behavior: zone policies, host-inbound enforcement, stable zone identity, and making sure packets that should be denied are denied while packets that should be allowed are allowed.

## 2. Duplicate Suppression Summary

Read prior `/tmp/codex-review*.md` and `/tmp/agy-review*.md` before counting findings. Suppressed as already covered:

- `codex-review-127.md`: generic host-inbound diagnostic gaps and host-bound policy wording.
- `codex-review-128.md`: addressless host-inbound fail-open windows, unknown/global zone admit-all, VLAN logical ifindex lookup bypass, and global ESP/AH/ICMP host-inbound exceptions.
- `codex-review-131.md` / `agy-review-140.md` / `agy-review-141.md`: host-inbound bracket/list token collapse and strict token validation.
- `codex-review-132.md`: mixed-zone/family addressless observability and policy diagnostic selector issues.
- `codex-review-152.md`: Rust policy snapshot parser, ICMP application semantics, and duplicate rule/policy ID integrity.
- `_Log.md`: #3703/#3704 fixes for bracket lists and stable zone IDs, plus recent README/doc drift entries.

The findings below intentionally avoid those themes. New material is concentrated on destination-address-only host-inbound scoping, physical-interface override expansion, and lenient/helper-boundary zone-ID collision behavior.

## 3. Explicit Module Checklist

| Module / feature | Inspected | Result |
|---|---:|---|
| `pkg/dataplane/userspace/zones.go` host-inbound view builder | yes | Duplicate-address and physical-override issues found |
| `pkg/daemon/daemon_nft.go` nft host-inbound renderer | yes | Destination-address-only rule collision found |
| `pkg/config/compiler_validate_strict.go` zone/host-inbound validators | yes | No duplicate local-address guard; per-interface token guard exists |
| `pkg/config/zoneid.go` stable zone ID gate | yes | Strict gate exists; lenient runtime shape still unsafe |
| `userspace-dp/src/policy.rs` zone snapshot helper | yes | Duplicate zone IDs accepted at helper boundary |
| `userspace-dp/src/afxdp/forwarding_build/zones.rs` zone population | yes | id-keyed maps overwrite on duplicate IDs |
| `userspace-dp/src/afxdp/forwarding_build/interfaces.rs` interface zone map | yes | Parent/child ambiguity noted; existing logical-ingress tests cover main fast path |
| `pkg/config/host_inbound_view.go` presentation helpers | yes | Physical override expansion not represented |
| REST/gRPC zone inventory (`pkg/api/security.go`, `pkg/grpcapi/server_show_zones.go`) | yes | Raw override fields do not show effective expanded runtime view |
| CLI/gRPC interface diagnostics | yes | Exact-ref lookup misses inherited physical override |
| Existing host-inbound tests | yes | Same-zone exact override is covered; physical+unit, duplicate-address, and lenient collision cases are missing |

## 4. Verification Performed

Temporary tests were added, run, and removed. They asserted current bad behavior, so passing proves the behavior exists today:

```text
go test ./pkg/dataplane/userspace ./pkg/daemon -run TestCodexAudit -count=1
ok github.com/psaab/xpf/pkg/dataplane/userspace
ok github.com/psaab/xpf/pkg/daemon

go test ./pkg/dataplane/userspace -run TestCodexAuditLenientCollisionWouldPublishBothWireZones -count=1
ok github.com/psaab/xpf/pkg/dataplane/userspace

go test ./pkg/config -run TestCodexAuditDuplicateLocalAddressAcrossZonesCommits -count=1
ok github.com/psaab/xpf/pkg/config
```

Final checkout was restored clean after removing the temporary tests.

## 5. Module-by-Module Inspection Log

- Host-inbound view builder: found that views group only by zone and token signature, and addresses are later rendered without ingress-interface or VRF predicates.
- nft host-inbound renderer: found that every per-zone permit/drop rule is `ip/ip6 daddr ...` only, so duplicated local addresses across zones are order-dependent.
- Strict config validation: found hard gates for zone-interface ownership and host-inbound tokens, but no global duplicate local-address guard across interface unit addresses or VRRP VIPs.
- Stable zone ID: strict commit rejects known FNV-fold collisions, but lenient load warns and still lets downstream builders publish both names with the same ID.
- Rust forwarding build: `zone_name_to_id_from_snapshot` and `populate_zones` accept duplicate IDs and let id-keyed maps overwrite.
- Presentation/API: exact-ref helpers and raw structured fields do not model physical-interface override expansion, so diagnostics can disagree with enforcement.
- Tests: current #3362 tests cover exact same-zone overrides; no red-on-revert coverage for duplicate local addresses, physical+unit specificity, duplicate zone IDs in helper snapshots, or lenient collision quarantine.

## 6. High Confidence Findings

### H01 - Duplicate local IPv4 addresses across zones make kernel host-inbound order-dependent

- Severity: HIGH
- Confidence: High
- Labels: `bug`, `security`, `host-inbound`, `zone-policy`, `vsrx-parity`
- Evidence:

```go
pkg/daemon/daemon_nft.go:469-517
func emitHostInboundZone(rules *[]string, v dpuserspace.ZoneHostInboundView, family string, addrs []string) {
    if len(addrs) == 0 {
        return
    }
    daddr := family + " daddr " + nftAddrSet(addrs)
...
    for _, m := range rulesSet {
        *rules = append(*rules, "    "+daddr+" "+m.match+" "+m.action)
    }
...
    *rules = append(*rules, "    "+daddr+" counter name \""+cn+"\" drop")
}
```

`BuildZoneHostInboundViews` accumulates addresses by zone, then the daemon sorts views by zone/token signature:

```go
pkg/dataplane/userspace/zones.go:283-303
// Emit groups deterministically: the signature begins with the zone name,
// so sorting by signature orders views by zone then by token set.
sigs := make([]string, 0, len(groups))
for sig := range groups {
    sigs = append(sigs, sig)
}
sort.Strings(sigs)
...
out = append(out, ZoneHostInboundView{
    Zone:           g.zone,
```

Temporary probes proved both pieces: strict config accepts two interfaces in different zones with `192.0.2.1/24`, and the nft payload emits the earlier-sorting zone's `ip daddr 192.0.2.1 ... drop` before the later zone's `tcp dport 22 accept`.

- Runtime trace:
  1. Operator configures `ge-0/0/1.0` in zone `aaa` with no host-inbound stanza and `ge-0/0/0.0` in zone `zzz` with `system-services ssh`.
  2. Both units carry `192.0.2.1/24`. Strict compile accepts this today.
  3. `BuildZoneHostInboundViews` emits two views with the same `V4Addrs=["192.0.2.1"]`.
  4. The nft renderer emits rules sorted by zone name, not by ingress interface.
  5. The `aaa` catch-all drop matches any packet to `192.0.2.1` before `zzz`'s SSH accept.
  6. SSH that should be allowed for `zzz` is denied, or the inverse can happen if the allowing zone sorts first.
- Why it matters: Host-inbound is a security boundary. A config accepted by the strict compiler can enforce the wrong zone's management-plane policy.
- Suggested fix: Strictly reject duplicate firewall-local addresses and duplicate VRRP VIPs across non-lifeline security-zone scopes, or render nft rules with an ingress-interface predicate that disambiguates the zone.

### H02 - Lenient StableZoneID collisions still publish both colliding zones to the userspace wire

- Severity: HIGH
- Confidence: High
- Labels: `bug`, `security`, `zone-id`, `ha-sync`, `userspace-dataplane`
- Evidence:

```go
pkg/config/zoneid.go:162-170
msg := fmt.Sprintf(
    "zone id collision between %q and %q (both fold to %d) - rename one zone (#3075)",
    owner, name, id)
if !lenient {
    return nil, fmt.Errorf("security zones: %s", msg)
}
warnings = append(warnings, msg+
    "; the later-sorting zone is NOT installed in the dataplane")
```

But the live wire builder unconditionally emits every configured zone with `StableZoneID(name)`:

```go
pkg/dataplane/userspace/zones.go:508-533
for _, name := range names {
    zs := ZoneSnapshot{
        Name: name,
...
        ID: config.StableZoneID(name),
    }
```

Temporary probe with the existing collision pair `z174`/`z214` proved `buildZoneSnapshots` publishes both snapshots with the same ID.

- Runtime trace:
  1. Upgraded node lenient-loads or peer-syncs an older persisted config with zones `z174` and `z214`.
  2. `CompileConfigLenient` warns but returns a config.
  3. `buildZoneSnapshots` emits both zones, both with the same numeric ID.
  4. Rust receives two configured zones in the same key space instead of one quarantined/inert zone.
- Why it matters: The warning says the later-sorting zone is not installed, but the dataplane wire contradicts it. Policies, host-inbound sets, session display, and HA ownership can merge two security zones.
- Suggested fix: On lenient load, quarantine the later-sorting colliding zone before building runtime snapshots and compile results, or fail closed at the userspace snapshot preflight.

### H03 - Rust helper boundary accepts duplicate zone IDs and overwrites id-keyed zone state

- Severity: HIGH
- Confidence: High
- Labels: `bug`, `security`, `snapshot-integrity`, `zone-id`, `userspace-dataplane`
- Evidence:

```rust
userspace-dp/src/policy.rs:646-660
pub(crate) fn zone_name_to_id_from_snapshot(zones: &[ZoneSnapshot]) -> FxHashMap<String, u16> {
    let mut map = FxHashMap::default();
    for zone in zones {
        if zone.id == 0 || zone.name.is_empty() {
            continue;
        }
...
        map.insert(zone.name.clone(), zone.id);
    }
```

```rust
userspace-dp/src/afxdp/forwarding_build/zones.rs:21-61
state.zone_name_to_id = crate::policy::zone_name_to_id_from_snapshot(&snapshot.zones);
for zone in &snapshot.zones {
...
    state.zone_id_to_name.insert(zone.id, zone.name.clone());
...
    if zone.host_inbound_configured {
        state
            .zone_host_inbound
            .insert(zone.id, zone_host_inbound_from_snapshot(zone));
    }
```

- Runtime trace:
  1. Snapshot has zones `trust{id=7}` and `guest{id=7}`.
  2. `zone_name_to_id_from_snapshot` maps both names to `7`.
  3. `populate_zones` overwrites `zone_id_to_name[7]` and `zone_host_inbound[7]` with the later zone.
  4. Interfaces and policies for both names resolve to the same numeric zone.
  5. One zone's host-inbound set, TCP-RST bit, counters, and display name can stand in for both.
- Why it matters: The Rust boundary is the last defense against mixed-version or lenient control-plane snapshots. Duplicate IDs are a direct zone isolation failure.
- Suggested fix: Add a snapshot-integrity error for duplicate nonzero, non-reserved zone IDs before any map population. Include both zone names in the error.

### H04 - A physical host-inbound override shadows a more specific unit override

- Severity: HIGH
- Confidence: High
- Labels: `bug`, `host-inbound`, `configuration`, `vsrx-parity`
- Evidence:

```go
pkg/dataplane/userspace/zones.go:451-474
refs := make([]string, 0, len(zone.InterfaceHostInbound))
for ref := range zone.InterfaceHostInbound {
    refs = append(refs, ref)
}
sort.Strings(refs)
for _, ref := range refs {
...
    if _, ok := out[ref]; !ok {
        out[ref] = hib
    }
...
    if ifCfg := cfg.Interfaces.Interfaces[ref]; ifCfg != nil {
        for unitNum := range ifCfg.Units {
            un := fmt.Sprintf("%s.%d", ref, unitNum)
            if _, ok := out[un]; !ok {
                out[un] = hib
```

- Runtime trace:
  1. Same zone defines `interfaces reth0 host-inbound-traffic system-services ssh`.
  2. It also defines `interfaces reth0.10 host-inbound-traffic system-services https`.
  3. Sorted refs visit `reth0` before `reth0.10`.
  4. The physical ref expands and fills `out["reth0.10"] = ssh`.
  5. The later exact unit override sees the key already exists and is ignored.
  6. The more specific unit's intended `https` posture is not enforced.
- Why it matters: Exact interface-unit config is usually more specific than physical-interface config. First-writer wins makes the less-specific physical ref silently win.
- Suggested fix: Resolve override specificity explicitly: exact unit > physical inherited > zone. If Junos semantics are additive, union physical and unit overrides instead of dropping one.

### H05 - Logical-unit diagnostics miss inherited physical host-inbound overrides that runtime enforces

- Severity: MEDIUM
- Confidence: High
- Labels: `bug`, `observability`, `host-inbound`, `cli`, `api`
- Evidence:

Runtime expands physical refs to units:

```go
pkg/dataplane/userspace/zones.go:467-473
if ifCfg := cfg.Interfaces.Interfaces[ref]; ifCfg != nil {
    for unitNum := range ifCfg.Units {
        un := fmt.Sprintf("%s.%d", ref, unitNum)
        if _, ok := out[un]; !ok {
            out[un] = hib
        }
```

Presentation looks up only the exact ref:

```go
pkg/config/host_inbound_view.go:71-85
func (z *ZoneConfig) InterfaceHostInboundEffective(ref string) (svc, proto []string, overridden bool) {
...
    if z != nil {
        ov = z.InterfaceHostInbound[ref]
    }
    if ov == nil {
        return UnionHostInboundTokens(zoneSvc, nil), UnionHostInboundTokens(zoneProto, nil), false
    }
```

CLI `show interfaces` calls that exact-ref helper for each logical unit:

```go
pkg/cli/cli_show_interfaces.go:303-310
// Host-inbound traffic services ... show the EFFECTIVE
// admitted set for THIS logical interface ...
if li.zone != nil {
    svc, proto, overridden := li.zone.InterfaceHostInboundEffective(li.ifaceRef)
```

- Runtime trace:
  1. Operator configures `interfaces reth0 host-inbound-traffic system-services ssh`.
  2. Runtime expands it to `reth0.10` and admits SSH on that unit.
  3. `show interfaces reth0.10` calls `InterfaceHostInboundEffective("reth0.10")`.
  4. The exact map lookup misses the physical `reth0` entry.
  5. Output says no interface override / default-deny posture while the dataplane admits SSH.
- Why it matters: This is exactly the diagnostic used to prove why management traffic is admitted or denied. It can give the operator the opposite answer.
- Suggested fix: Share the same physical-to-unit expansion resolver between runtime and presentation, and expose whether an override was exact or inherited.

## 7. Medium Confidence Findings

### M01 - Lenient zone-interface ownership warnings can combine with physical host-inbound expansion to leak overrides across zones

- Severity: MEDIUM
- Confidence: Medium
- Labels: `bug`, `host-inbound`, `lenient-load`, `security`
- Evidence:

The strict validator documents that lenient load downgrades multi-zone interface ownership:

```go
pkg/config/compiler_validate_strict.go:3430-3438
// Strict on the commit / commit-check path (CompileConfig - hard-reject);
// downgraded to a cfg.Warnings entry on the tolerant load / peer-sync paths
// (CompileConfigLenient / CompileConfigForNodeLenient, flag
// lenientZoneInterfaceMembership) so an already-persisted or peer-synced config
// that an older binary accepted still BOOTS...
```

The runtime override map expands a physical ref to every configured unit:

```go
pkg/dataplane/userspace/zones.go:467-474
if ifCfg := cfg.Interfaces.Interfaces[ref]; ifCfg != nil {
    for unitNum := range ifCfg.Units {
        un := fmt.Sprintf("%s.%d", ref, unitNum)
        if _, ok := out[un]; !ok {
            out[un] = hib
        }
    }
}
```

Temporary probe with `trust` owning physical `reth0` override and `guest` owning `reth0.20` showed `guest` inherited `ssh`.

- Runtime trace:
  1. Older or peer-synced config leaves a physical `reth0` override in one zone and a unit `reth0.20` in another.
  2. Lenient compile warns instead of rejecting.
  3. `buildInterfaceHostInboundMap` expands the physical override to `reth0.20`.
  4. `BuildZoneHostInboundViews` uses `overrideByIface["reth0.20"]` for the guest zone.
  5. Guest zone admits a service configured under trust.
- Why it matters: Lenient load is supposed to preserve bootability without silently changing security posture. Here it can leak management-plane admission across zones.
- Suggested fix: On lenient duplicate ownership, do not expand physical overrides onto units owned by a different resolved zone; quarantine or exact-scope only.

### M02 - Duplicate IPv6 local addresses have the same host-inbound collision class as IPv4

- Severity: MEDIUM
- Confidence: Medium
- Labels: `bug`, `security`, `host-inbound`, `ipv6`, `vsrx-parity`
- Evidence:

The same nft renderer handles `ip6` with only `daddr`:

```go
pkg/daemon/daemon_nft.go:448-450
for _, v := range views {
    emitHostInboundZone(&rules, v, "ip", v.V4Addrs)
    emitHostInboundZone(&rules, v, "ip6", v.V6Addrs)
}
```

Addresses are split by string containing `:`:

```go
pkg/dataplane/userspace/zones.go:143-152
addAddr := func(g *group, host string) {
    if strings.Contains(host, ":") {
        if !g.seen6[host] {
            g.seen6[host] = true
            g.v6 = append(g.v6, host)
```

- Runtime trace:
  1. Two zone interfaces carry the same IPv6 host address.
  2. Both produce views containing the same `V6Addrs` value.
  3. nft emits two `ip6 daddr <addr>` rule blocks in zone-sort order.
  4. The first block decides traffic for both zones.
- Why it matters: IPv6 management and routing protocols are first-class in vSRX. The IPv4 collision bug is not family-specific.
- Suggested fix: Same as H01, but cover both families and add explicit IPv6 tests.

### M03 - Duplicate VRRP VIPs across zones can collide in host-inbound scoping

- Severity: MEDIUM
- Confidence: Medium
- Labels: `bug`, `security`, `vrrp`, `host-inbound`, `vsrx-parity`
- Evidence:

VRRP VIPs are added into the same per-zone address groups:

```go
pkg/dataplane/userspace/zones.go:263-277
svc, proto := unionHostInboundTokens(zone.HostInboundTraffic, overrideByIface[unitName])
...
for _, vip := range vg.VirtualAddresses {
    if host := hostIPFromCIDR(vip); host != "" {
        addAddr(getGroup(zoneName, svc, proto, unitName), host)
    }
}
```

The validator only checks that a VIP is in a subnet on the same unit:

```go
pkg/config/compiler_validate_strict.go:5923-5933
// validateVRRPVirtualAddressSubnet (#3013) rejects a VRRP virtual-address that
// does not fall within any subnet configured on the same interface unit for the
// matching address family.
```

- Runtime trace:
  1. Two zones configure the same VRRP virtual address on different units.
  2. Subnet validation passes if each VIP is on-link for its own unit.
  3. `BuildZoneHostInboundViews` adds the same VIP to two zone views.
  4. nft emits destination-only rules and the earlier-sorting zone wins.
- Why it matters: VRRP VIPs are exactly the management and service addresses operators may target during HA failover. Wrong zone scoping here can open or close the active VIP.
- Suggested fix: Reject duplicate VRRP VIPs across security-zone scopes, or include ingress-interface/VRF predicates in host-inbound rules.

### M04 - Host-inbound nft scoping is not VRF/routing-instance aware

- Severity: MEDIUM
- Confidence: Medium
- Labels: `bug`, `security`, `host-inbound`, `routing-instance`, `vsrx-parity`
- Evidence:

The nft chain is a single `inet xpf_hostinbound` input chain:

```go
pkg/daemon/daemon_nft.go:403-419
rules = append(rules, "add table inet xpf_hostinbound")
rules = append(rules, "delete table inet xpf_hostinbound")
rules = append(rules, "table inet xpf_hostinbound {")
...
rules = append(rules, fmt.Sprintf("    type filter hook input priority %d; policy accept;", nftHostInboundPriority))
```

Per-zone rules are destination-address only (`emitHostInboundZone`, H01).

- Runtime trace:
  1. Two routing instances use the same local address on different interfaces.
  2. Kernel input sees a single host-inbound chain, not a per-VRF chain.
  3. The first `daddr` rule for that address wins regardless of routing-instance context.
- Why it matters: vSRX deployments commonly reuse addressing in separate routing instances. Host-inbound policy should follow the ingress zone/context, not a global address singleton.
- Suggested fix: Include `iifname`/ifindex or VRF device predicates in emitted rules, and validate duplicate addresses only within the same scoping domain if deliberate reuse is supported.

### M05 - Per-interface host-inbound deny counters collapse multiple enforcement views into one zone/family counter

- Severity: MEDIUM
- Confidence: Medium
- Labels: `observability`, `host-inbound`, `metrics`
- Evidence:

The counter name intentionally keys only on zone and family:

```go
pkg/daemon/daemon_nft.go:374-383
// The counter name is keyed only on (zone, family) - and so is the DROP rule
// that references it (emitHostInboundZone). With per-interface host-inbound
// overrides (#3362) a single zone can yield MULTIPLE views sharing the same
// v.Zone...
// intended aggregation (one per-zone/family kernel-deny counter...)
```

- Runtime trace:
  1. A zone has one interface with SSH opened and another default-deny.
  2. Both views emit drops referencing the same counter.
  3. Metrics show only `zone=<z>,family=ip`.
  4. Operator cannot tell which local address/interface caused the deny spike.
- Why it matters: Per-interface host-inbound was added to isolate management exposure. Aggregated counters hide the boundary that feature introduced.
- Suggested fix: Add optional per-zone/per-family/per-interface or per-local-address counters while keeping the aggregate for compatibility.

### M06 - Token-order signatures can duplicate identical effective host-inbound views

- Severity: MEDIUM
- Confidence: Medium
- Labels: `performance`, `host-inbound`, `nftables`
- Evidence:

Group signature preserves token order:

```go
pkg/dataplane/userspace/zones.go:127-136
getGroup := func(zone string, svc, proto []string, iface string) *group {
    sig := zone + "\x00" + strings.Join(svc, ",") + "\x00" + strings.Join(proto, ",")
    g := groups[sig]
```

Union preserves source order:

```go
pkg/dataplane/userspace/zones.go:399-404
// unionHostInboundTokens returns the EFFECTIVE host-inbound ... lower-cased,
// trimmed, and de-duplicated, with zone-level tokens kept first in their original
// order and override-only tokens appended.
```

- Runtime trace:
  1. Interface A effective set is `[ssh ping]`.
  2. Interface B effective set is `[ping ssh]`.
  3. Sets are semantically identical, but signatures differ.
  4. Builder emits two nft views/rule blocks instead of one.
- Why it matters: This is not a correctness bug by itself, but it inflates nft rules and counters on large trunk configs.
- Suggested fix: Use canonical sorted token sets for grouping while preserving operator order only in display surfaces.

### M07 - REST and gRPC expose raw interface overrides but not expanded/effective runtime overrides

- Severity: MEDIUM
- Confidence: Medium
- Labels: `api`, `grpc`, `host-inbound`, `observability`
- Evidence:

REST:

```go
pkg/api/security.go:71-78
for _, ref := range zone.SortedInterfaceHostInboundRefs() {
    hib := zone.InterfaceHostInbound[ref]
    zi.InterfaceHostInbound = append(zi.InterfaceHostInbound, ZoneInterfaceHostInbound{
        Interface:      ref,
        Configured:     true,
        SystemServices: append([]string{}, hib.SystemServices...),
```

gRPC:

```go
pkg/grpcapi/server_show_zones.go:69-76
for _, ref := range zone.SortedInterfaceHostInboundRefs() {
    hib := zone.InterfaceHostInbound[ref]
    zi.InterfaceHostInbound = append(zi.InterfaceHostInbound, &pb.InterfaceHostInbound{
        Interface:      ref,
        Configured:     true,
        SystemServices: append([]string{}, hib.SystemServices...),
```

- Runtime trace:
  1. Physical override `reth0` expands to runtime units `reth0.10` and `reth0.20`.
  2. REST/gRPC list only one raw ref `reth0`.
  3. Clients cannot know which logical units inherit the override or whether a unit-specific override was shadowed.
- Why it matters: Automation auditing firewall-local exposure needs the effective runtime view, not only raw authored config.
- Suggested fix: Add an `effective_interface_host_inbound` inventory with interface/unit, exact/inherited source, effective tokens, and local addresses.

### M08 - Zone-ID reverse maps can misattribute lenient collision events and session display

- Severity: MEDIUM
- Confidence: Medium
- Labels: `observability`, `zone-id`, `syslog`, `ha-sync`
- Evidence:

CLI syslog reverse map overwrites by stable ID:

```go
pkg/cli/apply.go:31-35
func syslogZoneNameMap(cfg *config.Config) map[uint16]string {
    znMap := make(map[uint16]string, len(cfg.Security.Zones))
    for name := range cfg.Security.Zones {
        znMap[config.StableZoneID(name)] = name
    }
```

Userspace manager reverse lookup returns the first map iteration match:

```go
pkg/dataplane/userspace/manager_ha.go:1157-1166
func (m *Manager) zoneNameByID(zoneID uint16) string {
...
    for name, id := range cr.ZoneIDs {
        if id == zoneID {
            return name
        }
    }
```

- Runtime trace:
  1. Lenient config contains two colliding zone names.
  2. Both reverse-map paths use a map keyed by numeric ID.
  3. One name overwrites or nondeterministically wins.
  4. RT_FLOW/syslog/session-sync diagnostics can name the wrong zone.
- Why it matters: During incident response, wrong zone names in logs can send an operator to the wrong policy.
- Suggested fix: Carry collision/quarantine state into ApplyResult and refuse to build reverse maps with duplicate IDs.

### M09 - Strict config lacks a duplicate firewall-local address validator

- Severity: MEDIUM
- Confidence: Medium
- Labels: `validation`, `host-inbound`, `security`, `vsrx-parity`
- Evidence:

Search found duplicate checks for DHCP static bindings and VRRP subnet containment, but no strict duplicate local-interface-address gate. Temporary `pkg/config` probe proved `CompileConfig` accepts two different zone units with the same `192.0.2.1/24`.

Relevant existing validator only covers zone-interface ownership:

```go
pkg/config/compiler_validate_strict.go:3439-3475
func validateZoneInterfaceMembershipStrict(cfg *Config) error {
...
    for _, iface := range zone.Interfaces {
...
        for _, key := range zoneIfaceLogicalKeys(cfg, iface) {
            prev, exists := owner[key]
            if exists {
                if prev.zone != zoneName {
                    return fmt.Errorf(
```

- Runtime trace:
  1. Config assigns unique interfaces to unique zones.
  2. Both units carry the same local IP.
  3. Zone-interface membership validation passes because ownership is unique.
  4. Host-inbound nft scoping later collides by destination address.
- Why it matters: This is the compile-time place to catch H01 before it becomes live firewall behavior.
- Suggested fix: Add strict duplicate local address/VIP validation by host IP and security-zone scope, with a lenient warning path that forces safe host-inbound quarantine.

### M10 - Current #3362 tests miss physical override specificity and duplicate-address collisions

- Severity: MEDIUM
- Confidence: Medium
- Labels: `tests`, `host-inbound`, `nftables`
- Evidence:

Existing userspace tests cover exact same-zone override only:

```go
pkg/dataplane/userspace/host_inbound_per_iface_3362_test.go:24-31
cfg.Security.Zones = map[string]*config.ZoneConfig{
    "wan": {
        Name:       "wan",
        Interfaces: []string{"reth0.50", "reth1.0"},
        InterfaceHostInbound: map[string]*config.HostInboundTraffic{
            "reth0.50": {SystemServices: []string{"ssh"}},
        },
```

Existing daemon nft test mirrors that exact case:

```go
pkg/daemon/host_inbound_per_iface_3362_test.go:31-38
cfg.Security.Zones = map[string]*config.ZoneConfig{
    "corp": {
        Name:       "corp",
        Interfaces: []string{"reth0.50", "reth1.0"},
        InterfaceHostInbound: map[string]*config.HostInboundTraffic{
            "reth0.50": {SystemServices: []string{"ssh"}},
```

- Runtime trace:
  1. Tests prove exact unit override works.
  2. They never combine physical `reth0` with unit `reth0.50`.
  3. They never duplicate a local address across zones.
  4. H01/H04 survive.
- Why it matters: The missing matrix covers common trunk/vSRX-style interface authoring.
- Suggested fix: Add red-on-revert tests for physical-only, physical+unit, duplicate-address across zones, duplicate VRRP VIP, and lenient collision cases.

## 8. Low Confidence Findings

### L01 - Host-inbound logic is spread across too many packages for a security boundary

- Severity: LOW
- Confidence: Low
- Labels: `refactor`, `modularity`, `host-inbound`
- Evidence: Runtime grouping is in `pkg/dataplane/userspace/zones.go`, nft rendering in `pkg/daemon/daemon_nft.go`, token validation in `pkg/config/compiler_validate_strict.go`, presentation in `pkg/config/host_inbound_view.go`, REST/gRPC mapping in `pkg/api`/`pkg/grpcapi`, and Rust classification in `userspace-dp/src/afxdp/forwarding/host_inbound.rs`.
- Runtime trace: A new host-inbound invariant must be kept manually consistent across Go compiler, Go nft mirror, Rust AF_XDP classifier, CLI/API display, metrics, and tests.
- Why it matters: H01-H05 are cross-module invariant failures. More flat files will keep producing drift.
- Suggested fix: Create `pkg/security/hostinbound/` for the effective model and `userspace-dp/src/host_inbound/` for Rust mirrors; generate token tables and parity tests from one source.

### L02 - Go/Rust host-inbound token semantics are still manually mirrored

- Severity: LOW
- Confidence: Low
- Labels: `refactor`, `codegen`, `host-inbound`
- Evidence:

```go
pkg/daemon/daemon_nft.go:628-705
func hostInboundServiceMatches(token, family string) []string {
...
```

```rust
userspace-dp/src/afxdp/forwarding/host_inbound.rs:503-518
pub(in crate::afxdp) fn host_inbound_admits_iface(
...
```

- Runtime trace: Adding a token requires updating Go validation, Go nft emission, Rust classification, docs, and tests. A missed surface creates split-brain host-inbound behavior.
- Why it matters: Host-inbound controls management-plane exposure; drift here is a security bug class.
- Suggested fix: Generate both match tables from `pkg/config/host_inbound_tokens.go` or a shared YAML/JSON SSOT.

### L03 - No property test compares nft and Rust host-inbound decisions across generated configs

- Severity: LOW
- Confidence: Low
- Labels: `tests`, `host-inbound`, `fuzzing`
- Evidence: Existing tests are strong examples, but they are hand-picked exact cases. No found test generates random zones/interfaces/tokens and asserts nft rules and Rust `ZoneHostInbound` classify equivalently for the same packet tuple.
- Runtime trace: A token/family/override case can be correct in one path and wrong in the other while fixed fixtures stay green.
- Why it matters: The kernel nft path is primary for host-bound traffic, but AF_XDP local-delivery also enforces host-inbound in specific paths. Split-brain bugs are hard to debug.
- Suggested fix: Add a property/golden harness that builds a config, extracts nft decisions for sampled tuples, builds Rust forwarding state, and compares admits/drops.

### L04 - No Rust regression test rejects duplicate zone IDs in `ZoneSnapshot`

- Severity: LOW
- Confidence: Low
- Labels: `tests`, `snapshot-integrity`, `zone-id`
- Evidence: Existing tests cover reserved IDs and IDs above 255:

```rust
userspace-dp/src/afxdp/forwarding_build/tests.rs:1673-1702
/// #3075 fail-on-revert: a stable name-hash zone id > 255 ...
#[test]
fn build_forwarding_state_admits_zone_id_above_255() {
...
/// #919/#922: any zone with id >= ZONE_ID_RESERVED_MIN must be
/// dropped at config-build time...
#[test]
fn build_forwarding_state_rejects_reserved_zone_ids() {
```

No adjacent duplicate-ID rejection test exists.
- Runtime trace: A helper-boundary duplicate ID can be accepted even though reserved IDs are filtered.
- Why it matters: Duplicate IDs merge zones; this should be pinned in the Rust boundary suite.
- Suggested fix: Add `build_forwarding_state_rejects_duplicate_zone_ids` and wire it to a `SnapshotIntegrityError`.

### L05 - No effective per-local-address host-inbound inventory exists

- Severity: LOW
- Confidence: Low
- Labels: `observability`, `host-inbound`, `api`, `vsrx-parity`
- Evidence: REST/gRPC zone inventory lists configured zones, interfaces, raw host-inbound fields, and lifeline interfaces, but not the exact `(zone, interface, local-address, effective-service-set)` views that `BuildZoneHostInboundViews` emits.
- Runtime trace: Operator asks "why is SSH allowed to 192.0.2.1?" Structured APIs cannot answer which view generated the nft accept/drop rule.
- Why it matters: vSRX-style firewall operations need explainable allow/deny behavior for management-plane traffic.
- Suggested fix: Add `/api/v1/security/host-inbound/effective` and gRPC equivalent backed by `BuildZoneHostInboundViews`.

### L06 - Duplicate-address host-inbound parity should be tracked with `vsrx-parity`

- Severity: LOW
- Confidence: Low
- Labels: `process`, `vsrx-parity`, `host-inbound`
- Evidence: The bug class concerns vSRX/Junos host-inbound scoping by interface/zone, not only xpf implementation hygiene.
- Runtime trace: Without a feature-parity label, the issue can be triaged as a local nft quirk and miss the operator-visible vSRX contract.
- Why it matters: The user specifically wants vSRX-class firewall behavior.
- Suggested fix: Label duplicate local-address/VRF host-inbound issues with `vsrx-parity`.

### L07 - No HA smoke scenario covers duplicate-address or duplicate-VIP host-inbound on failover

- Severity: LOW
- Confidence: Low
- Labels: `tests`, `ha`, `host-inbound`, `vrrp`
- Evidence: Recent host-inbound tests are unit/nft-payload tests. No inspected smoke evidence exercises duplicate VIP/local-address scoping across an RG failover.
- Runtime trace: A VIP changes owner, but the nft rules remain destination-address-only. If two zones share a VIP, the wrong zone can continue deciding host-bound packets after failover.
- Why it matters: VRRP VIPs are central to HA appliance behavior.
- Suggested fix: Add an isolated HA smoke cell for management-plane SSH/ping to VRRP VIPs with same-address rejection expected at commit.

### L08 - Physical override inheritance semantics are undocumented

- Severity: LOW
- Confidence: Low
- Labels: `docs`, `host-inbound`, `configuration`
- Evidence: Code comments say physical refs expand to units, but user-facing config docs do not clearly state specificity order when both physical and unit host-inbound stanzas exist.
- Runtime trace: Operator writes both `reth0` and `reth0.10` stanzas expecting unit-specific behavior. Current builder silently picks first writer.
- Why it matters: This is security policy. Ambiguous inheritance should not be left to source-code comments.
- Suggested fix: Document and validate a single precedence rule: exact unit wins, union, or reject ambiguous physical+unit overrides.

### L09 - Lenient zone-ID collision lacks a runtime status/metric

- Severity: LOW
- Confidence: Low
- Labels: `observability`, `zone-id`, `metrics`
- Evidence: `CompileConfigLenient` stores warnings, but no inspected runtime status counter/metric advertises that a colliding zone-ID config is active.
- Runtime trace: Node boots with a lenient warning during load; later operators only see merged/misattributed zone IDs.
- Why it matters: Security-zone identity collision is severe enough to page an operator until remediated.
- Suggested fix: Publish `xpf_config_lenient_zone_id_collisions` or equivalent daemon status with zone names and ID.

### L10 - Host-inbound nft rule count can grow unnecessarily on large trunk configs

- Severity: LOW
- Confidence: Low
- Labels: `performance`, `nftables`, `host-inbound`
- Evidence: M06 shows semantically identical token sets with different order produce separate views. Each view becomes another nft rule block.
- Runtime trace: A 500-unit trunk with mostly identical services but different authored order can inflate nft payload size and apply time.
- Why it matters: Config commit latency and nft replace time are operationally important on routers with many VLAN units.
- Suggested fix: Canonicalize grouping and add a benchmark for `BuildZoneHostInboundViews` plus `buildHostInboundFilterPayload`.

### L11 - `BuildZoneHostInboundViews` should return structured conflict diagnostics, not only views

- Severity: LOW
- Confidence: Low
- Labels: `refactor`, `host-inbound`, `operator-ux`
- Evidence: The builder already sees duplicate addresses, duplicate VIPs, and physical/unit override collisions, but returns only `[]ZoneHostInboundView`.
- Runtime trace: Callers cannot distinguish "safe view" from "view built after dropping/shadowing an ambiguous scope."
- Why it matters: The same builder drives nft enforcement, metrics, and observability. It is the right place to surface conflicts.
- Suggested fix: Return `(views, diagnostics)` or expose a sibling `ValidateHostInboundViews` used by compile and daemon apply.

### L12 - No source canary enforces destination-address-only nft rules are intentional

- Severity: LOW
- Confidence: Low
- Labels: `tests`, `nftables`, `host-inbound`
- Evidence: Tests assert payload fragments, but no canary states the high-level invariant "host-inbound rules must include ingress scope whenever duplicate local addresses are allowed."
- Runtime trace: Future refactors can keep tests green while continuing to emit `ip daddr` only.
- Why it matters: The most important part of H01 is absence of `iif`/VRF predicates.
- Suggested fix: After deciding the contract, add tests that either reject duplicates or assert emitted rules include the chosen ingress-scope predicate.

### L13 - Zone-ID collision warning wording overclaims safety

- Severity: LOW
- Confidence: Low
- Labels: `docs`, `operator-ux`, `zone-id`
- Evidence: The warning says "the later-sorting zone is NOT installed in the dataplane", but H02 proved both wire snapshots are emitted.
- Runtime trace: Operator may keep running because warning text implies fail-closed quarantine, while runtime has merged zone IDs.
- Why it matters: Warnings must not overstate safety for security-zone identity.
- Suggested fix: Change the behavior first; if not, change wording to say runtime behavior is unsafe and requires immediate rename.

### L14 - Physical host-inbound override tests should cover exact-vs-inherited display parity

- Severity: LOW
- Confidence: Low
- Labels: `tests`, `cli`, `api`, `host-inbound`
- Evidence: `Test_3362_WireCarriesEffectiveOverride` pins wire behavior for exact `reth0.50`, while `host_inbound_view_3654_test.go` tests exact ref presentation. No test ties physical inherited runtime behavior to `show interfaces`/REST/gRPC presentation.
- Runtime trace: Runtime admits SSH via inherited physical override; display surfaces miss it.
- Why it matters: Observability and enforcement drift are production incidents waiting to happen.
- Suggested fix: Add a physical-ref fixture to userspace, CLI, REST, and gRPC tests.

### L15 - Duplicate local-address validation should include generated/device addresses, not only authored config

- Severity: LOW
- Confidence: Low
- Labels: `validation`, `host-inbound`, `device-map`
- Evidence: H01 used authored static addresses. The same host-inbound view builder also scopes kernel-learned addresses and VRRP VIPs.
- Runtime trace: A learned DHCP address can collide with a static address in another zone after commit, outside the strict config validator.
- Why it matters: Runtime collisions are as dangerous as committed collisions.
- Suggested fix: Add daemon apply-time diagnostics for live snapshot collisions and fail closed or quarantine the ambiguous address.

## 9. Suggested Issue Split

1. `bug(host-inbound): reject or ingress-scope duplicate firewall-local addresses across zones` - H01, M02, M04, M09, L12, L15.
2. `bug(host-inbound/vrrp): reject duplicate VRRP VIPs across security-zone scopes` - M03, L07.
3. `bug(zone-id): quarantine lenient StableZoneID collisions before runtime publication` - H02, H03, M08, L04, L09, L13.
4. `bug(host-inbound): define physical-vs-unit override precedence and fix first-writer shadowing` - H04, M01, L08, L11.
5. `bug(observability): show effective inherited host-inbound overrides in CLI/REST/gRPC` - H05, M07, L05, L14.
6. `perf(host-inbound): canonicalize effective token grouping to reduce nft payload bloat` - M06, L10.
7. `refactor(host-inbound): centralize Go/Rust host-inbound model and parity generation` - L01, L02, L03.
