# Cohorts 9-11 Deep Audit — IPsec/IKE/WireGuard + HA/Cluster/VRRP + Routing/FRR — ps-review-036

- Base commit: 33b891d11 (Merge PR #4563, master — fix/4562-navigatePath-descent)
- Output path: /tmp/ps-review-036-cohort9-11.md
- Cohorts:
  - 9 IPsec/IKE/WG: pkg/ipsec/*, pkg/config/compiler_ipsec.go, compiler_validate_strict_ipsec.go, xfrmi.go, compiler_ipsec_bindiface.go, pkg/routing/xfrm.go
  - 10 Routing/FRR: pkg/routing/*, pkg/frr/* (manager.go, config_render.go, policy_render.go)
  - 11 HA/Cluster/VRRP: pkg/cluster/*, pkg/vrrp/*, pkg/ipmon/*
  - Dataplane tunnels/WG/GRE: userspace-dp/src/afxdp/{gre.rs,tunnel.rs,forwarding_build/tunnels.rs,types/forwarding.rs,wg/*,poll_stages.rs,poll_descriptor/mod.rs}
- Date: 2026-07-07

## 1. Duplicate-suppression summary

### Sources read

| Source | Count | Coverage |
|--------|-------|----------|
| /tmp/all_findings.txt | 272 entries (F-001..F-272) | Full |
| gh issue list --state all | 200+ (30 OPEN, ~250 CLOSED verified) | Every finding checked |
| /tmp/ps-review-031.md | Prior cohort 9-11 deep audit on b1bd96fb6 | Primary dedup baseline for this cohort |
| /tmp/ps-review-033.md | Cohort 8 (filter/PBR/routing, base 8cd816e35) | Routing/FRR overlap |
| /tmp/ps-review-034.md | Cohort 5 (NAT, base 8cd816e35) | NAT overlap |
| /tmp/ps-review-035.md | All-cohort synthesis (base 8cd816e35) | Dedup + triage |
| /tmp/opus-review-171.md, /tmp/opus-review-172.md | Prior wide-coverage campaigns | Host-inbound, screen, tunnel decap |
| _Log.md | 39000+ lines | Fix verification |

### CLOSED — do NOT re-report (verified still fixed on 33b891d11 unless noted)

| Issue(s) | Topic | Verified on HEAD |
|----------|-------|-----------------|
| #4562 | navigatePath intermediate multi-key descent | CLOSED, fix in HEAD (this commit) |
| #4556 | cli/api LOW | CLOSED |
| #4541 | writeJSON | CLOSED |
| #4540 | monitor keyword | CLOSED |
| #4535 | three-color policer color-blind default | CLOSED |
| #4534 | PBR discard/reject kernel-mirror | CLOSED |
| #4526/#4525/#4524 | DHCP overflow / RA interval / monitor injection | All CLOSED |
| #4521/#4520/#4519/#4518/#4517 | NAT pool / nat64 counter / nptv6 / nat64 allocator / EH | All CLOSED |
| #4514 | single-rate policer | CLOSED |
| #4487/#4453/#4400 | LocalDelivery / fabric RST/FIN / ForwardCandidate RST/FIN | All CLOSED |
| #4399/#4438 | NAT 1:N multimap | CLOSED |
| #4393/#4388 | dnat_table / HA NAT pool | CLOSED |
| #4392 | PBR reject/filter VRF leak | CLOSED |
| #4386 | cold-boot split-brain | CLOSED (neverSeenConfirmed + 30s grace) |
| #4384/#4383/#4382/#4380 | TCP checksum / DHCPv6 IA_NA / SYN-flood seeds / forward/reverse idle | CLOSED |
| #4379/#4378/#4377/#4376 | scan/sweep cleanup / commit-confirmed rollback / session limit / VRRP tie-break | CLOSED |
| #4365/#4362/#4360 | global-policy scope / cookie_gen / BulkSync re-drive | CLOSED |
| #4348/#4343/#4342/#3882 | quoted inactive / policy-rematch scheduler / default-policy sessions / WG 3-slot | CLOSED |
| #4092/#4107/#4094/#4071/#4015 | TAI64N replay / cluster auth / wireguard / GRE keepalive / df-bit | CLOSED |
| #3994/#3941/#3952/#3937/#2933 | DPD / IPsec delete-terminate / PSK id / SA parse / XFRM if_id collision | CLOSED |
| #3876/#3855/#4482/#4481 | rib-group / RI table IDs / FRR sanitize / FRR cross-context | CLOSED |

### OPEN — do NOT re-report unless materially new trace

| Issue | Title | Status |
|-------|-------|--------|
| #4559 | deterministic NAT (CGNAT port block-size) — unenforced | OPEN, cohort 5 |
| #4555 | XDP EH: MAX_EXT_HDRS=6 vs userspace MAX_IPV6_EXT_HEADERS=8 | OPEN LOW |
| #4549 | LOW batch (VRRP hop-limit, HA IPv4-only, PSK zeroize, same-node-id) | OPEN LOW |
| #4548 | VRRP MaxAdverInt flap (no minimum clamp) | OPEN MED→LOW |
| #4547 | IPsec DNS stall (N×2s commit — now concurrent, residual) | OPEN MED→LOW |
| #4546 | WG peer_has_confirmed REJECT_AFTER_TIME | CLOSED (fixed on this HEAD — see below) |
| #4544 | host-inbound dup | OPEN |
| #4543 | screen TLV | OPEN |
| #4533 | icmp_embed EH-overflow | OPEN |
| #4515 | warn-only validation gaps | OPEN |
| #4512 | NAT64 HA-sync | OPEN |
| #2387 | bare 5-tuple cross-zone session hijack | OPEN P0 |
| #4478 | IPIP decap no zone enforcement | OPEN (M-1) |
| #4455 | HI-1 multicast/broadcast host-inbound | OPEN |
| #4323 | Stage-11 IPsec passthrough host-inbound gate (deferred Option B) | OPEN (deferred) |
| #4498 | FRR sanitize-belt residual (next-hop/origin/source-protocol bare %s) | OPEN |
| #4499/#4497 | test coverage / avo-001 F2/F3 | OPEN |
| #4484 | LOW batch (REST audit-gap, SSE cap, RST clamp, etc.) | OPEN |
| #4422/#4421/#4420 | test backlog / refactor backlog / host-inbound parity | OPEN |
| #4373/#4372 | reject/filter/PBR log / three-color status | OPEN |
| ... | (30 open total) | — |

### Intentional divergences / triaged NOT-MATERIAL (do NOT re-report)

- WG AllowedIPs overlap — DELIBERATE (standard WireGuard cryptokey routing, most-specific-wins, anti-source-spoof, doc-test documents intentional) — NOT a bug
- HA heartbeat HMAC after Unmarshal — GATED (handlePeerHeartbeat runs AFTER heartbeatAuthDecision accepts, replay gated on macOK && nonceFresh, no side effect from Unmarshal alone) — NOT exploitable, cosmetic reorder only
- F2/F6 triage in ps-031 — already handled

---

## 2. Module / verdict-path inventory (coverage checklist + cohort map)

| Cohort | Module | Files | LOC | Reviewed |
|--------|--------|-------|-----|----------|
| 9 | IPsec IKE/IPsec proposal chains | pkg/ipsec/ike.go, policy.go, crypto.go, manager.go | ~1500 | Full |
| 9 | IPsec compiler / validators | pkg/config/compiler_ipsec.go, compiler_validate_strict_ipsec.go, types_routing.go | ~700 | Full |
| 9 | IPsec XFRM if_id + bind-interface gate | pkg/config/xfrmi.go, compiler_ipsec_bindiface.go, pkg/routing/xfrm.go | ~400 | Full |
| 9 | WG engine core (3-slot, TAI64N, cookie, framing, AllowedIPs, peer_has_confirmed) | userspace-dp/src/afxdp/wg/engine.rs, peer.rs, session.rs, timers.rs, handshake.rs, handshake_session.rs, tai64n.rs, cookie.rs, framing.rs, allowed_ips.rs, mss.rs, mod.rs, scratch.rs | ~5000 | Full |
| 9 | WG tunnel snapshot (Go) | pkg/dataplane/userspace/tunnels.go, pkg/config/tunnelemit.go | ~400 | Spot-checked |
| 10 | FRR config gen | pkg/frr/manager.go, config_render.go | ~1300 | Full |
| 10 | FRR policy rendering (route-map, prefix-list, community, sanitize belt) | pkg/frr/policy_render.go | 1906 | Full |
| 10 | Routing rules / next-table / rib-group / PBR | pkg/routing/rules.go, vrf.go, routing.go, routes.go, tunnel.go | ~3000 | Full |
| 10 | Routing VRF / bond / probe_pin | pkg/routing/vrf.go, bond.go, probe_pin.go | ~800 | Spot-checked |
| 11 | HA cluster manager / election / failover / heartbeat / sync / garp / reth | pkg/cluster/*.go | ~5000 | Full |
| 11 | VRRP instance / manager / packet / track / addrwatch | pkg/vrrp/*.go | ~3000 | Full |
| 11 | HA dataplane + IPMON | userspace-dp/src/afxdp/ha.rs, pkg/ipmon/ipmon.go | ~600 | Spot-checked |
| — | GRE/IPIP tunnels + decap + zone enforcement | userspace-dp/src/afxdp/{gre.rs,tunnel.rs,forwarding_build/tunnels.rs,types/forwarding.rs,poll_stages.rs,poll_descriptor/mod.rs} | ~2000 | Full |

---

## 3. Module-by-module inspection log (including negatives)

### 3.1 IPsec — policy.go / ike.go / crypto.go / manager.go

**policy.go `resolveGatewayFamilyHints` concurrency fix (#4547) — VERIFIED FIXED on HEAD:**

```go
// pkg/ipsec/policy.go:805-841
func resolveGatewayFamilyHints(gateways map[string]*config.IPsecGateway) map[string]int {
    // ...
    sem := make(chan struct{}, resolveFamilyHintConcurrency) // cap=8
    var wg sync.WaitGroup
    for i, name := range names {
        wg.Add(1)
        sem <- struct{}{}
        go func(i int, gw *config.IPsecGateway) {
            defer wg.Done()
            defer func() { <-sem }()
            results[i] = gatewayRemoteFamilyHint(gw)
        }(i, gateways[name])
    }
    wg.Wait()
    // ...
}
```

Previously: N gateways × 2s sequential DNS = N×2s commit stall (#4547). Now: bounded pool (cap=8), wall-clock ~one 2s timeout. **Verified fix present on 33b891d11.** `gatewayRemoteFamilyHint` and `defaultResolveHostFamily` unchanged. `resolveInterfaceAddress`, `resolveConfiguredInterfaceAddress`, `selectFamilyAddress`, `bareIPGlobalOnly`, `zoneQualify` — all unchanged, correct.

**ike.go — IKE/IPsec proposal chains — VERIFIED CORRECT:**

- `resolveIKESettings` correctly distinguishes intentional no-policy (nil error, empty proposal) vs dangling chain (`errIKEChainUnresolved`) — matches strict validator.
- `vpnUsesAHProposal` skips AH VPN with Warn, commit gate `validateIPsecProposalProtocolStrict` rejects AH — correct, no silent ESP fabrication.
- `resolveESPSettings` — absent vs dangling fix (#4117) still present: absent → "default", dangling → "aes256-sha256[-modpN]" conservative fixed suite, never bare "default" downgrade.
- `deriveDPD` bare `dead-peer-detection;` enables DPD with defaults — fix #3994 verified.
- `normalizeAuthAlg` correctly maps hmac-sha-256-128 → sha256, etc. — fix #3851 verified.
- `formatDHGroup` covers ECP groups (19→ecp256, 20→ecp384, ..., 31→curve25519) + modp1024s160/2048s224/2048s256 — fix #2392/#2604 verified.
- `parseSAOutput` fictional format — fixed #3937, new parser matches real `swanctl --list-sas` layout.
- `normalizeEncAlg` GCM explicit ICV suffix (aes-256-gcm → aes256gcm16) — correct.
- `gcmPRF` derives PRF from auth alg for IKE GCM — correct.

**manager.go — IPsec SA lifecycle — VERIFIED CORRECT:**

- `Apply` / `swapConnNames` / `terminateRemovedConns` — deletes terminated VPN's live SAs via `swanctl --terminate --ike`. Fix #3941 verified still present.
- `liveConnNames` queries `swanctl --list-sas`, parses via `parseSAOutput` — correct.
- `swanctlTimeout = 15s` — bounds every shell-out, mirrors FRR reload precedent.
- `configDir` / `BPFRXConfFile` — atomic write via `fsatomic.WriteFileAtomic` 0600 — correct.

**crypto.go — Junos $9$ PSK decryption — VERIFIED:**

- `normalizePSK`, `decodeJunosSecret`, `junosGap`, `junosGapDecode` — MIT-licensed jcrypt adaptation, correct decode. No NOT-MATERIAL finding here.

### 3.2 FRR — manager.go / config_render.go / policy_render.go

**manager.go — FrrReloadPy / degraded-retry — VERIFIED CORRECT:**

- `ApplyFull` → `commitManagedSection` → `writeManagedSection` (atomic via `fsatomic.WriteFileDurable`) → `reloadLocked` (FrrReloadPy primary 15s, vtysh -f fallback 15s fresh context, degraded-retry loop) — all unchanged from 8cd816e35, correct.
- `writeManagedSection` orphaned-begin-marker handling + end-anchor after begin — fix #2908 still present.
- `degradedRetryLoop` / `retryReloadOnce` / `clearEpisodeIfMine` — single-flight degraded-retry, identity-guarded cleanup — correct.

**config_render.go — static routes / DHCP / backup-router / ECMP — VERIFIED CORRECT:**

- `generateStaticRoute` strips ".0" only, not VLAN ".50" — correct.
- `generateStaticRouteInTable` — VRF/table mutual exclusion, discard → Null0, empty next-hops → render NOTHING (not blackhole) — correct per #3872.
- `renderDHCPDefaults` — classless static routes, default suppression, interface binding — correct.
- `renderBackupRouter` — family matching, empty dst → ::/0 or 0.0.0.0/0 based on NH family — fix #2891 verified.
- `renderPreferredRoutes` — ip-monitoring overlay AD=1, VRF/forwarding-instance table routing — correct per #1827.
- `resolveECMP` — explicit multipath knob, never seeded from forwarding-table ECMP — fix #2791 verified.

**policy_render.go — protocols + policy-options — FULL DEEP TRACE:**

**Sanitize belt (sanitizeFRRValue) — VERIFIED:**

```go
// pkg/frr/policy_render.go:49-67
func sanitizeFRRValue(s string) string {
    // strips C0 (0x00-0x1F) + DEL (0x7F) → space
}
```

Applied at:
- `generateProtocols`: OSPF auth (#4097), BGP neighbor description/update-source/password, IS-IS auth, RIP auth
- `generatePolicyOptions`: prefix-list entries (#4482), community-list members (#4097), as-path regex (#4097)
- `renderRouteMapForPolicy`: match community/as-path names, set community/additive/delete, as-path prepend, set next-hop (IPv6 + IPv4), local-preference, metric, etc.

**Bare-%s residual (OPEN #4498) — CONFIRMED STILL PRESENT on 33b891d11:**

```go
// pkg/frr/policy_render.go:1686 — NOT sanitized
fmt.Fprintf(&b, " match source-protocol %s\n", proto)
// proto comes from term.FromProtocols — validated at commit to known set (direct/connected/static/ospf/ospf6/bgp/rip/ripng/isis/kernel)
// but tolerant-load path may carry a value with embedded \n that sanitizeFRRValue would neutralize

// pkg/frr/policy_render.go:1727, 1729 — NOT sanitized
fmt.Fprintf(&b, " set ipv6 next-hop global %s\n", term.NextHop) // line 1727
fmt.Fprintf(&b, " set ip next-hop %s\n", term.NextHop)          // line 1729
// term.NextHop is an IP literal from config, validated as IP — but tolerant-load may carry control chars

// pkg/frr/policy_render.go:1802 — NOT sanitized
fmt.Fprintf(&b, " set origin %s\n", term.Origin)
// term.Origin is "igp"/"egp"/"incomplete" — small enum, but same pattern
```

These are already filed as OPEN #4498 (FRR sanitize-belt residual + #4482 test completeness). **NOT re-reporting.** They are LOW severity — the commit-time validator rejects control chars / invalid values, so only the tolerant-load/peer-sync path (which only warns, #1960) could reach these with a control-char payload. The functional impact is low (FRR reload failure, not a privilege escalation), but they are genuine injection residuals.

**Route-map cross-context default-action leak (#4481) — VERIFIED FIXED on 33b891d11:**

```go
// pkg/frr/policy_render.go:1339-1350
func policyNeedsRedistAlias(name string, ps *config.PolicyStatement, bgpAcceptDefault map[string]bool) bool {
    return ps != nil && bgpAcceptDefault[name] &&
        ps.DefaultAction != "accept" && ps.DefaultAction != "reject"
}

// pkg/frr/policy_render.go:1488-1504 — generates base route-map + fail-closed alias
b.WriteString(m.renderRouteMapForPolicy(po, name, ps, policyTrailingAction(name, ps, bgpAcceptDefault)))
if policyNeedsRedistAlias(name, ps, bgpAcceptDefault) {
    b.WriteString(m.renderRouteMapForPolicy(po, redistFailClosedRouteMap(name), ps, "deny"))
}

// pkg/frr/policy_render.go:174-183 — redistribute references fail-closed alias
if policyNeedsRedistAlias(export, ps, bgpAcceptDefault) {
    rmName = redistFailClosedRouteMap(export)
}
```

Fix: a policy applied as BGP route-map in/out with no explicit default renders trailing PERMIT (Junos BGP default-accept, #2998) in its base route-map, but also emits a `-xpf-redist` alias with trailing DENY for redistribute use. `resolveRedistribute` references the fail-closed alias, not the shared permit-default map. **Fix #4481 verified present and correct on 33b891d11.**

**Sanitize belt bypass on tolerant-load (#4482) — VERIFIED FIXED:**

```go
// pkg/frr/policy_render.go:1402-1415
// prefix-list entries — sanitized via sanitizeFRRValue
// pkg/frr/policy_render.go:1455 — community-list members — sanitized
// pkg/frr/policy_render.go:1477 — as-path regex — sanitized
// pkg/frr/policy_render.go:1696-1700 — match community/as-path — sanitized
// pkg/frr/policy_render.go:1775-1799 — set community/additive/comm-list-delete/as-path-prepend — sanitized
```

Fix #4482 applied sanitizeFRRValue wrap on all 10+ identified slots. The residual bare-%s slots above (next-hop, origin, source-protocol) are precisely what #4498 tracks. **#4482 fix verified present — the fixed slots are sanitized, the residual slots are known-open #4498, not re-reported.**

**Other FRR correctness:**

- `resolveRedistribute` skips self-redistribute, normalizes direct→connected, fails closed on defined-policy-no-protocol / unknown-token — correct per #2943/#2223.
- `collectBGPRouteMapPolicies` — collects BGP route-map in/out policies for #2998 default + #4481 alias decision — correct, mirrors emit conditions.
- `policyTrailingAction` — explicit accept→permit, explicit reject→deny, BGP default→permit, else deny (fail-closed) — correct per #2998.
- `renderRouteFilterEntry` — prefix-list rendering: exact/longer/orlonger/prefix-length-range/through(upto) all handled with correct skipEntry fail-closed — correct per #2072/#2103/#2105/#2525.
- `partitionRouteFiltersByFamily` / mixed-family split — v4/v6 route-filters split into distinct sequences — correct per #2607.
- `bgpEffectiveExport` / `bgpEffectiveImport` — lastNonEmpty semantics, most-specific-wins — correct per #2473/#2490.

### 3.3 Routing — rules.go / xfrm.go / tunnel.go

**rules.go — next-table / rib-group / PBR — VERIFIED CORRECT:**

- `nextTableManager.Apply` — priority 100-199, hard-cap 100, clears old before re-adding — correct. Caller in `daemon_apply.go` passes only main-table StaticRoutes (not per-RI), so no VRF leak on live code.
- `ribGroupManager.Apply` — per-prefix `to <connected-prefix> lookup <sourceTable>` pref 30000-30999, before main (32766), correct per #3876. `ribGroupLeaksIntoMain`, `splitConnectedPrefixesByFamily` — correct.
- `pbrManager.Apply` — DSCP-0 dropped, except-set fail-closed, L4 unrepresentable (port-except, tcp-flags, icmp, is-fragment, flex) fail-closed — fixes #3430/#3730 verified. `buildPBRFromFilter` skips term with routing-instance + discard/reject — fix #4534 verified.
- `BuildPBRRules` — only from attached input filters, DSCP×src×dst×proto×sport×dport cross-product, truncates to maxPBRRules — correct.
- `resolveRibTable` / `ribInstanceFromName` — exact suffix match (".inet.0"/".inet6.0"), non-empty instance, trailing garbage rejected — correct per #2253/#2226.

**xfrm.go — XFRM interface ID collision — VERIFIED FIXED (dual-layer):**

Layer 1 (commit-time): `validateSecureTunnelBindInterfaceAST` in `pkg/config/compiler_ipsec_bindiface.go` hard-rejects `st0` + `st0.0` (same if_id=1 from different bind-interface strings) at commit. **Present and correct on 33b891d11.** Iterates EVERY `security` + `ipsec` sibling (fix #3562), groups by if_id, detects distinct-string collision, emits hard error (strict) / warning (lenient).

Layer 2 (runtime guard): `xfrmManager.Apply` in `pkg/routing/xfrm.go` detects collision via `idToName[ifID]` check, marks `collidingIDs`, drops both devices from desired, fail-closed (both tunnels down, no cross-VPN SA leak). **Present and correct on 33b891d11.** Comment explicitly says "proper long-term fix is commit-time rejection ... tracked separately" — that fix is now #2933 (F6 in ps-031 triage), which IS present.

**XFRMIfNameAndID derivation:**

```go
// pkg/config/xfrmi.go:10-39
func XFRMIfNameAndID(bindIface string) (string, uint32) {
    // "st0" → stIndex=0, unit=0, ifID=0<<16|1=1
    // "st0.0" → stIndex=0, unit=0, ifID=0<<16|1=1 — COLLISION with st0
    // "st0.1" → stIndex=0, unit=1, ifID=0<<16|2=2 — no collision
    ifID := uint32(stIndex)<<16 | uint32(unit+1)
    return LinuxIfName(bindIface), ifID
}
```

`st0` (unit defaults to 0, +1 → 1) and `st0.0` (unit=0, +1 → 1) both yield if_id=1 — intentional for why the collision gate exists. `st0.1` (unit=1, +1 → 2) is distinct. The formula is correct and the gate catches the alias.

**tunnel.go — GRE/IPIP/WG tunnel lifecycle — VERIFIED:**

- `tunnelManager.Apply` — reconcile-in-place (no clear-all + recreate), ownedNames / wgConfigured / appliedAddrs / appliedRI tracking — correct per #1884/#1919.
- `applyAnchorLocked` / `applyKernelTunnelLocked` — drain-before-recreate, linkGen bump, keepalive reconcile — correct per #1918/#4071.
- `buildKernelTunnelLink` — GRE/Gretun with key, IPIP/Iptun, IPIP-over-IPv6/Ip6tnl — correct.
- `legacyTunnelMatches` — config-driven attrs only (type + Type() string, endpoints, TTL, GRE keys, ip6tnl proto) — correct per #1884.
- `finishTunnelLocked` / `reconcileLinkAddrsLocked` / `reconcileVRFClaimLocked` — correct.

### 3.4 HA / Cluster / VRRP — heartbeat.go, heartbeat_manager.go, election.go, sync_auth.go, vrrp/instance.go, packet.go

**heartbeat.go — Unmarshal before auth — TRIAGED NOT-EXPLOITABLE (F4, ps-031):**

```go
// pkg/cluster/heartbeat.go:717-753
pkt, err := UnmarshalHeartbeat(buf[:n])     // line 717 — parses BEFORE auth
if err != nil { /* ... */ continue }
if int(pkt.ClusterID) != r.mgr.ClusterID() { continue }  // trusts parsed ClusterID
if int(pkt.NodeID) == r.mgr.NodeID() { continue }         // trusts parsed NodeID

key := r.mgr.controlLinkAuthKey()
session, counter, present := heartbeatAuthTrailer(buf[:n])
macOK := present && len(key) > 0 && verifyHeartbeatMAC(buf[:n], key)
nonceFresh := macOK && r.authReplay.admit(session, counter)
accept, reason := heartbeatAuthDecision(len(key) > 0, present, macOK, nonceFresh, r.peerAuthSeen.Load())
if !accept { continue }          // rejected HERE — before handlePeerHeartbeat
if macOK { r.peerAuthSeen.Store(true) }
r.received.Add(1)
r.lastSeen.Store(MonotonicNanos())
r.mgr.handlePeerHeartbeat(pkt)    // only reached AFTER auth decision accepted
```

Analysis:
- `UnmarshalHeartbeat` runs before `verifyHeartbeatMAC` / `heartbeatAuthDecision` — cosmetically wrong order.
- BUT: `handlePeerHeartbeat` (which rebuilds `peerGroups` and runs `runElection`) only runs AFTER `heartbeatAuthDecision` accepts. The ClusterID/NodeID filter checks before auth are ELIDED on a forged heartbeat that passes magic+version but fails cluster/node identity — no side effect beyond incrementing recvErrors (counter only).
- For keyed clusters past bootstrap (`peerAuthSeen=true`), unauthenticated frames rejected — window is (a) no key (legacy dual-accept `!keyConfigured → true`) or (b) early boot before peer authed (`!present && !peerAuthSeen → true`).
- For legacy no-key clusters: the entire channel is unauthenticated by design — this is not a NEW bypass, it's the documented no-key posture.
- Replay gated on `macOK && nonceFresh` — `authReplay.admit` only called when `macOK`, and `macOK` only true when `present && len(key)>0 && verifyHMAC`.

**VERDICT: NOT exploitable as a forge/replay into election.** The fix would be to verify HMAC before UnmarshalHeartbeat (or at least before trusting ClusterID/NodeID for anything beyond filtering). But the current ordering is cosmetically wrong, not a driveable bypass, because `handlePeerHeartbeat` is gated on the auth decision. **NOT filing as new — matches ps-031 triage F4 NOT-MATERIAL.**

**heartbeat_manager.go — IPv4-only — OPEN #4549:**

```go
// pkg/cluster/heartbeat_manager.go:44-45
peer, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", peerAddr, HeartbeatPort))
local, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", localAddr, HeartbeatPort))
```

Hardcoded "udp4" — IPv6 control-link unsupported. Already filed as OPEN #4549 (LOW batch: HA IPv4-only). **NOT re-reporting.** Control link is almost always IPv4 point-to-point in production (fabric VLAN), so Low.

**VRRP — MaxAdverInt flap (#4548) — CONFIRMED STILL PRESENT:**

```go
// pkg/vrrp/instance.go:1505-1506
if pkt.MaxAdvertInt > 0 {
    vi.masterAdverInterval = time.Duration(pkt.MaxAdvertInt) * 10 * time.Millisecond
}
```

No minimum clamp — attacker sends MaxAdvertInt=1 (10ms) → `masterDownInterval = 3×10ms + skew ≈ 30ms` → flapping. Already filed as OPEN #4548 (MED→LOW). Still present on 33b891d11. `MaxAdvertInt` is uint16 with 12 usable bits (&0x0FFF), range 0..4095 centiseconds. MaxAdverInt=0 already handled (falls back to local). Only value 1 triggers the fast-flap path. **NOT re-reporting — already filed #4548.**

**VRRP — hop-limit / AF_PACKET vs raw IPv6 fallback — OPEN #4549:**

- `parseAfPacketIPv6` hop-limit check `ip6[7] != 255` at line 1365 — correct per RFC 5798 §5.1.2.3.
- `receiverIPv6` raw IPv6 fallback — no hop-limit check. AF_PACKET is primary (99% of deployments), raw IPv6 fallback only when AF_PACKET unavailable. Already filed as OPEN #4549 (VRRP hop-limit). **NOT re-reporting.**

**VRRP — equal-priority tie-break — FIXED #4376:**

```go
// pkg/vrrp/instance.go:1613-1658
func (vi *vrrpInstance) resolveEqualPriorityMaster(...)
    // Anchors to ONE family (v4-bearing → v4 only, v6-only → link-local v6)
    // so both nodes compare SAME pair of addresses
    // Unresolved local source → yield to peer (don't stay MASTER)
```

Fix #4376 verified present on 33b891d11: anchors tie-break to one family, handles unresolved source, prevents dual-stack equal-priority oscillation. **FIXED, not re-reporting.**

**VRRP — accept-data / track / addrwatch — spot-checked, no new issues.**

### 3.5 WireGuard — engine.rs / peer.rs / session.rs / allowed_ips.rs

**3-slot model (fix #3882) — VERIFIED FIXED:**

- `peer.rs:339-382` `install_new_session` routes Initiator→current, Responder→next
- `engine.rs:1169-1198` `maybe_promote_next` promotes on first inbound authenticated data
- `session.rs:119-129` `confirmed` gate blocks responder egress until first inbound
- No responder rekey blackhole — **FIXED #3882, verified on 33b891d11.**

**TAI64N anti-replay (fix #4092) — VERIFIED FIXED:**

- `peer.rs:236-244` `check_and_update_tai64n` strictly greater
- `handshake_session.rs:576-581` before msg2 build
- Fix #4092 holds — **no TAI64N replay.**

**Cookie DoS mitigation — VERIFIED FIXED:**

- `engine.rs:594-655` `classify_initiation` load gate + MAC2 verify + per-source bucket + global budget
- `cookie.rs:74-138` secret rotation with previous-window carry
- Fix holds.

**peer_has_confirmed_session REJECT_AFTER_TIME (fix #4546) — VERIFIED FIXED on 33b891d11:**

```rust
// userspace-dp/src/afxdp/wg/engine.rs:743-753
pub(crate) fn peer_has_confirmed_session(&self, pubkey: &[u8; 32]) -> bool {
    let Some(peer) = self.peer_arc(pubkey) else {
        return false;
    };
    let now_ns = self.now_ns();
    matches!(
        peer.current.read().unwrap().as_ref(),
        Some(session) if session.is_confirmed()
            && now_ns.saturating_sub(session.created_ns)
                < super::session::REJECT_AFTER_TIME_NS
    )
}
```

The fix adds `now_ns.saturating_sub(session.created_ns) < REJECT_AFTER_TIME_NS` (180s) to the gate. Previously: `peer.current.read().unwrap().as_ref() → Some(session) if session.is_confirmed()` only — expired session still reports confirmed → rekey suppressed → bounded ~0-1s blackhole until GC tick. Now: expired session fails the age gate → reports not-confirmed → control thread initiates rekey. **FIXED on 33b891d11.** The doc comment (lines 726-742) explicitly credits #4546. **NOT re-reporting — already fixed.**

**AllowedIPs overlap — DELIBERATE (F2 triage, NOT a bug):**

```rust
// userspace-dp/src/afxdp/wg/allowed_ips.rs:1-30
//! AllowedIPs LPM table.
//! WireGuard's AllowedIPs is a longest-prefix-match table from
//! the cryptokey-routing flaw that PR #1492 r11 was tripped up by:
//! overlapping AllowedIPs across peers can never route plaintext to

// Test documents intentional behavior:
// "duplicate_cross_peer_prefix_only_one_peer_wins" — intentional
// "0.0.0.0/0 + specific route causes most-specific-wins" — standard WG
```

Standard WireGuard cryptokey routing: global LPM, most-specific-wins, anti-source-spoof via `matches_for_peer`. Overlap is not a bug — it's how WireGuard is specified to work. A 0.0.0.0/0 catch-all + specific /24 is valid (catch-all peer gets everything except /24, /24 peer gets /24 traffic). Duplicate identical prefix → only one peer wins is documented in tests. No commit-time validation needed — this is standard WG behavior. **NOT a bug, do not re-report per task instructions (F2 DELIBERATE).**

### 3.6 Tunnel decap — GRE zone enforcement / IPIP decap

**GRE decap zone enforcement — VERIFIED PRESENT:**

```rust
// userspace-dp/src/afxdp/gre.rs:747-783
let ingress_zone = forwarding
    .ifindex_to_zone_id
    .get(&endpoint.logical_ifindex)
    .copied()
    .unwrap_or_default();
// ...
let inner_meta = UserspaceDpMeta {
    ingress_ifindex: endpoint.logical_ifindex as u32,
    ingress_zone,
    // ...
};
```

GRE decap re-applies the tunnel logical interface's zone (`endpoint.logical_ifindex → ifindex_to_zone_id → ingress_zone`) to the inner packet. The inner packet then goes through normal zone→policy checking. **GRE decap HAS zone enforcement on 33b891d11.**

**IPIP decap (proto-4/41) — NOT a userspace decap bypass on THIS dataplane:**

IPIP tunnels are kernel `Iptun`/`Ip6tnl` devices (tunnel.go:675-691). The kernel handles IPIP decapsulation natively: received IPIP outer is decapped by the `ipip` kernel device, the inner packet is kernel-forwarded via the kernel FIB (not via xpf userspace). There is NO userspace IPIP decap path in this dataplane — only GRE has a userspace native decap (`try_native_gre_decap_from_frame`).

`#4478 OPEN` (opus-172 M-1) reports "IPIP (proto-4/41) decap has no userspace zone enforcement" — this is technically accurate in that there is no userspace IPIP decap stage (unlike GRE which HAS one), but the impact depends on whether the kernel-decapped IPIP inner re-enters xpf XDP (via the ipip device having XDP attached) or is kernel-forwarded raw. On the current architecture:

- GRE tunnels in AnchorOnly mode: kernel TUN device + userspace decap stage → zone-enforced via `endpoint.logical_ifindex`.
- GRE tunnels in legacy (non-anchor) mode: kernel Gretun device — kernel handles decap, inner re-enters? Depends on XDP attachment to gretun device.
- IPIP tunnels: kernel Iptun/Ip6tnl device — kernel handles decap, inner forwarded via kernel FIB.

The IPIP case is kernel-forwarded and does NOT go through xpf userspace zone policy — but this is also true for any kernel-decapped tunnel on a non-XDP-attached device. The fix would be to either (a) add a userspace IPIP decap stage parallel to GRE, or (b) attach XDP+zone to the Iptun/Ip6tnl device.

**This is already filed as OPEN #4478.** The issue correctly identifies the gap and rates it Medium pending runtime trace. **NOT re-reporting — already filed #4478 (OPEN, M-1).**

**Confirming: still present on 33b891d11.** No IPIP decap stage was added between 8cd816e35 and 33b891d11 (only navigatePath fix #4562 changed). `#4478` OPEN remains valid.

### 3.7 Stage-11 IPsec passthrough host-inbound gate (#4323 — deferred hardening)

**Verified:** Stage 11 (`stage_ipsec_passthrough_check`, poll_stages.rs:821-908) exempts IPsec passthrough (ESP/AH/IKE) from the per-zone host-inbound gate by design:

```rust
// poll_stages.rs:831 comment:
// not enforce host-inbound — Stage 11 short-circuits with
// `RecycleAndContinue` before `host_inbound_admits_iface` is ever
// reached, so the passthrough is exempt from the per-zone host-inbound

// poll_stages.rs:843-858
fn ipsec_passthrough_decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 0,  // MUST stay 0 — see #3616
            // ...
        },
    }
}
```

The primary enforcement is the kernel nftables host-inbound chain (`pkg/daemon/daemon_nft.go`), which gates NEW inbound IKE on `system-services ike`/`ipsec` while accepting raw ESP/AH globally and letting established/return IKE ride `ct established,related accept`. Gating NEW IKE / inner-ESP on the secondary AF_XDP path is deferred as Option B (#3616) — tracked as OPEN #4323.

**This is already filed as OPEN #4323** (deferred hardening, Option B). No new angle beyond what #3616/#4323 already document. The deferred gate must reproduce the kernel chain's `ct established,related accept`-first ordering and resolve the logical/GRE-inner ingress zone, or it drops return/established and tunnelled IPsec. **NOT re-reporting — already filed #4323 (OPEN, deferred).**

---

## 4. Findings — Consolidated (NEW only — deduped against all sources)

### High confidence — NEW findings

None. All cohort 9-11 code on 33b891d11 is either already-fixed, already-filed OPEN, or triaged as DELIBERATE/NOT-MATERIAL.

### Verified FIXED on 33b891d11 (not re-reporting as NEW)

- **WG peer_has_confirmed_session REJECT_AFTER_TIME (#4546)** — fix adds `now_ns.saturating_sub(session.created_ns) < REJECT_AFTER_TIME_NS` age gate to `peer_has_confirmed_session`. Previously: expired-but-not-GC'd confirmed session suppressed rekey → bounded ~0-1s blackhole. Now: expired session fails age gate → rekey initiated. Doc comment explicitly credits #4546. **VERIFIED FIXED on 33b891d11** (was OPEN at time of ps-031 but now closed).
- **IPsec DNS stall (#4547)** — `resolveGatewayFamilyHints` now concurrent (bounded pool, cap=8), wall-clock ~one 2s timeout instead of N×2s. **VERIFIED FIXED on 33b891d11** (was OPEN #4547 MED→LOW, now fixed — open issue may need closing).
- **XFRM if_id collision (#2933)** — `validateSecureTunnelBindInterfaceAST` commit-time hard-reject + runtime guard in xfrmManager.Apply fail-closed. **VERIFIED STILL FIXED on 33b891d11.**
- **WG 3-slot responder rekey blackhole (#3882)** — 3-slot model with Initiator→current, Responder→next, promote on first inbound data. **VERIFIED STILL FIXED.**
- **WG TAI64N anti-replay (#4092)** — strictly greater check + before msg2 build. **VERIFIED STILL FIXED.**
- **FRR cross-context route-map default-action leak (#4481)** — per-use-site `-xpf-redist` fail-closed alias. **VERIFIED FIXED on 33b891d11.**
- **FRR sanitize belt bypass (#4482)** — 10 slots sanitized via `sanitizeFRRValue`. **VERIFIED FIXED** (residual 3 slots → OPEN #4498).
- **VRRP equal-priority tie-break oscillation (#4376)** — anchor to one family, unresolved source yields. **VERIFIED FIXED.**
- **VRRP address-owner preempt (#4116)** — owner (priority 255) always preempts irrespective of no-preempt. **VERIFIED FIXED.**
- **IPsec delete-terminate (#3941)** — `swapConnNames` + `terminateRemovedConns` after reload. **VERIFIED STILL FIXED.**
- **IPsec PSK id selectors (#3952)** — `pskIDSelectors` with remote-id/addr + local-id, dedup, %any exclusion. **VERIFIED STILL FIXED.**
- **IPsec normalizeAuthAlg (#3851)** — hmac-sha-256-128 → sha256, not sha256128. **VERIFIED STILL FIXED.**
- **IPsec normalizeAuthAlg DH groups ECP (#2392/#2604)** — group 19→ecp256, 22→modp1024s160, etc. **VERIFIED STILL FIXED.**

### Confirmed OPEN (already filed, not re-reporting)

| Issue | Title | Why not re-reporting |
|-------|-------|---------------------|
| #4548 | VRRP MaxAdverInt no min clamp → 10ms flap | OPEN, still present — no code change since filing |
| #4549 | LOW batch: VRRP hop-limit (raw IPv6), HA IPv4-only, PSK zeroize, same-node-id | OPEN LOW batch — all 4 still present, none changed |
| #4555 | XDP EH: MAX_EXT_HDRS=6 vs userspace MAX_IPV6_EXT_HEADERS=8 | OPEN LOW — no code change |
| #4478 | IPIP decap no zone enforcement | OPEN M-1 — no IPIP decap stage added, kernel Iptun path unchanged |
| #4455 | HI-1 multicast/broadcast host-inbound | OPEN — not in cohort scope for this pass but confirmed still OPEN |
| #4323 | Stage-11 IPsec passthrough host-inbound gate (deferred Option B) | OPEN deferred — no new angle |
| #4498 | FRR sanitize-belt residual (next-hop/origin/source-protocol bare %s) | OPEN — 3 slots still bare %s, no code change |
| #4499/#4497 | test coverage / avo-001 F2/F3 | OPEN — not re-reporting |
| #4440-#4445 | review-watcher backlogs | Various — not cohort 9-11 |
| #4422/#4421/#4420 | test/refactor/host-inbound parity backlogs | OPEN — not re-reporting |
| #2387 | bare 5-tuple cross-zone session hijack | OPEN P0 — confirmed still OPEN, session/key.rs unchanged |

### Triaged DELIBERATE / NOT-MATERIAL (not re-reporting)

| Finding | Triage | Reason |
|---------|--------|--------|
| WG AllowedIPs overlap (F2, ps-031) | DELIBERATE | Standard WireGuard cryptokey routing, most-specific-wins, anti-source-spoof. Doc-test documents intentional. |
| HA heartbeat HMAC after Unmarshal (F4, ps-031) | NOT-MATERIAL (gated) | `handlePeerHeartbeat` runs AFTER `heartbeatAuthDecision` accepts, replay gated on `macOK && nonceFresh`, no side effect from Unmarshal alone. Cosmetic reorder only. |
| XFRM if_id collision (F6, ps-031) | ALREADY-FIXED #2933 | `validateSecureTunnelBindInterfaceAST` commit-time HARD-REJECT, runtime guard fail-closed. |
| IPIP decap beyond GRE (F7 sibling) | Already filed #4478 | IPIP is kernel Iptun, not userspace decap. No new trace beyond #4478. |

### Low confidence — hardening / parity-gaps (not warranting new issues)

None beyond what is already filed in #4498 (FRR sanitize residual) and #4549 (LOW batch).

---

## 5. Verified negatives (paths confirmed fail-closed — coverage proof)

### IPsec — verified fail-closed

- **N-01**: Undefined gateway reference → `validateIPsecGatewayReferencesStrict` hard-rejects at commit, `resolveRemoteAddr` fail-closed (returns ok=false, VPN skipped). Verified on 33b891d11.
- **N-02**: Dangling ike-policy chain → `errIKEChainUnresolved` → VPN skipped at render, hard-rejected at commit. Verified (#2270).
- **N-03**: Dangling ipsec-policy proposal reference → conservative fixed suite "aes256-sha256[-modpN]" instead of bare "default" — no silent crypto weakening. Hard-rejected at commit. Verified (#4117).
- **N-04**: AH proposal → skipped at render, hard-rejected at commit. No ESP fabrication. Verified (#4298).
- **N-05**: Manual-key SA block → hard-rejected at commit, inert on tolerant-load. Verified (#4300).
- **N-06**: PSK $9$ decode — invalid secret → `errInvalidJunosSecret`, not panic. Verified.
- **N-07**: `sanitizeSwanctlValue` strips C0/DEL → space, `escapeSwanctlQuoted` escapes backslash then quote — no injection. Verified (#1798/#2126).
- **N-08**: `normalizeAuthAlg` hmac-sha-256-128 → sha256 (not sha256128) — no rejected proposal. Verified (#3851).
- **N-09**: `formatDHGroup` ECP 19→ecp256, modp1024s160 (not modp22) — no rejected proposal. Verified (#2392/#2604).
- **N-10**: `XFRMIfNameAndID` st0 + st0.0 collision → commit-time hard-reject (#2933) + runtime fail-closed (both tunnels down, no leak). Verified.

### FRR — verified fail-closed

- **N-11**: Undefined prefix-list / dangling community-list → skip + warn, no `redistribute <name>` injection. Verified (#2223).
- **N-12**: Self-redistribute (`redistribute ospf` under `router ospf`) → skip, not poison whole reload. Verified (#2943).
- **N-13**: Defined policy-statement no `from protocol` → skip + warn, not emit `redistribute <policy>`. Verified.
- **N-14**: Bare protocol token vs defined policy-statement — classified by same predicate as commit validator, split render paths (redistribute vs route-map out). Verified (#2473).
- **N-15**: Dangling route-map in `neighbor X route-map <name> out/in` → guard `isDefinedPolicyStatement` skips, FRR permit-all leak prevented. Verified (#2473/#2539/#2490).
- **N-16**: Inverted / out-of-range prefix-length-range → skipEntry (match-nothing, fail-closed), not open-ended "le maxLen". Verified (#2525).
- **N-17**: "through" match-type, unknown match-type, TODO-typed → skipEntry, fail-closed. Verified (#2525).
- **N-18**: Max-length "longer" (/32 longer, /128 longer) → skipEntry (empty set), no FRR-invalid "ge 33 le 32". Verified (#2103).
- **N-19**: Per-route-filter prefix-list → always emits match line even when 0 entries (fail-closed via undefined list = RMAP_NOMATCH/DENY). Verified.
- **N-20**: Mixed-family route-filters → split into v4/v6 sequences (FRR ANDs different-type match clauses). Verified (#2607).
- **N-21**: Same-type `from prefix-list` / `from community` / `from as-path` → cartesian product (OR within type, AND across types). Verified (#2642).
- **N-22**: Policy cross-context default-action leak (#4481) → fail-closed `-xpf-redist` alias. Verified FIXED.

### Routing — verified fail-closed

- **N-23**: Next-table rule limit (100) → cap, future routes ignored, not programmed beyond window. Verified.
- **N-24**: Rib-group leak rule limit (1000) → cap, error returned, not programmed beyond. Verified.
- **N-25**: PBR rule limit (1000) → truncate + error, not silently drop later terms. Verified.
- **N-26**: PBR DSCP-0 → dropped (fail-safe under-steer), not match-all. Verified (#3430 H2).
- **N-27**: PBR except prefix-list (non-empty) → dropped, degraded error. Verified.
- **N-28**: PBR unrepresentable L4 (port-except, tcp-flags, icmp, is-fragment, flex) → whole term dropped, fail-closed. Verified (#3730).
- **N-29**: PBR routing-instance + discard/reject → skip (deny wins, no steering). Verified (#4534).
- **N-30**: Unresolvable rib name → `resolveRibTable` returns ok=false, never bare 0. Verified (#2226).
- **N-31**: Malformed rib family suffix (".inetX.0", ".inet60.0", ".inet.0.garbage") → rejected, not mapped. Verified (#2253).

### HA/VRRP/WG — verified fail-closed

- **N-32**: Duplicate heartbeat magic → `UnmarshalHeartbeat` rejects invalid magic. Verified.
- **N-33**: Heartbeat wrong cluster ID → filtered, recvErrors++. Verified.
- **N-34**: Heartbeat self → filtered (NodeID == local). Verified.
- **N-35**: Heartbeat auth rejected → recvErrors++, no election, no lastSeen advance. Verified.
- **N-36**: Heartbeat truncated monitor section → returns parsed RGs, monitorSectionComplete=false, version not attempted. Verified.
- **N-37**: VRRP wrong packet version/type → rejected. Verified.
- **N-38**: VRRP wrong TTL/hop-limit (AF_PACKET) → dropped. Verified (RFC 5798 §5.1.1.3, §5.1.2.3).
- **N-39**: VRRP self-sent → filtered by localIP/localIPv6. Verified.
- **N-40**: VRRP wrong VRID → dropped. Verified.
- **N-41**: VRRP IPv4 checksum → pseudo-header-aware with legacy accept during migration. Verified.
- **N-42**: VRRP duplicate address → GARP/NA, not silent. Verified.
- **N-43**: WG TAI64N replay → strictly greater check. VERIFIED FIXED (#4092).
- **N-44**: WG cookie budget flood → global budget + per-source bucket + load gate. VERIFIED FIXED.
- **N-45**: WG peer_has_confirmed REJECT_AFTER_TIME → age gate added. VERIFIED FIXED (#4546).
- **N-46**: XFRM if_id collision → commit-time hard-reject + runtime fail-closed (both down). VERIFIED FIXED (#2933).
- **N-47**: GRE decap inner → zone-enforced via `endpoint.logical_ifindex → ifindex_to_zone_id`. Verified on 33b891d11.
- **N-48**: IPIP — already filed #4478. NOT a new negative — kernel-decapped IPIP inner bypasses userspace zone policy on current architecture (no userspace IPIP decap stage).

---

## 6. Suggested issue split

**No NEW issues to file.** All cohort 9-11 code on 33b891d11 is either:

- **FIXED** (not re-reporting): #4546 WG peer_has_confirmed (#4546 — now fixed, verify close), #4547 IPsec DNS stall (now concurrent — now fixed, verify close), #2933 XFRM collision, #3882 WG 3-slot, #4092 TAI64N, #4481 FRR cross-context, #4482 FRR sanitize, #4376 VRRP tie-break, etc.
- **OPEN already filed** (not re-reporting unless materially new trace): #4548 VRRP flap, #4549 LOW batch, #4555 XDP EH 6vs8, #4478 IPIP decap, #4455 HI-1, #4323 Stage-11 passthrough, #4498 FRR sanitize residual, #2387 bare 5-tuple, etc.
- **DELIBERATE / NOT-MATERIAL**: WG AllowedIPs overlap (F2), HA heartbeat auth order (F4 — cosmetic, gated), XFRM if_id (F6 — fixed #2933).

**Two OPEN issues should be CLOSED (fixed on HEAD):**

1. **#4546** WG `peer_has_confirmed_session` ignores REJECT_AFTER_TIME — **FIXED on 33b891d11** (age gate `now_ns.saturating_sub(session.created_ns) < REJECT_AFTER_TIME_NS` added). Doc comment explicitly says "The age gate is load-bearing (#4546)". The `gh issue list` still shows #4546 as CLOSED — verified.
2. **#4547** IPsec dynamic-hostname gateway DNS stall (N×2s) — **FIXED on 33b891d11** (`resolveGatewayFamilyHints` concurrent, bounded pool cap=8, wall-clock ~one timeout). Open issue may need closing if tests pass.

**One existing OPEN should remain OPEN (still present):**

- **#4478** IPIP decap no zone enforcement — still present (no IPIP decap stage, kernel Iptun path, no XDP on ipip device). No code change since filing. Confirmed OPEN.
- **#4548** VRRP MaxAdverInt no min clamp — still present (no clamp added, `recordMasterAdvert` still `if pkt.MaxAdvertInt > 0 { vi.masterAdverInterval = ... }` with no min). Confirmed OPEN.
- **#4498** FRR sanitize-belt residual — still present (3 bare-%s slots: `match source-protocol`, `set ip/ipv6 next-hop`, `set origin`). Confirmed OPEN.
- **#4323** Stage-11 IPsec passthrough host-inbound gate — still OPEN, deferred by design. No new angle.

---

## 7. Appendix — Specific triage notes per task instruction

### IPIP decap zone enforcement (ps-033 opus-172 M-1 — #4478 OPEN, fail-open, parallel to GRE — is it still present? Confirm)

**CONFIRMED STILL PRESENT on 33b891d11.**

- GRE decap (`try_native_gre_decap_from_frame` → `match_tunnel_endpoint` → `endpoint.logical_ifindex` → `ifindex_to_zone_id` → `ingress_zone` stamped on inner `UserspaceDpMeta`) — **HAS zone enforcement** (gre.rs:747-783).
- IPIP decap — there is NO userspace IPIP decap path. IPIP tunnels are kernel `Iptun`/`Ip6tnl` devices (tunnel.go:675-691). The kernel handles IPIP decap; the inner packet is kernel-forwarded via kernel FIB, not via xpf userspace. No `try_native_ipip_decap_from_frame`, no `ipip_decap_index`, no `IPIP_DECAP_INGRESS_FLAG`.
- On the current architecture, a kernel-decapped IPIP inner packet does NOT re-enter xpf XDP (the Iptun/Ip6tnl device does not have XDP attached), so it bypasses userspace zone policy entirely.
- `#4478 OPEN` (opus-172 M-1) correctly identifies this gap. The fix would be to either (a) add a userspace IPIP decap stage parallel to GRE (`try_native_ipip_decap_from_frame` + `ipip_decap_index` + `IPIP_DECAP_INGRESS_FLAG` + zone enforcement via `endpoint.logical_ifindex`), or (b) attach XDP+zone to the Iptun/Ip6tnl device. (a) mirrors GRE and is more complete.
- Opus-172 M-1 severity was High-if-confirmed (Medium pending runtime trace). Since IPIP is less common than GRE in production, and the kernel FIB forwarding of the decapped inner is the actual path (not a direct bypass into a protected zone), the rating depends on whether the IPIP inner is an RFC 1918 private address that should be zone-gated. For a typical IPIP deployment (WAN transport), the inner is a private LAN prefix that SHOULD be zone-gated — so this is a real fail-open.

**Dedup note: Already filed #4478 OPEN (opus-172 M-1). NOT a new finding. CONFIRMED still present.**

### FRR sanitize-belt residual (ps-035 #4498 — still open? Origin, next-hop, source-protocol bare %s — is Origin field still unsanitized?)

**CONFIRMED STILL PRESENT on 33b891d11.**

- `#4498` item 1: `set ip/ipv6 next-hop <term.NextHop>` (policy_render.go:1727/1729), `set origin <term.Origin>` (line 1802), `match source-protocol <proto>` (line 1686) still render with bare `%s`.
- `term.NextHop` is an IP literal from config (validated as IP at commit, but tolerant-load path may carry control chars).
- `term.Origin` is "igp"/"egp"/"incomplete" — small enum, low injection risk but same pattern.
- `term.FromProtocols` values (direct, connected, static, ospf, ospf6, bgp, rip, ripng, isis, kernel) — validated at commit to known set, but tolerant-load path may carry `\n`.
- All other slots (10+) are now sanitized via `sanitizeFRRValue` (fix #4482). The 3 residual slots are what #4498 tracks.
- Severity: LOW — commit-time validator rejects control chars / invalid values, so only tolerant-load/peer-sync path (which only warns, #1960) could reach these with a control-char payload. The functional impact is FRR reload failure (managed-section reload degraded to vtysh -f additive fallback, stale-config removal deferred), not privilege escalation. The injection would need to be a newline in a trusted config source (already-persisted / peer-synced config) — narrow attack surface.
- Fix: wrap these 3 residual slots with `sanitizeFRRValue` (same as fix #4482 did for the other 10 slots).

**Dedup note: Already filed #4498 OPEN. NOT a new finding. CONFIRMED still present — 3 bare-%s slots remain.**

### FRR route-map cross-context default-action leak (ps-033 #4481 — CLOSED, verify FIXED on this HEAD)

**VERIFIED FIXED on 33b891d11.**

```go
// policy_render.go:1325-1337 — redistFailClosedRouteMap derives per-use-site alias name
func redistFailClosedRouteMap(name string) string { return name + "-xpf-redist" }

// policy_render.go:1339-1350 — alias needed only when policy is BGP route-map with no explicit default
func policyNeedsRedistAlias(...) bool { return ps != nil && bgpAcceptDefault[name] && ps.DefaultAction != "accept" && ps.DefaultAction != "reject" }

// policy_render.go:1488-1504 — generate base route-map + fail-closed alias
b.WriteString(m.renderRouteMapForPolicy(po, name, ps, policyTrailingAction(name, ps, bgpAcceptDefault)))
if policyNeedsRedistAlias(name, ps, bgpAcceptDefault) {
    b.WriteString(m.renderRouteMapForPolicy(po, redistFailClosedRouteMap(name), ps, "deny"))
}

// policy_render.go:174-183 — redistribute references fail-closed alias
rmName := export
if policyNeedsRedistAlias(export, ps, bgpAcceptDefault) {
    rmName = redistFailClosedRouteMap(export)
}
```

The bug: FRR route-maps are keyed by NAME (one object shared by every use site). A policy applied as BGP route-map in/out with no explicit default renders trailing PERMIT (Junos BGP default-accept, #2998). If SAME policy also used for IGP redistribute, that permit leaks every non-matching route into IGP. Fix: emit per-use-site fail-closed alias (`-xpf-redist` suffix, trailing DENY) for redistribute contexts.

**Dedup note: FIXED #4481 CLOSED. VERIFIED FIXED on 33b891d11. NOT re-reporting.**

### FRR sanitize belt (#4498 OPEN), next-hop/origin/source-protocol bare %s (#4498 item 1)

Same as above — **CONFIRMED STILL PRESENT**, already filed #4498 OPEN.

### Stage-11 IPsec passthrough host-inbound gate (ps-033 #4323 — deferred, any new angle?)

**No new angle.** Stage 11 (`stage_ipsec_passthrough_check`, poll_stages.rs:821-908, poll_descriptor/mod.rs:740-751) exempts IPsec passthrough (ESP/AH/IKE) from per-zone host-inbound by design (#3616 Option A ratified). Primary enforcement is kernel nftables host-inbound chain (`daemon_nft.go`). Deferred hardening is Option B (gate NEW inbound IKE against per-zone host-inbound) — tracked as OPEN #4323. No new bypass angle beyond what #3616/#4323 already document. The deferred gate must reproduce the kernel chain's `ct established,related accept`-first ordering and resolve logical/GRE-inner ingress zone, or it drops return/established and tunnelled IPsec.

**Dedup note: Already filed #4323 OPEN (deferred). NOT re-reporting. No new angle.**

### HA heartbeat auth order — triaged as NOT exploitable (gated on macOK), no new angle?

**No new angle.** Heartbeat `UnmarshalHeartbeat` (line 717) before `verifyHeartbeatMAC` (745) / `heartbeatAuthDecision` (747) is cosmetically wrong order, but `handlePeerHeartbeat` (which rebuilds `peerGroups` and runs `runElection`) only runs AFTER auth decision accepts. No side effect from Unmarshal alone (ClusterID/NodeID filter checks before auth are elided on forged heartbeat — no mutation). Replay gated on `macOK && nonceFresh`. No new angle.

**Dedup note: ps-031 triage F4 NOT-MATERIAL (gated). NOT re-reporting.**

### WireGuard AllowedIPs overlap — DELIBERATE, not a bug

**DELIBERATE per task instructions.** Standard WireGuard cryptokey routing: global LPM, most-specific-wins, anti-source-spoof via `matches_for_peer`. 0.0.0.0/0 catch-all + specific /24 is valid WireGuard config. Duplicate identical prefix → only one peer wins is documented in tests. No commit-time validation needed.

**Dedup note: F2 DELIBERATE — NOT a bug, do not re-report.**

### Config schema opt-in unmodeled leaves (#4313 — known, do not re-report)

Known OPEN #4313 (config schema opt-in — unmodeled Junos leaves commit clean and are silently inert). Cross-cutting root cause, tracked separately. **NOT re-reporting.**

### Any NEW IPsec/WG/HA/VRRP/routing/FRR issue not in the list above

**None found.** See §4 above for full dedup and coverage proof.

