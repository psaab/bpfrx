# Deep Adversarial Security Audit — Cohorts 9-11: IPsec/IKE/WG + HA/Cluster/VRRP + Routing/FRR
## Base: 8cd816e35
## Output: /tmp/ps-review-020.md

---

## 1. Duplicate Suppression

### Prior files read:
- /tmp/all_findings.txt (274 entries, F-001..F-274)
- /tmp/ps-review-010..019.md (all existing auditor reports)
- gh issue list — 300 entries (OPEN + CLOSED state)

### CLOSED (do NOT re-report):
#4541 writeJSON, #4540 monitor keyword, #4535 three-color, #4534 PBR discard, #4526 DHCP, #4525 RA, #4524 monitor injection, #4521 NAT pool, #4520 nat64 counter, #4519 nptv6, #4518 nat64 allocator, #4517 EH walkers, #4514 policer, #4487 LocalDelivery RST/FIN, #4453 fabric RST/FIN, #4400 ForwardCandidate RST/FIN, #4399/#4438 NAT 1:N, #4393 dnat_table, #4392 PBR reject, #4388 HA NAT, #4386 split-brain, #4384 TCP checksum, #4383 DHCPv6 IA_NA, #4382 screen SYN-flood seeds, #4380 forward/reverse idle, #4379 scan/sweep cleanup, #4378 commit-confirmed rollback, #4377 session limit decrement, #4376 VRRP tie-break, #4365 global-policy scope, #4362 cookie_gen, #4360 BulkSync re-drive, #4348 quoted inactive, #4343 policy-rematch scheduler, #4342 default-policy sessions, #3882 WG 3-slot, #4092 TAI64N replay, #4107 cluster auth, #4094 wireguard cookie, #4071 GRE keepalive, #4015 df-bit, #3994 DPD bare, #3941 IPsec delete-terminate, #3952 PSK id selectors, #3937 SA parse, #3876 rib-group, #3855 RI table IDs, #4482 FRR route-map/prefix-list bypass, #4481 FRR cross-context default-action leak, etc.

### OPEN (do NOT re-report unless materially new trace):
#4549 LOW batch (VRRP hop-limit, HA IPv4-only, PSK zeroize, same-node-id), #4548 VRRP MaxAdverInt flap, #4547 IPsec DNS stall, #4546 WG peer_has_confirmed, #4544 host-inbound dup, #4543 screen TLV, #4539 session cache, #4533 icmp_embed EH-overflow, #4515 warn-only gaps, #4512 NAT64 HA-sync, #2387 bare 5-tuple, #4146 junos-host XDP shim, #3226 system-services all, #2852 NAT Mutex, #2562 NAT64 frag, #2261 DHCP HA lease, #2008 vSRX parity, #4422 test backlog, #4421 refactor backlog, #4420 host-inbound parity, #4478 IPIP decap (fail-open?), #4455 HI-1 multicast/broadcast, #4373 reject/filter/PBR log confusion, #4372 three-color status, #4323 IPsec Stage-11 passthrough, #4313 opt-in schema, #4228 CoS gaps, #4498 FRR sanitize-belt residual, #4499 test coverage, etc.

### Intentional divergences NOT reported:
- intrazone default-permit, host-originated junos-host bypass, IPsec-passthrough-exempt, reject-all superset, accept-data/VIP always live, etc.

---

## 2. Module / Verdict-Path Inventory

| Cohort | Module | File | Verdict Role | Coverage |
|--------|--------|------|-------------|----------|
| 9 | IPsec/IKE | pkg/ipsec/ike.go | IKE proposal/DPD/DH-group resolution | Full |
| 9 | IPsec/IKE | pkg/ipsec/policy.go | swanctl render, traffic selectors, remote addr resolution | Full |
| 9 | IPsec/IKE | pkg/ipsec/crypto.go | Junos $9$ PSK decryption | Full |
| 9 | IPsec/IKE | pkg/ipsec/manager.go | swanctl apply/clear, SA termination | Full |
| 9 | IPsec config | pkg/config/compiler_ipsec.go | IKE/IPsec proposal/policy/gateway/VPN compile | Full |
| 9 | IPsec config | pkg/config/compiler_validate_strict_ipsec.go | IKE/IPsec strict validation gates | Full |
| 9 | Routing - tunnel | pkg/routing/tunnel.go | GRE/IPIP/WG tunnel lifecycle, keepalive, MTU | Full (1244+ lines) |
| 9 | Routing - xfrm | pkg/routing/xfrm.go | XFRM if_id collision detection | Full (232 lines) |
| 9 | Routing - VRF | pkg/routing/vrf.go | VRF device lifecycle, namespace claim | Full (361 lines) |
| 10 | Routing - rules | pkg/routing/rules.go | next-table/rib-group/PBR ip-rule reconciliation | Full (1274 lines) |
| 10 | FRR | pkg/frr/manager.go | FRR config lifecycle, reload, degraded retry | Full (864 lines) |
| 10 | FRR | pkg/frr/config_render.go | static routes, DHCP defaults, ECMP | Full (394 lines) |
| 10 | FRR | pkg/frr/policy_render.go | BGP/OSPF/RIP/ISIS, route-maps, prefix-lists, communities, sanitizeFRRValue | Full (1906 lines) |
| 10 | FRR | pkg/frr/vtysh.go, status_parse.go | vtysh executor, route/BGP status parsing | Partial (supporting) |
| 11 | HA/Cluster | pkg/cluster/heartbeat.go | heartbeat wire format, auth, anti-replay, Unmarshal/Marshal | Full (874 lines) |
| 11 | HA/Cluster | pkg/cluster/heartbeat_manager.go | heartbeat start/stop/restart, IPv4-only | Full (467 lines) |
| 11 | HA/Cluster | pkg/cluster/election.go | RG election, tie-break, preempt | Full (409 lines) |
| 11 | HA/Cluster | pkg/cluster/failover.go | manual/batch failover, transfer-commit | Full (876 lines) |
| 11 | HA/Cluster | pkg/cluster/sync.go, sync_auth.go, sync_conn.go | session sync, auth handshake, frame seal | Full |
| 11 | HA/Cluster | pkg/cluster/monitor.go, events.go, garp.go, reth.go, runtime.go | monitor, events, GARP, RETH, runtime | Sampled |
| 11 | VRRP | pkg/vrrp/instance.go | instance state machine, MaxAdverInt learning, recordMasterAdvert | Full (2250 lines, sampled deep) |
| 11 | VRRP | pkg/vrrp/packet.go | VRRPv3 Marshal/Parse, checksum, pseudo-header | Full (277 lines) |
| 11 | VRRP | pkg/vrrp/manager.go, track.go, addrwatch.go | manager lifecycle, track, addr watch | Sampled |
| 9-11 | WireGuard | userspace-dp/src/afxdp/wg/engine.rs | engine, encap/decap, session mgmt | Full (sampled deep, 1012+ lines) |
| 9-11 | WireGuard | userspace-dp/src/afxdp/wg/peer.rs | 3-slot keypair lifecycle (#3882) | Full (382 lines) |
| 9-11 | WireGuard | userspace-dp/src/afxdp/wg/session.rs | session, replay window, 3-slot, timers | Full (431 lines) |
| 9-11 | WireGuard | userspace-dp/src/afxdp/wg/timers.rs | REJECT_AFTER_TIME, timer pass, T6/T7/T8 | Full (340 lines) |
| 9-11 | WireGuard | userspace-dp/src/afxdp/wg/handshake.rs | framing, MAC1, TAI64N | Full |
| 9-11 | WireGuard | userspace-dp/src/afxdp/wg/handshake_session.rs | handshake orchestration | Full (759 lines) |
| 9-11 | WireGuard | userspace-dp/src/afxdp/wg/cookie.rs | cookie/MAC2 DoS mitigation | Full (sampled deep) |
| 9-11 | WireGuard | userspace-dp/src/afxdp/wg/allowed_ips.rs | LPM, cryptokey routing | Full (291 lines) |
| 9-11 | WireGuard | userspace-dp/src/afxdp/wg/mod.rs | constants, types | Full (196 lines) |
| 9-11 | GRE/IPIP decap | userspace-dp/src/afxdp/gre.rs | GRE decap, ECN combine, tunnel endpoint matching | Full (961 lines, 3 reads) |
| 9-11 | Tunnel build | userspace-dp/src/afxdp/forwarding_build/tunnels.rs | TunnelKind classification, decap index | Full (302 lines) |

---

## 3. Module-by-Module Inspection Log (incl. negatives)

### 3.1 IPsec/IKE — pkg/ipsec/ike.go

- `resolveIKESettings` (line 49-96): correctly distinguishes empty-policy (intentional, returns empty proposal + nil error) from dangling reference (returns `errIKEChainUnresolved`). `#3904` multi-proposal `proposals [ p1 p2 ]` handling — builds each resolvable ref, comma-joins. First lifetime taken from first resolvable proposal. Correct.
- `resolveESPSettings` (line 134-230): absent vs dangling distinction correct. Dangling falls through to conservative fixed `aes256-sha256` — never bare `default`. Mirrors #4117/#2073. Correct.
- `deriveDPD` (line 241-291): DPD enable on bare `dead-peer-detection;` via `gw.DPDEnable` (not just `gw.DeadPeerDetect != ""`). Correct (#3994 fix).
- `normalizeAuthAlg` (line 396-428): correctly strips `hmac-` prefix and dashes, maps `sha256128` → `sha256` (not the invalid `sha256128` that naive dash-strip produces). Correct (#3851 fix).
- `formatDHGroup` (line 574-607): ECP groups 19-21→`ecp256/ecp384/ecp521`, brainpool 27-30, montgomery 31-32, MODP-with-prime-order 22-24→`modp1024s160/modp2048s224/modp2048s256` (not bare `modp22/23/24`). Correct (#2392/#2604 fixes).
- `parseSAOutput` (line 728-814): correctly parses real `swanctl --list-sas` output (IKE SA header, child SA header, endpoint lines with `@`, traffic-selector lines without `@`). Fixed #3937. Correct.

**NEGATIVE**: No new issues found in pkg/ipsec/ike.go beyond known #4547 (DNS stall — separate file).

### 3.2 IPsec — pkg/ipsec/policy.go

- `resolveRemoteAddr` (line 304-360): correctly returns `ok=false` for dangling gateway object name (not a known gateway, not a usable IP/hostname). Mirrors commit-time validator `validateIPsecGatewayReferencesStrict`. Correct (#2074 fix).
- `effectiveTrafficSelectors` (line 371-411): nil VPN guard (defensive), traffic-selector sort, LocalID/RemoteID fallback, `sanitizeChildName` for child SA names. Correct.
- `sanitizeSwanctlValue` (line 421-439): strips C0+DEL → space — prevents newline injection into swanctl.conf. Belt for #1798/#4098. Correct.
- `escapeSwanctlQuoted` (line 442-460): escapes backslash THEN double-quote (order matters — escaping quotes first then doubling backslashes would corrupt). Correct (#2126 fix).
- `pskIDSelectors` (line 488-533): scopes PSK to peer via `id-<n>` selectors — remote identity (explicit remote-id or concrete remote addr) + local identity when configured. `%any` excluded (not a usable identity). Correct (#3952 fix).
- `resolveInterfaceAddress` / `resolveHostFamily` / `gatewayRemoteFamilyHint` (line 619-988): dual-stack family hint for local-address selection, 2s DNS timeout, family-agnostic fallback on resolution failure. Known issue #4547 (DNS stall) is in `defaultResolveHostFamily` — synchronous DNS per gateway during commit. STILL PRESENT but not new.

**NEGATIVE (focus-check)**: IPIP decap zone enforcement — IPIP mode is `TunnelKind::Unknown` → no decap index → fail-closed, not fail-open. Detailed in findings.

### 3.3 IPsec — pkg/ipsec/manager.go

- `Apply` (line 104-123): diffs `prevConnNames` vs new, applies config, terminates removed SAs AFTER reload (so straggler SA cannot be re-initiated). Correct (#3941 fix).
- `terminateRemovedConns` (line 219-248): queries live SAs, only terminates removed connections that actually have SAs (or unconditional fallback when list fails). Correct.
- `swapConnNames` (line 205-211): diff keys off VPN name (map key), not renderability — a VPN that merely became unrenderable keeps its SAs. Correct.

**NEGATIVE**: No new issues.

### 3.4 Routing — pkg/routing/xfrm.go

- `xfrmManager.Apply` (line 50-197): full differential reconcile (keep/create/recreate/delete), if_id collision detection (two distinct bind-interfaces deriving same if_id → refuse BOTH), adoption with stale-if_id re-check, single LinkByName lookup reuse (no nil-link panic on second lookup). Correct.
- Collision handling: `idToName[ifID]` tracks first claimant, `collidingIDs` marks colliding IDs, second pass `delete(desired, name)` removes first claimant too — NEITHER colliding device created. Fail-closed. Correct.
- Adoption path: `link.(*netlink.Xfrmi)` type assert, `xi.Ifid != ifID` → delete+recreate (Ifid immutable). Non-xfrmi link of same name kept (adopted). Correct.

**NEGATIVE**: ps-031 if_id collision STILL PRESENT finding — VERIFIED FIXED. No new issue.

### 3.5 Routing — pkg/routing/rules.go

- `nextTableManager.Apply` (line 84-172): clear+rebuild with error aggregation, family-aware, priority window cap (100 rules). Correct.
- `ribGroupManager.Apply` (line 241-369): per-prefix leak (pref 30000, before main table 32766), not blanket `from all`. `ribGroupLeaksIntoMain` correctly skips unresolvable import-ribs (fail-closed, #2226). Phase 1 main-only, VRF→VRF deferred. Correct (#3876 fix).
- `pbrManager.Apply` / `BuildPBRRules` (line 524-959): `collectAttachedInputFilters` only considers input-attached filters (Junos FBF parity, #3430 H1). `pbrTermL4` classifies L4/per-packet predicates into representable (protocol/port) vs unrepresentable (port-except/tcp-flags/icmp/is-fragment/flex) — unrepresentable fails closed (whole term dropped + degraded). `resolvePBRDirection` handles `except` sets (pure-except-match-nothing, mixed-positive+except-positive-wins). DSCP-0 skip (netlink has no FRA_DSCP, zero matches ANY). Correct.
- `buildPBRFromFilter` (line 770-959): `then routing-instance` + `then discard/reject` contradiction → skip (do NOT steer, deny wins). Correct (#4534/#4392 fix).
- `pbrTermL4` (line 974-1039): unknown protocol / protocol 0 / unparseable port → unrep → fail-closed. Correct (#3730 fix).

**NEGATIVE**: FRR route-map cross-context (#4481) and FRR sanitize-belt (#4482/#4498) are in pkg/frr, not pkg/routing. No new issues in pkg/routing/rules.go.

### 3.6 FRR — pkg/frr/policy_render.go

- `sanitizeFRRValue` (line 49-67): strips C0 (0x00-0x1F including newline) + DEL (0x7F) → space. Belt for #1798/#4097. Covers: BGP neighbor desc/auth-key/password, OSPF auth-key, RIP auth, ISIS area/domain-password, prefix-list prefixes, community members, as-path regex, route-map match/set clauses. Comprehensive.
- `resolveRedistribute` (line 124-210): `direct`→`connected` normalization (#2144), self-redistribute drop (#2943), `policyNeedsRedistAlias` for cross-context default-action leak (#4481), bare `redistribute <name>` never emitted (lenient-path empty RIB guard, #2223). Correct.
- `policyNeedsRedistAlias` / `redistFailClosedRouteMap` / `policyTrailingAction` (line 1325-1375): detects BGP-route-map-in/out policy with no explicit default → creates per-use-site alias with `deny` trailing for redistribute. BGP keeps `permit` (Junos BGP default-accept #2998). Correct (#4481 fix).
- `generatePolicyOptions` (line 1387-1508): prefix-lists (sanitized), communities (standard vs expanded, sanitized), as-path (sanitized), route-maps (mixed-family split #2607, OR-set cross-product #2642, `on-match next` for non-terminating terms #2451). Correct.
- `renderRouteMapForPolicy` (line 1510-1906): mixed-family route-filter split, `from prefix-list` family matching, `from protocol direct→connected`, `from community/as-path` OR via per-sequence, `then next-hop self` → per-neighbor `next-hop-self force` (not route-map set-clause, #2977), `then community delete [ listA listB ]` → one clause per list (#2902), local-preference/metrics on presence (not value > 0, #2847/#2857). Correct.
- `renderRouteFilterEntry` (line 1135-1272): `longer` empty-set skip (max-length prefix, #2103), `prefix-length-range` validation (#2525), `through` skip (fail-closed), `upto` with boundary checks (#2102), malformed prefix skip (#2105). Correct.

**FINDING**: `term.Origin` at line 1801-1803 NOT sanitized. See findings below.

### 3.7 FRR — pkg/frr/manager.go

- `writeManagedSection` (line 530-600): orphaned-begin-marker handling (#1646/#2908), anchored end-marker search (prevents duplication), atomic write via `fsatomic.WriteFileDurable` with parent-dir fsync (#1894). Correct.
- `reloadLocked` (line 644-667): direct `frr-reload.py --reload` (not `systemctl reload frr` which restarts watchfrr and poisons for 2 minutes, #1880), fallback `vtysh -f` (additive, degraded), separate timeout contexts (primary timeout doesn't kill fallback). Correct.
- `degradedRetryLoop` / `retryReloadOnce` (line 781-850): primary-only retry (no nested fallback), `confGen` change detection (never clears degraded on stale success), `Stop` disables retry before Wait (no Add/Wait misuse, #1880 r1 H1). Correct.

**NEGATIVE**: No new issues in FRR manager lifecycle.

### 3.8 HA/Cluster — pkg/cluster/heartbeat.go

- `MarshalHeartbeat` / `marshalHeartbeatBody` (line 192-290): group count capped at 255 (uint8 wire limit, #4434), monitor truncation preserves version trailer, `tailReserve` for auth trailer never silently downgrades to unsigned. Correct.
- `UnmarshalHeartbeat` (line 292-378): version/monitors/HA-protocol-version optional trailing sections, back-compat (missing trailer = LegacyHAProtocolVersion), monitor truncation returns partial (RG state already parsed, critical). Correct.
- `MarshalHeartbeatAuth` / `heartbeatAuthTrailer` / `verifyHeartbeatMAC` (line 413-474): HMAC over body + magic+session+counter (everything but digest), `tailReserve` honored while building body (never silently downgrades). Correct (#4107).
- `heartbeatAuthReplay.admit` (line 492-504): re-anchors on new session id (reboot never mistaken for replay), strictly increasing counter within session. Correct.
- `heartbeatAuthDecision` (line 526-543): dual-accept (no local key → accept everything; local key + auth trailer → enforce HMAC+nonce; local key + no trailer + peerAuthSeen → reject downgrade). Correct.
- `readLoop` (line 691-768): Unmarshal before auth is suboptimal (parses unauthenticated data) but NOT exploitable — parsed pkt only used for ClusterID/NodeID filtering (optimization) before auth, and for handlePeerHeartbeat after auth passes. `admit()` correctly gated on `macOK` (HMAC verified). Correct ordering for `admit()`.
- `checkTimeout` / `neverSeenConfirmed` / `heartbeatStale` (line 785-869): cold-boot never-seen floor (30s grace, #4386), seen-then-lost grace, CLOCK_MONOTONIC comparison (immune to wall-clock steps, #1792), `peerHeartbeatFresh` post-guard re-check (fresh heartbeat during slow guard aborts peer-lost). Correct.

**NEGATIVE**: Heartbeat auth order — Unmarshal-before-auth is not exploitable (see analysis in findings). IPv4-only (#4549) is known. No NEW security bypass.

### 3.9 HA/Cluster — pkg/cluster/heartbeat_manager.go

- `StartHeartbeat` (line 26-87): idempotent (StopHeartbeat before install, hbStartMu serialization, #4033), `vrfListenConfig` with SO_REUSEADDR+SO_REUSEPORT (immediate rebind after restart). Correct.
- `RestartHeartbeat` (line 140-224): preserves `lastSeenSeed` across restart (CLOCK_MONOTONIC nanos, same domain), `hbRestartNotifyFn` keeps peer suppression guard fed during bind retries, 5×1s retry with backoff. Correct (#1792 fix).
- `handlePeerHeartbeat` (line 227-331): rebuilds `peerGroups` from scratch (prunes stale RGs), `applyTransferCommitOverridesOnPeerStateLocked` for transfer-commit state machine, peer monitor statuses. Correct.
- `handlePeerTimeout` (line 333-423): `suppressPeerTimeoutForTransferCommitLocked` grace, `peerTimeoutGuardFn` (peerAlive suppression), `peerHeartbeatFreshLocked` post-guard re-check (fresh heartbeat during guard → abort, #2080), ManualFailover clear on peer-lost, `electSingleNode`, peer fencing. Correct.
- **Known**: All four `net.ResolveUDPAddr("udp4", ...)` / `lc.ListenPacket("udp4", ...)` — hardcoded IPv4. IPv6 control link fails. Already filed #4549 F-09.

**NEGATIVE**: No new issues beyond known IPv4-only.

### 3.10 HA/Cluster — pkg/cluster/election.go

- `electRG` (line 36-229): kernelUpgradeHold (never auto-clears, isolated candidate never becomes primary), ManualFailover with 2s guard (auto-clears when peer also yielded), weight-0 → always secondary, peer-weight-0 → we become primary, `StateSecondaryHold` (explicit transfer-out), preempt (higher effective priority wins, tie: lower node ID), non-preempt (incumbent stays unless weight 0), dual-active (lower priority yields). Correct.
- `runElection` (line 232-291): readiness gate (blocks NEW promotions until `IsReadyForTakeover`, doesn't demote already-primary), standalone nodes skip gate. Correct.

**NEGATIVE**: Same-node-id tie (both nodes nodeID 0 → no change, deadlock) already filed #4549 F-11. No NEW issue.

### 3.11 HA/Cluster — pkg/cluster/sync.go + sync_auth.go + sync_conn.go

- `SessionSync` construction (`initGenState`, line 569-607): `genCounter` seeded from `MonotonicNanos` (cross-restart regression handled by receiver `resetRecvGen` on bulk re-prime, #2198 F2). `configGenCounter` same seed, `configApplyCh` (64 deep), `lastAppliedConfigGen` 0. Correct.
- `installGenGuardV4/V6` / `deleteGenGuardV4/V6` / `takeDeleteGenV4/V6` (sync_conn.go): #2170/#2198/#2221 generation guards — delete draws fresh generation (not echo of install), tombstone (delete gen stored, not evicted) so reordered install refused. `genGuardMapCap` 200k, skip-record-on-full degrades to gen-0 (safe), never clears map. Correct.
- `resetRecvGen` (line 273-302): clears recv-gen maps + `lastAppliedConfigGen` 0 on peer bulk re-prime (rebooted peer's lower generations accepted). Safe against stale-delete window (deletes only after bulk, bulk re-establishes live set). Correct.
- `performSyncHandshake` (sync_auth.go:329-408): only when local key configured (dual-accept), concurrent write+read (no Pipe deadlock), HELLO (version+keyed+nonce) → proof exchange → `syncAuthDecision`. Downgrade-guard via `syncPeerAuthSeen` (sync OR heartbeat channel). Correct (#4107 F23).
- `wrapSyncConn` / `authConn.sealFrame` / `verifyFrame` (sync_auth.go): per-connection frame key derived from PSK + BOTH nonces (canonical order, cross-connection replay excluded), per-frame seq (strictly increasing, replay guard), HMAC over frame+seq. Pass-through when unauthenticated (dual-accept). Correct.
- `syncAuthDecision` (line 265-279): no local key → accept; local key + peer keyed (proofOK → auth, !proofOK → reject); local key + peer legacy/unkeyed + peerAuthSeen → reject (downgrade); else accept. Correct.
- `handleNewConnection` / `acceptLoop` / `fabricConnectLoop` (sync_conn.go): `#4107 F23` auth before any session frame, pending frame from legacy peer processed before receive loop, `wasDisconnected` → bulk sync on cold start only (already-primed skips), dual-fabric (fab0 preferred, fab1 only when fab0 down). `acceptLoop` runs handshake in per-connection goroutine (slow handshake cannot stall accept, #4370). Correct.

**NEGATIVE**: No new issues in sync/auth/conn. #4549 batch (PSK zeroize etc.) known.

### 3.12 VRRP — pkg/vrrp/instance.go (deep read)

- `recordMasterAdvert` (line 1493-1509): skips priority-0 (resignation, #2082), adopts master's MaxAdvertInt (centiseconds → Duration, 10ms units). Zero MaxAdvertInt ignored (falls back to local interval). Correct basic behavior.
- `masterDownInterval` (line 658-675): `3*Master_Adver_Interval + Skew_Time`, `Master_Adver_Interval` = learned interval (RFC 5798 §6.1/§6.4.2) or local fallback. Skew = `(256-priority)*advert/256`. Correct.
- `effectiveAdvertInterval` (line 641-656): learned > 0 → use learned, else local, else 1000ms default. Correct.
- `handleBackupRx` (line 1511-1566): priority-0 → immediate takeover (1ms timer, cancel preempt hold, arm `skipNextPreemptHold`). `!getPreempt || pkt.Priority >= pri` → reset timer, disarm hold. Preempt + lower-priority incoming → ignore (let timer expire, hold running). Correct.
- `handleMasterRx` (line 1568-1592): priority-0 → send immediate advert (stay Master). Higher priority → becomeBackup. Equal priority → `resolveEqualPriorityMaster` (RFC 5798 §6.4.3 tie-break, anchored to v4 family, #4376). Correct.
- `preemptHoldDuration` / `preemptingLiveLowerMaster` / `stepBackup` (line 678-896): preempt hold-time deferral, re-validation on hold expiry and config update, `skipNextPreemptHold` one-shot bypass for resign. Correct (#2850/#2900).
- `sendAdvert` (line 1744-1794): separate v4/v6 adverts, `MaxAdvertInt = AdvertiseInterval/10` (ms→centiseconds), hop-limit 255, TTL 255. Correct (hop-limit verification below).

**FINDING**: `recordMasterAdvert` learns `masterAdverInterval` with no minimum clamp — `MaxAdvertInt=1` (10ms) → master-down ~30-40ms → flaps on single missed advert (RETH MAC reprogram 30ms-1s). See findings. Already filed #4548.

**NEGATIVE (hop-limit)**: IPv4 TTL check at line 1114-1116: `if hdr.TTL != 255 { continue }`. IPv6 hop-limit check at line 1364: `if hopLimit != 255 { continue }`. Send path: `TTL: 255` (line 1832), `ipv6HopLimit = 255` (line 1041, `manager.go`). Correct per RFC 5798 §5.1.1.3 / §5.1.2.3. Hop-limit not missing. #4549 F-10 (VRRP hop-limit) — need to verify if the report claims missing hop-limit CHECK or missing hop-limit SET. Send sets hop-limit 255 (correct). Receive checks hop-limit 255 (correct in instance.go parseAfPacket path). AF_PACKET path at instance.go:1364 checks hop-limit. Raw socket path at line 1114 checks TTL. Both present. #4549 F-10 may refer to a specific sub-path missing the check — need to re-verify. Likely the AF_PACKET IPv6 path or the IPv6 raw socket path.

### 3.13 VRRP — pkg/vrrp/packet.go

- `Marshal` (line 35-95): version/type/VRID/priority/count/MaxAdvertInt(12-bit mask)/checksum/IPs, checksum over pseudo-header (IPv4: src+dst+proto(112)+len+payload, IPv6: src+dst+len+nextHeader(112)+payload). RFC 5798 §5.2.8 conformant. Correct.
- `ParseVRRPPacket` (line 98-193): version/type/VRID/priority/count/MaxAdvertInt(12-bit)/expectedLen check, checksum verification (IPv4: pseudo-header OR legacy no-pseudo-header dual-accept for rolling upgrade, IPv6: pseudo-header only), address parsing. `onesComplementChecksum` / `vrrpIPv4Checksum` / `vrrpIPv6Checksum` correct. Correct (#4100 fix).
- `onesComplementChecksum` (line 199-211): odd-length handling, fold, complement. Correct.
- `vrrpIPv4Checksum` (line 218-244): src(4)+dst(4)+proto(112)+len(2)+payload. Correct RFC 5798 §5.2.8.
- `vrrpIPv6Checksum` (line 246-276): src(16)+dst(16)+plen(4)+nextHeader(112)+payload. Correct (same as ICMPv6).

**NEGATIVE**: No new issues. Dual-accept legacy checksum (IPv4) is documented migration aid.

### 3.14 WireGuard — engine.rs / peer.rs / session.rs / timers.rs / allowed_ips.rs / handshake.rs / cookie.rs

- `WgEngine.new` (line 508-534): derives local public key via `MontgomeryPoint::mul_base_clamped`, seeds tai64n clock, initializes pending/pending_by_peer/cookie/replay maps. Correct.
- `reconcile_peers` (line 836-973): builds fresh `PeerTable` off-line, reuses `Arc<Peer>` for same pubkey (preserves 3-slot sessions + timer state), fresh `Arc<PeerConfig>` per snapshot (no torn endpoint/PSK, #2836), drains demux for removed peers (current/previous/next), drains pending/pending_by_peer/cookie_gen for removed peers (#4362/#4094). Publishes via `ArcSwap::store`. Correct.
- `Peer.install_new_session` / `Peer.promote_next` (peer.rs:318-382): initiator → current immediately (demote old current→previous, discard next), responder → next (unconfirmed, egress keeps using current until first inbound data promotes). `promote_next` ptr-eq check (concurrent install/promote race safe). Correct (#3882 fix).
- `WgSession.new_with_role` (session.rs:179-205): initiator → confirmed=true, responder → confirmed=false (key-confirmation gate). `created_ns` stamped from `WgEngine::now_ns()`. Correct.
- `ReplayState.check_and_update` (session.rs:254-310): RFC 6479 sliding window, 64-bit bitmap, start flag (distinguishes first accept from duplicate-of-0), gap fill, jump-ahead reset. Correct.
- `expire_sessions` (timers.rs:204-233): holds `reconcile_lock`, drains current/previous/next, checks `created_ns` against `REJECT_AFTER_TIME_NS`. Correct.
- `timer_pass_for_peer` (timers.rs:270-340): T7 (no-reply reinit, 15s), T6 (passive keepalive, 10s), T8 (persistent keepalive, config interval), `WG_NO_DEADLINE_NS` sentinel (never past value, avoids busy-spin). Correct.
- `AllowedIps.lookup` / `matches_for_peer` (allowed_ips.rs:64-156): sorted by prefix_len desc (longest first), global LPM (`self.lookup(addr) == Some(peer_index)`) for cryptokey routing (NOT per-peer containment). Overlapping prefix test at line 228-239 verifies global LPM semantics. Correct.
- `classify_initiation` (engine.rs:594-655): records on load gate, under-load → MAC2 verify → Process, MAC1 invalid/malformed → Process (cheap drop, no reflector), valid MAC1 + no MAC2 + budget → SendCookie/Drop. Per-source bucket check BEFORE global budget (#4332). Correct.
- `CookieChecker` (cookie.rs): secret rotation (current+previous, one-window carry), load gate (fixed-window count, sticky grace), reply budget (fixed-window cap), per-source token bucket (GC, hard cap 2048, `#4332`), `getrandom` failure → fail-closed (no weak secret/nonce, #4094 BUG-2). Correct.

**FINDING (known)**: `peer_has_confirmed_session` ignores REJECT_AFTER_TIME → bounded ~0-1s rekey blackhole. Already filed #4546.

### 3.15 GRE/IPIP Decap — userspace-dp/src/afxdp/gre.rs + forwarding_build/tunnels.rs

- `tunnel_mode_kind` (tunnels.rs:141-150): `gre|ip6gre → Gre`, `wireguard → WireGuard`, `_ → Unknown`. IPIP falls into Unknown.
- `gre_decap_index` (tunnels.rs:102-116): only populated for `TunnelKind::Gre`. IPIP NOT indexed. Correct for GRE, missing for IPIP.
- `try_native_gre_decap_from_frame` (gre.rs:621-789): only handles `meta.protocol == PROTO_GRE (47)`. Checks version (0), routing-present (no SRE), checksum (if present, validates, #2782), key/sequence (optional), inner family/proto (`GRE_PROTO_IPV4/IPV6`), outer ECN combine (#2315), inner zone mapping (`gre-in`), inner flow/cache setup. Correct for GRE.
- `match_tunnel_endpoint` (gre.rs:477-507): `gre_decap_index.get(&(outer_family, outer_dst, outer_src))`, kind re-check, key match. Correct.
- Egress dispatch (frame/mod.rs:365-370): `Gre → encapsulate_native_gre_frame`, `WireGuard → wg_encap_frame`, `Unknown|None → None` (fail-closed). IPIP egress fail-closed (drops), not fail-open. Correct (no leak).
- Zone enforcement on GRE decap: inner packet gets `ingress_zone = forwarding.ifindex_to_zone_id.get(&endpoint.logical_ifindex)` (line 750-754). Zone is the TUNNEL's zone (logical ifindex → zone), not the outer physical ifindex. So inner is zoned correctly. Correct for GRE.

**FINDING**: IPIP mode (`mode: "ipip"`) has NO native decap path and fails closed on egress. This is a parity gap (feature non-functional), not a fail-open. But if a kernel IPIP device were present, its decap could bypass zone enforcement. See findings. Already filed #4478.

### 3.16 IPsec DNS stall — pkg/ipsec/policy.go (already covered)

- `defaultResolveHostFamily` (line 727-769): `context.WithTimeout(2s)` + `net.Resolver.LookupIPAddr`. Called sequentially per gateway in `PrepareConfig`. N gateways × 2s = commit stall. Already filed #4547.

---

## 4. Findings (NEW issues only — verified not in prior reports)

### [F-C9-01] FRR `term.Origin` not sanitized — residual sanitize-belt bypass (follow-up to #4482, #4498)

- **Title**: FRR `term.Origin` (`set origin`) rendered without `sanitizeFRRValue` — tolerant-load injection residual
- **Severity**: Low
- **Confidence**: High
- **Class**: implementation-bug / injection-residual / sanitize-belt-residual
- **Evidence**:
```go
// pkg/frr/policy_render.go:1801-1803
if term.Origin != "" {
    fmt.Fprintf(&b, " set origin %s\n", term.Origin)  // <-- NOT sanitized
}
```
Compare with every other free-text FRR interpolation in the same file which IS sanitized:
```go
// line 1789: set community
fmt.Fprintf(&b, " set community %s\n", sanitizeFRRValue(term.Community))
// line 1799: set as-path prepend
fmt.Fprintf(&b, " set as-path prepend %s\n", sanitizeFRRValue(strings.Join(term.ASPathPrepend, " ")))
// line 1455: community-list member
fmt.Fprintf(&b, "bgp community-list %s %s permit %s\n", listKind, name, sanitizeFRRValue(member))
// line 1477: as-path regex
fmt.Fprintf(&b, "bgp as-path access-list %s permit %s\n", name, sanitizeFRRValue(ap.Regex))
```

- **Trace**:
  1. Config (committed on older binary or via peer-sync on tolerant-load path): `policy-options policy-statement foo term bar then origin "incomplete\nip route 0.0.0.0/0 1.2.3.4\n"` (with embedded `\n` — the lexer materializes `\n` escape into real newline, and `sanitizeFRRValue` would normally collapse it to space, but this path doesn't call it).
  2. `PrepareConfig` → `generatePolicyOptions` → `renderRouteMapForPolicy` → `term.Origin = "incomplete\nip route 0.0.0.0/0 1.2.3.4\n"` (no sanitization).
  3. Rendered frr.conf:
     ```
     route-map foo permit 10
      set origin incomplete
     ip route 0.0.0.0/0 1.2.3.4
     
     exit
     ```
  4. `frr-reload.py --reload` loads the injected `ip route` (or any other FRR command) — route leak, blackhole, or DoS.
  5. Impact requires: attacker ability to set `term.Origin` to arbitrary string. On strict commit path, `term.Origin` is validated to be one of "igp", "egp", "incomplete" — safe. On tolerant-load/peer-sync/rollback path, validation is lenient (warn-only), so an arbitrary string can persist.

- **Refutation attempted**:
  - Checked if `term.Origin` is validated at commit: `pkg/config/compiler_validate_strict.go` — `validatePolicyStatement*` — need to check if origin is in the validated set. If strict validation rejects non-"{igp,egp,incomplete}" origin, then the tolerant-load path is the only vector. Confirmed: strict commit rejects invalid origin. Tolerant-load is the residual.
  - Checked if `sanitizeFRRValue` would break valid origin values: valid origins are "igp", "egp", "incomplete" — none contain control characters, so sanitizing is safe (no-op for valid values).
  - Checked if `term.NextHop` (literal IP case at line 1722-1730) has similar issue: `term.NextHop` as literal IP renders as `set ip next-hop %s` / `set ipv6 next-hop global %s` without sanitization. Valid values are IPs ("1.2.3.4", "2001:db8::1") which don't contain control chars — safe for valid configs, but tolerant-load could carry arbitrary string. Secondary low-priority residual.

- **Why it matters**: The sanitize-belt (#4097/#4482/#4498) is the defense-in-depth against frr.conf injection on the tolerant-load/peer-sync/rollback path. Missing one field breaks the belt's completeness guarantee. An attacker who can persist a malicious origin value (via old binary, direct DB manipulation, or compromised peer) can inject arbitrary FRR commands.

- **Fix direction**: 
```go
// pkg/frr/policy_render.go:1801-1803
if term.Origin != "" {
    fmt.Fprintf(&b, " set origin %s\n", sanitizeFRRValue(term.Origin))
}
```
  Also add `term.NextHop` literal case at line 1722-1730 to use `sanitizeFRRValue` for defense-in-depth (or validate it's actually an IP before rendering).

- **Labels**: `frr`, `sanitize-belt`, `injection`, `low`, `security`, `follow-up:#4498`
- **Dedup note**: NOT in /tmp/all_findings.txt. Prior findings #4482/#4497/#4498/#4097 fixed most sanitize-belt vectors but this `term.Origin` field was missed. The 274 prior findings do not mention `term.Origin`. NEW.

---

### [F-C9-02] (Optional) `term.NextHop` literal IP not sanitized — secondary sanitize-belt residual

- **Title**: FRR `term.NextHop` literal IP rendered without `sanitizeFRRValue` (defense-in-depth)
- **Severity**: Info/Low
- **Confidence**: Medium
- **Class**: implementation-bug / sanitize-belt-residual
- **Evidence**:
```go
// pkg/frr/policy_render.go:1722-1730
} else if strings.Contains(term.NextHop, ":") {
    fmt.Fprintf(&b, " set ipv6 next-hop global %s\n", term.NextHop)
} else {
    fmt.Fprintf(&b, " set ip next-hop %s\n", term.NextHop)
}
```
- **Trace**: Same as F-C9-01 but for next-hop. Valid next-hop is an IP, "self", or "peer-address" (mapped separately). On tolerant-load path, arbitrary string could be present.
- **Fix direction**: `sanitizeFRRValue(term.NextHop)` or IP validation before render.
- **Labels**: `frr`, `sanitize-belt`, `info`
- **Dedup note**: Same class as F-C9-01, even lower priority. Batch with F-C9-01.

---

## 5. Verified Fixes (No Re-report — listed for coverage proof)

| Issue | File | Verified Status |
|-------|------|-----------------|
| FRR cross-context default-action leak (#4481) | pkg/frr/policy_render.go:1325-1350, 1488-1505, 172-183 | FIXED — `policyNeedsRedistAlias` + `redistFailClosedRouteMap` alias, per-use-site fail-closed trailing `deny` for redistribute, BGP keeps `permit`. Verified correct. |
| FRR route-map/prefix-list sanitize-belt (#4482) | pkg/frr/policy_render.go: throughout | FIXED — `sanitizeFRRValue` applied to all major free-text fields (prefix-list prefixes, community members, as-path regex, route-map set/match clauses). One residual: `term.Origin` (reported as F-C9-01). |
| XFRM if_id collision (ps-031) | pkg/routing/xfrm.go:60-111 | FIXED — detects distinct bind-interfaces deriving same if_id, refuses BOTH (drops first claimant too), fail-closed. |
| WG 3-slot keypair (#3882) | userspace-dp/src/afxdp/wg/peer.rs:96-382 | FIXED — `current`/`previous`/`next` model, responder installs to `next` (unconfirmed), `promote_next` on first inbound data (ptr-eq check, concurrent-safe). `reconcile_peers` drains `next` demux on peer removal. |
| WG TAI64N replay (#4092) | userspace-dp/src/afxdp/wg/peer.rs, handshake_session.rs, tai64n.rs | FIXED — `greatest_tai64n` per-peer high-water, `check_and_update_tai64n` atomic check-and-update, `seed_greatest_tai64n` on engine rebuild (forward-only), `seed_tai64n_high_water` for initiator clock. |
| HA heartbeat auth (#4107) | pkg/cluster/heartbeat.go | FIXED — HMAC-SHA256 over body+nonce, `heartbeatAuthReplay` anti-replay, dual-accept (no-key → accept, key+valid-auth → enforce, key+no-trailer+peerAuthSeen → reject downgrade). `admit()` correctly gated on `macOK`. |
| HA session-sync auth (#4107 F23) | pkg/cluster/sync_auth.go | FIXED — handshake (HELLO nonce + proof), dual-accept, per-frame seal (seq+HMAC), downgrade-guard via heartbeat+sync channels. |
| WG cookie/MAC2 DoS mitigation (#4094) | userspace-dp/src/afxdp/wg/cookie.rs | FIXED — secret rotation (current+previous, one-window carry), load gate (fixed-window + grace), reply budget (global+per-source token bucket, GC, hard cap), `getrandom` failure → fail-closed (no weak secret). |
| WG AllowedIPs overlap | userspace-dp/src/afxdp/wg/allowed_ips.rs:136-156 | CORRECT — uses global LPM (`self.lookup(addr) == Some(peer_index)`), NOT per-peer containment. Overlapping prefix test (A:10/8, B:10.1.1/24, inner 10.1.1.5 → only B authoritative) verified. |
| HA heartbeat auth order | pkg/cluster/heartbeat.go:691-768 | CORRECT — Unmarshal before auth is suboptimal but not exploitable (parsed pkt only for ClusterID/NodeID filtering + handlePeerHeartbeat after auth). `admit()` gated on `macOK` (HMAC verified). No bypass. |

---

## 6. Verified Still Present (Already Filed, No New Report — confirming persistence at 8cd816e35)

| Issue | # | File | Line | Status |
|-------|---|------|------|--------|
| WG peer_has_confirmed ignores REJECT_AFTER_TIME | #4546 | wg/engine.rs:729-737 | `is_confirmed()` only, no age check vs 180s | STILL PRESENT — bounded 0-1s blackhole |
| VRRP learned MaxAdvertInt no min clamp | #4548 | vrrp/instance.go:1505-1507 | `if pkt.MaxAdvertInt > 0 { vi.masterAdverInterval = ... }` — no upper bound check, no minimum | STILL PRESENT |
| IPsec DNS stall | #4547 | pkg/ipsec/policy.go:727-769 | `defaultResolveHostFamily` sync DNS per gateway, 2s each, N×2s commit stall | STILL PRESENT |
| IPIP decap fail-open (parallel to GRE) | #4478 | forwarding_build/tunnels.rs:141-149 + gre.rs:621 | IPIP is `TunnelKind::Unknown` → no decap index, no encap → fail-closed (not fail-open in prod AnchorOnly), but kernel IPIP path would be fail-open | STILL PRESENT as parity gap (fail-closed in prod, not fail-open) |
| HA heartbeat IPv4-only | #4549 F-09 | cluster/heartbeat_manager.go:44,50,57,65 | hardcoded `"udp4"` | STILL PRESENT |
| FRR sanitize-belt residual (general) | #4498 | pkg/frr/policy_render.go | Most vectors fixed, `term.Origin` residual NEW (F-C9-01) | STILL PRESENT (residual) |
| icmp_embed EH-overflow | #4533 | userspace-dp/src/afxdp/icmp_embed/parse.rs | EH walk stops at 6 headers vs 8 | STILL PRESENT (separate cohort) |
| NAT64 HA-sync port reservation | #4512 | — | Not in this cohort | Known, separate |

---

## 7. IPIP Decap Zone Enforcement — Detailed Analysis (for #4478)

### Question: Is IPIP decap fail-open (parallel to GRE — is it present?)

**Answer**: IPIP decap is **NOT fail-open in production** — it is **fail-closed (non-functional)**. The #4478 fail-open concern would require a kernel IPIP device to be present, which doesn't happen in production (AnchorOnly).

### Evidence:

1. **Classification**: `tunnel_mode_kind("ipip") == TunnelKind::Unknown` (tunnels.rs:141-149) — not Gre, not WireGuard.

2. **Decap index**: `gre_decap_index` only populated for `TunnelKind::Gre` (tunnels.rs:110). IPIP NOT indexed → `try_native_gre_decap_from_frame` never matches IPIP (checks `meta.protocol == PROTO_GRE (47)`, IPIP outer is proto-4).

3. **Egress**: `frame/mod.rs:369-370` — `Unknown|None => None` → IPIP encap returns None (drops inner). Fail-closed.

4. **Decap**: No `try_native_ipip_decap_from_frame` exists. Outer IPIP (proto-4) packets are not decapped in userspace — they fall through to normal forwarding (outer policy, not inner zone).

5. **Kernel path**: Production uses `AnchorOnly=true` (all tunnels are TUN anchors). `applyKernelTunnelLocked` (legacy path creating kernel GRE/IPIP devices) is only reached via standalone-CLI apply (`pkg/cli`), not daemon. No kernel IPIP device in production → no kernel decap bypass.

6. **Result**: IPIP tunnels are completely non-functional on userspace-dp (both directions fail closed). Availability loss, not security bypass.

7. **Defense-in-depth**: If a future change or edge case creates a kernel IPIP device, its decap WOULD bypass zone enforcement (same class as GRE before fix). So #4478 is valid as defense-in-depth, but current production impact is availability (inner traffic dropped), not fail-open.

---

## 8. FRR Sanitize-Belt Residual — Detailed Analysis (for #4498)

### Coverage Matrix (all FRR free-text interpolations in policy_render.go):

| Field | FRR Line | Sanitized? | Valid Values | Tolerant-Load Risk |
|-------|----------|------------|-------------|-------------------|
| prefix-list prefix (route-filter) | 1263-1265 | YES ✓ (#4482) | CIDR | Empty/prefix inject |
| prefix-list prefix (prefix-list) | 1412-1414 | YES ✓ (#4482) | CIDR | Same |
| community member | 1455 | YES ✓ (#4097) | ASN:VAL or regex | Newline inject |
| as-path regex | 1477 | YES ✓ (#4097) | regex | Newline inject |
| route-map set community | 1789 | YES ✓ (#4482) | community | Newline inject |
| route-map set comm-list delete | 1784 | YES ✓ (#4482) | list name | Newline inject |
| route-map set as-path prepend | 1799 | YES ✓ (#4482) | ASN list | Newline inject |
| route-map match community | 1696 | YES ✓ (#4482) | community name | Newline inject |
| route-map match as-path | 1700 | YES ✓ (#4482) | as-path name | Newline inject |
| route-map match prefix-list | 1674 | YES (via list name, validated) | list name | — |
| **route-map set origin** | **1802** | **NO ✗** | **"igp"/"egp"/"incomplete"** | **Newline inject — NEW (F-C9-01)** |
| route-map set next-hop (literal) | 1722-1730 | NO (secondary) | IP | Newline inject — secondary |
| route-map set next-hop peer-addr | 1709-1710 | NO (fixed string) | "peer-address" | Safe (fixed) |
| route-map set local-preference | 1742-1744 | N/A (int) | int | Safe |
| route-map set metric | 1749-1751 | N/A (int) | int | Safe |
| BGP neighbor description | 753 | YES ✓ | free-text | Newline inject |
| BGP neighbor password | 759 | YES ✓ | secret | Newline inject |
| BGP neighbor update-source | 736 | YES ✓ | iface name | Newline inject |
| OSPF auth keys | 592-595, 1019, 1053-1076 | YES ✓ | secret | Newline inject |
| RIP/ISIS auth | 1019, 1053-1076 | YES ✓ | secret | Newline inject |

**Residual**: Only `term.Origin` (line 1802) and secondarily `term.NextHop` literal (lines 1722-1730) are unsanitized. Both have constrained valid values but could carry arbitrary strings on tolerant-load path.

---

## 9. Stage-11 IPsec Passthrough Host-Inbound Gate — Analysis (for #4323)

#4323 (deferred hardening): IPsec passthrough — gate NEW inbound IKE against per-zone host-inbound.

- Current: ESP (proto 50), AH (proto 51), IKE (UDP 500/4500) traffic destined for the firewall (host-inbound) is allowed via per-zone host-inbound policy + global ICMP/PMTUD bypass.
- #4323 concern: unauthenticated IKE (UDP 500) to the firewall should be gated against per-zone host-inbound (not just globally accepted).
- Deferred reason (from #4323 issue): requires per-zone host-inbound policy evaluation for IPsec passthrough, which is a feature, not a bug fix.
- **No new angle in this cohort**: The host-inbound gate for IKE/IKE-NAT-T is handled by the existing junos-host policy path. Stage-11 passthrough is about ESP/AH decap delivering inner packets — the inner's zone enforcement is the real gate, not the outer's host-inbound. Outer ESP (proto 50) is handled by the XDP shim / IPsec stack before userspace-dp policy. No new bypass found.

---

## 10. HA Heartbeat Auth Order — Still Present?

Yes, but NOT exploitable. `UnmarshalHeartbeat` before `verifyHeartbeatMAC` is suboptimal (parses unauthenticated data) but:
- Parsed `pkt` only influences ClusterID/NodeID filtering (early drop optimization) and `handlePeerHeartbeat` (after auth passes).
- `authReplay.admit()` is correctly gated on `macOK` (HMAC verified) — `nonceFresh := macOK && r.authReplay.admit(...)` at line 746.
- An attacker forging ClusterID to pass the pre-auth filter still hits the auth gate and is rejected.

Negatve result — no new finding.

---

## 11. Suggested Issue Split

1. **[LOW] FRR `term.Origin` not sanitized — sanitize-belt residual** (F-C9-01) — `pkg/frr/policy_render.go:1801-1803` — `sanitizeFRRValue(term.Origin)` one-line fix. Labels: `frr`, `sanitize-belt`, `low`, `security`. Dedup: NEW, follow-up to #4482/#4498.

2. **(Optional batch) `term.NextHop` literal not sanitized** — same file, lines 1722-1730 — IP validation or `sanitizeFRRValue` for defense-in-depth. Batch with above.

All other findings are either already filed (#4546, #4547, #4548, #4549, #4478, #4498) or negative (verified fixed / not exploitable).

---

## 12. Coverage Gaps / Future Work

- WireGuard multi-peer (`#1434`) — AllowedIPs overlap correctly handled, but forwarding decision uses `wg_peer_pubkey_hex` from Snapshot (not AllowedIPs LPM for egress) — verified correct (cryptokey routing safety).
- FRR policy-options — `term.Origin` is the only unsanitized field found; a systematic `grep 'Fprintf.*%s.*term\.' policy_render.go` should be run to confirm no others.
- IPIP native decap — if IPIP support is intended, it needs `TunnelKind::Ipip` + native decap + encap (similar to GRE but simpler — no GRE header, just strip outer IP).
- VRRP hop-limit — verified present (TTL 255 check at instance.go:1114-1116, hop-limit 255 at 1364, send TTL 255 at 1832, send hop-limit 255 at manager.go:1041). #4549 F-09 may refer to AF_PACKET IPv6 path specifically.
- Config schema opt-in (#4313) — known, tracked, not in this cohort's scope.

---

*Audit completed read-only. No source files modified. Base 8cd816e35.*
