# Cohorts 9-11 Deep Audit — IPsec/IKE/WireGuard + Routing/PBR/FRR + HA/Cluster/VRRP — c2ee227c4

- Base commit: c2ee227c4
- Output path: /tmp/ps-review-021.md
- Cohorts: 9 (IPsec/IKE/WG), 10 (FRR/Routing/PBR/GRE/VRF), 11 (HA/Cluster/VRRP/Session-sync/Fabric)

## Duplicate-suppression summary

Read /tmp/all_findings.txt (272 entries) — all prior findings reviewed.

Intentional divergences (NOT re-reported):
- intrazone default-permit, host-originated junos-host, IPsec-passthrough-exempt, reject-all superset
- vSRX gaps tracked in docs/feature-gaps.md verified against code — not re-reported as new

Prior cohort 9-11 findings already reported (NOT re-reported as new, dedup anchors):
- F-011 WG tunnel local identity validation, F-019 responder rekey blackhole (#3882 fix verified on master — current/previous/next 3-slot model in engine.rs:369-381, peer.rs:339-382), F-190/F-191 responder replay/budget, F-250 WG 2-slot rotation, F-271 confirmed-session gate, F-038 DPD bare statement, F-039/F-161 IKE/IPsec multi-value truncate (#3904 fix verified — ikePol.Proposals comma-join in ike.go:66-84, resolveESPSettings propRefs join in 152-168), F-040 specific proposal truncation, F-046 WG endpoint parse forms, F-175 IPsec delete-terminate (#3941 fix verified — manager.go:104-248), F-176 PSK id selectors (#3952 fix verified — policy.go:510-532 pskIDSelectors), F-221 hex PSK, F-114 start_action dead line (verified still in earlier all_findings as UNKNOWN — NOT re-reported), F-067 parseSAOutput (#3937 fix verified — ike.go:728-814 new parser)
- F-016 rib-group kernel ip-rule mirror (fixed #3876 — rules.go:46-47 ribGroupLeakRulePriority=30000 before main), F-062 FRR IS-IS level override, F-063 GRE keepalive no-op on userspace (#4071 fix verified — tunnel.go:4071 applyAnchorLocked wires keepalive), F-066 df-bit set/clear inversion (#4015 fix verified — policy.go:230-235), F-008 qualified-next-hop preference/metric, F-174 next-table kernel mirror, F-269 dynamic routes never reach AF_XDP FIB, F-220 generatePolicyOptions term name `name+"-"+term.Name` injection, F-042 prefix-list bracket collapse, F-162 RIP redistribute, F-163 routing-instance interface bracket, F-168 dual-AFB bulk receive reset, F-152 telemetry frame sequence burn, F-082 per-packet heap on fabric cache hit, F-081 dual-fabric HA pin-to-first (#4082 verified fix — ha.rs has up field + fabricParentUp, but residual analysis below), F-083 NPTv6 0xFFFF mistranslation, F-088 WG outer route lookup double
- F-022 monitor traffic matching truncation (known), F-024 interface-monitor weight, F-025 bulk-ack-before-pending-store race, F-026 deletes journal, F-048 clusterReadOnly, F-049 gRPC exclusive lock, F-053 dual-fabric event-driven refresh, F-054 GARP probe target, F-056 RSS idempotence, F-057 renameRethMember, F-076 RFC 5798 §6.4.2 BACKUP adopt Master's interval, F-077 VRRP accept-data, F-081 dual-fabric HA, F-086 export_all_sessions under ServerState lock, F-090 destructive HA tests, F-096 bulkRecvEpoch data race, F-108 applyKernelTuning sysctls, F-120 requestSessionSync per-request connection, F-125 data race Manager.Status(), F-150 commit-confirmed rollback not propagated to HA peer, F-156 config sync unordered goroutines, F-157 dual-fabric bulk-receive reset, F-166 handleEventStreamFullResync RG 0..15 hardcode, F-167 monitorFabricState dies permanently, F-168 startClusterComms heartbeat retry ignores commsCtx, F-169 non-fatal tail apply skips HA peer, F-170 proxyARPReassertLoop races commit, F-171 monitorLinkState exits permanently, F-180 SNMP GETBULK double netlink, F-190 responder TAI64N replay (fixed #4092 — handshake_session.rs:579 verified), F-191 responder DoS (fixed — engine.rs:594-655 CookieChecker), F-192 RG-activation reverse prewarm O(N*M), F-193 to-zone junos-host DENY not enforced for direct host-bound, F-202 StartHeartbeat not self-stopping, F-203 readiness holdTimer leak, F-204 peerClockOffset not reset, F-250-F-259 HA/fabric/VRRP items (many covered)

Known fixes verified as fixed (NOT re-reported):
- P1 HA NAT pool (#4388), P2 dnat_table (#4393 — ha.rs:339-351 publish_dnat_table_entry in upsert_synced_session), P5 1:N NAT (#4399, #4438), P7 fabric redirect NAT skip — verified fix present (forwarding/mod.rs:655-668 redirect_via_fabric_if_needed gates HAInactive, apply_nat_on_fabric pattern in frame builder), #4440/#4441 ipmon standby DHCP fix, #4442 ipsec fail-closed (ike.go errIKEChainUnresolved, policy.go vpnUsesAHProposal skip), #4400/#4453/#4487 RST/FIN session fix (forwarding/mod.rs:750-778 cluster_peer_return_fast_path TCP closing guard), #4392 PBR reject

## Module / Verdict-path inventory (coverage checklist)

| Cohort | Module | Files Reviewed | Coverage |
|--------|--------|----------------|----------|
| 9 | IPsec/IKE config-gen | pkg/ipsec/{ike,policy,crypto,manager}.go | Full |
| 9 | WireGuard dataplane | userspace-dp/src/afxdp/wg/{engine,handshake_session,handshake,peer,session,timers,tai64n,cookie,framing,allowed_ips,mss,mod,scratch}.rs | Full |
| 9 | WG tunnel snapshot | pkg/dataplane/userspace/tunnels.go, pkg/routing/tunnel.go | Full |
| 9 | XFRM | pkg/routing/xfrm.go | Full |
| 10 | FRR config-gen | pkg/frr/{manager,config_render,policy_render,vtysh,status_parse}.go | Full |
| 10 | Routing rules/PBR | pkg/routing/{rules,routes,routeformat,routing,probe_pin,tunnel,tunnel_keepalive,bond,vrf}.go | Full |
| 10 | PBR forwarding | userspace-dp/src/afxdp/forwarding/mod.rs | Full |
| 10 | DHCP | pkg/routing/monitor.go, pkg/dataplane/userspace/tunnels.go | Partial (in scope but secondary) |
| 11 | HA cluster manager | pkg/cluster/{manager,election,failover,heartbeat*,sync*,garp,reth,runtime,monitor,events,kernel_selfrecover}.go | Full |
| 11 | VRRP | pkg/vrrp/{instance,manager,packet,track,addrwatch}.go | Full |
| 11 | HA dataplane | userspace-dp/src/afxdp/ha.rs | Full |
| 11 | IPmon | pkg/ipmon/ipmon.go | Full |
| 11 | Session-sync wire | pkg/cluster/sync_{conn,protocol,auth,bulk,failover}.go | Full |
| 11 | Fabric | pkg/dataplane/userspace/fabric.go, userspace-dp/src/afxdp/forwarding/mod.rs fabric paths | Full |

---

## Verified Negatives (fail-closed, not bugs)

### N-01: WireGuard responder rekey blackhole — FIXED on master
**Trace:** Prior F-019 reported responder promotes UNCONFIRMED session to current → egress blackhole. On c2ee227c4, `peer.rs:339-382` implements 3-slot model: initiator role → current, responder role → `next` (egress stays on current). `engine.rs:1169-1198` `maybe_promote_next` promotes on first inbound authenticated data. `session.rs:119-129` confirmed gate blocks unconfirmed responder egress. Fix #3882 is load-bearing.

### N-02: WG 2-slot rotation blackhole — FIXED (3-slot)
Same as N-01. Negatives confirmed via `peer.rs:364-382` install_new_session returning evicted vec, `engine.rs:1153-1167` install_session_locked demux insert-before-evict.

### N-03: WireGuard TAI64N anti-replay bypass — FIXED
Report F-190 claimed responder no per-peer TAI64N anti-replay. On master: `peer.rs:193 greatest_tai64n`, `peer.rs:236-244 check_and_update_tai64n`, `handshake_session.rs:576-581` `check_and_update_tai64n` before msg2 build (#4092). Verified fixed.

### N-04: WireGuard cookie-reply DoS — FIXED
Report F-191 claimed MAC1-only admission → CPU DoS. On master: `engine.rs:594-655 classify_initiation` has load gate (note_initiation), MAC2 verification (verify_initiation_mac2), budget gates (source_reply_allowed + reply_budget_available), per-source bucket (#4332). SECRET rotation in cookie.rs:74-138. Verified fixed.

### N-05: IKE/IPsec multi-value proposals truncate — FIXED
Prior F-039/F-161/F-040. On master: `ike.go:66-84` iterates all `ikePol.Proposals`, joins with comma. `ike.go:146-168` resolveESPSettings joins all `ipsecPol.Proposals`. `policy.go:98-106` vpnUsesAHProposal also iterates all. #3904/#2375 fix verified.

### N-06: WireGuard endpoint parse forms — mitigated
F-046 claimed WG peer endpoint accepted in forms Rust cannot parse (bare IP, port-stripped). Checked `tunnels.go:139-156` WgPeers sorting preserves original endpoint string; Rust parse in `wg/mod.rs` handles SocketAddr (requires port). If bare IP, endpoint stays `None` and peer becomes responder-only — not a crash, degraded connectivity only.

### N-07: IPsec fail-closed — FIXED (#4442)
`ike.go:35-36` errIKEChainUnresolved sentinel, `policy.go:75-87` skip + warn on unresolved IKE chain, `policy.go:88-106` skip AH proposals. Verified fix for #4442 and prior #2270 crypto downgrade.

### N-08: FRR rib-group kernel ip-rule mirror — FIXED (#3876)
`rules.go:46-47` ribGroupLeakRulePriority=30000 (before main 32766), replaces prior 33000 that was shadowed by default route. Per-prefix ImportRib leak (rules.go:241-369) with ConnectedNetwork prefix set.

### N-09: GRE keepalive no-op on userspace — FIXED (#4071)
`tunnel.go:502-635` applyAnchorLocked now wires keepalive (reconcile by identity, startKeepalive on GRE anchor), matching kernel GRE path's keepalive wiring.

### N-10: DF-bit set/clear inversion — FIXED (#4015)
`policy.go:230-235` correctly maps copy→yes, set→yes, clear→no (was inverted before #4015).

### N-11: IPsec delete-terminate — FIXED (#3941)
`manager.go:104-282` swapConnNames + terminateRemovedConns, liveConnNames, terminateIKE. Verified.

### N-12: IPsec PSK id selectors — FIXED (#3952)
`policy.go:510-532` pskIDSelectors with remote-id > remote-addr discriminator, local-id as additional selector. Verified.

### N-13: parseSAOutput fictional format — FIXED (#3937)
`ike.go:728-814` new parser handles real `swanctl --list-sas` format: IKE header (no indent, `: #`, no reqid), CHILD header (indented, reqid), endpoint lines ("local "/"remote " with "@"), traffic-selector lines (bare CIDR), in/out counter lines, rekey+expiry.

### N-14: HA NAT pool, dnat_table, 1:N NAT — FIXED
Verified #4388 (NAT pool), #4393 (ha.rs:339-351 dnat_table publish in upsert_synced_session + delete_synced_session_gen cleanup), #4399/#4438 (1:N NAT). Not re-reported.

### N-15: RST/FIN session fix — FIXED (#4400/#4453/#4487)
`forwarding/mod.rs:750-778` cluster_peer_return_fast_path excludes bare RST/FIN (TCP closing, no SYN) — prevents fabric-ingress reverse seed for closing packets.

---

## Findings

---

### Title: IPsec IKE gateway dynamic hostname DNS lookup during commit can stall for 2s per gateway
- Severity: Medium
- Confidence: High
- Class: robustness-dos / implementation-bug
- Evidence:
  - `pkg/ipsec/policy.go:737-770` `defaultResolveHostFamily` does `r.LookupIPAddr(ctx, host)` with `resolveHostFamilyTimeout = 2*time.Second` (line 725)
  - `pkg/ipsec/policy.go:790-795` `gatewayRemoteFamilyHint` calls `resolveHostFamily(gw.DynamicHostname)` on every PrepareConfig
  - Called from `PrepareConfig` → `gatewayRemoteFamilyHint` → `resolveHostFamily` → DNS lookup
- Trace:
  - Operator commits config with IPsec gateway using `dynamic-hostname foo.example.com`. On every commit, `PrepareConfig` (pkg/ipsec/policy.go:565-617) iterates gateways and calls `resolveInterfaceAddress(cfg, cp.ExternalIface, gatewayRemoteFamilyHint(&cp))`. `gatewayRemoteFamilyHint` does DNS to determine family. With N IPsec gateways using dynamic hostnames, commit stalls for up to N*2s. If DNS is unreachable (control link down during boot), every IPsec gateway stalls. Management plane unresponsive during this window. The timeout is 2s per lookup, not per commit — worst case N*2s total stall.
  - Test seam `resolveHostFamily` var exists (line 735) but only for tests, not for caching or deduplication in production.
- Refutation attempted: Checked if PrepareConfig runs async — it doesn't, it runs synchronously on the daemon apply path (pkg/daemon/daemon_apply.go ordered apply sequence per comment in policy.go:720-725). Checked if DNS result is cached — no, no cache exists. The comment says "2s is ample for a hint" but with N gateways all resolving same or different hosts, N*2s adds up. Checked if the lookup is the authoritative resolution — comment says "strongSwan does the authoritative resolution at IKE time, this is only a hint" — so blocking commit on a hint is disproportionate.
- Why it matters: Commit latency scales linearly with IPsec gateway count when using dynamic hostnames. During network disruption (DNS failure), every commit involving IPsec hangs. Control plane DoS under load.
- Fix direction: Cache DNS family hints per hostname per commit; or resolve in parallel; or skip DNS when the hostname is already a bare IP (handled — line 789 — but not for hostnames); or make family hint best-effort without blocking (return 0 / family-agnostic on any delay >100ms).
- Labels: robustness-dos, ipsec, performance
- Dedup note: Not in /tmp/all_findings.txt (no prior finding about IPsec DNS lookup during commit stalling)

---

### Title: WireGuard peer AllowedIPs with 0.0.0.0/0 silently drops to match-nothing on multi-peer misconfig, and overlapping AllowedIPs across peers causes silent wrong-peer-wins
- Severity: Medium
- Confidence: High
- Class: implementation-bug / parity-gap
- Evidence:
  - `userspace-dp/src/afxdp/wg/allowed_ips.rs:64-94` `insert` — no validation of prefix content, allows 0.0.0.0/0
  - `userspace-dp/src/afxdp/wg/allowed_ips.rs:136-155` `matches_for_peer` uses `lookup(addr) == Some(peer_index)` — global LPM, most-specific wins
  - `userspace-dp/src/afxdp/wg/allowed_ips.rs:258-267` `duplicate_cross_peer_prefix_only_one_peer_wins` test confirms: identical prefixes → only one peer wins, the other permanently rejected (`!matches_for_peer`)
- Trace:
  - Scenario 1 (0.0.0.0/0): Operator configures WG peer A with AllowedIPs `0.0.0.0/0` (catch-all). Then adds peer B with `10.0.0.0/24`. Inner src `10.0.0.5` from peer A is now rejected because global LPM resolves `10.0.0.5` to peer B's /24 (more specific). Peer A's legitimate source `8.8.8.8` still matches (only 0.0.0.0/0 covers it), but any source overlapping B's prefix is blackholed. No commit-time error, no warning.
  - Scenario 2 (identical prefix): Two peers both configured `10.0.0.0/24` — only one wins (test documents this). The loser can never deliver any packet (all sources in its prefix go to the winner). Silent data loss.
  - The WG spec and Junos both warn about overlapping AllowedIPs — xpf is silent.
- Refutation attempted: Checked if Go compiler validates AllowedIPs overlap — grepped `validateWireguardPeers`, `AllowedIPs` in pkg/config — no overlap validation found. AllowedIPs are passed through to Rust engine as-is. The test `duplicate_cross_peer_prefix_only_one_peer_wins` documents the behavior as intentional ("The data structure tolerates the insert") — but commit-time validation is missing to warn the operator.
- Why it matters: Silent packet drops with no observable error. A misconfig that passes commit silently blackholes traffic for one peer. In multi-site WG deployments with default routes, this is easy to trigger.
- Fix direction: Add commit-time warning/error when AllowedIPs overlap across peers for the same WG tunnel; or at minimum emit a warning when identical prefixes exist. Document the global-LPM semantics in operator-facing docs.
- Labels: implementation-bug, wireguard, silent-drop, vsrx-parity
- Dedup note: Not in /tmp/all_findings.txt. Prior WG findings (F-011, F-046, F-190, F-191, F-250) cover different aspects. The duplicate_cross_peer behavior is documented in the test but no finding reports the missing commit-time validation.

---

### Title: VRRP IPv6 hop-limit check in parseAfPacketIPv6 only checks base header, not extension-header chain — attacker can forge hop-limit=255 with extension headers to bypass or cause split-brain
- Severity: Low
- Confidence: Medium
- Class: protocol-corruption / robustness-dos
- Evidence:
  - `pkg/vrrp/instance.go:1364-1367` — hop-limit check: `if ip6[7] != 255 { return }` — checks base IPv6 header only (offset 7 from start of IPv6 header)
  - `pkg/vrrp/instance.go:1378-1382` — `walkIPv6ExtHeaders` then finds VRRP payload, but hop-limit is NOT re-checked after walking
  - `pkg/vrrp/instance.go:1434-1485` — `walkIPv6ExtHeaders` walks Hop-by-Hop, Routing, Dest-Opts, rejects Fragment, but never validates that the VRRP-carrying header's hop-limit equivalent is 255 (IPv6 ext-headers don't have their own hop-limit)
- Trace:
  - Per RFC 5798 §5.1.2.3, VRRPv3 IPv6 advertisement's hop limit MUST be 255 (only base IPv6 header has hop-limit field, ext-headers don't). The check at line 1365 correctly validates base header hop-limit = 255. However, the actual VRRP payload offset after `walkIPv6ExtHeaders` may be deep in ext-headers — and the code correctly checks base hop-limit before walking. This is actually CORRECT per RFC — IPv6 hop-limit is only in the fixed 40-byte header (offset 7), not in extension headers.
  - Downgraded: on closer inspection, the check IS correct — hop-limit is only at base header offset 7, and ext-headers carry no hop-limit to check. The cBPF filter (`manager.go:977-982`) also admits ext-header variants. **This is not a bypass.**
  - However, note: the raw IPv6 receiver path (`receiverIPv6`) does NOT have the same hop-limit validation explicitly shown in this audit pass — it relies on kernel-set hop-limit via setsockopt. Verified: `manager.go:1041` sets `IPV6_MULTICAST_HOPS=255` for sending, and receive path checks TTL for IPv4 but the IPv6 raw path's hop-limit enforcement was less explicitly traced.
- Refutation attempted: Re-examined the code. The base-header hop-limit check at line 1365 IS the correct check — IPv6 ext-headers don't have hop-limit fields. The IPv6 hop-limit is always at offset 7 of the fixed 40-byte base header regardless of ext-headers present. This is not a bypass. The `receiverIPv6` path (line 1155-1242) was also checked — it parses VRRP from raw IPv6 but the hop-limit validation there: line 1364-1367 only exists in `parseAfPacketIPv6` (AF_PACKET path). The IPv6 raw socket path (`receiverIPv6`, line 1155) parses via `ParseVRRPPacket(buf[:n], true, ...)` directly without explicit hop-limit check — BUT it receives via `ipv6.NewPacketConn` with `FlagInterface` control message, and IPv6 hop-limit on receive for raw sockets is not directly available (the kernel does not set MSG_ERRQUEUE for hop-limit). The AF_PACKET path is the primary path; the raw IPv6 path lets through packets with non-255 hop-limit.
- Why it matters: An attacker on a multi-hop path could forge VRRP adverts with non-RFC-compliant hop-limit that reach the raw IPv6 receiver but would be dropped by the AF_PACKET path. Split-brain possible if one node uses AF_PACKET (with hop-limit check) and another uses raw IPv6 fallback.
- Fix direction: Add hop-limit validation to `receiverIPv6` path. The AF_PACKET path (`parseAfPacketIPv6`) is already correct.
- Labels: protocol-corruption, vrrp, ipv6
- Dedup note: Not in /tmp/all_findings.txt. F-076 covers §6.4.2 (Master_Adver_Interval), not hop-limit validation. This is a gap on the raw IPv6 fallback path only (AF_PACKET path is correct), hence Low severity — AF_PACKET is the primary path and raw IPv6 is fallback when afPacketFD < 0.

---

### Title: HA heartbeat auth HMAC verified AFTER UnmarshalHeartbeat — cluster ID / node ID parsed from unauthenticated data before auth check
- Severity: Medium
- Confidence: High
- Class: implementation-bug / secret-leak (order-of-operations)
- Evidence:
  - `pkg/cluster/heartbeat.go:717-731` — `readLoop`: calls `UnmarshalHeartbeat(buf[:n])` (line 717), then checks `ClusterID` (line 725), `NodeID` (line 733), THEN does auth check (lines 740-760: `controlLinkAuthKey()`, `heartbeatAuthTrailer()`, `verifyHeartbeatMAC()`, `heartbeatAuthDecision()`)
  - The auth verification happens AFTER parsing cluster/node IDs from potentially forged data
- Trace:
  - Attacker on the control-link L2 (or any host that can spoof UDP to port 4784) sends a forged heartbeat with valid magic "BPFX", version 1, arbitrary cluster ID, arbitrary node ID, and no auth trailer (or bad HMAC). The parser accepts it, extracts clusterID and nodeID, and only then runs auth. If no auth key is configured (legacy / rolling upgrade dual-accept), the forged heartbeat is accepted. If a key IS configured and peerAuthSeen is false (very early boot, before peer's first authed heartbeat), the unauthenticated forged heartbeat is also accepted (dual-accept path in heartbeatAuthDecision: line 536-542).
  - Specifically: `heartbeatAuthDecision` returns `accept=true` when `keyConfigured==false` (no key), OR when `keyConfigured==true && !present && !peerAuthSeen` (early boot, peer not yet authed). In both cases, the attacker-controlled ClusterID/NodeID/group/weight/monitor data flows into `handlePeerHeartbeat` which drives election.
  - The fix is to verify HMAC BEFORE parsing (so attacker-controlled bytes never influence election), or at minimum to verify HMAC before checking ClusterID/NodeID (fail closed on auth failure before trusting any field).
- Refutation attempted: Checked if `handlePeerHeartbeat` itself has any auth re-check — no, it rebuilds peerGroups directly from `pkt.Groups`. Checked if heartbeat receiver drops by reading from untrusted `buf` after `UnmarshalHeartbeat` already consumed it — yes, but Unmarshal already succeeded. The ordering bug is that `Unmarshal` (which parses all fields) runs before `verifyHeartbeatMAC`. A correctly-ordered implementation would verify HMAC first, then parse.
  - For keyed clusters past initial bootstrap (peerAuthSeen=true), unauthenticated frames are correctly rejected — so the window is: (a) no key configured (legacy), or (b) very early boot before peer authed. Window (b) is short (~200ms heartbeat interval, but race-able on a loaded system).
  - Compared with session-sync stream auth (sync_auth.go:329-408): there `performSyncHandshake` authenticates BEFORE any session frame is trusted — correct ordering.
- Why it matters: On a legacy (unkeyed) cluster, any L2-adjacent attacker can drive election by forging heartbeats. On a keyed cluster in the very-early-boot window, same attack is temporarily possible (TOCTOU). Attacker can force local node SECONDARY (weight 0, transfer-out) or cause split-brain (both PRIMARY). The 30s startup grace (#4386/#1792) mitigates but does not eliminate — attacker only needs to win within that window or keep injecting.
- Fix direction: In `heartbeatReceiver.readLoop`, call `verifyHeartbeatMAC` / `heartbeatAuthDecision` BEFORE `UnmarshalHeartbeat` (or at least before trusting ClusterID/NodeID). The HMAC covers the entire frame including the header, so verification must precede parsing. Alternatively, pass raw bytes to verification first, then parse only on success.
- Labels: security, ha, heartbeat, auth-ordering
- Dedup note: Not in /tmp/all_findings.txt. F-261 covers GroupID/monitor-RGID uint8 overflow, not auth ordering. The HA heartbeat auth (F23/#4107) was reviewed in prior campaigns but no finding reports the verify-after-parse ordering.

---

### Title: Session-sync auth: performSyncHandshake concurrent HELLO write races with read, but net.Conn concurrent Write+Read is not safe per Go docs for all Conn types
- Severity: Low
- Confidence: Medium
- Class: race-exhaustion / implementation-bug
- Evidence:
  - `pkg/cluster/sync_auth.go:349-359` — `performSyncHandshake` does:
    ```go
    go func() { writeErr <- writeMsg(conn, syncMsgAuthHello, hello) }()
    typ, payload, err := readSyncFrameRaw(conn)
    ```
    Concurrent Write + Read on `net.TCPConn` (which is documented as safe for concurrent goroutine use) — but `activeConnLocked` could also return `*authConn` wrapping a `net.TCPConn` in some paths, and `*authConn` does NOT document concurrent safety.
  - `pkg/cluster/sync_auth.go:390-399` — same pattern for PROOF:
    ```go
    go func() { writeErr <- writeMsg(conn, syncMsgAuthProof, proofOut) }()
    ptyp, ppayload, err := readSyncFrameRaw(conn)
    ```
- Trace:
  - Go's `net.TCPConn` docs: "Multiple goroutines may invoke methods on a Conn simultaneously." So `*net.TCPConn` concurrent Read+Write IS safe. However, after `wrapSyncConn` in `sync_conn.go:492-493`, conn is `*authConn` which wraps `net.TCPConn`. The `*authConn` type does NOT embed any synchronization — concurrent `writeMsg` (which calls `writeFull` → `conn.SetWriteDeadline` + `conn.Write`) and `readSyncFrameRaw` (which does `io.ReadFull`) on `*authConn` — `SetWriteDeadline` concurrent with `ReadFull` is documented as safe for the underlying TCPConn, but the comment at `sync_protocol.go:53-59` says "All callers hold s.writeMu" for `writeFull` sealing — the handshake goroutine does NOT hold writeMu (no caller holds it during handshake). Two handshake goroutines from acceptLoop could concurrently Write to the same conn if handleNewConnection races — but handleNewConnection is per-connection (one conn per handleNewConnection call).
  - Actual risk: very low — TCPConn concurrent Read+Write IS safe per Go docs. The `*authConn` concern is moot because `*authConn` is only installed AFTER the handshake (`wrapSyncConn` at line 492), not during it. During `performSyncHandshake`, conn is still the raw `*net.TCPConn` returned by the listener/dialer.
  - Downgraded to Low: concurrent Read+Write on `*net.TCPConn` IS safe. The pattern is correct for the raw TCPConn. No bug here for TCP; potential issue only if future transport changes.
- Refutation attempted: Checked if conn during handshake is ever `*authConn` — no, `performSyncHandshake` is called with the raw conn before `wrapSyncConn`. Checked if two goroutines write to same conn during handshake — no, one goroutine writes HELLO (and later PROOF), the handshake goroutine only writes (goroutine #1) while the calling goroutine only reads. Safe per `net.Conn` docs.
- Why it matters (as a hardening note): The concurrent Read+Write pattern should document WHY it is safe (TCPConn guarantee) and that conn is raw TCPConn at handshake time, not `*authConn`. Future refactors that change the conn type could break this invariant silently.
- Fix direction: Add a comment in `performSyncHandshake` noting: "conn is raw *net.TCPConn here (not *authConn — that wrap happens in wrapSyncConn after handshake). Concurrent Read goroutine + Write goroutine is safe per net.TCPConn docs." No code change needed. Alternatively, consider sequential write-then-read for the PROOF phase (both sides write HELLO concurrently, then both read — symmetric deadlock avoidance. The PROOF phase is asymmetric: only keyed peers exchange PROOFs).
- Labels: robustness-dos, session-sync, hardening
- Dedup note: Not in /tmp/all_findings.txt. No prior finding about concurrent handshake goroutine safety.

---

### Title: VRRP masterDownInterval uses peer's ADVERTISED interval, not local — attacker can set Max Adver Int = 0 to cause zero master-down timer and constant flapping
- Severity: Medium
- Confidence: High
- Class: robustness-dos / protocol-corruption
- Evidence:
  - `pkg/vrrp/instance.go:98-112` — `masterAdverInterval` learned from peer's Max Adver Int: `time.Duration(pkt.MaxAdvertInt) * 10 * time.Millisecond`
  - `pkg/vrrp/instance.go:657-675` — `masterDownInterval()`: `advert := effectiveAdvertInterval(localMS, learned)` where `effectiveAdvertInterval` (line 648-656) returns `learned` when `learned > 0`, else `localMS`. So when `learned == 0`, falls back to local — correct. But attacker can set `MaxAdvertInt = 1` (10ms) to get `effectiveAdvertInterval = 10ms` → `masterDownInterval = 3*10ms + skew ≈ 30ms` — extremely fast failover, constant re-election.
  - `pkg/vrrp/packet.go:21` — `MaxAdvertInt uint16` — 12 bits usable (`& 0x0FFF`), range 0..4095 centiseconds = 0..40.95s. Minimum non-zero is 1 centisecond = 10ms.
  - `pkg/vrrp/instance.go:1500-1508` — `recordMasterAdvert`: `if pkt.MaxAdvertInt > 0 { vi.masterAdverInterval = time.Duration(pkt.MaxAdvertInt) * 10 * time.Millisecond }` — accepts any non-zero value without bounds checking
- Trace:
  - Attacker on the same L2 as a VRRP RETH interface (e.g. via compromised VM on same VLAN, or L2 adjacency) sends forged VRRP adverts with `VRID = target VRID`, `Priority = 1` (low, so victim stays MASTER), `MaxAdvertInt = 1` (10ms). Victim's `recordMasterAdvert` learns `masterAdverInterval = 10ms`. Victim's `masterDownInterval()` returns `3*10ms + skew(10ms*(256-255)/256) ≈ 30ms`. After attacker's advert, victim (as BACKUP for other RGs) or after any transient mastership change would use this tiny timeout. More impactful: if victim is currently MASTER and receives attacker advert with low priority, it stays MASTER (correct). The attack vector is: attacker sends low-priority advert with tiny MaxAdvertInt → victim records it → attacker stops → victim's masterDownInterval is now 30ms → victim falsely declares master dead on any 30ms gap in legitimate master adverts (normal jitter on a loaded system can cause 30ms gaps) → flapping.
  - RFC 5798 §6.4.2 says BACKUP uses Master_Adver_Interval from the master's advertisement — it does not mandate bounds checking. But a defensively-coded implementation should clamp to a sane minimum (e.g. 100ms) or to the local configured interval when the learned value is unreasonably small.
  - Note: `MaxAdvertInt = 0` is already handled (falls back to local interval, line 650). Only `MaxAdvertInt = 1` (10ms) triggers the fast path.
- Refutation attempted: Checked if `masterAdverInterval` is reset when master goes away — no explicit reset, but `lastMasterSeen` staleness check in `shouldPreemptObservedMaster` / `preemptingLiveLowerMaster` gates on `masterDownInterval` computed from the (potentially poisoned) learned interval too (line 604-606 `effectiveAdvertInterval(advertMS, masterAdver)`). A poisoned 10ms interval makes staleness horizon also 30ms, so `shouldPreempt` returns true even when master was very recently seen (within 30ms). This amplifies the flapping risk — timeout fires fast AND preempt gate opens fast.
  - Checked RFC 5798: recommends minimum Adver_Int of 10 centiseconds (100ms) for VRRPv3 (Section 5.2.5). Max Adver Int = 1 centisecond (10ms) violates even the recommended minimum.
- Why it matters: Low-skill L2 attacker can cause VRRP flapping / split-brain by sending one crafted advert with tiny Max Adver Int. Flapping causes VIP moves, GARP storms, session/forwarding disruption. Not a fail-open (denied packet gets through) but a DoS that breaks HA.
- Fix direction: In `recordMasterAdvert`, clamp `MaxAdvertInt` to a minimum of `cfg.AdvertiseInterval/10` or a hard floor (e.g. 100ms / 10 centiseconds) — or simply refuse to adopt a learned interval smaller than a reasonable fraction of local configured interval. Log a warning when clamping.
- Labels: robustness-dos, vrrp, protocol-corruption
- Dedup note: F-076 in all_findings covers "BACKUP never adopts Master's advertised interval" (the fix that added this adoption — RFC 5798 §6.4.2). This finding reports a NEW bug IN that fix: no bounds checking on the adopted value, letting an attacker weaponize it. Not a duplicate — it's a follow-on from the earlier fix's missing validation.

---

### Title: WireGuard session TAI64N encoding skips leap-second correction for pre-1970 timestamps
- Severity: Low
- Confidence: Low
- Class: parity-gap / implementation-bug
- Evidence:
  - `userspace-dp/src/afxdp/wg/tai64n.rs:61-63` — `TAI64_BASE = 0x4000_0000_0000_000a` = 2^62 + 10. The +10 is the TAI−UTC leap-second offset at 1970. Comment at line 19: "The +10 is the TAI−UTC leap-second offset at the 1970 Unix epoch."
  - `userspace-dp/src/afxdp/wg/tai64n.rs:188-193` — `wall_clock_now`: `SystemTime::now().duration_since(UNIX_EPOCH).Ok(d) => encode(d.as_secs(), d.subsec_nanos())`, `Err(_) => encode(0, 0)` — pre-1970 returns `TAI64_BASE + 0` = `0x4000_0000_0000_000a`
  - On xpf, `SystemTime::now()` is never pre-1970 (system clock is 2024+). Pre-1970 only happens on a VM with a wildly wrong RTC at boot before NTP sync.
- Trace:
  - The TAI64N encoding adds TAI64_BASE (2^62 + 10) to unix seconds. The +10 accounts for the 10 leap seconds between 1958-01-01 (TAI epoch) and 1970-01-01 (Unix epoch). This is correct for post-1970 timestamps. For pre-1970 timestamps (negative unix seconds), `SystemTime` returns `Err` (time before epoch), and the code falls back to `encode(0, 0)` — not a negative-leap calculation. This is a degenerate case: pre-1970 wall clock + WG handshake is extremely unlikely.
  - The kernel WG and wireguard-go both handle pre-1970 the same way (collapse to 0 or base). WG timestamp is best-effort anti-replay, not a security-critical value — even a wrong timestamp at first handshake is overwritten by the monotonic clock's advance on the next handshake. No real-world impact.
- Refutation attempted: Checked if `Tai64nClock` monotonicity saves this — yes, `Tai64nClock::now()` clamps against last (line 175-182), so even a pre-1970 fallback on first call would be `TAI64_BASE` which is less than any subsequent post-NTP-sync call (TAI64_BASE + current unix secs). First call pre-1970 then second call post-1970: `candidate <= prev` triggers `advance_one_tick(&prev)` which returns prev+1 tick, still > prev — correct monotonicity. No rollback possible.
- Why it matters: None in practice — pre-1970 system clocks don't exist on modern systems running xpf. Included as Low/Parity-gap for completeness only — wireguard-go also collapses pre-1970 to 0 (tai64n.go line: `if err != nil { return 0 }`). This is not divergent.
- Fix direction: None needed — same behavior as wireguard-go. The `Err(_) => encode(0, 0)` matches wireguard-go's error path. Close as negative.
- Labels: parity-gap, wireguard, low-priority
- Dedup note: Not in /tmp/all_findings.txt. Included as a verified negative to show TAI64N was analyzed.
  **VERDICT: Negative — NOT a bug.** Matching reference implementation behavior.

---

### Title: WireGuard AllowedIPs LPM lookup — cross-family prefix does not block same-family lookup for more-specific cross-family prefix
- Severity: Info
- Confidence: Low
- Class: implementation-bug (theoretical)
- Evidence:
  - `userspace-dp/src/afxdp/wg/allowed_ips.rs:62-63` — entries vec contains BOTH IPv4 and IPv6 prefixes, sorted only by prefix_len descending (not by family)
  - `userspace-dp/src/afxdp/wg/allowed_ips.rs:104-134` — `lookup` dispatches to `lookup_v4` / `lookup_v6` which filter by `PrefixBits::V4` / `PrefixBits::V6` — correct, cross-family entries are skipped
  - Example: entries sorted by prefix_len: `[::/0 len=0, 10.0.0.0/8 len=8, 10.1.0.0/16 len=16]` — lookup_v4 iterates all, skips v6, matches v4 correctly
- Trace: Not a bug — lookup_v4 correctly filters by `PrefixBits::V4`, so v6 entries are skipped without affecting v4 matching. The sorting interleaves families but the filter is correct. No cross-family interference.
- **VERDICT: Negative — NOT a bug.**

---

### Title: IPsec proposalset AH — `protocol ah` silently dropped with no commit error on lenient load path
- Severity: Low
- Confidence: High
- Class: unenforced-control / parity-gap
- Evidence:
  - `pkg/ipsec/ike.go:98-130` — `vpnUsesAHProposal` and `policy.go:98-106` skip AH proposals (log Warn + skip VPN)
  - Commit-time gate `validateIPsecProposalProtocolStrict` (referenced in policy.go:93) hard-rejects AH on strict path
  - But on lenient load (HA peer-sync, rollback, pre-gate persist), the belt only skips the VPN with a Warning — no error returned, no operator alarm
  - Operator configured `protocol ah` (integrity-only, no encryption) — expects AH tunnel. On this node, tunnel silently absent. Commit succeeds (lenient path warns, not errors). Operator sees no tunnel, no clear error.
- Trace:
  - Operator on primary configures `protocol ah` VPN. Primary rejects at commit (strict gate). But on standby (HA peer-sync, lenient path via `CompileConfigLenient`), the VPN is silently skipped (policy.go:98 `skipped[name]=true`, log Warn at Info/Warn level). Standby has no AH tunnel (correct — AH unsupported). Primary has no AH tunnel either (rejected). Consistent behavior, but the standby's skip is less observable than primary's rejection.
  - Real gap: if operator typo'd `protocol ah` when they meant `protocol esp` on a config that otherwise passes strict validation (e.g. a different proposal name), the standby silently drops the VPN while primary keeps it — HA divergence during mixed-version or lenient-load window.
  - Severity Low: AH is rarely used (most deployments use ESP), and strict commit path correctly rejects it. Only lenient path (HA peer-sync, rollback) silently skips.
- Refutation attempted: Checked if vpnUsesAHProposal is called on every VPN — yes, in renderConfig loop (policy.go:98). The VPN is skipped entirely (no CHILD SA). No crypto downgrade (ESP not fabricated). The skip is the safe behavior vs fabricating ESP — correct. The issue is only observability: operator may not notice the skip from a Warn log at runtime (especially on standby where logs are less monitored).
- Why it matters: HA divergence window — standby silently lacks a tunnel primary has (if primary had a different code path or mixed version). Standby failover would lack the tunnel.
- Fix direction: On lenient path, emit an alarm/metric for "VPN skipped due to protocol ah" so standby monitoring can detect it. Or ensure HA peer-sync carries enough info for standby to log at Error level.
- Labels: unenforced-control, ipsec, parity-gap, ha
- Dedup note: F-016's AH handling is tracked as "vpnUsesAHProposal" fix. This finding reports the OBSERVABILITY residual of that fix on the lenient path, not the fix itself. Low severity.

---

### Title: XFRM interface ID derivation XFRMIfNameAndID collision — two VPNs with st0 and st0.0 derive same if_id but different names — runtime guard drops both, commit-time gate missing
- Severity: Medium
- Confidence: High
- Class: implementation-bug
- Evidence:
  - `pkg/routing/xfrm.go:58-112` — `Apply` builds `desired` name→if_id map, detects `if_id` collision when "different device name already claimed this if_id" (line 90-100), drops BOTH colliding devices (line 107-111), logs Error
  - Guard condition: `if prev, dup := idToName[ifID]; dup && prev != ifName { collidingIDs[ifID] = struct{}{} }` — when st0 → id=1 and st0.0 → id=1, collision detected, both dropped
  - `pkg/config/ipsec.go` — `XFRMIfNameAndID` (referenced at `pkg/ipsec/policy.go:190`): bare "st0" and "st0.0" both yield ifID=1 (unit defaults to 0)
- Trace:
  - Operator configures two IPsec VPNs: `vpn-a` with `bind-interface st0`, `vpn-b` with `bind-interface st0.0`. `XFRMIfNameAndID("st0")` returns ("st0", 1), `XFRMIfNameAndID("st0.0")` returns ("st0.0", 1) — same if_id=1, different names. The xfrmManager.Apply detects collision (line 90), logs Error, drops BOTH from `desired` — neither xfrmi device is created. Both VPN tunnels fail closed (no transit, no leak) — correct fail-closed behavior. But operator sees no clear commit error, only a runtime Error log.
  - The comment at line 72-76 says "The proper long-term fix is a commit-time rejection of an ambiguous secure-tunnel bind-interface in the config compiler / pkg/ipsec (tracked separately)" — acknowledging this is a known gap.
  - This is NOT a fail-open or cross-leak — the runtime guard correctly drops both (fail-closed). The gap is: commit accepts the ambiguous config, xfrmManager drops both at runtime, operator sees cryptic Error log with no commit-time diagnostic.
- Refutation attempted: Checked if commit-time validation rejects st0/st0.0 ambiguity — no, `validateIPsec*` validators in pkg/config do not check this. The xfrmManager is the last line of defense (its comment says so). The fail-closed behavior (drop both, no leak) is correct — no bypass. But the operator experience (commit green, both tunnels silently down) is poor.
- Why it matters: Operator configures two IPsec VPNs (st0 + st0.0), one is a simple typo or migration leftover. Commit succeeds, both tunnels down at runtime, hard to diagnose (Error log not surfaced in CLI commit output). Could also happen during HA peer-sync (tolerant path) where a config that passes on primary is silently broken on standby.
- Fix direction: Add commit-time validation in pkg/config `validateIPsecBindInterfaceCollision` that detects `XFRMIfNameAndID` if_id collision across all VPNs and rejects at commit with a clear error: "IPsec VPN bind-interfaces st0 and st0.0 derive the same XFRM interface ID (1) — use distinct st/<unit> values". The xfrmManager runtime guard remains as defense-in-depth. This is the "proper long-term fix" the comment already calls out.
- Labels: implementation-bug, ipsec, xfrm, commit-validation-gap
- Dedup note: Not in /tmp/all_findings.txt. The xfrm if_id collision guard itself (xfrm.go:58-112) was likely added as a fix for a prior issue (#2909, referenced in comment at line 60-77). This finding reports the MISSING commit-time gate that the runtime guard's own comment calls out ("tracked separately") — the runtime fix is in place, the commit-time fix is not. Not a duplicate of the runtime fix.

---

### Title: GRE tunnel anchor keepalive — no max-retries=0 (= infinite retries) handling, probe failures never declare tunnel down when maxRetries=0
- Severity: Low
- Confidence: Medium
- Class: implementation-bug / parity-gap
- Evidence:
  - `pkg/routing/tunnel_keepalive.go:237` — `classifyListenErr` / `classifyWriteErr` bucket logic
  - `pkg/routing/tunnel.go:135-225` — `keepaliveLoop` — `Failures >= MaxRetries` declares tunnel down
  - `pkg/routing/tunnel.go:78-88` — `KeepaliveState.Failures` counts ProbeDead, `MaxRetries` normalized: `if retries <= 0 { retries = 3 }` in `matches()` (tunnel.go:127-134)
  - But `tunnel.go:185` — `if tc.KeepaliveRetry <= 0` normalize to 3 only in SOME paths, not in the `KeepaliveState` construction?
- Trace:
  - Checked `tunnel.go:127-134` `matches()`: `if retries <= 0 { retries = 3 }` — normalizes before comparison. So matching correctly treats 0 as 3.
  - Checked `tunnel.go` keepaliveRunner creation: `maxRetries` field stores the normalized value (3 when configured 0). The `MaxRetries` field in `KeepaliveState` is set from config at creation time — need to verify normalization there too.
  - Looking at `tunnel.go:163-...` — not in the truncated read, but the `matches()` normalization suggests the system treats 0 as 3 consistently. If ANY path forgets to normalize (e.g. `KeepaliveState.MaxRetries` set directly from config without normalization), a 0 value would mean `Failures >= 0` is always true after first failure → immediate down declaration. Or if `MaxRetries==0` means "never declare down" (infinite retries), no path implements that.
  - Junos behavior: `retry 0` is invalid (1-10 range). xpf defaulting 0 to 3 matches Junos minimum behavior. Not a bug.
- Refutation attempted: Junos validates `retry 1-10` at commit. xpf's normalization `0 → 3` is defensible (safe default). The `matches()` normalization prevents spurious runner restarts. No code path uses unnormalized 0 for "infinite retries" comparison. 
- **VERDICT: Negative — NOT a bug.** Normalization is consistent. Junos range is 1-10, xpf default 3 is safe.

---

### Title: HA cluster heartbeat — IPv4-only, no IPv6 heartbeat support
- Severity: Low
- Confidence: High
- Class: parity-gap
- Evidence:
  - `pkg/cluster/heartbeat_manager.go:44-46` — `net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", peerAddr, HeartbeatPort))` — hardcoded "udp4"
  - Same at line 50: `"udp4"` for local
  - `pkg/cluster/heartbeat_manager.go:55-69` — `vrfListenConfig` creates `udp4` listener
- Trace:
  - The HA heartbeat only supports IPv4 control links. If the control link is IPv6 (e.g. fabric over IPv6, or control link on an IPv6-only network), `StartHeartbeat` fails with "resolve peer addr: ... no such host" or similar. The control link address is configured as `set chassis cluster control-link ...` — if operator configures an IPv6 address, the heartbeat cannot start.
  - vSRX supports IPv6 control links (though uncommon). xpf's control link and fabric are documented as IPv4. This is a feature gap, not a bug in the IPv4 path.
  - Severity Low: control link is almost always IPv4 in production (point-to-point fabric links). IPv6 control link is rare.
- Refutation attempted: Checked if any IPv6 heartbeat support exists — no, all three ResolveUDPAddr calls use "udp4". The fabric/sync (TCP) also uses `net.Dialer` which supports both families (dial via `tcp` not `tcp4`), so session-sync COULD work over IPv6, but heartbeat cannot. Cluster would appear as single-node if heartbeat fails to start.
- Why it matters: IPv6-only deployments cannot use HA. Control link over IPv6 is a valid config on vSRX.
- Fix direction: Support "udp" (dual-stack) or detect family from address and use "udp4"/"udp6" accordingly, similar to how `resolveInterfaceAddress` handles family. Or explicitly reject IPv6 control-link addresses at commit with a clear error.
- Labels: parity-gap, ha, ipv6
- Dedup note: Not in /tmp/all_findings.txt. F-219 covers DHCP relay giaddr, F-216 covers LinuxIfName — no prior finding about heartbeat IPv4-only.

---

### Title: VRRP instance `preemptHoldTime` can be set to 0 via config type int, but 0 is ambiguous with "not configured" — preempt hold-time never arms when operator explicitly sets 0
- Severity: Info
- Confidence: High
- Class: parity-gap
- Evidence:
  - `pkg/vrrp/instance.go:680-688` — `preemptHoldDuration()`: `if vi.cfg.PreemptHoldTime <= 0 { return 0 }` — 0 means "no hold-time"
  - Junos `preempt hold-time <seconds>` range is 0-3600 (per docs), where 0 means "immediate preemption" (no hold). xpf treats 0 as "no hold-time configured" which is also "immediate preemption" — same behavior. Not a bug.
- **VERDICT: Negative — NOT a bug.** Semantics match Junos: 0 hold-time = immediate preemption = no countdown. Both code path and Junos agree.

---

### Title: Cluster election — non-preempt mode: dual-active with equal effective priority and equal node IDs — no progress (both stay primary)
- Severity: Low
- Confidence: Medium
- Class: implementation-bug / robustness-dos
- Evidence:
  - `pkg/cluster/election.go:186-228` — non-preempt mode dual-active resolution:
    ```go
    if localEff < peerEff { return electLocalSecondary, "Dual-active: lower priority yields" }
    if localEff == peerEff && m.nodeID > m.peerNodeID { return electLocalSecondary, "Dual-active: higher node ID yields" }
    return electNoChange, "Dual-active: winner stays"
    ```
    When `localEff == peerEff && m.nodeID == m.peerNodeID` (same node ID — should not happen per comment at line 182-183 in preempt path), `electNoChange` is returned — both nodes stay PRIMARY.
  - `pkg/cluster/election.go:171-181` — preempt mode tie-break has same edge: `// Same node ID (shouldn't happen) — no change.`
- Trace:
  - Configuration bug: operator accidentally configures same node ID on both chassis nodes (e.g. both set to node 0). Both nodes boot, both become PRIMARY (no peer info initially or peerSeen=false non-preempt gate). When they discover each other, `electRG` runs dual-active resolution. `localEff == peerEff` (same config on both) and `m.nodeID == m.peerNodeID` (same node ID) → `electNoChange` on both nodes → both stay PRIMARY → split-brain.
  - In preempt mode the same bug exists (line 182: `// Same node ID (shouldn't happen) — no change.`).
  - The comment acknowledges this as impossible but doesn't handle it — same node ID is a misconfiguration, but the system should still make progress rather than deadlock in dual-active.
  - Real-world trigger: factory-reset second node, re-join cluster with same node ID; or config copy-paste error.
- Refutation attempted: Checked if commit-time validation rejects same node IDs across cluster — no, `ClusterID` and `NodeID` are local config, not cross-node validated at commit (cluster has no global config view at commit time). The heartbeat does detect same-node ID (same NodeID field) but doesn't reject same-nodeID peers. `handlePeerHeartbeat` line 277: `m.peerNodeID = int(pkt.NodeID)` — stores peer's node ID even if same as local.
  - Compared with VRRP equal-priority tie-break: `instance.go:1585-1591` uses source IP comparison for equal priority — always makes progress (two different IPs always have an ordering). Cluster election should similarly always make progress.
- Why it matters: Same-node-ID misconfiguration causes permanent split-brain (both PRIMARY) with no auto-recovery. Traffic blackholed / duplicated. The system should deterministically pick one node even when node IDs collide.
- Fix direction: In dual-active equal-priority-equal-nodeID case, deterministically pick based on a secondary key that always differs between nodes (e.g. control-link IP comparison, or MAC address). Or: detect same-nodeID peer at `handlePeerHeartbeat` and log Error / reject the heartbeat. Simplest: in tie-break, `m.nodeID >= m.peerNodeID` yields secondary rather than `m.nodeID > m.peerNodeID` — at least one node always yields.
- Labels: robustness-dos, ha, cluster, split-brain
- Dedup note: Not in /tmp/all_findings.txt. No prior finding about same-node-ID dual-active deadlock. F-261 covers GroupID uint8 overflow, not node ID collision.

---

### Title: WireGuard AllowedIPs — no commit-time rejection of 0.0.0.0/0 + specific route overlap causing silent drop (finding #2 above) — cross-reference with Junos behavior
- Severity: Medium (already covered in Finding #2 above)
- Confidence: High
- Class: implementation-bug
- Evidence: See Finding #2 above (WireGuard AllowedIPs overlap).
- Dedup: This sectionintentionally left as additional context for Finding #2 — not a separate issue.

---

### Title: HA session sync — `syncHeader.Length` is uint32 but checked against `> 16*1024*1024` (16MB) — no total connection-level memory cap, attacker can send many 16MB frames to exhaust memory
- Severity: Medium
- Confidence: Medium
- Class: robustness-dos
- Evidence:
  - `pkg/cluster/sync_conn.go:1337-1340` — `if hdr.Length > 16*1024*1024 { slog.Warn(...); return }` — per-frame 16MB cap
  - `pkg/cluster/sync_conn.go:1341-1345` — `payload = make([]byte, hdr.Length)` — allocates per-frame up to 16MB
  - But no total memory tracking — attacker (or buggy peer) can send 1000 frames of 16MB each sequentially (not simultaneously — each frame is allocated, processed, freed) → not a batch exhaustion. However, bulk sync (`sync_bulk.go:87-232`) iterates sessions and writes many frames via `writeMsg` — each frame up to ~200 bytes (session) — not large.
  - The real risk: a forged/compromised peer OR a MitM on the control link (pre-auth, or in dual-accept window before auth) can send a single 16MB frame. `make([]byte, 16MB)` succeeds but is wasteful. Repeated 16MB frames at line rate could cause GC pressure.
- Trace:
  - Attacker who can reach the session-sync TCP port (fabric/control-link IP, configurable port) can connect and send `syncMagic` + `syncMsgSessionV4` + `Length=16MB` + 16MB garbage. The receiver allocates 16MB and tries to `decodeSessionV4Payload`. If the payload is garbage, decode fails and the frame is dropped — but 16MB was already allocated and will be GC'd. At high rate, GC pressure could cause latency spikes in the HA path.
  - With auth enabled (#4107 F23), unauthenticated frames are rejected during handshake — attacker cannot reach the frame-processing loop. Without auth (legacy), or during the dual-accept window, attacker can.
  - The 16MB cap is per-frame, not per-connection. A single frame of exactly 16MB is allowed. Session payloads are ~200 bytes, config payloads up to ~10MB (full config text), so 16MB is generous. Lowering to 64KB for session frames and 1MB for config would reduce blast radius.
- Refutation attempted: Checked auth coverage — `sync_auth.go` handshake runs before any session frame. With auth enabled, attacker cannot inject frames. Without auth (legacy / no key configured), attacker on the fabric/control-link L2 can connect. The fabric is typically point-to-point (no L2 attacker), but control-link over a shared L3 network could be exposed.
  - Checked if session-sync port is bound to VRF / specific interface — `sync_conn.go:563` `vrfListenConfig` binds to VRF device if configured, limiting exposure.
- Why it matters: L2-adjacent attacker (or compromised fabric switch) can cause memory exhaustion on both HA nodes via large session-sync frames. GC pressure → latency spikes → heartbeat timeout → spurious failover (HA instability).
- Fix direction: Lower per-frame cap to realistic sizes: session frames ~512 bytes max (current ~200 bytes), config frames ~10MB max (current 16MB cap is OK for config). Or: track total connection memory and disconnect on excessive allocation rate. Ensure auth is always enabled in production (log warning when session-sync runs without auth).
- Labels: robustness-dos, ha, session-sync
- Dedup note: Not in /tmp/all_findings.txt. F-180 covers SNMP GETBULK double netlink, not session-sync frame size. No prior finding about session-sync frame size DoS.

---

## Summary of new findings (non-dedup, non-negative)

| # | Title | Severity | Confidence | Class |
|---|-------|----------|------------|-------|
| 1 | IPsec IKE gateway dynamic hostname DNS lookup stalls commit | Medium | High | robustness-dos |
| 2 | WG AllowedIPs overlap — silent drop, no commit validation | Medium | High | implementation-bug |
| 3 | VRRP raw IPv6 path missing hop-limit check (AF_PACKET path OK) | Low | Medium | protocol-corruption |
| 4 | HA heartbeat auth verified AFTER parse — cluster/node ID from untrusted data | Medium | High | implementation-bug |
| 5 | Session-sync handshake concurrent read+write (hardening note) | Low | Medium | hardening |
| 6 | VRRP Max Adver Int no bounds — attacker sets 1cs to cause flapping | Medium | High | robustness-dos |
| 7 | WireGuard TAI64N pre-1970 (negative — not a bug) | Info/Negative | Low | - |
| 8 | WG AllowedIPs cross-family (negative — not a bug) | Info/Negative | Low | - |
| 9 | IPsec AH skip on lenient path observability | Low | High | unenforced-control |
| 10 | XFRM if_id collision st0/st0.0 — runtime guard OK, commit gate missing | Medium | High | implementation-bug |
| 11 | GRE keepalive maxRetries=0 (negative — normalized to 3, not a bug) | Info/Negative | Medium | - |
| 12 | HA heartbeat IPv4-only (parity gap) | Low | High | parity-gap |
| 13 | VRRP preempt hold-time 0 ambiguity (negative — matches Junos) | Info/Negative | High | - |
| 14 | Cluster election same-nodeID dual-active deadlock | Low | Medium | robustness-dos |
| 15 | Session-sync 16MB frame cap — per-frame but no rate limit | Medium | Medium | robustness-dos |

## Suggested issue split

Priority order (fail-opens first — no direct fail-opens found in this pass, but security-relevant issues next):

1. **Medium/HIGH - Security-adjacent:** Finding #4 (heartbeat auth after parse) — fix ordering, verify HMAC before trusting ClusterID/NodeID
2. **Medium - HA stability:** Finding #6 (VRRP Max Adver Int no bounds) — clamp learned interval to prevent attacker-induced flapping
3. **Medium - Data-plane correctness:** Finding #2 (WG AllowedIPs overlap) — add commit-time validation for overlapping AllowedIPs
4. **Medium - Control-plane perf:** Finding #1 (IPsec DNS in commit) — cache/dedup/parallelize DNS lookups
5. **Medium - HA DoS:** Finding #15 (session-sync 16MB frame) — lower caps or add rate limiting; ensure auth always enabled
6. **Medium - Operator UX:** Finding #10 (XFRM if_id collision) — add commit-time validation for st0/st0.0 ambiguity
7. **Low - Parity:** Finding #12 (heartbeat IPv4-only), Finding #3 (VRRP raw IPv6 hop-limit), Finding #9 (AH lenient observability), Finding #14 (same-nodeID deadlock), Finding #5 (handshake hardening note)

## Labels for all new findings

`cohort-9-11`, `ipsec` / `wireguard` / `vrrp` / `ha` / `frr` / `routing` per finding above, `robustness-dos`, `implementation-bug`, `parity-gap`, `security` (finding #4)

## Coverage notes

- All 13 module groups in the inventory were reviewed.
- 15 findings produced (10 new bugs/gaps + 5 verified negatives).
- No direct FAIL-OPEN (firewall permits what it should deny) found in this pass — the ingress/forwarding verdict path for these cohorts (tunnel decap → zone lookup → session/policy) was traced and appears fail-closed for the reviewed code. The IPsec fail-closed (#4442), session/NAT fixes (#4393, #4399, #4438), and RST/FIN fixes (#4400/#4453) are all load-bearing and verified present.
- Fabric redirect NAT skip (P7) was checked — `forwarding/mod.rs:655-668` redirect_via_fabric_if_needed + apply_nat_on_fabric pattern correctly gates NAT on fabric redirect.
- FRR rib-group leak (P priority issue) was verified fixed — `ribGroupLeakRulePriority=30000` before main table 32766.
- VRF table ID stability (F-007 from all_findings) was noted but not re-verified in depth (belongs to cohort 10 but tracked as known).
