# Cohorts 9-11 Deep Audit — IPsec/IKE/WireGuard + Routing/FRR + HA/Cluster/VRRP — ps-review-031

- Base commit: b1bd96fb68de40d6fc357e63d9717f7ad75241fa (Merge PR #4531, master)
- Output path: /tmp/ps-review-031.md
- Cohorts:
  - 9 IPsec/IKE/WG: pkg/ipsec/*, userspace-dp/src/afxdp/wg/*
  - 10 Routing/FRR/PBR: pkg/routing/*, pkg/frr/*, pkg/dataplane/userspace/tunnels.go
  - 11 HA/Cluster/VRRP: pkg/cluster/*, pkg/vrrp/*, userspace-dp/src/afxdp/ha.rs, pkg/ipmon/*, pkg/dataplane/userspace/manager_ha.go

## Duplicate-suppression summary

Read `/tmp/all_findings.txt` (272 entries, F-001..F-272), `/tmp/ps-review-024.md` (filter/PBR/VRF, M-01 PBR discard-term kernel mirror, M-02 flex cache, M-03 next-table VRF leak, L-01 policer), `/tmp/ps-review-025.md` (policy engine, no cohort 9-11 overlap), `/tmp/ps-review-020.md` (S-001 cross-zone, S-002 bare ACK), `/tmp/ps-review-021.md` (prior cohort 9-11 on c2ee227c4).

Dedup'd / not re-reported as new (verified still present unless noted fixed):
- F-011 WG tunnel local identity, F-019/F-250 WG responder rekey blackhole (fixed #3882 3-slot, verified), F-190 TAI64N replay (fixed #4092), F-191 DoS (fixed cookie), F-271 peer_has_confirmed_session ignores REJECT_AFTER_TIME (still present, tracked as F-271), F-038 DPD bare statement (fixed #3994), F-039/F-040/F-161 IKE/IPsec multi-value truncate (fixed #3904), F-046 WG endpoint forms, F-067 parseSAOutput (fixed #3937), F-175 delete-terminate (fixed #3941), F-176 PSK id selectors (fixed #3952), F-114 start_action dead line (known), F-221 hex PSK, F-016 rib-group 33000 shadow (fixed #3876), F-062 IS-IS level, F-063 GRE keepalive (fixed #4071), F-066 df-bit inversion (fixed #4015), F-008 q-nh pref, F-174 next-table mirror scope divergence, F-269 dynamic routes never reach AF_XDP FIB (known gap), F-220 policy term name injection, F-042 prefix-list bracket, F-083 NPTv6 0xFFFF, F-088 WG double route lookup, F-081 dual-fabric pin-to-first (fixed #4082), F-024 monitor weight, F-025 bulk-ack race (fixed #3912), F-026 deletes journal (fixed #3926), F-048 clusterReadOnly, F-049 gRPC exclusive lock, F-053 dual-fabric refresh, F-054 GARP probe, F-076 RFC 5798 §6.4.2 adopt interval (fixed, but new bypass below), F-077 VRRP accept-data (still present, known), F-086 export_all_sessions under lock, F-090 HA tests, F-096 bulkRecvEpoch race, F-108 sysctls, F-120 requestSessionSync per-conn, F-125 Manager.Status race, F-150 commit-confirmed rollback, F-156 config sync unordered, F-157 dual-fabric bulk reset, F-166 RG 0..15 hardcode, F-167 monitorFabricState, F-168 heartbeat retry ignores ctx, F-169 non-fatal tail apply, F-170 proxyARP race, F-171 monitorLinkState, F-204 peerClockOffset, F-178 LLDP table unbounded, etc.
- ps-review-024 M-01 PBR discard-term kernel mirror, M-02 flex cache invalidation (F-129), M-03 next-table VRF leak — verified still present on b1bd96fb6, not re-reported as new.
- ps-review-024 N-01..N-09 verified negatives — not re-reported.

Intentional divergences (NOT bugs):
- intrazone default-permit, host-originated junos-host rejected at commit, IPsec-passthrough-exempt, reject-all superset, flowless fragment policy still enforced with l4_present=false, NAT64 clamp, etc. — documented.

Known fixes on b1bd96fb6 verified present (not re-reported):
- P1 HA NAT pool (#4388) — nat source pool handling in session, verified via tests; P2 dnat_table (#4393) — ha.rs:339-351 publish_dnat + delete path; P5 1:N NAT (#4399/#4438) — session/mod.rs NatIndexBucket SmallVec fix; P7 fabric redirect NAT skip — forwarding/mod.rs; #4440/#4441 ipmon standby DHCP (appliedOverlay nil on standby); #4442 ipsec fail-closed (ike.go errIKEChainUnresolved + policy.go vpnUsesAHProposal skip); #4400/#4453/#4487 RST/FIN (forwarding/mod.rs cluster_peer_return_fast_path excludes RST/FIN); #4392 PBR reject (forwarding/mod.rs RouteOverride::Drop); #4384 TCP checksum (userspace-dp checksum fix); #4521 NAT pool bracket-list; #4525 RA interval; #4526 DHCP timer overflow; #4524 monitor traffic truncation; #4534 PBR discard (#4392 + M-01 residual noted); #4535 three-color policer.

## Module / verdict-path inventory

| Cohort | Module | Files | Reviewed |
|--------|--------|-------|----------|
| 9 | IPsec IKE/IPsec proposal chains | pkg/ipsec/ike.go, policy.go, crypto.go, manager.go | Full |
| 9 | IPsec compiler / validators | pkg/config/compiler_ipsec.go, compiler_validate_strict_ipsec.go, types_ipsec.go | Full |
| 9 | IPsec XFRM if_id | pkg/routing/xfrm.go | Full |
| 9 | WG engine core | userspace-dp/src/afxdp/wg/engine.rs, peer.rs, session.rs, timers.rs, handshake.rs, handshake_session.rs, tai64n.rs, cookie.rs, framing.rs, allowed_ips.rs, mss.rs, mod.rs | Full |
| 9 | WG tunnel snapshot | pkg/dataplane/userspace/tunnels.go, pkg/config/tunnelemit.go | Full |
| 10 | FRR config gen | pkg/frr/manager.go, config_render.go, policy_render.go, vtysh.go, status_parse.go | Full |
| 10 | Routing rules / next-table / rib-group / PBR | pkg/routing/rules.go, vrf.go, routing.go, routes.go, tunnel*.go, xfrm.go | Full |
| 10 | Routing VRF / bond / probe_pin | pkg/routing/vrf.go, bond.go, probe_pin.go | Full |
| 11 | HA cluster manager / election / failover / heartbeat / sync / garp / reth | pkg/cluster/*.go | Full |
| 11 | VRRP instance / manager / packet / track / addrwatch | pkg/vrrp/*.go | Full |
| 11 | HA dataplane | userspace-dp/src/afxdp/ha.rs | Full |
| 11 | IPMON | pkg/ipmon/ipmon.go | Full |

## Inspection log (selected deep traces, including negatives)

### IPsec — policy.go / ike.go

- `resolveRemoteAddr` correctly rejects dangling gateway name vs usable IP/hostname via `IsUsableIPsecEndpoint` — fail-closed, verified via #2074 tests.
- `resolveIKESettings` correctly distinguishes intentional no-policy (nil error, empty proposal) vs dangling chain (errIKEChainUnresolved) — verified #2270 / #4442 fix still present.
- `vpnUsesAHProposal` skips AH VPN with Warn, commit gate `validateIPsecProposalProtocolStrict` rejects AH at commit — lenient path only Warn, no error — observability gap (Low, ps-review-021 Finding #10, still present, dedup).
- `gatewayRemoteFamilyHint` → `resolveHostFamily` does `r.LookupIPAddr` with 2s timeout per gateway on synchronous PrepareConfig — N gateways stall N*2s, no cache — Medium DoS (ps-review-021 Finding #1, verified still present on b1bd96fb6: policy.go:737-795).
- `deriveDPD` bare `dead-peer-detection;` enables DPD with defaults — fix #3994 verified.
- `normalizeAuthAlg` correctly maps hmac-sha-256-128 → sha256, etc. — fix #3851 verified.
- `buildESPProposal` defaults enc to aes256 when empty — safe fallback, not a leak.
- `pskIDSelectors` correctly builds id-1 remote-id/addr + id-2 local-id, but responder-only with no remote-id and no local-id yields empty list → no id selectors → PSK matches ANY peer — two responder-only VPNs with different PSKs collide silently. Low, not fail-open (auth fails closed, but wrong PSK could be tried first).
- `XFRMIfNameAndID` collision st0 (id=1) vs st0.0 (id=1) — runtime guard in xfrm.go:90-111 drops both, fail-closed, but no commit-time gate — Medium, tracked separately, still present.

### WireGuard — engine.rs / peer.rs / session.rs / handshake_session.rs / cookie.rs

- 3-slot model verified: `peer.rs:339-382` install_new_session routes Initiator→current, Responder→next; `engine.rs:1169-1198` maybe_promote_next promotes on first inbound authenticated data; `session.rs:119-129` confirmed gate blocks responder egress until first inbound. Fix #3882 holds — no responder rekey blackhole.
- TAI64N anti-replay verified: `peer.rs:236-244` check_and_update_tai64n strictly greater, `handshake_session.rs:576-581` before msg2 build — fix #4092 holds.
- Cookie DoS mitigation verified: `engine.rs:594-655` classify_initiation load gate + MAC2 verify + per-source bucket + global budget; `cookie.rs:74-138` secret rotation with previous-window carry — fix holds.
- `peer_has_confirmed_session` (engine.rs:730-737) ignores REJECT_AFTER_TIME — still present, tracked as F-271 / all_findings. Trace: session expired (created_ns + 180s) still in map until expire_sessions runs (1s tick) → peer_has_confirmed_session returns true → control thread skips rekey initiation → traffic blackhole for up to 1s, or indefinitely if expire_sessions not run due to lock contention. Medium, known.
- `AllowedIPs` overlap: `allowed_ips.rs:64-94` insert allows 0.0.0.0/0, `lookup` global LPM most-specific wins, duplicate prefix only one peer wins — test `duplicate_cross_peer_prefix_only_one_peer_wins` documents intentional, but no commit-time validation — Medium silent-drop.
- `reserve_pending_locked` re-checks peer_arc under reconcile_lock — TOCTOU fix verified.
- `install_session_locked` holds reconcile_lock then sessions_by_local_index write — consistent lock ordering with expire_sessions, no deadlock.

### Routing / FRR / PBR

- `nextTableManager.Apply` (rules.go:84-172) installs `ip rule to <dst> lookup <table>` global, no source-VRF scoping — VRF leak, but already reported as ps-review-024 M-03, verified still present on b1bd96fb6.
- `ribGroupManager.Apply` per-prefix leak `to <connected-prefix> lookup <sourceTable>` pref 30000 — before main (32766), correct fix #3876, verified.
- `pbrManager.Apply` and `BuildPBRRules` — DSCP-0 drop, except-set fail-closed, L4 unrepresentable fail-closed — fixes #3430/#3730 verified.
- `buildPBRFromFilter` skips term with routing-instance + discard/reject? No Action check — reported as ps-review-024 M-01 (PBR kernel mirror ignores discard), verified still present, dedup.
- `generateStaticRouteInTable` strips ".0" only — correct, not bug.
- `vrfManager.Reconcile` namespace-claim whole vrf-* — correct, no leak.
- `tunnel_keepalive` — normalization 0→3 consistent, not bug.

### HA / Cluster / VRRP / Session-sync

- `heartbeat.go:717-760` readLoop: `UnmarshalHeartbeat` (line 717) before `verifyHeartbeatMAC` (745) — parses clusterID/nodeID/groups from unauthenticated bytes before auth check. On legacy (no key) or early-boot (peerAuthSeen=false) dual-accept window, attacker-controlled heartbeat drives election. Medium, ps-review-021 Finding #4, verified still present on b1bd96fb6.
- `heartbeat.go:506-542` `heartbeatAuthDecision` dual-accept: no key → accept all, key+no trailer+!peerSeen → accept (rolling upgrade) — window ~200ms but raceable on loaded system.
- `heartbeat_manager.go:44-46` `net.ResolveUDPAddr("udp4", ...)` hardcoded IPv4 — IPv6 control-link unsupported, parity gap Low, ps-review-021 Finding #12, still present.
- `vrrp/instance.go:98-112` `masterAdverInterval` learned from peer MaxAdvertInt (centiseconds*10ms), no bounds check — attacker sends MaxAdvertInt=1 (10ms) → `masterDownInterval` ≈ 30ms → flapping, split-brain. Medium, ps-review-021 Finding #6, verified still present: `recordMasterAdvert` at 1500-1508 accepts any non-zero without clamp.
- `vrrp/instance.go:1364-1367` `parseAfPacketIPv6` hop-limit check base header only — actually correct per RFC (hop-limit only in fixed 40-byte header, not ext-headers). AF_PACKET path correct. `receiverIPv6` (raw IPv6 fallback) has no hop-limit check — Low, ps-review-021 Finding #3 residual, still present.
- `cluster/election.go:186-228` same NodeID deadlock — both nodes same NodeID, same priority, dual-active → both stay PRIMARY (electNoChange on tie with same NodeID) — split-brain, Low/Medium, ps-review-021 Finding #13, still present.
- `cluster/sync_auth.go:349-359` concurrent HELLO write goroutine + Read on raw *net.TCPConn — actually safe per net.TCPConn docs (concurrent Read+Write allowed), and conn is raw TCPConn at handshake time (not *authConn) — negative, not a bug, ps-review-021 Finding #5 downgraded to Low/hardening, verified.
- `cluster/sync_conn.go:1337-1340` 16MB per-frame cap but no total connection memory cap — DoS via many 16MB frames, but each frame allocated then freed, not batched — Low.
- `ipmon/ipmon.go` overlay computation — winner resolution per (RI,prefix) with DHCP lease resolution before winner selection — correct per #1844.

### Cross-zone session hijack (S-001) — verification

`userspace-dp/src/session/key.rs:10-17` SessionKey is still bare 5-tuple:

```rust
pub(crate) struct SessionKey {
    pub addr_family: u8,
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}
```

No zone/VRF discriminator. `session/lookup.rs:48-68` lookup by bare 5-tuple, `poll_descriptor/mod.rs:858-879` session hit path does not re-validate ingress_zone for ForwardCandidate transit. `flow_cache.rs:759-780` flow cache includes ingress_ifindex in set index (zone-aware), but miss falls through to zone-unaware session table.

Trace (same as ps-review-020 S-001):
1. Client untrust 10.0.0.5:1234 → 8.8.8.8:443 permit → session created.
2. Attacker dmz spoofs same 5-tuple 10.0.0.5:1234 → 8.8.8.8:443 arriving on dmz ifindex.
3. Flow cache miss (different ingress_ifindex), session table hit (same 5-tuple) → permit reused, dmz→trust DENY bypassed.

vSRX: zone-aware session table, no cross-zone reuse.

Refutation attempted: checked SessionMetadata.ingress_zone stamped at install but never compared on hit; checked resolve_flow_session_decision / lookup_session_across_scopes — pure 5-tuple; checked flow-cache zone isolation — does not prevent session-table hit; checked interface filtering — reth/VLAN shared physical port allows L2 injection.

**VERDICT: Still present on b1bd96fb6. Already filed as S-001 (ps-review-020). Do not count as new, but confirmed.**

---

## Findings (new / verified residual that survives dedup)

### [HIGH] S-001 (verified still present) Cross-zone / cross-VRF session hijack via bare 5-tuple SessionKey — policy bypass (FAIL-OPEN)

- Title: SessionKey has no zone/VRF discriminator — packet from zone C reuses zone A→B session and bypasses zone C policy
- Severity: High
- Confidence: High
- Class: fail-open
- Evidence:
  ```rust
  // userspace-dp/src/session/key.rs:10-17
  pub(crate) struct SessionKey {
      pub addr_family: u8, pub protocol: u8,
      pub src_ip: IpAddr, pub dst_ip: IpAddr,
      pub src_port: u16, pub dst_port: u16,
  }
  // poll_descriptor/mod.rs:858-879 session hit — no zone re-validation for ForwardCandidate
  // flow_cache.rs:759-780 flow cache is zone-aware, session table is not
  ```
- Trace: Untrust client 10.0.0.5:1234→8.8.8.8:443 permit → session installed. Attacker on dmz spoofs same 5-tuple, flow-cache miss (different ingress_ifindex), session-table hit (same 5-tuple), dmz→trust DENY bypassed. vSRX would deny (zone-aware sessions).
- Refutation attempted: Metadata ingress_zone not validated on hit; flow-cache miss does not prevent; no zone check in lookup; reth/VLAN L2 injection feasible. Confirmed still present.
- Why it matters: Worst firewall bug — DENY bypassed via existing PERMIT session from different zone/VRF. VRF isolation broken.
- Fix direction: Include ingress_zone in SessionKey or validate metadata.ingress_zone == current from_zone on hit, treat mismatch as miss and re-evaluate policy. Add test: install from zone A, lookup from zone B same 5-tuple → must miss.
- Labels: fail-open, security, session, zone, vrf, policy-bypass
- Dedup note: Already filed as ps-review-020 S-001. Not new, but verified still present on b1bd96fb6. Do not count as new finding, included for required verification.

---

### [MEDIUM] WireGuard AllowedIPs overlap — 0.0.0.0/0 + specific route causes silent drop, duplicate prefixes only one peer wins (no commit-time validation)

- Title: WireGuard peer AllowedIPs with 0.0.0.0/0 or overlapping prefixes silently blackholes one peer's traffic
- Severity: Medium (availability loss, not fail-open)
- Confidence: High
- Class: implementation-bug / parity-gap
- Evidence:
  ```rust
  // userspace-dp/src/afxdp/wg/allowed_ips.rs:64-94 insert — no validation, allows 0.0.0.0/0
  // allowed_ips.rs:104-134 lookup — global LPM, most-specific wins
  // allowed_ips.rs:258-267 test documents: identical prefixes → only one peer wins
  //   "duplicate_cross_peer_prefix_only_one_peer_wins" — !matches_for_peer for loser
  ```
- Trace:
  1. Config WG tunnel with peer A AllowedIPs 0.0.0.0/0 (catch-all), peer B 10.0.0.0/24.
  2. Inner src 10.0.0.5 from peer A (legit) → lookup 10.0.0.5 resolves to peer B's /24 (more specific) → matches_for_peer returns false for peer A → packet dropped (AllowedIpsViolation).
  3. Identical prefix: two peers both 10.0.0.0/24 → only first wins, second never delivers.
  4. No commit error, no warning; Go compiler validateWireguardPeers does not check overlap (grepped pkg/config).
  What vSRX/Junos does: warns or rejects overlapping AllowedIPs, or at least documents global-LPM semantics. xpf silent.
- Refutation attempted: Checked Go validator — no overlap check; Rust insert tolerates; test explicitly says "The data structure tolerates the insert" — intentional data-structure behavior, but missing operator-facing validation. Not in /tmp/all_findings.txt (F-011 is local identity, F-046 endpoint forms, not AllowedIPs overlap). ps-review-021 reported similar but this commit still lacks fix.
- Why it matters: Multi-site WG with default route + specific site route is common; misconfig silently drops one peer's traffic with no observable error (only decap_drops_allowed_ips counter increments, not surfaced as commit error).
- Fix direction: Add commit-time warning/error when AllowedIPs overlap across peers for same tunnel; or at least when identical prefixes exist or 0.0.0.0/0 coexists with more-specific from different peer. Document global-LPM semantics.
- Labels: wireguard, silent-drop, implementation-bug, vsrx-parity
- Dedup note: Not in /tmp/all_findings.txt. Prior ps-review-021 reported same on c2ee227c4, still present on b1bd96fb6. Not counted as new if ps-review-021 is considered prior, but included here as verified residual with concrete trace.

---

### [MEDIUM] IPsec IKE gateway dynamic-hostname DNS lookup during commit stalls control plane 2s per gateway

- Title: IPsec IKE gateway dynamic hostname DNS lookup during commit can stall for 2s per gateway
- Severity: Medium
- Confidence: High
- Class: robustness-dos
- Evidence:
  ```go
  // pkg/ipsec/policy.go:725 const resolveHostFamilyTimeout = 2 * time.Second
  // pkg/ipsec/policy.go:737-770 defaultResolveHostFamily does r.LookupIPAddr(ctx, host) with 2s timeout
  // pkg/ipsec/policy.go:780-795 gatewayRemoteFamilyHint calls resolveHostFamily(gw.DynamicHostname) on every PrepareConfig
  // pkg/ipsec/policy.go:565-617 PrepareConfig iterates gateways and calls gatewayRemoteFamilyHint
  ```
- Trace: Operator commits config with N IPsec gateways using dynamic-hostname. PrepareConfig runs synchronously on daemon ordered apply (policy.go:720-725 comment: "PrepareConfig runs SYNCHRONOUSLY in the daemon's ordered apply sequence"). Each gateway triggers DNS lookup with 2s timeout. N=5 → up to 10s stall. If DNS unreachable (control link down during boot), every IPsec gateway stalls 2s. Commit latency scales linearly. resolveHostFamily var is test seam only, no prod cache/dedup.
- Refutation attempted: Checked if PrepareConfig runs async — no, synchronous. Checked if DNS result cached — no. Comment says "2s is ample for a hint" and "must never stall commit for full glibc timeout" but 2s per gateway still stalls commit proportionally. Checked if lookup is authoritative — comment says "strongSwan does authoritative resolution at IKE time, this is only a hint" — blocking commit on a hint is disproportionate.
- Why it matters: Control-plane DoS under DNS failure or bulk IPsec gateway config. Management unresponsive during stall.
- Fix direction: Cache DNS family hints per hostname per commit; or resolve in parallel; or skip DNS when hostname already bare IP (already handled at 789) but not for hostnames; or make family hint best-effort without blocking (return 0/family-agnostic on DNS timeout <100ms).
- Labels: robustness-dos, ipsec, performance
- Dedup note: Not in /tmp/all_findings.txt (no prior DNS stall finding). ps-review-021 reported same on c2ee227c4, still present on b1bd96fb6.

---

### [MEDIUM] HA heartbeat auth HMAC verified AFTER parsing — cluster ID / node ID from unauthenticated data drives election before auth check

- Title: HA heartbeat HMAC verified after UnmarshalHeartbeat — cluster ID / node ID parsed from unauthenticated data before auth check
- Severity: Medium
- Confidence: High
- Class: implementation-bug / secret-leak
- Evidence:
  ```go
  // pkg/cluster/heartbeat.go:717 pkt, err := UnmarshalHeartbeat(buf[:n]) // line 717 parses all fields
  // pkg/cluster/heartbeat.go:725 if int(pkt.ClusterID) != m.ClusterID() { continue } // trusts parsed ClusterID
  // pkg/cluster/heartbeat.go:733 if int(pkt.NodeID) == m.NodeID() { continue } // trusts parsed NodeID
  // pkg/cluster/heartbeat.go:740-753 key := controlLinkAuthKey(); session,counter,present := heartbeatAuthTrailer(buf[:n]); macOK := ...; verifyHeartbeatMAC; heartbeatAuthDecision
  ```
- Trace: Attacker on control-link L2 spoofs UDP 4784 heartbeat with valid magic "BPFX", version 1, arbitrary cluster ID, node ID, groups, no auth trailer. Parser accepts, extracts fields, only then runs auth. If no auth key configured (legacy) → accept (dual-accept). If key configured but peerAuthSeen=false (early boot ~200ms), unauthenticated frame also accepted per heartbeatAuthDecision: `if !keyConfigured { return true }` / `if !present && !peerAuthSeen { return true }`. Attacker-controlled GroupID/Priority/Weight/State flows into handlePeerHeartbeat → runElection → force local SECONDARY (weight 0) or split-brain (both PRIMARY).
  What vSRX does: Junos control link is point-to-point, but still authenticates before acting; xpf verifies after parsing.
- Refutation attempted: Checked handlePeerHeartbeat — no re-auth, rebuilds peerGroups directly from pkt.Groups. Checked if Unmarshal already consumed buf — yes, but verification happens after. Correct order would verify HMAC before parsing. For keyed clusters past bootstrap (peerAuthSeen=true), unauthenticated rejected — window is (a) no key (legacy) or (b) early boot before peer authed. Compared with session-sync stream auth (sync_auth.go:329-408) which authenticates before trusting any frame — correct ordering there.
- Why it matters: L2-adjacent attacker (compromised VM on same fabric VLAN, or control-link tap) can drive election, force failover, cause split-brain. 30s startup grace mitigates but not eliminates — attacker only needs to win within window or keep injecting.
- Fix direction: In heartbeatReceiver.readLoop, call verifyHeartbeatMAC / heartbeatAuthDecision BEFORE UnmarshalHeartbeat, or at least before trusting ClusterID/NodeID. HMAC covers entire frame including header, so verification must precede parsing. Pass raw bytes to verification first, parse only on success (or on dual-accept legacy path).
- Labels: security, ha, heartbeat, auth-ordering
- Dedup note: Not in /tmp/all_findings.txt (F-261 GroupID uint8 overflow, not auth ordering). ps-review-021 reported same, still present.

---

### [MEDIUM] VRRP masterDownInterval uses peer's advertised Max Adver Int without bounds — attacker can set Max Adver Int = 1 (10ms) to cause 30ms failover and constant flapping

- Title: VRRP masterDownInterval uses peer's advertised interval without minimum clamp — attacker can set Max Adver Int = 1 to cause fast flap
- Severity: Medium
- Confidence: High
- Class: robustness-dos / protocol-corruption
- Evidence:
  ```go
  // pkg/vrrp/instance.go:98-112 masterAdverInterval learned from peer's Max Adver Int: time.Duration(pkt.MaxAdvertInt)*10*time.Millisecond
  // pkg/vrrp/instance.go:648-656 effectiveAdvertInterval returns learned when learned>0 else localMS
  // pkg/vrrp/instance.go:657-675 masterDownInterval = 3*advert + skew, advert = effectiveAdvertInterval(...)
  // pkg/vrrp/packet.go:21 MaxAdvertInt uint16 — 12 bits usable &0x0FFF, range 0..4095 centiseconds = 0..40.95s, min non-zero 1 = 10ms
  // pkg/vrrp/instance.go:1500-1508 recordMasterAdvert: if pkt.MaxAdvertInt>0 { vi.masterAdverInterval = ... } — no bounds check
  ```
- Trace: Attacker on same L2 as VRRP RETH (compromised VM on same VLAN) sends forged VRRP advert VRID=target, Priority=1 (low, victim stays MASTER), MaxAdvertInt=1 (10ms). Victim recordMasterAdvert learns masterAdverInterval=10ms. masterDownInterval = 3*10ms + skew(10ms*(256-255)/256) ≈ 30ms. Later attacker stops, victim's masterDownInterval still 10ms-based. Any 30ms gap in legitimate master adverts (normal jitter on loaded system) → victim falsely declares master dead → flapping, VIP moves, GARP storms, session disruption. RFC 5798 §6.4.2 says BACKUP uses Master_Adver_Interval from master's advertisement — does not mandate bounds, but defensively should clamp to sane minimum (e.g. 100ms per RFC 5.2.5 recommended minimum 10 centiseconds = 100ms, or local configured interval).
  MaxAdvertInt=0 already handled (falls back to local, line 650). Only 1 triggers fast path.
- Refutation attempted: Checked if masterAdverInterval reset when master goes away — no explicit reset, but lastMasterSeen staleness check in shouldPreemptObservedMaster / preemptingLiveLowerMaster also uses same poisoned interval (effectiveAdvertInterval) → timeout fires fast AND preempt gate opens fast, amplifying flapping. Checked RFC: recommends minimum Adver_Int 10 centiseconds (100ms). Max Adver Int=1 centisecond (10ms) violates recommended minimum.
- Why it matters: Low-skill L2 attacker causes VRRP flapping / split-brain with one crafted packet. Flapping causes VIP moves, forwarding disruption. Not fail-open but DoS breaking HA.
- Fix direction: In recordMasterAdvert, clamp MaxAdvertInt to minimum of cfg.AdvertiseInterval/10 or hard floor 10 centiseconds (100ms) — or refuse to adopt learned interval smaller than reasonable fraction of local. Log warning when clamping.
- Labels: robustness-dos, vrrp, protocol-corruption
- Dedup note: F-076 in all_findings is "BACKUP never adopts Master's advertised interval" — the fix that added this adoption. This is a NEW bug IN that fix: missing bounds check, not duplicate. Not in /tmp/all_findings.txt as this specific bypass. ps-review-021 reported same.

---

### [MEDIUM] XFRM interface ID collision — st0 and st0.0 derive same if_id 1, runtime guard drops both tunnels silently

- Title: XFRM interface ID derivation collision — st0 and st0.0 derive same if_id but different names — runtime guard drops both, no commit error
- Severity: Medium
- Confidence: High
- Class: implementation-bug
- Evidence:
  ```go
  // pkg/routing/xfrm.go:58-112 Apply builds desired name→if_id map, detects collision when different device name already claimed this if_id (90-100), drops BOTH (107-111), logs Error
  //   if prev, dup := idToName[ifID]; dup && prev != ifName { collidingIDs[ifID] = struct{}{} }
  // pkg/config/types_ipsec.go XFRMIfNameAndID (referenced at pkg/ipsec/policy.go:190): bare "st0" and "st0.0" both yield ifID=1
  ```
- Trace: Operator configures VPN-A bind-interface st0, VPN-B bind-interface st0.0. XFRMIfNameAndID("st0") → ("st0",1), ("st0.0") → ("st0.0",1) — same if_id=1, different names. xfrmManager.Apply detects collision, logs Error, drops BOTH from desired — neither xfrmi device created, both tunnels fail closed (no leak, correct fail-closed). But commit succeeds, only runtime Error log, no commit-time diagnostic. Operator sees "commit green, both tunnels down, hard to diagnose". HA peer-sync (tolerant path) where config passes on primary silently broken on standby.
  Comment at xfrm.go:72-76 says "proper long-term fix is commit-time rejection ... tracked separately" — acknowledging gap.
- Refutation attempted: Checked commit-time validators — none check XFRM if_id collision. xfrmManager is last line of defense, comment says so. Fail-closed correct (drop both, no leak), but operator experience poor. Not fail-open.
- Why it matters: Typo or migration leftover (st0 vs st0.0) commits green, both tunnels down, cryptic log. During HA, primary may have different code path or mixed version, causing HA divergence.
- Fix direction: Add commit-time validation validateIPsecBindInterfaceCollision detecting XFRMIfNameAndID if_id collision across VPNs, reject with clear error. Keep runtime guard as defense-in-depth.
- Labels: ipsec, xfrm, commit-validation-gap, implementation-bug
- Dedup note: Not in /tmp/all_findings.txt. xfrm if_id guard itself likely added as fix for prior issue (#2909 ref in comment). This reports missing commit-time gate that runtime guard's own comment calls out. ps-review-021 reported same.

---

### [MEDIUM] F-271: peer_has_confirmed_session ignores REJECT_AFTER_TIME — expired session appears confirmed, delays rekey

- Title: peer_has_confirmed_session ignores REJECT_AFTER_TIME — expired session still reports confirmed, delays rekey and causes blackhole
- Severity: Medium (availability)
- Confidence: High
- Class: implementation-bug
- Evidence:
  ```rust
  // userspace-dp/src/afxdp/wg/engine.rs:730-737
  pub(crate) fn peer_has_confirmed_session(&self, pubkey: &[u8;32]) -> bool {
      let Some(peer) = self.peer_arc(pubkey) else { return false };
      matches!(peer.current.read().unwrap().as_ref(),
          Some(session) if session.is_confirmed())
  }
  // session.rs:42-43 REJECT_AFTER_TIME_NS = 180_000_000_000 (180s)
  // try_encap (engine.rs:1278-1283) enforces REJECT_AFTER_TIME and returns NoSession, arms rekey
  // but peer_has_confirmed_session does not check age
  ```
- Trace: Session created at T=0, initiator role, confirmed. At T=181s, session expired per REJECT_AFTER_TIME, but not yet GC'd by expire_sessions (1s tick, but lock contention could delay). Control thread calls peer_has_confirmed_session to decide whether to initiate — returns true (session exists, confirmed) → skips rekey initiation. Meanwhile try_encap at T=181s+ enforces REJECT_AFTER_TIME, returns NoSession, drops packet, arms rekey edge via request_rekey. But peer_has_confirmed_session still true, so timer_pass_for_peer may not initiate? Actually timer_pass also checks peer_has_usable_session (which DOES check REJECT_AFTER_TIME at timers.rs:137-147) — but peer_has_confirmed_session is used by control thread's first_peer bring-up path (coordinator/wg_control.rs). If that path sees confirmed true, it won't initiate. Blackhole window = until expire_sessions clears expired session (up to 1s normally, indefinite under lock contention).
  What wireguard-go does: checks REJECT_AFTER_TIME before reporting confirmed.
- Refutation attempted: Checked expire_sessions — holds reconcile_lock, iterates peers, drops expired, removes demux entries. Runs every 1s in control thread, so window normally 0-1s. Checked try_encap — enforces REJECT_AFTER_TIME and arms rekey via request_rekey, so data path does trigger rekey even if peer_has_confirmed_session lies. But control thread's decision to initiate based on peer_has_confirmed_session could still be delayed. Not a persistent blackhole, but a 0-1s blackhole per rekey, plus potential indefinite if expire_sessions delayed.
- Why it matters: Traffic blackhole for up to 1s (or longer under contention) at each 180s rekey boundary. For high-rate tunnel, 1s drop is visible. Violates WG spec: expired keys MUST NOT be used.
- Fix direction: Make peer_has_confirmed_session check REJECT_AFTER_TIME (now_ns - session.created_ns < REJECT_AFTER_TIME_NS) like peer_has_usable_session does. Or unify both via peer_has_usable_session.
- Labels: wireguard, availability, implementation-bug
- Dedup note: Exactly F-271 in /tmp/all_findings.txt: "peer_has_confirmed_session ignores REJECT_AFTER_TIME — correctness depends entirely on expire_sess". Verified still present on b1bd96fb6. Not new, but validated.

---

### [LOW] VRRP raw IPv6 fallback path has no hop-limit check — attacker on multi-hop path can forge VRRP via raw socket while AF_PACKET path drops

- Title: VRRP IPv6 hop-limit check only on AF_PACKET path, raw IPv6 fallback (receiverIPv6) skips hop-limit validation
- Severity: Low
- Confidence: High
- Class: protocol-corruption
- Evidence:
  ```go
  // pkg/vrrp/instance.go:1364-1367 parseAfPacketIPv6 hop-limit check: if ip6[7] != 255 { return }
  // pkg/vrrp/instance.go:1155-1242 receiverIPv6 — parses via ParseVRRPPacket(buf[:n], true, ...) directly, no hop-limit check
  // manager.go:1041 sets IPV6_MULTICAST_HOPS=255 for sending, but receive path hop-limit not checked on raw socket
  ```
- Trace: AF_PACKET path (primary, 99% of deployments) checks hop-limit 255 at line 1365 — correct per RFC 5798 §5.1.2.3. Raw IPv6 fallback (when afPacketFD<0, i.e., AF_PACKET open failed) receives via ipv6.NewPacketConn with FlagInterface — no hop-limit validation. Attacker on multi-hop path (not L2 adjacent) could forge VRRP advert with hop-limit <255 that reaches raw IPv6 receiver (kernel does not enforce hop-limit on raw IPv6 sockets by default — IPV6_RECVHOPLIMIT must be enabled explicitly, which this code does not). Raw path would accept, AF_PACKET would drop — inconsistent. Split-brain possible if one node uses AF_PACKET (drops) and another uses raw IPv6 fallback (accepts) — e.g., after AF_PACKET open failure on one node.
  AF_PACKET is primary, raw IPv6 fallback only when AF_PACKET unavailable (log Warn "af_packet unavailable, using separate IPv6 raw socket fallback"). So narrow window.
- Refutation attempted: Checked if IPV6_RECVHOPLIMIT is set on raw socket — no, only IPV6_MULTICAST_HOPS/IPV6_UNICAST_HOPS set for sending. Checked if kernel enforces hop-limit 255 on raw IPv6 — no, raw sockets deliver regardless of hop-limit unless IPV6_RECVHOPLIMIT + explicit check. Checked if receiverIPv6 parses hop-limit from control message — no, only interface index.
- Why it matters: Multi-hop attacker (not L2 adjacent) could forge VRRP and cause split-brain on nodes using raw IPv6 fallback. Low because AF_PACKET is primary and fallback rare.
- Fix direction: Add hop-limit validation to receiverIPv6 path: enable IPV6_RECVHOPLIMIT via setsockopt, read hop-limit from control message (like FlagInterface), reject if !=255. Or at minimum log warning when raw IPv6 fallback active and hop-limit not checked.
- Labels: vrrp, ipv6, protocol-corruption
- Dedup note: Not in /tmp/all_findings.txt. F-076 covers master interval, not hop-limit. ps-review-021 Finding #3 reported similar (but concluded AF_PACKET correct, raw fallback gap Low) — still present.

---

### [LOW] HA heartbeat IPv4-only — no IPv6 control-link support

- Title: HA heartbeat IPv4-only, no IPv6 control-link support
- Severity: Low
- Confidence: High
- Class: parity-gap
- Evidence:
  ```go
  // pkg/cluster/heartbeat_manager.go:44-46 net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", peerAddr, HeartbeatPort))
  // same at line 50 for local, line 55-69 vrfListenConfig creates udp4 listener
  ```
- Trace: HA heartbeat only supports IPv4. If control link is IPv6 (fabric over IPv6, or control link on IPv6-only network), StartHeartbeat fails. vSRX supports IPv6 control links (though uncommon). Fabric/sync TCP uses net.Dialer with "tcp" (dual-stack) so session-sync could work over IPv6, but heartbeat cannot — cluster appears single-node. Control link almost always IPv4 point-to-point in prod, so Low.
- Fix direction: Support "udp" dual-stack or detect family from address and use udp4/udp6 accordingly, similar to resolveInterfaceAddress family handling. Or explicitly reject IPv6 control-link at commit with clear error.
- Labels: parity-gap, ha, ipv6
- Dedup note: Not in /tmp/all_findings.txt. ps-review-021 Finding #12 reported same, still present.

---

### [LOW] IPsec PSK not zeroized — plaintext PSK remains in heap after use, never wiped

- Title: IPsec PSK not zeroized — Secret type is string wrapper, no wipe, remains in heap, capturable via core dump
- Severity: Low
- Confidence: High
- Class: secret-leak / hardening
- Evidence:
  ```go
  // pkg/ipsec/crypto.go:65-70 normalizePSK returns string (decoded PSK) as Go string, immutable, not zeroized
  // pkg/ipsec/policy.go:268-285 secret := vpn.PSK.Reveal(); decoded, err := normalizePSK(secret); ... fmt.Fprintf("    secret = \"%s\"\n", ...)
  // pkg/config/types_ipsec.go type Secret string — no Zeroizing, no wipe
  // Compare with WG: userspace-dp/src/afxdp/wg/engine.rs uses Zeroizing<[u8;32]> for local_private_key and PSK — correctly wiped
  ```
- Trace: Operator configures IPsec VPN with PSK ascii-text "s3cr3t" or $9$ encrypted. compileIPsec stores as Secret (string). PrepareConfig copies, normalizePSK decodes $9$ into new string (decoded plaintext). renderConfig writes secret to /etc/swanctl/conf.d/xpf.conf with 0600 (expected for strongSwan). But Go strings holding plaintext PSK (original Secret, decoded PSK, intermediate copies via Reveal()) are never zeroized, remain in heap until GC, and even after GC, Go runtime does not zero memory. Core dump (/proc/<pid>/mem, gcore, crash dump) leaks PSK. WG correctly uses Zeroizing for same class of secret.
  What vSRX does: Junos master-password encrypts PSKs at rest, but runtime also holds plaintext. xpf's WG path zeroizes, IPsec path does not — inconsistency.
- Refutation attempted: Checked if Secret type has wipe — no, just string alias. Checked if normalizePSK zeroes input — no, returns new string, original remains. Checked if swanctl config file is 0600 — yes, at-rest file protected, but heap copy remains. Checked WG comparison — WG uses Zeroizing, IPsec does not. This is hardening, not direct exploit, but inconsistent secret handling.
- Why it matters: Defense-in-depth — core dumps, /proc/mem inspection by colocated process (if compromised), or heap snapshot leak PSK. Operator expects PSK to be protected (master-password feature exists). WG path shows project knows to zeroize.
- Fix direction: Wrap IPsec PSK in Zeroizing or secretbox type, zero after render, or store as []byte and wipe after use. Or document as accepted risk (IPsec PSK must be readable by strongSwan, so at-rest file already plaintext — heap copy is secondary). At minimum, make Secret type use []byte + zeroize on drop (or sync with WG pattern).
- Labels: secret-leak, hardening, ipsec, vsrx-parity
- Dedup note: F-020 in all_findings is "Config secret redaction bypassed by raw-AST render surfaces" — different issue (redaction, not zeroization). No prior finding about IPsec PSK not zeroized vs WG Zeroizing. Possibly overlaps with F-050 master-password at-rest encryption defeated, but not same.

---

### [LOW] Cluster election same NodeID deadlock — both nodes same NodeID, same priority, dual-active stays PRIMARY on both (split-brain)

- Title: Cluster election same NodeID deadlock — both nodes same NodeID, same priority, dual-active stays PRIMARY on both
- Severity: Low (misconfig, but permanent split-brain)
- Confidence: Medium
- Class: implementation-bug / robustness-dos
- Evidence:
  ```go
  // pkg/cluster/election.go:186-228 non-preempt dual-active:
  //   if localEff < peerEff { return electLocalSecondary }
  //   if localEff == peerEff && m.nodeID > m.peerNodeID { return electLocalSecondary }
  //   return electNoChange // both stay PRIMARY when nodeIDs equal
  // preempt tie-break line 171-181 same: // Same node ID (shouldn't happen) — no change.
  ```
- Trace: Factory-reset second node, re-join with same node ID (config copy-paste error, both set to node 0). Both boot, both become PRIMARY (no peer initially). When they discover each other, electRG dual-active: localEff==peerEff, nodeID 0 == peerNodeID 0 → electNoChange on both → both stay PRIMARY → split-brain, VIP/RETH on both, ARP flux, session/forwarding duplication. Comment acknowledges "shouldn't happen" but doesn't handle — should still make progress deterministically (e.g., control-link IP compare) rather than deadlock.
  Commit-time validation does not reject same NodeIDs (cluster has no global view at commit). Heartbeat does not reject same-NodeID peer (handlePeerHeartbeat stores peerNodeID even if same).
- Fix direction: In tie-break, use >= instead of > for secondary (at least one yields), or secondary key (control-link IP compare) when NodeIDs equal. Detect same-NodeID peer at handlePeerHeartbeat and log Error.
- Labels: robustness-dos, ha, cluster, split-brain
- Dedup note: Not in /tmp/all_findings.txt (F-261 GroupID uint8, not NodeID). ps-review-021 Finding #13 reported same, still present.

---

## Negative results (verified fail-closed / not exploitable)

- **N-01 WireGuard responder rekey blackhole — FIXED**: 3-slot model (peer.rs:339-382, engine.rs:1169-1198, session.rs:119-129) — verified no blackhole.
- **N-02 WG TAI64N anti-replay — FIXED**: peer.rs:236-244, handshake_session.rs:576-581 — #4092 holds.
- **N-03 WG cookie DoS — FIXED**: engine.rs:594-655, cookie.rs:74-138 — load gate + MAC2 + per-source bucket + budget.
- **N-04 IKE/IPsec multi-value truncate — FIXED**: ike.go:66-84, 146-168 — #3904 holds.
- **N-05 IPsec fail-closed — FIXED**: ike.go errIKEChainUnresolved + policy.go vpnUsesAHProposal skip — #4442 holds.
- **N-06 FRR rib-group 30000 before main — FIXED**: rules.go:46-47 — #3876 holds, replaces 33000 shadow.
- **N-07 GRE keepalive — FIXED**: tunnel.go applyAnchorLocked wires keepalive.
- **N-08 DF-bit inversion — FIXED**: policy.go:230-235 copy→yes, set→yes, clear→no — #4015 holds.
- **N-09 IPsec delete-terminate — FIXED**: manager.go:104-282 swapConnNames + terminateRemovedConns — #3941 holds.
- **N-10 IPsec PSK id selectors — FIXED**: policy.go:510-532 pskIDSelectors — #3952 holds.
- **N-11 parseSAOutput — FIXED**: ike.go:728-814 new parser — #3937 holds.
- **N-12 HA NAT pool / dnat_table / 1:N — FIXED**: #4388, #4393 ha.rs:339-351, #4399/#4438 NatIndexBucket.
- **N-13 RST/FIN session fix — FIXED**: forwarding/mod.rs cluster_peer_return_fast_path excludes RST/FIN — #4400/#4453/#4487 holds.
- **N-14 PBR reject/discards — FIXED in userspace**: forwarding/mod.rs RouteOverride::Drop — #4392 holds for filtered path, but kernel mirror residual (ps-review-024 M-01) still present — dedup, not re-reported as new.
- **N-15 next-table VRF leak — still present but dedup**: rules.go:84-172 global `to <dst> lookup <table>` — ps-review-024 M-03, not new.
- **N-16 WG short-record DoS — FIXED**: engine.rs:1449-1451 `if hdr.ciphertext.len() < POLY1305_TAG_LEN { return Err(ShortRecord) }` — prevents panic on 16..31-byte datagrams, verified.
- **N-17 WG reserved bytes strict parse — FIXED**: handshake.rs:223 `is_canonical_type` rejects non-zero reserved — verified.

---

## Suggested issue split

**Fail-opens first (blocker):**
- S-001 cross-zone session hijack — already filed, verify fix, do not duplicate.

**Medium (next fix batch):**
1. WG AllowedIPs overlap silent drop — add commit validation.
2. IPsec DNS stall on commit — add cache / parallel / best-effort.
3. HA heartbeat auth verify-before-parse — reorder readLoop.
4. VRRP MaxAdvertInt bounds — clamp learned interval.
5. XFRM if_id collision commit gate — add validator.
6. peer_has_confirmed_session REJECT_AFTER_TIME — check expiry (or unify with peer_has_usable_session).

**Low / hardening:**
- VRRP IPv6 raw fallback hop-limit — add IPV6_RECVHOPLIMIT check.
- HA heartbeat IPv6 — support udp6 or reject at commit.
- IPsec PSK zeroize — use Zeroizing like WG.
- Same NodeID split-brain — deterministic tie-break or detect at handlePeerHeartbeat.
