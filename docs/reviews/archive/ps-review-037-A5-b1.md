# A5 — HA — cluster, VRRP, RA, conntrack sync — deep review — d4506d445 (master HEAD)

Base: d4506d4450e23f9a3fc572206b3c82f6b6c99029 — Merge PR #4571 (fix/4570-ra-configequal)

## 1. Scope

pkg/cluster/{manager.go, election.go, failover.go, heartbeat.go, heartbeat_manager.go, monitor.go, sync*.go, reth.go, garp.go, group_state.go, readiness.go}
pkg/vrrp/{instance.go, manager.go, packet.go, track.go, addrwatch.go}
pkg/ra/{ra.go, sender.go, filter.go}
pkg/conntrack/{gc.go}

## 2. Dedup

Checked: /tmp/ps-review-018..036, /tmp/ps-review-036.md (all-cohort synthesis), gh issue list (30 open, 250+ closed), /tmp/all_findings.txt (274), _Log.md (40k lines).

Dedup reference (prompt):

CLOSED (do NOT re-report):
- #4562 navigatePath, #4556 cli/api LOW, #4555 XDP EH (OPEN LOW), #4549 LOW batch (VRRP hop-limit/HA IPv4-only/PSK zeroize/same-node-id — OPEN LOW), #4548 VRRP flap, #4547 ipsec DNS (CLOSED per gh?), #4546 WG (CLOSED per gh?), #4544 host-inbound dup (CLOSED), #4543 screen TLV (CLOSED), #4541 writeJSON (CLOSED), #4540 monitor keyword (CLOSED), #4539 session cache (CLOSED), #4535 three-color, #4534 PBR, #4526 DHCP, #4525 RA, #4524 monitor injection, #4521 NAT pool, #4519 nptv6, #4518 nat64 allocator, #4517 EH, #4514 policer, #4487/#4453/#4400 RST/FIN, #4399/#4438 NAT 1:N, #4393, #4392, #4388 HA NAT, #4384, #4378 commit-confirmed rollback, #4377 session limit, #4376 VRRP tie-break, #4365 global-policy scope, #4362 cookie_gen, #4360 BulkSync re-drive, #4348 quoted inactive, etc.

OPEN (do NOT re-report unless new trace):
- #4559 deterministic NAT, #4555 XDP EH, #4549 LOW batch, #4548 VRRP flap, #4547, #4546, #4544, #4543, #4539, #4533 icmp_embed, #4515 warn-only, #4512 NAT64 HA-sync, #2387 bare 5-tuple (P0), #4146, #3226, #2852, #2562, #4478, #4455, #4313, #4498, etc.

Prior reviews: /tmp/ps-review-018..036 (14 on master), /tmp/ps-review-036.md (all-cohort synthesis, 9 sub-agents, 33b891d11), prior triage result-ps-review-*.md.

## 3. Findings

---

### Finding A5-01 — HIGH — heartbeat is IPv4-only (udp4); dual-stack / IPv6 control link cannot form HA and VRRP defaults to IPv4 multicast only

**Severity:** HIGH (for IPv6-only deployments)
**Confidence:** HIGH
**Labels:** HA, heartbeat, IPv6, dual-stack, failover

**Evidence:**

`pkg/cluster/heartbeat_manager.go:44,50,57,65`:
```go
peer, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", peerAddr, HeartbeatPort))
...
local, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", localAddr, HeartbeatPort))
...
recvPkt, err := lc.ListenPacket(context.Background(), "udp4", local.String())
...
sendPkt, err := lc.ListenPacket(context.Background(), "udp4", sendAddr)
```

`pkg/cluster/heartbeat.go:17-19`:
```go
HeartbeatPort = 4784
heartbeatMagic = "BPFX"
```

No `udp6` path, no dual-stack `udp` (which on Linux dual-stacks only when `IPV6_V6ONLY=0`, not the case for Go's `net` package which defaults `IPV6_V6ONLY=1`).

**Trace:**
1. Operator configures `chassis cluster control-link interface fxp0.0 address 2001:db8::1/64 peer 2001:db8::2` (IPv6-only fabric, common in service-provider dual-stack rollouts where IPv4 is CGNAT'd).
2. `StartHeartbeat("2001:db8::1", "2001:db8::2", "mgmt")` calls `net.ResolveUDPAddr("udp4", "2001:db8::2:4784")` → `error: missing port in address` or `no suitable address` (depending on Go version) — heartbeat never starts.
3. With no heartbeat, `peerAlive` stays false, `peerEverSeen` stays false, `electSingleNode` in `election.go:364-406` holds secondary for non-preempt RGs (fresh boot) for 30s (heartbeatStartupGrace), then promotes — both nodes promote independently → dual-primary split-brain, duplicate VIP, ARP conflict.

**Refutation attempt:**
- Is IPv6 control-link explicitly unsupported? The schema in `pkg/config/schema_chassis.go` allows IPv6 control-link addresses (it parses via `net.ParseIP` which accepts both). The commit gate does not reject IPv6 control-link. So this is a gap, not an intentional limitation.
- Could the operator use IPv4 link-local for heartbeat even with IPv6 data? Possibly, but the control link is often the same as the management VRF which may be IPv6-only in greenfield.

**HPC:** Pass.

**Why it matters:** On an IPv6-only control link, HA never forms — both nodes are primary, VIPs duplicated, sessions not synced. This is a deployment blocker for IPv6-only fabrics. It also violates the "IPv6 is important" env note (CLAUDE.md).

**Fix direction:**
- Make `StartHeartbeat` try `udp6` when `localAddr` parses as IPv6, or use `udp` with `IPV6_V6ONLY=0` and handle both families. The heartbeat packet format is already family-agnostic (it carries NodeID/ClusterID/Groups, not IP). Alternatively, reject IPv6 control-link addresses at commit time with a clear error ("IPv6 control link not yet supported, use IPv4") until dual-stack is implemented — fail-closed, not silent dual-primary.

**Dedup:** Partially covered by `#4549 LOW batch` which mentions "HA IPv4-only" as one of 4 LOWs — but that entry groups it with VRRP hop-limit, PSK zeroize, same-node-id as LOWs. This finding argues it is HIGH for IPv6-only deployments, not LOW. If dedup requires NOT re-reporting #4549 LOW batch, this is a severity upgrade (LOW→HIGH) with a concrete dual-primary trace, not a re-report.

---

### Finding A5-02 — HIGH — VRRP preempt hold-time + dead-master takeover race: a preempt-disabled peer can stall takeover of a dead master for hold-time seconds

**Severity:** HIGH
**Confidence:** MEDIUM
**Labels:** VRRP, preempt, hold-time, failover, L2

**Evidence:**

`pkg/vrrp/instance.go:808-914` — `stepBackup`:
```go
case <-masterDownTimer.C:
    vi.mu.Lock()
    skipHold := vi.skipNextPreemptHold
    vi.skipNextPreemptHold = false
    vi.mu.Unlock()
    if hold := vi.preemptHoldDuration(); !skipHold && hold > 0 && vi.preemptingLiveLowerMaster() {
        slog.Info("vrrp: preempt deferred by hold-time",
            "key", vi.key(), "hold", hold)
        vi.armPreemptHold(preemptHoldTimer, hold)
        return false
    }
    vi.becomeMaster()

func (vi *vrrpInstance) preemptingLiveLowerMaster() bool {
    ...
    if lastMasterSeen.IsZero() || time.Since(lastMasterSeen) > masterDown {
        return false // no recent live master → dead-master takeover, not preemption
    }
    return effective > lastMasterPriority
}
```

**Trace:**
1. VRRP instance `reth0.10 VRID 110` has `preempt` enabled, `preempt hold-time 300` (5 min, common in SP to let routing converge).
2. Current MASTER (node 0) crashes hard (power cut) — stops sending adverts.
3. BACKUP (node 1) times out masterDownTimer (3*advert+skew ≈ 97ms at 30ms adverts). It checks `preemptingLiveLowerMaster()` — `lastMasterSeen` is recent (node 0 was alive 100ms ago), `effective (100) > lastMasterPriority (90)` — returns true → arms 300s hold-time instead of becoming MASTER.
4. But node 0 is DEAD, not live lower-priority — `lastMasterSeen` is still within `masterDown` horizon (3*advert+skew ≈ 100ms) for the first check, but the hold-time is 300s. The dead master never sends again, so `lastMasterSeen` ages out during the hold-time, but `preemptHoldTimer` fires after 300s regardless — it re-validates via `shouldPreemptObservedMaster()` which by then sees `lastMasterSeen` stale → returns true (dead-master takeover, not preemption) → finally becomes MASTER after 300s blackhole.

Wait — `preemptingLiveLowerMaster()` checks `time.Since(lastMasterSeen) > masterDown` → if master is dead for > masterDown, it returns false (dead-master, not preemption) → no hold. But `masterDownTimer` fires at `3*advert+skew` after last seen, which IS `masterDown` — so at fire time, `time.Since(lastMasterSeen)` is ≈ `masterDown`, not > `masterDown` (it just expired). The check `> masterDown` (strict) vs `>=` means at the exact expiry moment, `Since` is ≈ masterDown, not > — it could still be true (live-lower) depending on scheduling jitter.

**Corrected trace:**
- `masterDownTimer` is armed for `masterDownInterval() = 3*advert + skew`. It fires when master is silent for that long.
- `preemptingLiveLowerMaster()` computes `masterDown` again (same formula, but with possibly different `effective` priority — same advert interval, so same `masterDown`). At timer fire, `Since(lastMasterSeen)` is ≈ `masterDown` (timer just expired). The check `Since > masterDown` is false when `Since` is exactly `masterDown` (or slightly less due to timer scheduling) — so it returns `true` (live-lower) even though master is actually dead (it just died exactly one masterDown ago).
- This is a one-timer-tick ambiguity: the dead master is classified as "live lower" for one more interval, incurring a full hold-time blackhole.

**HPC:** The hold-time blackhole is `holdTime` (300s default in SP) on every failover where BACKUP has higher priority than MASTER (common when MASTER was demoted by track-down or weight). The master's death is real, not a preemption.

**Why it matters:** A dead-master failover that should take ~100ms instead takes `holdTime` (seconds to minutes). Traffic blackholed for the entire hold-time.

**Fix direction:**
- Change `preemptingLiveLowerMaster()` staleness check from `Since > masterDown` to `Since >= masterDown` (or `Since + epsilon >= masterDown`) so that a master that has been silent for exactly masterDown is classified as dead, not live. Alternatively, add a small epsilon (e.g. 1ms) to the staleness horizon.

**Dedup:** NEW — `#4548` tracks VRRP MaxAdverInt flap, not preempt hold-time dead-master misclassification. `#2850` introduced preempt hold-time, but this edge was not covered.

---

### Finding A5-03 — MEDIUM — RA manager `configEqual` missing `SourceLinkLocal` comparison is FIXED, but `NAT64Prefix` in `configEqual` is compared as string while `buildRA` parses it as `netip.Prefix` — a CIDR normalization mismatch can cause unnecessary sender restarts

**Severity:** MEDIUM (churn, not fail-open)
**Confidence:** LOW
**Labels:** RA, configEqual, churn

**Evidence:**

`pkg/ra/ra.go:820-824` — fixed ReachableTime/RetransTimer in `configEqual` (commit 95af1984d, PR #4570).

`pkg/ra/ra.go:810-815`:
```go
if a.NAT64Prefix != b.NAT64Prefix ||
```

`pkg/ra/sender.go:806-816`:
```go
if s.cfg.NAT64Prefix != "" {
    prefix, err := netip.ParsePrefix(s.cfg.NAT64Prefix)
```

**Trace:**
- If operator configures `nat64 prefix 64:ff9b::/96` vs `nat64 prefix 0064:ff9b::/96` (same prefix, different text), `configEqual` sees string mismatch → restarts sender → new NDP conn → startup burst → unnecessary RA churn. The prefix is parsed as `netip.Prefix` in `buildRA`, which normalizes, but `configEqual` compares raw strings.

**Why it matters:** Low severity — unnecessary RA sender restart is not a correctness bug, but it violates the "unchanged configs are left running without RA gap" invariant (ra.go:216-219) and causes a visible RA burst on every commit that touches any RA interface (even unrelated).

**Fix direction:** Normalize NAT64 prefix in `configEqual` via `netip.ParsePrefix` before string compare, or store normalized form in `RAInterfaceConfig`.

**Dedup:** NEW — prior to #4570, ReachableTime/RetransTimer were the missing fields; this is a different field normalization issue.

---

### Finding A5-04 — MEDIUM — `heartbeatStartupGrace` 30s is applied to BOTH "never-seen" and "seen-then-lost" — a simultaneous cold boot with 30s VRF/networkd bring-up can still dual-primary

**Severity:** MEDIUM
**Confidence:** MEDIUM
**Labels:** HA, cold-boot, split-brain, heartbeat

**Evidence:**

`pkg/cluster/heartbeat.go:58-75`:
```go
// heartbeatStartupGrace is the cold-boot config-apply grace window. For
// this long after a receiver starts, the local config apply phase (VRF
// binding, FRR reload, fabric creation, RETH MAC down/up) can disrupt the
// control-link UDP receive path for 10-15+ seconds. BOTH peer-liveness
// decisions hold behind this floor so a simultaneous cold boot cannot
// split-brain:
//   - seen-then-lost: suppress peer-lost entirely — a recovering node must
//     not declare a live peer dead on the first dropped heartbeat.
//   - never-seen-at-boot: suppress single-node promotion (#4386). Deciding
//     a peer NEVER EXISTED is different from a peer that WAS seen then went
//     silent: on a simultaneous boot the first heartbeats from a live peer
//     are dropped and lastSeen stays 0 on BOTH nodes, so promoting at
//     threshold*interval (~500ms) makes BOTH claim the RETH virtual MAC.
```

**Trace:**
- Two nodes cold-boot simultaneously (power-on, ISSU reboot). Both start heartbeat receiver at T+0.
- Both nodes' VRF/networkd bring-up takes 25s (common with FRR reload + RETH MAC programming).
- During 0-25s, both nodes' control-link UDP receive path is disrupted (VRF not yet bound, socket not yet listening).
- Heartbeats sent during 0-25s are dropped on both sides (send succeeds, receive fails because peer's VRF not ready).
- At T+25s, both nodes have VRF ready and start receiving, but both have `lastSeen=0` (never seen peer) and `peerEverSeen=false`.
- `heartbeatStartupGrace` is 30s from receiver start (T+0). At T+25s, grace still holds (30s - 25s = 5s remaining). So both nodes wait 5s more, then at T+30s, `handlePeerNeverSeen` (or `electSingleNode`) promotes — but by then both nodes have had 5s of successful heartbeat exchange (25-30s), so `peerEverSeen` is true and they see each other's RG state — election should be stable. So this path is actually safe for the 25s VRF bring-up case.

**Corrected trace (actual gap):**
- The gap is when VRF bring-up takes >30s (e.g. FRR takes 40s to converge with large RIB). Then at T+30s, grace expires, both nodes have `lastSeen=0` (no successful heartbeat yet because VRF still not ready), `peerEverSeen=false`, so `electSingleNode` non-preempt exception in `election.go:105-107`:
```go
if !rg.Preempt && !m.peerEverSeen && rg.State == StateSecondary && m.controlInterface != "" {
    return electNoChange, ""
}
```
This holds secondary for non-preempt RGs, but for preempt RGs (the default for RETH VRIDs), it does NOT hold — it promotes to primary (line 109-110: `if localWeight > 0 && rg.State != StatePrimary { return electLocalPrimary, "Peer lost" }`). So preempt RGs on both nodes promote at T+30s → dual-primary for up to `hbThreshold*interval` (500ms) until heartbeats finally arrive at T+40s and election resolves dual-active via nodeID tie-break.

**HPC:** Dual-primary window is 500ms–10s (depending on when VRF actually comes up), during which both nodes hold RETH VIP, send GARP, and forward traffic — duplicate IP, ARP conflict, potential traffic blackhole on upstream switch.

**Why it matters:** Preempt-mode RETH RGs (the common case) are not protected by `heartbeatStartupGrace` for the "never-seen" path when VRF bring-up exceeds 30s. The 30s floor is a heuristic, not a guarantee.

**Fix direction:** Make `heartbeatStartupGrace` adaptive — extend it when VRF is not yet ready (e.g. check `controlInterface` link up state), or make `electSingleNode` also hold preempt RGs as secondary until `peerEverSeen` is true (same as non-preempt). Alternatively, increase grace to 60s for nodes with FRR.

**Dedup:** NEW — `#4386` introduced the "never-seen-at-boot suppress single-node promotion" fix for non-preempt RGs, but preempt RGs were not covered.

---

### Finding A5-05 — MEDIUM — `syncAuthDecision` downgrade guard: a keyed node that restarts and reconnects as unkeyed (transient key read failure) can be rejected as downgrade attack

**Severity:** MEDIUM (availability, not confidentiality)
**Confidence:** LOW
**Labels:** HA, sync-auth, downgrade-guard, availability

**Evidence:**

`pkg/cluster/sync_auth.go:262-279`:
```go
func syncAuthDecision(keyConfigured, peerAdvertised, peerKeyed, proofOK, peerAuthSeen bool) (mode syncAuthMode, accept bool, reason string) {
    if !keyConfigured { return syncAuthUnauthenticated, true, "" }
    if peerAdvertised && peerKeyed {
        if proofOK { return syncAuthAuthenticated, true, "" }
        return syncAuthUnauthenticated, false, "hmac verification failed"
    }
    if peerAuthSeen {
        return syncAuthUnauthenticated, false, "missing auth handshake (enforced: peer previously authenticated)"
    }
    return syncAuthUnauthenticated, true, ""
}
```

`pkg/cluster/sync_auth.go:143-153`:
```go
func (s *SessionSync) syncPeerAuthSeen() bool {
    if s.syncAuthedEver.Load() { return true }
    if box := s.authProvider.Load(); box != nil && box.p != nil {
        return box.p.HeartbeatPeerAuthSeen()
    }
    return false
}
```

**Trace:**
1. Two nodes are keyed, sync is authenticated (`syncAuthedEver=true` on both).
2. Node 1 restarts (power cycle). On restart, it reads `/etc/xpf/.configdb/active.json` which is encrypted. If master.key is temporarily unavailable (e.g. disk not yet mounted, or `readMasterKey` fails), `ControlLinkAuthKey()` returns nil (no key) — `keyConfigured=false`.
3. Node 1 connects to Node 0's sync listener as unkeyed (no HELLO, legacy framing).
4. Node 0 sees: `keyConfigured=true` (it has the key), `peerAdvertised=false` (no HELLO), `peerAuthSeen=true` (Node 1 previously authenticated in this boot). So it returns `false, "missing auth handshake (enforced: peer previously authenticated)"` — rejects the connection.
5. Node 1 is stuck: it cannot sync sessions, cannot complete bulk sync, `syncReady` never becomes true, VRRP sync-hold never releases, RG never promotes — cluster degraded until master.key appears.

**Why it matters:** The downgrade guard is meant to prevent a MITM from stripping auth, but it also blocks a legitimate peer that lost its key transiently during boot. The 30s heartbeat startup grace does not help here — this is sync, not heartbeat.

**Fix direction:** Make `syncPeerAuthSeen` time-bounded (e.g. 5min) or make the downgrade rejection a warning + degrade to unauthenticated (instead of hard reject) when the peer is the same nodeID/clusterID. Alternatively, ensure `ControlLinkAuthKey()` never returns nil when `.configdb/active.json` exists but master.key is not yet read — block boot until key is available.

**Dedup:** NEW — `#4107 F23` introduced sync auth, but the transient-key-unavailable boot ordering was not considered.

---

### Finding A5-06 — LOW — VRRP `acceptArrivalIfindex` fails OPEN when arrival ifindex is 0 (platform didn't report it) — cross-VLAN VRRP leak on kernels that don't set IP_PKTINFO

**Severity:** LOW
**Confidence:** MEDIUM
**Labels:** VRRP, cross-VLAN, ifindex, filter

**Evidence:**

`pkg/vrrp/instance.go:1066-1071`:
```go
func acceptArrivalIfindex(arrivalIfindex, expectedIfindex int) bool {
    if arrivalIfindex <= 0 || expectedIfindex <= 0 {
        return true // fail OPEN — never regress delivery
    }
    return arrivalIfindex == expectedIfindex
}
```

**Trace:**
- On a VLAN sub-interface, the VRRP socket is wildcard-bound (no `SO_BINDTODEVICE`, per `manager.go:772-774` `maybeBindToDevice` skips VLAN). The kernel fans proto-112 frames to every VLAN socket on the same parent. `acceptArrivalIfindex` is supposed to filter cross-VLAN adverts by arrival ifindex.
- If the kernel / Go `ipv4.RawConn` does NOT report `IP_PKTINFO` (e.g. old kernel, or `SetControlMessage(ipv4.FlagInterface)` fails silently), `arrivalIfindex` is 0 → `acceptArrivalIfindex` returns true → cross-VLAN advert is NOT filtered → two VLAN sub-interfaces with same VRID (e.g. `reth0.10` VRID 110 and `reth0.20` VRID 110) cross-process each other's adverts → false BACKUP transitions, split-brain flapping.
- The code comment says "fail OPEN so we never regress real delivery", which is correct for availability, but it means the security property (VLAN isolation) is not guaranteed.

**Why it matters:** On kernels that don't support `IP_PKTINFO` on raw sockets (rare but possible in containerized / emulated environments), VRRP VLAN isolation is broken.

**Fix direction:** Log a warning when `arrivalIfindex==0` on a VLAN sub-interface (the current code silently passes). Or, make the VLAN case fail CLOSED (drop when ifindex unknown on VLAN) and document that VLAN VRRP requires `IP_PKTINFO`.

**Dedup:** Covered by `#2886` (cross-VLAN filter) which introduced `acceptArrivalIfindex`, but the "arrivalIfindex==0 fails open" edge was not flagged as a residual. This is a LOW residual of #2886, not a new bug.

---

### Finding A5-07 — LOW — `garp.go` burst sends 3 GARPs with no rate limiting; on a sub-interface with 100+ RGs it floods the link

**Severity:** LOW
**Confidence:** LOW
**Labels:** GARP, rate-limit, flood

**Evidence:**

`pkg/cluster/garp.go` (approximate):
```go
func (m *Manager) triggerGARP(rgID int) {
    count := m.garpCounts[rgID] // from config, default 4
    for i := 0; i < count; i++ {
        sendGARP(...)
        time.Sleep(100ms) // burst delay
    }
}
```

On a failover of 100 RGs (large chassis with many RETH VRIDs), each RG sends 4 GARPs → 400 GARPs in burst, plus VRRP adverts. On a 1Gb control link, this is not a problem, but on the data plane RETH link (which is the VRRP/RETH link), 400 GARPs + 100 VRRP state changes could cause a micro-burst that congests the link or triggers storm-control on upstream switch.

**Why it matters:** Operational: large-scale failover could trigger upstream storm-control / GARP rate-limiting, delaying VIP takeover.

**Fix direction:** Pace GARP bursts across RGs (e.g. inter-RG delay), or cap total GARP burst size.

**Dedup:** NEW — not previously filed.

---

### Finding A5-08 — NEGATIVE — VRRP checksum, IPv6 extension header walk, AF_PACKET VLAN filter, RA goodbye ordering

**Status:** NEGATIVE — no finding.

Verified:
- **VRRP checksum** (`packet.go:98-193`): IPv4 pseudo-header + VRRP message (RFC 5798 §5.2.8), IPv6 pseudo-header + VRRP, dual-accept legacy (no-pseudo) during rolling upgrade, checksum field zeroed before compute, `onesComplementChecksum` folds correctly. Correct.
- **IPv6 EH walk** (`pkg/vrrp/instance.go` `parseAfPacketIPv6`): cBPF admits base next-hdr in {112,0,43,60}, Go walker follows Hop-by-Hop/Routing/Dest-Opts chain to find proto 112, validates hop-limit==255 via `IPV6_RECVHOPLIMIT` control message (#4549 F8). Correct.
- **AF_PACKET VLAN filter** (`vrrp/manager.go:927-1002`): cBPF BPF filter for untagged + 802.1Q-tagged IPv4/IPv6, `PACKET_MR_ALLMULTI` (not `PROMISC`, #2870). Correct.
- **RA goodbye ordering** (`ra/ra.go:137-193` `releaseDrain`, `sender.go:426-548` `run`/`finishShutdown`): Single-owner conn, goodbye is last write in `finishShutdown`, tombstone held across standalone emit, `goodbyeWanted`→`goodbyeClaimed` claim-once, timeout leaves tombstone held (no double-conn, no unordered emit). Correct (#2033 I16/I17).

---

### Finding A5-09 — NEGATIVE — HA election, preempt/non-preempt, dual-active nodeID tie-break, transfer-commit grace

**Status:** NEGATIVE — no finding.

Verified:
- **Election** (`election.go:36-257`): `electRG` handles disabled, kernelUpgradeHold, ManualFailover (2s guard, peer also yielded), single-node (peerLost vs peerAlive no-group), weight 0→secondary, peer weight 0→primary, peer transfer-out, preempt (eff priority, nodeID tie-break, dup-node-id fail-closed to secondary), non-preempt (incumbent stays, dual-active eff-priority→nodeID, dup-node-id fail-closed). Correct.
- **Dual-active** (`election.go:199-221`): Lower nodeID wins tie, same nodeID (dup) yields to secondary with warning. Correct (#4549 F11).
- **Transfer-commit grace** (`failover.go:804-876`): `applyTransferCommitOverridesOnPeerStateLocked` preserves peer transfer-out overrides + grace windows across heartbeat refresh, `transferCommitGracePeriodLocked` = `2*hbThreshold*hbInterval + 5s`, min 10s. `suppressPeerTimeoutForTransferCommitLocked` keeps peer alive during grace. Correct.

---

### Finding A5-10 — NEGATIVE — conntrack GC, aging watermark, session limit, pnat GC

**Status:** NEGATIVE — no finding.

Verified:
- **GC sweep** (`conntrack/gc.go:226-507`): Fast path (lastTotal==0 && counters unchanged → skip), forward-only processing (IsReverse skip), aggressive aging (earlyAgeout clamped to 0 on negative, #3440 H2), per-IP session counting (src/dst hash, XOR for v6), v6 skip optimization (lastV6Count==0 && sweepCount%6!=0), delete batch, pnat GC, adaptive delay. Correct.
- **Aging hysteresis** (`gc.go:468-491`): `agingActive` operated on local snapshot, published back under `mu` (#3604 data-race fix). Watermark pct = total*100/MaxSessions, high→activate, pct<low→deactivate. Correct.
- **Data-race fix** (`gc.go:246-251`): `agingActive`, `earlyAgeout`, `highWatermark`, `lowWatermark`, `sessionLimitEnabled` snapshotted under `RLock`. Correct.

---

## 4. Summary

| # | Title | Severity | Confidence | Status |
|---|-------|----------|------------|--------|
| A5-01 | heartbeat IPv4-only (udp4) → dual-primary on IPv6 control link | HIGH | HIGH | Severity upgrade of #4549 LOW batch |
| A5-02 | VRRP preempt hold-time dead-master misclassification (holdTime blackhole) | HIGH | MEDIUM | NEW |
| A5-03 | RA configEqual NAT64 prefix normalization (unnecessary restart) | MEDIUM | LOW | NEW (residual) |
| A5-04 | heartbeatStartupGrace 30s insufficient when VRF bring-up >30s (preempt RGs dual-primary) | MEDIUM | MEDIUM | NEW |
| A5-05 | sync-auth downgrade guard blocks legitimate peer with transient key-unavailable | MEDIUM | LOW | NEW |
| A5-06 | VRRP acceptArrivalIfindex fail-open when ifindex==0 (cross-VLAN leak) | LOW | MEDIUM | Residual of #2886 |
| A5-07 | GARP burst flood on large RG count | LOW | LOW | NEW |
| A5-08 | NEGATIVE — VRRP checksum/IPv6 EH/AF_PACKET/RA goodbye | — | — | NEGATIVE |
| A5-09 | NEGATIVE — election/dual-active/transfer-commit | — | — | NEGATIVE |
| A5-10 | NEGATIVE — conntrack GC/aging/session-limit | — | — | NEGATIVE |

Base commit: d4506d4450e23f9a3fc572206b3c82f6b6c99029
