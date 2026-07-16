# Triage result — ps-review-036 (Cohorts 9-11: IPsec/IKE/WG + Routing/FRR + HA/Cluster/VRRP)

## Header
- **Cohort / scope**: crypto + HA re-audit — pkg/ipsec, pkg/config/compiler_ipsec*, pkg/routing, pkg/frr, pkg/cluster, pkg/vrrp, pkg/ipmon, userspace-dp WG/GRE/tunnel/HA.
- **Review base commit**: `33b891d11` (Merge PR #4563).
- **Triaged against current master**: `0b4109522e7f4a93cb3b8ec7b7655483bb5a6b3f` (fetched this session).
- **Base freshness**: **STALE by 3 relevant commits.** `33b891d11` PREDATES three HA/VRRP fixes that landed on master after the review was written:
  - `1ec29a035` — vrrp: clamp learned Master_Adver_Interval to a safe floor (#4548)
  - `2b3e25b53` — vrrp: enforce hop-limit 255 on the raw-IPv6 fallback receiver (#4549 F8)
  - `7e076ecbd` — cluster: fail closed on a duplicate-node-id cluster (#4549 F11)
  This is why the review reports #4548 / #4549-F8 / #4549-F11 as "CONFIRMED STILL PRESENT / OPEN" — they were open at the review's base but are **already-fixed on current master**.
- **Real bpfrx or avacado?** **Real bpfrx.** Every cited symbol exists on `origin/master`: `peer_has_confirmed_session`, `resolveGatewayFamilyHints`/`resolveFamilyHintConcurrency`, `masterAdverFloor`, `warnDuplicateNodeIDLocked`, `receiverIPv6` hop-limit gate, `sanitizeFRRValue`, `host_inbound_admits_iface`, `stage_ipsec_passthrough_check`, GRE `ifindex_to_zone_id`/`logical_ifindex`. No avacado-fork tell (no external nftables host-inbound subsystem — the review correctly cites the Rust zone-keyed classifier).
- **Outcome counts**: NOVEL genuine residuals = **0**. Already-fixed (verified present) = **11** (incl. 3 the review mis-marked open due to stale base). OPEN already-filed (confirmed still present) = **7**. NOT-MATERIAL / DELIBERATE (ps-031, do-not-refile) = **2**. Confabulated = **0**. Negatives verified = many (§5 of review, spot-checked correct).

## Method note
ps-036 is not a numbered-finding review — it is an exhaustive coverage/dedup document whose §4 concludes "High confidence — NEW findings: **None**." My re-audit independently verifies that conclusion against a master that has moved 3 commits past the review's base, and corrects the review's stale disposition on the 3 now-merged fixes. Weight: this is a self-triaging review (author already deduped against ps-031 + the filed issue list), so the risk here is not over-reporting but a *stale-base false-open* — which is exactly what I found and corrected. No finding was dropped; every item below carries a tracked disposition.

---

## Per-finding disposition (with reasoning)

### A. The 3 fixes the review reported OPEN that are now ALREADY-FIXED on current master

**A1 — VRRP MaxAdverInt no-min-clamp → 10ms flap (review: "OPEN #4548, CONFIRMED STILL PRESENT")**
- Disposition: **ALREADY-FIXED (#4548, commit `1ec29a035`).**
- Proof: `pkg/vrrp/instance.go:1542-1560` on current master now clamps: `if pkt.MaxAdvertInt > 0 { learned := ...; if floor := vi.masterAdverFloor(); learned < floor { learned = floor }; vi.masterAdverInterval = learned }`. The review quoted the pre-fix form (`vi.masterAdverInterval = time.Duration(pkt.MaxAdvertInt)*10*ms` with no floor) from its base `33b891d11`. The clamp floor is the node's own configured advertise interval, so a peer advertising MaxAdverInt=1 (10ms) can no longer collapse `masterDownInterval` to ~30ms and flap; a legitimately slower master (learned≥floor, the #4061 anti-premature case) is still adopted unchanged. **This finding is closed — not re-filing, not re-opening.**

**A2 — VRRP GTSM hop-limit on raw-IPv6 fallback receiver (review: "OPEN #4549 F8, no hop-limit check on receiverIPv6")**
- Disposition: **ALREADY-FIXED (#4549 F8, commit `2b3e25b53`).**
- Proof: `pkg/vrrp/instance.go:1188-1238` — `receiverIPv6` now sets `pc.SetControlMessage(ipv6.FlagInterface|ipv6.FlagHopLimit, true)`, reads `hopLimit = cm.HopLimit`, and rejects `if hopLimit != 255` with an explicit `#4549 F8` / RFC 5798 §5.1.2.3 comment. The review's claim that "raw IPv6 fallback — no hop-limit check" was true at its base but is refuted on current master. The AF_PACKET path (`parseAfPacketIPv6` `ip6[7] != 255` at :1402) was already correct; the fallback path now matches. **Closed.**

**A3 — VRRP/HA duplicate node-id (review: "OPEN #4549 same-node-id")**
- Disposition: **ALREADY-FIXED (#4549 F11, commit `7e076ecbd`).**
- Proof: `pkg/cluster/election.go:181-291` — election now detects `m.nodeID == m.peerNodeID` in every branch (preempt path :186-188, dual-active path :216-218, standard path :249-250) and returns `electLocalSecondary` ("duplicate node-id yields (invalid config)") — i.e. **fail-closed, both nodes stay SECONDARY, no split-brain**. `warnDuplicateNodeIDLocked` (:266) emits a rate-limited (≥30s) `slog.Error` and records `EventRG`. `NoteDuplicateNodeIDHeartbeat` wires the heartbeat side. **Closed.**

### B. Genuinely still-OPEN residuals (tracked in existing issues — NOT novel, NOT re-filing)

**B1 — HA heartbeat IPv4-only (F9, #4549 residual).** Confirmed still present: `pkg/cluster/heartbeat_manager.go:44/50/57/65` all hardcode `"udp4"` (ResolveUDPAddr + ListenPacket). IPv6 control-link unsupported. Per task, F9 REMAINS in #4549. Severity LOW: the control/fabric link is almost always IPv4 point-to-point on the fabric VLAN; no traffic-plane exposure, no fail-open — a deployment that *wants* an IPv6 heartbeat simply can't configure one (missing feature, not a break). Tracked, not novel.

**B2 — PSK zeroize (F10, #4549 residual).** Confirmed still present: `git grep -i "zeroiz" origin/master -- pkg/ipsec/` returns nothing — Go-side PSK material (decoded $9$ secrets) is held in ordinary `string`/`[]byte` never wiped. Per task, F10 REMAINS in #4549. Severity LOW: exploitation requires local process-memory / core-dump access (already game-over for a firewall control plane); Go strings are immutable and not reliably wipeable anyway. Defense-in-depth hardening, tracked in #4549, not novel.

**B3 — IPIP decap has no userspace zone enforcement (#4478, opus-172 M-1).** Confirmed still present: `git grep "try_native_ipip_decap|ipip_decap_index|IPIP_DECAP" origin/master -- userspace-dp/` returns **empty** — there is no userspace IPIP decap stage (unlike GRE, which HAS one: `gre.rs:751-760` re-stamps `ingress_zone` from `endpoint.logical_ifindex → ifindex_to_zone_id` onto the inner meta). IPIP is a kernel `Iptun`/`Ip6tnl` device; the kernel decaps and FIB-forwards the inner without re-entering xpf zone policy. Already filed OPEN #4478 (M-1). Not re-filing.

**B4 — FRR sanitize-belt residual: bare-`%s` slots (#4498).** Confirmed still present: `pkg/frr/policy_render.go:1686` `match source-protocol %s`, `:1727` `set ipv6 next-hop global %s`, `:1729` `set ip next-hop %s`, `:1802` `set origin %s` — all render `term.*` with no `sanitizeFRRValue` wrap (the other 10+ slots ARE wrapped, per #4482). Already filed OPEN #4498. LOW: commit-time validators reject control chars / non-IP / unknown-enum on these fields, so only the tolerant-load / peer-sync path (warn-only, #1960) could carry a newline into an FRR reload → reload-degrade, not privilege escalation. Not re-filing.

**B5 — Stage-11 IPsec passthrough exempt from per-zone host-inbound (#4323, deferred Option B).** Confirmed unchanged: `stage_ipsec_passthrough_check` still `RecycleAndContinue`s before `host_inbound_admits_iface`; primary enforcement remains the kernel nftables host-inbound chain. No new angle. OPEN deferred #4323. Not re-filing.

**B6 — bare 5-tuple cross-zone session key (#2387, P0).** Session-key symbols still present in `userspace-dp/src/afxdp/`; no zone field added to the conntrack key since the review base. OPEN P0 #2387. Not re-filing (already the highest-tracked item).

### C. Already-fixed, verified STILL present on current master (review §4 correct)

- **#4546** WG `peer_has_confirmed_session` REJECT_AFTER_TIME age gate — present `engine.rs:743-752` (`now_ns.saturating_sub(session.created_ns) < REJECT_AFTER_TIME_NS`). Symbol proving closed: the age-gate clause in the `matches!`. (MERGED this session per task.)
- **#4547** IPsec DNS parallel resolution — present `policy.go:805-828` (`resolveFamilyHintConcurrency = 8` bounded pool + `sync.WaitGroup`). (MERGED this session per task.)
- **#2933** XFRM if_id collision — commit-time `validateSecureTunnelBindInterfaceAST` + runtime `xfrmManager.Apply` fail-closed. (ps-031 F6 already-fixed.)
- **#3882** WG 3-slot responder rekey; **#4092** WG TAI64N anti-replay; **#4481** FRR cross-context default-action alias (`redistFailClosedRouteMap`); **#4482** FRR sanitize belt (10 slots); **#4376** VRRP equal-priority tie-break — all verified present by the review and spot-confirmed on master (GRE zone enforcement `gre.rs:751`, sanitize slots present).

### D. DELIBERATE / NOT-MATERIAL (ps-031, task says do-not-refile — confirmed still accurate)

- **F2 — WG AllowedIPs overlap.** DELIBERATE: standard WireGuard cryptokey routing (global LPM, most-specific-wins, anti-source-spoof via `matches_for_peer`); doc-test documents the intentional most-specific-wins behavior. Not a bug.
- **F4 — HA heartbeat HMAC-after-Unmarshal.** NOT-MATERIAL: `heartbeat.go:717` `UnmarshalHeartbeat` runs before `verifyHeartbeatMAC`/`heartbeatAuthDecision`, but `handlePeerHeartbeat` (the only state-mutating call — rebuilds peerGroups + runs election) is gated at `:747+` behind the accept decision; replay is gated on `macOK && nonceFresh`. The pre-auth ClusterID/NodeID checks only `continue` (increment recvErrors) — no mutation from Unmarshal alone. Disproving path: the accept-gate at the auth decision sits between Unmarshal and `handlePeerHeartbeat`, so a forged frame that fails HMAC never reaches election. Claim of a forge/replay-into-election is false. Cosmetic reorder only.

---

## Bottom line
No NOVEL genuine residual exists in cohorts 9-11 on current master. The review's own "no new findings" verdict is correct. The single correction is disposition-freshness: the review marked #4548 (VRRP clamp), #4549-F8 (GTSM hop-limit), and #4549-F11 (dup-node-id) as OPEN because its base `33b891d11` predated commits `1ec29a035` / `2b3e25b53` / `7e076ecbd` — all three are **merged and verified present** on `0b4109522`. F9 (HA IPv4-only) and F10 (PSK zeroize) remain the genuine open residuals in #4549. No confabulation — every cited symbol is real bpfrx code.
