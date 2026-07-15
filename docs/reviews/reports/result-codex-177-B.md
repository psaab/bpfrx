# Triage result — codex-review-177, slice B (IDs A5 / A6 / A7)

- **Review file:** `/tmp/codex-review-177.md` (base commit d22789fa6 — STALE)
- **Verified against:** origin/master HEAD `812bf30c1` (fetched fresh; ~3300 commits ahead of base; ~33 recent PRs merged)
- **Slice owned:** every finding whose ID begins with A5, A6, or A7
- **Findings processed:** 48 (A5 = 18, A6 = 9, A7 = 21)
- **Verdict summary:** 48 GENUINE / 0 already-fixed / 0 symbol-gone / 0 not-material / 0 dup
- **Issues filed:** 48 new issues, **#5078–#5125** (1:1 with findings; no cohorting — none were pure test-coverage)
- **Method:** each finding re-verified against CURRENT origin/master via `git show origin/master:<path>` (never the stale working tree), across 5 parallel per-subsystem verification passes; all cited symbols still exist, quoted current code confirmed each defect unfixed.

Notably, despite ~33 recent merges, **none** of these 48 findings were fixed — the merge wave landed in other slices. Codex's ~90% signal held: 100% genuine here.

---

## Per-finding ledger

Format: `finding-id → verdict → #issue` + one-line current-code basis.

### A5 — cluster / HA / VRRP / RA (18)

| ID | Verdict | Issue | Current-code basis (origin/master) |
|----|---------|-------|-------------------------------------|
| A5-b1-F1  | GENUINE (High, sec) | #5078 | `sync_auth.go:330-408` sends proof before reading peer's, accepts equal/reflected nonce, `syncDeriveFrameKey` sorts nonces → undirected key; no role/identity binding. Reflection auth without PSK. |
| A5-b1-F2  | GENUINE (High)      | #5079 | `failover.go:243-277` runs remote `ManualFailover` (owner demote) before requester commit; abort restores only local override, no abort frame/lease/reqID → both nodes can strand secondary. |
| A5-b1-F3  | GENUINE (High)      | #5080 | `monitor.go:291-301` missing local link → warn+continue, no SetMonitorWeight(down); `UpdateGroups` replaces slice only → fail-open + stale monitor debt. |
| A5-b1-F4  | GENUINE (High, sec) | #5081 | `daemon_ha_sync.go:997-1020` clusterTransportKey has endpoints only; heartbeat timing snapshotted at start, `authConn.key` immutable → committed PSK/timing never applied live. |
| A5-b1-F7  | GENUINE (High)      | #5082 | `instance.go:1849-1867` becomeMaster advertises/emits before void `addVIPs`; `addVIPs` swallows AddrAdd failures; `ReconcileVIPs` check-then-act re-adds VIPs after demotion. |
| A5-b1-F9  | GENUINE (Med)       | #5083 | `vrrp.go:44-81` stores raw Junos name (no unit/family); manager key `{iface,groupID}` collides dual-stack v4/v6 → standalone/dual-stack VRRP silently not built / dropped. |
| A5-b1-F10 | GENUINE (Med)       | #5084 | `sync.go:436-441` configApplyItem `{gen,text}` has no epoch; `resetRecvGen` zeroes high-water without draining queued items → stale config applies across bulk reset. |
| A5-b1-F11 | GENUINE (Med)       | #5085 | `sync_bulk.go:19-32` override sends empty BulkStart/End; `sync.go:817-836` skips reconcile on empty set → stale peer sessions survive cold-prime. |
| A5-b1-F12 | GENUINE (Med, sec)  | #5086 | `heartbeat.go:483-505` admit re-anchors on any session change, no retired-session memory → captured A/B heartbeats replayed A→B→A keep dead peer alive. |
| A5-b1-F13 | GENUINE (Med)       | #5087 | `manager.go:409-416` no-change gate + `instance.go:473-490` updateConfig omit AdvertiseInterval & GARPCount → day-2 changes ignored. |
| A5-b1-F14 | GENUINE (Med)       | #5088 | `manager.go:968-1004` cBPF accepts only 0x8100; parser `instance.go:1415` accepts 0x88a8 → 802.1ad adverts dropped by kernel. |
| A5-b1-F15 | GENUINE (Med)       | #5089 | `instance.go:1912-1958` IPv6 advert serializes only global VIPs; virtual-router link-local never prepended (RFC 5798 §5.2.9/6.1). |
| A5-b1-F17 | GENUINE (Low)       | #5090 | `packet.go:41-49` `buf[3]=uint8(count)` narrows unbounded count → 256 addrs wrap to Count=0. Filed Low (impractical MTU trigger). |
| A5-b1-F18 | GENUINE (Low, parity)| #5091 | `reth.go:106-114` per-node MAC vs RFC shared virtual MAC; GARP uses phys MAC. **Deliberate documented tradeoff** (FDB conflict avoidance on shared-PF VFs) — filed Low for tracking; may be WONTFIX / label-mode. |
| A5-b1-F19 | GENUINE (Med)       | #5092 | `ra.go:302-312` removal = hard stop (modeHard), `Clear` no goodbye → no final lifetime-zero RA on config removal (RFC 4861 §6.2.5). |
| A5-b1-F20 | GENUINE (Med)       | #5093 | `sender.go:293-303` discards goodbye success bool; `daemon_ha.go:769-790` sets cold-boot sticky bit before async WithdrawOnce → swallowed failure, false success. |
| A5-b1-F21 | GENUINE (Med)       | #5094 | `ra.go:180-185`/`242-256` join-timeout reclaimer deletes tombstone, drops onProvenClose replacement + owed goodbye → interface can stay senderless. |
| A5-b1-F22 | GENUINE (Low, sec)  | #5095 | `sender.go:586-618` RS handler discards control msg, no HopLimit==255 / source-scope check (RFC 4861 §6.1.1). Rate-limit bounds impact → Low. |

### A6 — dataplane / NAT / firewall-filter / counters (9)

| ID | Verdict | Issue | Current-code basis |
|----|---------|-------|--------------------|
| A6-b1-F1 | GENUINE (High, sec) | #5096 | `legacy_dataplane.go:382-395` overrides only singular delete; BatchDelete/ClearAll promote to BPF mirror (`bpfShim`), no helper IPC → policy-tighten/clear-all leaves authoritative Rust sessions forwarding (fail-open). |
| A6-b1-F2 | GENUINE (Med, sec)  | #5097 | `filters.go:489-498` `continue` on unresolved ref before `hasExcept` set → sole except loses polarity; Rust `matching.rs:260-267` returns match-none → discard term fail-open (tolerant-load path). |
| A6-b1-F3 | GENUINE (Low)       | #5098 | `maps_counters.go:36-44/153-166/215-233` ClearAll never resets `userspaceCounterOffsets` → cleared global totals snap back in userspace mode. |
| A6-b1-F4 | GENUINE (Low)       | #5099 | `compiler_nat.go:122-145` collision fallback resolves vs already-assigned IDs only → colliding NAT keys swap counter IDs on reorder. FNV collision pair reproduced. |
| A6-b1-F5 | GENUINE (Low)       | #5100 | `fairness_throughput.go` never `delete(w.queues,key)` → vanished queue identities retained for process lifetime (mem + scrape-cost growth). |
| A6-b2-F2 | GENUINE (Med)       | #5101 | `nat_static.go:13-18` clampPort→0 collides with the whole-address wildcard sentinel; Rust `static_nat.rs:422-427` `(0,_)=>(None,None)` → invalid port becomes whole-address NAT (fail-open, lenient load). |
| A6-b2-F3 | GENUINE (Med)       | #5102 | `nat_destination.go:266-318` DNAT `application any` → `appConfigured` true but resolves nothing → emits `natNeverMatchPortRange`; SNAT normalizes `any`, DNAT doesn't → silent DNAT outage (reachable via strict commit). |
| A6-b2-F4 | GENUINE (Med)       | #5103 | `daemon_apply.go:878-891` calls `programRethMAC` (link DOWN/UP) then `PrepareLinkCycle` → worker/UMEM join barrier after the NIC transition (contract inversion); void return hides stop_workers failure. |
| A6-b2-F5 | GENUINE (Low)       | #5104 | `process_status.go:207-212`/`process_napi.go:278-284,362-369` prewarm has no singleflight guard → overlapping full scans + unbounded per-target goroutines. |

### A7 — daemon host-integration / routing / FRR / IPsec / LLDP / RSS (21)

| ID | Verdict | Issue | Current-code basis |
|----|---------|-------|--------------------|
| A7-b1-F1  | GENUINE (High, sec) | #5105 | `daemon_snmp_reconcile.go:41-69` hash writes name+authorization only, omits Clients/Restrict → clients-only edit no-ops, old source allowlist stays live (SNMPv2c source-restriction bypass). |
| A7-b1-F2  | GENUINE (High, sec) | #5106 | `daemon_system.go:856-985` early return on empty users; per-user password reconcile in-loop; key block gated `len>0` → deleted user / last SSH key leaves working host creds. |
| A7-b1-F4  | GENUINE (Med)       | #5107 | `daemon_ra.go:94` uses LinuxIfName(ResolveReth) (keeps unit) not ResolveKernelIfName; post-MAC repair indexes `Units[vlanID]` → RA/NDP fails when unit# ≠ vlan-id. |
| A7-b1-F5  | GENUINE (Med)       | #5108 | `daemon_flow.go:63-137` early return + RouteReplace only, no RouteList/RouteDel → withdrawn mgmt-VRF (table 999) routes never removed. |
| A7-b1-F6  | GENUINE (Low-Med)   | #5109 | `daemon_apply.go:1220` `_ = applyFRRConfig`; `manager.go` schedules retry only for degraded, not hard error from healthy state. Narrow trigger; on-disk config self-heals at restart. |
| A7-b1-F7  | GENUINE (Med)       | #5110 | `daemon_snmp_reconcile.go:250/265` serve discards `a.Start` error; hash published on launch → bind failure permanently disables SNMP while state says started. |
| A7-b1-F8  | GENUINE (Med)       | #5111 | `daemon_system.go:742-855` `os.Remove` doesn't set `changed`; `changed:=false` → removing final syslog dest skips rsyslog restart. |
| A7-b1-F9  | GENUINE (Low, sec)  | #5112 | `daemon_system.go:534-582` `if len(...)==0 { return }` → clearing ssh-known-hosts leaves managed trust file installed (revoked key stays trusted). |
| A7-b1-F10 | GENUINE (Low)       | #5113 | `daemon_apply.go:1478-1481` bare `d.mgmtVRFInterfaces = nil/=map` vs unsynchronized DHCP-callback reads → Go data race. |
| A7-b1-F11 | GENUINE (Low)       | #5114 | `host_tunables_daemon.go:140-151` clears capture unconditionally after void best-effort restore → failed restore loses debt, host stays pinned. |
| A7-b2-F2  | GENUINE (Med)       | #5115 | `policy_render.go:280-293/982-1022` any-term self → unconditional `neighbor X next-hop-self force` → rewrites all accepted routes, not the term's subset. |
| A7-b2-F3  | GENUINE (Low)       | #5116 | `policy_render.go:1385-1554` `-xpf-redist` alias in name-keyed namespace, no reserved-suffix/collision guard → operator name collision can undo #4481 fail-closed. Documented accepted risk. |
| A7-b2-F5  | GENUINE (Med)       | #5117 | `rules.go:557-596` PBR rule never sets `IifName`; `collectAttachedInputFilters` drops iface identity → kernel FBF over-steers cross-interface into wrong VRF. |
| A7-b2-F6  | GENUINE (Med)       | #5118 | `rules.go:194-198/442-446` next-table & rib-group clear debug-log RuleDel failures, don't aggregate (PBR does) → stale inter-VRF leak survives "successful" apply. |
| A7-b2-F7  | GENUINE (Med)       | #5119 | `bond.go:40-43/138-160` unconditional clearLocked (LinkDel tracked bonds) + daemon calls ApplyBonds every commit with no diff → unchanged LAG flaps on every commit. |
| A7-b2-F9  | GENUINE (Med)       | #5120 | `tunnel.go:1421-1427` binds VRF only when RI non-empty, no unbind branch; bypasses appliedRI claim machinery → WG TUN stays enslaved to old VRF on RI removal (comment concedes gap). |
| A7-b2-F10 | GENUINE (Med)       | #5121 | `lldp.go:235-345` no lifecycle mutex over cancel/wg; shutdown Stop (no applySem) races wg.Add vs Wait, can miss an RX socket → daemon hang / socket leak. |
| A7-b2-F11 | GENUINE (Low)       | #5122 | `ipsec/policy.go:463-486` sanitizeChildName maps all bad runes to '-' (non-injective) → distinct selector names collide to one strongSwan child. |
| A7-b2-F12 | GENUINE (Low)       | #5123 | `lldp.go:517-521/594-595` TTL=0 shutdown stored as ordinary neighbor, reaped only on 10s ticker → departed neighbor lingers up to 10s. |
| A7-b2-F13 | GENUINE (Low)       | #5124 | `rss_indirection.go:164-166` workers==1 early return, no default-table restore → transition from concentrated table leaves stale mlx5 indirection (RX on subset of queues). |
| A7-b2-F14 | GENUINE (Low)       | #5125 | `routes.go:64-84` + `status_parse.go` GetRouteDetailJSON `continue` on per-family failure, return nil err → partial/empty route output rendered as authoritative. |

---

## Notes / caveats flagged for the coordinator

- **A5-b1-F18 (#5091):** genuine RFC-5798 / vSRX interop divergence but the per-node RETH MAC is an **explicit documented design tradeoff** (avoids FDB conflicts when both nodes' member interfaces share an L2 domain / same-PF SR-IOV VFs — exactly the loss-cluster topology). Filed Low; likely resolution is WONTFIX or "explicitly label non-interoperable mode," not a straight fix.
- **A5-b1-F17 (#5090):** downgraded to Low — the 256-VIP trigger is not realistically reachable (IPv6 MTU caps a single-family list well below 255). Filed as validation hardening.
- **A7-b1-F6 (#5109):** weakest of the Mediums — requires the rare both-frr-reload-paths-fail mode from a healthy (non-degraded) state, and the managed section is written to frr.conf on disk so a restart reconverges. Filed Low-Medium.
- **Fail-open / security cluster:** #5078 (reflection auth), #5081 (PSK not applied), #5086 (heartbeat replay), #5096 (session mirror bypass), #5097 (except polarity), #5101 (NAT wildcard), #5105 (SNMP allowlist), #5106 (login creds), #5112 (ssh-known-hosts) — the highest-value subset.
- **Route-leak / VRF-isolation cluster:** #5108, #5117, #5118, #5120.
- No duplicates against the 76 open issues (#4800–#5030 range checked; nearest cohorts #4909/#4908/#4422/#4484 list different specific items).
- Did NOT touch `/tmp/.researched-codex-review-177.md`.
