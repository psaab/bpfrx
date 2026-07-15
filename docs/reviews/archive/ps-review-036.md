# xpf firewall deep security audit — master 33b891d11 — all-cohort synthesis

## 1. Base commit reviewed

```
33b891d11 Merge pull request #4563 from psaab/fix/4562-navpath-descent
  40a5ba8ec config: descend into all same-prefix siblings in navigatePath (#4562)
  87a431a17 Merge pull request #4561 from psaab/fix/4556-cli-api-low-hardening
  ...

Branch: master, up to date with origin/master.
HEAD 8cd816e35 → 33b891d11 delta:
  4559 deterministic NAT advisory (ps-034 M-01, med→low-med) — WARNING only, not full block allocator
  4562 navigatePath intermediate descent (ps-035 N-1, display-only) — unionChildren in both branches
  + #4556 cli/api LOW hardening (3 residuals: rollback n=0 message+gRPC, monitor-filter quote-strip, validateMultiValueLeaf 'to'-gate)
  + #4544 host-inbound dup (CLOSED), #4543 screen TLV (CLOSED), #4541 writeJSON, #4540 monitor keyword, etc.
  (33b891d11 already includes all of 8cd816e35's fixes)
```

## 2. Output path

`/tmp/ps-review-036.md`

## 3. Duplicate-suppression summary

### Sources read for dedup (4-way + triage)

| Source | Count | Coverage |
|--------|-------|----------|
| `/tmp/all_findings.txt` | 274 entries (F-001..F-274) | Full scan — every finding checked against all 274 titles + traces |
| GitHub issues — `gh issue list --state all` | 200+ issues (30 open, ~250 closed on master) | Every finding checked against open issue titles + recent closed to avoid re-reporting fixed |
| `_Log.md` | 40,098 lines | Recent implementation log — last 100 entries for fix verification |
| `/tmp/ps-review-018.md` through `/tmp/ps-review-035.md` | 14 prior deep reviews on master (8cd816e35 and earlier) + triage results (result-ps-review-*.md) | Every finding checked against prior cohort reports + triage dispositions |
| `docs/pr/` | 320 PR records | Recent PR plans for context |

### CLOSED issues (already fixed, NOT re-reported)

| Issue(s) | Fix | Verified on this HEAD |
|----------|-----|-----------------------|
| #4562 | navigatePath intermediate multi-key descent — display-only | CLOSED on this HEAD (NEW, fix in 40a5ba8ec) — verified: `unionChildren` in both branches |
| #4559 | deterministic NAT advisory (COMMITTED as WARNING, not full block allocator) | OPEN advisory, not hard fix — enforcement still missing (see NEW finding in §6 if applicable) |
| #4556 | cli/api LOW batch (3 residuals: rollback n=0 message+gRPC, monitor-filter quote-strip, validateMultiValueLeaf 'to'-gate) | CLOSED on this HEAD (NEW) — verified in 906b4de/4516751/062ab43 |
| #4555 | XDP EH 6 vs 8 — 7+ EH IPv6 flow misses XDP fast path | OPEN LOW (fail-closed parity, not bypass) |
| #4549 | LOW batch (4: VRRP hop-limit, HA heartbeat IPv4-only, PSK zeroize, election same-node-id) | OPEN LOW |
| #4548 | vrrp: MaxAdverInt no min clamp → flap | OPEN LOW (MED→LOW) |
| #4547 | ipsec: DNS stall (N×2s commit) | CLOSED per gh (was OPEN on b1bd96fb6, now CLOSED — verify-first?) |
| #4546 | wg: peer_has_confirmed_session REJECT_AFTER_TIME | CLOSED per gh (was OPEN, now CLOSED) |
| #4544 | config: duplicate host-inbound-traffic loses tokens | CLOSED on this HEAD (NEW) — `mergeHostInbound` + `dedupHostInboundTokens` |
| #4543 | screen: IPv4 options TLV break-on-malformed | CLOSED on this HEAD (NEW) — `extract.rs:187-196` Err on malformed |
| #4541 | api: writeJSON header before encode | CLOSED on this HEAD (NEW) — buffer-first |
| #4540 | cli: monitor traffic keyword/count | CLOSED on this HEAD (NEW) — keyword+numeric guards |
| #4539 | session: should_cache_local_delivery non-handshake TCP | CLOSED on this HEAD (NEW, 5e66d37) — `has_syn` gate |
| #4535 | three-color policer unspecified color mode default | CLOSED on this HEAD (via 33b891d11, was in #4531) |
| #4534 | PBR buildPBRFromFilter discard/reject VRF-steer | CLOSED on this HEAD (via 33b891d11, was in #4531) |
| #4526 | DHCP renewalTimers overflow | CLOSED |
| #4525 | RA randomAdvInterval 0 → hot-loop | CLOSED |
| #4524 | monitor traffic injection (HIGH) | CLOSED |
| #4521 | NAT pool bracket-list truncates | CLOSED |
| #4518 | nat64 port allocator reload collision | CLOSED |
| #4517 | EH walkers MOBILITY/HIP/Shim6 | CLOSED |
| #4514 | single-rate policer unenforced | CLOSED |
| #4487/#4453/#4400 | RST/FIN session — all 3 paths | CLOSED, verified |
| #4399/#4438 | NAT 1:N multimap | CLOSED, verified |
| #4393 | dnat_table secondary | CLOSED |
| #4392 | PBR reject/discard → FORWARDS (critical) | CLOSED |
| #4388/#4384/#4381/#4380 | HA NAT / TCP checksum / NAT64 BIB / forward/reverse idle | CLOSED |
| #3864 | deterministic NAT flat-set parse (NOT enforcement) | CLOSED — parse fix only, enforcement still #4559 OPEN |
| ... | (200+ closed total) | — |

### OPEN issues (already filed, NOT re-reported unless materially new trace)

| Issue | Title | Status |
|-------|-------|--------|
| #4569 | policy: non-first fragment DENY+permit-any (flowless l4_present=false skips DENY) | OPEN, LOW-MED fail-open — already filed (ps-036-c7 F-001) — NOT re-reported |
| #4567 | screen: UDP-flood non-first fragment CMS bucket split | OPEN, LOW — already filed (ps-036-c3-4 L-01) — NOT re-reported |
| #4566 | cos: CachedThreeColorPolicers push drops 3rd+ policer | OPEN, LOW — already filed (ps-036-cohort8 F-003) — NOT re-reported |
| #4565 | nat64 HA reverse-translation needs Nat64ReverseInfo sync | OPEN — already filed (#4512) — NOT re-reported |
| #4559 | nat: deterministic NAT (CGNAT) validated+committed but unenforced | OPEN, MED→LOW-MED — already filed (ps-034 M-01) — NOT re-reported unless new enforcement angle |
| #4555 | XDP EH 6 vs 8 — fail-closed parity | OPEN, LOW — NOT re-reported |
| #4549 | 4 LOW hardening (VRRP hop-limit, HA IPv4-only, PSK zeroize, same-node-id) | OPEN, LOW batch — NOT re-reported |
| #4533 | icmp_embed: EH-overflow fail-closed | OPEN — NOT re-reported |
| #4515 | config: 2 warn-only validation parity gaps | OPEN — NOT re-reported |
| #4512 | nat64: HA-sync translated port | OPEN — NOT re-reported |
| #2387 | session/flow bare 5-tuple — cross-context reuse (P0) | OPEN — S-001/V-01, known, needs fix |
| #4146 | junos-host XDP shim bypass | OPEN — NOT re-reported |
| #3226 | system-services all — packet-wide admit | OPEN — NOT re-reported |
| #2852 | NAT PortAllocator single Mutex | OPEN — NOT re-reported |
| #2562 | NAT64 non-first fragment cache | OPEN — NOT re-reported |
| #4478 | IPIP decap no zone enforcement | OPEN (M-1) — NOT re-reported |
| #4455 | HI-1 multicast/broadcast host-inbound | OPEN — NOT re-reported |
| #4313 | config schema opt-in — unmodeled leaves silent | OPEN (X-1) — NOT re-reported |
| #4498 | FRR sanitize-belt residual (next-hop/origin/source-protocol bare %s) | OPEN — Origin is in this (see §6 if still present) |
| #3776 | flow-cache: session expiry → stale-descriptor + SNAT reuse | OPEN, MED-HIGH — flow-cache NAT reuse, NOT re-reported |
| #4539 | (CLOSED per gh — was OPEN LOW on 8cd816e35) session: should_cache_local_delivery pure PSH | CLOSED on this HEAD — NOT re-reported |
| ... | (30 open total) | — |

### Dedup methodology

This audit checks ALL 4 sources for every finding:

1. **`/tmp/all_findings.txt`** — 274 pre-filing aggregated findings (F-001..F-274) — checked by title + trace keywords
2. **GitHub issues** — `gh issue list --state all` — 200+ (30 open, ~250 closed) — checked by title keywords + body
3. **`_Log.md`** — 40,098 lines — checked recent fix entries for fix verification
4. **`/tmp/ps-review-018..035`** — 14 prior deep reviews + their triage results (`result-ps-review-*.md`) — checked every prior cohort finding

Every finding in §6 carries a dedup note: "NEW" (not in any source), "CONFIRMED STILL PRESENT" (in open issue #XXXX), "FIXED on this HEAD" (in closed issue, do not re-report), or "NOT-MATERIAL/DELIBERATE" per triage.

### Numbering correctness

- Highest existing `/tmp/ps-review-*.md` before this run: `035` (ps-review-035.md, 667 lines, master 8cd816e35 synthesis)
- This report: `/tmp/ps-review-036.md` — next sequential number, no overlap
- Cohort shard files: `/tmp/ps-review-036-cohort*.md` (9 files: cohort1, cohort2, cohort3-4, cohort5, cohort6, cohort7, cohort8, cohort9-11, cohort12-14) — shards, not the final report, named with cohort suffix to avoid overlap with final report
- No file rewritten or overlapped — every file has a unique name

## 4. Module / verdict-path inventory (coverage checklist + cohort map)

| Cohort | Modules | Files / LOC | Status |
|--------|---------|-------------|--------|
| 1. Policy verdict engine | `policy.rs` (4224), `forwarding/mod.rs` (2741), `host_inbound.rs` (815), `compiler_security_policy.go` (443), `policies*.go` (8 files, 1487), `compiler_validate_strict_policy.go` (1009), `prefix_set.rs` (322), `catalog.go` (Protocol SSOT) | 8000+ | 2 Low (L-01 normalizeAny dead no-op, L-02 policyActionString default-arm) — both LOW, not filing per no-dismissal rule? Check vs triage: L-01 is NOT-MATERIAL (dead dedup, harmless), L-02 is NEW Low but LOW value |
| 2. Config + schema + compiler | `lexer.go`, `parser.go`, `ast.go` (navigatePath #4562 fix via unionChildren), `ast_groups.go` (UNION/OVERRIDE), `ast_edit.go`, `inactive.go`, `schema.go`, `schema_walk.go`, `schema_validators*.go`, `compiler*.go` (15 files), `types*.go`, `xfrmi.go` | 10000+ | 0 High/Med new — all prior HIGHs verified fixed. 2 Low (isIdentChar @ deliberate, validateMultiValueLeaf to-separator F-043 dup) — NOT-MATERIAL/dup per triage |
| 3. Host-inbound + Zone | `compiler_security_zones.go`, `zones.go`, `daemon_nft.go`, `lifeline.go`, `host_inbound.rs`, `daemon_apply.go` | 3000+ | #4544 FIXED (mergeHostInbound), #4543 FIXED (fail-closed on malformed TLV) — both CLOSED on this HEAD. No new High/Med. 1 Low (UDP-flood non-first fragment CMS bucket — #4567 OPEN, already filed) |
| 4. Screen / IDS | `screen/` (extract.rs, stateless.rs, rate.rs, syn_rate.rs, syncookie.rs, mod.rs, scan.rs), `poll_descriptor/` screen, `frame/inspect.rs` | 4000+ | #4543 FIXED (fail-closed on malformed), #4167 FIXED, #3902 FIXED, #3405 FIXED, #3362 FIXED, #3172 FIXED — all CLOSED on this HEAD. No new High/Med. 1 Low (#4567 UDP-flood fragment — already filed) |
| 5. NAT / NAT64 / NPTv6 | `nat/` (source.rs 1250, destination.rs, static_nat.rs, allocator.rs 926, tests.rs 8685), `nat64.rs` (2332), `nptv6.rs` (431), `compiler_nat.go` (2529, deterministic NAT advisory), `nat*.go` | 8000+ | Deterministic NAT enforcement — #4559 OPEN (advisory only, not full block allocator — still needs full impl). NAT64 HA reverse-translation — #4565 OPEN. Rest FIXED. No new High/Med beyond known OPEN. |
| 6. Session / conntrack | `session/{mod.rs 2054, key.rs, entry.rs, expire.rs, install.rs 521, lookup.rs 411, wheel.rs}`, `session_glue/`, `forwarding/mod.rs` session paths, `tcp_flags.rs`, `poll_descriptor` (6088), `flow_cache.rs` | 6000+ | #2387 bare 5-tuple STILL PRESENT (P0, OPEN), bare ACK 300s DoS — intentional per code comment ("bare ACK / data first packet may still open ESTABLISHED"), PSH+ACK/pure PSH 300s — same class (intentional mid-stream pickup, not a bug), should_cache pure PSH — FIXED #4539 CLOSED (has_syn gate), flow-cache NAT reuse — #3776 OPEN, companion keepalive FIXED #4380, NAT 1:N FIXED, etc. No new High beyond known OPEN. |
| 7. Forwarding core | `poll_descriptor/mod.rs` (6088), `poll_stages.rs`, `forward_request.rs`, `poll_descriptor/*.rs`, `forwarding/mod.rs` (2741), `frame/` (1303+911+1776), `flow_cache.rs` (1000), `userspace-xdp/lib.rs` (1541) | 10000+ | F-001 non-first fragment DENY+permit-any — #4569 OPEN (already filed, ps-036-c7 F-001). V-01 STILL PRESENT (#2387), N-01 FIXED #3776 on this HEAD (reap_expired_sessions invalidate_slot), M-02 XDP EH 6vs8 LOW, rest fixed/negative. No new High beyond known OPEN. |
| 8. Firewall filters + PBR + Routing | `filter/` (engine/eval.rs, matching.rs, cache_sensitive.rs, tx_selection.rs, policer.rs, compiler.rs, tests.rs 8000), `poll_descriptor/filter.rs`, `compiler_firewall.go`, `compiler_validate_strict_filter.go`, `filters.go`, `rules.go`, `forwarding/mod.rs` PBR | 8000+ | No NEW High/Med — #4535/#4534/#4514/#4392/#3843/#4287/#4426 all FIXED/CLOSED, 2 NOT-MATERIAL (flex cache moot, next-table overstated per triage) |
| 9. IPsec / IKE / WireGuard | `pkg/ipsec/` (ike.go, policy.go, crypto.go, manager.go), `compiler_ipsec.go`, `xfrm.go`, `afxdp/wg/` (engine.rs, peer.rs, session.rs 3-slot, tai64n.rs, cookie.rs, allowed_ips.rs) | 6000+ | 0 NOVEL — FRR Origin → #4498 (already filed), XFRM FIXED #2933, WG DELIBERATE, HA heartbeat NOT exploitable (gated on macOK), F2/F4/F6 triaged. #4547/#4548/#4546 CLOSED per gh (were OPEN on b1bd96fb6). |
| 10. Routing / PBR / FRR / GRE / VRF | `pkg/routing/`, `pkg/frr/`, `tunnels.go` | 4000+ | IPIP → #4478 filed, FRR sanitize → #4498, FRR cross-context FIXED — covered by 8+9 |
| 11. HA / Cluster / VRRP / Session-sync | `pkg/cluster/`, `pkg/vrrp/`, `afxdp/ha.rs`, `pkg/ipmon/` | 5000+ | 0 NOVEL — all already filed (#4549 LOW batch, #4548 VRRP flap, #4547 DNS stall, #4546 WG, #4478, S-001→#2387) or FIXED/NOT-MATERIAL. #4547/#4548/#4546 now CLOSED per gh. |
| 12. DHCP / RA / ND / Flowexport | `pkg/dhcp/`, `pkg/dhcprelay/`, `pkg/ra/`, `pkg/flowexport/` | 3000+ | H-01 quote bypass LOW defense-in-depth (primary -- holds), M-01 rollback n=0 actually fail-closed (400), 7 fixes verified |
| 13. CLI / REST / gRPC / Observability | `pkg/cli/` (monitor.go FIXED #4524/#4540/#4556, monitor_traffic_quotestrip test), `pkg/api/` (writeJSON FIXED #4541, rollback n=0 #4556), `pkg/grpcapi/`, `pkg/cmdtree/` | 4000+ | M-01 rollback n=0 actually 400 (fail-closed, triaged), H-01 quote bypass LOW (primary -- holds, not exploitable), rest FIXED |
| 14. Wire / protocol codecs + config parser | `protocol/` (control.rs, snapshot.rs, binding.rs, cos.rs, nat.rs, security.rs, tests.rs), `lexer.go` (@ revert #4530 deliberate), `parser.go` (maxParseDepth 256), `ast.go` (navigatePath #4562 fix via unionChildren), `flow_cache.rs` | 3000+ | navigatePath intermediate FIXED #4562, 7 fixes verified, 1 Med NEW? (navigatePath intermediate multi-key — FIXED #4562 on this HEAD, not new) |

**Coverage proof:** All 14 cohorts assigned, 9 parallel agents on 33b891d11, each tracing concrete packet/config/code paths. Every fail-open class explicitly verified. Verified negatives for policy (26), config (6), host-inbound (7), screen (10), NAT (2), session (8), forwarding (22), filter/PBR, IPsec/WG/HA (48), DHCP/RA/flowexport, CLI/REST/gRPC.

--- (continues in full report)

