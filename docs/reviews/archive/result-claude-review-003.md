# Triage result — claude-review-003.md

- Review base SHA: `7e0fecf3b` (a few commits behind). Verified against
  **origin/master `4d127e986`** (fetched fresh).
- Open GH issues at triage: 183 (fresh `gh issue list`), plus the review's
  embedded "do NOT re-report" list.
- Outcome: **0 individually-filed material issues**, **1 cohort issue** for
  the low-materiality / defense-in-depth / test-coverage survivors.

## Why zero individual material issues

The file is a *focused* Claude review that over-reports; the body is dominated
by the reviewer's own NEGATIVE self-refutations. The two most concrete,
highest-severity claims were **already fixed on origin/master** (the review's
base is stale), and the only non-NEGATIVE "High" is in the **retired eBPF**
path. Everything else is Low / parity / observability / lenient-HA-sync
defense-in-depth → cohort.

Verified-against-origin/master highlights:
- **make_config_drive.py ISO perms (A10-b3 F1, Medium secret-leak): ALREADY
  FIXED.** origin/master `scripts/image/make_config_drive.py` chmods the staged
  `xpf.conf` **and** the output ISO to `0o600` (lines 72-76, 94) with explicit
  isoinfo-extraction comments. Base 7e0fecf3 predated the fix.
- **Failover-batch RGID byte-truncation (A5-b1, Medium): ALREADY GUARDED.**
  `pkg/cluster/sync_failover.go:34,403` guard `rgID < 0 || rgID > 255`; config
  caps RG id at 255 (`compiler.go:1396` VRID 1..255,
  `compiler_validate_strict_chassis.go:17 MaxHeartbeatRedundancyGroups = 255`).
  Distinct from #5090 (which is the VRRP advert *address-count* uint8 wrap).
- **NAT pool-id uint8 overflow (A6-b1 #1, High): STALE (retired eBPF path).**
  The `dp.SetNATPool*` uint8 `poolID` is the legacy Manager BPF-map path
  (eBPF retired #1476). The **live** userspace path caps pools at
  `userspaceShimMaxNATPools = 32` (`loader_userspace_shim.go:532`).
- **Legacy partial-apply / legacy zone-collision (A6-b1 #3,#4): STALE.**
  Both are explicitly in the retired legacy eBPF compile path
  (`pkg/dataplane/compiler*.go`, RETIRED-eBPF, not the enforcement path).
- **policy_id 0 first-policy-delete fail-open (A7-b1 F1): DUP of #4626 L01**
  ("reserve policy_id 0 — retire the overloaded wire value").
- **ApplyConfig non-gate errors "swallowed" (A7-b1 F3): fail-SAFE, not
  fail-open.** origin/master helper "retains previous-good / default-deny while
  staying armed — never fail-open" (manager_compile.go), and
  `recordCompileFailure` tracks it (#1960). No concrete non-gate trigger.
  Downgraded to cohort (return-err-on-any-ApplyConfig-error is defense-in-depth).

## Per-finding table

Legend: FIXED = already fixed on origin/master; STALE = symbol gone / retired
path; DUP = covered by open issue; COHORT = low-materiality survivor →
cohort issue; NEG = author's own NEGATIVE/no-bug (not carried).

| Finding | Area | Gate verdict | Reasoning |
|---|---|---|---|
| H1 remote-CLI io.ReadAll buffers full output | A10-b1 | dropped-low→cohort | client-side DoS of `cli` only, not daemon |
| H2 os.Stdout global replace no defer/recover | A10-b1 | dropped-low→cohort | CLI robustness; crash already fatal |
| H3 zone-name terminal ANSI injection | A10-b1 | NEG | config schema rejects control chars (system_string_injection #4902) |
| M1 MAX_INTERFACES memory | A10-b1 | NEG | author: "not a bug", preflight fail-closed |
| M2 commit-comment Trim over-trims quotes | A10-b1 | dropped-low→cohort | audit-log cosmetic |
| M3 scoped-global v3 not bumped | A10-b1 | dropped-dup | #5488 |
| M4 effective-filter banner version | A10-b1 | NEG | gen-check covers it |
| L1-L3 load-override/curl/iface-count | A10-b1 | NEG/cohort | super-user gated / display |
| session_display egress first-wins | A10-b2 | dropped-low→cohort | display only |
| dhcprelay accepts IPv6 but binds udp4 | A10-b2 | dropped-low→cohort | fails closed per-server |
| DDNS generic ok-response single-token | A10-b2 | dropped-low→cohort | durability, operator typo |
| F1 make_config_drive ISO world-readable | A10-b3 | dropped-fixed | origin/master chmods conf+ISO 0o600 |
| F2 scheduler DST fall-back double-active | A10-b3 | dropped-low→cohort | Junos wall-clock parity |
| F3 natshow counter silently partial | A10-b3 | dropped-low→cohort | display on transient read error |
| F4 xpf-deploy overlay collide | A10-b3 | NEG | guard present |
| F-FIB-01 unknown-zone id0 None=>true | A1-b1 | NEG | all transit ifaces zoned; id0 unreachable |
| F-CHK-02 / F-ZONE-03 | A1-b1 | NEG | proven sound |
| F-BYTE-04 byte_writes NO-GUARD contract | A1-b1 | dropped-low→cohort | no unguarded caller; add debug_assert |
| F-HOST-05 system-services `all` broader than Junos | A1-b1 | dropped-low→cohort | acknowledged in code, doc parity |
| F-FILTER-01 / F-NEIGH-03 / F-ICMP-EMBED-04 / F-COS-06 | A1-b2 | NEG | sound (defense-in-depth complete) |
| F-RATELIMIT-02 unzoned fallback reject bucket | A1-b2 | dropped-low→cohort | id0 only, negligible |
| F-TX-05 single-recycle invariant 39 sites | A1-b2 | dropped-low→cohort | hardening note; test injections exist |
| H1 reply_matches canonical NAT-unaware fallback | A1-b3 | dropped-low→cohort | deliberate #4399 validate-on-lookup + 6 tests; speculative |
| H2 zone_counters build race | A1-b3 | NEG | immutable after build |
| M1 xsk_ffi UMEM drop-order not type-enforced | A1-b3 | dropped-low→cohort | safe in practice (join-before-free) |
| M2 screen MSS first-wins vs RFC last | A1-b3 | dropped-low→cohort | parity, matches BPF |
| M3/L1-L5 | A1-b3 | NEG | offline tool / info |
| HA reserve_flow fails when port locally owned | A2 | dropped-low→cohort | RG-flap race, low prob; distinct from #5446/#5338 |
| address-only proto=0 try_next_port untokenized | A2 | dropped-low→cohort | doesn't reach wire today |
| dead-code catalogProtocolNumber (name→0) | A3-b1 | dropped-low→cohort | zero callers; hygiene |
| zone-completion DynamicFn unsorted map | A3-b1 | dropped-low→cohort | non-deterministic CLI completion |
| global-policy empty zone == wildcard | A3-b2 | dropped-low→cohort | semantic; author "not a bypass" |
| ResolveFilterPortRange string round-trip | A3-b2 | dropped-low→cohort | cold perf, no bug |
| HostInboundLifelineInterface `fab` prefix over-match | A3-b3 | dropped-low→cohort | acknowledged design #3682; requires operator naming iface fab* |
| zoneCoarseAdmitsIKE case-sensitive (lenient) | A3-b3 | dropped-low→cohort | lenient path only |
| UnionHostInboundTokens case-sensitive dedup | A3-b3 | dropped-low→cohort | display only |
| M1 StaticNATRuleSet.FromZone singular | A3-b4 | dropped-low→cohort | test-coverage; verify Cartesian-expand |
| H1/H2/M2/L1/L2 | A3-b4 | NEG | fail-closed / audit-safe |
| archive cleartext secrets under master-password | A4 | dropped-low→cohort | 0600, intentional per comment |
| loadRollbackHistory no MaxConfigSize cap | A4 | dropped-low→cohort | local-root write; DoS defense-in-depth |
| fsatomic temp-sweep no lstat type-check | A4 | dropped-low→cohort | consistency with journal |
| RGID failover-batch byte-truncation | A5 | dropped-fixed | sync_failover.go guards + config caps 255 |
| VRRP acceptArrivalIfindex fail-open (arrival 0) | A5 | dropped-low→cohort | degraded raw-socket path only |
| heartbeat monitor truncation no counter | A5 | dropped-low→cohort | observability |
| NAT pool-id uint8 overflow | A6-b1 | dropped-stale | retired eBPF path; live caps at 32 |
| syntheticLogicalIfindex panics daemon | A6-b1 | dropped-low→cohort | unreachable (1<<20); panic→error hygiene |
| legacy partial-apply not transactional | A6-b1 | dropped-stale | retired eBPF path |
| legacy zone-id collision fail-open | A6-b1 | dropped-stale | retired eBPF path (userspace quarantines) |
| global policy {0,0} fragile vs zone-id 0 | A6-b1 | dropped-low→cohort | today safe; assert-hardening |
| scoped-global multi-zone v3 rolling-upgrade | A6-b2 | dropped-dup | #5488 (author: "extends #5488") |
| VRRP VIP host-inbound first-wins on dup iface | A6-b2 | dropped-low→cohort | deliberate #1960 no-brick lenient; strict gate covers |
| workers int→uint32 no upper clamp | A6-b2 | dropped-low→cohort | fail-closed via cap guard |
| route snapshot dup NextTable overlap | A6-b2 | dropped-low→cohort | determinism |
| F1 RST-suppress As4() panic v6-in-v4 | A6-b3 | dropped-low→cohort | prod caller separates families; exported-API hardening |
| F2 RemoveRSTSuppression dead code + nft leak | A6-b3 | dropped-low→cohort | post-stop table leak; availability |
| F3 TOCTOU ListTables/Flush | A6-b3 | dropped-low→cohort | Manager.mu held; external-only |
| F4 fail-open nft-unavailable no metric | A6-b3 | dropped-low→cohort | observability; 5s retry exists |
| F5 rst_suppress test gaps | A6-b3 | dropped-low→cohort | test-coverage |
| F1 policy_id 0 first-policy-delete | A7-b1 | dropped-dup | #4626 L01 |
| F2 HA session-delta silent drop on zone mismatch | A7-b1 | dropped-low→cohort | observability; transient config-sync lag |
| F3 non-gate ApplyConfig errors not returned | A7-b1 | dropped-low→cohort | fail-SAFE retain-last-good; #1960 tracks |
| F4 DHCP lease fingerprint excludes Remaining | A7-b1 | dropped-low→cohort | 30s heartbeat bound |
| networkd protectedResolver nil sweep | A7-b2 | NEG | set at init; nil only in tests |
| IPsec TS not CIDR-validated at render | A7-b2 | dropped-low→cohort | lenient/HA-sync only; strongSwan-default speculative |
| FRR config_render VRF name not sanitized | A7-b2 | dropped-low→cohort | validated at commit; render belt |
| login_password markerPath collision | A7-b2 | dropped-low→cohort | username regex-validated at commit |
| diagcmd Target length not bounded | A7-b2 | dropped-low→cohort | slot-hold DoS bounded by limiter=4 |
| F-1 makeNonce fixed fallback entropy | A7-b3 | dropped-low→cohort | rand.Read ~never fails; liveness only |
| F-2 wgkey raw private scalar not zeroed | A7-b3 | dropped-low→cohort | key-handling hardening |
| F-3 X25519 low-order | A7-b3 | NEG | parity with `wg`, WONTFIX |
| dead lenient queryInt/queryUint16 exported | A8-b1 | dropped-low→cohort | latent fail-open, zero callers |
| peerSessionsRequest lenient ParseUint | A8-b1 | dropped-low→cohort | relies on caller validation |
| sameHostAs default-port omission | A8-b1 | dropped-low→cohort | CSRF false-positive (avail, not bypass) |
| ShowPolicies text filter ignores unknown tokens | A8-b2 | dropped-low→cohort | display parity (#4814/#3696 class) |
| GetSessions negative PageSize downgrade | A8-b2 | dropped-low→cohort | input-validation symmetry |
| SNMP v3 DES/AES rand.Read error ignored | A9 | dropped-low→cohort | IV uniqueness; distinct from #5544 |
| RPM Manager Apply lacks WaitGroup | A9 | dropped-low→cohort | probe-loop overlap on churn |
| flowexport post-NAT fallback pre==post | A9 | NEG | documented intentional forensics continuity |

Total findings parsed: ~63 distinct (excludes pure inventory/NEGATIVE-only lines).
- dropped-dup: 3 (#5488 x2 aggregated, #4626 L01)
- dropped-stale-or-fixed: 6 (2 fixed: make_config_drive, RGID; 4 stale: NAT-pool-uint8, legacy partial-apply, legacy zone-collision, [retired-path])
- pure NEG (not carried): ~13
- cohort'd (low-materiality survivors): ~41
- filed individually: 0
