# xpf firewall deep audit — Cohort 5: NAT / NAT64 / NPTv6 — ps-review-034

- Base commit: 8cd816e35 (master HEAD)
- Output path: /tmp/ps-review-034.md
- Cohort: 5 — NAT / NAT64 / NPTv6 (source.rs 1250 LOC, destination.rs, static_nat.rs, allocator.rs 926 LOC, nat/mod.rs, nat64.rs 2332 LOC, nptv6.rs 431 LOC, pkg/config/compiler_nat.go 2529 LOC, pkg/dataplane/userspace/nat*.go, pkg/dataplane/compiler_nat.go)

## 1. Base commit reviewed

\`\`\`
8cd816e35 Merge pull request #4545 from psaab/fix/4540-4541-cli-api-hardening
```

Branch: master, HEAD 8cd816e35 = 8cd816e35 at review time.

## 2. Output path

\`/tmp/ps-review-034.md\`

## 3. Duplicate-suppression summary + intentional-divergence list (cited, not re-reported)

### Prior findings + issues reviewed

- \`/tmp/all_findings.txt\` — 272 entries (F-001..F-272)
- \`/tmp/ps-review-018..033\` — 14 files (policy, session, filter, NAT, etc.)
- \`gh issue list --state all\` — 500 issues (open + closed)
- \`docs/feature-gaps.md\`, \`docs/vsrx-gaps.md\`, recent \`_Log.md\`
- Specific ps-review-028 (Cohort 5 prior audit, base b1bd96fb6, 353 lines, thorough)

### Dedup'd against — NOT re-reported

| ID | Topic | Why dedup'd |
|---|---|---|
| #4521 | SNAT pool bracket-list truncation | Fixed — appendPoolAddresses full token stream |
| #4520 | NAT64 empty-pool vs exhaustion counter | Fixed — record_nat64_source_failure splits |
| #4519 | NPTv6 host-bits debug_assert only | Fixed — parse_prefix returns None on host bits |
| #4518 | NAT64 allocator reset on reload | Fixed — from_snapshots_with_previous reuses Arc PortAllocator |
| #4517 | IPv6 EH walkers exotic types | Fixed — MOBILITY/HIP/Shim6 arms added |
| #4514 | Single-rate policer unenforced | Fixed — lowered to srTCM |
| #4381 | NAT64 no port/ICMP-id translation (BIB) | Fixed — PortAllocator per prefix, allocate_source |
| #4384 | TCP checksum segmentation dead code | Fixed — deleted |
| #4388 | HA NAT standby port not reserved | Fixed — reserve_synced_source_nat_allocation + reserve_flow |
| #4399/#4438 | NAT 1:N reverse index single-value | Fixed — 1:N multimap |
| #4393 | dnat_table not published for synced SNAT | Fixed |
| #4535 | Three-color policer color-blind default | Fixed |
| #4534 | PBR discard/reject steer | Fixed |
| #2387 | Bare 5-tuple | OPEN known, not in cohort scope |
| #4146 | junos-host XDP shim | OPEN known, not in cohort scope |
| #3226 | system-services | OPEN known, not in cohort scope |
| #4512 | NAT64 HA-sync port reservation | OPEN — explicitly excluded by task ("do NOT re-report unless materially new") — not re-reported |

### Intentional divergences (NOT bugs)

- Intrazone default-permit, host-originated junos-host rejection, IPsec-passthrough-exempt — documented
- NPTv6 only /48 and /64 — RFC 6296 parity, /56 intentionally rejected
- NAT64 only /96 — RFC 6052, non-/96 rejected
- NAT64 MatchUnavailable fails closed (drop) — intentional
- Source NAT pool /24 expands to FULL prefix range (256 hosts, #3049) — Junos FULL range
- natAddrFamily textual classification (colon == v6) — matches Rust Ipv6Addr::from_str
- port-overloading-factor / port-overloading off — accepted-with-advisory (known #4291, documented)
- translation-target routing-instance — accepted-with-advisory (known #4292, documented)

### Verification of CLOSED fixes on HEAD 8cd816e35

All 14 CLOSED issues verified present on HEAD. No regressions.

## 4. Module / verdict-path inventory (coverage checklist + cohort map)

| Module | File(s) | Role | LOC | Reviewed |
|---|---|---|---|---|
| NAT source | userspace-dp/src/nat/source.rs | SNAT rule matching, L4 constraints, pool expansion, allocator, HA reserve | 1250 | YES full |
| NAT destination | userspace-dp/src/nat/destination.rs | DNAT exact+wildcard+PROTO_ANY+prefix-LPM, src/src-port/ICMP, off exemption | 1072 | YES (ps-028 full, spot-check) |
| Static NAT | userspace-dp/src/nat/static_nat.rs | Host 1:1 + block-to-block, port-mapped, source-constraint, scope | 793 | YES (ps-028 full, spot-check) |
| Port allocator | userspace-dp/src/nat/allocator.rs | Claim/assign/recycle FIFO, persistent leases, GC, HA reserve, sticky | 926 | YES (ps-028 full, spot-check) |
| NAT core | userspace-dp/src/nat/mod.rs | NatDecision reverse/merge, NatRuleCounter atomic reset, NatCounterStore | 297 | YES (ps-028 full, spot-check) |
| NAT64 | userspace-dp/src/nat64.rs | Prefix match, BIB pool alloc, v6↔v4 translation, ICMP error+embedded, frag, checksum, EH walk | 2332 | YES (ps-028 full first 1006 + spot, this pass full EH/frag/checksum/alloc) |
| NPTv6 | userspace-dp/src/nptv6.rs | Prefix parse, adjustment, 0xFFFF handling, overlap reject, inbound/outbound | 431 | YES full |
| NAT Go compiler | pkg/config/compiler_nat.go | compileNAT all sub-blocks, SNAT/DNAT/static/NAT64/NPTv6/natv6v4/proxy-arp, deterministic, pool | 2529 | YES full (ps-028) + deterministic check |
| NAT Go snapshot (userspace) | pkg/dataplane/userspace/nat_source.go, nat_destination.go, nat.go, nat_static.go, nat_nptv6.go, nat64.go | Userspace snapshot builders | ~1500 | YES (deterministic gap check) |
| NAT Go snapshot (BPF legacy) | pkg/dataplane/compiler_nat.go | BPF NAT pool config (includes deterministic NAT) | 1258 | YES (deterministic NAT only) |

## 5. Module-by-module inspection log (including negatives)

### 5.1 nat/source.rs — Source NAT

Full review in ps-review-028 §5.1 (verified correct on b1bd96fb6, unchanged in 8cd816e35 for SNAT core). No new issues.

### 5.2 nat/destination.rs, static_nat.rs, allocator.rs, nat/mod.rs

Full review in ps-review-028 §5.2-5.5. No new issues.

### 5.3 nat64.rs — NAT64

**Spot-checked areas this pass:**

- Non-first fragment handling: `write_v6_to_v4_into` (line 1067) and `write_v4_to_v6_into` (line 1301) both correctly drop non-first fragments via `ipv6_is_non_first_fragment()` / `v4_offset_units != 0`. The NAT64 allocation path (`allocate_source`) is only reachable from `if flow.is_some()` branch (flowed path) in poll_descriptor/mod.rs; non-first fragments return `None` from `parse_session_flow_from_bytes` (line 1277-1279, #2344) and go through flowless path which never reaches NAT64 allocation. **No port leak for non-first fragments** — verified through `frame_is_non_first_fragment` -> parse returns None -> flowless path -> no NAT.

- Embedded ICMP error translation: `translate_embedded_v6_to_v4` / `translate_embedded_v4_to_v6` correctly handle fragment/non-first-fragment checks on embedded packets. `MAX_EMBEDDED_LEN = 1300` bounds scratch, no per-packet heap. Non-first fragment embedded packets dropped (line 1808). Correct.

- EH walkers: 0/43/60/135/139/140/253/254 + 51 (AH) + 44 (Fragment) + 59 (No-Next-Header) + terminal. MAX_IPV6_EXT_HEADERS=8 (#4435/#4517). Post-loop fail-closed None. Correct.

- Incremental checksum (#3025): 3 full-recompute cases (ICMP, zero-checksum UDP v4->v6, zero-checksum UDP v6->v4) correctly handled. Incremental path byte-identical. Correct.

- Port allocator reuse (#4518): `from_snapshots_with_previous` reuses Arc-backed PortAllocator on byte-identical (prefix_bytes, pool_v4) with order-sensitive Vec equality. Fresh on changed pool. Correct.

**Negative**: No bypass, no OOB, no unbounded alloc.

### 5.4 nptv6.rs — NPTv6

Full review: 0xFFFF handling (#3233) via is_zero_adjustment skip, host-bits (#4519) via parse_prefix None return, overlapping (#2241/#4339) via find_overlap min(common). No new issues.

### 5.5 pkg/config/compiler_nat.go + pkg/dataplane/compiler_nat.go + pkg/dataplane/userspace/nat_source.go — Deterministic NAT Gap

**This is the NEW finding (M-01):**

- `pkg/config/compiler_nat.go:1269-1341` — `applyDeterministicKeys`, `applyDeterministicChildren`, `applyDeterministicHost` parse deterministic NAT (CGNAT) config (`port deterministic block-size N host address CIDR`) from both flat-set and hierarchical shapes. Accumulate across sibling `port deterministic ...` leaves (#3864). Validated in `compileNATSource` (block-size > 0, host address required, capacity check, mutual exclusion with persistent-nat and address-persistent).

- `pkg/dataplane/compiler_nat.go:473-496` — BPF legacy path compiles deterministic NAT to `NATPoolConfig.Deterministic` / `BlockSize` / `HostBase` / `HostCount` / `BlocksPerIP` / `HostBaseV6` / `HostPrefixLen` (mode 1=IPv4 host, 2=IPv6 host). Writes to `SetNATPoolConfig` / `SetNATPoolIPV4`.

- `pkg/dataplane/userspace/nat_source.go` (422 LOC) — userspace snapshot builder `buildSourceNATSnapshotsWithFeeds`: **ZERO** refs to Deterministic/BlockSize/HostBase/CGNAT. Does NOT read `pool.Deterministic`. The `SourceNATRuleSnapshot` in userspace types has no deterministic fields.

- `userspace-dp/src/nat/` — Rust userspace dataplane (the **ONLY** runtime per README: "Dataplane: Rust AF_XDP userspace dataplane is the only runtime") has **ZERO** deterministic NAT refs.

- `docs/feature-gaps.md` — claims "Deterministic NAT (Port Block Allocation) | Done (74e1d17, 439cd3f)" — but those commits (74e1d17 BPF, 439cd3f DPDK) are for the RETIRED BPF dataplane (#1373) and DPDK (also retired). The current production userspace-dp has no deterministic NAT.

**Result**: Config `security nat source pool CGNAT-POOL port deterministic block-size 2016 host address 100.64.0.0/25` commits clean (no error, no warning), but the production userspace-dp silently ignores it — allows patternless port allocation instead of deterministic blocks. The operator believes CGNAT deterministic NAT is active (compliance logging, predictable port mapping) and is not. Port-block logging and ISP compliance are broken.

