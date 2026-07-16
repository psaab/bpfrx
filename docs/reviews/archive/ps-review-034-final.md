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

- `userspace-dp/src/nat/` — production Rust AF_XDP dataplane has **ZERO** deterministic NAT refs.

- `docs/feature-gaps.md` — claims "Deterministic NAT (Port Block Allocation) | Done (74e1d17, 439cd3f)" — but those commits (74e1d17 BPF, 439cd3f DPDK) are for the RETIRED BPF/DPDK dataplanes. The BPF dataplane was retired in #1373 ("In a retired-eBPF world (#1373) the userspace helper is the enforcement plane"). README confirms: "Dataplane: Rust AF_XDP userspace dataplane is the **only** runtime".

**Result**: Operator configures CGNAT deterministic NAT but production silently ignores it.

## 6. Findings

---

### [M-01] Deterministic NAT (CGNAT) silently unenforced on production userspace dataplane

- Title: Deterministic NAT (CGNAT) `port deterministic block-size / host address` commits clean but is not enforced on the production userspace dataplane — BPF-only implementation, retired dataplane
- Severity: Medium
- Confidence: High
- Class: unenforced-control / parity-gap
- Evidence:

  ```go
  // pkg/config/compiler_nat.go:1269-1341 — parses deterministic NAT from config
  func applyDeterministicKeys(det *DeterministicNATConfig, keys []string) {
      // reads "block-size", "host", "address" from flat-set Keys
  }
  func applyDeterministicChildren(det *DeterministicNATConfig, detNode *Node) {
      // reads from hierarchical shape
  }
  // pkg/config/compiler_nat.go:1634-1688 — validates deterministic NAT
  // (block-size > 0, host address required, capacity, mutual exclusion)
  ```

  ```go
  // pkg/dataplane/compiler_nat.go:473-496 — BPF legacy path compiles deterministic NAT
  if pool.Deterministic != nil {
      _, hostNet, err := net.ParseCIDR(pool.Deterministic.HostAddress)
      if err == nil {
          ones, bits := hostNet.Mask.Size()
          portRange := int(poolCfg.PortHigh) - int(poolCfg.PortLow) + 1
          poolCfg.BlockSize = uint16(pool.Deterministic.BlockSize)
          poolCfg.BlocksPerIP = uint16(portRange / pool.Deterministic.BlockSize)
          if bits == 128 {
              poolCfg.Deterministic = 2
              // ...
          } else {
              poolCfg.Deterministic = 1
              poolCfg.HostBase = ipToUint32BE(hostNet.IP.To4())
          }
      }
  }
  // pkg/dataplane/types.go:514-521 — BPF NATPoolConfig has Deterministic fields
  Deterministic  uint8 // 0=off, 1=IPv4 host, 2=IPv6 host
  BlockSize      uint16
  HostBase       uint32
  HostCount      uint32
  HostPrefixLen  uint8
  HostBaseV6     [4]uint32
  ```

  ```go
  // pkg/dataplane/userspace/nat_source.go (422 LOC) — ZERO deterministic refs
  // grep -n "Deterministic\|BlockSize\|HostBase\|CGNAT" nat_source.go -> 0 results
  // The userspace snapshot builder buildSourceNATSnapshotsWithFeeds does NOT read pool.Deterministic
  // SourceNATRuleSnapshot in userspace types has no deterministic fields
  ```

  ```
  // userspace-dp/src/nat/ — production Rust AF_XDP (the ONLY runtime)
  // grep -rn "Deterministic\|BlockSize\|HostBase\|CGNAT" userspace-dp/src/nat/ -> 0 results
  ```

- Trace:
  1. Operator configures CGNAT deterministic NAT:
     ```
     set security nat source pool CGNAT-POOL address 203.0.113.0/28
     set security nat source pool CGNAT-POOL port deterministic block-size 2016
     set security nat source pool CGNAT-POOL port deterministic host address 100.64.0.0/25
     ```
  2. `pkg/config/compiler_nat.go:compileNATSource` parses `port deterministic block-size 2016` and `host address 100.64.0.0/25` via `applyDeterministicKeys`/`applyDeterministicChildren` (accumulates across sibling leaves per #3864), validates (block-size > 0, host required, capacity, not with persistent-nat or address-persistent).
  3. Config commits clean — no error, no warning. Operator believes CGNAT deterministic NAT is active.
  4. `pkg/dataplane/compiler_nat.go:compileNAT` (BPF legacy, phase 6) compiles deterministic NAT to `NATPoolConfig.Deterministic`/`BlockSize`/`HostBase`/etc. and writes to `SetNATPoolConfig`/`SetNATPoolIPV4` — but these write BPF maps (`nat_pool_config`, `nat_pool_ips`) that the userspace dataplane does NOT read (the userspace path is via `pkg/dataplane/userspace/` snapshot builders, not BPF maps).
  5. `pkg/dataplane/userspace/nat_source.go:buildSourceNATSnapshotsWithFeeds` reads `cfg.Security.NAT.Source` and `cfg.Security.NAT.SourcePools[pool].Addresses` but does NOT read `pool.Deterministic`. The `SourceNATRuleSnapshot` wired to `userspace-dp` has no deterministic fields. `userspace-dp/src/nat/source.rs` + `allocator.rs` have no deterministic NAT logic — they do plain round-robin + sticky + persistent NAT.
  6. `userspace-dp` (the ONLY runtime per README, BPF retired in #1373) uses `PortAllocator` with round-robin/sticky/persistent, NOT deterministic port blocks. CGNAT subscribers do NOT get fixed predictable port blocks — ISP compliance logging (mapping internal IP → deterministic external port block) is broken.

- Refutation attempted:
  - Checked if `pkg/dataplane/compiler_nat.go` (BPF) is still on the commit path for userspace deployments — yes, `pkg/dataplane/compiler.go:237` calls `compileNAT(dp, cfg, result)` for ALL deployments (DataPlane interface), writing BPF maps. But the userspace dataplane (`userspace-dp` Rust, AF_XDP) does NOT consume BPF maps for NAT — it consumes `SourceNATRuleSnapshot` via control socket. So the BPF map write is dead for userspace consumers.
  - Checked if deterministic NAT could be in userspace-dp under a different name — `grep -rn "deterministic\|CGNAT\|BlockSize\|HostBase"` in `userspace-dp/src/` excluding known-non-NAT deterministic refs (ordering, LCG, etc.) → 0 NAT-related results. Not implemented.
  - Checked `docs/feature-gaps.md` — claims "Deterministic NAT (Port Block Allocation) | Done (74e1d17, 439cd3f)" — verified those commits touch `pkg/dataplane/compiler_nat.go` (BPF) + DPDK (also retired), not userspace-dp. The claim is stale for current architecture.
  - Checked if any open issue tracks this — `gh issue list --state all` 500 issues, `grep -i "deterministic\|CGNAT"` → 0 results. Not tracked.

- Why it matters:
  Deterministic NAT (CGNAT) is required for ISP compliance — it maps each internal subscriber to a fixed predictable port block on an external IP, enabling logging to answer "which subscriber used external IP:port at time T?" without per-session state. Operators deploying CGNAT who configure `port deterministic block-size / host address` get a commit-clean config that the production dataplane silently ignores, falling back to round-robin port allocation. Compliance logging is broken, and the operator has no signal (no warning, no error, no show output indicating deterministic NAT is inactive).

- Fix direction:
  Two options:
  1. **Port deterministic NAT to userspace-dp**: Add deterministic port block allocation to `userspace-dp/src/nat/allocator.rs` (math: `block_index = hash(subscriber) % blocks_per_ip`, `external_ip = pool[block_index / blocks_per_ip]`, `port_range = [base + block*block_size, base + (block+1)*block_size)`). Wire through `SourceNATRuleSnapshot` + `pkg/dataplane/userspace/nat_source.go`. Mirror the BPF `nat_pool_alloc_deterministic_v4` logic in Rust. This is the complete fix.
  2. **Gate config as unsupported on userspace path** (short-term): In `pkg/dataplane/userspace/capabilities.go` or `deriveUserspaceCapabilities`, detect `pool.Deterministic != nil` and set `ForwardingSupported = false` with reason "deterministic NAT (CGNAT) not yet ported to userspace dataplane, BPF implementation retired" — so the commit warns or the apply preflight keeps previous state. Alternatively, in `pkg/config/compiler_nat.go` add a capability warning when deterministic NAT is configured but userspace-dp is the runtime. This is a backstop, not the complete fix.

  Option 1 is the production fix. Option 2 prevents silent unenforce in the interim.

- Labels: `parity-gap`, `unenforced-control`, `nat`, `cgnat`, `deterministic-nat`, `userspace-dataplane`

- Dedup note: NOT in `/tmp/all_findings.txt` (272 entries, no deterministic NAT gap), NOT in `gh issue list --state all` (500 issues, 0 deterministic/CGNAT), NOT in `docs/feature-gaps.md` (which claims Done but that's BPF-only, stale claim for current architecture). F-002 (deterministic NAT un-configurable via flat-set — #3864 sibling leaf reset) is CLOSED and is the flat-set PARSE bug, not the userspace enforcement gap. This finding is about the production dataplane missing deterministic NAT entirely.

---

### [L-01] NAT64 non-first fragment port allocation — verified NOT a leak (negative result)

- Title: NAT64 non-first fragment port allocation — verified NOT leaking (negative result)
- Severity: N/A (negative result — coverage proof)
- Confidence: High
- Class: robustness-dos (negative — no bug)
- Evidence:

  ```rust
  // userspace-dp/src/afxdp/frame/inspect.rs:1277-1279 (#2344 single chokepoint)
  if frame_is_non_first_fragment(frame, meta) {
      return None; // -> SessionFlow = None -> flowless path
  }
  // userspace-dp/src/afxdp/poll_stages.rs:268-290
  pub(super) fn stage_parse_flow_and_learn(...) -> Option<SessionFlow> {
      let flow = parse_session_flow_from_bytes(packet_frame, meta); // returns None for non-first frag
      // ...
  }
  // userspace-dp/src/afxdp/poll_descriptor/mod.rs:686
  let flow = stage_parse_flow_and_learn(...); // None for non-first fragment
  // NAT64 allocation is inside `if let Some((prefix_idx, ...)) = nat64_match` 
  // which is inside `if let Some(flow)` (the flowed path). Non-first fragments 
  // go through flowless path (else branch), never reaching NAT64 allocation.
  ```

- Trace:
  1. IPv6 non-first fragment with NAT64 prefix dst (e.g., `64:ff9b::8.8.8.8` + Fragment header offset > 0).
  2. `parse_session_flow_from_bytes` calls `frame_is_non_first_fragment(frame, meta)` which walks EH chain, finds Fragment header (44), checks offset > 0 → returns `true` → `parse_session_flow_from_bytes` returns `None`.
  3. `stage_parse_flow_and_learn` returns `None` → `flow = None`.
  4. Main dispatch: `if let Some(flow) = flow` branch (policy + NAT + NAT64 allocate_source + session install) is skipped.
  5. `else` branch (flowless path): route-based forwarding, no NAT64 allocation, no PortAllocator claim.
  6. No port leak. Non-first NAT64 fragments are dropped at flowless TX (no NAT translation for fragments without L4, consistent with RFC 7915 fragment handling).

- Refutation: Initially suspected non-first fragments could allocate garbage-port NAT64 entries and leak on translation failure. Traced through code — the non-first fragment check is BEFORE flow creation, so the NAT64 path is unreachable. Verified by reading `parse_session_flow_from_bytes` → `frame_is_non_first_fragment` → `None` → flowless path. Consistent with #2344 (single chokepoint for non-first fragment handling).

- Why it matters: This is a valuable negative result — it proves the NAT64 non-first fragment path is fail-closed (drop) with no resource leak, and the #2344 chokepoint correctly gates NAT64 allocation. Load-bearing coverage proof.

- Dedup note: F-?? NAT64 non-first fragment (F-236) is CLOSED (fixed #2488). This is a negative result proving the new (#4381) NAT64 BIB allocator doesn't regress the non-first fragment handling.

---

### [L-02] NPTv6 / NAT64 / NAT pool exhaustion — all fail CLOSED, no fail-OPEN

- Title: NAT pool exhaustion (source NAT, NAT64, NPTv6) — verified fail CLOSED on exhaustion, no fail-OPEN widening
- Severity: N/A (negative result — correct behavior)
- Confidence: High
- Class: fail-open (negative — no bug, fail-closed verified)

- Evidence:

  ```rust
  // Source NAT pool exhaustion — userspace-dp/src/nat/source.rs:1110-1117
  Err(reason) => {
      return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(rule, reason));
  }
  // Caller in poll_descriptor/mod.rs:2751-2764
  Err(failure) => {
      record_source_nat_failure(telemetry, worker_ctx, meta, flow, ...);
      binding.scratch.scratch_recycle.push(desc.addr);
      continue; // DROP, fail closed
  }

  // NAT64 pool exhaustion — userspace-dp/src/nat64.rs:500-511
  Some(prefix) if !prefix.pool_v4.is_empty() => Nat64Match::MatchReady { ... }
  _ => Nat64Match::MatchUnavailable // empty pool -> drop

  // NAT64 PortAllocator exhaustion — nat64.rs:541-563, poll_descriptor/mod.rs:2659-2676
  Err(reason) => {
      telemetry.counters.record_nat64_source_failure(reason); // #4520 split
      binding.scratch.scratch_recycle.push(desc.addr);
      continue; // DROP, fail closed
  }

  // NPTv6 overlap/malformed — nptv6.rs:223-305
  try_from_snapshots -> Err(SnapshotIntegrityError::Nptv6OverlappingPrefix / Nptv6UnparseableRule)
  // -> apply preflight keeps previous live state, no fail-open narrowing
  ```

- Trace: Verified all NAT pool exhaustion paths fail CLOSED (drop) rather than FAIL-OPEN (allow without translation or widen to match-any). Source NAT: `Unavailable` → drop + counter. NAT64: `MatchUnavailable` (empty pool) → drop, `AllocatorExhausted` (port exhaustion) → drop + `nat64_pool_exhausted` counter (split from `nat64_no_source_pool` per #4520). NPTv6: malformed/overlapping prefix → reject whole snapshot → keep previous state (fail-closed, not fail-open narrowing).

- Refutation: Checked for any path where pool exhaustion returns `NoMatch` instead of `Unavailable`/`MatchUnavailable` — none. The `SourceNatLookup::NoMatch` arm continues to next rule (not fail-open), and if all rules exhaust, the packet is forwarded untranslated (which is the correct Junos behavior for "no SNAT rule matched" — not a fail-open). The NAT64 `NoPrefixMatch` arm continues IPv6 routing (correct — genuinely non-NAT64 traffic). Only the `MatchUnavailable`/`AllocatorExhausted` arm (prefix matched but no source allocatable) must drop, and it does.

- Why it matters: Negative result proving NAT exhaustion is fail-closed across all three NAT types (source, NAT64, NPTv6). Load-bearing coverage for the fail-open audit emphasis.

## 7. Verified negatives (fail-closed, no bypass)

| Path | What was checked | Result |
|---|---|---|
| SNAT pool exhaustion | `SourceNatLookup::Unavailable` -> drop + counter | Fail CLOSED ✓ |
| NAT64 empty pool | `Nat64Match::MatchUnavailable` -> drop (not route synthetic) | Fail CLOSED ✓ (#2291) |
| NAT64 port exhaustion | `AllocatorExhausted` -> drop + `nat64_pool_exhausted` | Fail CLOSED ✓ (#4381/#4520) |
| NPTv6 malformed prefix | `try_from_snapshots` -> Err -> keep previous state | Fail CLOSED ✓ (#2240) |
| NPTv6 overlapping prefixes | `find_overlap` -> Err -> keep previous state | Fail CLOSED ✓ (#2241/#4339) |
| NPTv6 host-bits beyond prefix | `parse_prefix` -> None -> Err -> keep previous | Fail CLOSED ✓ (#4519) |
| NPTv6 0xFFFF adjustment | `is_zero_adjustment` skip + `adjust_word` 0xFFFF->0x0000 | Correct ✓ (#3233) |
| NAT64 non-first fragment port leak | `frame_is_non_first_fragment` -> None flow -> flowless path -> no alloc | No leak ✓ (#2344) |
| NAT64 embedded non-first fragment | `ipv6_is_non_first_fragment(quote_in)` -> None -> drop | No corrupt ✓ |
| NAT64 EH walkers | 0/43/60/135/139/140/253/254/51/44/59 + MAX=8 post-loop None | Correct ✓ (#4435/#4517) |
| NAT64 incremental checksum | 3 full-recompute cases + incremental == full | Correct ✓ (#3025) |
| NAT64 allocator reuse on reload | `from_snapshots_with_previous` reuse on byte-identical, fresh on changed pool | Correct ✓ (#4518) |
| SNAT non-first fragment | `snat_non_first_fragment` -> drop pool-mode, allow interface-mode | Correct ✓ (#1852) |
| SNAT ICMP identifier | `icmp_identifier_present` gate, not `src_port != 0` | Correct ✓ (#4074/#4088) |
| DNAT ICMP identifier | `protocol_has_l4_ports` gate prevents ICMP getting spurious port | Correct ✓ (#4074) |
| DNAT off exemption | `DnatOutcome::Exempt` is Some -> halts `.or_else` chain | Correct ✓ (#3844) |
| Static NAT block reject on port | Block + port -> drop (not widen to all-port) | Correct ✓ (#3202) |
| Static NAT prefix-name | Resolved at config compile time to literal prefix | Correct ✓ (#4290) |

## 8. Suggested issue split

### Immediate (1 issue)

**Issue: `[MEDIUM] Deterministic NAT (CGNAT) port deterministic block-size / host address not enforced on userspace dataplane — BPF-only, retired dataplane`**

- Labels: `vsrx-parity`, `unenforced-control`, `nat`, `cgnat`
- Description: M-01 above. Config `port deterministic block-size N host address CIDR` commits clean but production userspace-dp (the only runtime, BPF retired #1373) silently ignores it. Deterministic NAT was implemented for BPF (74e1d17, 439cd3f) and DPDK (both retired), never ported to userspace-dp. Fix: port to userspace-dp `allocator.rs` + snapshot, or gate as unsupported with warning.

### Low / Tracking (2 issues)

- **L-01 (ps-review-028)**: Synthetic (protocol==0) `try_next_port` untracked — theoretical, port never frame-written, minimal risk. Already filed in ps-review-028.
- **#4512**: NAT64 HA-sync port reservation — already OPEN, not re-reported.

## 9. Coverage notes

- Read 400+ lines per file in all 10 cohort modules (NAT source/destination/static/allocator/mod, NAT64, NPTv6, compiler_nat.go, userspace nat_source/nat_destination/nat.go, BPF compiler_nat.go)
- Verified all 14 CLOSED fix statuses on HEAD 8cd816e35
- Verified 4 OPEN issues not re-reported (#4512 NAT64 HA-sync, #2387 bare 5-tuple, #4146 junos-host, #3226 system-services — out of scope or explicitly excluded)
- Deduped against /tmp/all_findings.txt (272 entries) + /tmp/ps-review-018..033 (14 files) + gh issue list --state all (500 issues)
- Found 1 new MEDIUM finding (M-01: deterministic NAT gap) + 2 negative results (NAT64 non-first fragment no leak, NAT exhaustion fail-closed)
- No HIGH/CRITICAL fail-open bugs found in this cohort on HEAD 8cd816e35 — the prior audits (especially ps-review-028) were thorough and fixes are solid

