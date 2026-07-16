# xpf firewall deep audit — Cohort 5: NAT / NAT64 / NPTv6 — ps-review-028

- Base commit: b1bd96fb6 (merge PR #4531, master)
- Output path: /tmp/ps-review-028.md
- Cohort: 5 — userspace-dp/src/nat/{mod,source,destination,static_nat,allocator,status}.rs, userspace-dp/src/nat64.rs, userspace-dp/src/nptv6.rs, pkg/config/compiler_nat.go, pkg/dataplane/userspace/nat{,_source,_destination,_nptv6,nat64}.go

## 1. Base commit reviewed

```
b1bd96fb6 Merge pull request #4531 from psaab/fix/4526-dhcp-timer-overflow
```

Branch master, HEAD includes fixes #4521, #4381, #4388, #4393, #4399/#4438, #4384, #4518, #4526 etc.

## 2. Output path

```
/tmp/ps-review-028.md
```

## 3. Duplicate-suppression summary + intentional-divergence list

### Prior findings reviewed

- `/tmp/all_findings.txt` — 272 entries (F-001..F-272)
- `/tmp/ps-review-024.md` — firewall filters + PBR cohort (ps-review-024)
- `/tmp/ps-review-025.md` — policy verdict engine cohort (ps-review-025)
- `docs/feature-gaps.md`, `docs/vsrx-gaps.md` (stale), recent `_Log.md`

### Dedup'd against (NOT re-reported as new)

| Prior ID | Topic | Why dedup'd |
|---|---|---|
| F-158 | compileNAT reads only FIRST source/destination/static/nat64 block | Fixed #3915 — forEachChild loop in compiler_nat.go:compileNAT |
| F-083 | NPTv6 0xFFFF adj word mistranslation | Fixed #3233 — is_zero_adjustment skip |
| F-032 | NAT64 prefix /96 not validated at commit | Fixed #3886 — validateNAT64PrefixStrict |
| F-033 | SNAT pool `port range <low> to <high>` silently dropped | Fixed #3906 — parseSourcePoolPortRange Junos shape |
| F-098 | SNAT pool bracket-list `address [ a b c ]` keeps only first | Fixed #4521 — appendPoolAddresses full token stream |
| F-186 | Pool-mode SNAT never translates ICMP query ID | Fixed #4074/#4088 — icmp_query detection |
| F-132 | Persistent-NAT lease keeps creation-time timeout forever | Fixed — lease reuse updates expires_at_ns |
| F-236..F-240 | NAT64 embedded-error / fragment / port-less translation | Fixed #3025/#2488/#3111 or tracked known |
| F-206 | NAT compile scattered / refactor debt | Acknowledged refactor — not correctness |
| F-181 | pool-utilization-alarm raise-only rejected | Fixed #4077 — defaultPoolAlarmClearThreshold |
| All ps-review-024/025 | Filter / policy engine findings | Out of cohort — not re-reported |

### Intentional divergences (NOT bugs)

- Intrazone default-permit, host-originated junos-host rejection, IPsec-passthrough-exempt — documented, not reported.
- NAT rule-set `from zone any` literal zone named "any" is NOT wildcard (unlike security policies). Source-NAT `scope_matches` only special-cases empty string. Consistent with match engine.
- NPTv6 only /48 and /64 — RFC 6296 parity. /56 etc. intentionally rejected.
- NAT64 only /96 — RFC 6052. Non-/96 rejected.
- NAT64 `MatchUnavailable` (prefix matched but empty pool) fails closed (drop) — intentional.
- Source NAT pool /24 expands to FULL prefix range (256 hosts per #3049) — Junos FULL range, not host-mask bug. DNAT pool /24 correctly rejected (must be single host via dnatPoolHostIP).
- `natAddrFamily` textual classification (colon == v6) so `::ffff:1.2.3.4` is v6 — matches Rust Ipv6Addr::from_str, not Go To4().

### Required fix-status verification (HEAD b1bd96fb6)

| Fix ID | Topic | Status | Evidence |
|---|---|---|---|
| #4521 | SNAT pool address bracket-list truncation | FIXED | `compiler_nat.go:1137-1418` `appendPoolAddresses(pool, prop.Keys[1:])` reads full token stream; expandRange in place. Verified Keys[1:] not Keys[1]. |
| #4381 | NAT64 port/ICMP-id translation (RFC 6146 BIB) | FIXED | `nat64.rs:419-439` per-prefix `PortAllocator`, `allocate_source()` → `allocate_nat64_pool_port()` → `PortAllocator::allocate_translation()` unique (pool_v4, port) per flow. `classify_ipv6_dest` returns MatchReady (deferred alloc). |
| #4388 | HA NAT — standby reserves synced pool port | FIXED | `nat/source.rs:748-800` `reserve_synced_source_nat_allocation()`, `allocator.rs:724-766` `reserve_flow()` idempotent, never steals from different live allocation. |
| #4393 | dnat_table reverse for synced SNAT | FIXED | Per git log merge. Reverse SNAT dnat_table entry published for synced sessions. |
| #4399/#4438 | NAT 1:N reverse index | FIXED | Git log: #4399 `nat_reverse_index` 1:N multimap, #4438 `forward_wire + reverse_translated` 1:N. Prevents NAT source collision. |
| #4384 | TCP checksum segmentation dead code | FIXED | `1b43d1633 forwarding: delete dead-but-wrong incremental TCP checksum in segmentation (#4384)` in HEAD. |
| #4518 | NAT64 allocator durability across reload | FIXED | `nat64.rs:308-467` `from_snapshots_with_previous()` reuses Arc-backed PortAllocator when (prefix_bytes, pool_v4) byte-identical. `dd40ca389` in HEAD. |
| #4526 | DHCP timer overflow | FIXED (out of cohort) | `3915d0018 dhcp: avoid int64 overflow` in HEAD. |

All in-scope fixes verified present on b1bd96fb6. No regressions.

## 4. Module / verdict-path inventory (coverage checklist + cohort map)

| Module | File(s) | Role | Reviewed |
|---|---|---|---|
| NAT source + pool + persistent | `userspace-dp/src/nat/source.rs` | SNAT rule matching, L4 constraints, interface/pool/off/addr-persist/persistent-NAT, pool expansion, allocator keying, HA reserve | YES full |
| NAT destination (DNAT) | `userspace-dp/src/nat/destination.rs` | DNAT exact+wildcard+PROTO_ANY+prefix-LPM, src/src-port/ICMP constraints, off exemption, local-addr reg | YES full |
| Static NAT (host + block) | `userspace-dp/src/nat/static_nat.rs` | Host 1:1 + block-to-block, port-mapped, source-constraint, zone/interface/RI scope, SNAT reverse | YES full |
| Port allocator + persistent leases | `userspace-dp/src/nat/allocator.rs` | Claim/assign/recycle FIFO, seq probe, persistent lease lifecycle, expiry GC, HA reserve, sticky | YES full |
| NAT core (NatDecision, counters) | `userspace-dp/src/nat/mod.rs` | NatDecision reverse/merge, NatRuleCounter atomic reset (#3830), NatCounterStore | YES full |
| NAT64 translation | `userspace-dp/src/nat64.rs` | Prefix match, pool alloc (BIB), v6↔v4 translation, ICMP error+embedded, frag, checksum, ext-hdr walk, fail-scoped parse | YES full (first 1006 lines focused, rest sampled) |
| NPTv6 (RFC 6296) | `userspace-dp/src/nptv6.rs` | Prefix parse, adjustment, 0xFFFF handling (#3233), overlap reject (#2241), inbound/outbound | YES full |
| NAT Go compiler | `pkg/config/compiler_nat.go` | compileNAT all sub-blocks (#3915), SNAT/DNAT/static/NAT64/NPTv6/natv6v4/proxy-arp, pool expansion, deterministic NAT, NPTv6+NAT64 validation | YES full (all 2529 lines) |
| NAT Go snapshot builders | `pkg/dataplane/userspace/nat_source.go`, `nat_destination.go`, `nat.go` | SNAT/DNAT snapshot build, addr-book+feed overlay, app-term expansion, port-range coalesce, never-match sentinels, scope tiering (#4161) | YES full |

## 5. Module-by-module inspection log (including negatives)

### 5.1 nat/source.rs — Source NAT

- `matches()` → `scope_matches()` (interface/RI AND-ed, empty wildcard), `l4_matches()` (dst-port AND app-term, proto 0 synthetic fails closed), `nets_match_v4/v6` with `source_constrained`/`destination_constrained` fail-closed (empty parsed list → match nothing when constrained true, #2398). Correct.
- `l4_matches()`: `protocol==0` fails closed when any L4 constraint present. `match_apps`: `SOURCE_NAT_PROTO_ANY=256`, `src_ports` AND-ed (#3491), `low>high` sentinel preserved. Correct.
- `expand_pool_address()`: bare IP → single host, CIDR → FULL prefix enumeration (Junos, #3049). Cap 65536. Correct.
- `parse_source_nat_rules_with_previous()`: preserves allocator via `allocator_key` dedup; fresh for changed pool. `pool_failure` for invalid/missing/empty/inverted range. Correct.
- `match_source_nat_result_for_tuple()`: `non_first_fragment` gate (#1852) drops pool-mode on fragments, interface/off/static unaffected. `port_less`/`tuple_unknown`/`no_translation` → address-only path leaves `rewrite_src_port=None`. ICMP Query ID via `icmp_query = matches!(proto,ICMP|ICMPv6) && icmp_identifier_present` (#4074/#4088). Correct.
- `reserve_synced_source_nat_allocation()` (#4388): finds pool containing translated IP, reserves specific (flow, tuple), idempotent refresh. Correct.

**Negative**: No bypass. All fail-closed gates verified.

### 5.2 nat/destination.rs — DNAT

- `PROTO_ANY=256` u16 distinct from HOPOPT(0) (#2396). `DnatKey.protocol: u16`. Lookup tiers: exact → wildcard-port → PROTO_ANY → prefix-LPM. Zone-specific wins over wildcard within tier. Correct.
- `source_matches()`: unscoped→any, constrained+empty→fail closed (#2394). `l4_extra_matches()`: dst-ports (#3449), src-ports (#3437 H10), icmp type/code (H11) AND-ed, never-match sentinel never satisfies. Correct.
- `DnatOutcome::Exempt` vs `Translate` — Exempt is Some so `.or_else` halts (Junos ordered off, #3844). `insert_entry`/`insert_prefix_slot` dedup on (zone,interface,RI,source,match_src_ports,match_dst_ports,icmp,off). Scope-distinct + off-vs-translate distinct (#3605/#3844). Correct.
- `destination_ips_scoped()` skips off entries. `MAX_LOCAL_PREFIX_HOSTS=4096` bounds proxy-ARP. `#4074` port-less gate prevents ICMP getting spurious port. Correct.

**Negative**: No bypass.

### 5.3 nat/static_nat.rs — Static NAT

- `SourceConstraint` fail-closed, `static_scope_ok` AND-ed, `pick_scoped` (#3605) zone-scoped wins over wildcard, Vec per key so scope-differing rules coexist (pre-#3605 last-write-wins fixed). `StaticNatBlock` (#3031) offset-preserving `remap_addr`, equal-length+same-family validation, port-mapped block rejected (#3202). `parse_nat_prefix` canonicalizes, `host_mask` guards UB on `MAX>>32`. `match_dnat/snat_with_counter_scoped` per-candidate zone+interface+RI+source, port-specific fails→whole-address fallback (#2864/#2871/#2769). Correct.

**Negative**: No bypass.

### 5.4 nat/allocator.rs — Port Allocator

- `allocate_translation`: max_tracked_flows cap, live_by_flow dedup, persistent reuse+expiry refresh, GC on alloc/pressure/release. `claim_free_port_locked` (#3047) seq probe forward past out-of-band occupants, FIFO recycled (pop_front oldest first, #3011 2MSL), collided recycled retained at back (never discarded, 062-10), lazy retained Vec. `release_flow`/`rollback_flow` persistent accounting correct. `reserve_flow` (#4388) idempotent, never steals. `release_expired_lease_locked` checks active_flows==0 && expires==expected. `sticky_pool_index` FxHash deterministic. Correct.

**Negative**: No double-free, no port leak on collision, no stale lease after concurrent refresh.

### 5.5 nat/mod.rs — NatDecision + Counters

- `NatDecision::reverse` swaps rewrite_src↔rewrite_dst with original tuple. `merge` prefers self. `NatRuleCounter::reset` uses load+fetch_sub (not store 0) to avoid clobbering concurrent per-flow add (#3830, mirrors PolicyRuleCounter). `NatCounterStore::reconcile_ids` retains only active, `clear` via reset. Correct.

### 5.6 nat64.rs — NAT64

- `from_snapshots_with_previous`: fail-scoped per-rule skip (not abort-all, #3888), requires exactly 2 `/`-parts AND /96. `parse_pool_v4` bare or /32 only, non-host→skip whole rule (all-or-nothing #2212). Per-prefix `PortAllocator` BIB (#4381). Reuse on byte-identical (prefix,pool) (#4518), fresh on changed pool. `Nat64Match` tri-state (#2291) prevents fail-open (MatchUnavailable→drop, not route synthetic). `ipv6_l4_offset_and_protocol` walks 0/43/60/51/44 bounded MAX_IPV6_EXT_HEADERS=8 (#4435 alignment), post-loop fail-closed None. `ipv6_is_non_first_fragment` correct. `next_frag_id` `raw%65535+1` cycle 1..=65535 no consecutive dup within 65535. Incremental checksum (#3025) byte-identical to full recompute, 3 full-recompute cases correct. `MAX_EMBEDDED_LEN=1300` bounded scratch, no per-packet heap. SSOT eth-header writer (#2844). Correct.

**Negative**: No OOB, no unbounded alloc, no stale allocator reuse.

### 5.7 nptv6.rs — NPTv6

- `parse_prefix` requires 2 `/`-parts, /48 or /64 only. `compute_adjustment` isum+!esum folded. `adjust_word` carry fold + 0xFFFF→0x0000. `is_zero_adjustment` accepts 0x0000||0xFFFF (0x0000 identity, 0xFFFF negative-zero neutral — skipping avoids 0xFFFF host collapse, verified proof). `translate_outbound/inbound` prefix rewrite + adj / +!adj, `adj_word` /64→4 /48→3. `try_from_snapshots` fail-closed (#2240) + overlap reject both directions (#2241), same (ruleset,rule) identity skipped (#4339). `find_overlap` min(common) correct for /48 nesting /64. Correct.

**Negative**: No silent 0xFFFF mistranslation, no overlap-miss.

### 5.8 pkg/config/compiler_nat.go — NAT Compiler

- `compileNAT()` (#3915) `forEachChild` every sub-block. `parseNATMatchScopes` (#3096) all kinds both shapes, mixed-kind AND-ed. `appendPoolAddresses` (#4521) FULL token stream Keys[1:]+Children. `expandAddressRange` max 256. `parseSourcePoolPortRange` (#3906) Junos `<low> to <high>` + legacy. Deterministic accumulate (#3864). `compileNATSource` pool/port/persistent-nat/determ/port-overload-factor+routing-instance advisory (#4291/#4292), `#3850` every match/then with whole-struct reset, `#3431` firewallMatchValues/parseDNATPortList full accumulation. `compileNATDestination` `#3444` from-only, `#3844` off exemption both shapes, `#3850`, `#3431`. `parseDNATPortList` (#3449) unified shape + invalid token tracking + `appendDNATPortRange` bounded (no OOM on `1 to 4000000000`). `compileNATStatic` `#3850`, `#3435`, `#2491`, `#4290` prefix-name deferred, `#4292` routing-instance, scope expansion. `compileNAT64` prefix+pool. natv6v4 OR accumulation. Correct.

### 5.9 pkg/dataplane/userspace/nat_*.go — Snapshot Builders

- `nat.go`: `resolveNATAddressNamePrefixes` unions static+feed (#3303 direct ref OK), fail-closed on unknown (raw token, Rust fails parse→no prefix→match nothing). `natNeverMatchPortRange={1,0}` never satisfies `p>=1&&p<=0`. `coalescePortRanges` skips OOR, run-merges. `appPortsFromSpec` reversed `lo>hi→nil` (#3726). Correct.
- `nat_source.go`: `buildSourceNATSnapshotsWithFeeds` source/dest address-name feed res (#2416/#3229), pool, `sourceNATPoolPortRange` validation, persistent 3-way permit, `sourceNATDestPortRanges` with invalid (#3546) → never-match sentinel, `buildSourceNATAppTerms` src-port + `natProtoNever=0xFFFF` fail-closed, `sourceNATScopeTier` MIN(from,to) interface>zone>RI>unscoped (#4161) stable sort. `scopeContextTier` empty only wildcard, not "any". Correct.
- `nat_destination.go`: `dnatDestinationParts` host vs prefix (#3164), `dnatPoolHostIP` host-only (#3450), off exemption (`Off=true`, #3844), multi-dest (#2395), dest-addr-name feed (#3229), src-addr-name (#2416), app-terms src-ports+icmp (#3437), `MatchUnavailable` fail-closed (#3434), rule-level dport authoritative (#3857), `MatchDestinationPorts` range vs exact (#3449), never-match on configured-but-unrepresentable (#3446), non-host prefix LPM via `DestinationPrefix` (#3164). Correct.

## 6. Findings

---

### [L-01] Source NAT synthetic (protocol==0) port allocation via try_next_port is untracked

- Title: Source NAT synthetic (protocol==0) port allocation via try_next_port is untracked — no ownership record
- Severity: Low
- Confidence: Medium
- Class: implementation-bug
- Evidence:
  ```rust
  // userspace-dp/src/nat/source.rs:1067-1099
  let address_only = port_less || tuple_unknown || rule.no_translation;
  // ...
  if address_only {
      let addr_idx = rule.pool_allocator.address_index(
          src_ip, 0, rule.pool_addresses_v4.len(), rule.address_persistent);
      let pool_addr = rule.pool_addresses_v4[addr_idx];
      let port = if tuple_unknown && !rule.no_translation {
          match rule.pool_allocator.try_next_port(addr_idx) {
              Ok(port) => Some(port),
              Err(reason) => return SourceNatLookup::Unavailable(
                  SourceNatFailure::for_rule(rule, reason)),
          }
      } else { None };
      return SourceNatLookup::Matched(NatDecision {
          rewrite_src: Some(IpAddr::V4(pool_addr)),
          rewrite_src_port: port, ..Default::default() });
  }

  // userspace-dp/src/nat/allocator.rs:295-310
  pub(super) fn try_next_port(&self, addr_index: usize) -> Result<u16, SourceNatFailureReason> {
      let counter = &self.shared.counters[addr_index];
      let val = counter.fetch_add(1, Ordering::Relaxed);
      Ok(self.port_low + (val % range) as u16)
  }
  // NOTE: try_next_port does NOT insert into owner_by_translated / live_by_flow
  ```
- Trace:
  1. Config: SNAT pool-mode rule with pool 203.0.113.0/28 (16 addrs, 64512 ports each).
  2. Internal caller `match_source_nat()` (address-only, protocol==0 synthetic) triggers repeatedly — each call goes through `tuple_unknown=true` path, `address_only=true`, calls `try_next_port` which round-robins port N, N+1, ... via atomic counter only.
  3. These ports are NOT tracked in `owner_by_translated` / `live_by_flow`.
  4. Subsequent TCP flow via `allocate_translation` → `claim_free_port_locked` → `assign_owner_locked` checks `owner_by_translated.contains_key` — does NOT see synthetic ports, could claim same (pool_addr, port) via sequential probe or recycled queue.
  5. Two flows share same (pool_addr, port) on wire → reverse tuple collision, reply demux to wrong session.
  6. Mitigation: `match_source_nat()` callers are synthetic address-only probes (not real L4 flows). The `NatDecision.rewrite_src_port` is Some(port) but packet rewriters gate on `has_l4_ports(protocol)` and protocol==0 never has L4 ports, so port is never frame-written. No wire collision. Theoretical only.
- Refutation attempted:
  - Checked `nat/source.rs:1036` comment: "The port it returns can never be written to a frame" — verified `has_l4_ports(0)==false`, rewriters skip L4 write for protocol 0.
  - Checked callers of `match_source_nat()` — they are address-only probes (health checks, route probes), not forwarding-path TCP/UDP flows.
  - No live fail-open or traffic corruption on current code. Untracked-port is defense-in-depth gap.
- Why it matters:
  Minimal — synthetic callers only, port never frame-written. But untracked ports could confuse future code or HA sync that reads `rewrite_src_port` from a synthetic decision. Bounded risk.
- Fix direction:
  Return `None` for port when `tuple_unknown` (protocol==0) instead of `try_next_port` — same as `port_less` and `no_translation` paths already do (address-only, no port). Or make `try_next_port` also insert into `owner_by_translated` with synthetic Flow key (tracked, bounded). Option (a) is simpler: synthetic path is address-only by definition, no port needed.
- Labels: `nat`, `allocator`, `low-priority`, `implementation-bug`
- Dedup note: Not in /tmp/all_findings.txt. No prior finding mentions try_next_port untracked ownership. Distinct from F-186 (ICMP ID not translated — fixed #4074).

---

### [I-01] NAT64 Nat64Prefix.pool_index AtomicUsize dead in production

- Title: NAT64 Nat64Prefix.pool_index AtomicUsize is dead in production — only used by #[cfg(test)] allocate_v4_source
- Severity: Low
- Confidence: High
- Class: parity-gap
- Evidence:
  ```rust
  // userspace-dp/src/nat64.rs:166-172
  pub(crate) pool_v4: Vec<Ipv4Addr>,
  pool_index: AtomicUsize,  // retained for empty-pool / liveness probe only (comment) but only used by test
  pub(crate) port_allocator: PortAllocator,

  // userspace-dp/src/nat64.rs:515-527
  #[cfg(test)]
  pub(crate) fn allocate_v4_source(&self, prefix_idx: usize) -> Option<Ipv4Addr> {
      let idx = prefix.pool_index.fetch_add(1, Ordering::Relaxed);

  // Clone copies the AtomicUsize value:
  // impl Clone for Nat64Prefix: pool_index: AtomicUsize::new(self.pool_index.load(Ordering::Relaxed))
  ```
  Production `classify_ipv6_dest` only checks `!pool_v4.is_empty()`, `allocate_source` goes via `PortAllocator`. No production reader of `pool_index`.
- Trace:
  1. `Nat64State::from_snapshots_with_previous` creates `AtomicUsize::new(0)` per prefix, even when reusing `port_allocator`.
  2. No production path reads `pool_index`.
  3. One AtomicUsize (8 bytes) per prefix overhead, no correctness impact.
- Refutation attempted:
  - Grepped all non-test callers of `pool_index` — none.
  - `Nat64Prefix::clone()` copies the value but no production code depends on it.
  - `from_snapshots_with_previous` always creates fresh 0, not preserved across reload.
  - Not a correctness issue.
- Why it matters:
  Dead code — 8 bytes per prefix, negligible. Could be gated `#[cfg(test)]` or removed. No security impact.
- Fix direction:
  Gate `pool_index` with `#[cfg(test)]` or remove. Keep only `port_allocator`. No urgency (P4).
- Labels: `nat64`, `dead-code`, `low-priority`
- Dedup note: Not in /tmp/all_findings.txt. Not security-relevant. Informational only.

---

### [I-02] source_nat_runtime_compatible dead function — never called

- Title: source_nat_runtime_compatible is defined but never called — dead function intended for incremental reload optimization
- Severity: Low
- Confidence: High
- Class: parity-gap
- Evidence:
  ```rust
  // userspace-dp/src/nat/source.rs:650-665
  #[allow(dead_code)]
  fn source_nat_runtime_compatible(new_rule: &SourceNatRule, old_rule: &SourceNatRule) -> bool {
      new_rule.name == old_rule.name
          && new_rule.pool_name == old_rule.pool_name
          && new_rule.pool_mode == old_rule.pool_mode
          && new_rule.no_translation == old_rule.no_translation
          && new_rule.pool_failure == old_rule.pool_failure
          && new_rule.address_persistent == old_rule.address_persistent
          && new_rule.persistent_nat == old_rule.persistent_nat
          && new_rule.persistent_nat_permit == old_rule.persistent_nat_permit
          && new_rule.persistent_nat_inactivity_timeout_secs == old_rule.persistent_nat_inactivity_timeout_secs
          && new_rule.pool_addresses_v4 == old_rule.pool_addresses_v4
          && new_rule.pool_addresses_v6 == old_rule.pool_addresses_v6
          && new_rule.pool_allocator.port_low == old_rule.pool_allocator.port_low
          && new_rule.pool_allocator.port_high == old_rule.pool_allocator.port_high
  }
  // grep: no call sites in codebase
  ```
- Trace:
  1. Function defined at `source.rs:650`.
  2. `#[allow(dead_code)]` annotation confirms author knows it is unused.
  3. Intended to mirror NAT64 `reuse_allocator` pattern (#4518) for source NAT incremental reload — compare new vs old rule for compatibility to decide if allocator can be reused.
  4. Actual source NAT reload uses `previous_allocators` keyed by `SourceNatPoolAllocatorKey` (pool_name + addresses + port range), not this function.
  5. Dead function, no runtime effect.
- Refutation attempted:
  - Grepped `source_nat_runtime_compatible` across entire repo — 0 call sites.
  - `#[allow(dead_code)]` present (author-intended temporary).
  - No correctness issue — dead code only.
- Why it matters:
  Informational. Might be intended for future optimization or was superseded by `allocator_key` dedup path. No security/correctness impact.
- Fix direction:
  Either wire into incremental reload path (compare to NAT64 #4518 pattern) or remove. No urgency.
- Labels: `nat`, `dead-code`, `low-priority`
- Dedup note: Not in /tmp/all_findings.txt. Not security-relevant. Dead-code informational.

---

## 7. Negative results (verified fail-closed / not exploitable)

### N-01: DNAT PROTO_ANY distinct from HOPOPT(0) — verified fixed #2396

- Path: `destination.rs:28 PROTO_ANY=256 (u16)`, `DnatKey.protocol: u16`, probe `u16::from(protocol)` (0..=255) then `PROTO_ANY=256` separately. Protocol 0 (HOPOPT) keys as 0, never conflates with wildcard. IP-only DNAT (`""`+no port) keys under 256 and covers ICMP/GRE via fallback. Verified correct.

### N-02: Source NAT source_constrained / destination_constrained fail-closed — verified #2398

- Path: `source.rs:542-543 source_constrained = !snap.source_addresses.is_empty()`, `nets_match_v4/v6` returns false when constrained but both v4/v6 empty (all failed to parse) → matches NOTHING, not match-any. Prevents fail-open. Same in DNAT and static NAT.

### N-03: Static NAT block-to-block remap_addr correctness

- Path: `static_nat.rs:288-304 remap_addr()` uses `src.len` mask (equal to dst.len by validation), `dst.base` network bits, `addr & host_mask` host bits preserved. Correct for v4 (u32) and v6 (u128). `len>=32/128→host_mask=0` avoids UB.

### N-04: NPTv6 is_zero_adjustment both 0x0000 and 0xFFFF — verified correct #3233

- Path: `nptv6.rs:127-129 is_zero_adjustment = adj==0||adj==0xFFFF`. Proof: `compute_adjustment` neutral pair → `isum+!isum=0xFFFF` (negative zero). Applying 0xFFFF to 0xFFFF→0xFFFF→0x0000 collapses host; must skip. Applying 0x0000 is identity (w+0=w), skipping same. Both safe to skip. Verified correct.

### N-05: NAT64 classify_ipv6_dest tri-state prevents fail-open — verified #2291

- Path: `nat64.rs:497-513` `NoPrefixMatch→route as IPv6`, `MatchReady (non-empty pool)→translate`, `MatchUnavailable (empty pool)→drop` (fail closed, not route synthetic 64:ff9b::). Prevents pre-#2291 fail-open.

### N-06: Port allocator max_tracked_flows bounding

- Path: `allocator.rs:51 MAX=262144`, `PortAllocator::new` caps, `allocate_translation` early `AllocatorExhausted` when `live_by_flow.len()>=max`. Prevents OOM from attacker opening many flows.

### N-07: Source NAT port-less protocol gate (#3111)

- Path: `source.rs:1055-1057 port_less = protocol!=0 && !has_l4_ports(protocol) && !icmp_query`. GRE/ESP/AH/OSPF/ICMP-non-query → `address_only=true` → no port allocated/written. Previously corrupted GRE flags / ESP SPI. Verified fixed.

### N-08: NAT64 prefix /96 strict parsing

- Path: `nat64.rs:370-377` requires exactly 2 `/`-parts AND mask==96, extra slash `/96/garbage`→3 parts→rejected. Verified correct.

### N-09: NPTv6 overlap rejection

- Path: `nptv6.rs:252-271` `find_overlap` both directions, `common=min(a_words,b_words)`, `candidate[..common]==prefix[..common]` correctly detects /48 nesting /64 and identical, correctly distinguishes two /64s in same /48 with different 4th word. Same (ruleset,rule) scope-expansion skipped (#4339). Verified correct.

### N-10: DNAT multi-destination + prefix LPM

- Path: `nat_destination.go:29-51` host vs prefix classification, Go and Rust agree. Per-dest snapshot emission (`for _, rawDst := range destAddrs`). Exact host map tried first, /32 wins over prefix LPM. Verified #3164+#2395.

### N-11: Go snapshot builders never-match sentinels preserved

- Path: `nat.go:124-135 natNeverMatchPortRange={1,0}` never satisfies `p>=1&&p<=0`, preserved verbatim through `source.rs:558-586` / `destination.rs:433-446` (low>high ranges kept, not dropped). Empty list = unconstrained (legitimate), configured-but-empty = never-match (fail-closed). AGY finding on PR #3471 addressed. Verified.

## 8. Suggested issue split

No High/Medium issues. All required fixes verified present on b1bd96fb6.

| Priority | Issue | Finding | Title |
|---|---|---|---|
| P3 | Low | L-01 | SNAT try_next_port synthetic path untracked — return None for protocol==0 instead of try_next_port |
| P4 | Info | I-01 | NAT64 pool_index AtomicUsize dead in production — gate #[cfg(test)] |
| P4 | Info | I-02 | source_nat_runtime_compatible dead function — wire or remove |

Fail-opens: **0 new** — all prior NAT/NAT64/NPTv6 fail-open fixes verified present, no regressions, no new bypass found.

---

Base commit reviewed: b1bd96fb6
Output path: /tmp/ps-review-028.md
Cohort: 5 (NAT / NAT64 / NPTv6)
Date: 2026 audit cycle
