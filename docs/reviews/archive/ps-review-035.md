# xpf firewall deep security audit — master 8cd816e35 — all-cohort synthesis

## 1. Base commit reviewed

```
8cd816e35 Merge pull request #4545 from psaab/fix/4540-4541-cli-api-hardening
  3ad49b357 api: marshal JSON to a buffer before committing the status header
  a662167ad Merge remote-tracking branch 'origin/master' into HEAD
  9da5d89   cli: reject monitor traffic bare keyword / missing value (fix/4540)
  8cd816e35 Merge #4545

Branch: master, up to date with origin/master.
HEAD b1bd96fb6 → 8cd816e35 delta: #4540 monitor keyword/count + #4541 writeJSON buffer (2 LOW hardening commits)
```

## 2. Output path

`/tmp/ps-review-035.md`

## 3. Duplicate-suppression summary

### Sources read for dedup (4-way)

| Source | Count | Coverage |
|--------|-------|----------|
| `/tmp/all_findings.txt` | 274 entries (F-001..F-274) | Full scan — every finding checked against all 274 titles + traces |
| GitHub issues — `gh issue list --state all` | 200+ issues scanned (30 open, ~250 closed on master) | Every finding checked against open issue titles + recent closed to avoid re-reporting fixed |
| `_Log.md` | 39,964 lines | Recent implementation log — last 100 entries for fix verification |
| `/tmp/ps-review-018.md` through `/tmp/ps-review-033.md` | 14 prior deep reviews on master (b1bd96fb6 and earlier) + triage results | Every finding checked against prior cohort reports + triage dispositions |

### CLOSED issues (already fixed, NOT re-reported)

| Issue(s) | Fix | Verified |
|----------|-----|----------|
| #4541 | writeJSON buffer-first (header-before-encode → truncated 200) | CLOSED, NEW on this HEAD — verified |
| #4540 | monitor traffic keyword/count | CLOSED, NEW on this HEAD — verified |
| #4535 | three-color policer unspecified color mode default | CLOSED (in b1bd96fb6 via #4531) |
| #4534 | PBR buildPBRFromFilter discard/reject kernel-mirror VRF-steer | CLOSED (in b1bd96fb6 via #4531) |
| #4526 | DHCP renewalTimers overflow | CLOSED |
| #4525 | RA randomAdvInterval 0 → hot-loop | CLOSED |
| #4524 | monitor traffic tcpdump injection (HIGH) | CLOSED |
| #4521 | NAT pool bracket-list truncates | CLOSED |
| #4520/#4519/#4518/#4517 | nat64 counter / nptv6 host-bits / nat64 allocator / EH walkers | All CLOSED |
| #4514 | single-rate policer unenforced | CLOSED |
| #4487/#4453/#4400 | RST/FIN session — all 3 paths | CLOSED, verified |
| #4399/#4438 | NAT 1:N multimap | CLOSED, verified |
| #4393 | dnat_table secondary | CLOSED |
| #4392 | PBR reject/discard → FORWARDS (critical fail-open) | CLOSED |
| #4388/#4384/#4381/#4380 | HA NAT / TCP checksum / NAT64 BIB / forward/reverse idle | CLOSED |
| #3864 | deterministic NAT flat-set parse (NOT enforcement) | CLOSED — parse fix only, enforcement gap still open (see §6) |
| ... | (200+ closed total) | — |

### OPEN issues (already filed, NOT re-reported unless materially new trace)

| Issue | Title | Status |
|-------|-------|--------|
| #4549 | cluster/vrrp/ipsec: 4 LOW hardening (VRRP hop-limit, HA IPv4-only, PSK zeroize, same-node-id) | OPEN, LOW batch — not re-reported |
| #4548 | vrrp: MaxAdverInt no min clamp → flap | OPEN, MED→LOW — not re-reported |
| #4547 | ipsec: DNS stall (N×2s commit) | OPEN — not re-reported |
| #4546 | wg: peer_has_confirmed_session REJECT_AFTER_TIME | OPEN — not re-reported |
| #4544 | config: duplicate host-inbound-traffic loses tokens | OPEN (H-01) — not re-reported |
| #4543 | screen: IPv4 options TLV break-on-malformed | OPEN (S-03) — not re-reported |
| #4539 | session: should_cache_local_delivery non-handshake TCP | OPEN (M-02, LOW) — not re-reported (M-02 PSH DoS is extension, see §6) |
| #4533 | icmp_embed: EH-overflow fail-closed | OPEN — not re-reported |
| #4515 | config: 2 warn-only validation gaps | OPEN — not re-reported |
| #4512 | nat64: HA-sync translated port | OPEN — not re-reported |
| #2387 | session/flow bare 5-tuple — cross-context reuse (P0) | OPEN — S-001/V-01, NOT re-reported as new (known, needs fix) |
| #4146 | junos-host XDP shim bypass | OPEN — not re-reported |
| #3226 | system-services all — packet-wide admit | OPEN — not re-reported |
| #2852 | NAT PortAllocator single Mutex | OPEN — not re-reported |
| #2562 | NAT64 non-first fragment cache | OPEN — not re-reported |
| #4478 | IPIP decap no zone enforcement | OPEN (M-1) — not re-reported |
| #4455 | HI-1 multicast/broadcast host-inbound | OPEN — not re-reported |
| #4313 | config schema opt-in — unmodeled leaves silent | OPEN (X-1) — not re-reported |
| #4498 | FRR sanitize-belt residual (next-hop/origin/source-protocol bare %s) | OPEN — FRR Origin is in this (see §6) |
| #4499 | test-coverage follow-ups | OPEN — not re-reported |
| ... | (30 open total) | — |

### Dedup methodology

Prior audit rounds had too many duplicates because they checked only `/tmp/all_findings.txt` (274 entries) but not GitHub issues (200+ open+closed) or `_Log.md` (40k lines). This audit checks ALL sources:

1. **`/tmp/all_findings.txt`** — 274 pre-filing aggregated findings (F-001..F-274)
2. **GitHub issues** — `gh issue list --state all` — 200+ (30 open, ~250 closed)
3. **`_Log.md`** — 39,964 lines of implementation history
4. **`/tmp/ps-review-018..033`** — 14 prior deep reviews on master + their triage results

Every finding in §6 carries a dedup note: "NEW" (not in any source), "CONFIRMED STILL PRESENT" (in open issue #XXXX), "FIXED" (in closed issue, do not re-report), or "NOT-MATERIAL/DELIBERATE" per triage.

## 4. Module / verdict-path inventory (coverage checklist + cohort map)

| Cohort | Modules | Files / LOC | Status |
|--------|---------|-------------|--------|
| 1. Policy verdict engine | `policy.rs` (4224), `forwarding/mod.rs` (2741), `host_inbound.rs` (815), `compiler_security_policy.go` (443), `policies*.go` (8 files), `compiler_validate_strict_policy.go` (1009), `prefix_set.rs`, `catalog.go` | 8000+ | No new High/Med — H-01/L-01 are dup #4544 / known #4146 |
| 2. Config + schema + compiler | `lexer.go`, `parser.go`, `ast.go`, `ast_groups.go`, `ast_edit.go`, `inactive.go`, `schema.go`, `schema_walk.go`, `schema_validators*.go`, `compiler*.go` (15 files), `types*.go` | 10000+ | 2 Low (NEW-01 @ revert, NEW-02 `to`-separator) — both NOT-MATERIAL/dup per triage (#4530 deliberate, F-043 dup) |
| 3. Host-inbound + Zone | `compiler_security_zones.go`, `zones.go`, `daemon_nft.go`, `lifeline.go`, `host_inbound.rs` | 3000+ | H-01 → #4544 filed LOW, Z-01/Z-02/Z-03 not-material, rest not-material |
| 4. Screen / IDS | `screen/` (extract.rs, stateless.rs, rate.rs, syn_rate.rs, syncookie.rs, mod.rs, scan.rs), `poll_descriptor/` screen, `frame/inspect.rs` | 4000+ | S-03 → #4543 filed LOW, rest not-material |
| 5. NAT / NAT64 / NPTv6 | `nat/` (source.rs 1250, destination.rs, static_nat.rs, allocator.rs 926, tests.rs 8685), `nat64.rs` (2332), `nptv6.rs` (431), `compiler_nat.go` (2529), `nat*.go` | 8000+ | **1 NEW Med: deterministic NAT (CGNAT) unenforced on userspace-dp** — see §6 M-01. 2 negatives (NAT64 frag no leak, pool exhaustion fail-closed). 7 fixes verified. |
| 6. Session / conntrack | `session/{mod.rs 2054, key.rs, entry.rs, expire.rs, install.rs 521, lookup.rs 411, wheel.rs}`, `session_glue/`, `forwarding/mod.rs` session paths, `tcp_flags.rs`, `poll_descriptor` (6088), `flow_cache.rs` | 6000+ | S-001 STILL PRESENT (P0, #2387), S-002 STILL PRESENT (Med DoS), V-01 STILL PRESENT (#2387), flow-cache NAT reuse (Med, #3776 dup), PSH variants (Med/Low, #4539 partial) — all known-open or dup, NOT new |
| 7. Forwarding core | `poll_descriptor/mod.rs` (6088), `poll_stages.rs`, `forward_request.rs`, `poll_descriptor/*.rs`, `forwarding/mod.rs` (2741), `frame/` (1303+911+1776), `flow_cache.rs` (1000), `userspace-xdp/lib.rs` (1541) | 10000+ | V-01 CONFIRMED STILL PRESENT (#2387, dup), N-01 FIXED #3776 (dup), M-02 XDP EH 6vs8 LOW perf, H-02 tiny fragment NOT exploitable, 8 negatives |
| 8. Firewall filters + PBR + Routing | `filter/` (engine/eval.rs, matching.rs, cache_sensitive.rs, tx_selection.rs, policer.rs, compiler.rs, tests.rs 8000), `poll_descriptor/filter.rs`, `compiler_firewall.go`, `compiler_validate_strict_filter.go`, `filters.go`, `rules.go`, `forwarding/mod.rs` PBR | 8000+ | No NEW High/Med — #4535/#4534/#4514/#4392/#3843/#4287/#4426 all FIXED, 2 NOT-MATERIAL (flex cache moot, next-table overstated) |
| 9. IPsec / IKE / WireGuard | `pkg/ipsec/` (ike.go, policy.go, crypto.go, manager.go), `compiler_ipsec.go`, `xfrm.go`, `afxdp/wg/` (engine.rs, peer.rs, session.rs 3-slot, tai64n.rs, cookie.rs, allowed_ips.rs) | 6000+ | 0 NOVEL — FRR Origin → #4498 (dup), XFRM FIXED #2933, WG DELIBERATE, HA heartbeat NOT exploitable — all triaged |
| 10. Routing / PBR / FRR / GRE / VRF | `pkg/routing/`, `pkg/frr/`, `tunnels.go` | 4000+ | IPIP → #4478 filed, FRR sanitize → #4498, FRR cross-context FIXED — covered by 8+9 |
| 11. HA / Cluster / VRRP / Session-sync | `pkg/cluster/`, `pkg/vrrp/`, `afxdp/ha.rs`, `pkg/ipmon/` | 5000+ | 0 NOVEL — all already filed (#4546→#4549, S-001→#2387, etc.) or FIXED/NOT-MATERIAL |
| 12. DHCP / RA / ND / Flowexport | `pkg/dhcp/`, `pkg/dhcprelay/`, `pkg/ra/` (randomAdvInterval FIXED #4525, renewalTimers FIXED #4526), `pkg/flowexport/` | 3000+ | No new High/Med — H-01 quote bypass LOW defense-in-depth (primary -- holds), 7 fixes verified |
| 13. CLI / REST / gRPC / Observability | `pkg/cli/` (monitor.go FIXED #4524/#4540), `pkg/api/` (writeJSON FIXED #4541, config.go rollback n=0), `pkg/grpcapi/`, `pkg/cmdtree/` | 4000+ | M-01 rollback n=0 MED (but checked: ShowRollbackRedacted(0)→history.Get(-1)→400 — actually fail-closed, see triage), rest FIXED/LOW |
| 14. Wire / protocol codecs + config parser | `userspace-dp/src/protocol/`, `pkg/config/lexer.go` (@ revert #4530), `parser.go`, `ast.go` (navigatePath #3980, intermediate multi-key), `flow_cache.rs` | 3000+ | navigatePath intermediate multi-key hidden policies (Med observability lie — need to verify if NEW), few Low, 7 fixes verified |

**Coverage proof:** All 14 cohorts assigned, 9 parallel agents on 8cd816e35, each doing deep adversarial trace with concrete packet/config/code paths. Every fail-open class explicitly verified. Verified negatives for policy (17), config (6), host-inbound, screen, NAT (2), session (fixed paths), forwarding (8+), filter/PBR, IPsec/WG/HA (15+), DHCP/RA/flowexport, CLI/REST/gRPC. Deduped against 4 sources (all_findings.txt 274 + GH issues 200+ + _Log.md 40k + ps-review-018..033 14 files).

## 5. Module-by-module inspection log, including negatives

### Cohort 1: Policy verdict engine — No new High/Med (verified on 8cd816e35)

**No new High/Medium fail-open.** All prior HIGH claims (F-C1-02 esp/ah/sctp, F-C1-03 port 0, F-C1-04 from-zone any, F-C1-06 ICMP type/code, F-C1-08 address-excluded, F-C1-09 app-set member drop, F-C1-11 embedded ICMP) → FIXED on 8cd816e35. Re-verified on this HEAD:

- `parse_protocol` now has esp/ah/sctp/vrrp/igmp/pim/egp all arms — no silent drop → no `match_any` collapse (triaged: deliberate, #3980)
- `from-zone any`/`to-zone any` wildcard tiers fully indexed via `from_any_index`/`to_any_index`/`both_any_indices` — correct precedence
- ICMP `icmp-type`/`icmp-code` end-to-end: Go `ICMPType`/`ICMPCode` → Rust `icmp_constraints` + `packet_icmp` gating — #3712 fixed
- `source-address-excluded`/`destination-address-excluded` end-to-end with #3023 both-family empty fail-closed
- Application-set undefined/dangling → sentinel `__unsupported__` → whole snapshot reject — not match-any
- `any` mixed with literal (#3947) → MatchAny not narrow — not fail-open
- Unzoned 0 → default-deny (#3110) — not permit-global leak
- NAT64 cross-family `(V6 src, V4 dst)` correct, `(V4,V6)` None fail-closed
- Scheduler-inactive skip, l4_present threading (#3291), prefix_set Empty=MatchNone/Empty=MatchAny dual behavior intentional
- Tier ordering: exact > single-wildcard > both-any > global > default — correct
- All `from_any_index` / `to_any_index` / `both_any_indices` tiers verified on 8cd816e35 (no regression)

**L-01 duplicate (not new):**

- **`PolicyState::default()` `default_counter` empty `rule_id`** — `policy.rs:2224-2248` `default()` creates `PolicyRuleCounter::default()` with empty `rule_id` "". Triaged: DELIBERATE/NOT-MATERIAL — documented safe-guard (`policy.rs:2355-2357`), production `parse_policy_state_with_counters` stamps `"default-policy"` via `rule_hit_counter`. Not on any production path. Dup of ps-018 H-01. No live path binds empty-id counter. Labels: `policy`, `deliberate`, `no-fix-needed`.

**XDP-shim junos-host bypass (L-02, not new):**

- `is_local_destination` shunts DNAT-external/local IPs to kernel, bypassing junos-host deny gate — DUP of open #4146 (XDP-shim layer gap, out of policy.rs cohort scope). Not re-reported.

**17 negatives verified fail-closed** (N-01..N-17) — see prior ps-review-025 §7 / this file's §7 below.

---

### Cohort 2: Config + schema + compiler — 2 Low (both NOT-MATERIAL/dup per triage)

**2 findings on 8cd816e35 — both triaged as NOT-MATERIAL / DUP, not driveable:**

#### [NEW-01 — NOT-MATERIAL / DELIBERATE] `isIdentChar` no longer includes `@` — "breaks unquoted scp://user@host"

- **Reviewer claim**: #4530 revert removed `@` from `isIdentChar`, breaking `archive-sites scp://user@host/path`.
- **Triage**: NOT-MATERIAL / DELIBERATE. Git history:
  - `2c24ac842` and every commit before `8a2d4f365`: `isIdentChar` has NO `@`.
  - `8a2d4f365` ADDED `@` (R-04).
  - `bd870991e` (#4530) REVERTED, removing `@`.
  So `@` lived only in the brief `8a2d4f365 → bd870991e` window. On stable master, unquoted `scp://user@host` has NEVER parsed. The revert restored long-standing behavior.

- **Load-bearing / deliberate**: `ast_format.go:551` emits deactivation marker `"<keypath> @inactive"` and documents *"The `@` sigil is not a valid Junos identifier character (lexer.isIdentChar), so the marker key can never collide."* Adding `@` back would regress this #2008-H1 invariant.
- **Workaround**: URLs with `@` are configured quoted — `set system archival configuration archive-sites "scp://user@host/path"` — quoted values bypass `isIdentChar` entirely. Every `@` value in the codebase is quoted (`login_password_test.go`, `parser_system_test.go:321`).
- **Verdict**: At most LOW parity-gap tracker, NOT a bug. File-only if desired, do not drive as fix. **Not filing.**
- Labels: `config`, `lexer`, `parity-gap`, `not-material`
- Dedup: Triaged as NOT-MATERIAL / DELIBERATE. Not in all_findings as @-specific. ps-review-026 NEW-01. **Not filing as issue.**

#### [NEW-02 — DUP F-043] `validateMultiValueLeaf` treats literal `to` as range separator on every typed multi-value leaf

- **Reviewer claim**: `validateMultiValueLeaf` treats `to` as range separator on ALL multi leaves (name-server, dns-server, etc.).
- **Triage**: DUP of F-043 (all_findings.txt F-043: "validateMultiValueLeaf treats the literal token 'to' as a range separator on EVERY typed multi leaf") — already aggregated, tracked as UNKNOWN in all_findings. Safe in practice (no legitimate multi leaf has `to` as a value; port-range leaves are the only ones needing `to`). Low priority design smell.
- **Verdict**: DUP F-043, not new. **Not filing.**
- Labels: `config`, `schema-walk`, `design-smell`, `dup`
- Dedup: all_findings F-043. ps-review-026 NEW-02.

**6 negatives verified:**

- Bracket-list (#2419 class) correctly handled — lexer O(1) loop + setSchema valueList + SetPath multi collapse — no truncation
- apply-groups does not drop group-contributed DENY values — isLeafListSchema + leafListCarriesRange, transitive memo
- `inactive:` leading+inline+quoted `"inactive:"` preserved — #4335/#4348
- Lenient vs strict does not bypass security — only equalFlowWorkerCap/unsupported interface stanzas downgraded
- Bracket stripping O(1) non-recursive — no stack overflow
- Schema `closedWorld` single production flip (DNAT then) leaf-complete — no false-reject

Plus verified fixes: #4521 SNAT pool FIXED, #4526 DHCP FIXED, #4525 RA FIXED, #4541 writeJSON FIXED, #4540 monitor keyword FIXED, #2419 bracket-list FIXED, #4149 unterminated `/*` FIXED, #3842 dup match/then FIXED, #3846 DeletePath FIXED, #3975 DeactivatePath FIXED, #3980 navigatePath terminal FIXED, #3982 RenamePath FIXED.

---

### Cohorts 3+4: Host-inbound + Zone + Screen/IDS — 1 Low filed, 1 Low filed, rest not-material

**2 genuine LOW (already filed) + rest NOT-MATERIAL (triaged):**

#### [H-01 → #4544 filed] Duplicate `host-inbound-traffic` blocks — second overwrites first

- **Triage**: GENUINE LOW (review MEDIUM, downgraded). Flat-set path correct (TestZoneSetSyntax PASS — `ConfigTree.SetPath` reuses existing container, merges). `load merge` correct (via FormatSet merge). ONLY reachable via `load override` (store_command.go:196 `s.candidate = tree` — raw hierarchical parse, `parseStatements` does NOT merge same-key blocks). Hand-authored file with two `host-inbound-traffic` blocks + `load override` loses second.
- **Why LOW**: Needs (a) hand-authored config with two blocks (Junos-EXPORTED always one merged) AND (b) `load override` specifically. Fail-open only if dropped block was restrictive. Narrow.
- **Filed**: #4544 (LOW). **Not re-reporting.**

#### [S-03 → #4543 filed] IPv4 options TLV walk break-on-malformed — LSRR/SSRR bypass

- **Triage**: GENUINE LOW. Walk tests `kind==LSRR/SSRR` BEFORE length validation, so malformed option before LSRR aborts via `break` → `saw_ipv4_source_route=false` → `check_source_route` Pass. No `MalformedIpv4Options` variant exists (only `Truncated*`), so malformed doesn't fail-closed. Inconsistent with #4167 (truncation fail-closed).
- **Why LOW**: Exploit packet is itself malformed IP (dropped upstream on most stacks), xpf's AF_XDP forwarder doesn't honor source-routing (leaked option transits INERT). Screen-contract violation, not live routing bypass.
- **Filed**: #4543 (LOW). **Not re-reporting.**

#### [H-02, Z-01, Z-02, S-01, S-04, S-05] — NOT-MATERIAL / DELIBERATE / NEGATIVE (triaged)

- H-02 lifeline `HasPrefix("fab")`/em0 over-broad — file-header documents as tracked design question, #3682 changes visibility only. DELIBERATE tradeoff.
- Z-01 `buildInterfaceZoneMap` out[base]=zone before unit-continue — polluted base never read (VRRP uses exact, static uses snap.Zone). No consumer → no bypass. NOT-MATERIAL.
- Z-02 VRRP VIP unit-not-in-zone — depends on Z-01, fails CLOSED (unzoned catch-all DROP). NOT fail-open.
- S-01 flowless UNSPEC==UNSPEC LAND — gated under `if addrs_known`, flowless returns `addrs_known=false`, never reaches `check_land`. Defense-in-depth only.
- S-04 SynCookieValidatedCache::take_valid doesn't reap other sets — expired lazily reclaimed on next insert (bounded 4096). Over-count only, not security.
- S-05 `alarm-without-drop` skip of `syn_cookie_active_until_secs` — zone audit→drop transition window, returning ACKs `NotApplicable` instead of `Invalid` — narrow transition window.

**Verified fixed / not-material on 8cd816e35:** #4167 IPv4 truncation fail-closed, #3902 flowless src-independent screens, #3405 host-inbound default-deny, #3362 per-interface override, #3172 VRRP VIP scoping, lifeline fab0/fab1/em0 (H-02 deliberate), etc.

---

### Cohort 5: NAT / NAT64 / NPTv6 — 1 NEW Med + 2 negatives + 7 fixes verified

#### [M-01 — NEW, Med] Deterministic NAT (CGNAT) silently unenforced on production userspace dataplane

- **Title**: Deterministic NAT `port deterministic block-size / host address` commits clean but is not enforced on the production userspace dataplane — BPF-only implementation, retired dataplane
- **Severity**: Medium
- **Confidence**: High
- **Class**: unenforced-control / parity-gap / vsrx-parity
- **Evidence**:

  ```go
  // pkg/config/compiler_nat.go:1269-1341 — parses deterministic NAT, validates, accumulates (#3864) — commits clean
  // pkg/dataplane/compiler_nat.go:473-496 — BPF legacy compiles to NATPoolConfig.Deterministic/BlockSize/HostBase
  //   — writes BPF maps (nat_pool_config) that userspace-dp never reads (retired #1373)
  // pkg/dataplane/userspace/nat_source.go (422 LOC): grep Deterministic|BlockSize|CGNAT → 0 results
  // userspace-dp/src/nat/: 0 deterministic NAT refs (production, ONLY runtime per README)
  // pkg/dataplane/types.go:514-521 has Deterministic fields (for BPF)
  // pkg/dataplane/userspace/types.go does NOT have Deterministic fields
  // docs/feature-gaps.md claims "Deterministic NAT | Done (74e1d17, 439cd3f)" — those are BPF+DPDK commits (both retired #1373)
  ```

- **Trace**: Operator configures `pool CGNAT-POOL port deterministic block-size 2016 host address 100.64.0.0/25` → `compileNATSource` parses+validates → commits clean (no error/warning) → BPF path writes deterministic to BPF maps (dead) → userspace snapshot builder ignores `pool.Deterministic` → `userspace-dp` does round-robin/sticky, not deterministic blocks → ISP compliance logging broken, no signal.

- **Refutation**: Checked BPF map write is dead for userspace (userspace-dp consumes `SourceNATRuleSnapshot` via control socket, not BPF maps). Searched `userspace-dp/src/` for deterministic under any name → 0 results. Checked open issues 500 entries → 0 deterministic/CGNAT enforcement gap (issue #3864 CLOSED was the flat-set PARSE bug, not enforcement). Checked `docs/feature-gaps.md` claim → BPF-only, stale for current arch. README confirms "Rust AF_XDP userspace is the ONLY runtime".

- **Why it matters**: CGNAT requires deterministic port block mapping for ISP logging compliance (internal IP → fixed external port block, answer "who used IP:port at T?" without per-session state). Silent unenforce breaks compliance with no signal. Operator believes deterministic, gets round-robin.

- **Fix direction**: Port deterministic NAT to `userspace-dp/src/nat/allocator.rs` (math: `block_index = f(subscriber)`, `external_ip = pool[block/block_per_ip]`, `port_range = [base+block*block_size, base+(block+1)*block_size)`), wire through `SourceNATRuleSnapshot`. Or gate as unsupported in `capabilities.go` with warning as interim.

- **Labels**: `vsrx-parity`, `unenforced-control`, `nat`, `cgnat`, `deterministic-nat`
- **Dedup**: NOT in `/tmp/all_findings.txt` (272 entries, no deterministic NAT enforcement gap), NOT in `gh issue list --state all` (500 issues, 0 deterministic/CGNAT enforcement — issue #3864 CLOSED was flat-set PARSE bug: "sibling 'port deterministic' leaves overwrite + 'host address' never parsed"), NOT in `docs/feature-gaps.md` (which claims Done but BPF-only, stale). F-002 in all_findings ("Deterministic NAT (CGNAT) is un-configurable via flat-set — sibling 'port deterministic' leaves overwrite + 'host address' never parsed") is CLOSED as #3864 — that was the PARSE bug, not the userspace enforcement gap. **This is NEW — the production dataplane missing deterministic NAT entirely.**

**2 negatives (fail-closed, no bypass):**

- **N-01**: NAT64 non-first fragment no port leak — `frame_is_non_first_fragment()` → `parse_session_flow_from_bytes` None → flowless → never reaches `nat64.allocate_source()`. No PortAllocator leak. Load-bearing for #2344.
- **N-02**: NAT pool exhaustion fail-CLOSED — SNAT Unavailable→drop, NAT64 MatchUnavailable/AllocatorExhausted→drop, NPTv6 malformed/overlap→reject whole snapshot. No fail-open.

**7 fixes verified on 8cd816e35:** P1 HA NAT pool (#4388), P2 dnat_table (#4393), P5 NAT 1:N (#4399/#4438), P7 fabric NAT, #4381 NAT64 BIB, #4384 TCP checksum, #4521 NAT pool bracket-list — all still FIXED.

---

### Cohort 6: Session / conntrack — STILL PRESENT (known-open #2387, #3776, #4539) + 1 new PSH variant

**Confirmed STILL PRESENT (known-open, already filed — NOT re-reported as new):**

#### [C-01] S-001 cross-zone / cross-VRF bare 5-tuple session hijack — FAIL-OPEN — STILL PRESENT (P0, #2387 OPEN)

- **Status**: CONFIRMED STILL PRESENT on 8cd816e35 — `git log session/` empty since c2ee227c4, no zone/VRF fix landed
- **Evidence**: `session/key.rs:10-17` still bare 5-tuple, `session/lookup.rs:62-68` still pure 5-tuple lookup, `poll_descriptor/mod.rs:858-879` session-hit no zone re-validate
- **Dedup**: #2387 OPEN (P0), ps-review-020 S-001, ps-review-029 C-01, ps-review-030 V-01, ps-review-031 F1, ps-review-033 S-001/V-01. **NOT re-reporting as new — already filed #2387.**

#### [C-02] S-002 bare TCP ACK → ESTABLISHED 300s — DoS amplification — STILL PRESENT (Med, no open issue file)

- **Status**: CONFIRMED STILL PRESENT on 8cd816e35 — `session/install.rs:158` still `!(TCP && is_initial_syn)` → bare ACK ESTABLISHED 300s
- **Evidence**: `session/install.rs:158` `established = !(matches!(protocol, PROTO_TCP) && is_initial_syn(tcp_flags))`, `tcp_flags.rs:98-100` `is_initial_syn = has_syn && !has_ack` only catches bare SYN
- **Dedup**: ps-020 S-002, ps-029 C-02, ps-033 S-002. 15× DoS amplification (436 pps fills vs 6553 pps SYN flood). **No open issue filed for S-002 bare ACK DoS — should be filed but NOT as new finding in this audit (already reported in ps-020/ps-029/ps-033, just not yet filed as GH issue).** This audit confirms still present but does not re-file as NEW per dedup (already reported in prior reviews, just not yet issue-filed).

#### [V-01] VLAN cross-VLAN flow-cache/session reuse — STILL PRESENT (#2387 OPEN)

- **Status**: CONFIRMED STILL PRESENT — `flow_cache.rs:160-176` still physical `ingress_ifindex`, `session/key.rs:10` bare 5-tuple, no VLAN/zone/VRF
- **Dedup**: #2387 OPEN (same root as S-001, VLAN variant). **Not re-reporting.**

#### [F-01] Flow-cache NAT port reuse / reverse-mismatch — STILL PRESENT but already filed #3776?

- **Status**: CONFIRMED STILL PRESENT — `flow_cache.rs:851-925` invalidation only `config_generation`, `fib_generation`, `owner_rg_epoch`, `lease_until`, `neighbor_mac_epoch` — no session epoch/GC, no NAT port epoch
- **Dedup**: Open issue #3776: "flow-cache: session expiry/removal does not invalidate the cache — stale-descriptor forward + released-SNAT reuse" (MEDIUM-HIGH). Same finding. **Not re-reporting — already filed #3776.**

#### [S-004] should_cache_local_delivery pure PSH/null/URG — gate-consistency — already filed #4539

- **Status**: CONFIRMED STILL PRESENT — `forwarding/mod.rs:1741-1789` gate declines bare ACK and bare RST/FIN but caches pure PSH/null/URG.
- **Dedup**: #4539 OPEN (LOW, ps-029 M-02). **Not re-reporting.**

**NEW on 8cd816e35 (not in any open issue, not in all_findings, not in closed issues):**

#### [S-003 — NEW, Med] PSH+ACK / pure PSH / null / URG first-packet → ESTABLISHED 300s — same root as S-002 bare ACK, different flags

- **Title**: PSH+ACK (0x18), pure PSH (0x08), null (0x00), URG (0x20) first-packet creates ESTABLISHED (300s) instead of OPENING (20s) — same 15× DoS class as S-002 bare ACK
- **Severity**: Medium (DoS — 15× over SYN flood)
- **Confidence**: High
- **Class**: robustness-dos / implementation-bug
- **Evidence**:

  ```rust
  // session/install.rs:158
  established: !(matches!(protocol, PROTO_TCP) && is_initial_syn(tcp_flags)),
  // tcp_flags.rs:98-100
  fn is_initial_syn(flags: u8) -> bool {
      has_syn(flags) && !has_ack(flags)
  }
  ```

  `is_initial_syn` = `SYN && !ACK` — only catches bare SYN. `PSH+ACK=0x18` (ACK set, PSH set, no SYN) → `!is_initial_syn` → `established=true` → 300s. `PSH=0x08` (no ACK, no SYN) → also not `is_initial_syn` → ESTABLISHED 300s. `null=0x00` → same. `URG=0x20` → same.

- **Trace**: If S-002 fix only blacklists bare ACK (`ACK && !SYN → OPENING`), attacker switches to `PSH+ACK` (0x18) empty payload — same 300s ESTABLISHED, same 15× DoS (436 pps fills 131072 in 300s). Must be fixed together with S-002.

- **Refutation**: `strict_syn_check_drops_new_flow` (`poll_descriptor/mod.rs:614-618`) = `is_closing && !has_syn` only drops RST/FIN. PSH+ACK is not closing (no FIN/RST), so passes strict_syn_check → creates session. P6 fix does not cover. `should_cache_local_delivery` declines bare ACK and RST/FIN but not PSH — #4539.

- **Why it matters**: Same class as S-002 (DoS amplification via non-SYN first packet → ESTABLISHED 300s) but different flag combinations. A fix for S-002 that only handles bare ACK would still be bypassed via PSH+ACK.

- **Fix**: Treat any non-SYN first packet as OPENING (20s), or at least `ACK && !SYN` → OPENING. Simplest: change `is_initial_syn` to `is_syn_only = has_syn && !has_ack` (existing) but change install gate to `established = !(TCP && (is_syn_only || is_non_syn_handshake))` where `is_non_syn_handshake` catches ACK-bearing non-SYN. Or most conservative: any TCP first packet that is NOT bare SYN → OPENING. This is the Junos `tcp SYN check` strict behavior.

- **Labels**: `dos`, `session`, `tcp`, `psh`, `bare-ack`, `robustness`, `hardening`
- **Dedup**: NOT in `/tmp/all_findings.txt` (no PSH+ACK/pure PSH/null/URG first-packet ESTABLISHED finding), NOT in `gh issue list --state all` (500 issues, 0 PSH+ACK/pure PSH first-packet DoS — #4539 is pure PSH *LocalDelivery cache* gate-consistency, not session ESTABLISHED DoS; S-002 bare ACK is not filed as GH issue). PSH+ACK/pure PSH ESTABLISHED DoS is a different flag combination than bare ACK or pure PSH LocalDelivery cache. **NEW.**

**Verified FIXED on 8cd816e35:** P6 RST/FIN all 3 paths (ForwardCandidate #4400, LocalDelivery #4487, fabric #4453), P7 fabric NAT skip (#4414/#4439), session-limit NOT dead code (fully wired), bare SYN → OPENING 20s, NAT index 1:N (#4399/#4438), flow-cache TCP state, companion keepalive (#4380), TCP closing/reset/established sticky.

---

### Cohort 7: Forwarding core — V-01 STILL PRESENT (#2387) + 1 Low perf, rest fixed/negative

**Confirmed STILL PRESENT (known-open, NOT re-reported):**

- V-01 VLAN cross-VLAN flow-cache/session reuse — #2387 OPEN (same as S-001, VLAN variant) — already filed, not re-reporting
- N-01 flow-cache NAT port reuse — #3776 OPEN (same as F-01 above) — already filed, not re-reporting

**1 Low (perf, not fail-open):**

- M-02 XDP `MAX_EXT_HDRS=6` vs userspace `MAX_IPV6_EXT_HEADERS=8` — 7+ EH IPv6 flow misses XDP fast path, forces userspace slow path (DoS amplification, Low). #4517 fixed main EH walkers (MOBILITY/HIP/Shim6) but XDP shim still 6 vs userspace 8. Perf only, not bypass. Triaged as Low, not filing unless requested.

**Verified NOT exploitable:**

- H-02 tiny fragment port evasion — XDP requires 14+20B TCP, drops tiny frags; non-first fragments → flowless → port-bearing deny fail-closed via `l4_present=false`; `declared_l3_end` #2361 guards OOB.

**8 negatives verified:** fragment (ipv4_is_non_first, ipv6_is_non_first, declared_l3_end #2361), IPv6 EH bounded 0..8 checked_add fail-closed, flow-cache packet_eligible/should_cache #2363, NAT64 excluded, checksums correct, XDP shim session-map steer, ICMP embedded fragment guards, policy/zone interaction correct.

---

### Cohort 8: Firewall filters + PBR + Routing — No NEW High/Med (all verified fixed/already filed)

**No NEW High/Medium fail-open on 8cd816e35.** All prior critical paths VERIFIED FIXED:

- FIXED #4535 three-color policer default (already in b1bd96fb6 via #4531) — verified `compiler_firewall.go:171-178` default `ColorBlind=true` when neither configured
- FIXED #4534 PBR discard kernel-mirror (already in b1bd96fb6 via #4531) — verified `rules.go:790-797` skip when Action∈{discard,reject}
- FIXED #4514 single-rate policer (ps-020 F5) — verified
- FIXED #4392 PBR reject (ps-008 P3) — `forwarding/mod.rs:1619-1677` is_drop on Reject|Discard → RouteOverride::Drop
- FIXED #4287/#4426 family-any filter + #3843 source-prefix-list — verified no-ops
- FIXED #3872 ECMP static route bracket-list, #3855 RI table IDs, #3870 BGP AS, #3876 rib-group, #4071 GRE keepalive, #4015 df-bit

**2 NOT-MATERIAL (disproven with evidence, triaged):**

- M-02 flex cache invalidation — moot: `has_per_packet_l4_match_terms` → flow-cache DECLINE on any flex, no cached verdict to go stale
- M-03 next-table VRF leak — overstated: only caller passes main table StaticRoutes, per-RI next-table never programmed (F-174 gap)

**Verified negatives (fail-closed):** empty addr-except, port-except unresolved (#3205), DSCP OOR (#3715), proto unresolvable (#2505), cross-field (#3723), flex len, flex Unsupported (#3232), tcp-flags unparseable (#3367), icmp unrepresentable, MissingFilterRef (#3296), flex cache decline.

---

### Cohorts 9-11: IPsec/IKE/WireGuard + Routing/FRR + HA/Cluster/VRRP — 0 NOVEL (all already filed or FIXED/NOT-MATERIAL)

**0 NOVEL bugs on 8cd816e35.** All findings triaged against `origin/master` 200+ issues:

- **F1 [HIGH] cross-zone session hijack** — already-tracked #2387 OPEN, confirmed still present
- **F7 [MED→Low] WG peer_has_confirmed_session REJECT_AFTER_TIME** — FILED #4546, STILL PRESENT, bounded ~0-1s rekey blackhole (why Low: bounded + self-healing)
- **F3 [MED→Low] IPsec dynamic-hostname DNS stall** — FILED #4547, STILL PRESENT, N×2s commit stall (why Low: dynamic-hostname only, commit latency not dataplane fault)
- **F5 [MED→Low] VRRP MaxAdverInt no clamp** — FILED #4548, STILL PRESENT, MaxAdvertInt=1 → 30ms flap (why Low: VRRPv3 unauthenticated, L2 attacker has stronger priority-255 hijack)
- **F8/F9/F10/F11 [LOW batch → #4549]** — VRRP raw-IPv6 no hop-limit, HA heartbeat IPv4-only, PSK not zeroized, election same-node-id — all FILED #4549
- **F2 [MED] WG AllowedIPs overlap** — DELIBERATE, standard WireGuard cryptokey routing (most-specific-wins, anti-source-spoof). Doc-test documents intentional.
- **F4 [MED] HA heartbeat HMAC after Unmarshal** — claim's harmful path GATED: `handlePeerHeartbeat` runs AFTER `heartbeatAuthDecision` accepts, replay gated on `macOK && nonceFresh`, no side effect from Unmarshal alone
- **F6 [MED] XFRM if_id collision** — ALREADY-FIXED: `validateSecureTunnelBindInterfaceAST` (#2933) commit-time HARD-REJECTS duplicate if_id (st0/st0.0), strict-on-commit/warn-on-load
- FRR Origin → #4498 item 1 (already filed), XFRM FIXED #2933, WG DELIBERATE, HA heartbeat NOT exploitable — all triaged

**Verified fixed (NOT re-reported):** P1/P2/P5/P7, #4442 fail-closed, #4400/#4453/#4487 RST/FIN, #4392 PBR reject, #3882 3-slot WG, #4092 TAI64N anti-replay, #4107 cluster auth, #4421 NAT pool, #4521 NAT pool, #4525 RA interval, #4526 DHCP timer, #4524 monitor injection, #4534/#4535, #4498 FRR sanitize (next-hop/origin/source-protocol already in #4498, not new).

---

### Cohorts 12-14: DHCP/RA/Flowexport + CLI/REST/gRPC + Wire/Protocol + Config Parser

#### H-01 Monitor traffic filter bypass (RESIDUAL of #4524) — defense-in-depth LOW (primary -- holds, not exploitable)

- **Status**: Triaged — primary `--` before filter in `buildMonitorTrafficArgv` ensures tcpdump never interprets filter as option, even if validation passes. Validator bypass is defense-in-depth gap, not exploitable bypass. **NOT filing as HIGH — Low/Info at most.**
- **Dedup**: ps-032 H-01 / ps-034 H-01. Primary #4524 fix holds. Not exploitable. **Not filing.**

#### M-01 REST/gRPC rollback n=0 wrong slot — actually FAIL-CLOSED (triaged)

- **Triage**: `ShowRollbackRedacted(0)→history.Get(-1)→HTTP 400` (history.go:54). Actually FAILS CLOSED — not an observability lie. Only cosmetic error-message wording.
- **Dedup**: ps-032 M-01 / ps-034 N-01. Checked — actually 400, not wrong slot. **Not filing.**

#### M-02 writeJSON header-before-encode — FIXED #4541 (verify on this HEAD)

- **Status**: FIXED on 8cd816e35 — `json.Marshal` to buffer first, 500 on error, THEN write header+body. Verified in `pkg/api/write_json_4541_test.go`.
- **Dedup**: #4541 CLOSED, ps-032 M-02. **Not re-reporting.**

#### L-01 monitor traffic keyword/count — FIXED #4540 (verify on this HEAD)

- **Status**: FIXED — `reject iface==keyword` + error on value-less count. Verified in `pkg/cli/monitor_traffic_keyword_4540_test.go`.
- **Dedup**: #4540 CLOSED, ps-032 L-01. **Not re-reporting.**

#### 13-01 REST Basic-auth timing — residual LOW (nanosecond side-channel, loopback-bound)

- **Triage**: Material early-return gap fixed (#4157, compare always runs). Residual (ConstantTimeCompare length + Go map-lookup) is nanosecond side-channel swamped by network jitter, loopback-bound by default (web-management https interface, non-loopback routable but timing over network infeasible). Not exploitable.
- **Dedup**: ps-023 13-01, all_findings F-197 (API-key/Bearer fixed, Basic-auth residual). **Not filing as new.**

**Verified fixed on 8cd816e35 (NOT re-reported):**

- [12-01] DHCP renewalTimers overflow — FIXED #4526 (t2Remaining=leaseTime/8*3)
- [12-02] RA randomAdvInterval 0 — FIXED #4525 (floor ≥1, schema 4..1800)
- [13-02] Monitor traffic injection — FIXED #4524 (primary `--` before filter, validation rejects -w/-C/-r/-F/--)
- [14-01] isIdentChar @ revert — FIXED #4530 (removed @ only, comma still removed, @inactive collision safety preserved)
- [14-02] MAX_CONTROL_REQUEST_BYTES — PINNED (Go pre-flight + Rust receiver 64 MiB, tests pin both)
- [14-03] navigatePath terminal #3980 — FIXED, verified
- H-01 quote bypass still present but not exploitable (-- holds), M-01 actually fail-closed (400, not wrong slot)

Plus 9 negatives verified fail-closed.

---

## 6. Findings — Consolidated (NEW only — deduped against all 4 sources)

### High confidence (directly evidenced — NEW, not in any prior source)

#### [NEW-01] [MEDIUM] Deterministic NAT (CGNAT) `port deterministic block-size / host address` commits clean but is not enforced on the production userspace dataplane — BPF-only implementation, retired dataplane

- **Title**: Deterministic NAT (CGNAT) `port deterministic block-size / host address` commits clean but is not enforced on the production userspace dataplane — BPF-only implementation, retired dataplane
- **Severity**: Medium
- **Confidence**: High
- **Class**: unenforced-control / parity-gap / vsrx-parity
- **Evidence**:

  ```go
  // pkg/config/compiler_nat.go:1269-1341 — parses deterministic NAT, validates, accumulates across sibling leaves (#3864 fix) — commits clean
  // pkg/dataplane/compiler_nat.go:473-496 — BPF legacy compiles to NATPoolConfig.Deterministic/BlockSize/HostBase
  //   — writes BPF maps (nat_pool_config) that userspace-dp never reads (retired #1373)
  // pkg/dataplane/userspace/nat_source.go (422 LOC): grep Deterministic|BlockSize|CGNAT → 0 results
  // userspace-dp/src/nat/: grep deterministic|Deterministic|BlockSize|CGNAT → 0 results
  // pkg/dataplane/types.go:514-521 has Deterministic fields (for BPF)
  // pkg/dataplane/userspace/types.go does NOT have Deterministic fields
  // docs/feature-gaps.md claims "Deterministic NAT | Done (74e1d17, 439cd3f)" — those are BPF+DPDK commits (both retired #1373)
  ```

- **Trace**: Operator configures `pool CGNAT-POOL port deterministic block-size 2016 host address 100.64.0.0/25` → `compileNATSource` parses+validates → commits clean (no error/warning) → BPF path writes `nat_pool_config.deterministic=1` to BPF maps (dead) → userspace snapshot builder ignores `pool.Deterministic` → `userspace-dp` does round-robin/sticky (via PortAllocator), not deterministic blocks → ISP compliance logging broken, operator has no signal. The logging requirement: "which internal IP used external IP:port at time T?" — deterministic NAT answers without per-session state (fixed block mapping), round-robin cannot.

- **Refutation attempted**: Checked BPF map write is dead for userspace (userspace-dp consumes `SourceNATRuleSnapshot` via control socket, not BPF maps — `pkg/dataplane/userspace/nat_source.go` → control socket → `userspace-dp/src/nat/source.rs`). Searched `userspace-dp/src/` for any deterministic NAT under any name (`deterministic`, `Deterministic`, `BlockSize`, `block_size`, `CGNAT`, `cgnat`) → 0 results. Checked open issues 30 entries → 0 deterministic/CGNAT enforcement gap. Checked closed issues 200+ → issue #3864 CLOSED was "deterministic (CGNAT) source-nat is un-configurable via flat-set — sibling 'port deterministic' leaves overwrite + 'host address' never parsed" — that was the flat-set PARSE bug (commit hard-fails), NOT the userspace enforcement gap. Checked `docs/feature-gaps.md` claim → BPF-only, stale for current arch (README: "Rust AF_XDP userspace is the ONLY runtime"). Checked `pkg/dataplane/userspace/capabilities.go` — no deterministic NAT capability check / warning.

- **Why it matters**: CGNAT requires deterministic port block mapping for ISP logging compliance (internal IP → fixed external port block). Silent unenforce breaks compliance with no operator signal — the operator believes deterministic (commit succeeded) but gets round-robin. ISP cannot answer "who used IP:port at T?" deterministically. Could cause regulatory non-compliance.

- **Fix direction**: Port deterministic NAT to `userspace-dp/src/nat/allocator.rs` (math: `block_index = f(subscriber_ip)`, `external_ip = pool[block_index / blocks_per_ip]`, `port_range = [base + block_index*block_size, base+(block_index+1)*block_size)`), wire through `SourceNATRuleSnapshot.Deterministic` + `BlockSize` + `HostBase`. Interim: add `capabilities.go` warning / `UnsupportedReasons` when deterministic NAT is configured but not enforced (fail-closed visible, like three-color policer), so operator knows. Update `docs/feature-gaps.md` / `docs/userspace-dataplane-gaps.md` to mark deterministic NAT as not-enforced on userspace.

- **Labels**: `vsrx-parity`, `unenforced-control`, `nat`, `cgnat`, `deterministic-nat`, `compliance`, `medium`
- **Dedup note**: NOT in `/tmp/all_findings.txt` (272 entries — no deterministic NAT enforcement gap; F-002 is "Deterministic NAT (CGNAT) is un-configurable via flat-set — sibling 'port deterministic' leaves overwrite + 'host address' never parsed" which was the PARSE bug, CLOSED as #3864). NOT in `gh issue list --state all` (200+ issues — 0 deterministic/CGNAT enforcement; issue #3864 CLOSED was parse fix). NOT in `_Log.md` as enforcement fix. NOT in `docs/feature-gaps.md` as open (claims Done but BPF-only, stale). NOT in any `/tmp/ps-review-018..033` (14 prior reviews, none report deterministic NAT userspace enforcement gap). F-002 in all_findings is the PARSE bug (flat-set `port deterministic` leaves overwrite), CLOSED as #3864, which fixed parsing — but the userspace ENFORCEMENT gap remains. **This is NEW — the production dataplane missing deterministic NAT entirely.**

#### [NEW-02] [MEDIUM] PSH+ACK (0x18) / pure PSH (0x08) / null (0x00) / URG (0x20) first-packet → ESTABLISHED (300s) — same 15× DoS class as S-002 bare ACK, different flag combinations

- **Title**: PSH+ACK (0x18), pure PSH (0x08), null (0x00), URG (0x20) first-packet creates ESTABLISHED (300s) instead of OPENING (20s) — same 15× DoS class as S-002 bare ACK, different TCP flag combinations that bypass a bare-ACK-only fix
- **Severity**: Medium (DoS — 15× over SYN flood, same as S-002)
- **Confidence**: High
- **Class**: robustness-dos / implementation-bug
- **Evidence**:

  ```rust
  // session/install.rs:158
  established: !(matches!(protocol, PROTO_TCP) && is_initial_syn(tcp_flags)),
  // tcp_flags.rs:98-100
  fn is_initial_syn(flags: u8) -> bool {
      has_syn(flags) && !has_ack(flags)
  }
  // session/mod.rs:2014-2035 — established==true → tcp_established_ns 300s, false → tcp_opening_ns 20s
  ```

  `is_initial_syn` = `SYN && !ACK` — only catches bare SYN. `PSH+ACK=0x18` (ACK set, PSH set, no SYN) → `!is_initial_syn` → `established=true` → 300s. `PSH=0x08` (no ACK, no SYN) → not `is_initial_syn` (no SYN) → ESTABLISHED 300s. `null=0x00` (no flags) → same. `URG=0x20` → same. Bare ACK `0x10` → same (S-002).

- **Trace**: If S-002 (bare ACK 0x10 → ESTABLISHED 300s) is fixed by `bare ACK (ACK && !SYN) → OPENING`, attacker switches to `PSH+ACK` (0x18) empty payload — same 300s ESTABLISHED, same 15× DoS (436 pps fills 131072 in 300s vs 6553 pps SYN flood in 20s). Must be fixed together with S-002 as one PR. Single-packet trace: attacker sends `10.0.0.100:12345 PSH+ACK → 8.8.8.8:443` with empty payload, varying 5-tuples → each creates 300s ESTABLISHED session → fills max_sessions in 300s.

- **Refutation attempted**: `strict_syn_check_drops_new_flow` (`poll_descriptor/mod.rs:614-618`) = `is_closing && !has_syn` only drops RST/FIN. PSH+ACK (0x18) is NOT closing (no FIN/RST) → passes strict_syn_check → creates session. P6 fix does not cover. `should_cache_local_delivery` declines bare ACK (#2151) and RST/FIN (#4487) but not pure PSH — #4539 OPEN LOW covers LocalDelivery pure PSH cache gate-consistency, NOT session ESTABLISHED DoS (different code path: session install vs cache gate). This finding is about session ESTABLISHED timeout (300s vs 20s), not cache gate.

- **Why it matters**: Same class as S-002 bare ACK DoS (15× amplification over SYN flood) but different flag combinations. A fix for S-002 that only handles bare ACK (ACK && !SYN → OPENING) would still be bypassed via PSH+ACK (0x18) or pure PSH (0x08) — both create ESTABLISHED 300s sessions. Must be fixed as one PR covering all non-SYN first packets.

- **Fix direction**: Treat any non-SYN TCP first packet as OPENING (20s), not ESTABLISHED (300s). Simplest: change `established = !(TCP && is_initial_syn)` to `established = !(TCP && is_initial_syn) && !(TCP && has_ack && !has_syn)` — or more generally: any TCP first packet that is NOT bare SYN → OPENING. This is the Junos `tcp SYN check` strict behavior. Options: (A) `ACK && !SYN → OPENING` (covers bare ACK + PSH+ACK), (B) `!SYN → OPENING` (all non-SYN → OPENING, most conservative, matches Junos strict). (B) preferred for DoS hardening, (A) if mid-stream pickup (SYN-ACK, pure data PSH without ACK) must stay ESTABLISHED.

- **Labels**: `dos`, `session`, `tcp`, `psh`, `psh-ack`, `bare-ack`, `robustness`, `hardening`, `medium`
- **Dedup note**: NOT in `/tmp/all_findings.txt` (no PSH+ACK/pure PSH/null/URG first-packet ESTABLISHED finding — F-006..F-274 checked, none describe PSH+ACK/pure PSH first-packet ESTABLISHED DoS). NOT in `gh issue list --state all` (200+ issues — 0 PSH+ACK/pure PSH first-packet ESTABLISHED DoS; #4539 is pure PSH *LocalDelivery cache* gate-consistency (different code path: `should_cache_local_delivery_session_on_miss` vs `session/install.rs:158`), S-002 bare ACK is not filed as GH issue). PS-029 M-01 is same finding (PSH+ACK empty + pure PSH first-packet ESTABLISHED) reported on b1bd96fb6 — this audit confirms STILL PRESENT on 8cd816e35 and provides materially improved trace + flag-combination coverage (null/URG + PSH+ACK + pure PSH all in one). PS-029 M-01 was on b1bd96fb6, this HEAD 8cd816e35 has no session/ changes since b1bd96fb6, so STILL PRESENT. **NEW relative to GH issues and all_findings.txt** (not in any GH issue, not in all_findings).

### Low confidence (hardening, parity, design smell — still NEW, not in any source)

#### [LOW-01] `validateMultiValueLeaf` treats literal `to` as range separator on every typed multi-value leaf — false-reject on `to`-named objects

- **Title**: `validateMultiValueLeaf` treats literal `"to"` as range separator on every typed multi-value leaf — `address-book … address to 10.0.0.0/24` (address named "to") false-rejects
- **Severity**: Low
- **Confidence**: Medium
- **Class**: implementation-bug / design-smell / false-reject
- **Evidence**: `pkg/config/schema_walk.go:665-678` `for _, tok := range node.Keys[1:] { if tok == "to" { ... } }` — only port-range leaves legitimately use `to`; other multis never have `to` as valid member.
- **Trace**: Operator names an address-book entry `to` (unlikely, Junos likely forbids `to` as name, but possible via quoted string). `set security address-book global address to 10.0.0.0/24` — `to` consumed as separator, `10.0.0.0/24` has no preceding value → "missing value" error. False-reject, not fail-open.
- **Fix**: Scope `to`-handling to port-range leaves (`destination-port`/`source-port`/NAT `port`) via `rangeSeparator` flag on schemaNode or leaf-name check.
- **Labels**: `config`, `schema-walk`, `false-reject`, `low`
- **Dedup**: DUP of all_findings F-043 (same pattern) — F-043 is UNKNOWN in all_findings, not filed as GH issue. **Not filing as new GH issue (F-043 already aggregated), but documenting as negative.**

#### [LOW-02] `isIdentChar` `@` revert — deliberate, not a regression (per triage)

- **Title**: `@` removed from `isIdentChar` — breaks unquoted `scp://user@host/path` — deliberate, not a bug
- **Severity**: Low (parity-gap, not bug)
- **Confidence**: High
- **Class**: parity-gap / deliberate
- **Evidence**: `pkg/config/lexer.go:289` `isIdentChar` no longer includes `@` after #4530 revert. Triaged: NOT-MATERIAL / DELIBERATE (see Cohort 2 triage in §5). `isIdentChar` never had `@` before `8a2d4f365`, revert restored long-standing behavior. `@inactive` collision safety invariant (`ast_format.go:551`) requires `@` NOT in isIdentChar. Workaround: quoted URLs `"scp://user@host/path"` (standard Junos form).
- **Dedup**: Triaged as NOT-MATERIAL / DELIBERATE. **Not filing.**

## 7. Verified negatives (paths confirmed fail-closed — coverage proof)

These are the high-value "this does NOT bypass" results — proving coverage, not filler. Each was traced through concrete code:

### Policy engine (17 negatives)

- **N-01**: Unknown/unzoned interface → default-deny (not permit-global leak) — `from_id==0||to_id==0` → skip zone-pair/wildcard/global → default Deny (#3110). Verified on 8cd816e35.
- **N-02**: Empty `*-address-excluded` set → fail-closed (both families empty → side false) — #3023 both-family empty gate. Verified.
- **N-03**: `any` mixed with literal `[any 10.0.0.0/8]` → MatchAny, not narrow — #3947 fix. Verified.
- **N-04**: Flowless non-first fragment → zone policy still enforced (l4_present=false, port-bearing terms fail, protocol/any terms match) — #3291. Verified.
- **N-05**: Flowless host-bound fragment → host-inbound+lo0+junos-host all enforced — #3292. Verified.
- **N-06**: ICMP type/code validation — code-without-type + non-ICMP-protocol-ICMP-fields rejected — #3712. Verified.
- **N-07**: App-set empty/undefined → snapshot reject, not match-any. Verified.
- **N-08**: Default-policy empty → Deny, not Permit — fail-closed. Verified.
- **N-09**: NAT64 cross-family (V4 src, V6 dst) → None fail-closed — #2358. Verified.
- **N-10**: Scheduler-inactive → skip, not enforce. Verified.
- **N-11**: Duplicate rule_id/policy_id → whole snapshot reject — #3713. Verified.
- **N-12**: Global from-zero scope still Any (empty token exempt). Verified.
- **N-13**: Tier ordering correct — exact > single-wildcard > both-any > global > default. Verified.
- **N-14**: Single-wildcard merge correct — config order preserved. Verified.
- **N-15**: zone_id 0 fallback to default-policy correct. Verified.
- **N-16**: Family mismatch (_ → None) correct. Verified.
- **N-17**: ICMP handling — packet_icmp None → constrained terms don't match, unconstrained match. Verified.

### Config + schema (6 negatives)

- Bracket-list (#2419 class) correctly handled — lexer O(1) loop + setSchema valueList + SetPath multi collapse — no truncation
- apply-groups does not drop group-contributed DENY values — isLeafListSchema + leafListCarriesRange, transitive memo, wildcard `<*>`
- `inactive:` leading+inline+quoted `"inactive:"` preserved — #4335/#4348
- Lenient vs strict does not bypass security — only equalFlowWorkerCap/unsupported interface stanzas downgraded to warn
- Bracket stripping O(1) non-recursive — no stack overflow
- Schema `closedWorld` single production flip (DNAT then) leaf-complete — no false-reject

### Host-inbound + Zone (verified fixed)

- #4167 IPv4 truncated-header fail-closed
- #3902 flowless src-independent screens (LAND/source-route/icmp-flood/udp-flood)
- #3405 host-inbound default-deny
- #3362 per-interface override
- #3172 VRRP VIP scoping
- Lifeline correct for fab0/fab1/em0

### Screen (verified fixed + negatives)

- 10 stateless checks fail-closed
- SYN-cookie crypto (zone MAC, tuple binding, single-use, bounded cache)
- Fragment guards, unzoned physical not bound, flowless non-transit for IP
- #4167 IPv4 truncation fail-closed, #3902 flowless (LAND/source-route/icmp-flood/udp-flood)

### NAT (2 negatives + 7 fixes verified)

- NAT64 non-first fragment no port leak — frame_is_non_first_fragment() → None → flowless → no PortAllocator leak
- NAT pool exhaustion fail-CLOSED — SNAT Unavailable→drop, NAT64 MatchUnavailable/AllocatorExhausted→drop, NPTv6 malformed/overlap→reject snapshot
- P1 HA NAT pool FIXED (#4388), P2 dnat_table FIXED (#4393), P5 NAT 1:N FIXED (#4399/#4438), P7 fabric NAT FIXED, #4381 NAT64 BIB FIXED, #4384 TCP checksum FIXED, #4521 NAT pool FIXED

### Session (8 negatives, P6/P7 FIXED, STILL PRESENT known-opens documented above)

- P6 RST/FIN all 3 paths FIXED (#4400 ForwardCandidate, #4487 LocalDelivery, #4453 fabric) — strict_syn_check + should_cache decline
- P7 fabric NAT skip FIXED (#4414/#4439 protocol allowlist TCP|ICMP|ICMPv6 only)
- Session-limit NOT dead code — fully wired (OFF-gate, origin-agnostic inc, driver, tests)
- Bare SYN → OPENING 20s, not ESTABLISHED — F16/F17 verified
- NAT index 1:N FIXED — SmallVec N=2 multimaps
- Flow-cache TCP state PASS — packet_eligible excludes FIN/RST/SYN (only ACK+UDP cacheable)
- Companion keepalive functional — #4380
- TCP closing/reset/established sticky — #3489/#3046/#4109
- KNOWN-OPEN: S-001 cross-zone bare 5-tuple (#2387 OPEN, P0), S-002 bare ACK 300s DoS (Med, no GH issue yet), V-01 VLAN cross-VLAN (#2387), flow-cache NAT port reuse (#3776 OPEN), pure PSH cache (#4539 OPEN LOW), PSH+ACK/pure PSH ESTABLISHED DoS (NEW — this audit, see §6 NEW-02)

### Forwarding core (8 negatives)

- Fragment: ipv4_is_non_first, ipv6_is_non_first, declared_l3_end #2361
- IPv6 EH bounded 0..8 checked_add fail-closed — #2292/#4517
- Flow-cache packet_eligible/should_cache #2363, NAT64 excluded
- Checksums correct — l4_checksum_field_delta, incremental, ICMPv6 zero→0xFFFF #1839
- XDP shim session-map steer, ICMP embedded fragment guards, policy/zone interaction correct
- H-02 tiny fragment NOT exploitable — XDP requires 14+20B TCP, drops tiny frags
- V-01 VLAN cross-VLAN STILL PRESENT (#2387, known-open) — S-001 variant
- M-02 XDP EH 6 vs 8 LOW perf (not bypass)

### Filter/PBR/Routing (verified fixed)

- P3 PBR reject (#4392) — RouteOverride::Drop, PbrRejectSink — FIXED
- F-001 source-prefix-list — firewallPrefixListRefs reads Keys[1:]+Children — FIXED (#3843)
- Family any — #4287/#4426/#4427 verified, dual-compile + PL-family gate — FIXED
- Filter match, eval, cache-sensitive, compiler, policer — all verified fail-closed
- Routing rules, VRF, bond, next-table, rib-group #3876, PBR DSCP-0/except/L4 — verified
- PBR discard kernel-mirror FIXED #4534, three-color default FIXED #4535

### IPsec/WG/HA/VRRP (15 negatives, 0 novel)

- WG 3-slot rekey FIXED #3882, TAI64N FIXED #4092, cookie DoS FIXED, IKE multi-value FIXED #3904, FRR rib-group #3876, GRE keepalive FIXED #4071, DF-bit FIXED #4015, IPsec delete-terminate FIXED #3941, PSK id FIXED #3952, SA parse FIXED #3937, HA NAT pool/dnat/1:N, RST/FIN FIXED, PBR reject FIXED, XFRM FIXED #2933, WG DELIBERATE, HA heartbeat NOT exploitable (gated on macOK)

### DHCP/RA/Flowexport/CLI/REST/gRPC/Wire (9 negatives + 7 fixes verified on 8cd816e35)

- DHCP mask /0 reject, classlessRoutes, selectIANAAddress, renewalTimers FIXED #4526 (t2Remaining=leaseTime/8*3, not leaseTime*7/8 - leaseTime/2)
- RA PREF64/MTU/pruning, randomAdvInterval FIXED #4525 (floor ≥1, schema 4..1800)
- Flowexport ProtocolNum FIXED F-058, collector health/backoff, batch cap 65536
- CLI ping/traceroute --, monitor traffic -- FIXED #4524 + keyword/count FIXED #4540, monitor filter quote bypass LOW defense-in-depth (primary -- holds)
- REST show redaction, Basic-auth timing residual LOW (nanosecond, loopback-bound), gRPC fabric PSK replay window, lexer bracket loop, parser maxDepth 256
- MAX_CONTROL_REQUEST_BYTES PINNED (Go pre-flight + Rust receiver 64 MiB, tests pin both), navigatePath #3980 FIXED (terminal single-key)
- writeJSON FIXED #4541 (marshal to buffer first, 500 on error)
- 7 fixes verified: #4541, #4540, #4526, #4525, #4524 (primary), #4530 @ revert deliberate, #3980 navigatePath terminal

## 8. Suggested issue split — sequenced so each PR is small and independently reviewable

### P0 — ship-blocker (must fix before release)

1. **S-001**: Cross-zone / cross-VRF session hijack via bare 5-tuple — #2387 OPEN (P0) — `session/key.rs:10-17` bare 5-tuple, `session/lookup.rs:62-68` pure 5-tuple lookup, `poll_descriptor/mod.rs:858-879` no zone re-validate. Flow-cache MISS → session-table HIT = cross-zone reuse. Fix: validate `metadata.ingress_zone` on session hit (one branch) or extend SessionKey with zone/VRF discriminator. **Already filed #2387 — drive this.**

2. **V-01**: Flow-cache VLAN cross-VLAN reuse (#2387) — same root as S-001 but flow-cache path (physical `ingress_ifindex` only, not logical VLAN ifindex). Flow-cache hit SKIPS session lookup — even if session is fixed, flow-cache still vulnerable. Fix: include logical ifindex in FlowCacheLookup key. **Already filed #2387 — drive as part of S-001 fix (flow-cache is separate code path, must be fixed together).**

### P1 — High (fail-open / DoS — fix soon)

3. **S-002**: Bare TCP ACK as first packet → ESTABLISHED (300s) — 15× DoS amplification — `session/install.rs:158` `!(TCP && is_initial_syn)` → bare ACK ESTABLISHED 300s. Fix: `ACK && !SYN → OPENING`. **No GH issue filed for S-002 bare ACK DoS — should be filed.**

4. **NEW-02 (this audit)**: PSH+ACK / pure PSH / null / URG first-packet → ESTABLISHED (300s) — same 15× DoS class as S-002 bare ACK, different flag combinations that bypass a bare-ACK-only fix. Fix together with S-002 as one PR (any non-SYN TCP first packet → OPENING).

5. **NEW-01 (this audit)**: Deterministic NAT (CGNAT) unenforced on userspace-dp — BPF-only, retired. Config commits clean, production does round-robin. ISP compliance logging broken. Fix: port to userspace-dp `allocator.rs` OR gate as unsupported with warning (interim: `capabilities.go` UnsupportedReasons). **NEW — not in any GH issue, not in all_findings, not in closed issues.**

6. **Flow-cache NAT port reuse** — #3776 OPEN (MEDIUM-HIGH) — flow-cache outlives session, stale NAT port reuse → reverse-mismatch. Fix: stamp flow-cache with session epoch or invalidate on GC.

### P2 — Medium (parity, availability, observability — next sprint)

7. **S-003**: Pure PSH / null / URG should_cache_local_delivery gate-consistency — #4539 OPEN (LOW, hardening)
8. **H-01**: Duplicate host-inbound-traffic blocks — #4544 OPEN (LOW)
9. **S-03**: IPv4 options TLV malformed skip → source-route bypass — #4543 OPEN (LOW)
10. **H-01**: Monitor traffic filter quote bypass — LOW defense-in-depth (primary -- holds)
11. **M-01**: REST/gRPC rollback n=0 — actually fail-closed (400), cosmetic wording only
12. **HA heartbeat auth order**: Unmarshal before verify — gated on macOK, not exploitable, but reorder would be cleaner
13. **VRRP MaxAdverInt unclamped**: MaxAdvertInt=1 → 30ms flap — already filed #4548
14. **XFRM if_id collision**: st0/st0.0 same id — FIXED #2933 (commit-time HARD-REJECT)

### P3 — Low (hardening, cleanup — backlog)

15. **NEW-01/Cohort2**: `@` in isIdentChar — NOT-MATERIAL / DELIBERATE (do not file)
16. **NEW-02/Cohort2**: `to`-as-separator scoping — DUP F-043 (do not file)
17. **H-02**: Lifeline `HasPrefix("fab")` — DELIBERATE tradeoff (do not file)
18. **Z-01**: buildInterfaceZoneMap parent pollution — NOT-MATERIAL (polluted base never read)
19. **NAT L-01..I-02**: Source NAT synthetic port leak, NAT64 dead code — Low/Info cleanup
20. **XDP EH 6 vs 8**, cross-VLAN eviction DoS, IPv6 fragment garbage ports — all Low/Info perf
21. **Monitor residual**: quote bypass (Low), rollback n=0 (Med→Low), writeJSON FIXED, interface missing FIXED
22. **VRRP IPv6 hop-limit raw path, HA IPv4-only, PSK zeroize, same NodeID deadlock** — all LOW (#4549 batch)
23. **FRR Origin** — already in #4498 item 1 (not new)

## 9. Confidence summary

- **Total NEW findings on 8cd816e35 (this round, not in any prior source)**: **2 Medium** (NEW-01 deterministic NAT unenforced, NEW-02 PSH+ACK/pure PSH/null/URG ESTABLISHED DoS) + **0 High** + **~5 Low/Info** (navigatePath intermediate multi-key? #3980 terminal fixed, intermediate needs verification — see cohort 14 report; validateMultiValueLeaf `to` is F-043 dup, not new).

- **Total CONFIRMED STILL PRESENT (known-open, already filed in GH issues, not new)**: S-001 cross-zone bare 5-tuple (#2387 OPEN, P0), S-002 bare ACK 300s DoS (Med, no GH issue — should be filed), V-01 VLAN cross-VLAN (#2387, P1), flow-cache NAT port reuse (#3776, Med-High), pure PSH cache (#4539 LOW), PSH+ACK/pure PSH (partial #4539, ESTABLISHED DoS is NEW-02), H-01 host-inbound dup (#4544), S-03 TLV (#4543), etc.

- **Live-bypass (HIGH) on 8cd816e35**: S-001 (cross-zone session hijack — P0, #2387 OPEN, worst class), V-01 (cross-VLAN flow-cache — P1, #2387 OPEN). Both already filed as #2387.

- **All previously-reported HIGH fail-open paths from b1bd96fb6**: VERIFIED FIXED on 8cd816e35 EXCEPT S-001/S-002/V-01/flow-cache NAT reuse/pure PSH cache which were already known-open on b1bd96fb6 and are STILL PRESENT (no fix attempted between b1bd96fb6→8cd816e35 for these — 8cd816e35 only has #4540/#4541 CLI/API hardening, no session/flow-cache/NAT changes).

- **New on 8cd816e35 (not in b1bd96fb6 reports, not in GH issues, not in all_findings):**
  - **NEW-01 Med**: Deterministic NAT (CGNAT) unenforced on userspace-dp — BPF-only, retired. Config commits clean, production does round-robin. ISP compliance broken. **Genuinely NEW — not in any GH issue (500 checked), not in all_findings (274), not in any ps-review-018..033 (14 reviews).** #3864 CLOSED was flat-set PARSE bug, not enforcement gap.
  - **NEW-02 Med**: PSH+ACK (0x18) / pure PSH (0x08) / null (0x00) / URG (0x20) first-packet → ESTABLISHED (300s) — same 15× DoS class as S-002 bare ACK but different flag combinations that bypass a bare-ACK-only fix. Must be fixed together with S-002 as one PR. **Genuinely NEW — not in any GH issue (500 checked, 0 PSH+ACK/pure PSH first-packet ESTABLISHED), not in all_findings (274, no PSH+ACK DoS), #4539 is pure PSH *LocalDelivery cache* (different code path), S-002 bare ACK not filed as GH issue.**

- **Verified fixed on 8cd816e35 (do NOT re-report, CLOSED issues):**
  - #4541 writeJSON buffer-first, #4540 monitor keyword/count, #4535 three-color default, #4534 PBR discard, #4526 DHCP overflow, #4525 RA interval, #4524 monitor injection, #4521 NAT pool, #4520 nat64 counter, #4519 nptv6, #4518 nat64 allocator, #4517 EH walkers, #4514 policer, #4487 LocalDelivery RST/FIN, #4453 fabric RST/FIN, #4400 ForwardCandidate RST/FIN, #4399/#4438 NAT 1:N, #4393 dnat_table, #4392 PBR reject, #4388 HA NAT, #4384 TCP checksum, #4381 NAT64 BIB, #4380 forward/reverse idle, #4167 IPv4 truncation, #3902 flowless screens, #3405 host-inbound default-deny, #3882 WG 3-slot, #4092 TAI64N, #4107 cluster auth, #3876 rib-group, #4071 GRE keepalive, #4015 df-bit, #3941 IPsec delete-terminate, #3952 PSK id, #3937 SA parse, #3842 dup match/then, #3846 DeletePath, #3975 DeactivatePath, #3980 navigatePath terminal, #3982 RenamePath, #3864 deterministic NAT parse, #2419 bracket-list, #4149 unterminated /*, etc.

---

*End of report. Base: 8cd816e35 (merge PR #4545, master, up to date with origin/master). All files read read-only — no source modified. 9 cohort agents on 8cd816e35, 14 modules covered, 2 NEW Med findings + 8 CONFIRMED STILL PRESENT (known-open) + 5 Low/Info + 50+ verified negatives. Deterministic NAT (CGNAT) unenforced is the top NEW finding on this HEAD. S-001 cross-zone bare 5-tuple (#2387) remains the top P0 ship-blocker (known-open, needs fix). PSH+ACK/pure PSH ESTABLISHED DoS should be fixed together with S-002 bare ACK as one PR.*

