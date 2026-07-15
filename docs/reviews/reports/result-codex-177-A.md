# codex-review-177 — Triage result ledger (slice A: A1, A2, A3, A4)

**Triage authority:** slice A (finding IDs beginning A1/A2/A3/A4). A5–A10 owned by other agents.
**Review file:** /tmp/codex-review-177.md (base d22789fa6 — STALE, ~3300 commits behind).
**Verified against:** current origin/master (fetched; HEAD 812bf30c1 → advanced to 6daa3519+ during the run; post-#5030 campaign of ~33 merges).
**Method:** 13 parallel read-only verification agents, one per bucket, each applying the 3 gates
(SYMBOL-EXISTS / ALREADY-FIXED / REAL+MATERIAL) against origin/master via `git show origin/master:<path>`
and recent-merge grep, plus dedup vs 76 open issues. Coordinator (me) filed genuine findings serially.

## Totals
- **Findings processed:** 89 (all A1–A4 in High/Medium/Low sections).
- **FILED:** 86 findings → **57 new issues** (#5139–#5197). HIGH (7) + MEDIUM (41) filed individually;
  37 LOW cohorted into 9 subsystem issues (repo convention, cf. #4907/#4883/#4886).
  One consolidation: A3-b2-F3 + A3-b3-F1 → a single issue (#5180) — same FindChild-first-sibling root.
- **ALREADY-FIXED:** 3 (A1-b8-F7, A3-b2-F5, A4-b1-F4).
- **DUP of open issue:** 0. **SYMBOL-GONE:** 0. **NOT-MATERIAL:** 0.
  (Codex ~90% signal held: every survived finding was genuine on current origin/master.)

## Newly-filed issues (most-severe first)

### HIGH (7)
| # | finding | title |
|---|---------|-------|
| #5139 | A1-b1-F1 | flow-cache keys physical parent ifindex → co-parented VLAN cross-zone policy replay (sec) |
| #5140 | A1-b1-F2 | post-GRE-decap ICMP/host-inbound reads outer raw_frame w/ inner offset (sec) |
| #5141 | A1-b2-F1 | TCP segmentation promotes bytes beyond IP total_len into checksummed payload (sec) |
| #5142 | A1-b3-F1 | filter `then discard`/`reject` + `next term` → implicit permit (fail-open) (sec) |
| #5143 | A1-b8-F1 | reconcile swallows post-spawn AF_XDP bind failure → silent forwarding outage |
| #5144 | A2-b1-F1 | overlapping NAT/NAT64 pools separate allocator domains → identical public tuples (sec) |
| #5145 | A2-b1-F2 | DNAT most-specific-wins discards Junos first-match → `destination-nat off` bypass (sec) |

### MEDIUM (41)
| # | finding | title |
|---|---------|-------|
| #5146 | A1-b1-F3 | NAT64 first-frag assoc published pre-commit; rollback leaves it live (sec) |
| #5147 | A1-b1-F4 | flow-cache neighbor invalidation is map-wide → attacker cache-thrash |
| #5148 | A1-b2-F3 | TCP seg admits first IP fragments → overlapping pseudo-segments |
| #5149 | A1-b2-F4 | tunnel L4 recompute covers Ethernet slack GRE/WG trim → bad inner checksum |
| #5150 | A1-b2-F5 | flexible-match-range matches bytes outside IP-declared packet (sec) |
| #5151 | A1-b3-F2 | FilterResult::default allocates empty Arc<str> on every full filter eval |
| #5152 | A1-b4-F2 | activating one RG resets standby HOLD clocks for unrelated split-RG sessions |
| #5153 | A1-b4-F3 | reverse companion drops application inactivity_timeout_ns |
| #5154 | A1-b4-F4 | poisoned shared-session read skips #2170 generation guard (sec) |
| #5155 | A1-b4-F5 | demote-owner-RG cancelled_keys dedup O(N^2) on packet worker |
| #5156 | A1-b5-F1 | non-exact CoS queue lease not conserved at init/teardown |
| #5157 | A1-b5-F2 | mirror-reserve mid-batch drop breaks submit_local sidecar accounting |
| #5158 | A1-b6-F1 | post-NAT wire key re-walks pre-NAT ingress input filter |
| #5159 | A1-b6-F3 | 1280-byte MTU floor bypasses TCP seg for smaller IPv4 MTUs |
| #5160 | A1-b6-F5 | redirect-sample RMW adds 2nd contended atomic to every MPSC enqueue |
| #5161 | A1-b7-F2 | interface-only ECMP members starve to width-1 |
| #5162 | A1-b7-F3 | GRE mixed-family outer src/dst commits clean, drops every encap |
| #5163 | A1-b7-F4 | ZoneCounterStore global Arc<Mutex> folded every poll batch by every worker |
| #5164 | A1-b8-F2 | WG engine-global handshake/rekey edges consumed by first sorted peer |
| #5165 | A1-b8-F3 | neighbor monitor has no JoinHandle → old-gen mutates new cache after teardown |
| #5166 | A1-b8-F4 | snapshot refresh publishes forwarding before CoS owner/lease maps |
| #5167 | A1-b9-F2 | cross-worker mirror clone reserves live queue before sampler |
| #5168 | A1-b9-F3 | 64-packet WG replay window drops authentic reordered traffic |
| #5169 | A1-b10-F1 | full apply_snapshot lacks generation-monotonicity guard → stale permit revival (sec) |
| #5171 | A1-b10-F2 | defer_workers ACKs+persists before full forwarding/mandatory-map build (sec) |
| #5172 | A1-b10-F3 | io_uring WriteMode never demoted after permanent ring failure |
| #5173 | A1-b11-F1 | shim modulo mis-steers HW-queue-N packets to wrong-queue socket |
| #5174 | A1-b12-F1 | NAT64 MissingNeighbor cold path evaluates synthetic v6 tuple, replays non-NAT64 |
| #5176 | A2-b1-F3 | NPTv6 drops static-NAT from_zone → translates from every zone (sec) |
| #5177 | A2-b1-F4 | NAT64 reverse ICMP-error leaves translated PAT port in embedded quote |
| #5178 | A2-b1-F5 | synced deterministic NAT reservations leak into never-drained recycle queue |
| #5179 | A3-b1-F1 | nil application-set value panics CatalogNames (sec) |
| #5180 | A3-b2-F3 (+A3-b3-F1) | duplicate hierarchical group/interface/screen blocks last-writer-wins (sec) |
| #5181 | A3-b2-F4 | bracketed application-set members truncated to first value |
| #5182 | A3-b3-F3 | WG IPv6 endpoint loses port in tokenization → hydrates responder-only |
| #5183 | A3-b3-F4 | non-empty malformed feed URLs pass strict commit → empty deny set (sec) |
| #5184 | A3-b4-F3 | packed `vrrp-group N priority M;` bypasses ValidateInteger(1,255), uint8 truncation |
| #5185 | A4-b1-F1 | commit post-rename fsync failure: reports failed while active.json holds new config (sec) |
| #5186 | A4-b1-F3 | factory reset never erases on-box config archive → prior-tenant secrets survive (sec) |
| #5187 | A4-b1-F6 | LoadSet/LoadMerge leave earlier lines applied after mid-body error (sec) |
| #5188 | A4-b1-F9 | upgraded 0644 journals + rotated segments never migrated to 0600 (sec) |

### LOW cohorts (9 issues, 37 findings)
| # | cohort | members |
|---|--------|---------|
| #5189 | udp warmed-path alloc/contention | A1-b4-F6, A1-b6-F4, A1-b7-F5, A1-b7-F6, A1-b8-F5, A1-b10-F4 |
| #5190 | udp observability/telemetry + bind/bench | A1-b1-F5, A1-b1-F6, A1-b1-F7, A1-b8-F6, A1-b12-F2, A1-b12-F3 |
| #5191 | udp segmentation/ICMP + WG protocol fidelity | A1-b2-F6, A1-b2-F7, A1-b9-F4, A1-b9-F5 |
| #5192 | udp memory-safety (sec) | A1-b6-F6, A1-b11-F3 |
| #5193 | udp CoS/fairness + snapshot-integrity | A1-b5-F3, A1-b5-F4, A1-b7-F1, A1-b7-F7 |
| #5194 | pkg/config validation | A3-b1-F2, A3-b2-F1, A3-b2-F9, A3-b2-F11, A3-b2-F12, A3-b3-F5, A3-b3-F6, A3-b3-F7 |
| #5195 | pkg/config secret-handling (sec) | A3-b2-F7, A3-b2-F10 |
| #5196 | CLI/appid UX | A3-b1-F3, A3-b1-F4, A3-b1-F5 |
| #5197 | configstore durable-delete (sec) | A4-b1-F5, A4-b1-F10 |

## ALREADY-FIXED (3 — not filed)
- **A1-b8-F7** — debug BPF session dump unaligned read. Fixed by **#4882 / 75cd8d5db**
  (`decode_session_map_key` now uses `core::ptr::read_unaligned`).
- **A3-b2-F5** — mixed NAT scope kinds expanded as OR. Fixed by **#5020 / 53702b638**
  (`validateNATRuleSetMixedScopeAST` rejects mixed scope in one clause; closes #4881).
- **A4-b1-F4** — unknown encrypted-body format bypasses AES-GCM as empty config. Fixed by
  **#5013 / 657791f19** (`unmarshalEnvelope` now fails closed on unknown envelope format).

## Per-finding notes of interest
- **A1-b8-F1 (#5143):** shares its *outcome* with open **#4952** but is a DISTINCT mechanism
  (post-spawn in-worker bind failure vs `spawn_supervised_worker` returning Err). Cross-referenced
  in the issue body; fold only if #4952 adopts a full per-worker readiness barrier.
- **A3-b2-F3 + A3-b3-F1 (#5180):** consolidated — both are the FindChild-first-sibling / whole-object
  last-writer-wins root cause, spanning groups, interfaces, and the screen compiler. One tracker.
- **A3-b1-F2 (in #5194):** protocol sub-claims already fixed by #4887/#4008; only the residual
  bare-`0` → (0,0) wildcard-sentinel collision survives → filed as LOW in the cohort.
- **A1-b6-F4 (#5189)** and **A1-b8-F5 (#5190)** are siblings of open #4973/#4971 respectively but at
  distinct call sites/paths; noted in-issue for the fixer to fold if the sibling fix generalizes.
- **A1-b12-F3 (#5190)** is bench-only but a *false-PASS merge gate* → material as LOW per triage rule.

## Provenance discipline
All GitHub-bound text is free of harness/system tags. Every issue body cites current-origin/master
file:line, the violated invariant/RFC/contract, the review's fix-direction, and provenance
`codex-review-177 [<id>], <severity> confidence`. Filing log: /tmp/codex177-filed.tsv (resumable).
