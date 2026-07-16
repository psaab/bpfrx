# Triage result — codex-review-180 (Full-Tree Firewall and Zone-Policy Review)

- Review base: `4567ffb78` — **40 commits behind** current origin/master `0ab8a90a8` (verified).
- All findings re-verified against `git show origin/master:<path>` at `0ab8a90a8`, NOT the stale base.
- Parsed canonical findings: **26** (3 High, 18 Medium, 5 Low per the review; severities cross-checked).
- Open issues fetched for dedup: 180 (`gh issue list --state open --limit 400`).

## Counts
| Bucket | N |
|---|---|
| Parsed canonical findings | 26 |
| Dropped — duplicate of open issue | 1 (C180-022 → #4971) |
| Dropped — stale / already-fixed | 0 |
| Filed individually (material High+Medium) | 21 |
| Cohort'd (Low / doc tail) | 4 |

All 26 findings survived GATE 1 (symbol exists) and GATE 2 (not already fixed by the 40 post-base merges). The post-base security batch (zeroize #5280/#5281/#5552/#5554, session-total #5034, MonitorInterface #5497, snmp salt #5544, ddns multiword, etc.) did **not** overlap any of the 26 roots. One finding (C180-022) is a dedup drop against an already-open issue (#4971), not a fix.

## Per-finding table
| Finding | Area | Sev | Gate verdict | Reasoning (one line) |
|---|---|---|---|---|
| C180-001 | userspace-dp snapshot publication | High | **FILED #5562** | `snapshot_refresh.rs` stores validation + forwarding via two separate ArcSwaps (303-304); worker can stamp a stale permit with the new generation → persistent policy fail-open. Distinct store-pair vs open #5166/#5169/#5171. |
| C180-002 | cluster HA failover | High | **FILED #5563** | `TransferReadinessSnapshot` has no applied-config epoch + `resetRecvGen` clears config high-water on bulk → planned failover promotes stale-policy peer (fail-open + false-deny). Distinct gate vs #5274/#5084/#4957. |
| C180-003 | daemon HA receive-side apply | High | **FILED #5564** | `syncAndApply` returns before the 3 `clearSessionsFor*` invalidators on any apply error; equal-text fast path makes omission permanent → armed standby keeps revoked sessions. Distinct from #4957. |
| C180-004 | host-inbound nft projection | Med | **FILED #5565** | `CoarseAdmitsIKE` is a zone-wide bit emitted `iifname {whole-zone-set} udp dport {500,4500} accept` → per-interface IKE/ident exception widened to siblings (false-allow, vsrx-parity). |
| C180-005 | host-inbound nft conntrack | Med | **FILED #5566** | `ct state established,related accept` precedes per-interface coarse drops + table replace doesn't flush conntrack → host-service tightening leaves direct-kernel session authorized (false-allow). |
| C180-006 | userspace-dp ICMP generated-error | Med | **FILED #5567** | `allow_generated_error(TimeExceeded/PTB)` consumes the process-global token before egress/builder feasibility → cross-interface diagnostic starvation (DoS/false-deny). Distinct from #3656. |
| C180-007 | userspace-dp frame classification | Med | **FILED #5568** | Scalar `icmp_type_code_present`/`is_fragment`/tcp_flags derive from physical `frame.len()`, not `declared_end` (#5150 only clamped flex slices) → Ethernet slack drives policy/filter/host-inbound/embedded classification (fail-open/false-deny). |
| C180-008 | userspace-dp reject reply | Med | **FILED #5569** | `allow_generated_reject` consumes zone token before `classify_generated_reply` can output-filter-drop it → same-zone cross-protocol reject-bucket starvation (availability). Distinct from #3656/#3618. |
| C180-009 | cli / grpcapi clear | Med | **FILED #5570** | `clear security policies hit-count` accepts trailing selectors but issues unscoped global `clear-policy-counters` → destructive fail-closed violation, erases all policy evidence. |
| C180-010 | ddns persisted state | Med | **FILED #5571** | `loadDDNSState` `os.ReadFile` with no byte/record bound before validation → CWE-770 heap/OOM on corrupt/oversized 0600 file at startup (availability). Distinct locus from #4886. |
| C180-011 | policymatch simulator | Med | **FILED #5572** | `Query` has no l4-present/non-first-fragment dimension → simulator reports permit where dataplane applies the #4569 fragment-associated deny (management-parity, fail-open diagnostic, vsrx-parity). |
| C180-012 | upgrade HA gate | Med | **FILED #5573** | `ClusterNodeIDPresent` returns `err==nil` — every Stat error → standalone-absent; both cut gates reuse it → marker I/O error authorizes uncoordinated stop (HA fail-open). Residual of #5284. |
| C180-013 | config compiler applications | Med | **FILED #5574** | `compileApplications` overwrites direct scalars with no value-aware dup tracking → conflicting `protocol/port/timeout/icmp/alg` keep only last, commit clean → deny under-matches (fail-open, vsrx-parity). Distinct from #3366. |
| C180-014 | config lenient compile | Med | **FILED #5575** | `expandUserspacePolicyApplications` returns `(nil,true)` for empty apps → lenient-dropped match constraints become wildcard permits (no `__unsupported__` sentinel); permit-widening on lenient/HA load. Distinct from #3044/#3113/#3114. |
| C180-015 | config route-filter validator | Med | **FILED #5576** | `ValidateRouteFilterArg` position-agnostic — accepts `route-filter longer exact` (keyword in CIDR slot); renderer emits undefined-list match → authored accept becomes match-none (false-deny). |
| C180-016 | dataplane zone quarantine | Med | **FILED #5577** | `refsQuarantinedZone` drops whole scoped-global rule if ANY plural-set member is quarantined → multi-zone deny removed from surviving valid members (fail-open). Distinct from #5488 / #4626. |
| C180-017 | daemon policy invalidation | Med | **FILED #5578** | `clearSessionsForPolicyIDs` is void; enumerate/batch-delete failures log-only → commit succeeds with stale authorized sessions (fail-open). Distinct from C180-003 (attempted-but-failed vs skipped) and #4234/#4320. |
| C180-018 | api match-policies host-inbound | Med | **FILED #5579** | No `ingress_interface` selector + existential-any classifier → mixed-zone host-inbound folds to unqualified zone-wide admit (false-admission diagnostic, vsrx-parity). |
| C180-019 | api REST policy counters | Med | **FILED #5580** | `PolicyRule` has no availability marker; unloaded dataplane returns `hit_packets/bytes=0` at HTTP 200 → authoritative-looking false zeroes (observability). Distinct from #3345/#3408. |
| C180-020 | logging syslog transport | Med | **FILED #5581** | `dial()` `default: dialUDP()` + unvalidated constructor → unknown transport token (lenient/HA) silently sends plaintext UDP (crypto fail-open, telemetry leak). Distinct from #2008/#3350. |
| C180-021 | docs afxdp-packet-processing | Low | **cohort #5583** | Doc line 32-33 states obsolete non-SYN shim drop; shim now redirects all misses → doc-contract drift. |
| C180-022 | userspace-dp tx finalise | Low | **DROPPED-DUP → #4971** | `finalise.rs` retry_tail `Vec::new()` + owned retry `String` on TX partial/zero-insert — same root as open #4971 (remove String alloc + last_error lock from TX retry/partial-submit paths). |
| C180-023 | userspace-dp nat destination | Low | **cohort #5583** | Malformed non-empty `destination_prefix` falls back to exact host with no parse-error → silent narrowing; requires corrupt/mixed-version snapshot. Distinct from #3029/#3164/#4718. |
| C180-024 | config tcp_flags parser | Low | **cohort #5583** | Non-negated parens `continue`d with no depth/order tracking → `(syn`/`syn)`/`syn)(` commit as plain syn; mask not widened → auditability debt. Distinct from #3076/#4714/#5455. |
| C180-025 | host-inbound WireGuard | Med | **FILED #5582** | Listen port steered to kernel but no `wireguard` host-inbound token/dynamic exception → fresh passive handshake hits catch-all drop (false-deny/availability). Medium confidence — open design question on implied admission. |
| C180-026 | snmp traps shutdown | Low | **cohort #5583** | Shutdown-abandoned trap jobs not added to `trapsDropped` → zero-drops report while discarding queued traps; safety correct, accounting wrong (Medium confidence). |

## Notes on dedup rigor
- The review pre-suppressed 121 prior reports; each survivor's dedup note was cross-checked against the 180 open issues by symbol+root-cause (not title text).
- C180-001/002/003 (Highs) are in active problem families (snapshot publication, HA config epoch) but each names a distinct store-pair / gate / receive-side mechanism not owned by an existing open issue; filed individually with cross-references so the maintainer can consolidate at fix time.
- Only C180-022 matched an open issue root exactly (#4971) → dropped as duplicate.
