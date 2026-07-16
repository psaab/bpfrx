# Triage result — fable-review-175 (dedup-disabled raw view)

- **Review base:** fc479ca65e15c28dd0deb942268556fe0df23c53
- **Triaged against origin/master:** 675133b8486fc5dd42f4cd1ca8fdf248531c2f67 (fetched 2026-07-12)
- **Open issues consulted:** 271 (gh issue list --state open --limit 400) + recently-merged #5721/#5722/#5667/#5651-5668
- **Review character:** 23-batch Paladin full-tree sweep, ~2748 files, dedup DISABLED. Overwhelmingly PASS/NEGATIVE (~146 pure NEG in the CLI/DDNS/DHCP batch alone; author's own bottom line "High/Medium confidence — NONE MATERIAL"). codex-review-182 already covered this tree at the same base, so the NEW-and-not-covered set is tiny, as expected.

## Outcome

- **FILED (new): 2 issues** — #5726 (material), #5727 (low-materiality cohort).
- **DUP: 1** (HA address-only NAT reservation → #5338).
- **ALREADY-FIXED: 1** (direct-host app/set precedence → merged #5721/#5677).
- **STALE: 2** (legacy BPF compiler_nat casts — retired eBPF path).
- **DROP: bulk** (~146 PASS/NEG + not-a-bug + test-infra/informational).

## Per-finding table

| Finding | Loc (master) | Verdict | Reasoning |
|---|---|---|---|
| F-01 qualified-next-hop `<gateway>` has NO keyValidator → malformed backup gateway commits clean, never installs | schema_routing.go qualified-next-hop node | **FILED #5726** | Verified: node lacks keyValidator/keyValueType (contrast next-hop keyValidator: ValidateStaticNextHop). ValidateStaticNextHop DOES reject 1.2.3.999 — just not invoked here. Not in open list. |
| F-02 ECMP `next-hop [ gw1 gw2 ]` — only first gateway validated | schema_walk.go container path L389-408 (declaredKeyTokens=2 → Keys[1:2]); #2419 bracket-collapse | **FILED #5726** (same root/fix area as F-01) | Verified: container keyValidator loop spans only `1+args` tokens; Keys[2:] ECMP members bypass validation while compiler installs all. Distinct from #2448 (runtime FIB drop), #5678 (preference drop), #5161 (interface-only ECMP starve). |
| F-03 direct-host junos-host deny resolves application-set before same-named user application | junos_host_deny.go junosHostResolveApplications | **ALREADY-FIXED #5721** (#5677) | Exact match to the #5677 fix I authored, merged in #5721. Review base fc479ca65 predates the merge. |
| HA sync reservation skips address-only NAT flows (dup public tuple post-failover) | nat/source.rs:827 reserve_synced_source_nat_allocation | **DUP #5338** | Exact function + symptom match to open #5338 (+ #5269 token family #5341/#5178/#5446/#5295). Verified source.rs:827 present. |
| legacy BPF uint8 poolID overflow → cross-pool wrong NAT IP | pkg/dataplane/compiler_nat.go:236/444/493/1237 | **STALE** | Retired eBPF backend (#1476), hard-rejected at commit/runtime — not the enforcement path. Review itself notes "backend retired". |
| legacy BPF uint16(BlocksPerIP) div0 if BlockSize=0 | pkg/dataplane/compiler_nat.go:538 | **STALE** | Same retired legacy compiler; userspace path guards. |
| try_next_port counter unsynchronized with bitmap (proto-0 synthetic) | nat/allocator.rs | **DROP** | Review's own verdict: "not a correctness bug" — port never written to frame. |
| DNAT source-constraint parse `Err(_) => {}` not surfaced via record_parse_error | nat/destination.rs | **COHORT #5727** | Low observability gap (#4718 seam); fail-closed correct, no counter. May overlap #5190/#5250. |
| static_nat SourceConstraint::from_list unparseable silent | nat/static_nat.rs | **COHORT #5727** | Same class as above; low. |
| DHCPv6 DUID-LLT time uint32 wrap (year 2136) | pkg/dhcp/dhcp.go:637 | **COHORT #5727** | 136y horizon; DUID-LL already default. |
| DDNS Cloudflare listRecords 1000-page cap warns-not-errors on truncation | pkg/ddns/backend_cloudflare.go:205-209 | **COHORT #5727** | Low; abuse-only truncation, harmless duplicate POST. |
| monitor traffic `count 0` == omission (unlimited) ambiguity | pkg/cli/monitor_traffic.go:60,98 | **COHORT #5727** | Help-text/display-only; no risk. |
| CLI address-book show O(n*m) member-detail, no early break | pkg/cli/cli_show_security_objects.go | **COHORT #5727** | Control-plane perf, bounded <100k; not hot-path. |
| frame_l3_offset single-VLAN only (QinQ NAT64 L3 offset) | frame/headers.rs frame_l3_offset | **DROP** | Review's own coverage notes: single-tag is vSRX parity, fail-closed on <14/<18. QinQ arguably out of scope; not fail-open as the isolated row claimed. |
| tcp_segmentation.rs `as u16` casts / flow_cache MAC epoch `!=` wrap / PbrRejectSink reject→silent-drop-logged-REJECT / GRE inner-MTU underflow disables MSS clamp | userspace-dp Rust dataplane | **DROP (cohort-adjacent)** | All Low/defense-in-depth; cast/observability items map to existing #5190/#5250/#5660 cohort themes — not refiled to avoid soft-dup. |
| Inline `inactive:` + `{block}` re-parents body | pkg/config/parser.go | **DROP** | Review's own gate: PASS (requires malformed input, inert). |
| Zeroize test seam parallelism / EISDIR spurious error / root-revocation pin | pkg/grpcapi zeroize | **DROP** | Test-infra + informational; not a production defect. |
| ~146 PASS/NEGATIVE (CLI/DDNS/DHCP/deploy/dist/image/policymatch/scheduler/…) | — | **DROP** | Proven-sound in the review; no action. |

## Notes
- The material next-hop validation gaps (#5726) are the campaign's expected "single-digit new" outcome; codex-182 covered config/routing but missed the qualified-next-hop / ECMP-list residuals of the #2448 commit-validation doctrine.
- No tracker was commented on. No source edited/committed/pushed.
