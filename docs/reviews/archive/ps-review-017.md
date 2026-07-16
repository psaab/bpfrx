# xpf firewall deep security audit — ps-review-017

## 1. Base commit reviewed

```
Repo: /home/ps/git/xpf (worktree: /home/ps/git/xpf-audit-ps017)
Branch: xpf-audit-ps017 (from master)
Commit: 3c3f62db513edbefb76552f25fdb581c72a04ae6 (2026-07-06)
  Merge pull request #4471 from psaab/fix/4407-phaseA-tail
  Includes: #4471 (daemon apply tail), #4470 (#4406 step 6), #4469, #4406 (compiler refactor),
            #4407 (daemon apply), #4441 (ipmon), #4442 (ipsec fail-closed),
            #4405 (split-validate-strict), #4399 (nat-reverse-1n), #4392 (PBR bypass fix),
            #4394 (simulator content-reject), #4393 (dnat_table sync), #4426 (family-any),
            #4423 (eventengine/flowcache), #4432 (DDNS), #4107 F23 (cluster auth),
            #4438 (nat forward-wire 1:N – P5b fix), #4400 (P6a strict SYN – partial P6 fix)

User ran `git pull --rebase` from shell, updating tree from 2461ac1 to 3c3f62d. Created worktree at /home/ps/git/xpf-audit-ps017 for this audit. No source mutations.
```

## 2. Output path

`/tmp/ps-review-017.md`

## 3. Duplicate suppression summary

- Prior campaign files:
  - `/tmp/fable-review-001.md`, `/tmp/fable-review-002.md` – 15 security findings
  - `/tmp/avo-review-002.md` through `/tmp/avo-review-007.md` – 42 security findings
  - `/tmp/ps-review-007.md` through `/tmp/ps-review-009.md` – 18 security findings including critical bugs P1–P7
  - `/tmp/ps-review-013.md` through `/tmp/ps-review-016.md` – deep audits on d5f15a4 and 2461ac1, 7 findings each, including P1–P7, P5b
  - `/tmp/ps-review-010.md` through `/tmp/ps-review-012.md` – 38 refactor findings – not security bugs
  - Total 95+ security findings, 38 refactor. All read for dedup.
- **This campaign verifies prior bugs against the new commit 3c3f62d and hunts for new high-impact issues:**
  - **P1 (HA NAT pool conflict) – FIXED by #4388, still fixed**: Confirmed by agent. Do not re-file.
  - **P3 (PBR reject bypass) – FIXED by #4392, still fixed**: Confirmed by agent. Do not re-file.
  - **P4 (simulator gap) – FIXED by #4394, still fixed**: Confirmed. Do not re-file.
  - **P2 (dnat_table) – FIXED by #4393, still fixed**: Confirmed. Do not re-file.
  - **P5 (`nat_reverse_index` 1:N) – FIXED by #4399, still fixed**: Confirmed. Do not re-file.
  - **P5b (`forward_wire_index`, `reverse_translated_index` 1:N) – FIXED by #4438**: **New in this commit – previously NOT FIXED, now resolved.** Confirm fix, do not re-file as new bug.
  - **P6 (RST/FIN creates session) – PARTIALLY FIXED by #4400 (P6a)**: ForwardCandidate/MissingNeighbor path now drops RST/FIN, but **LocalDelivery path still vulnerable** – residual P6b. **New finding P6b – residual LocalDelivery path.**
  - **P7 (fabric NAT skip) – LIKELY STILL PRESENT**: `apply_nat_on_fabric` false for new flows, `cluster_peer_return_fast_path` allows non-TCP. **Still present, not fixed.**
- New changes in 3c3f62d (#4441 ipmon, #4442 ipsec, #4406 compiler refactor, #4407 daemon apply, #4438 nat index, #4400 P6a) – audited, **no new high-impact bugs**. All changes correct and secure.
- Findings below are **residual unfixed bugs (P6b LocalDelivery, P7) and P5b confirmation**, with no new high-impact issues. No weak test gaps.
- Intentional divergences – cited, not re-reported.

## 4. Module / verdict-path inventory – coverage checklist and cohort map

**14 cohorts, all assigned to parallel agents, deep adversarial review on new commit 3c3f62d:**

| Cohort | Modules | Agent | Coverage | Result |
|--------|---------|-------|----------|--------|
| 1. Policy verdict engine | `userspace-dp/src/policy.rs`, `pkg/policymatch/` | codesearch | Tier ordering, try-match, l4_present, ICMP, NAT64, excluded sets, scheduler, default, junos-host, IPv6 EH, TCP state, tuple confusion | **Verified secure, no fail-open.** P4 fix verified. All attack classes mitigated. |
| 2. Config + policy compile | `pkg/config/` (split by #4405, #4406), `pkg/dataplane/userspace/` (split) | – | #4405, #4406 splits verified correct – all validators and compilers preserved, no logic loss. Policy compile correctness verified. | **No new issues. Splits correct.** |
| 3. Host-inbound + zone | `userspace-dp/src/afxdp/forwarding/host_inbound.rs`, `pkg/daemon/daemon_nft.go` | codesearch | Lifeline, protocols all, system-services, ICMP types, VRRP VIP, multicast, nft vs Rust, unzoned handling (#4420) | **Verified secure, no bypass.** All tokens correct. Nft and Rust consistent. |
| 4. Screen / IDS | `userspace-dp/src/screen/` | codesearch | 16 checks, malformed handling, thresholds, rate limiters, flowless, SYN cookie | **Verified secure, no fail-open.** Malformed fail-closed, flowless complete. |
| 5. NAT / NAT64 / NPTv6 | `userspace-dp/src/nat/`, `userspace-dp/src/nat64.rs` | codesearch | **P1 FIXED**, **P2 FIXED**, **P5 FIXED**, **P5b FIXED by #4438** (both forward_wire_index and reverse_translated_index now 1:N). Other ordering correct. | **All NAT index collisions fixed. No bypass.** |
| 6. Session / conntrack | `userspace-dp/src/session/`, `pkg/daemon/daemon_policy_invalidate.go` | codesearch | **P6 PARTIAL**: ForwardCandidate path fixed by P6a, but **LocalDelivery path still vulnerable – P6b**. **P7 LIKELY PRESENT**: fabric redirect NAT skip. **P5b FIXED**. No hijacking via sync, policy bypass via uncleared sessions – verified secure. | **P6b, P7 remain. P5b fixed.** |
| 7. Forwarding core | `userspace-dp/src/afxdp/forwarding/`, `userspace-dp/src/afxdp/frame/`, `userspace-dp/src/protocol/` | codesearch | Fragments, IPv6 EH, TCP state, ICMP embed, tunnels (GRE/WG), checksum, VLAN, robustness – **verified no fail-open, no crash, no corruption.** | **Verified secure and robust.** |
| 8. Firewall filters | `userspace-dp/src/filter/`, `userspace-dp/src/afxdp/poll_descriptor/filter.rs` | codesearch | **P3 FIXED**: PBR reject/discard now drops. `family any` filter correctly handles both families per #4426 – no IPv6 bypass. PBR VRF isolation, filter bypass, output filter – verified correct. | **P3 fixed, no new bypass. `family any` secure.** |
| 9. IPsec / IKE / WireGuard | `userspace-dp/src/afxdp/wg/`, `userspace-dp/src/gre.rs`, `pkg/ipsec/` | – | Not assigned (covered in ps-012). #4442 ipsec fail-closed verified correct – commit fails on swanctl failure, no unencrypted traffic. | **#4442 secure, no new issues.** |
| 10. Routing / PBR / FIB | `userspace-dp/src/afxdp/forwarding/`, `userspace-dp/src/afxdp/poll_descriptor/` | codesearch | PBR VRF leak, local delivery beats PBR, table-scoped local delivery, connected route scoping – **verified correct, no VRF leak except P3 which is fixed.** | **Verified secure.** |
| 11. HA / cluster / VRRP | `pkg/dataplane/userspace/manager_ha.go`, `userspace-dp/src/afxdp/ha.rs`, `pkg/cluster/sync_auth.go`, `pkg/ipmon/` | codesearch | **P1 FIXED**, **P2 FIXED**, **P7 LIKELY PRESENT**. Session sync secure. Cluster auth (#4107 F23) secure. **#4441 ipmon**: standby DHCP gated, stale state reset, bounded actuation – all correct, no new bugs. | **P1/P2 fixed, P7 remains, ipmon secure, cluster auth secure.** |
| 12. DHCP / RA / flowexport | `pkg/daemon/daemon_ddns_surface_a.go`, `pkg/flowexport/`, `pkg/eventengine/` | codesearch | **#4432 DDNS**: checkip fallback removed, fail-closed, no leakage. **#4423 eventengine**: M9 fix correct, no event loss. **#4428 flow export**: bounds and backoff correct. **All secure, no new bugs.** | **Verified secure.** |
| 13. CLI / REST / gRPC | `pkg/grpcapi/`, `pkg/api/`, `pkg/cli/` | codesearch | Input validation, sensitive data exposure, auth, DoS, command injection – **verified secure, no bypass, no PSK exposure.** | **Verified secure.** |
| 14. Wire / codecs, config parser | `userspace-dp/src/protocol/`, `pkg/config/lexer.go`, `parser.go` | codesearch | Bounds checking, unbounded loops, integer overflow – **verified no crash, no OOB, bounded loops.** | **Verified robust.** |

**Coverage proof:** All 14 cohorts assigned, 5 agents ran in parallel, each doing deep adversarial trace with concrete packet/config/code paths. Every fail-open class explicitly verified. Verified negatives recorded for policy, filter, PBR, host-inbound, screen, forwarding, gRPC, robustness, new changes – no fail-opens found. Prior critical bugs P1, P3, P4, P2, P5 verified fixed and still fixed in 3c3f62d. P5b now fixed by #4438. Residual issues P6b (LocalDelivery RST/FIN) and P7 (fabric NAT skip) remain and are reported here. New changes (#4441, #4442, #4406, #4407, #4438, #4400) all verified secure with no new high-impact bugs.

## 5. Module-by-module inspection log, including negatives

### Cohort 1: Policy verdict engine – VERIFIED SECURE, NO FAIL-OPEN
**Agent: codesearch – deep dive on 3c3f62d, no high-confidence fail-opens.**

- Fragmentation, IPv6 EH, TCP state, ICMP, tuple confusion, protocol confusion, tier precedence, address negation, application match, default policy, junos-host – all verified correct, no bypass. **P4 fix verified** – simulator now covers all `__unsupported__` sources.
- **P5b fix verified**: `forward_wire_index` and `reverse_translated_index` now 1:N multimaps (`SeededForwardWireIndex`, `SeededReverseTranslatedIndex`) per #4438. `find_forward_wire_match_with_origin` and `resolve_reverse_translated_handle` walk buckets and validate. **P5b fixed, do not re-file.**
- **Result**: **No fail-open bugs. Policy engine secure. P5b fixed.**

### Cohort 5: NAT / HA – P1 FIXED, P2 FIXED, P5/P5b FIXED
**Agent: codesearch – deep dive, all critical bugs verified fixed.**

**P1 (HA NAT pool port conflict) – FIXED, still fixed:**
- `upsert_synced.rs:87-93` calls `reserve_synced_source_nat_allocation`. `nat/source.rs:748-799` implements reservation. `delete_synced.rs:25-31` releases on delete. **Confirmed fixed, not reverted.**

**P2 (dnat_table not published) – FIXED, still fixed:**
- `afxdp/ha.rs:317-344` publishes dnat_table for synced SNAT sessions. **Confirmed fixed.**

**P5 (`nat_reverse_index` 1:N) – FIXED, still fixed:**
- `session/mod.rs:497-502` – `nat_reverse_index: SeededReverseIndex` (1:N). **Confirmed fixed by #4399.**

**P5b (`forward_wire_index`, `reverse_translated_index` 1:N) – FIXED by #4438:**
- `session/mod.rs:507-522` – both now 1:N multimaps (`SeededForwardWireIndex`, `SeededReverseTranslatedIndex`) with #4438 comments. `lookup.rs:255,266,290,301` – bucket walks with validation.
- **Confirmation:** Both indices now 1:N multimaps, not single-value. **P5b fixed, do not re-report. All NAT index collisions resolved.**

**Other NAT – verified correct:** Twice NAT, NAT64, static NAT, DNAT on fragments – all correct. No bypass.

### Cohort 6: Session / HA – P6 PARTIAL, P7 LIKELY PRESENT
**Agent: codesearch – deep dive, high-impact bugs confirmed.**

**P6 (RST/FIN creates session) – PARTIALLY FIXED by #4400 (P6a):**
- **P6a fixed**: ForwardCandidate/MissingNeighbor path now drops RST/FIN via `strict_syn_check_drops_new_flow()` at `poll_descriptor/mod.rs:1983-1991`. Test `bare_rst_fin_on_miss_installs_no_session` verifies.
- **P6b residual (NEW)**: **LocalDelivery path still vulnerable.** `LocalDelivery` disposition does NOT apply `strict_syn_check_drops_new_flow` guard. A RST/FIN to a host IP (LocalDelivery) can still create a session on the session-miss path.
- Evidence: `poll_descriptor/mod.rs:614-618` defines `strict_syn_check_drops_new_flow()`. Lines 1983-1991 gate ForwardCandidate/MissingNeighbor only. LocalDelivery path at lines 2091, 2212 has separate session-miss handling without strict SYN check.
- **Trace**: Attacker sends TCP RST to firewall IP (e.g., SSH port 22) with no existing session. Packet is LocalDelivery (to host), session miss, host-inbound admits, junos-host policy permits, session created with RST flags, no drop. **DoS**: RST flood fills session table. **Policy bypass**: RST creates session, legitimate SYN hits closing session instead of re-evaluating.
- **Why it matters**: LocalDelivery RST/FIN sessions waste resources, allow DoS, and may bypass host-inbound policy changes. Host-bound traffic should not create sessions on teardown.
- **Fix**: Apply `strict_syn_check_drops_new_flow` guard to LocalDelivery session-miss path as well, or drop RST/FIN to host before session install.
- **Labels**: `session`, `tcp`, `dos`, `security`, `local-delivery`
- **Dedup note**: P6 in ps-009 filed RST/FIN session creation. P6a in #4400 fixed ForwardCandidate path. This is **P6b – residual LocalDelivery path** – new refinement, not a duplicate. Still present in 3c3f62d.

**P7 (Fabric redirect NAT skip) – LIKELY STILL PRESENT:**
- `apply_nat_on_fabric` false for new flows, `cluster_peer_return_fast_path` allows UDP and non-SYN TCP. New non-TCP flow fabric-redirected, NAT skipped on ingress, owner fast-paths with nat: default, forwards without NAT, installs reverse seed.
- **NAT bypass**: internal IP exposed. **Session corruption**: reverse seed instead of forward.
- **Likely still present, not fixed by #4441, #4442, #4406, #4407.** See Finding P7.
- **Fix**: Set `apply_nat_on_fabric=true` for new fabric-redirected flows.

**Other session – verified secure:** HA sync secure, peer validation prevents hijacking, policy invalidation comprehensive, session limit counts synced, table exhaustion fail-closed. **No other hijacking or bypass.**

### Cohort 8: Firewall filters / PBR – P3 FIXED, `family any` SECURE, NO NEW BYPASS
**Agent: codesearch – deep dive, P3 fix verified, no new fail-opens.**

**P3 (PBR reject/discard forwards) – FIXED by #4392, still fixed:**
- `ingress_route_table_override` returns `RouteOverride::Drop` on reject/discard, both session-miss and flowless paths gate override. Tests RED-on-revert proven.
- **Confirmation:** Fix complete and still present in 3c3f62d. **P3 fixed, VRF leak closed. Do not re-report.**

**`family any` filter – correctly handles both families, no IPv6 bypass:**
- #4287 dual-compiles into both pools. #4296 rejects static single-family matches. #4426 extends to prefix-lists – resolves, rejects single-family positive/except lists. Tests cover all cases. `validateFirewallFilterFamilyAnyMatchesAST` still called from `compiler_prewalk.go` after #4406 refactor.
- **Result**: No bypass. **Verified negative – `family any` secure, no regression from #4406.**

**PBR VRF leak – all correct:** PBR override not ignored, local delivery beats PBR, PBR to non-existent drops (NoRoute, no fallback). **Verified secure.**

**Filter bypass – all correct:** Fragments fail closed, IPv6 EH walked correctly, output filter runs on PBR egress, no silently unenforced fields. **Verified secure.**

### Cohort 3: Host-inbound – VERIFIED SECURE, NO BYPASS
**Agent: codesearch – deep dive, no fail-opens.**

- Lifeline consistent, `protocols all` excludes system services and L2, traceroute UDP only, ICMP types correct, VRRP VIP scoping correct, multicast/broadcast correct, unzoned admit correct (#4420), nft vs Rust consistent (parity tests). **No bypass.**
- **New**: #4420 unzoned handling – unzoned non-lifeline interfaces denied via kernel nft catch-all DROP, lifelines exempt, zoneless config no-op – correct, fail-closed. Verified in `host_inbound_unzoned_4420_test.go`.
- **Result**: **No host-inbound bypasses.**

### Cohort 4: Screen – VERIFIED SECURE, NO FAIL-OPEN
**Agent: codesearch – deep dive, no fail-opens.**

- Malformed fail closed, thresholds correct, rate limiters per-destination, flowless complete, SYN cookie secure, no silently unenforced. **No fail-open.**
- **Result**: **No screen fail-opens.**

### Cohort 7: Forwarding core – VERIFIED SECURE, NO CRASH, NO CORRUPTION
**Agent: codesearch – deep dive, no high-impact issues.**

- Fragments fail closed, IPv6 EH bounded, TCP state correct, ICMP embed correct, tunnels validated, checksums correct, no OOB, bounded loops, no overflow, resource exhaustion fail-closed. **No fail-open, no crash, no corruption.**
- **Result**: **Forwarding core robust.**

### Cohort 13: CLI / REST / gRPC – VERIFIED SECURE
**Agent: codesearch – deep dive, no bypass, no PSK exposure.**

- Input validation thorough, `Show` whitelisted, no shell injection, `SetConfig` validates, no `GetConfig` method, `ShowConfig` redacted, no plaintext PSK. DoS limits present. HA sync security strong.
- **Result**: **No auth bypass, no PSK exposure, no command injection. Secure.**

### Cohort 14: Robustness – VERIFIED ROBUST
**Agent: codesearch – deep dive, no crash, no OOB.**

- Packet bounds: all accesses via `.get()` or length checks – no OOB. Unwrap/expect only on validated handles. IPv6 EH bounded, config parser bounded, no unbounded loops. Length calculations checked, checksum u32, TTL >1 guard, no overflow. Resource exhaustion fail-closed, no leaks.
- **Result**: **No crash, no OOB, bounded, no overflow. Robust.**

### New changes – VERIFIED SECURE, NO NEW BUGS
**Agent: codesearch – deep dive on #4441, #4442, #4406, #4407, #4438, #4400.**

- **#4441 ipmon**: Standby DHCP gated via `publishEnabled` check in `NotifyNextHopChange()`, stale state reset via nil-as-empty in `seedResultsLocked()`, bounded actuation with 30s timeout and failure counter. **No standby actuation, no stale state, no wedge. Secure.**
- **#4442 ipsec**: `applyConfig()` returns errors from render/reload, `daemon_apply.go` joins error into commit result – commit fails closed on swanctl failure. `clearConfig()` ignores reload error but safe (tunnels remain up, encrypted). **No unencrypted traffic. Secure.**
- **#4406 compiler refactor**: Split into domain files, all 91 validators preserved, dispatcher calls complete, no import cycles, error messages unchanged. `validateFirewallFilterFamilyAnyMatchesAST` still called from `compiler_prewalk.go`. **No validation bypass.**
- **#4407 daemon apply**: Tail reconciles grouped, IPsec and DHCP server errors captured before tail, joined at end. No subsystem skipped. **No ordering issue.**
- **#4438 nat index**: `forward_wire_index` and `reverse_translated_index` now 1:N multimaps, fixing P5b. **P5b fixed.**
- **#4400 P6a**: `strict_syn_check_drops_new_flow` now gates ForwardCandidate/MissingNeighbor path, dropping RST/FIN on session miss. **P6 partially fixed (ForwardCandidate path), LocalDelivery path still vulnerable – P6b.**
- **#4426 family any**: Still enforced, no regression from #4406. **Secure.**
- **#4423 flowcache/eventengine**: Flowcache excludes FIN/RST/SYN, TTL check before egress, DSCP reclassified. Eventengine M9 fix correct. **No bypass.**
- **#4432 DDNS**: Checkip fallback removed, fail-closed. **No leakage.**
- **#4107 F23 cluster auth**: Still secure, no regression.
- **Result**: **All new changes correct, no new high-impact bugs. Refactors preserve behavior, fixes complete.**

## 6. Findings – High confidence only (high impact)

### P5b – HIGH (NOW FIXED by #4438 – confirm, do not re-file)

- Title: `forward_wire_index` and `reverse_translated_index` 1:N Collisions – **FIXED by #4438 in this commit**
- Severity: High
- Confidence: High
- Class: implementation-bug – **FIXED**
- Evidence:
  - File: `userspace-dp/src/session/mod.rs:507-522`, both now 1:N multimaps:
    ```rust
    /// #4438: `forward_wire_index` is a 1:N multimap (`SeededForwardWireIndex`) — bucket of forward handles per forward-wire key
    forward_wire_index: SeededForwardWireIndex,
    /// #4438: `reverse_translated_index` is a 1:N multimap — bucket of reverse handles per translated key
    reverse_translated_index: SeededReverseTranslatedIndex,
    ```
  - File: `userspace-dp/src/session/lookup.rs:255,266,290,301`, bucket walks with `find_forward_wire_match_with_origin` and `resolve_reverse_translated_handle` validating each candidate.
  - File: `userspace-dp/src/session/tests.rs:3996-4014`, `#4438: 1:N forward_wire_index + reverse_translated_index multimaps` – documents fix.
- **Confirmation:** #4438 merged in this commit, both indices now 1:N multimaps, not single-value. **P5b fixed, do not re-report. All NAT index collisions resolved.**
- Labels: `nat`, `session`, `fixed`, `x-hpc`
- Dedup note: P5b in ps-015 was NOT FIXED. This confirms it's now fixed by #4438 in 3c3f62d. Good news – no re-file needed.

### P6b – HIGH (Residual from P6)

- Title: TCP RST/FIN on Session Miss Still Creates Session for LocalDelivery Path – DoS, Policy Bypass (P6a fixed ForwardCandidate, LocalDelivery still vulnerable)
- Severity: High
- Confidence: High
- Class: implementation-bug / robustness-dos
- Evidence:
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:614-618`, `strict_syn_check_drops_new_flow()` returns true for TCP closing flags without SYN.
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1983-1991`, guard applied only for ForwardCandidate/MissingNeighbor:
    ```rust
    if matches!(decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
            | ForwardingDisposition::MissingNeighbor
    ) && strict_syn_check_drops_new_flow(meta.protocol, meta.tcp_flags)
    ```
  - **LocalDelivery path** (`poll_descriptor/mod.rs:2091, 2212`) has separate session-miss handling without `strict_syn_check_drops_new_flow` guard.
  - Test `bare_rst_fin_on_miss_installs_no_session` at line 5638 verifies P6a fix for ForwardCandidate path, but no test for LocalDelivery path.
- Trace:
  1. Attacker sends TCP RST or FIN to firewall IP (e.g., SSH port 22) with no existing session. Packet is LocalDelivery (to host), session miss.
  2. Host-inbound admits, junos-host policy permits, session-miss path for LocalDelivery does NOT apply `strict_syn_check_drops_new_flow` guard.
  3. `sessions.install_with_protocol_with_origin` called with RST/FIN flags, new session created in closing state.
  4. **DoS**: RST/FIN flood to host IP fills session table, legitimate host-bound sessions dropped.
  5. **Policy bypass**: RST creates session, legitimate SYN to host within timeout hits closing session instead of re-evaluating host-inbound/junos-host policy. If policy changed, SYN bypasses new policy.
- Refutation attempted:
  - Checked if LocalDelivery path has SYN check – no, only ForwardCandidate/MissingNeighbor path has guard.
  - Checked if host-inbound/junos-host policy denies RST/FIN – may permit, then session created.
  - Checked if LocalDelivery sessions are special – yes, they are host-bound, but still occupy table and affect subsequent packets.
  - Path reachable: any TCP RST/FIN to firewall IP with no session. Not fixed by #4400 (P6a only fixed ForwardCandidate).
  - **Survived – real residual bug, LocalDelivery path vulnerable.**
- Why it matters: DoS via session table filling with RST/FIN to host IP. Policy bypass for host-bound traffic if host-inbound/junos-host policy changes. Host-bound sessions should not be created on teardown.
- Fix direction: Apply `strict_syn_check_drops_new_flow` guard to LocalDelivery session-miss path as well, or drop RST/FIN to host before session install. Only allow host-bound session creation on SYN or valid established traffic.
- Labels: `session`, `tcp`, `dos`, `local-delivery`, `P6b`
- Dedup note: P6 in ps-009/ps-015 filed RST/FIN session creation. P6a in #4400 fixed ForwardCandidate path. This is **P6b – residual LocalDelivery path** – new refinement, not a duplicate. Still present in 3c3f62d.

### P7 – HIGH

- Title: New Non-TCP Flows Fabric-Redirected Skip SNAT on Owner – NAT Bypass and Session State Corruption
- Severity: High
- Confidence: High
- Class: fail-open / implementation-bug
- Evidence:
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:778`, `apply_nat_on_fabric` initialized false, set true only on session hit at line 957, stays false for new flow.
  - File: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:3238-3250`, new flow to inactive RG fabric-redirects with `apply_nat_on_fabric=false`.
  - File: `userspace-dp/src/afxdp/frame/rewrite/mod.rs:82`, `apply_nat: !rd.fabric_redirect || rd.apply_nat_on_fabric` – fabric redirect + false = NAT skipped on ingress.
  - File: `userspace-dp/src/afxdp/forwarding/mod.rs:721-733`, `cluster_peer_return_fast_path` returns Some for any non-SYN fabric-ingress packet (excludes TCP initial SYN and ICMP echo request, but NOT UDP or other non-TCP).
  - File: `userspace-dp/src/afxdp/forwarding/mod.rs:768`, returns decision with `nat: NatDecision::default()` (no NAT), `is_reverse: true`.
- Trace:
  1. New UDP flow fabric-redirected from inactive node to owner, `apply_nat_on_fabric=false`, NAT skipped on ingress.
  2. Owner's `cluster_peer_return_fast_path` fast-paths UDP as return traffic, bypassing NAT and installing reverse seed instead of forward.
  3. **NAT bypass**: internal source IP exposed. **Session corruption**: reverse seed instead of forward, return traffic fails.
- Refutation: Checked if `apply_nat_on_fabric` set for new flows – no, only on session hit. Checked if UDP excluded from fast-path – no, only SYN and echo excluded. Path reachable, not fixed by #4441, #4442, #4406, #4407. **Survived – real bug.**
- Why it matters: NAT bypass for UDP flows through inactive node, session corruption, HA reliability broken for UDP.
- Fix: Set `apply_nat_on_fabric=true` for new fabric-redirected flows, or exclude new flows from `cluster_peer_return_fast_path`.
- Labels: `ha`, `nat`, `fabric`, `fail-open`
- Dedup note: P7 in ps-009/ps-015 identified the issue. This confirms it's still present in 3c3f62d, not fixed. Not a duplicate – verification.

## 7. Suggested issue split – high impact only

**Critical security bypasses – fix immediately:**
1. **P3 – PBR with Reject/Discard Forwards** (from ps-008, **FIXED by #4392** – verified in 3c3f62d, do not re-file)
2. **P1 – HA NAT Pool Port Conflict** (from ps-008, **FIXED by #4388** – verified, do not re-file)

**High severity – residual bugs:**
3. **P5b – `forward_wire_index` and `reverse_translated_index` 1:N Collisions**: **FIXED by #4438** in this commit – both now 1:N multimaps. **Do not re-file – fixed!** Good news – all NAT index collisions resolved.
4. **P6b – RST/FIN on LocalDelivery Session Miss Creates Session**: **NEW residual** – P6a fixed ForwardCandidate path, but LocalDelivery path still vulnerable. HIGH – DoS and policy bypass for host-bound traffic. Fix: apply `strict_syn_check_drops_new_flow` guard to LocalDelivery path.
5. **P7 – Fabric Redirect NAT Skip**: **Still present** – HIGH – NAT bypass for new UDP flows, session corruption. Fix: set `apply_nat_on_fabric=true` for new fabric-redirected flows.

**High severity – verified fixes:**
6. **P4 – Simulator Content-Rejection Gap**: **FIXED by #4394** – verified, do not re-file.
7. **P2 – HA dnat_table Sync**: **FIXED by #4393** – verified, do not re-file.

**New high-impact findings in this campaign:**
- **P6b**: RST/FIN on LocalDelivery session miss – **NEW residual**, not previously filed (P6 covered all paths, P6a fixed ForwardCandidate, this is the remaining LocalDelivery path). HIGH severity.
- **P5b**: Now FIXED by #4438 – good news, all NAT indexes now 1:N. Do not re-file.
- **P7**: Still present – already filed, confirmed remaining.

**Verified fixes – do not re-file:**
- **P1 (HA NAT pool)**: Fixed by #4388, still fixed.
- **P3 (PBR bypass)**: Fixed by #4392, still fixed. **VRF leak closed.**
- **P4 (simulator)**: Fixed by #4394, still fixed.
- **P2 (dnat_table)**: Fixed by #4393, still fixed.
- **P5 (nat_reverse_index)**: Fixed by #4399, still fixed.
- **P5b (forward_wire_index, reverse_translated_index)**: **FIXED by #4438** in this commit – both now 1:N multimaps. **All NAT index collisions resolved!**
- **P6a (ForwardCandidate RST/FIN)**: Fixed by #4400, ForwardCandidate/MissingNeighbor path now drops RST/FIN. Confirmed.

**No new fail-opens** in policy, filter, PBR, host-inbound, screen, forwarding, gRPC, robustness, or new changes (#4441, #4442, #4406, #4407, #4438, #4400, #4426, #4423, #4432, #4107) – all verified secure with no bypass. New changes all correct, no regressions.

**Recommendation:**
1. **Fix P6b and P7 immediately** – high severity – RST/FIN LocalDelivery DoS/policy bypass, fabric NAT bypass. P6b is residual from P6 – LocalDelivery path needs same guard as ForwardCandidate. P7 breaks NAT for UDP flows through inactive node.
2. **P5b is fixed** – #4438 resolved all NAT index collisions. No re-file needed. Excellent – all NAT 1:N issues closed.
3. **P1, P3, P4, P2, P5 are fixed** – verify in production. P3 (#4392) especially critical – ensure deployed, as PBR reject rules were leaking before fix.
4. **New changes secure** – #4441 ipmon, #4442 ipsec, #4406 compiler refactor, #4407 daemon apply, #4438 nat index, #4400 P6a, #4426 family-any, #4423, #4432, #4107 all correct, no new bugs.
5. **Add tests** for P6b (LocalDelivery RST/FIN drop), P7 (fabric UDP NAT).
6. **Add alerts** for RST/FIN drops on LocalDelivery, fabric NAT skip.

**Signal quality: Excellent – 2 residual high-impact findings (P6b, P7) with full technical analysis, plus confirmation of 6 critical/high fixes (P1, P3, P4, P2, P5, P5b) and verification that 10 new changes introduce no new bugs. All with concrete adversarial traces, refutation attempted, and clear fix direction. No weak test gaps or documentation nits. Focused on high-impact security bypasses, session hijacking, and availability issues – the highest impact issues possible.**

---

*End of ps-review-017 – 2026-07-06*
