# Triage Result — ps-review-036 (Cohorts 12-14: CLI/REST/gRPC + Wire/Protocol + Config Parser + DHCP/RA/Flowexport/LLDP)

## Header
- **Review**: ps-review-036, Cohorts 12-14 (auditor: ps / model "spark"), 4th pass over this surface.
- **Review base**: 33b891d11 (Merge #4563 fix/4562-navpath-descent).
- **Triaged against**: `origin/master` = **bfe83c531bd79a3c47bf28eb694ee6a574cab314** (fetched this run).
- **Base freshness**: base 33b891d11 is ~3 commits behind current master (0b4109522 VRRP/cluster/nat64 wave + merges). STALE-BY-3 but the cohort-12-14 surface (RA / config parser / CLI / REST / gRPC / DHCP / LLDP / flowexport) is UNTOUCHED by those 3 commits, so no stale-base false-opens here. All cited symbols re-verified on current master.
- **Real bpfrx code, not avacado fork**: every cited path resolves in bpfrx (`pkg/ra`, `pkg/cli`, `pkg/api`, `pkg/grpcapi`, `pkg/config`, `pkg/dhcp*`, `pkg/lldp`, `pkg/flowexport`, `userspace-dp/src/protocol`). No confabulation tells. One MINOR path slip in the review (it cites `pkg/config/types_ra.go` for the RA fields; they actually live in `pkg/config/types_routing.go:346-347`) — symbol exists, finding holds.
- **Nature of this review**: it is itself a self-triaged verification pass. It re-confirms 11 already-merged fixes as still-present, documents 22 load-bearing NEGATIVE (fail-closed) results, and raises exactly **ONE novel finding** (5.1, LOW). My job on this 4th pass: HARD-verify the one novel claim + spot-confirm the dedup is honest.

### Outcome counts
- **GENUINE-RESIDUAL (NOVEL)**: 1 — RA configEqual omits ReachableTime/RetransTimer (LOW).
- **ALREADY-FIXED (re-verified on master)**: 11 (review §3.1-§3.11).
- **NEGATIVE (verified fail-closed / correct)**: 22 (review §5.2 N-01..N-22, plus the §4 module sweeps).
- **CONFABULATED**: 0.
- **NOT-MATERIAL / refuted**: 0 (the one non-fixed finding is genuine, not refuted).

---

## THE NOVEL FINDING — GENUINE-RESIDUAL (verify HARD)

### 5.1 [LOW] RA `configEqual` does not compare `ReachableTime` / `RetransTimer` — day-2 edit of those knobs does not restart the sender → stale RA on wire

**Disposition: GENUINE-RESIDUAL — NOVEL. Not a dup of #4307, not already-fixed, symbol confirmed on current master.**

**Full verification trace (current master bfe83c531):**
1. **Fields exist** — `pkg/config/types_routing.go:346-347`:
   `ReachableTime int // reachable-time (ms), 0 = unspecified` / `RetransTimer int // retransmit-timer (ms), 0 = unspecified`. Populated by compiler at `pkg/config/compiler_protocols.go:840,846`.
2. **buildRA reads them** — `pkg/ra/sender.go:718-719`:
   `ReachableTime: time.Duration(s.cfg.ReachableTime) * time.Millisecond` / `RetransmitTimer: time.Duration(s.cfg.RetransTimer) * time.Millisecond`. This is the #4307 wire-stamping fix; verified present, pinned by `sender_marshal_4307_test.go`.
3. **configEqual OMITS them** — `pkg/ra/ra.go:797-840`. The scalar comparison list ends at `SourceLinkLocal`; the only deep compares are `Prefixes` and `DNSServers`. `git show origin/master:pkg/ra/ra.go | grep ReachableTime|RetransTimer` → **NONE in ra.go** (Manager never references the fields at all).
4. **Apply gates restart on configEqual** — `pkg/ra/ra.go:282`:
   `if ok && !existing.dead() && configEqual(existing.cfg, cfg) { continue }` → when equal, the sender is left running unchanged with its OLD cfg. No other code path in `pkg/ra/*.go` triggers a restart on a ReachableTime/RetransTimer delta (confirmed by grep — the fields appear only in sender.go + tests).

**Failure scenario (input → wrong output):**
- Commit A: `set protocols router-advertisement interface ge-0-0-0 reachable-time 0 retransmit-timer 0`. Sender runs, wire carries reachable-time=0, retrans-timer=0.
- Commit B (day-2, changes ONLY these): `set ... reachable-time 1000` / `retransmit-timer 5000` → commit → `Manager.Apply` → `configEqual(old,new)` compares Interface..SourceLinkLocal + Prefixes + DNSServers, none differ → returns **true** → `continue` → old sender kept, new 1000/5000 **never advertised**. Hosts keep using stale ND timings until an unrelated RA-field edit (which DOES flip configEqual) or a daemon restart.

**Strong corroboration this is a real bug class the codebase already guards:** the `#4119` comment INSIDE configEqual (ra.go, just above `DefaultLifetimeSet`) reads: *"otherwise an unset→'default-lifetime 0' edit would not restart the sender and the wire would keep advertising 1800."* That is EXACTLY this failure mode — a config field that buildRA stamps but configEqual didn't track. #4119 fixed it for the lifetime set-flag; #4307 later added ReachableTime/RetransTimer to buildRA but did **not** extend configEqual. So the residual is the identical omission the author already recognized as a bug for a sibling field.

**Dedup evidence:** `gh issue list --state all --search "RA configEqual"` and `"configEqual reachable-time retransmit"` → no matching issue. #4307 (fable-review-167 I-2, CLOSED) is the wire-stamping fix, NOT change-detection. #2865 (CLOSED) is the dead-sender rebuild path, unrelated. Not in the review's own /tmp/all_findings.txt (272 entries) per the review's dedup note. NOVEL.

**Severity justification — LOW (agree with review, not dismissible):**
- **Exploitability / trigger**: config-authoring only. Requires an operator to commit a day-2 change touching ONLY reachable-time or retransmit-timer with no other RA field change. Not remote, not attacker-controllable, not a crafted packet.
- **Blast radius**: RFC 4861 §4.2 ND host optimization hints (host reachable-time, retransmit interval). Wrong values do NOT bypass any security policy, do NOT alter forwarding, do NOT drop the prefix/default-route. Hosts merely keep using stale ND timing hints. It is a silently-unenforced control + Junos-parity gap (Junos applies these live), not a fail-open.
- **Bounding factors**: self-healing — any later commit that changes ANY other RA field flips configEqual→false→restart→new values take effect; a daemon restart also re-reads the new cfg. So the divergence window closes on the next unrelated RA edit.
- **Why not higher**: no forwarding/security impact, self-healing, config-authoring trigger only. **Why not lower / not dismissed**: it IS a genuine "commit clean = enforced" contract violation, no warning is emitted, and the codebase already treats this exact class as a fix-worthy bug (#4119). It deserves a tracked LOW issue, not a drop.

**Fix direction** (from review, sound): add `a.ReachableTime != b.ReachableTime || a.RetransTimer != b.RetransTimer` to the scalar list in `pkg/ra/ra.go:~805`, plus a configEqual unit test with two configs differing only in those two fields → expect false → restart. One-liner, same pattern as the surrounding fields. Follow-up to #4307.

---

## ALREADY-FIXED — re-verified present on current master (review §3)

Each confirmed by `git show origin/master:<path>` this run. Symbol/file:line proving the case is closed:

| # | Finding | Fixing PR(s) | Closing symbol on master |
|---|---------|--------------|--------------------------|
| 3.1 | DHCP renewalTimers int64 overflow | #4526/#4531 | `pkg/dhcp/commit.go` `t2Remaining = leaseTime / 8 * 3` (divide-first, no intermediate > lease); infinite-lease sentinel test pinned |
| 3.2 | RA randomAdvInterval 0 hot-loop | #4525/#4528 | `pkg/ra/sender.go` `minAdvInterval = 1s` + `if d < minAdvInterval { d = minAdvInterval }`; `sender_interval_4525_test.go` |
| 3.3 | navigatePath intermediate descent (display-set drop) | #4562/#4563 | `pkg/config/ast.go` `unionChildren(matched)` in BOTH multi-key + single-key branches |
| 3.4 | Lexer bracket stripping stack overflow | #4530 (fable-164 H-2) | `pkg/config/lexer.go` `[`/`]` → `l.advance(); continue` loop (O(1), no `return l.Next()` recursion) |
| 3.5 | Parser maxParseDepth unbounded recursion | fable-164 H-2 | `pkg/config/parser.go` `const maxParseDepth = 256` + `skipToBlockClose` iterative drain |
| 3.6 | isIdentChar `@` ride-along regression | #4530 | `pkg/config/lexer.go:289-297` isIdentChar — `'@'` **absent** (grep count 0 this run); `SENTINEL@` #4099 fail-closed preserved |
| 3.7 | Monitor filter quote-bypass (H-01) | #4556 N-01 / #4561 | `pkg/cli/cli_request.go:626` `monitorFilterOptionToken` peels leading `'`/`"` before `-` check |
| 3.8 | Rollback n=0 wrong slot (M-01) | #4556 M-01 / #4561 | REST `pkg/api/config.go:362` + gRPC `pkg/grpcapi/server_config.go:330` both reject `n<=0` with "rollback index must be a positive integer" |
| 3.9 | writeJSON truncated-200 on marshal fail (M-02) | #4541/#4545 | `pkg/api/api.go:60` `json.Marshal` to buffer FIRST, header only after success; 500 static body on error |
| 3.10 | Monitor interface keyword-as-value / missing value | #4540/#4545 | `pkg/cli/cli_request.go` `parseMonitorTrafficArgs` keyword+numeric guards |
| 3.11 | Monitor traffic tcpdump argv injection (13-02) | #4524/#4527 | `pkg/cli/cli_request.go:607` `"--"` end-of-options separator before filter + `validateMonitorFilter` |

Also cross-checked in §3/§4 and confirmed on master: `validateMultiValueLeaf` `to`-gate behind `rangeSeparator` (`pkg/config/schema_walk.go:681`, #4556 L-01/#4561); REST basic-auth constant-time (`pkg/api/auth.go:103` `constantTimeAPIKeyMatch` OR-fold + line 82 always-run Basic compare, #4157); gRPC `maxRecvMsgSize = 16<<20`; Rust `MAX_CONTROL_REQUEST_BYTES = 64 MiB` (#2744); `null_tolerant_vec` (#2214/#1961). None re-openable.

---

## NEGATIVE — verified fail-closed / correct (review §4 sweeps + §5.2 N-01..N-22)

The review documents 22 explicit negative results proving audit depth; I did not re-derive all 22 line-by-line (they restate already-merged fixes verified above), but spot-confirmed the load-bearing security ones and found no contradiction:
- **DHCP relay** (§4.2): hop-count check BEFORE `++` (uint8-wrap-safe, #4309); rogue-reply source filter fail-closed (#4163); raw-L2 unicast to yiaddr with UDP-csum-0 (#2076). NEGATIVE — no residual.
- **RA** (§4.3): prefix pref>valid clamp-down (RFC 4862 §5.5.3); pruneUnmarshalableOptions (#3895); #2033 single-owner lifecycle. NEGATIVE.
- **Flowexport** (§4.4): collectorWriteTimeout 2s + unhealthyProbeInterval 30s + flowBatch cap 65536 drop-newest (#4423 H07/#3747/#2464). NEGATIVE.
- **LLDP** (§4.5): maxNeighborsPerInterface 64 (#4044), sanitizeTLVString control-strip (#4043), mandatory-TLV gating (#2551), PACKET_OUTGOING filter (#2992). NEGATIVE.
- **CLI/REST/gRPC/wire/parser** (§4.6-4.9): RBAC monitor-traffic=PermControl / request-maint=PermMaint (#4067/#4108), secret redaction (#4051), SSE category fail-closed (#3383), quoteKey round-trip (#3854), inactive: marker (#4348). NEGATIVE.

All are correct fail-closed guards on current master. No new bug surfaced by the negative sweep.

---

## Method note
- Base is 3 commits behind master but the 3 commits (VRRP/cluster/nat64) do not touch cohort-12-14 files — verified by inspecting the actual cited files on `origin/master`, not the review's "confirmed". No stale-base false-opens.
- This is the 4th pass over a heavily-fixed surface; consistent with the task's expectation, the outcome is 11 already-fixed re-verifications + 22 negatives + exactly ONE genuine novel LOW. The review did NOT over-scope severities — it correctly self-rated its one finding LOW and did not inflate any negative into a finding.
- The one novel finding is a change-detection residual of the #4307 wire fix, corroborated by the codebase's own #4119 comment recognizing the identical bug class for a sibling field. Weight-verified HARD (fields + buildRA + configEqual + Apply-gate all traced on current master); it is real and material-as-LOW, not refuted.

*Read-only triage. No source files modified. No PRs opened. /tmp/.researched-* left for parent to mark.*
