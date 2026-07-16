# Triage Result — ps-review-038 DETAILED findings roll-up

**Files triaged:** `/tmp/ps-review-038-findings-part.md` (High/Med, F-038-001..013) +
`/tmp/ps-review-038-low-section.md` (Low, F-038-014..047)
**Cohort:** ps-038 "Paladin Coverage Campaign" — DETAILED per-finding roll-up of the 19 A-batches.
**Base:** verified against `origin/master` @ `3bbe3d39c` (fetched fresh; local checkout stale).
**Prior:** the 100%-dup synthesis (ps-038.md) and ALL 19 A-batches were individually triaged
earlier this session with every novel residual filed. These detailed fragments are the same
findings and were EXPECTED ~100% dup. Job: confirm nothing NOVEL + genuine slipped.

## Outcome counts (47 findings)

| Disposition | Count |
|---|---|
| DUP (filed issue, mostly MERGED) | 18 |
| Dispositioned in a recorded batch-triage (NOT-MATERIAL / DELIBERATE) | 6 |
| NOT-MATERIAL (verified bounded/unreachable this pass) | 12 |
| DELIBERATE (documented + tested behavior) | 3 |
| ALREADY-FIXED (merged PR) | 1 |
| DUP-of-deferred / low-confidence design gap | 7 |
| **NOVEL GENUINE RESIDUAL** | **0** |

**BOTTOM LINE: NO novel genuine residual. Campaign is fully covered.** Both High findings are
already-dispositioned NOT-MATERIAL and were re-verified false this pass. Every Med/Low maps to a
filed batch issue, a deferred issue, a recorded batch disposition, or resolves NOT-MATERIAL /
DELIBERATE / ALREADY-FIXED on source verification.

---

## High findings — both re-verified NOT-MATERIAL (dispositioned A5)

- **F-038-001 Manager.Start deadlock → NOT-MATERIAL (dispositioned "A5 Manager.Start-deadlock
  unreachable"; re-verified false).** `manager.go:381` `m.monitor.Stop()` runs under `m.mu`, BUT
  the poll goroutine it waits on uses the **Monitor's own** `mon.mu` (`monitor.go:185` Stop,
  `monitor.go:228` poll), NOT the Manager's `m.mu`. The finding's stated mechanism ("poll needs
  m.mu") is refuted — two different mutexes, no cross-lock. No deadlock.

- **F-038-002 handleDisconnect double-close/send-on-closed → NOT-MATERIAL (dispositioned "A5
  double-close panic-safe"; re-verified false).** Both `completeBarrierWait` (`sync_bulk.go:297-304`)
  and `handleDisconnect` (`sync_conn.go:1739-1744`) delete/nil the waiter map **under
  `barrierWaitMu`** BEFORE `close()`; a waiter removed under the lock by one path is invisible to
  the other → no double-close. Failover path clears the four failover maps under `failoverWaitMu`
  before the `select{ch<-…; default}`+`close` → no send-on-closed. Structurally panic-safe.

## Medium findings

- **F-038-003 annotate named containers → DUP #4587/#4592 (MERGED).**
- **F-038-004 journal 0644 → DUP #4579/#4603 (MERGED, journal→0600).**
- **F-038-005 NewDB pre-#4056 files stay 0644 on upgrade → NOT-MATERIAL.** `db.go:51-57` chmods the
  `.configdb` dir to **0700 (owner-only) on upgrade**, so any lingering 0644 file inside is
  unreachable by a non-owner (can't traverse a 0700 dir); new writes are 0600 (#4056). A4 perms are
  covered by #4579/#4603. Bounded.
- **F-038-006 parseSrcPort wraps (`daemon_flow.go:244`) → NOT-MATERIAL (low).** Flow-**archive**
  display/record path only — not forwarding; a malformed archived source-port string is cosmetic.
  Within the A7 low batch scope.
- **F-038-007 scp option injection → DUP #4589/#4597 (MERGED — "scp argv" enumerated).**
- **F-038-008 vtysh injection via BGP neighbor IP → DUP #4588/#4593 (MERGED).**
- **F-038-009 gRPC session-filter port truncation → NOT-MATERIAL (dispositioned "A8
  session-filter-display-only").**
- **F-038-010 feeds SSRF → DELIBERATE (dispositioned "A9 feeds-SSRF-deliberate").**
- **F-038-011 GRE/IPIP tunnel TTL uint8 truncation → NOT-MATERIAL.** Schema bounds tunnel TTL to
  **0..255** at commit: `schema_interfaces.go:399` valueDesc "Tunnel TTL (0..255…)" + validation,
  regression test `schema_validate_interfaces_test.go:149 "tunnel-ttl"`. Tunnel config is not
  HA-synced raw; config-sync re-runs the same schema. `uint8(ttl)` at `tunnel.go:767` cannot
  overflow post-validation.
- **F-038-012 SSE no cap / no send deadline → DELIBERATE/NOT-MATERIAL.** `server.go:309-310`
  documents WriteTimeout is **deliberately UNSET** for the long-lived SSE streams; REST is
  localhost-only (127.0.0.1:8080). Partial overlap with the opus-172 L SSE-cap item. Bounded to a
  local caller.
- **F-038-013 Deterministic NAT /0 HostCount=0 → NOT-MATERIAL (dispositioned "A6
  deterministic-NAT-shift-not-0-on-64bit").**

## Low findings (F-038-014..047)

Filed-batch DUPs:
- **F-038-014** remote monitor port → DUP #4589/#4597 (monitor-count bound).
- **F-038-015** resolveAppName truncate, **F-038-016** ping negative, **F-038-026**
  FilterTermExpansionCount, **F-038-043** trailingInt/atoiSafe atoi → DUP #4589/#4597
  (CLI/config LOW hardening batch, "+ others — see result files").
- **F-038-017** DDNS empty host → DUP #4589/#4597 ("DDNS host" enumerated).
- **F-038-020** fairness-eval CLI fallback, **F-038-021** fairness-eval TSV skip → DUP #4590/#4606
  (MERGED, fairness-eval arg/TSV robustness).
- **F-038-025** BGP ASN negative → DUP #4589/#4597 (BGP peer-as ASN wrap, MERGED).
- **F-038-029** CoS queue unbounded → DUP #4594/#4600 (MERGED, hard-reject out-of-range queue).
- **F-038-033** VRRP truncations → DUP #4573 (VRID/priority) + #4590/#4606 (VRRP configEqual).
- **F-038-034** RA time.After leak / blocking goodbye → within #4590/#4606 RA LOW batch.
- **F-038-041** LLDP TTL int→uint16 → ALREADY-FIXED #4596/#4600 (MERGED, bound LLDP TTL).

Deferred / low-confidence design gaps (not novel):
- **F-038-023** HA-synced source-NAT drops persistent-NAT lease → DUP-of-deferred: `source.rs:748`
  `reserve_synced_source_nat_allocation` sets `persistent_key: None` **by design** (standby replays
  an already-made allocation; rebuilds on failover). Rule-level persistent-NAT modeling is a known
  gap (cf. #4313 / deterministic-NAT #4559). Report marks it Low confidence.
- **F-038-024..027 (combined NAT lows)** → the report itself states "all Low confidence, verified
  against dedup"; A2 batch negatives already covered NAT64 EH walk (#4517/#4533), IPv6 pool wrap,
  sticky_pool, NPTv6 word.
- **F-038-031** configstore key not zeroized → DUP #4549 (PSK-zeroize intent) / A4 batch.
- **F-038-035** warnDuplicateNodeID wall-clock (`election.go:267`) → DUP #4549 (election same-node-id
  area); trivial rate-limit hardening nit.

NOT-MATERIAL / DELIBERATE (verified this pass):
- **F-038-018** DHCP buildL2Reply total-length → NOT-MATERIAL: a DHCP payload never approaches
  65527B (option space bounded); unreachable.
- **F-038-019** DHCP stableGroups rename remaps subnet_id → deliberate determinism trade-off
  (rename ⇒ new deterministic id); operator-visible, not forwarding. A10 batch scope.
- **F-038-022** Umem::frame `offset as isize` → NOT-MATERIAL: safe on 64-bit (200MB ≪ isize::MAX);
  report itself calls it defense-in-depth only.
- **F-038-027** global policy from/to-zone bracket-list drop → DELIBERATE: Junos single-value only
  today (report acknowledges); consistency nit vs #2419, no functional bug.
- **F-038-028** SNATValue.CounterID uint16 (legacy) → NOT-MATERIAL: vestigial retired-eBPF array
  path (#1476), not on the primary userspace dataplane (report says "vestigial").
- **F-038-030** configstore temp-file accumulation → NOT-MATERIAL: bounded by the 0700 dir;
  cosmetic disk-usage; A4-adjacent.
- **F-038-032** master-password removal keeps master.key → NOT-MATERIAL: master.key lives in the
  0700 owner-only dir and is wiped by zeroize (#4576/#4582); owner-only remnant, low.
- **F-038-036** SNMP teardown WaitGroup ordering, **F-038-037** rpm retry data race, **F-038-039**
  archiveToSites temp leak, **F-038-040** VLAN-id-from-name, **F-038-042** junosSpeedToNetworkd →
  A7 LOW batch scope; teardown-ordering / cosmetic / name-format-bounded; none forwarding.
- **F-038-038** neighbor probe max targets OOM → NOT-MATERIAL: targets bounded by the
  configured/kernel neighbor set (`daemon_neighbor.go`, `collectNeighborProbeTargets` #1197), not
  attacker-unbounded fan-out.
- **F-038-044 / F-038-045** REST NAT/peer-session port display truncation → NOT-MATERIAL (A8
  display-only class, same as F-038-009).
- **F-038-046** feeds response-header DoS → NOT-MATERIAL: Go `http.Transport` caps response header
  size (DefaultMaxResponseHeaderBytes); feeds SSRF itself was DELIBERATE (A9).
- **F-038-047** eventengine supersede drain/refill not atomic → DELIBERATE: `engine.go` +
  `README.md:224-242` document the supersede drain/refill semantics; regression test
  `TestSupersede_PreservesFIFOPlacesNewAtTail`. Not a bug.

## Confabulation check
All cited symbols exist on `origin/master`: `pkg/cluster/manager.go` Manager.Start,
`pkg/cluster/sync_conn.go` handleDisconnect + `sync_bulk.go` completeBarrierWait,
`pkg/configstore/db.go` NewDB, `pkg/daemon/daemon_flow.go` parseSrcPort/scpArchiveTransfer,
`pkg/routing/tunnel.go` uint8(ttl), `pkg/api/server.go` SSE handlers,
`userspace-dp/src/nat/source.rs` reserve_synced_source_nat_allocation,
`pkg/eventengine/engine.go`+README, `pkg/cluster/election.go` warnDuplicateNodeIDLocked. **No
confabulated finding.**

## Conclusion
Zero novel genuine residuals. The two High findings were re-verified false (different mutex; map
cleared under lock before close). Every Medium/Low is a DUP of a filed/merged issue, a
deferred issue, a recorded batch-triage disposition, or NOT-MATERIAL/DELIBERATE/ALREADY-FIXED on
source verification. The ps-038 campaign is fully covered — nothing slipped through.
