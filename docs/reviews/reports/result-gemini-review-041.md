# Triage result — gemini-review-041.md

**Cohort:** gemini authoritative defensive-hardening review, 33 findings across A1–A10 (4 High, 15 Medium, 14 Low).
**Base reviewed:** `0ebdb74b2e8` — **STALE** (ancestor of current master, ~425 commits behind).
**Triaged against:** current `origin/master` = **`cae466c7b`** (verified via `git show origin/master:<path>` + `git grep`, NOT the review's "confirmed", NOT the working tree).
**Method:** 3-gate protocol (symbol-exists / already-fixed / real+material), 4 parallel read-only verification agents + coordinator spot-checks on the High/security items.

## Outcome counts
| Disposition | Count | Findings |
| :-- | :-- | :-- |
| **Genuine — filed** | 17 | High1, High2, High4, Med2, Med8, Med11, Med12, Med13, Low2, Low3, Low4, Low5, Low7, Low8, Low9, Low11, Low13 |
| **Already-fixed** | 2 | Med6, Med9 |
| **Not-material / refuted** | 13 | High3, Med1, Med3, Med4, Med5, Med7, Med10, Med14, Med15, Low1, Low6, Low10, Low12 |
| **Confabulated / no-evidence** | 1 | Low14 |
| **Total** | 33 | |

> **HIGH/security flag:** only **High2 (#4705)** is a security-severity bug — split `system` stanzas silently disable master-password config encryption (plaintext secrets on disk), with the #4579 downgrade-warning defeated by the same first-match bug. All other genuine findings are Low / Low-Med.

Note: **Med11 == ps-review-040 F1** and **Med12 == ps-review-040 F2** (same two cluster bugs reported by both reviewers); each filed once (#4715 / #4716) with dual provenance.

---

## Genuine — filed (per-finding WHY)

| # | Finding | Issue | Sev | file:line (master) | Why genuine + fix |
| :-- | :-- | :-- | :-- | :-- | :-- |
| High1 | address-set sibling overwrite | **#4706** | Low | compiler_security_addressbook.go:251-266 | `address-set` does `ab.AddressSets[as.Name]=as` (overwrite), asymmetric with the `address` case's merge-by-name (#2222). Flat-set `set` path is safe (SetPath merges into one node); only literal duplicate hierarchical `address-set NAME {}` blocks trigger silent member loss → downgraded High→Low. Fix: fetch-or-create + append members. |
| High2 | masterPasswordPRF split-system plaintext | **#4705** | **HIGH** | configstore/crypto.go:42-53 | `tree.FindChild("system")` returns first block only; master-password in a 2nd `system` block is missed → `maybeEncryptTreeJSON` writes plaintext secrets. Split-system is a supported shape (compiler uses `FindChildren`/`systemBlocksOf`). #4579 warning calls the same broken fn → silent. Fix: iterate `systemBlocksOf`. |
| High4 | BGP routes endpoint unbounded string | **#4708** | Low | api/routing.go:85-93 | `for _, route := range routes { Fprintf(&b,...) }`, no cap; full table → huge string. Auth-gated + loopback → Low. Fix: cap/paginate/stream. |
| Med2 | dispatchWithPager buffers all output | **#4709** | Low | cli/cli_dispatch.go:136-148 | `io.ReadAll(r)` unbounded then `strings.Split`; 10M-session `show` → GBs. Local admin CLI → Low. Fix: stream to pager / bound bytes. |
| Med8 | Secret has no UnmarshalYAML | **#4710** | Low (enh) | config/secret.go (~138-160) | Real asymmetry: `UnmarshalJSON` rejects the redacted sentinel, no `UnmarshalYAML`. LATENT — no YAML config ingestion exists today (`git grep yaml.Unmarshal` empty), so filed as defensive future-proofing, not a live bug. |
| Med11 | getNlHandle FD leak + race | **#4715** | Low-Med | cluster/monitor.go:543-558 | Lock-free lazy-init of `cachedNlHandle`; two concurrent callers (pollInterfaceMonitors :260, RGInterfaceReady :506) each `NewHandle()` → FD leak, and race `Stop()` (:189). Also ps-F1. Fix: lock/`sync.Once`. |
| Med12 | Manager.Stop leaves holdTimer running | **#4716** | Low | cluster/manager.go:388-406 + readiness.go:38-50 | `Stop()` never cancels `rg.holdTimer`; AfterFunc guards only `!rg.Ready`, no `m.stopped` → post-stop election + Manager leak. Also ps-F2. Fix: range groups, Stop each timer. |
| Med13 | CPU gauge = since-boot average | **#4707** | Low | api/metrics_system.go:322-343 | Cumulative `/proc/stat` ticks exported as GaugeValue, no prev-tick delta state → lifetime average, current spikes invisible → CPU alarms never fire. Fix: store prior ticks / export counters. |
| Low2 | RejoinAndConfirm swallows errors | **#4717** | Low | upgrade/kernel_drain.go:122-133 | Deadline error prints only bools, discards `aerr`/`serr` → no rejoin-failure diagnostic. Fix: wrap last errors. |
| Low3 | DNAT silent parse-drop | **#4718** | Low | nat/destination.rs:324,330,343 | `Err(_) => continue`, no warn. Grouped LOW cohort (obs-gap). |
| Low4 | static-NAT silent parse-drop | **#4718** | Low | nat/static_nat.rs:357,361 | `None => continue`, no warn. Same cohort. |
| Low5 | SNAT match-prefix silent drop | **#4718** | Low | nat/source.rs:1360→1375 | `Err(_) => {}` silent (review's ~1139 line was off; fn genuinely at 1360). Same cohort. |
| Low7 | BGP peer-as/local-as wrap | **#4713** | Low | compiler_protocols.go:305,464 | `uint32(Atoi)` no range guard; validator only checks `==0`. `peer-as -1`→4294967295 renders bogus remote-as; local-as unvalidated. Fix: range check. |
| Low8 | SNMP AllowsSource per-packet parse | **#4711** | Low (enh) | config/snmp_clients.go:39-40 | `net.ParseCIDR` per client per v2c packet (agent.go:588). Low-rate control traffic → negligible; filed as precompute cleanup. |
| Low9 | tcp-flags dangling `!` | **#4714** | Low | config/tcp_flags.go (post-loop) | No `if pendingNeg` after loop; `tcp-flags "!"`/`"syn & !"` silently drop the negation (fail-open on missing flag). Fix: post-loop error. |
| Low11 | ClearAllSessions O(N) syscalls | **#4719** | Low-Med | dataplane/maps_session.go:372,396 | Per-key delete, no batch/`Gosched`; 10M-session clear stalls controller → HA watchdog risk. Batch APIs (:282,:295) exist unused. Fix: chunk + yield. |
| Low13 | show-text unsorted map iteration | **#4712** | Low | api/show_text.go:26,63,69,82,88,102,150,173,179,191,201,213 | Direct map ranges, no `sort` → non-deterministic order across calls (breaks automation/tests). Fix: sort keys. |

## Already-fixed (proving symbol on master)

| Finding | file:line | Proof it's closed |
| :-- | :-- | :-- |
| Med6 — CoS percent NaN/Inf | compiler_class_of_service.go:855-857 | Consumer `resolveCoSPercentRateBytes` guards `if baseBytesPerSec==0 \|\| math.IsNaN(percent) \|\| math.IsInf(percent,0) \|\| percent<=0 \|\| percent>100 { return 0 }` before the boundary cast the finding worried about. NaN never reaches `uint64(scaled)`. |
| Med9 — Annotate empty-path panic | store_command.go:209 → ast.go:307-313 | `Store.Annotate` rewritten (#4587) to delegate to `candidate.AnnotatePath`, which guards `if len(path)==0 { return error }` and `len(matches)==0`; no nil `target` deref remains. |

## Not-material / refuted (disproving path)

| Finding | file:line | Disproving trace |
| :-- | :-- | :-- |
| High3 — det-NAT BlockSize/BlocksPerIP uint16 wrap → div-by-zero | compiler_nat.go:1651-1663; dataplane/compiler_nat.go:463-479 | `port-low 0` normalized to 1024 (validator :1651 AND dataplane :466), so `portRange ≤ 64512` (< 65536); `det.BlockSize > portRange` (compileNATSource, core compile — always run) rejects block-size 65536; strict gate bounds ports 1-65535. `uint16(BlockSize)` and `uint16(blocksPerIP)` never reach 65536. Divisions use the raw `int` BlockSize guaranteed `>0`. The finding's "portRange=65536" premise is impossible. |
| Med1 — non-volatile ring reads (UB) | userspace-dp/.../bpf_map/metrics.rs:76-77 | `read_ring_pair` reachable only from `diagnose_raw_ring_state`, gated by `cfg!(feature="debug-log")` (loop_body/mod.rs:1071); values only `write!`-formatted into a debug string. Not on forwarding path → torn u32 = cosmetic. |
| Med3 — readline signal goroutine leak | cli/cli.go:426,431 | `CLI.Run()` runs once per process (daemon console daemon_run.go:1679; `cli` binary once). Leaked goroutine reclaimed at process exit, never accumulates per-session. |
| Med4 — scheduler concurrent republish | scheduler/scheduler.go:100-101 | `Scheduler.Update` (the 2nd evaluate driver) has NO production caller (daemon replaces via `NewPrimed`); only the single 60s `Run` ticker drives `updateFn`, and `publishPolicyScheduleState` serializes on the apply semaphore. No concurrent updateFn reachable. |
| Med5 — cmdtree DynamicFn nil deref | cmdtree/tree.go:255,824 | Slices are `[]*RoutingInstanceConfig`/`[]*RedundancyGroup` but elements are always freshly `&T{}` (compiler_routing.go:398, compiler_system.go:1698); no nil element is appended, and DynamicFns guard `cfg==nil`. Unreachable. |
| Med7 — source-NAT port uint16 wrap (lenient) | dataplane/compiler_nat.go:463,1184 | `validateSourceNATPoolStrict` rejects port <1 or >65535 at commit (compiler_validate_strict_nat.go:546), so 70000 cannot be committed and cannot arrive from a peer that ran the same gate; lenient downgrade is the deliberate #1979/#1960 no-brick doctrine and the snapshot builder fails closed via `sourceNATPoolPortRange`. |
| Med10 — persistRetryLoop fsync under lock | store_persist.go:340-375 | Under-lock durable write is the documented, deliberate serialization contract ("Caller must hold s.mu", :233); every commit/sync path writes durably under `s.mu` identically, guaranteeing no out-of-order persist. Only the rare degraded/backoff path. Moving off-lock would break the ordering invariant. |
| Med14 — derived slog handler stale clients | logging/slog_handler.go:118,129 | Handler installed once via `slog.SetDefault` (daemon_run.go:182); repo-wide grep finds no production caller caching a `.With()`/`.WithGroup()` logger; `SetClients` updates the root in place. Latent trap, no current miscompile. |
| Med15 — rpm probeHTTP FD leak | rpm/rpm.go:751-765 | `resp.Body.Close()` WITHOUT draining → net/http closes the conn instead of pooling it, so `CloseIdleConnections()` would be a no-op; per-probe leak "as described" does not occur (only a redirect chain, which probes rarely issue, pools). Cheap hardening still advisable but not a live leak. |
| Low1 — commit-confirmed int32 truncation | cmd/cli/main.go:248 | Dangerous negative-wrap (e.g. 2147483648→negative immediate rollback) is clamped server-side: `if minutes<=0 { minutes=10 }` (store_commit.go:214). cli_config.go keeps `int` (no truncating cast). Residual is an absurd >2.1B input wrapping small-positive, echoed back to the operator — cosmetic. |
| Low6 — ast_format empty-Keys panic | config/ast_format.go:63 | `InheritedFrom` set only by `tagNodesInherited` on nodes cloned from parsed group children, all of which carry ≥1 key. An empty-Keys node with `InheritedFrom!=""` is not constructible via any real path → `n.Keys[-1]` unreachable. Defensive-only. |
| Low10 — ExpandAddressSet nil-ab deref | config/predefined.go (expandAddrSet) | Both call sites guard `ab==nil` first: `resolveStaticNATThenPrefixName` returns early at compiler_nat.go:2264; `pkg/dataplane/compiler.go` guards at :454 before :507. No live nil-ab path. |
| Low12 — metrics_sessions cache fallback mismatch | api/metrics_sessions.go:144-148 | Misread: the master comment reads "Do NOT poison the cache … Signal scrape_ok=0", which exactly matches returning `sessionGaugeSnapshot{}, false`. The fast-path (:126-129) already serves the cached snapshot within TTL. No discrepancy — deliberate design. |

## Confabulated / no-evidence

| Finding | Why |
| :-- | :-- |
| Low14 — "Port truncation in app name resolution and unused helper code" | File cited as `unknown`, Confidence field blank, "No direct evidence snippet provided." No symbol/file to verify → not a fileable finding. |
