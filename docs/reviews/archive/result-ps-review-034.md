# Triage result — ps-review-034 (Cohorts 12-14: CLI/REST/gRPC + Wire/Protocol + Config Parser)

- **Review file**: /tmp/ps-review-034.md
- **Review base**: 8cd816e35 (post #4540/#4541/#4545 merges)
- **Current master SHA**: 29fc0d45d7037fb9c8b33d86c9931d4275b352e8 (verified base is an ANCESTOR of master)
- **Freshness check**: `git diff --name-only 8cd816e35..origin/master` touches NONE of the cohort files (pkg/api/config.go, pkg/api/auth.go, pkg/api/api.go, pkg/cli/cli_request.go, pkg/config/schema_walk.go, pkg/config/lexer.go, pkg/grpcapi/server_config.go, pkg/configstore/*). The 4 commits since base are #4544 host-inbound, #4539 session-cache, #4547 ipsec-dns, #4543 screen-ipv4-opt — all outside this cohort. So the review's on-8cd816e35 verifications carry to master unchanged.
- **Repo identity**: REAL bpfrx. Every cited symbol EXISTS on origin/master. NO confabulation.
- **Third re-audit context**: prior ps-023 → #4524/#4525/#4526 (monitor-inj/RA/DHCP) MERGED; ps-032 → #4540/#4541 (monitor-parse/writeJSON) MERGED as #4545. This report is a self-triaged re-verification that those are still fixed + surfaces the LOW residual tails.

## Outcome counts

| Disposition | Count | IDs |
|---|---|---|
| GENUINE-RESIDUAL (all LOW) | 3 | M-01, N-01, L-01 |
| NOT-MATERIAL (known residual) | 1 | M-02 |
| DELIBERATE / intentional | 1 | L-02 |
| ALREADY-FIXED re-verify (prior merged) | 7 | writeJSON #4541, monitor-parse #4540, monitor-inj #4524/#4527, auth #4157, RA #4525/#4528, DHCP #4526/#4531, + control-cap #2744 |
| NEGATIVE (verified fail-closed) | 17 | §4 N-01..N-17 |
| CONFABULATED | 0 | — |

**No HIGH or Medium genuine residual survives.** All 3 genuine residuals are LOW (2 fail-closed defense-in-depth, 1 fail-closed UX-message nit). Every one is a RE-REPORT of a prior-cohort finding (ps-032 M-01, ps-032 H-01, ps-026 NEW-02) verified still-present — none is truly NOVEL, though M-01's gRPC leg is a small extension over ps-032's REST-only note.

---

## Per-finding disposition WITH reasoning

### M-01 — REST + gRPC rollback `n=0` — **GENUINE-RESIDUAL, downgrade Medium→LOW**

- **Symbol check**: EXISTS. `pkg/api/config.go:345` `configShowRollbackHandler`, `:349` `queryIntStrict(r,"n",1)`, `:351` msg "must be a non-negative integer". `pkg/api/api.go:204` `queryIntStrict` → `config.ParseCanonicalUint`. `pkg/configstore/store_format.go:422` `ShowRollbackRedacted` → `s.history.Get(n-1)`. `pkg/configstore/history.go:54` `Get(n)` → `if n<0||n>=size` error. `pkg/grpcapi/server_config.go:321` `ShowRollback` → `ShowRollbackRedacted(int(req.N))`, no `N<=0` guard.
- **Mechanism (traced end-to-end)**: `?n=0` → `ParseCanonicalUint("0")` = (0,nil) [confirmed: all-digits path → `strconv.Atoi("0")`=0] → `queryIntStrict` returns (0,**true**) → passes guard → `ShowRollbackRedacted(0)` → `history.Get(-1)` → `-1<0` → error `"history position -1 out of range [0, N)"` → REST 400 / gRPC InvalidArgument.
- **Why GENUINE**: `n=0` slips the query-param guard (0 IS a canonical non-negative uint) and is only stopped one layer down by the store, which emits an INTERNAL 0-based-index message. That is a real API-contract inconsistency: the handler advertises "non-negative integer" yet rejects 0, and the rejection message leaks the `-1` internal index rather than a clean "must be 1..N". gRPC has the identical hole (no `N<=0` guard).
- **Why LOW, not the review's Medium**: The path is **fully fail-closed** — `history.Get(-1)` returns an error, NEVER a wrong slot (no Go negative-index wrap; explicit `n<0` guard). The operator gets an error and retries with `n=1`. There is NO wrong-rollback display, so the review's "observability lie during incident response / Medium" is **overstated** — an observability lie would be showing the WRONG rollback as if correct; here you get a (slightly ugly) error. Blast radius: cosmetic message quality + minor contract inconsistency. No security impact, no data exposure, no wrong action. This is the LOW residual tail of already-**CLOSED #3443** ("REST/gRPC rollback-compare selectors default malformed/negative instead of failing") — #3443's `queryIntStrict` made it fail-closed; the n=0 message polish was left.
- **Review inaccuracy noted**: the review's trace step 4 claims the handler emits "must be a non-negative integer" for `n=0`. That is WRONG — that message fires only when `queryIntStrict` returns `ok=false` (non-canonical/non-digit input). For `n=0`, `ok=true`, so the operator actually sees the store's `"history position -1 out of range"` message. The review conflated the two error paths.
- **Fix direction (if driven, LOW)**: add `if n==0 { writeError(400, "rollback number must be a positive integer (1..N)") }` in `configShowRollbackHandler`; add `if req.N<=0 { return InvalidArgument }` in gRPC `ShowRollback`; optionally have `ShowRollbackRedacted` surface a 1-based message instead of the `-1` internal index.
- **Filing**: LOW UX/consistency nit; fold into a rollback-message-consistency PR or file as `api`/`grpc`/`low`. Not previously filed (ps-032 M-01 was noted, not issued).

### M-02 — REST Basic-auth `cfg.Users[user]` map-lookup timing — **NOT-MATERIAL (known residual, LOW)**

- **Symbol check**: EXISTS. `pkg/api/auth.go:82` `expected, exists := cfg.Users[user]` then `:83` `subtle.ConstantTimeCompare([]byte(pass),[]byte(expected))==1`, `:84` `return exists && passMatch`. `constantTimeAPIKeyMatch` (:104) OR-s `ConstantTimeCompare` over every key, no short-circuit.
- **Why NOT-MATERIAL**: #4157's PRIMARY fix is CONFIRMED PRESENT — the code ALWAYS runs `ConstantTimeCompare` even for an unknown user (the large µs gap from early-return-on-!exists is gone). The remaining `cfg.Users[user]` Go-map access is <100 ns (one `strhash` + bucket probe), dominated by network RTT jitter (10 µs–10 ms), reveals only username EXISTENCE (never the password), and the map seed is per-process (not brute-forceable per request). Requires 100K+ samples on a low-jitter LAN to even theoretically extract, for the marginal reward of enumerating usernames.
- **Consistency with prior triage**: identical residual as ps-023 13-01 and ps-032 N-01, both correctly downgraded. The review itself rates it Low and explains the downgrade — I concur. Not a bypass, not a regression.
- **Why not higher**: no password leak, not network-exploitable in practice. **Why not dismissed outright**: it is a genuine (tiny) side channel, so it stays on record as an accepted Low hardening residual, not driven.

### N-01 — Monitor-traffic filter validation quote-bypass — **GENUINE-RESIDUAL, LOW (defense-in-depth, not exploitable)**

- **Symbol check**: EXISTS. `pkg/cli/cli_request.go:571` `stripSurroundingQuotes` (strips ONE balanced outer `"`/`'` layer), `:626` `monitorFilterOptionToken` = `len>1 && tok[0]=='-'`, `:633` `validateMonitorFilter`, `:586` `buildMonitorTrafficArgv` appends `"--"` (:607) before `strings.Fields(filter)`.
- **Mechanism (traced)**: `matching` greedily joins rest tokens, applies `stripSurroundingQuotes` to the WHOLE joined string. A MATCHED wrapper `"-w /tmp/x"` → strips to `-w /tmp/x` → `validateMonitorFilter` sees token `-w` → REJECTED (correct). A MISMATCHED wrapper (e.g. tokens `'-w … /tmp/x'"` where first char `'`, last char `"`) → `stripSurroundingQuotes` does NOT strip (quotes differ) → filter keeps leading `'` → `validateMonitorFilter` token `'-w` → `monitorFilterOptionToken('-w)` = false (tok[0]=`'` not `-`) → **PASSES validation**.
- **Why GENUINE**: the validation layer CAN be bypassed by a mismatched-quote wrapper that hides the `-`.
- **Why LOW / not exploitable**: the PRIMARY defense is the `"--"` end-of-options separator in `buildMonitorTrafficArgv`, which is ALWAYS emitted before the filter tokens. After `--`, getopt stops option scanning, so the smuggled `'-w`/`/tmp/x'"` tokens reach tcpdump as pcap-filter OPERANDS → libpcap compile error (harmless), NEVER as options. No arbitrary file-write (`-w`) / command-exec (`-z`) is possible. `validateMonitorFilter` is EXPLICITLY documented in-code as "defense-in-depth" backstopping the `--`. So this is a bypass of a redundant layer whose primary is intact. Only a future refactor removing `--` or appending flags after the filter would make it exploitable.
- **Consistency**: same residual as ps-032 H-01, which the review correctly downgraded Medium→Low. I concur — LOW.
- **Fix direction (LOW)**: in `validateMonitorFilter`, strip a leading `'`/`"` from each token before the `-` test (e.g. `if tok[0]=='\''||tok[0]=='"' { tok=tok[1:] }`), add `TestValidateMonitorFilterRejectsQuotedOption`.

### L-01 — `validateMultiValueLeaf` treats literal `"to"` as range separator on EVERY typed multi-value leaf — **GENUINE-RESIDUAL, LOW (fail-closed false-reject / parity nit)**

- **Symbol check**: EXISTS. `pkg/config/schema_walk.go:665` `validateMultiValueLeaf`, `:673` `if tok=="to"`, `:671/684` `lastWasSeparator`, `:686` trailing-separator → "missing value".
- **Mechanism**: `"to"` is unconditionally treated as a range separator on any multi-value typed leaf. Legit for port-range (`source-port`/`destination-port`) and NAT-pool `address` ranges. For `source-prefix-list`/`application`/`protocol`/policy `source-address` (address-book names), a member literally named `"to"` is consumed as a separator: mid-string (`application foo to bar`) silently becomes `[foo,bar]`; trailing (`… source-address to`) → `lastWasSeparator` → "missing value" error.
- **Why GENUINE but LOW**: it is a real over-broad rule, BUT strictly **fail-closed** — worst case is a FALSE-REJECT (or a confusing "missing value" message) of a leaf member literally named `"to"`, which is essentially never used in practice (no operator names an application/prefix-list "to"). NO fail-open: it never widens a match or admits an invalid value. Parity gap with Junos (which allows arbitrary identifier names) of negligible blast radius.
- **Consistency**: same as ps-026 NEW-02 (all_findings F-043), verified still present (schema_walk.go untouched since). LOW.
- **Fix direction (LOW)**: gate `to`-as-separator behind a `rangeSeparator`/`allowRangeSeparator` schemaNode flag set only on port-range + NAT-pool-address leaves.

### L-02 — `isIdentChar` includes `=` and `,` — **DELIBERATE (intentional, not a bug)**

- **Symbol check**: EXISTS. `pkg/config/lexer.go:289` `isIdentChar` includes `'%','=',','` (`@` was removed by revert #4530). `IsIdentRune` (:303) mirrors it.
- **Why DELIBERATE**: intentional Junos-identifier extension, documented in the function's own doc comment. `=`/`,` inside bracket-lists are structural sugar carried on `Keys` by the deliberately bracket-agnostic lexer (#2419 class). No fail-open, no tokenization break in the current grammar. The review itself files it as informational/negative. NOT a bug.

---

## Prior-fix re-verifications (ALREADY-FIXED, confirmed present on master)

All confirmed by direct read + the "cohort files unchanged since 8cd816e35" invariant:

- **writeJSON #4541** — `pkg/api/api.go:59` marshals to buffer first, 500 on marshal error, THEN WriteHeader+Write. FIXED.
- **monitor-parse #4540** — `pkg/cli/cli_request.go:519` `parseMonitorTrafficArgs` rejects `interface`/`count` with missing-value or keyword-as-value; `count` non-numeric rejected. FIXED.
- **monitor-injection #4524 (parent's #4527)** — `buildMonitorTrafficArgv:607` always inserts `"--"` before `strings.Fields(filter)`; `validateMonitorFilter` defense-in-depth. FIXED.
- **auth const-time #4157** — always-run `ConstantTimeCompare` (Basic) + `constantTimeAPIKeyMatch` OR-scan (Bearer/API-key). FIXED.
- **RA floor #4525 (parent's #4528)**, **DHCP overflow #4526 (parent's #4531)** — DHCP/RA cohort; review verifies with file:line + RED-on-revert tests; outside the CLI/REST/wire/config focus, files unchanged, accepted as merged.
- **control-cap #2744** — Go/Rust `MAX_CONTROL_REQUEST_BYTES=64MiB` lockstep. (Review §N-04.)

## Negatives (§4 N-01..N-17) — spot-verified, all fail-closed

navigatePath #3980 (all-siblings return), null_tolerant_vec, skip_serializing secrets, fabric allowlist+PSK #4122/#4107, body caps + timeouts + metrics-auth gate, flow-cache hot-hash seed + RG-epoch + DSCP/L4 gates, lexer maxParseDepth 256 + unterminated-comment/string handling. No fail-open, no confabulation.

---

## Bottom line

Third re-audit of a well-covered, already-hardened surface. The prior HIGH/Medium injection + writeJSON + RA + DHCP findings are all MERGED and re-confirmed fixed on master. What remains are 3 LOW fail-closed residual tails (M-01 rollback-message-consistency incl. a gRPC leg, N-01 monitor-filter defense-in-depth quote-bypass with intact `--` primary, L-01 `to`-separator false-reject) + 1 known non-material timing residual (M-02) + 1 deliberate lexer extension (L-02). **No NOVEL HIGH/Medium residual. No confabulation. Nothing exploitable.** Primary correction to the review: M-01 is LOW (fail-closed, no wrong-slot), not Medium, and its "non-negative integer message fires for n=0" trace is inaccurate.
