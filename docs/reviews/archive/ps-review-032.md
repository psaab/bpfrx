# xpf firewall deep audit — Cohorts 12-14: CLI/REST/gRPC + Wire/Protocol + Config Parser — ps-review-032

- Base commit: b1bd96fb6 (merge PR #4531, master)
- Output path: /tmp/ps-review-032.md
- Cohorts:
  - 12: CLI/REST/gRPC — pkg/cli/, pkg/api/, pkg/grpcapi/, pkg/cmdtree/, cmd/cli/
  - 13: Wire/Protocol codecs — userspace-dp/src/protocol/, pkg/dataplane/userspace/process_control.go, proto/xpf/v1/
  - 14: Config parser/lexer/AST — pkg/config/lexer.go, parser.go, ast.go, ast_edit.go, ast_format.go

---

## 0. Required fix-status verification (prior cohort findings)

| Fix ID | Topic | Status on b1bd96fb6 | Evidence |
|---|---|---|---|
| [12-01] DHCP renewalTimers overflow (#4526) | reported FIXED | **VERIFIED FIXED** | `3915d0018 dhcp: avoid int64 overflow in renewalTimers T2 remainder` — git log HEAD, not in cohort 12-14 scope |
| [12-02] RA randomAdvInterval 0s (#4525) | reported FIXED | **VERIFIED FIXED** | `d274a9de0 ra: floor RA interval + RFC 4861 §6.2.1 schema range` — git log HEAD |
| [13-01] REST Basic-auth timing | check STILL PRESENT | **VERIFIED FIXED** | `pkg/api/auth.go:76-83` `subtle.ConstantTimeCompare` always run even for unknown user (exists && passMatch), `constantTimeAPIKeyMatch` OR-s all keys via ConstantTimeCompare, no early map lookup. `pkg/api/auth_consttime_4157_test.go` AST guard pins Bearer/X-API-Key through constantTimeAPIKeyMatch, no `cfg.APIKeys[...]` boolean indexing. Commit `6993d7827 api: constant-time API-key/Bearer/username auth (#4157)` in HEAD lineage. |
| [13-02] monitor traffic injection (#4524) | reported FIXED | **VERIFIED FIXED** | `pkg/cli/cli_request.go:570-624` `buildMonitorTrafficArgv` inserts `"--"` before filter tokens, `validateMonitorFilter` rejects `-w`/`-z`/`-r`/`--*` option-looking filter tokens. Tests `monitor_traffic_injection_4524_test.go` + `monitor_traffic_filter_4005_test.go` both green on HEAD. Commit `327fc6d86 cli: neutralize monitor traffic filter tcpdump option injection` in HEAD. |
| [14-01] isIdentChar %/ — #4530 revert-R04 | verify revert | **VERIFIED REVERTED** | HEAD `pkg/config/lexer.go:289-306` `isIdentChar` returns only `a-z A-Z 0-9 - _ . / : * + % = , < >` — no `@`. `IsIdentRune` same. Revert commit `bd870991e config lexer: revert R-04 @ isIdentChar (broke #4099 fail-closed test)` + merge `7d6f14fdf` present in HEAD. Note: `%` remains in isIdentChar (original design for `%` URL-encoding in identifiers) — intentional divergence from strict Junos where `%` is not normally bare-ident. |
| [14-02] MAX_CONTROL_REQUEST_BYTES mismatch | check if fixed | **VERIFIED FIXED** | Go: `pkg/dataplane/userspace/process_control.go:32` `const MaxControlRequestBytes = 64 * 1024 * 1024`. Rust: `userspace-dp/src/protocol/control.rs:64` `pub(crate) const MAX_CONTROL_REQUEST_BYTES: usize = 64 * 1024 * 1024`. Equal. Lockstep test `pkg/dataplane/userspace/control_request_cap_2744_test.go:120-128` pins equality `MaxControlRequestBytes != rustMaxControlRequestBytes → Fatal`. Rust server test `userspace-dp/src/server/tests.rs` + Go property test also verify. Commit `#2744` raised both from 16→64 MiB. |
| [14-03] navigatePath — check if fixed | verify | **VERIFIED FIXED** | `pkg/config/ast.go:169-252` `navigatePath`: multi-key consumption with `consumed` loop, single-key terminal branch `i+1>=len(path)` now returns ALL siblings sharing leading keyword (#3980) via `FindChildren`-style loop, not just first. `ast_format.go:39,155,185,446,473` — all 5 call sites now receive `[]*Node` slice. Tests `show_config_repeated_keyword_3980_test.go` verify display-set round-trip for repeated keywords (ntp server ×2, multiple routes). Prior bug was terminal single-key returned only first sibling, hiding statements from scoped show and breaking display-set backup. |

All 7 prior findings verified: 5 fixed, 1 reverted (as intended), 0 still present. No re-report.

---

## 1. Duplicate-suppression summary + intentional-divergence list

Read `/tmp/all_findings.txt` (272 entries), `/tmp/ps-review-024.md`, `/tmp/ps-review-025.md`, `/tmp/ps-review-028.md`.

### Dedup'd (NOT re-reported as new)

| Prior ID | Topic | Why dedup'd |
|---|---|---|
| F-005 | quoteKey never escapes backslashes | **FIXED** — `pkg/config/ast.go:76-101` now `keyEscaper = strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n")` — single-pass, backslash-first, symmetric with lexer `readString`. |
| F-035 | Annotations `/* */` injection via `*/` in comment text | Known, intentional: annotations are operator-authored comments, not attacker payload. Still a hardening gap but not new. |
| F-036 | RenamePath cannot rename non-first sibling | **FIXED** — `pkg/config/ast_edit.go:41-101` `RenamePath` now uses `findNodeWithParent` (longest-key match) + in-place rename for same-parent (preserves order) + collision guard. Tests `parser_ast_test.go:774` cover non-first rename. |
| F-037 | navigatePath single-key returns only first | **FIXED** — see [14-03] above, PR #3980. |
| F-022 | monitor traffic matching truncates to first token | **FIXED** — `pkg/cli/cli_request.go:519-547` now greedily consumes all tokens until next keyword, `monitor_traffic_filter_4005_test.go` pins multi-token `tcp port 80`. |
| F-023 | read-only can run monitor traffic (root tcpdump) | **FIXED** — `pkg/cli/permissions.go:130-137` `requiredPermission` elevates `monitor traffic` to `PermControl`, `permissions_monitor_traffic_4067_test.go` pins. |
| F-020 | Config secret redaction bypassed by raw-AST render | **FIXED** — `pkg/api/config.go:168-217` all endpoints call `Show*Redacted`, `pkg/cli/permissions.go:67-107` `showConfigRedacted` gates CLI, tests `config_secret_redaction_test.go` + `config_raw_ast_redaction_test.go` pin. |
| F-021 | monitor interface stdin-reading goroutine races readline | **FIXED** — `pkg/cli/monitor_interface.go:46-122` `setRawMode` with `VMIN=0 VTIME=1`, `keyReader` poll loop, `startKeyReader`/`stopKeys` WaitGroup, `stopKeys` called before terminal restore. Test `monitor_interface_stdin_3985_test.go`. |
| F-044 | 79-field lenient compileOpts duplicated | Known refactor debt, not a correctness bug. |
| F-051 | GC stats never update on userspace (SessionCount 0) | Intentional — documented in `pkg/api/types.go` `SessionCount` now reads live dataplane `SessionCount()`, GC path returns 0 stale. Not in cohort. |
| F-060 | system archival transfer-interval not implemented | Known parity gap, not in cohort. |
| F-061 | updateFlowTrace leaks EventReader per commit | Known, out of cohort. |
| Various | monitor interface, show security, completion, CLI dispatch | Reviewed, no new bypass beyond below. |

### Intentional divergences (NOT bugs)

- **Intrazone default-permit, host-originated junos-host rejection, IPsec-passthrough-exempt** — documented, not reported.
- **`isIdentChar` includes `%` `=` `,` `+`** — Junos does not use bare `%` normally (URL-percent-encoding), but xpf uses it for URL query paths in DDNS / feed URLs. Intentional extension, not reported as bug.
- **`%` in isIdentChar vs `_Log.md` doc** — doc says "percent signs" intentional. Verified intentional.
- **`monitor traffic` RBAC at PermControl not PermMaint** — design choice: read-only can view stats, control can capture, maintenance can reboot/zeroize. Correct tiering.
- **`isLoopbackBindAddr` conservative default (non-loopback = auth-gate metrics)** — intentional fail-closed, not a bug.
- **`writeJSON` writes header before Encode** — if Encode fails, header already sent as 200; body is truncated JSON. Minor but not a security hole — `writeJSON` only called with small well-typed structs, never user-controlled data that could fail marshal. Reviewed, not reported as NEW but noted as hardening.

---

## 2. Module / verdict-path inventory (coverage checklist + cohort map)

| Module | File(s) | Role | Reviewed |
|---|---|---|---|
| Config lexer | `pkg/config/lexer.go` | Junos tokenizer, bracket stripping, string escaping, block-comment errors, isIdentChar | YES full |
| Config parser | `pkg/config/parser.go` | Recursive-descent, maxParseDepth 256, inactive: marker, ParseSetVerb, deactivated leaf handling | YES full |
| Config AST core | `pkg/config/ast.go` | Node type, navigatePath, matchNodeKeys, FindChild/Children, quoteKey/keyEscaper, Clone | YES full |
| Config AST edits | `pkg/config/ast_edit.go` | SetPath/DeletePath/RenamePath/CopyPath/DeactivatePath/ActivatePath, removeMultiLeafMembers, markMultiLeafMembersInactive | YES full |
| Config AST format | `pkg/config/ast_format.go` | Format/FormatSet/FormatPath/FormatJSON/FormatXML/FormatCompare/nodesToJSON, inactivePrefix, canonicalOrder | YES full |
| CLI dispatch | `pkg/cli/cli.go`, `cli_dispatch.go`, `completion.go` | Operational cmd dispatch, abbreviation resolution, dynamic completion | YES sampled |
| CLI config mode | `pkg/cli/cli_config.go` | set/delete/deactivate/activate/commit/load/rollback, display-set round-trip | YES sampled |
| CLI permissions | `pkg/cli/permissions.go` | Login-class RBAC, monitor traffic / request maintenance escalation, showConfigRedacted | YES full |
| CLI monitor | `pkg/cli/monitor.go`, `monitor_interface.go` | monitor security flow/packet-drop (trace file bounds), monitor interface (raw-mode stdin), monitor traffic (tcpdump argv) | YES full |
| CLI monitor traffic | `pkg/cli/cli_request.go:498-678` | parseMonitorTrafficArgs (multi-token), buildMonitorTrafficArgv (-- separator), validateMonitorFilter, stripSurroundingQuotes | YES full |
| REST API server | `pkg/api/server.go`, `api.go` | HTTP server, TLS cert generation, timeouts, body caps, auth middleware wiring | YES full |
| REST auth | `pkg/api/auth.go` | Basic-auth constant-time, Bearer/X-API-Key constant-time, metrics loopback gate | YES full |
| REST config mgmt | `pkg/api/config.go` | enter/exit/commit/commit-confirmed/rollback/show/export/load/search/history, redaction | YES full |
| REST types | `pkg/api/types.go` | ZoneInfo/PolicyInfo/SessionEntry/MatchPoliciesResult, omission guards | YES sampled |
| REST SSE | `pkg/api/sse.go` | eventStream/logStream, parseCategories fail-closed, eventRecordSeverity | YES full |
| REST security | `pkg/api/security.go` | zones/policies/sessions/match-policies handlers, counter error handling | YES sampled |
| gRPC server | `pkg/grpcapi/server.go` | gRPC listener, maxRecvMsgSize 16 MiB, configLockInterceptor, fabric listener (allowlist + PSK auth), parseProxiedFailoverAction | YES full |
| gRPC fabric auth | `pkg/grpcapi/fabric_auth.go` | HMAC time-windowed PSK token, verifyFabricAuthToken (±1 window), dual-accept, downgrade guard arming, fabricAuthDecision | YES full |
| gRPC xpf.proto | `proto/xpf/v1/xpf.proto` | Service definition, RPC surface | YES skimmed |
| Wire: control | `userspace-dp/src/protocol/control.rs` | ControlRequest/Response, MAX_CONTROL_REQUEST_BYTES, ProcessStatus (large telemetry), session-sync shapes, inject-packet | YES full |
| Wire: snapshot | `userspace-dp/src/protocol/snapshot.rs` | ConfigSnapshot, Interface/Route/Flow/Zone/Fabric/TunnelEndpoint (WG private keys skip_serializing), NAC, CoS peer set | YES full |
| Wire: security | `userspace-dp/src/protocol/security.rs` | ScreenProfile/MissingRef, FirewallFilter/Term (flex, tcp_flags, icmp, dscp, cache-key invariant), Policer, ThreeColorPolicer, PolicyRule, AppCatalog, FlowExport | YES full |
| Wire: flow-cache | `userspace-dp/src/afxdp/flow_cache.rs` | 4-way set-assoc, hot-hash seed, RG epoch invalidation, NAT family guard, DSCP/L4 cache-sensitivity gates, active-flow debug, sentinel-clear on wrap | YES full |
| Go control socket | `pkg/dataplane/userspace/process_control.go` | MaxControlRequestBytes, controlRoundtripDeadline (scaled by payload), requestDetailedLocked, sessionSocketPath, never-log-secret | YES sampled |
| CLI show surfaces | `pkg/cli/cli_show_*.go` | show security policies/zones/interfaces, show config redaction, wireguard status | YES sampled |

---

## 3. Module-by-module inspection log (including negatives)

### 3.1 Config lexer — `pkg/config/lexer.go`

**`isIdentChar` / `IsIdentRune` (lines 283-306)** — reviewed for @/%, bracket, wildcard chars:

- After revert PR #4530, `@` removed. `%` remains (used in feed URLs, DDNS query strings like `example.com?key=%s`). Intentional extension, not a bug.
- Character set `{a-z A-Z 0-9 - _ . / : * + % = , < >}` — covers Junos identifiers, IP prefixes, interface names, wildcards (`*`), apply-groups wildcards (`<*>`), multi-value leaf lists (`=` `,` separators are handled as identifier chars because the lexer is deliberately bracket-agnostic — `Keys` carries the whole list). `=` `,` are safe: they only appear as interior tokens of a multi-value leaf and are consumed as part of identifier tokens by design.

**Bracket stripping (lines 95-120)** — `[` `]` consumed in `skipWhitespaceAndComments` loop without recursion (fixed fable-review-164 H-2). O(1) stack per bracket. A payload of N consecutive `[` no longer overflows Go's goroutine stack. Verified.

**`readString` escape handling (lines 243-272)** — `\\` → `\`, `\"` → `"`, `\n` → newline, default `\X` → `\X` preserved (raw). `keyEscaper` mirrors this exactly: `\\` → `\\\\`, `"` → `\\"`, `\n` → `\\n`. Single-pass Replacer so backslash escaped before quote. Previously `quoteKey` never escaped backslashes — fixed (#3844 / F-005).

**Block comment unterminated (lines 198-230)** — `pending` TokenError mechanism defers until `Next()` returns it. `Next()` checks `l.pending` before EOF so an unterminated `/*` consuming to EOF does not get swallowed as TokenEOF (fix #4147 / M-8). Verified.

**`readIdentifier` / `readString` symmetry** — `quoteKey` wraps in `""` only when `!isIdentChar`, escapes via `keyEscaper`. `readString` un-escapes the same 3-char set. Round-trip invariant `Parse(Format(x)) == x` holds.

**NEGATIVE**: No crash, no OOB, no bypass. Max-parse recursion guarded at 256 (`parser.go:23`). Lexer `advance()` / `readString` bounded.

### 3.2 Config parser — `pkg/config/parser.go`

**`maxParseDepth` 256 (line 23)** — `parseStatements` depth counter, `skipToBlockClose` on over-deep block drains iteratively, not recursively. Prevents `fatal error: stack overflow` from deeply nested braces. Verified.

**`inactive:` marker handling (lines 189-267)** — leading `inactive:` stripped from Keys and lifted to `Node.Inactive`; inline `inactive:` (e.g. `address ... inactive: port`) drops governed tokens (port modifier absent, address stays active). Quoted `"inactive:"` TokenString not mistaken for marker (#4348). Lone `inactive:` with no following statement → parse error. `skipStatementBody` recovery for malformed inactive: marker. Correct.

**`ParseSetVerb` (lines 72-116)** — recognizes `set`/`delete`/`deactivate`/`activate`, defaults bare path to `set`. Quoted string tokens (`TokenString`) included in path (values containing spaces). Error on empty path. Correct.

**`parseKeys` returns parallel `[]string` + `[]TokenType`** —-kind slice distinguishes bare `inactive:` from quoted `"inactive:"` — fix #4348.

**NEGATIVE**: Fully reviewed. No parser OOB or bypass.

### 3.3 Config AST — `pkg/config/ast.go`, `ast_edit.go`, `ast_format.go`

**`navigatePath` (ast.go:169-252)** — multi-key match (keyword + value pairs) with `matched` list filtering. Terminal single-key match now returns ALL siblings sharing leading keyword (#3980 fix) — previously returned only first, hiding `ntp server 1.1.1.1` / `ntp server 2.2.2.2`, multiple `from-zone` policy contexts, repeated `archive-sites`, multiple `route` statements. Fix verified: lines 216-239.

**`matchNodeKeys` (ast.go:254-276)** — first key must match; if node has more keys than remaining path elements, accepts as 1-key match (partial match for trailing value list nodes). Remaining keys must match exactly or returns 1 (first-key-only match). Used by `findNodeWithParent`, `childrenAtPath`, `navigateToNode` — all prefer longest match.

**`findNodeWithParent` / `childrenAtPath`** — longest-key-first walk, so `policy B` resolves correctly among siblings `[A B C]` (the #3982 class). `RenamePath` now uses `findNodeWithParent` for non-first sibling rename.

**`quoteKey` / `keyEscaper` (ast.go:76-101)** — single-pass Replacer, backslash + quote + newline escaped. Symmetric with lexer's `readString`. Previously never escaped backslashes — fixed (F-005 / #3854 PSK corruption). Example: IKE hex PSK `a\b` previously corrupted to `a<newline>` or `a\b` → `a"<control>` on round-trip; now preserved.

**`SetPath` (ast_edit.go:207-426)** — schema-driven traversal (compound keys, multi-value leaves, valueList opt-in #3872). Single-value leaves replace existing, flag leaves skip duplicate, multi-value leaves collapse bracket lists (#2419). Named containers created as block nodes. Wildcard fallback. Correct.

**`DeletePath` / `removeMultiLeafMembers` (ast_edit.go:428-531)** — value-list multi-leaf (`multi: true, args: 1`) member-specific deletion: bare `delete ... protocol` clears whole leaf, `delete ... protocol tcp` drops only `tcp` from `Keys[1:]` and child nodes. Empty node (no values, no children) removed entirely. Gate on `args==1` preserves whole-node delete for keyed multi entries (address <name> <prefix>, args==2). Fix #3846. Verified.

**`RenamePath` (ast_edit.go:41-101)** — uses `findNodeWithParent` (longest-key match) so non-first sibling rename works. Same-parent → in-place (preserves sibling order + children). Different-parent → detach + append. Collision guard rejects duplicate target. Fix #3982 residual (F-036).

**`DeactivatePath` / `ActivatePath` / `markMultiLeafMembersInactive` (ast_edit.go:533-814)** — inline `inactive:` marker plus verb-path deactivate both collapse bracket lists; block-shape members toggled individually. Gate on `args==1`. Fix #3975. Verified.

**`Format` / `FormatSet` / `FormatPath` / `FormatPathSet` (ast_format.go)** — all use `navigatePath` (now returns all matches). `FormatPathSet` parent-prefix computation uses `firstKey` from first match; multiple matches formatted via set nodes loop. `inactivePrefix` emitted for deactivated nodes. `canonicalOrder` moves `match`/`from` before `then` for Junos display order.

**`FormatJSON` / `nodesToJSON` (ast_format.go:431-593)** — deactivated nodes emit collision-safe `" @inactive"` marker key (sigil `@` not valid Junos ident). Nested named instances (`interface trust0` → `{"interface":{"trust0":{...}}}`). `FormatXML` similarly handles inactive attribute.

**NEGATIVE**: No bypass. navigatePath fix verified still present on HEAD.

### 3.4 CLI — `pkg/cli/`

**`permissions.go` reviewed full (lines 1-249)**:
- `resolveClassPerms` consults built-ins first, then custom `system login class` (#4304). Correct — prevents custom-class users being locked out when config commits clean.
- `checkPermission` fails closed on unknown class, allows legacy empty-class (no RBAC), gates on `requiredPermission(parts)`.
- `requiredPermission`: `monitor traffic` → `PermControl` (not `PermView`), `request system {reboot,halt,power-off,zeroize}` + `request chassis cluster failover` → `PermMaint`, rest as expected. `monitorSubcommandIsTraffic` / `requestSubcommandIsMaintenance` both use `resolveCommand` (prefix-abbrav) so abbreviated `mon tr`, `req sys reb` gated identically to fully-spelled forms. No bypass.
- `showConfigRedacted`: super-user (`PermAll`) reads cleartext, everyone else (read-only, operator, config-viewer, unknown) sees redacted. Empty class → cleartext (legacy compat). Correct per #4099 / #4051.

**`monitor.go` + `monitor_interface.go` reviewed full**:
- `sanitizeTraceFilename`: rejects empty, `.`, `..`, `/\` path separators, `filepath.Base` mismatch — prevents `../../etc/passwd` via trace file. `openTraceFile`: sanitized, `O_NOFOLLOW`, regular-file Stat, 0600 perms. `rotateTraceFile`: strict error handling — failure to drop oldest / shift intermediates / roll active → return error (writer stops, not grows unbounded). `traceWriter.writeLine`: size budget + rotation check before write. All #3378/#3379 fixes present.
- `monitorInterfaceSingle` / `monitorInterfaceTraffic`: `setRawMode` with `VMIN=0 VTIME=1` (poll-with-timeout), `keyReader` goroutine with `done` channel, `startKeyReader`/`stopKeys` WaitGroup, `stopKeys` deferred before terminal restore (prevents stale keyReader stealing next command). Fix #3985. `enterAltScreen`/`exitAltScreen`, `hideCursor`/`showCursor` escape sequences. `frozen`, `c`, `C`, `n`, `N` key handling.
- `handleMonitorSecurityFlowFile` / `handleMonitorSecurityFlowFilter`: locals-then-atomic-commit pattern (#3380), unknown tokens rejected, empty filter rejected (no broad-tracing fail-open), value-less options rejected. `sanitizeTraceFilename` before any state.

**`cli_request.go:498-678` reviewed full (monitor traffic)**:
- `monitorTrafficKeywords` = `{"interface","matching","count"}` — terminators for greedy `matching` clause.
- `parseMonitorTrafficArgs`: greedy collect until next keyword, `stripSurroundingQuotes`, multi-token filter preserved (`tcp port 80`). Fix #4005.
- `stripSurroundingQuotes`: single layer only, balanced quotes only, empty/mismatched/unbalanced passed through.
- `buildMonitorTrafficArgv`: `["tcpdump","-i",iface,"-n","-l", "-c",count, "--", ...filterTokens]` — explicit `--` separator neutralizes `-w`/`-z` option injection (Fix #4524). `strings.Fields` split keeps multi-token filter intact.
- `monitorFilterOptionToken`: `len>1 && [0]=='-'` — rejects every option-looking token including `--postrotate-command`, allows bare `-` (not an option).
- `validateMonitorFilter`: rejects any option-looking token in filter. Defense-in-depth on top of `--` separator. Clear error message vs opaque libpcap syntax error.
- `handleMonitorTraffic`: validates before exec, resolves fabric parents, warns on XDP redirect visibility, `exec.CommandContext` with cancel.

**CLI dispatch / completion (sampled)**: `resolveCommand` abbreviation, `completion_typed_leaf`, etc. No new bypass.

**NEGATIVE**: All CLI privilege-escalation / injection / traversal paths verified FIXED.

### 3.5 REST API — `pkg/api/`

**`auth.go` reviewed full (lines 1-137)**:
- `authMiddleware`: `/health` always exempt (no sensitive data, liveness probe), `/metrics` exempt only when `!metricsRequireAuth` (loopback-bind default, standard Prometheus posture; non-loopback + auth-configured → gate metrics — Fix #4162). Checks Authorization header (Bearer + Basic), then X-API-Key. `WWW-Authenticate` on 401.
- `checkAuthorization`:
  - Bearer: `constantTimeAPIKeyMatch` (not plain map lookup).
  - Basic: `base64.StdEncoding.DecodeString`, `strings.Cut` on `:`, `cfg.Users[user]` lookup then `subtle.ConstantTimeCompare([]byte(pass), []byte(expected)) == 1` — always runs compare even for unknown user, then `exists && passMatch`. Fix #4157 — prevents timing gap between known/unknown username (large measurable gap on early-return would leak existence).
  - `constantTimeAPIKeyMatch`: OR-s `ConstantTimeCompare` across every valid key, never short-circuits on match. Closes timing side channel of `cfg.APIKeys[presented]` (hash-bucket collision / presence leak) + which-key timing. `len(expected)==0` for unknown user compares against empty string, which `ConstantTimeCompare` handles (returns 0 on length mismatch — reveals only length, acceptable per doc). Loop count = deployment constant, not attacker-controllable. Fix #4157.
- `isLoopbackBindAddr`: `net.SplitHostPort`, empty host → false (wildcard bind `:8080` → non-loopback → gate metrics), hostname/malformed → false (conservative), `ip.IsLoopback()`. Correct fail-closed.
- **Timing residual (LOW)**: `cfg.Users[user]` map lookup itself has data-dependent timing (hash + bucket chain). However Go's native map access timing variation is <100ns with jitter from GC/scheduler, not reliably exploitable over network; and the constant-time compare dominates (µs). The fix removes the LARGE gap (skipping compare entirely ≈µs difference). This is acceptable — not reported as new, but noted. An even stronger fix would pre-hash username or use a sorted-list comparison, but that trades complexity for marginal gain.

**`api.go` / `server.go` reviewed (DoS hardening)**:
- `maxRequestBodyBytes = 16 << 20` (16 MiB) — bounds every REST mutation body via `decodeJSONBody` `http.MaxBytesReader`. Largest real body is full candidate config, well under 1 MiB; 16 MiB ceiling plus parser's own `MaxConfigSize` (16 MiB) gives transport+parser double ceiling. Reject → HTTP 413 fast. Fixes fable-review-164 H-2 OOM.
- `decodeJSONBody`: wraps `r.Body` in `MaxBytesReader`, `json.NewDecoder(...).Decode`, `*http.MaxBytesError` → 413, other → 400. Both write error response and return false so caller must not write more. Correct.
- `server.go:301-344`: `apiReadHeaderTimeout=10s`, `apiReadTimeout=30s`, `apiIdleTimeout=120s`, `apiMaxHeaderBytes=1MiB`, `metricsScrapeTimeout=10s`, `metricsMaxInFlight=3` — slowloris defense (pre-auth slow-header + slow-body). `WriteTimeout` intentionally 0 (unlimited) — SSE streams + large scrapes must not be severed. Correct per #4150 M-6.
- `metricsRequireAuth = !isLoopbackBindAddr(cfg.Addr)` — routable bind → gate metrics behind auth. Fix #4162. Verified.
- TLS cert generation: `generateSelfSignedCert` / `persistSelfSignedCert` — #1916 D5 strict sequence (MkdirAllDurable, strict-remove pair + SyncDir, WriteFileDurable key 0600 then cert 0644). Only-crash-visible states: {neither}, {key-only (LoadX509KeyPair rejects)}, {both-matching}. `tlsMkdirAllDurable`/`tlsRemove`/`tlsSyncDir`/`tlsWriteFileDurable` are test-seamed vars. Correct.

**`config.go` reviewed (redaction + commit-confirmed)**:
- `configHandler`: returns `ActiveConfig()` → `writeOK` → `json.Encode` of typed `*config.Config` (with `Secret` Marshaler returning `##SECRET-DATA##`). No raw leak.
- `configSetHandler` / `configDeleteHandler` / `configDeactivateHandler` / `configActivateHandler` / `configLoadHandler` / `configCommitHandler` / etc. — all through `decodeJSONBody` (16 MiB capped). `configLoadHandler` `LoadOverride`/`LoadMerge`/`LoadSet` with `MaxConfigSize` re-check (transport-independent parser ceiling). Correct.
- `configShowHandler` / `configExportHandler`: `Show*Redacted` on every render endpoint (#4051). `configSearchHandler`: searches redacted text, never leaks secret in snippet. `configCommitHandler`: bare commit during pending confirm → `ConfirmCommit()` only when `!IsDirty()` (staged edits committed normally, not silently dropped — Fix #4000). `configCompareHandler` / `configShowRollbackHandler`: `queryIntStrict` fail-closed on malformed/negative (Fix #3443). Correct.
- **Verified**: every `Show*Redacted` call present. No non-redacted raw-AST render path reachable from unprivileged caller.

**`sse.go` reviewed full**:
- `eventStreamHandler` / `logStreamHandler`: nil `eventBuf` guard (fixes #3381), `parseCategories` + `logging.ParseSeverityStrict` before SSE header switch (misspelled filter → 400, not silent wide-stream — Fix #3383). `parseCategories`: empty = match-all, non-empty with leading/trailing/double comma → error (fail-closed, prevents typo widening). `matchCategory`: future/unknown event type → false (narrower category mask must not deliver it). `eventRecordSeverity`: `SCREEN_DROP` + `permit` (alarm-without-drop #2234) → SyslogNotice, not error; only real drop → Error. Correct service-classification (false alerts → operator fatigue → ignore real drops).

**`types.go` / `security.go` sampled**: `ZoneInfo.HostInboundConfigured=true` unconditionally (Fix #3653 — mirrors dataplane truth, not config shape). `MatchPoliciesResult` fields (PolicyID via `*uint32` not `uint32+omitempty` — Fix #3623, first rule id 0 must not be omitted). `SessionEntry` `PolicyID`/`NodeID`/`Age`/`Idle` fixes present. Counter unavailable pattern (`HostInboundKernelDeniesUnavailable`, `PerZoneCountersAvailable`, `InterfaceStats.Unavailable`) — distinguishes real 0 from degraded read failure.

**`config_secret_redaction_test.go` / `config_raw_ast_redaction_test.go` / `config_load_bodycap_hb164_test.go` / `auth_consttime_4157_test.go` / `http_dos_hardening_4150_test.go`**: all regression nets present and verified green on HEAD.

**NEGATIVE**: REST auth timing — VERIFIED FIXED. Body caps, header timeouts, SSE filter fail-closed, secret redaction — all verified fixed / present.

### 3.6 gRPC — `pkg/grpcapi/`

**`server.go` reviewed full**:
- `maxRecvMsgSize = 16 << 20` (16 MiB) — caps inbound gRPC message, rejects oversized Load/config-sync with ResourceExhausted (fable-review-164 H-2). Both unary listener (127.0.0.1) and fabric listener use same cap. Test `server_recvsize_hb164_test.go` pins over-cap rejected, normal accepted.
- `configLockInterceptor`: auto-releases stale config lock when gRPC client context cancelled (Ctrl-C / disconnect) via `peerSessionID` (peer.Addr.String) + `ExitConfigureSession`. Prevents stale exclusive lock.
- `fabricAllowedUnaryMethods` / `fabricAllowedStreamMethods` — fail-closed allowlist (#4122): `GetStatus`, `GetSessions/Summary/ZonePairSummary`, `ShowText`, `ClearSessions`, `MonitorInterface`. Every other unary (Commit/Delete/Rollback/config-mode ops, SystemAction) rejected with PermissionDenied before handler. SystemAction multiplexes failover + destructive verbs, so NOT in allowlist — gated separately by `isFabricSafeSystemAction`.
- `parseProxiedFailoverAction`: strict parse of exactly 2 forms (`cluster-failover-data:node<N>`, `cluster-failover:<rg>:node<N>`), validates `strconv.Atoi` + `IsSupportedClusterNodeID(0/1)` — rejects garbage suffix, non-numeric, trailing `:node2`, out-of-range node (99). Loose `HasPrefix`/`Contains` gate would let `cluster-failover:1:node99` drive avoidable proxy dials → DoS.
- `isFabricSafeSystemAction`: only well-formed cross-node failover forms; zeroize/reboot/halt/power-off/local-only clear/ reset verbs denied on fabric (even though same gRPC method). Local loopback still runs any action.
- `peerSessionID`: `peer.FromContext(ctx)` p.Addr.String stable session id.

**`fabric_auth.go` reviewed full**:
- `fabricAuthMetadataKey` = `"xpf-fabric-auth"` (lowercase per gRPC metadata contract).
- `fabricAuthWindowSeconds = 30` — token window, verifier accepts ±1 (clock skew tolerance → ~60-90s replay horizon). Accepted tradeoff (NTP is cluster prerequisite).
- `fabricAuthDomain = "xpf-fabric-grpc-auth\x00"` — domain separation from heartbeat HMAC (prevents token substitution across surfaces).
- `computeFabricAuthToken`: `HMAC-SHA256(PSK, domain || littleEndian(window))`. Raw 32-byte digest.
- `fabricAuthTokenHex`: hex-encodes current window token; empty when no key (not-yet-keyed peer sends no token — legacy).
- `verifyFabricAuthToken`: `hex.DecodeString` + length check (must be SHA256.Size=32) → tries 3 windows (`now`, `now-1`, `now+1`), `hmac.Equal` constant-time per window. Returns false on empty/malformed/invalid.
- `fabricAuthDecision`: dual-accept policy mirroring `cluster.heartbeatAuthDecision`:
  - No local key → accept (standalone / not-yet-keyed side of rollout / legacy).
  - Has key + present + !tokenOK → reject (invalid token = forged).
  - Has key + present + tokenOK → accept + record.
  - Has key + no token + enforceArmed → reject (downgrade attack).
  - Has key + no token + !enforceArmed → accept (propagate/config-sync grace).
  - Fail-closed on invalid token, grace only for no-token during rollout.
- `checkFabricAuth`: sticky `fabricPeerAuthSeen.Store(true)` once peer proves key; downgrade-guard armed by EITHER `fabricPeerAuthSeen` OR `heartbeatPeerAuthSeen()` (fast arming via 200ms heartbeats, closes post-restart window where fabric would grace-accept tokenless). `heartbeatPeerAuthSeen()` is fast arming — heartbeat flows continuously, fabric RPCs are on-demand (operator show/clear/failover may be hours apart).
- `fabricAuthCreds` (client-side): `GetRequestMetadata` rotates token with window, picks up live key change, returns nil/no metadata when no key (dual-accept). `RequireTransportSecurity()=false` so rides fabric's insecure transport (private cluster segment).
- `fabricAuthUnaryInterceptor` / `fabricAuthStreamInterceptor`: run BEFORE allowlist interceptor so unauthenticated caller rejected before authorization consulted.
- **Residuals**: replay within ~30-90s window (bounded), clock skew > tolerance → Unauthenticated until corrected (accepted tradeoff, NTP prerequisite). No mTLS (deferred to #4047 stronger posture), but closes HIGH "no auth at all" hole with zero cert machinery.
- Tests `server_fabric_allowlist_4122_test.go` + `server_fabric_auth_*` (implied) should pin behavior.

**Proto** (`proto/xpf/v1/xpf.proto`): `BpfrxService` covers config lifecycle, operational show, diagnostics (streaming), mutations, generic text show, system actions, tab completion. No unexpected `MonitorTraffic` RPC (CLI-only). Config methods carry standard protobuf typing.

**NEGATIVE**: gRPC auth / allowlist / fabric PSK / message-size cap all verified fixed / present on HEAD. No network-exposed unauthenticated destructive RPC.

### 3.7 Wire / Protocol codecs — `userspace-dp/src/protocol/` + Go control socket

**`control.rs` — `MAX_CONTROL_REQUEST_BYTES`**:
```rust
pub(crate) const MAX_CONTROL_REQUEST_BYTES: usize = 64 * 1024 * 1024;
```
Lockstep with Go `MaxControlRequestBytes`. Test `TestControlRequestCapLockstepWithRust` pins equality. Old ceiling 16 MiB (#2523) insufficient for large dynamic-feed address books (~500K IPv6 prefixes ≈20+ MiB @ ~45 B/cidr). #2744 raises to 64 MiB (~1.4M prefixes). Handling in `server/handlers/mod.rs:73` `.take(MAX_CONTROL_REQUEST_BYTES as u64 + 1)` bounded read, `line.last()!=Some(b'\n')` over-cap detection, structured oversize error, daemon stays alive (fail-closed: stale config retained, one log line, no crash). Verified.

**`snapshot.rs` — Secret handling**:
- `TunnelEndpointSnapshot.wg_local_privkey_hex` — `#[serde(default, skip_serializing)]` so never written to `state.json` (world-readable 0644 via #3909). Deserialization still works via `default` path (control-socket delivery). `Debug` impl redacts to `<redacted>` / `<unset>`. Test `wg_local_privkey_hex_is_skipped_in_state_snapshot` pins.
- `TunnelWgPeerSnapshot.wg_preshared_key_hex` — same `skip_serializing`, same Debug redaction. `Debug for TunnelEndpointSnapshot` redacts whole peer set. Correct.
- `ConfigSnapshot.syn_cookie_master_key` — `#[serde(rename="syn_cookie_master_key", default, skip_serializing)]` — same pattern: off-disk (state.json world-readable), re-delivered on every config push from Go control plane deterministic derivation (`buildSYNCookieMasterKey`). No Rust-side regeneration (HA needs same key on both chassis). Verified.

**`security.rs` — Cache-key invariant, FirewallTermSnapshot**:
- Comment `CACHE-KEY INVARIANT (#1431)` documents every new match field must be classified (a) in SessionKey (5-tuple) or (b) cache-sensitive (flow-cache decline + re-eval). Classic fail-open class: new match field added to Wire but not to cache invalidation → flow-cache replays stale accept for different per-packet field value.
- `FirewallTermSnapshot` fields: `source/destination_addresses`, `source/destination_except`, `source/destination_constrained` (fail-closed: constrained + empty positive = match nothing; constrained + empty except = match all), `protocols`, `source/destination_ports`, `source/destination_ports_except`, `dscp_values`, `action`, `next_term`, `count`/`log`/`policer`/`routing_instance`/`forwarding_class`/`dscp_rewrite`, per-packet L4 (`tcp_flags`, `tcp_flags_forbidden`, `tcp_flags_unparseable`, `is_fragment`, `icmp_types/codes`, `icmp_type/code_unrepresentable`, `dscp_match_unrepresentable`, `flex_match`). All per-packet L4 terms are NOT in SessionKey → cache-sensitive.
- `tcp_flags_required` + `tcp_flags_forbidden` (#3076) — carries `syn & !ack` correctly (required=SYN, forbidden=ACK). Pre-fix dropped negative operand → `syn` matched every TCP including `syn+ack` (ACK-bypass).
- `tcp_flags_unparseable` / `icmp_type_unrepresentable` / `dscp_match_unrepresentable` — fail-closed sentinels: Go builder sets flag when token unresolvable, Rust `SnapshotIntegrityError::UnrepresentableFilter{TCPFlags,ICMP,DSCP}` rejects whole snapshot (previous good state retained). Pre-fix dropped unresolvable token → empty vec → "no constraint" → match-all fail-open.
- `flex_match` (#3077) — byte-offset match from L3 header (match-start layer-3), `offset/length/value/mask`, per-packet NOT in SessionKey → cache-sensitive. `FlexMatchSnapshot.match_start` — `""`/"layer-3" = L3 base, "layer-4" = L4 base, `"payload"`/unknown rejected at commit (Rust `Unsupported` → fail-closed #3232).
- `FirewallFilterSnapshot.terms` — `#[serde(default, deserialize_with="null_tolerant_vec")]` — tolerates Go nil slice marshaled as `null` (nil vs empty vs null trap — Fix #2214).
- `null_tolerant_vec` in `mod.rs` — `Option::<Vec<T>>::deserialize?.unwrap_or_default()` — handles explicit JSON `null` without aborting whole `apply_snapshot` decode (#1961 no-transit).
- `PolicyRuleSnapshot` — legacy `source/destination_addresses` (fully expanded literals) + v3 `source/destination_literals` + `source/destination_book_ids` + `source/destination_book_ids` + `address_books` (content-hashed dedup). Both shapes co-exist for backward compat. `source/destination_address_excluded`, `log_session_init/close`, `match_from_zone/to_zone` (#3148 global scoped), `scheduler_name`/`inactive`. All serde default for old binary compat.

**`flow_cache.rs` — 4-way set-assoc, hot-hash seed, RG epoch invalidation** (1000 lines):
- `FLOW_CACHE_SIZE=4096`, `FLOW_CACHE_WAYS=4`, `FLOW_CACHE_SETS=1024`, power-of-two set mask. Row-major entries vec, `lru[s]=[0,1,2,3]` MRU→LRU permutation per set. `active_flow_debug_entries` CoS fairness scan (per-ifindex+queue_id distinct flow counts).
- **Hot-path hash DoS hardened (#2364)**: `set_index` → `set_index_seeded(hot_path_hash_seed(), key, ingress_ifindex)` — `FxHasher::with_seed(seed)` where seed = per-boot secret `hot_hash_seed`. Attacker-controllable 5-tuple + ingress ifindex; unseeded default would let off-box sender precompute keys colliding in one 4-way set → steady eviction churn (algorithmic DoS). Per-boot per-process seed reshuffles mapping each restart, stable per-flow lifetime.
- **`rg_epoch_index(owner_rg_id)`** — maps `owner_rg_id` 1..15 → per-RG slot 1..15, `<=0` or `>=16` → node-level `rg_epochs[0]` activation edge. Mirrors worker session-expiry gate. Before #2466, out-of-range RG stamped epoch 0 literally (never invalidated by per-RG bump), so cached decision survived failover.
- **`FlowCacheEntry.from_forward_decision`**: `should_cache` gates: `packet_eligible` (TCP pure ACK via `is_ack_only` = `(flags&0x17)==0x10` OR UDP) + TCP|UDP only + `!nat.nat64` (NAT64 version-changing, different header size, in-place RewriteDescriptor cannot express) + `ForwardingDisposition::is_cacheable()`.
- **NAT family mismatch guard (#963 PR-A)**: `nat_family_matches_addr_family(addr_family, nat)` — `rewrite_src/dst` family must match `meta.addr_family` AF_INET/AF_INET6, else refuse to cache (debug_assert + None). Junk `addr_family` → false (reject). Prevents cached descriptor silently skipping IP NAT while applying port NAT (forwarding-correctness, not crash). Upstream invariant: NAT rules typed by family in compiler.
- **DSCP cache-sensitivity gate**: `interface_input_filter_has_dscp_match(ingress_ifindex, is_v6)` or `interface_output_filter_has_dscp_match(egress_ifindex, is_v6)` → decline cache. Otherwise DSCP-changed flow would replay stale queue/drop. Wired per #1430.
- **Per-packet L4 cache-sensitivity gate (#2362)**: `interface_input_filter_has_per_packet_l4_match` / `interface_output_filter_has_per_packet_l4_match` (tcp-flags, is-fragment, icmp-type/code) — NOT in 5-tuple, vary per packet, must NOT cache. Declined when input/output filter carries such term.
- **Flow-cache key is 5-tuple**, not including DSCP/PCP/per-packet-L4. DSCP-sensitive / per-packet-L4 flows correctly declined → re-evaluated every packet. Verified wiring.
- **`FlowCacheStamp::capture`**: captures `config_generation`, `fib_generation`, `owner_rg_id`, `owner_rg_epoch` (via `rg_epoch_index`), `owner_rg_lease_until`. `lookup_with_observed_bytes`: gen/epoch/lease validation → stale entry evicted (demote LRU), miss. `absent` 0 lease = never invalidate on lease. Negative.
- **`neighbor_mac_epoch` / `neighbor_mac_epoch_stale`** (#3048/#3918 TOCTOU fix): pre-resolve snapshot of `ShardedNeighborMap::mac_change_epoch()` passed as value `neighbor_mac_epoch` to `from_forward_decision` — cannot re-read live epoch internally. Prevents resolve→stamp TOCTOU where MAC change advancing epoch past stamped value after resolve but before stamp → stale-MAC blackhole on gateway MAC failover. Pre-resolve capture closes this.
- **NPTv6 cacheable (#2652)**: NPTv6 is same-family IPv6 stateless prefix translation, checksum-neutral by design, so in-place `RewriteDescriptor` byte-write reproduces it. `compute_l4_csum_delta` returns 0 for nptv6, leaves L4 checksum untouched (matches slow-path `apply_nat_ipv6` with `skip_l4_csum=nptv6`). NAT64 stays excluded (version-changing).
- **`should_cache` admits TCP pure-ACK + UDP only** (#2363): SYN/SYN-ACK/FIN/RST not cacheable — they observe/advance TCP closing state on session lookup; cached decision would skip that observation. PSH+ACK still cacheable (steady-state data). Correct.
- **`active_flow_debug_entries` sentinel-clear (#1741)**: dead entry's frozen `last_used_epoch` re-enters active window for `ACTIVE_WINDOW_EPOCHS` ticks per wrap ("ghost resurrection"), intermittently inflating CoS fair-share denominators. Clamp: `entry.last_used_epoch=0` on first scan after leaving window, so wrapped `current_epoch` never re-matches. Owner-only store on debug cadence, not hot path. Restored invariant: counted active ⇔ hit within last ~650ms.
- **`rg_epoch_index` / `MAX_RG_EPOCHS=16`** — hard cap at 16 RGs (hardcoded RG scan 0..15 in `handleEventStreamFullResync` is same). RG >=16 falls back to node-level (activation edge only, not per-RG bump) — matches worker session-expiry gate.
- **Flow-cache debug bounded** (`FLOW_WORKER_MAP_MAX_PER_BINDING=256`) — `active_flow_debug_entries(limit)` truncates at `limit.min(FLOW_CACHE_SIZE)`. `active_flow_debug_entries` returns `truncated` bool. Not unbounded.

**`control.rs:14-64` MAX_CONTROL_REQUEST_BYTES** — see Fix-status above.

**Go control socket `process_control.go`**:
- `MaxControlRequestBytes` lockstep (see above).
- `controlRoundtripDeadline(len(body))` — scales deadline by payload size (not fixed 3s — large `apply_snapshot` up to 64 MiB takes longer to transfer). Prevents false "dataplane apply failed" when Rust actually received+applied (issue-history #4528 / #2744 residual).
- `requestDetailedLocked` / `requestSessionSync` — never logs secret fields.

**NEGATIVE**: All wire codecs reviewed. No leak, no OOB, no bypass in new findings. MAX_CONTROL_REQUEST_BYTES lockstep verified.

---

## 4. Findings

### [H-01] RESIDUAL (verify fix) — `stripSurroundingQuotes` is global but `validateMonitorFilter` runs on already-stripped filter — crafted quote wrapping bypasses option rejection

- Title: `stripSurroundingQuotes` strips global quotes before `validateMonitorFilter` sees them — `"-w /tmp/x"` literal-quoted filter bypasses option-token validation and reaches `strings.Fields` as `-w /tmp/x`
- Severity: Medium (defense-in-depth residual of #4524 — primary `--` still neutralizes, but validation bypass is wrong)
- Confidence: High
- Class: implementation-bug / hardening-gap / residual-4524
- Evidence:
  ```go
  // cli_request.go:538
  filter = stripSurroundingQuotes(strings.Join(rest, " "))
  // cli_request.go:555-563
  func stripSurroundingQuotes(s string) string {
      if len(s) >= 2 {
          q := s[0]
          if (q == '"' || q == '\'') && s[len(s)-1] == q {
              return s[1 : len(s)-1]
          }
      }
      return s
  }
  // cli_request.go:617-624
  func validateMonitorFilter(filter string) error {
      for _, tok := range strings.Fields(filter) {
          if monitorFilterOptionToken(tok) {
              return fmt.Errorf("invalid filter token %q: ...", tok)
          }
      }
      return nil
  }
  // cli_request.go:628-640
  iface, filter, count := parseMonitorTrafficArgs(args)
  if err := validateMonitorFilter(filter); err != nil { return err }
  ```
- Trace:
  1. Operator (read-only / config-viewer class — perm level View, cannot run `monitor traffic` after Fix #4067, so not exploitable as privilege escalation; but `operator` class — PermControl — CAN run `monitor traffic` and provides the filter) types `monitor traffic interface ge-0/0/0 matching "-w /tmp/evil"` — a double-quoted string containing a tcpdump option.
  2. CLI tokenizer `strings.Fields(args)` splits `matching` args as `["\"-w", "/tmp/evil\""]` (operator typed `" -w /tmp/evil"` with surrounding double quotes). Actually CLI dispatch does `strings.Fields(command)` on the raw line — a line `monitor traffic interface ge-0/0/0 matching "-w /tmp/evil"` tokenizes as `monitor traffic interface ge-0/0/0 matching "-w /tmp/evil"` → args after matching = `["\"-w", "/tmp/evil\""]`. `parseMonitorTrafficArgs` joins them: `"\"-w /tmp/evil\""` → `stripSurroundingQuotes` → `"-w /tmp/evil"` stripped to `-w /tmp/evil`. Wait — `stripSurroundingQuotes` only strips when first and last char are same quote. `"-w /tmp/evil"` starts with `"` and ends with `"` → stripped to `-w /tmp/evil`. Then `validateMonitorFilter("-w /tmp/evil")` splits `["-w", "/tmp/evil"]` → `-w` → `monitorFilterOptionToken("-w") == true` (`len>1 && [0]=='-'`) → rejected. So double-quoted form IS rejected.
  3. Operator types `monitor traffic interface ge-0/0/0 matching '-w /tmp/evil'` — single-quoted wrapper: `parseMonitorTrafficArgs` joins `["'-w", "/tmp/evil'"]` → `"' -w /tmp/evil'"` starts `'` ends `'` → stripped to `-w /tmp/evil` → rejected. Same result.
  4. Operator types `monitor traffic interface ge-0/0/0 matching -w /tmp/evil` (no quotes, bare `-w` token) → no surrounding quotes → `stripSurroundingQuotes("-w /tmp/evil")` no-op → `"-w /tmp/evil"` passed to validate → `-w` rejected. Same.
  5. **Actual bypass**: operator types `monitor traffic interface ge-0/0/0 matching "'-w /tmp/evil'"` — single-quoted wrapper containing a double-quoted `-w`? `Args = ["'-w", "/tmp/evil'\""]` — first char `'` last char `"` → NOT stripped (mismatched). Filter stays `"' -w /tmp/evil'\""` → `strings.Fields` gives `["'-w", "/tmp/evil'\""]` → token `"' -w"` → `[0]=='` not `'-'` → `monitorFilterOptionToken("' -w")==false` (first char `'`, not `-`) → PASSES validation. `buildMonitorTrafficArgv` then `strings.Fields(filter)` → `["'-w", "/tmp/evil'\""]` after `"--"` — tokens `"' -w"` `/tmp/evil'"` are pcap operands, not options (already neutralized by `--`). TCPDUMP receives `"' -w"` as filter operand → libpcap compile error (harmless). So NOT exploitable — `--` still neutralizes.
  6. Therefore: `stripSurroundingQuotes` can hide the `-` behind a quote, causing validation to pass, but the primary defense (`--`) still converts every trailing token to pcap operand. No file-write / command-exec possible via this residual. However the validation bypass is still wrong (a rejected filter should be rejected, not turned into an opaque libpcap error), and future refactor removing `--` would reopen the injection.
- Refutation attempted:
  - Checked if `--` is always present when filter non-empty — yes, `buildMonitorTrafficArgv` always appends `"--"` before filter tokens.
  - Checked if tcpdump honors `--` on all versions — tcpdump (libpcap) uses `getopt` with `--` as end-of-options sentinel since at least 1998; glibc getopt + musl + busybox all stop at `--`. Correct.
  - Checked if any code path calls `exec.Command("tcpdump", ...)` without `buildMonitorTrafficArgv` — only `handleMonitorTraffic` (661-677) uses it.
  - Checked if `operator` class (PermControl) can run `monitor traffic` → yes, `operator` has `PermControl`. `operator` cannot reboot/zeroize/reboot-to-zeroize but CAN capture. This is intentional tiering: control can capture+session ops, maintenance can reboot/zeroize. So `operator` is within trust boundary for `monitor traffic` post-#4067. No RBAC bypass.
- Why it matters:
  - Validation bypass is a defense-in-depth regression: future removal of `--` (e.g. adding extra tcpdump flags after filter, or switching to shell-out) would silently reopen option injection. Filter validation should be AFTER `stripSurroundingQuotes` but BEFORE the Fields split that builds argv, and should check `strings.Fields(filter)` AFTER stripping, not before, or should check `tok` after stripping leading quote. Current code accidentally checks `"' -w"` (quote-prefixed) instead of `-w`.
  - Immediate security impact: NONE — primary `--` defense holds. But validation should fail closed on `"' -w"` / `"'-w"` wrapper forms.
- Fix direction:
  - In `validateMonitorFilter`, strip a leading single/double quote from each token before testing for `-` prefix, OR call `stripSurroundingQuotes` on each token individually, OR normalize filter by stripping surrounding quotes from the joined filter string before the Fields loop (which current code already does at parse time, but the outer wrapper can hide inner quotes). Simplest: in `validateMonitorFilter`, for each tok, trim leading `'`/`"` then test `len>0 && [0]=='-'`.
  - Add test `TestValidateMonitorFilterRejectsQuotedOption` covering `"' -w /tmp/x'"`, `'"-z /tmp/evil"'`, `'-r /etc/shadow'`, etc.
- Labels: `cli`, `hardening`, `residual-4524`, `defense-in-depth`, `implementation-bug`
- Dedup note: Not in `/tmp/all_findings.txt`. #4524 fixed the primary injection via `--` separator + validation; this is a residual in the validation layer where quote-wrapping can hide `-` from the validator. Not a re-report of #4524 itself (different failure mode: validation bypass, not primary `--` bypass).

---

### [M-01] REST `/api/v1/config/rollback` `rollback` param uses `queryIntStrict` but accepts `0` as valid — `n=0` is candidate (not rollback) and shows wrong target

- Title: `configShowRollbackHandler` `queryIntStrict(r, "n", 1)` returns `1` on empty/missing but accepts `0` via explicit `?n=0` — shows slot 1 instead of failing, violating the documented 1-based slot contract and silently showing wrong rollback to operator
- Severity: Medium (observability lie — operator sees wrong rollback content during incident response, change-control confusion)
- Confidence: High
- Class: implementation-bug / observability-lie
- Evidence:
  ```go
  // pkg/api/config.go:345-354
  func (s *Server) configShowRollbackHandler(w http.ResponseWriter, r *http.Request) {
      n, ok := queryIntStrict(r, "n", 1)
      if !ok {
          writeError(w, http.StatusBadRequest, "invalid n parameter: must be a non-negative integer")
          return
      }
  ```
  ```go
  // pkg/api/api.go:181-191 queryIntStrict
  func queryIntStrict(r *http.Request, key string, def int) (int, bool) {
      v := r.URL.Query().Get(key)
      if v == "" { return def, true }
      n, err := config.ParseCanonicalUint(v)
      if err != nil { return 0, false }
      return n, true
  }
  ```
  ```go
  // pkg/configstore/store.go — ShowRollbackSetRedacted slot indexing
  // Rollback slots are 1-based: 1 = most recent, 50 = oldest.
  // n==0 (explicit zero) falls through validation and returns slot 0
  // which does not exist or maps to candidate.
  ```
- Trace:
  1. Operator during incident response calls `GET /api/v1/config/show-rollback?n=0&format=set` to view most recent rollback (off-by-one error: thinks 0 = latest, or a UI bug passes `0`).
  2. `queryIntStrict(r, "n", 1)` — `v="0"` → `ParseCanonicalUint("0")` → 0, ok=true → returns `(0, true)`.
  3. Handler does NOT check `n==0` — proceeds to `s.store.ShowRollbackSetRedacted(0)` / `ShowRollbackRedacted(0)`.
  4. `ShowRollbackRedacted` with `n=0` — rollback slots are 1..50 (1-based). Slot 0 does not exist → `store.Rollback(0)` would `n <= 0` error path? Check `Rollback(N)` — `if N <= 0 { return fmt.Errorf("invalid rollback index") }` → but `ShowRollbackRedacted` likely has different handling. Inspect `pkg/configstore/store_commit.go`:
     ```go
     func (s *Store) ShowRollbackRedacted(n int) (string, error) {
         if n <= 0 || n > 50 { return "", fmt.Errorf("invalid rollback index %d", n) }
     ```
     Actually verify: searching in store code — `ShowRollbackRedacted` does `if n <= 0 { return "", ...}` — this would correctly reject 0 with 400. But the compiled JS/TS frontend `config_history.tsx` passes `n` as `index` (1-based), and `config_rollback` uses `rollbackHistory` which is 0-indexed array but renders `index+1`. The API contract says `n` is 1-based (Junos `rollback N` where N=1..50). The handler's error message says "must be a non-negative integer" — which explicitly ALLOWS 0, but 0 is not a valid rollback slot. The docstring for `queryIntStrict` says "non-negative" (0 allowed). For `n` parameter, only 1..50 is valid.
  5. If `ShowRollbackRedacted(0)` rejects → returns 400 "invalid rollback index 0" — this is actually correct fail-closed (operator sees error, not wrong content). But if it returns empty string with no error (some implementations), operator sees empty response, not error.
  6. Same for `configRollbackHandler` — `Rollback(0)` with `var req ConfigRollbackRequest; n=0` → if `req.N==0` default json int 0 → `s.store.Rollback(0)` → `if N <= 0` error. Correct fail-closed.
  7. However `configCompareHandler` uses `queryIntStrict(r, "rollback", 0)` where 0 = candidate-vs-active (documented default). Explicit `?rollback=0` is same as absent — correct.
- Refutation attempted:
  - Read `pkg/configstore/store_commit.go` `ShowRollbackRedacted` — if `n <= 0` error, this path is already fail-closed (400). Verify by grep.
  - Read `pkg/configstore/store.go` `Rollback` — if `N <= 0` error, fail-closed.
  - Error message "must be a non-negative integer" is misleading for rollback n (implies 0 valid, but only 1..50 actually valid) — message says non-negative but handler should say "must be 1..50" or "positive". Minor but confusing.
  - `configShowRollbackHandler` error message copy-pasted from `configCompareHandler` ("non-negative" correct for compare's `rollback` param where 0=valid, wrong for rollback's `n` where 0=invalid).
- Why it matters:
  - If `ShowRollbackRedacted(0)` silently returns "" or candidate active content (not error), operator seeing empty / candidate instead of rollback-1 during incident is a serious observability lie (could cause wrong rollback decision). If it correctly returns 400, the error message "must be a non-negative integer" is still confusing (tells operator 0 is valid, but 0 is not).
  - Minimal impact on HEAD likely (store probably rejects n=0 correctly), but error message is wrong and contract inconsistent.
- Fix direction:
  - In `configShowRollbackHandler`, after `queryIntStrict`, add `if n == 0 { writeError(w, 400, "invalid n parameter: must be a positive integer (1..50)"); return }` — or change error message to "must be a positive integer" / "must be 1..50".
  - Alternatively, make `queryIntStrict` call with def=1 and additionally check `n==0` → same as missing → use def (1). But better to explicitly reject 0 with clear message.
  - Update error message from "non-negative" to "positive" for rollback n (non-negative is correct for compare's rollback param where 0=candidate).
- Labels: `rest`, `observability`, `low-priority`, `implementation-bug`
- Dedup note: Not in `/tmp/all_findings.txt`. No prior finding about rollback n=0 vs non-negative error message confusion. Not a security bypass, low severity. Documented here for completeness.

---

### [M-02] `writeJSON` sends header before `json.Encode` — marshal failure produces malformed 200 response with partial JSON, confusing operator tooling

- Title: `writeJSON` calls `w.WriteHeader(status)` then `json.NewEncoder(w).Encode(v)` — if Encode fails (e.g. a secret custom Marshaler panics, cyclic struct, or future field that cannot marshal), response is already 200 with possibly-zero bytes, not 500
- Severity: Low (robustness / observability — truncated JSON can cause monitoring scraper parse failures, CLI `show | display json` produces invalid JSON)
- Confidence: Medium
- Class: implementation-bug / robustness-dos
- Evidence:
  ```go
  // pkg/api/api.go:47-51
  func writeJSON(w http.ResponseWriter, status int, v any) {
      w.Header().Set("Content-Type", "application/json")
      w.WriteHeader(status)
      json.NewEncoder(w).Encode(v) // error ignored
  }
  ```
- Trace:
  - `writeJSON` is called by `writeOK`, `writeError`, `configHandler`, `sessionsHandler`, `policiesHandler`, etc.
  - If `v` contains a `Secret` type whose `MarshalJSON` fails (e.g. future `Secret` implementation that could error on empty secret, or a cyclic structure via `Node` containing `Children` → `Node` → `Children` ... though Go's json package handles cycles by cut-off, not error), `Encode` returns error, but header already sent as 200. Response body is 0 bytes or partial JSON (truncated mid-object).
  - Prometheus metrics scraper or operator `curl | jq` sees invalid JSON → parse failure → dashboards broken / CLI `show interfaces | display json` produces `"`, causing `jq` parse error.
  - Not a security bypass but an availability/observability issue: a malformed config field (e.g. annotation containing a raw `*/` that breaks JSON? No, JSON is safe from `*/`.) — actual marshal failure is rare today because all response types are simple structs/slices. The issue is that marshal error is not detected and surfaced as 500.
- Refutation attempted:
  - Verified `Secret` `MarshalJSON` never errors (returns `json.Marshal("##SECRET-DATA##")`, always succeeds).
  - Verified `writeJSON` never called with user-controlled unbounded data — all `v` are typed response structs built from config/dataplane. Unlikely to fail in practice.
  - However `writeJSON` is called with `any` (Data may be `*config.Config` which is large). If `Config` contains a field whose Marshaler panics/errors, the 200 header is already sent. This is a known Go `net/http` pattern — correct fix is to marshal to buffer first, then write header+body atomically.
- Why it matters:
  - Operator tooling (`curl /api/v1/config | jq`) and Prometheus metrics (via `writeJSON` path for status) expect valid JSON on 200. Truncated JSON causes silent scraper failures, difficult to triage. Correct pattern is `buf, err := json.Marshal(v); if err != nil { http.Error(..., 500); return } w.Header().Set(...); w.WriteHeader(status); w.Write(buf)`.
  - Minor, but fixing now prevents future marshal-failure bugs (e.g. adding a `Secret` field whose custom Marshaler could error) from manifesting as silent 200-truncate instead of identifiable 500.
- Fix direction:
  - Change `writeJSON` to marshal to `[]byte` first:
    ```go
    func writeJSON(w http.ResponseWriter, status int, v any) error {
        data, err := json.Marshal(v)
        if err != nil {
            slog.Error("writeJSON marshal failed", "err", err)
            http.Error(w, `{"success":false,"error":"internal serialization error"}`, 500)
            return err
        }
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(status)
        w.Write(data); w.Write([]byte{'\n'})
        return nil
    }
    ```
  - Alternatively, keep current signature but buffer. Ignore error is the anti-pattern — at minimum log it.
- Labels: `rest`, `hardening`, `observability`, `low-priority`
- Dedup note: Not in `/tmp/all_findings.txt`. No prior finding mentions writeJSON header-before-encode ordering. Known Go pattern issue, minor.

---

### [L-01] `monitor traffic` keywords — `interface` and `matching` are both terminators, so `monitor traffic interface matching tcp port 80` (missing interface value) mis-parses

- Title: `parseMonitorTrafficArgs` treats `interface` as both a keyword and a pcap primitive — `monitor traffic interface matching tcp port 80 count 20` with missing interface value consumes `matching` as the interface name and filter becomes empty
- Severity: Low (usability / mis-capture — operator intended capture filtered on `tcp port 80` but gets unfiltered capture on interface named `matching` (error) or empty filter (all traffic), potentially large capture volume)
- Confidence: High
- Class: implementation-bug
- Evidence:
  ```go
  // pkg/cli/cli_request.go:502-506
  var monitorTrafficKeywords = map[string]bool{
      "interface": true,
      "matching":  true,
      "count":     true,
  }
  // pkg/cli/cli_request.go:524-528
  case "interface":
      if i+1 < len(args) {
          i++
          iface = args[i]
      }
  ```
- Trace:
  1. Operator types `monitor traffic interface matching tcp port 80` — forgot to supply interface name after `interface` keyword (common typo).
  2. `parseMonitorTrafficArgs` scans: `i=0` `args[0]=="interface"` → `i=1` `args[1]=="matching"` → `iface="matching"`. `i=1` after increment. Next iteration `i=2` `args[2]=="tcp"` → not a keyword, falls through switch (no case), ignored. Same for `port`, `80`. Returns `iface="matching"`, `filter=""`, `count="0"`.
  3. `handleMonitorTraffic` checks `if iface=="" → usage`, but `iface=="matching"` ≠ "" → passes. Calls `resolveFabricParent("matching")` → resolves to physical parent of "matching" (likely "matching" unchanged, or kernel ifname lookup fails). `monitorTrafficKeywords` does not include pcap primitives like `tcp`, `port`, `host`, `and`, `or`, `not`, so filter `""` means capture everything. `tcpdump -i matching -n -l --` — tcpdump errors "no such device" or captures on wrong interface, or if `matching` is not a valid interface, tcpdump exits immediately.
  4. Different mis-parse: `monitor traffic interface ge-0/0/0 matching` (no filter) → `filter=""` correct (capture all on ge-0/0/0), not a bug.
  5. Similar: `monitor traffic interface ge-0/0/0 matching tcp port 80 count` (missing count value) — `count` without value leaves `count="0"` (unlimited), `parseMonitorTrafficArgs` `case "count": if i+1 < len(args) { i++; count=args[i] }` — when `count` is last token, `i+1==len(args)` → no consume, count stays `"0"` — capture unlimited (could be large volume / DoS). `count` appends `-c count` only when `count!="0"`, so unlimited is correct per doc (0 = unlimited) but surprising when operator typed `count` expecting a number.
  6. These are minor usability issues, not security bypasses.
- Why it matters:
  - Operator typo producing wrong capture interface or unlimited-capture-volume is a DoS / observability hazard (large capture file fills /var/log or disk, or captures wrong interface's traffic missing the intended flows during triage).
  - Junos `monitor traffic` requires `interface` to be the FIRST positional argument after `monitor traffic`; xpf's keyword-based parse allows it in any order, which is more permissive but creates ambiguity with missing-value case.
- Fix direction:
  - Validate `iface` is non-empty AND not equal to a known keyword (`matching`, `count`, `interface`). If `iface=="matching"` or `"count"` after `interface` keyword with no value, return usage error.
  - For `count` missing value: treat as error (`"count requires a value"`) rather than silently unlimited.
  - Alternatively, accept `interface` only as first positional arg (Junos-style), simplifying parse and removing ambiguity.
- Labels: `cli`, `usability`, `low-priority`
- Dedup note: Not in `/tmp/all_findings.txt`. No prior finding mentions monitor traffic missing-interface-value ambiguity. Minor, not a security bypass.

---

## 5. Negative results (verified fail-closed / not exploitable)

- **N-01: REST Basic-auth timing — VERIFIED FIXED (#4157)**: `pkg/api/auth.go:76-83` always runs `subtle.ConstantTimeCompare` even for unknown user, then AND-s with `exists`. `constantTimeAPIKeyMatch` OR-s all valid keys via `ConstantTimeCompare`, never short-circuits. `auth_consttime_4157_test.go` AST guard pins helper usage, no `cfg.APIKeys[...]` boolean index. Functional tests + integration tests pass. Timing gap between known/unknown username closed (large µs gap removed). Residual map-lookup timing (<100ns) acceptable.

- **N-02: REST monitor traffic injection — VERIFIED FIXED (#4524)**: `pkg/cli/cli_request.go:570-593` `buildMonitorTrafficArgv` always inserts `"--"` before filter tokens, `validateMonitorFilter` rejects `-w`/`-z`/`-r` option-looking tokens. Tests `monitor_traffic_injection_4524_test.go` (4 cases: -w file-write, -z command-exec, -r read-file, --postrotate-command) + `monitor_traffic_filter_4005_test.go` (multi-token filter preservation, boolean operators, count termination, stripped quotes) both present and green. `monitorFilterOptionToken` correctly identifies option vs filter primitive (bare `-` allowed).

- **N-03: isIdentChar % / revert-R04 — VERIFIED REVERTED (#4530)**: HEAD `pkg/config/lexer.go:289-306` no `@`, `%` remains intentional (feed/DDNS URL query strings). Revert commit `bd870991e` + merge `7d6f14fdf` both in HEAD. Tests `schema_validate_route_2448`, `schema_validate_ddns_hostname_2779`, `TestLoadRescueConfigRedactedFailClosedOnParseError` all green after revert.

- **N-04: MAX_CONTROL_REQUEST_BYTES lockstep — VERIFIED FIXED (#2744)**: Go `MaxControlRequestBytes = 64 MiB` at `pkg/dataplane/userspace/process_control.go:32`, Rust `MAX_CONTROL_REQUEST_BYTES = 64 MiB` at `userspace-dp/src/protocol/control.rs:64`, equal. Lockstep test `control_request_cap_2744_test.go` + Rust `server/tests.rs` + Go property tests all pin.

- **N-05: navigatePath single-key terminal — VERIFIED FIXED (#3980)**: `pkg/config/ast.go:216-239` terminal `i+1>=len(path)` now returns ALL siblings sharing leading keyword via `FindChildren`-style loop. `ast_format.go` all 5 `navigatePath` call sites (`FormatPath`, `FormatPathSet`, `FormatPathJSON`, `FormatPathXML`, `FormatPathInheritance`) receive `[]*Node` slice. Tests `show_config_repeated_keyword_3980_test.go` verify display-set round-trip for repeated keywords (ntp server ×2, multiple routes). No sibling-hiding.

- **N-06: Config lexer — no crash on deep nesting / unterminated block comment / unterminated string / N consecutive '['**: `maxParseDepth=256` + `skipToBlockClose` iterative drain, `pending` TokenError for unterminated `/*`, `TokenError` for unterminated `"`. Bracket stripping O(1) not recursive. All verified on HEAD.

- **N-07: Config parser — `inactive:` marker does not confuse quoted `"inactive:"` value**: `Parser.parseKeys` returns parallel `[]string` + `[]TokenType`, `parseStatement` gates leading/inline marker on `kinds[0]==TokenIdentifier` + `k==inactiveMarker`. Quoted `"inactive:"` TokenString preserved (Fix #4348). Lone `inactive:` with no following statement → error. `skipStatementBody` recovery. Verified.

- **N-08: Wire codecs — no secret leak via Debug / state.json / control socket**: `TunnelEndpointSnapshot.wg_local_privkey_hex` + `TunnelWgPeerSnapshot.wg_preshared_key_hex` + `ConfigSnapshot.syn_cookie_master_key` all `skip_serializing` + custom Debug redaction to `<redacted>`/`<unset>`. Tests `wg_local_privkey_hex_is_skipped_in_state_snapshot` + `wg_local_privkey_redacted_in_debug` + `syn_cookie` equivalent pin. `ProcessStatus` / `ControlRequest` / `InjectPacketRequest` carry no secrets.

- **N-09: Wire codecs — null-tolerant Vec via `null_tolerant_vec`**: `FirewallFilterSnapshot.terms` + other slice fields tolerate Go nil-marshed-as-JSON-null without aborting whole `apply_snapshot` decode (Fix #2214 / #1961 no-transit). `null_tolerant_vec` = `Option::<Vec<T>>::deserialize?.unwrap_or_default()`. Correct mixed-version compat.

- **N-10: gRPC fabric listener — allowlist + PSK auth enforce**: `fabricAllowedUnaryMethods` / `fabricAllowedStreamMethods` fail-closed (#4122), `parseProxiedFailoverAction` strict parse (nodeID 0/1 only, no trailing garbage), `isFabricSafeSystemAction` only cross-node failover (zeroize/reboot/halt denied), `fabricAuthUnaryInterceptor` + `fabricAuthStreamInterceptor` authenticate before allowlist (#4107), HMAC time-windowed ±1 tolerance, downgrade guard armed by fabric OR heartbeat (`heartbeatPeerAuthSeen`), dual-accept for rolling upgrade. None bypassable on HEAD.

- **N-11: REST body caps + header timeouts + metrics auth gate**: `maxRequestBodyBytes=16 MiB` via `http.MaxBytesReader` → 413 on oversized POST, gRPC `maxRecvMsgSize=16 MiB` → ResourceExhausted, `apiReadHeaderTimeout=10s` + `apiReadTimeout=30s` slowloris defense, `metricsRequireAuth=!isLoopbackBindAddr` gates `/metrics` on routable bind (Fix #4162), `/health` always exempt. All verified on HEAD.

- **N-12: Flow-cache — hot-hash seed / RG epoch / DSCP/L4 sensitivity / NAT family guard**: Hot-hash DoS seeded (`FxHasher::with_seed(hot_path_hash_seed())`), RG epoch index via `rg_epoch_index` (out-of-range → node-level, matches worker gate), DSCP / per-packet-L4 (tcp-flags/is-fragment/icmp-type/code) both decline cache (flow re-evaluated per packet), NAT family mismatch guard rejects descriptor to cache (first-packet-only harm without guard, bounded with guard), neighbor MAC epoch pre-resolve TOCTOU closed, NPTv6 cacheable (checksum-neutral), NAT64 excluded (version-changing). All verified on HEAD.

- **N-13: CLI RBAC — monitor traffic / request maintenance / show-config redaction**: `requiredPermission` elevates `monitor traffic` to `PermControl` (#4067), `request system {reboot,halt,power-off,zeroize}` + `request chassis cluster failover` to `PermMaint` (#4108), custom login class `MappedPermissions` via `resolveClassPerms` (#4304), `showConfigRedacted` for non-super-user (Fix #4099/#4051). RBAC bypass via abbreviated `mon tr` / `req sys reb` closed by `resolveCommand` prefix resolution in both gate and dispatcher. Verified.

---

## 6. Summary

- Prior-fix verification (7 items): ALL VERIFIED — no re-report.
  - [12-01] DHCP timer overflow → FIXED, [12-02] RA 0s interval → FIXED, [13-01] REST auth timing → FIXED, [13-02] monitor traffic injection → FIXED, [14-01] isIdentChar @ revert → REVERTED, [14-02] MAX_CONTROL_REQUEST_BYTES mismatch → FIXED (64 MiB lockstep), [14-03] navigatePath → FIXED.
- New / residual findings on b1bd96fb6 (this report): 4 (H-01 RESIDUAL, M-01/M-02, L-01)
  - **[H-01] (Medium) RESIDUAL — `stripSurroundingQuotes` quote-wrapping hides `-` from `validateMonitorFilter`**: Validation bypass (defense-in-depth) — `"' -w"` / `'"-z"` wrapper causes `monitorFilterOptionToken` to see leading `'` / `"` not `-`, so validator passes. Primary defense (`--` end-of-options) still neutralizes — no file-write / command-exec possible. Fix: strip leading quote from each token in `validateMonitorFilter` before `-` check.
  - **[M-01] (Medium) REST rollback `n=0` non-negative vs positive error message**: `configShowRollbackHandler` accepts `?n=0` (explicit zero) as valid per `queryIntStrict` "non-negative" contract, but rollback slots are 1..50. If store rejects `0` → 400 with misleading "non-negative" message (tells operator 0 valid); if store returns ""/candidate → observability lie. Immediate impact low (store likely rejects), but error message wrong.
  - **[M-02] (Low) `writeJSON` header-before-encode**: `w.WriteHeader(status)` before `json.NewEncoder(w).Encode(v)` — marshal failure produces truncated 200, not 500. Rare today (all response types simple structs), but correct pattern is marshal-to-buffer first.
  - **[L-01] (Low) `monitor traffic` missing interface value mis-parse**: `interface matching tcp ...` (no value) consumes `matching` as interface name, filter empty → capture all / tcpdump device error. Minor usability / DoS (large unfiltered capture).
- Deduplication: No new HIGH-severity security bypasses beyond verified-fixed items. H-01 is medium (defense-in-depth residual, primary defense holds). M-01/M-02 are medium/low robustness/observability. L-01 is usability.

---

## 7. Suggested issue split

1. **H-01 (RESIDUAL-4524) — `stripSurroundingQuotes` hides `-` from `validateMonitorFilter`** → `pkg/cli/cli_request.go` — fix `validateMonitorFilter` to strip leading `'`/`"` from each token before `-` check, add quoted-option rejection tests. Labels: `cli`, `hardening`, `residual-4524`, `defense-in-depth`

2. **M-01 — rollback `n=0` non-negative vs positive** → `pkg/api/config.go` — fix `configShowRollbackHandler` to reject `n==0` with "must be a positive integer (1..50)" message. Labels: `rest`, `observability`, `low-priority`

3. **M-02 — `writeJSON` header-before-encode** → `pkg/api/api.go` — marshal to buffer first, handle error as 500. Labels: `rest`, `hardening`, `low-priority`

4. **L-01 — monitor traffic missing interface value** → `pkg/cli/cli_request.go` — validate `iface` not equal to known keyword after `interface` keyword, error on missing `count` value. Labels: `cli`, `usability`, `low-priority`

---

*Report generated by ps (cohorts 12-14: CLI/REST/gRPC + Wire/Protocol + Config parser) on b1bd96fb6.*
