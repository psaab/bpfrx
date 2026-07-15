# A8: API Security Review — gRPC / REST Surfaces

Base: d4506d4450e2
Reviewer: A8 (API-security)
Paths: pkg/grpcapi/*.go, pkg/api/*.go

## Summary

Full review of every gRPC handler (server.go, server_config.go, server_show*.go, server_diag.go, server_sessions.go, fabric_auth.go, server_admin/system_action via server_diag.go) and every REST handler (server.go, api.go, auth.go, config.go, security.go, sessions.go, sse.go, system.go, health.go, metrics*.go). Focus: untrusted-input validation on every RPC/HTTP field, injection, authz/allowlist enforcement, integer/format handling, resource leaks, DoS amplification, graceful shutdown.

No new High/Confident issues found. Fabric listener hardening (#4107 + #4122) is correctly layered. Input validation on session pagination, zone filters, protocol filters, CIDR parsing, rollback guards is consistently fail-closed. Several low-severity hardening observations noted.

---

## Finding A8-01: gRPC Rollback accepts negative N — opaque error message

- Title: gRPC Rollback with negative N returns opaque history error instead of clear InvalidArgument
- Severity: LOW
- Confidence: High
- Evidence:
  - `pkg/grpcapi/server_config.go:252-258` — `Rollback` passes `int(req.N)` directly to `s.store.Rollback` with no n-validation
  - `pkg/configstore/store_commit.go:498-524` — `Rollback(n)` handles n==0 as "revert to active" (valid), n>0 as history lookup, n<0 falls to `s.history.Get(n-1)` which returns ErrOutOfRange with opaque message like "history position -6 out of range"
  - Contrast: `ShowRollback` (`server_config.go:324-327`) explicitly guards `req.N <= 0` with clear message "rollback index must be a positive integer" (fixed in 906b4de)
  - Contrast: `ShowCompare` (`server_config.go:307-310`) guards `req.RollbackN < 0` with clear message
  - REST `configRollbackHandler` (`pkg/api/config.go:156-166`) delegates to `store.Rollback(req.N)` — same gap; `queryIntStrict` in `configShowRollbackHandler` guards n but not this path
- Trace:
  - gRPC client sends `RollbackRequest{N: -5}` → `server_config.go:253` → `store.Rollback(-5)` → `store_commit.go:520` → `s.history.Get(-6)` → opaque error wrapped as `status.Errorf(codes.InvalidArgument, ...)` → client sees "history position -6 out of range" instead of "invalid rollback index"
  - Functionally fail-closed (no wrong rollback target selected) — n==0 is valid ("revert to active"), negative n cannot select an unintended slot because Get() rejects it
- Refutation attempt:
  - Could negative n cause wrong behavior? No — `history.Get` validates bounds and returns error for any negative index. n==0 is intentionally valid ("revert to active", same as Junos `rollback 0`). Negative n only produces an opaque error message, not a security bypass or wrong-target rollback.
- HPC check: N/A — control-plane only, no dataplane iteration
- Why it matters: Operator tooling/scripting that sends a negative N (e.g. off-by-one in automation) gets an opaque "history position -6 out of range" instead of a clear "rollback index must be non-negative" — degrades debuggability, especially in HA where the error traverses node hops
- Fix direction: Add `if req.N < 0 { return nil, status.Errorf(codes.InvalidArgument, "invalid n %d: rollback index must be non-negative (0 = revert to active)", req.N) }` mirroring `ShowCompare`'s guard; same for REST `configRollbackHandler`
- Labels: [low, ux, message-quality, grpc, rest]
- Dedup note: #4556 LOW batch fixed ShowRollback n<=0 (906b4de) and ShowCompare negative rollback_n (#3443 M6) but did not cover the Rollback RPC's negative N — Rollback is the one verb where n==0 is legitimately "revert to active" so it wasn't caught by the n<=0 pattern. #3443 covered compare, not rollback.

---

## Finding A8-02: REST config/search URL query parameter not length-bounded beyond MaxHeaderBytes

- Title: /api/v1/config/search q parameter bounded only by MaxHeaderBytes (1 MiB), search is O(lines × query_len) with full config text materialization
- Severity: LOW
- Confidence: High
- Evidence:
  - `pkg/api/config.go:253-269` — `configSearchHandler` reads `q := r.URL.Query().Get("q")` with no length check
  - `text := s.store.ShowActiveRedacted(nil)` — materializes entire active config (potentially large)
  - `strings.Contains(line, query)` for every line — O(total_config_bytes × query_len) worst case
  - `pkg/api/server.go:330` — `apiMaxHeaderBytes = 1 << 20` — URL query (header) capped at 1 MiB total, but `q` alone could be ~1 MiB
  - Contrast: `decodeJSONBody` caps at `maxRequestBodyBytes = 16 MiB` for mutations; search is GET, uses URL query, not JSON body
  - Same pattern in REST GET handlers: `queryIntStrict` validates numeric types but search's string `q` has no length guard
- Trace:
  - Attacker with valid API auth sends `GET /api/v1/config/search?q=<1 MiB of 'a' × 1M>` → `ShowActiveRedacted` materializes config (~100 KB) → splits into lines (~1K lines) → `strings.Contains(line, 1MiB_query)` for each line → legitimate work but measurable CPU (strings.Contains with 1 MiB needle over short haystack is linear in haystack, not needle, so total ~1M × 1K × avg_line_len... actually strings.Contains short-circuits when needle > haystack, so O(lines) with early reject)
  - `strings.Contains` when `len(needle) > len(haystack)` returns false immediately (Go standard library checks `len(substr) > len(s)` first) — so the cost is actually O(lines) comparisons with early-out, ~1K iterations of a length check. Not a real DoS.
- Refutation attempt:
  - `strings.Contains` docs: "Contains reports whether substr is within s. If len(substr) == 0, true. If len(substr) > len(s), false." The `len(substr) > len(s)` check is O(1) — a 1 MiB query against typical config lines (avg ~50 bytes) returns false instantly. A query of moderate length (e.g. 40 bytes) against all lines is O(total_config_bytes), which is bounded by MaxConfigSize (16 MiB). Not a practical DoS.
  - `maxHeaderBytes` already caps total URL to 1 MiB, which includes all query parameters plus path plus headers. A legitimate search query is a few bytes. An attacker abusing this would need valid API credentials already.
- HPC check: N/A — single request, no hot-path contention
- Why it matters: Defense-in-depth — search is a read-only GET, but consistent length validation on string query params prevents any future change (e.g. switching to regex search) from becoming a ReDoS vector
- Fix direction: Add `if len(query) > 256 { writeError(w, 400, "q parameter too long"); return }` — a search query longer than 256 bytes is never legitimate config search. Alternatively, bound to e.g. 1024.
- Labels: [low, dos, rest, defense-in-depth]
- Dedup note: No prior dedup covers config/search DoS — #4549 LOW batch covers resource exhaustion in other areas but not this endpoint.

---

## Finding A8-03: gRPC page_token codec allocates binary.Size(key) (16 bytes) but only populates 13

- Title: gRPC encodePageTokenV4 allocates full struct size including padding, token carries 3 garbage bytes
- Severity: INFO (correctness / determinism)
- Confidence: High
- Evidence:
  - `pkg/grpcapi/server_sessions.go:1342-1351` — `encodePageTokenV4`:
    ```go
    b := make([]byte, binary.Size(key))  // 16 bytes (4+4+2+2+1+3 pad)
    copy(b[0:4], key.SrcIP[:])
    copy(b[4:8], key.DstIP[:])
    binary.NativeEndian.PutUint16(b[8:10], key.SrcPort)
    binary.NativeEndian.PutUint16(b[10:12], key.DstPort)
    b[12] = key.Protocol
    // b[13:16] — never written, stays 0
    return base64.RawURLEncoding.EncodeToString([]byte("v4:" + hex.EncodeToString(b)))
    ```
  - `pkg/api/sessions.go:1219-1227` — REST `encodePageTokenV4` correctly allocates exactly 13:
    ```go
    b := make([]byte, 13)
    copy(b[0:4], key.SrcIP[:])
    ...
    b[12] = key.Protocol
    ```
  - `decodeSessionKeyV4` (`server_sessions.go:1384-1395`) checks `len(b) < binary.Size(key)` (16) for gRPC but REST checks `len(b) < 13` — both work because gRPC token carries 16 hex chars (32 hex digits) and REST carries 13 (26 hex digits), both decode correctly
  - The 3 zero-padding bytes are deterministic (always 0) so tokens are deterministic; but the encoding is structurally asymmetric between gRPC (16-byte payload) and REST (13-byte payload) for the same session key
- Trace:
  - gRPC token: `base64("v4:" + hex(16-byte-struct))` — last 6 hex chars always "000000" (3 zero pad bytes)
  - REST token: `base64("v4:" + hex(13-byte-minimal))` — no padding
  - Both decode correctly because `hex.DecodeString` handles both lengths and `decodeSessionKeyV4` only reads [0:4],[4:8],[8:10],[10:12],[12]
  - No functional bug: tokens round-trip correctly on both surfaces. gRPC tokens are just 6 hex chars (3 base64 chars) longer than necessary.
- Refutation attempt: Deterministic, correct, no security issue. The 3-byte waste is negligible (tokens are short-lived pagination cursors). REST and gRPC tokens are never cross-decoded (they're opaque to clients, each surface only decodes its own tokens). Not a real issue.
- HPC check: N/A
- Why it matters: Minor — token size discipline, cross-surface asymmetry. If future code ever compares gRPC vs REST tokens for the same session (e.g. debug logging), the asymmetry is surprising.
- Fix direction: Change gRPC `encodePageTokenV4` to `make([]byte, 13)` matching REST, and `decodeSessionKeyV4` length check to `len(b) < 13`. Same for v6 (gRPC `binary.Size(key)` = 40, REST = 37, 3 pad bytes). Or leave as-is with comment explaining the padding is intentional for struct alignment.
- Labels: [info, determinism, pagination]
- Dedup note: No prior issue covers page_token padding asymmetry.

---

## Negative Findings (reviewed, no issue)

### N-01: Fabric allowlist — correctly fail-closed
- `pkg/grpcapi/server.go:328-454` — `fabricAllowedUnaryMethods` + `fabricAllowedStreamMethods` + `isFabricSafeSystemAction` correctly gate all fabric RPCs. `SystemAction` is NOT blanket-allowed; only `cluster-failover-data:node<N>` and `cluster-failover:<rgID>:node<N>` pass `parseProxiedFailoverAction`. Destructive actions (zeroize/reboot/halt/power-off/clear-*/cluster-failover-reset) are denied on fabric. Verified `clear-config-lock` RPC does not exist as SystemAction on fabric (it routes through `isFabricSafeSystemAction` which rejects it). Loopback listener has NO allowlist (full service). **No issue.**

### N-02: Fabric auth — HMAC PSK dual-accept + downgrade guard
- `pkg/grpcapi/fabric_auth.go` — `fabricAuthDecision` correctly implements dual-accept (rolling upgrade grace) + sticky downgrade-guard armed by EITHER valid fabric token OR `heartbeatPeerAuthSeen` (fast arming within ~200ms). `verifyFabricAuthToken` accepts ±1 window (60-90s tolerance), correct for NTP. `fabricAuthWindowSeconds=30` bounds replay to ~60-90s. `fabricPeerAuthSeen` is sticky (once set, tokenless always rejected). `computeFabricAuthToken` uses `hmac.Equal` (constant-time). `fabricAuthTokenFromMetadata` rejects empty token. `checkFabricAuth` runs BEFORE `fabricAllowlist*` (auth before authz). Interceptor chain in `RunFabricListener` is `fabricAuth→fabricAllowlist→configLock`. **No issue.**

### N-03: Fabric dial — plaintext + PSK auth
- `pkg/grpcapi/server_diag.go:652-707` — `dialPeer` uses `insecure.NewCredentials()` (no TLS) but attaches `fabricAuthCreds` HMAC token per-RPC. Residual: HMAC token is replayable within window, transport is plaintext (eavesdroppable on fabric network segment). This is the documented #4107 residual — mTLS is #4047 deferred. The fabric network is a private/dedicated link (not routable), so plaintext is acceptable risk. **Known residual, not re-reporting.**

### N-04: REST auth — constant-time comparison, /metrics gating
- `pkg/api/auth.go` — `constantTimeAPIKeyMatch` compares against ALL keys with `ConstantTimeCompare`, no short-circuit, closing the timing side-channel (#4157). `isLoopbackBindAddr` correctly treats wildcard/empty/hostname as non-loopback (conservative). `authMiddleware` requires auth for /metrics on non-loopback binds. `checkAuthorization` always runs `ConstantTimeCompare` even for unknown user. **No issue.**

### N-05: gRPC maxRecvMsgSize / REST maxRequestBodyBytes — DoS bound
- `pkg/grpcapi/server.go:51` — `maxRecvMsgSize = 16<<20` — matches `configstore.MaxConfigSize`, preventing OOM from oversized config-load. `pkg/api/api.go:96` — `maxRequestBodyBytes = 16<<20` — same bound for REST. Both surfaces bounded. `grpc.MaxRecvMsgSize` returns `ResourceExhausted` at transport layer (no buffer growth). REST `http.MaxBytesReader` returns 413. **No issue.**

### N-06: HTTP server timeouts — slowloris defense
- `pkg/api/server.go:315-344` — `ReadHeaderTimeout=10s`, `ReadTimeout=30s`, `IdleTimeout=120s`, `MaxHeaderBytes=1MiB` — all set, no zero values (G112/G114). `WriteTimeout` intentionally 0 (SSE streams + large scrapes). TLS min version 12. **No issue.**

### N-07: Session filter validation — fail-closed on malformed input
- `pkg/grpcapi/server_sessions.go:328-447` — `sessionFilter.validate()` correctly rejects: invalid zone (>65535), invalid port (>65535), unknown protocol (via `appid.ProtocolNumberLenient`), bad CIDR prefix, unknown NAT pool. Every invalid-input branch sets `f.inputErr` via `setInputErr` so a filtered clear cannot degrade to clear-all. REST `buildSessionQuery` mirrors with same fail-closed. **No issue** (this was the Codex r2 Critical that was fixed).

### N-08: Config lock — auto-release on disconnect
- `pkg/grpcapi/server.go:456-472` — `configLockInterceptor` releases config lock when `ctx.Err() != nil` (client disconnect). Uses `peerSessionID` from gRPC peer address. REST config enter/exit is also bounded by `EnterConfigure`/`ExitConfigure` with `ErrConfigLocked`. **No issue.**

### N-09: Pagination — negative offset rejected, cursor iteration
- `pkg/grpcapi/server_sessions.go:42-45` — `req.Offset < 0` rejected with InvalidArgument BEFORE path dispatch. REST `queryIntStrict` rejects negative/malformed page_size/limit/offset. Cursor path suppresses peer results on page_token resume (prevents mixed-page). **No issue.**

### N-10: Rollback n=0 "message" — FIXED
- Verified: `pkg/grpcapi/server_show_rollback_zero_n_4556_test.go` — gRPC ShowRollback n=0 now returns clear "rollback index must be a positive integer" (906b4de). REST `configShowRollbackHandler` same. **Fix verified, not re-reporting.**

### N-11: Syslog TLS profile — not honored, but rejected at commit
- `pkg/daemon/daemon_system.go:116-123` — `NewSyslogClientTransport(..., nil)` passes nil tlsConfig even when `stream.Transport.TLSProfile` is set. `syslog.go:dialTLS` with nil Config uses system CA roots. However, `validateSecurityLogStreamTLSProfileAST` rejects any named TLS profile at commit time. So an operator cannot configure a tls-profile that would be silently ignored. **Not re-reporting — tracked as #3350 area.**

### N-12: SSE / event streaming — no goroutine leak
- `pkg/api/sse.go:34-127` — `eventStreamHandler` / `logStreamHandler`: `Subscribe(128)` + `defer sub.Close()`, select on `ctx.Done()` to exit, correct. `parseCategories` fail-closed (empty token rejected). **No issue.**

### N-13: Prometheus metrics — bounded scrape, session cache
- `pkg/api/server.go:393-399` — `Timeout: 10s, MaxRequestsInFlight: 3` on metrics handler. `pkg/api/metrics.go:21-44` — session gauge cache with singleflight (5s TTL) prevents scrape amplification. **No issue.**

---

## Conclusions

A8 review found no High/Medium security issues requiring immediate fix. The fabric listener (the only network-exposed gRPC surface) is correctly hardened with two interceptor layers (auth + allowlist). REST API input validation is consistently fail-closed. Three Low/Info observations for hardening backlog.
