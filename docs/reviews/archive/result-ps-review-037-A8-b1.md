# Triage Result — ps-review-037-A8-b1

- **Subsystem**: A8 — API Security (gRPC handlers + REST handlers): `pkg/grpcapi/*.go`, `pkg/api/*.go`
- **Review base**: d4506d4450e2 (== current master lineage; 10 commits behind HEAD, none touch the API surfaces reviewed — they are CoS #4566, VRRP VRID #4573, dataplane workers-clamp #4572, screen UDP-frag #4567)
- **Current master SHA**: 57d24d9aed4b64680831a1765a128921e79c00f7
- **Provenance**: REAL bpfrx (every cited symbol exists at the cited path/line; contrast claims for ShowCompare/ShowRollback/#4556 test all verified — not avacado)
- **Outcome counts**: 3 findings → 1 GENUINE-RESIDUAL (LOW), 2 NOT-MATERIAL, 0 DUP, 0 ALREADY-FIXED, 0 CONFABULATED, 0 DELIBERATE. 13 reviewer negatives (N-01..N-13) spot-checked, all consistent with the hardened backlog.

This is a defensive review whose own summary states "No new High/Confident issues found." All three positive findings are self-rated LOW/INFO and two of them self-refute. The codebase's API surface is well-hardened; the triage confirms that.

---

## A8-01 — gRPC `Rollback` accepts negative N → opaque error (LOW) — **GENUINE-RESIDUAL (LOW, message-quality)**

**Verified accurate.** `pkg/grpcapi/server_config.go:252-257`:
```go
func (s *Server) Rollback(_ context.Context, req *pb.RollbackRequest) (*pb.RollbackResponse, error) {
    if err := s.store.Rollback(int(req.N)); err != nil {   // :253 — no n<0 guard
        return nil, status.Errorf(codes.InvalidArgument, "%v", err)
    }
    ...
}
```
REST leg `pkg/api/config.go:156-166` (`configRollbackHandler`) → `s.store.Rollback(req.N)` — same, no guard.

Downstream `configstore.Rollback` (`store_commit.go:497-524`): `n==0` clones active (valid "revert to active"), else `s.history.Get(n-1)`. `history.Get` (`history.go:54-59`) rejects `n<0` with `"history position %d out of range [0, %d)"`. So a negative N produces `history.Get(<-1>)` → the opaque range error, wrapped as `codes.InvalidArgument`.

**Why it is fail-closed (bounds the severity):** `history.Get` validates `n < 0 || n >= h.size` and returns an error for ANY negative index — no wrong-target slot can be selected. `n==0` is the intentionally-valid Junos `rollback 0` ("revert to active"). The only observable defect is error-message ergonomics: the client sees "history position -6 out of range" instead of a clear "rollback index must be non-negative."

**Novelty / dedup (correct):** #4556 added the `req.N <= 0` guard to `ShowRollback` (`server_config.go:319-323`, "rollback index must be a positive integer", test `server_show_rollback_zero_n_4556_test.go` confirmed present) and #3443 M6 added `req.RollbackN < 0` to `ShowCompare` (`server_config.go:307-313`). Neither covers the `Rollback` **mutation** RPC, precisely because Rollback's `n==0` is legitimately valid so it does NOT fit the `n<=0` reject pattern used for the read verbs. Grepped current master for `req.N < 0` / `rollback index must be non-negative` in `pkg/grpcapi` + `pkg/api` → **no match**. Not a dup, not already-fixed.

**Why GENUINE but not higher than LOW:** real, novel, reachable (any client can send `RollbackRequest{N:-5}`), unguarded at two concrete sites. But zero security/correctness impact — fully fail-closed, no wrong rollback target, no crash, no leak. Impact is purely a degraded/opaque `InvalidArgument` message. Trivial 2-line fold on each surface.

- **Lane**: go
- **Fix**: `server_config.go` Rollback — `if req.N < 0 { return nil, status.Errorf(codes.InvalidArgument, "invalid n %d: rollback index must be non-negative (0 = revert to active)", req.N) }`; mirror in `api/config.go` `configRollbackHandler`.

---

## A8-02 — REST `/config/search` q not length-bounded (LOW) — **NOT-MATERIAL**

**Verified accurate as code, self-refuted as a defect.** `pkg/api/config.go:253-269` (`configSearchHandler`): reads `q := r.URL.Query().Get("q")` with no length check, then `text := s.store.ShowActiveRedacted(nil)`, `strings.Split(text, "\n")`, and `strings.Contains(line, query)` per line.

**Why NOT-MATERIAL:**
1. **Authenticated** — reaching this handler requires valid API credentials (`authMiddleware`), so this is not an unauth DoS.
2. **Config-bounded haystack** — `ShowActiveRedacted` renders the active config, bounded by `configstore.MaxConfigSize` (16 MiB), typically ~100 KB. The per-line work is O(total_config_bytes), not O(query_len × config).
3. **`strings.Contains` short-circuits** — when `len(needle) > len(haystack)` it returns false in O(1) (stdlib checks `len(substr) > len(s)` first). A 1-MiB `q` against ~50-byte config lines returns false instantly; total cost ≈ O(#lines) length checks.
4. **URL already capped** — `apiMaxHeaderBytes = 1<<20` (`server.go:330`) bounds the whole request line + headers to 1 MiB.

The finding's own "Refutation attempt" concludes "Not a practical DoS." It is pure defense-in-depth speculation ("prevents any future change e.g. regex search from becoming a ReDoS vector"). No present defect; no genuine residual. A `len(q) > 256` guard is a fine optional hardening but not material.

---

## A8-03 — gRPC `encodePageTokenV4` allocates 16 bytes, populates 13 (INFO) — **NOT-MATERIAL**

**Verified accurate.** `pkg/grpcapi/server_sessions.go:1331-1340`: `b := make([]byte, binary.Size(key))`. `SessionKey` (`pkg/dataplane/types.go:6-13`) has an explicit `Pad [3]byte`, so `binary.Size` = 4+4+2+2+1+3 = 16; only 13 bytes are written, `b[13:16]` stay zero. REST `pkg/api/sessions.go:1219-1226` uses `make([]byte, 13)`. V6 mirrors: gRPC 40 (`SessionKeyV6` = 16+16+2+2+1+3), REST 37. `decodeSessionKeyV4` (`server_sessions.go:1387-1398`) checks `len(b) < binary.Size(key)` (16); REST checks `< 13`.

**Why NOT-MATERIAL (no functional or security bug):**
- Both surfaces **round-trip their own tokens correctly** — the decoder only reads `[0:4],[4:8],[8:10],[10:12],[12]`; the 3 trailing bytes are ignored.
- The pad bytes are **deterministic zeros**, so tokens are stable/deterministic.
- Tokens are **surface-local and opaque to clients** (each surface only decodes tokens it issued; gRPC and REST tokens are never cross-decoded). The finding itself notes this and says "No functional bug ... Not a real issue."
- Effect is 3 wasted payload bytes (6 hex chars) on the gRPC token and a cosmetic cross-surface asymmetry. Zero security/correctness/DoS impact.

INFO-level cosmetic determinism nit; not a residual worth driving. (Optional: change gRPC to `make([]byte, 13)`/`37` and adjust the decode length checks to match REST, OR add a comment that the padding is intentional struct-alignment — either is fine.)

---

## Reviewer negatives (N-01..N-13) — spot-check

Consistent with the current hardened backlog; no hidden residual surfaced:
- **N-01/N-02/N-03** fabric allowlist + HMAC dual-accept + downgrade-guard + plaintext-dial residual — matches #4107/#4122/#4357 hardening; #4047 mTLS is the known deferred residual.
- **N-04** REST auth constant-time (`constantTimeAPIKeyMatch`, #4157), `/metrics` gating — verified pattern.
- **N-05/N-06** `maxRecvMsgSize`/`maxRequestBodyBytes` = 16 MiB == `MaxConfigSize`; HTTP slowloris timeouts all non-zero (G112/G114).
- **N-07** `sessionFilter.validate()` fail-closed via `setInputErr` (the Codex-r2 filtered-clear-cannot-degrade-to-clear-all fix) — verified present.
- **N-10** #4556 ShowRollback n<=0 fix + test file `server_show_rollback_zero_n_4556_test.go` — confirmed exists on master.

These are the reviewer's own dispositions, not findings, and all check out against master.

---

## Bottom line

One genuine LOW residual (A8-01, message-quality/fail-closed, 2-site go fold). A8-02 and A8-03 are NOT-MATERIAL (self-refuted DoS; cosmetic token padding). No confabulation, no dup, no security/correctness residual. Matches the expected 0-1-residual profile for this hardened API surface.
