# #1711 — Policy simulator: reject malformed IP at all three boundaries

Status: PLAN-READY v2 — expanded to all three simulator boundaries
after Codex + AGY both returned PLAN-NEEDS-MAJOR on the gRPC-only v1.

## Issue framing

The policy simulator (`show security match-policies`) parses the
operator-supplied source/destination IP with `net.ParseIP` and feeds
the result to `matchPolicyAddr`:

```go
parsedSrc := net.ParseIP(req.SourceIp)   // grpc
...
func matchPolicyAddr(addrs []string, ip net.IP, cfg *config.Config) bool {
	if len(addrs) == 0 || ip == nil { // ip==nil → matches every term
		return true
	}
	...
}
```

`net.ParseIP` returns `nil` for **both** an empty string and a
syntactically invalid string. `matchPolicyAddr` treats `ip == nil` as
an unconditional wildcard, so a **non-empty malformed** IP (e.g.
`source-ip 10.0.0.999` or `source-ip garbage`) silently matches every
policy term → **false-positive PERMIT verdict** in the simulator
output. Diagnostic-only (does not admit real traffic), but misleading.

Two of the three `ip == nil` triggers are *correct* and must be kept:

- `len(addrs) == 0` → the policy term lists no addresses → Junos "any".
- empty `SourceIp` / `DestinationIp` → operator left the tuple field
  unconstrained → "any" / unspecified (the dominant CLI usage; the
  `source-ip`/`destination-ip` args are optional).

Only the **non-empty-but-invalid** case is the bug.

## v1 → v2: why scope expanded (adversarial review)

v1 fixed only the gRPC handler. Codex (`task-mpta3t25-pi958d`) and AGY
(`adversarial-review-mpta4os9-m2em4w`) both returned **PLAN-NEEDS-MAJOR**
with the same blocking finding: `show security match-policies` is
served by **three independent in-process copies** of this matcher, and
a gRPC-only fix leaves two of them false-positiveing:

1. **gRPC** — `pkg/grpcapi/server_cluster.go:123` `MatchPolicies`,
   matcher at `:174`. Used by the remote `cli` binary
   (`cmd/cli/show.go:882`) and any direct gRPC client.
2. **Local interactive CLI** — `pkg/cli/cli_show_security.go:1888`
   `(*CLI).showMatchPolicies`, dispatched in-process at
   `pkg/cli/cli_show_security_dispatch.go:332`, parses at `:1939`,
   matches via its own `pkg/cli/cli_helpers.go:189` copy. **Does NOT
   call the gRPC handler** — runs the whole simulation locally.
   Counterexample (Codex): local `show security match-policies ...
   source-ip garbage ...` still prints `Matching policy` after a
   gRPC-only fix.
3. **HTTP REST** — `pkg/api/security.go:184` `matchPoliciesHandler`
   (route `GET /api/v1/security/match`, `pkg/api/server.go:153`),
   parses at `:193`, matches via its own `pkg/api/security.go:229`
   copy. Automation/UI clients remain vulnerable under a gRPC-only fix.

To genuinely close #1711 ("operator running the simulator gets a false
permit for malformed input"), validate at **all three** boundaries.

## Honest scope/value framing

Input-validation fix on three diagnostic entry points. Not perf, not a
refactor. Value: correctness of operator-facing output for malformed
input — a clear error instead of a misleading PERMIT. PLAN-KILL would
only be warranted if the fix were wrong or broke the legit "any" path;
neither reviewer found that — the core rule is sound.

## Concrete design

Inline a non-empty-invalid guard at each of the three boundaries,
before the existing `net.ParseIP` feeds the matcher. Each boundary
keeps its native error type. The three `matchPolicyAddr` copies are
**unchanged** — after the guard, the only remaining `ip == nil` cause
is an *empty* (unspecified → any) input, which is intended. We do NOT
consolidate the three copies in this PR (separate refactor concern).

### gRPC — `pkg/grpcapi/server_cluster.go`

```go
if req.SourceIp != "" && net.ParseIP(req.SourceIp) == nil {
	return nil, status.Errorf(codes.InvalidArgument, "invalid source-ip %q", req.SourceIp)
}
if req.DestinationIp != "" && net.ParseIP(req.DestinationIp) == nil {
	return nil, status.Errorf(codes.InvalidArgument, "invalid destination-ip %q", req.DestinationIp)
}
parsedSrc := net.ParseIP(req.SourceIp)
parsedDst := net.ParseIP(req.DestinationIp)
```

`status`/`codes`/`net` already imported.

### Local CLI — `pkg/cli/cli_show_security.go`

```go
if srcIP != "" && net.ParseIP(srcIP) == nil {
	return fmt.Errorf("invalid source-ip %q", srcIP)
}
if dstIP != "" && net.ParseIP(dstIP) == nil {
	return fmt.Errorf("invalid destination-ip %q", dstIP)
}
parsedSrc := net.ParseIP(srcIP)
parsedDst := net.ParseIP(dstIP)
```

`fmt`/`net` already imported. Returned error propagates to the console.

### HTTP REST — `pkg/api/security.go`

```go
srcIPStr := r.URL.Query().Get("src_ip")
if srcIPStr != "" && net.ParseIP(srcIPStr) == nil {
	writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid src_ip %q", srcIPStr))
	return
}
dstIPStr := r.URL.Query().Get("dst_ip")
if dstIPStr != "" && net.ParseIP(dstIPStr) == nil {
	writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid dst_ip %q", dstIPStr))
	return
}
srcIP := net.ParseIP(srcIPStr)
dstIP := net.ParseIP(dstIPStr)
```

Needs `"fmt"` added to imports (`net`/`net/http` already present).
`writeError(w, http.StatusBadRequest, ...)` is the existing helper
(`pkg/api/api.go:44`).

## Empty-vs-invalid discriminator (reviewer-confirmed)

`field != "" && net.ParseIP(field) == nil`. Codex + AGY both confirmed
no legitimate caller passes a non-empty sentinel (`any`, `0.0.0.0/0`,
or a CIDR) in the IP field — the CLI and REST clients only copy a raw
IP token. Resolved open questions:

- `"0.0.0.0"` / `"::"` parse fine → valid path, matched by address-book
  containment. Correct, no special-casing.
- CIDR-in-IP-field (`10.0.0.0/24`) → `net.ParseIP` returns nil → now
  rejected as invalid. The field contract is a single IP; the matcher
  uses `cidr.Contains(ip)` against address-book entries, not the
  reverse. Rejecting is correct.
- Whitespace-only / leading-space values → `net.ParseIP` returns nil →
  rejected. Correct.

## Public API preservation

- gRPC `MatchPolicies` signature + proto unchanged.
- REST route + `MatchPoliciesResult` shape unchanged (error uses the
  existing `Response{Success:false,Error:...}` envelope at 400).
- `(*CLI).showMatchPolicies` signature unchanged (already returns
  `error`).
- All three `matchPolicyAddr` / `matchPolicyAddrSet` bodies unchanged.
- New behavior only on the malformed-input path.

## Hidden invariants preserved

1. Empty-IP "any" path — guarded by `!= ""`.
2. Policy-term "any" (`len(addrs)==0`) — matcher untouched.
3. No new import cycles — gRPC/CLI imports already present; REST adds
   stdlib `fmt`.
4. Read-only against `ActiveConfig()` — no new state.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Only the malformed-input path changes; valid + empty/any unchanged, covered by tests at all three boundaries. |
| Lifetime / borrow | N/A | Go. |
| Performance | NONE | Interactive diagnostic paths; one extra ParseIP per non-empty field. |
| Architectural mismatch | LOW | Boundary input validation is the idiomatic location; matches existing `codes.InvalidArgument` / `writeError(400)` usage. |

## Test plan

Per Codex: invalid-IP tests use a **restricted address-book term**
(not only permit-any) so they prove the actual false-positive shape —
with the bug the malformed IP would match a term it should not, and
the fix turns that into an error rather than a (wrong) match. Also
include an empty-means-any preservation test and a valid-match test.

- `pkg/grpcapi/server_cluster_test.go` (new):
  - `TestMatchPoliciesRejectsInvalidSourceIP` — restricted src term;
    `SourceIp:"10.0.0.999"` → `codes.InvalidArgument`, resp nil.
  - `TestMatchPoliciesRejectsInvalidDestinationIP` — same for dest.
  - `TestMatchPoliciesEmptyIPsMatchAny` — both IPs empty vs permit-any
    → `Matched==true`, no error (empty-any preserved).
  - `TestMatchPoliciesValidIPMatches` — valid IP inside the restricted
    term → matched, no error (valid path unaffected).
- `pkg/cli/cli_show_security_test.go` (append
  `TestShowMatchPoliciesValidation`):
  - invalid source-ip / destination-ip → non-nil error, no
    "Matching policy" output.
  - empty IPs → no error, simulates against any.
- `pkg/api/security_test.go` (new):
  - invalid `src_ip` / `dst_ip` query → HTTP 400, `Success:false`.
  - empty / valid → 200.

Gates (control-plane diagnostic change — NO cluster smoke):
- `go build ./...` clean.
- `go vet ./pkg/grpcapi/... ./pkg/cli/... ./pkg/api/...` clean.
- `go test ./pkg/grpcapi/... ./pkg/cli/... ./pkg/api/...` pass.
- Full `go test ./...` green.
- New named tests 5× loop, no flake.
- `make audit-check` only if a file crosses the size threshold (each
  edit adds <15 LOC; verify it does not trip).

## Out of scope (explicitly)

- Consolidating the three `matchPolicyAddr` copies into one shared
  helper (a refactor; deliberately deferred to keep this a tight bug
  fix). Noted as a possible follow-up.
- Any proto / schema / route change.

## Open questions — resolved by review

1. Discriminator correctness → confirmed (no non-empty sentinel
   callers).
2. `0.0.0.0`/`::` acceptance → correct as-is.
3. CIDR-in-IP-field → reject (field contract is a single IP).
4. Double-parse → acceptable on diagnostic paths.
5. Twin scope → **resolved by expanding to all three boundaries** (the
   blocking finding). gRPC-only would not close the operator-visible
   bug.
