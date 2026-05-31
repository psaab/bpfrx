# #1711 — Policy simulator `MatchPolicies`: reject malformed IP at the gRPC boundary

Status: DRAFT v1 — pending adversarial plan review

## Issue framing

`pkg/grpcapi/server_cluster.go` `MatchPolicies` (the gRPC policy
simulator behind `show security match-policies`) does:

```go
parsedSrc := net.ParseIP(req.SourceIp)
parsedDst := net.ParseIP(req.DestinationIp)
```

`net.ParseIP` returns `nil` for **both** an empty string and a
syntactically invalid string. `matchPolicyAddr` then treats
`ip == nil` as an unconditional wildcard match:

```go
func matchPolicyAddr(addrs []string, ip net.IP, cfg *config.Config) bool {
	if len(addrs) == 0 || ip == nil { // ip==nil → matches every term
		return true
	}
	...
}
```

So feeding the simulator a non-empty but malformed source/dest IP
(e.g. `source-ip 10.0.0.999` or `source-ip garbage`) makes the
address match always succeed, producing a **false-positive PERMIT
verdict** in the simulation output. This is diagnostic-only (the
simulator, not the dataplane enforcement path), so it does not admit
real traffic, but it gives the operator a misleading answer for bad
input.

The issue is explicit that two of the three `ip == nil` triggers are
*correct*:

- `len(addrs) == 0` → the policy term itself lists no addresses →
  Junos "any" semantics. **Keep.**
- empty `req.SourceIp` / `req.DestinationIp` → the operator did not
  constrain that tuple field → "any" / unspecified. This is how the
  CLI is used (`source-ip` / `destination-ip` are optional args;
  omitting them is a legitimate "match against any source"). **Keep.**
- non-empty but invalid `req.SourceIp` / `req.DestinationIp` →
  operator typo / malformed input → currently silently becomes "any".
  **This is the bug.**

## Honest scope/value framing

This is a single-function input-validation fix on a diagnostic gRPC
RPC. It is not a perf change and not a refactor. The value is purely
correctness of operator-facing output for malformed input: instead of
a misleading PERMIT verdict, the operator gets a clear
`InvalidArgument` error naming the bad field/value.

If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict. (There is no perf dimension here;
the relevant kill criterion would be "the fix is wrong / breaks the
legit any-path / belongs elsewhere".)

## What's already shipped / partially relevant

- `pkg/cli/cli_helpers.go` carries a **near-identical duplicate**
  `matchPolicyAddr` / `matchPolicyAddrSet` (local-CLI path,
  `pkg/cli` package). The local-CLI `showMatchPolicies`
  (`pkg/cli/cli_show_security.go:1888`) has the same `net.ParseIP`
  →`nil`→wildcard shape and the same latent false-positive on
  malformed input.
- The issue scopes the fix to the **gRPC** `server_cluster.go`
  handler. See "Out of scope" + Open Question 5 on whether to also
  fix the local-CLI twin in the same PR.

## Concrete design

Validate the two IP fields at the top of `MatchPolicies`, *after* the
`cfg == nil` short-circuit, *before* the `net.ParseIP` calls feed the
matcher. Distinguish empty (legit "any") from non-empty-invalid (error):

```go
func (s *Server) MatchPolicies(_ context.Context, req *pb.MatchPoliciesRequest) (*pb.MatchPoliciesResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.MatchPoliciesResponse{}, nil
	}

	// An empty source/destination IP means "unspecified" (match any),
	// which is a legitimate simulator query. A NON-EMPTY but malformed
	// value is an operator error: net.ParseIP would return nil and the
	// matcher would silently treat nil as a wildcard, yielding a
	// false-positive PERMIT verdict (#1711). Reject it explicitly.
	if req.SourceIp != "" && net.ParseIP(req.SourceIp) == nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid source-ip %q", req.SourceIp)
	}
	if req.DestinationIp != "" && net.ParseIP(req.DestinationIp) == nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid destination-ip %q", req.DestinationIp)
	}

	parsedSrc := net.ParseIP(req.SourceIp)
	parsedDst := net.ParseIP(req.DestinationIp)
	...
}
```

`matchPolicyAddr` is **unchanged**: with the guard above, by the time
it sees `ip == nil` the only remaining cause is an *empty* input
(unspecified → any), which is the intended Junos semantics. The
`len(addrs) == 0` arm is also unchanged (policy-term "any").

Notes:
- Empty-string check uses `req.SourceIp != ""` (not a trimmed
  compare) — the proto field is a plain `string`; the CLI only
  populates it from an explicit `source-ip <token>` arg, so a
  whitespace-only value is itself malformed and should be rejected.
  `net.ParseIP(" 1.2.3.4")` returns nil, so a leading-space value
  takes the InvalidArgument path, which is the correct behavior.
- `status` + `codes` are already imported in `server_cluster.go`
  (lines 17-18). No new imports.
- We call `net.ParseIP` twice for each field on the valid path (once
  in the guard, once for `parsedSrc`/`parsedDst`). This is a
  diagnostic RPC invoked interactively at human rate; the redundant
  parse is negligible and keeps the guard self-contained and obviously
  correct. Open Question 4 asks whether to instead reuse the parsed
  value.

## Public API preservation

- `MatchPolicies` gRPC signature unchanged.
- `MatchPoliciesRequest` / `MatchPoliciesResponse` proto unchanged.
- `matchPolicyAddr` / `matchPolicyAddrSet` signatures and bodies
  unchanged.
- New behavior: a previously-accepted (and silently-wildcarded)
  malformed IP now returns `codes.InvalidArgument`. This is a
  behavior change on an error/garbage input path, not on any valid
  query. The CLI caller (`cmd/cli/show.go:882`) already surfaces the
  gRPC error via `return fmt.Errorf("%v", err)`, so the operator sees
  the message.

## Hidden invariants the change must preserve

1. **Empty-IP "any" path preserved** — omitting source-ip and/or
   destination-ip must still simulate against "any" (the dominant CLI
   usage). Guarded by the `!= ""` precondition.
2. **Policy-term "any" preserved** — `len(addrs) == 0` arm untouched.
3. **No new imports / no import cycle** — `codes`/`status` already in
   the file.
4. **Error surfacing** — gRPC `status.Error` propagates to the remote
   CLI (`cmd/cli`) and the embedded local path; verify the embedded
   local CLI (`pkg/cli`) does not call this gRPC handler (it has its
   own in-process matcher), so the gRPC fix covers only the remote
   `cli` binary + any direct gRPC client. (See Open Question 5.)
5. **Determinism** — `MatchPolicies` is read-only against
   `ActiveConfig()`; adding the guard introduces no state.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Only changes the malformed-input path. Valid queries and empty/any queries unchanged. Worst case if the empty-vs-invalid boundary is wrong: a legit query gets rejected — covered by tests for empty + valid + invalid. |
| Lifetime / borrow | N/A | Go; no borrow checker. |
| Performance | NONE | Interactive diagnostic RPC; one extra `net.ParseIP` per non-empty field. |
| Architectural mismatch | LOW | Boundary input validation at the gRPC handler is the idiomatic location; matches existing `status.Error(codes.InvalidArgument, ...)` usage in the package. |

## Test plan

New test in `pkg/grpcapi/server_cluster_test.go` (new file), package
`grpcapi`, using the existing `configstore.New` + `LoadOverride` +
`Commit` + `&Server{store: store}` scaffolding (mirrors
`server_show_zones_test.go`):

1. `TestMatchPoliciesRejectsInvalidSourceIP` — config with a
   permit-any policy from trust→untrust; request with
   `SourceIp: "10.0.0.999"` (or `"not-an-ip"`); assert the call
   returns an error with `status.Code(err) == codes.InvalidArgument`
   and the response is **not** a PERMIT verdict (resp nil on error).
2. `TestMatchPoliciesRejectsInvalidDestinationIP` — same for
   destination.
3. `TestMatchPoliciesEmptyIPsMatchAny` — request with both IPs empty
   against the permit-any policy → `Matched == true`, action permit,
   **no error** (proves the legit "any" path is preserved).
4. `TestMatchPoliciesValidIPMatches` — request with a valid
   `SourceIp`/`DestinationIp` that falls inside an address-book term →
   correct match, no error (proves valid path unaffected).

Gates (control-plane / gRPC diagnostic change — NO cluster smoke):

- `go build ./...` clean.
- `go vet ./pkg/grpcapi/...` clean.
- `go test ./pkg/grpcapi/...` — new tests pass + existing pass.
- Full Go suite `go test ./...` green.
- New named test 5× loop (no flake).
- `make audit-check` only if a file crosses the size threshold (this
  change adds <15 LOC to a 600-line file + one new test file — should
  not trip it; will verify).

## Out of scope (explicitly)

- **`pkg/cli/cli_helpers.go` + `pkg/cli/cli_show_security.go`
  local-CLI twin.** Same latent bug, different package, not named by
  the issue. Open Question 5 asks reviewers whether to fold it in.
  Default plan: gRPC-only per issue scope; file a follow-up for the
  CLI twin if reviewers prefer scope discipline.
- Consolidating the two `matchPolicyAddr` copies into one shared
  helper (a refactor, separate concern).
- Any proto/schema change.

## Open questions for adversarial review

1. **Empty-vs-invalid boundary.** Is `req.SourceIp != "" &&
   net.ParseIP(...) == nil` the correct discriminator? Is there any
   legitimate caller that passes a non-empty sentinel like `"any"` or
   `"0.0.0.0/0"` as the IP field (which would now be rejected)? Grep
   of CLI callers shows only raw IP tokens — but confirm.
2. **Should `"0.0.0.0"` / `"::"` be accepted?** They parse fine via
   `net.ParseIP` (valid IPs), so they take the valid path and match
   per address-book containment. That seems correct — confirm no
   special-casing is wanted.
3. **CIDR input.** The field is documented as an IP, not a CIDR.
   `net.ParseIP("10.0.0.0/24")` returns nil → would now be rejected as
   InvalidArgument. Previously it silently wildcarded. Is rejecting
   CIDR-in-IP-field the right call, or should we accept a CIDR? (Plan
   position: reject — the field contract is a single IP; matcher uses
   `cidr.Contains(ip)` against address-book entries, not the reverse.)
4. **Double-parse.** Acceptable on a diagnostic RPC, or should we
   parse once and branch on nil+empty? (Plan position: keep the guard
   self-contained for clarity; cost is nil at human invocation rate.)
5. **Local-CLI twin scope.** Fold the identical
   `pkg/cli` fix into this PR, or keep gRPC-only per the issue and
   file a follow-up? PLAN-KILL is *not* warranted either way — this is
   a scope-boundary question.
