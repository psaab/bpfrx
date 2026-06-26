# pkg/policymatch

Single operator-side security-policy simulator shared by every
`match-policies` surface:

- REST `GET /api/v1/security/match` (`pkg/api` `matchPoliciesHandler`)
- gRPC `MatchPolicies` (`pkg/grpcapi`)
- gRPC `ShowText` `test-policy:` topic (`pkg/grpcapi` `showTestPolicy`) — the
  backing handler for the operational `test policy` CLI command
- CLI `show security match-policies` and `test policy` (`pkg/cli`)

Each surface is a THIN adapter: it parses/validates inputs and renders the
verdict, then delegates the matching to `policymatch.Match`.

## Port input validation (#3116)

`Match` gates a port term on `SrcPort/DstPort > 0`, so a port of `0` means
"unspecified" (no port constraint — the wildcard). That makes a malformed,
negative, or out-of-range port DANGEROUS at the adapter boundary: if it
silently coerces to `0` it becomes "match any port" and the simulator returns a
verdict for a packet that cannot exist on the wire (false confidence during
policy verification / incident response). Two shared validators close this
across every surface:

- `ValidatePort(int) error` — for the already-parsed numeric inputs (the gRPC
  `int32` field, and the REST query int after `queryIntStrict`). Accepts `0`
  (unspecified) and `1..65535`; rejects negative or `>65535`.
- `ParsePort(string) (int, error)` — for operator string tokens (the CLI
  `destination-port`/`source-port` args). An empty/whitespace token is
  unspecified `(0, nil)`; a non-empty token must parse and pass `ValidatePort`;
  a malformed (`abc`), negative, or out-of-range token is rejected. An explicit
  `0` is accepted as "unspecified" for parity with the gRPC `int32` field, where
  proto3 cannot distinguish an unset scalar from `0`.

A VALID port (`1..65535`) and an ABSENT port behave exactly as before; only an
explicitly-invalid port newly errors (REST → HTTP 400, gRPC → `InvalidArgument`,
CLI → command error). Coverage: `port_test.go` (helpers),
`pkg/api/rest_filter_failclosed_test.go`, `pkg/grpcapi/server_cluster_test.go`,
`pkg/cli/policymatch_port_test.go`.

## The surface #3042 missed (#3103)

The original #3042 consolidation routed the REST/gRPC `MatchPolicies` and CLI
`match-policies`/`test policy` paths through this package but left the gRPC
`ShowText` `test-policy:` handler (`grpcapi.showTestPolicy`) on its own pre-#3042
bespoke matcher (`matchShowPolicyAddr`/`matchShowPolicyApp`). That handler is
what the remote `cli` binary's `test policy` command actually drives, so a remote
operator could still be told `Default deny` while the dataplane permits under
`default-policy permit-all`, or miss a predefined-app / global / literal-CIDR /
feed-backed match. #3103 made `showTestPolicy` a thin adapter too (passing the
daemon's live feed overlay via `Server.feedOverlayFn`, mirroring `MatchPolicies`)
and deleted the bespoke helpers. Its rendered output format is unchanged except
the formerly hard-coded `Default deny` line now reflects the configured
default-policy (`Default permit`/`Default deny`/`Default reject`).

## Why this exists (#3042)

Before #3042 each surface carried its own hand-written shadow matcher, and all
of them diverged from the runtime evaluator — so the diagnostic could report
the OPPOSITE of what the dataplane actually enforces (a dangerous bug for a
"why is this packet allowed/denied?" tool). The old matchers:

- looped only `cfg.Security.Policies` (zone-pair sets) and never consulted
  `cfg.Security.GlobalPolicies`;
- hard-coded `deny (default)` on a miss, ignoring `default-policy permit-all`;
- matched addresses with `any` + address-book names/sets only — no literal
  CIDRs, no `any-ipv4`/`any-ipv6`, no `*-address-excluded` exclusion flags, no
  feed overlay;
- matched applications against `cfg.Applications.Applications` only — so
  predefined apps (`junos-http`, ...) never matched, only one application-set
  level was expanded, and source-port terms were ignored.

## Ground truth

The semantics replicate `userspace-dp/src/policy.rs`
(`evaluate_policy_result_with_len` + `try_match_rule` + `parse_v3_literal_set`
+ `CompiledApplications`) fed by the Go snapshot builder
(`pkg/dataplane/userspace/policies.go`). Precedence: **exact zone-pair → global
→ configured default-policy**. Address matching honors literal CIDRs, address
books (recursive set expansion), `any`/`any-ipv4`/`any-ipv6`, source/destination
exclusion (with the #2008 empty-excluded fail-closed rule), and the live
dynamic-address feed overlay (`Query.FeedOverlay`, supplied by the daemon via
`feeds.Manager.SnapshotForBindings`). Application matching resolves predefined +
user apps via `config.ResolveApplication`, expands application-sets recursively
via `config.ExpandApplicationSet`, compares protocols by IANA number via
`appid.ProtocolNumber`, and honors both source-port and destination-port terms.

Where the runtime and the old simulators disagreed, the runtime wins.

## Not modeled

Scheduler-driven policy `inactive` state is not applied — a scheduled policy is
simulated as if active (matching the pre-#3042 surfaces). This is
operator-diagnostic only; it never touches the dataplane or the snapshot wire.

The regression matrix from the issue is pinned in `policymatch_test.go`
(`TestSharedMatcherRegressionMatrix`), and `TestOldNarrowMatcherDiverges` is
the concrete fail-on-revert artifact proving the old per-surface logic returns
the opposite verdict on the affected cases.
