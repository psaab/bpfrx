# pkg/policymatch

Single operator-side security-policy simulator shared by every
`match-policies` surface:

- REST `GET /api/v1/security/match` (`pkg/api` `matchPoliciesHandler`)
- gRPC `MatchPolicies` (`pkg/grpcapi`)
- CLI `show security match-policies` and `test policy` (`pkg/cli`)

Each surface is a THIN adapter: it parses/validates inputs and renders the
verdict, then delegates the matching to `policymatch.Match`.

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
