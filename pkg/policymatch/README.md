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
  `destination-port`/`source-port` args, the gRPC `ShowText` `test-policy:`
  `port=` token, and the remote `cli` client's `destination-port`/`source-port`
  — the remote surface was fixed in #3354 to route through `ParsePort` instead
  of a silent `strconv.Atoi` drop that coerced a malformed port to the `0`
  wildcard). An
  empty/whitespace token is unspecified `(0, nil)`; a non-empty token must parse
  and pass `ValidatePort`; a malformed (`abc`), negative, or out-of-range token
  is rejected. An explicit `0` is accepted as "unspecified" for parity with the
  gRPC `int32` field, where proto3 cannot distinguish an unset scalar from `0`.

This is applied at ALL FOUR simulator surfaces (matching the thin-adapter list
above), so "all surfaces validate the port" is literally true:

- REST `matchPoliciesHandler` — `queryIntStrict` (malformed/negative) +
  `ValidatePort` (range) → HTTP 400;
- gRPC `MatchPolicies` — `ValidatePort` on the `int32` source/dest port →
  `InvalidArgument`;
- gRPC `ShowText` `test-policy:` (`showTestPolicy`) — `ParsePort` on the `port=`
  token → an "invalid port" diagnostic in the handler output (the same way a bad
  src/dst IP is reported);
- CLI `test policy` + `show security match-policies` (local `pkg/cli`) AND the
  remote `cli` client (`cmd/cli`) — `ParsePort` → a command error.

A VALID port (`1..65535`) and an ABSENT port behave exactly as before; only an
explicitly-invalid port newly errors. Coverage: `port_test.go` (helpers),
`pkg/api/rest_filter_failclosed_test.go`, `pkg/grpcapi/server_cluster_test.go`
(`MatchPolicies` + `ShowText` `test-policy:`), `pkg/cli/policymatch_port_test.go`,
and `cmd/cli/testpolicy_port_test.go`.

## Protocol input validation (#3108)

`matchApp` short-circuits to "match any application" only for the genuine
match-any cases (`len(apps)==0`, or a policy term of `application any`); a
protocol-constrained application term is NOT short-circuited by an empty `proto`
(#3323) — it is resolved through the protocol gate and fails closed for an
omitted/unresolvable protocol, exactly like the runtime. That still leaves an
unvalidated protocol token DANGEROUS at the adapter boundary in exactly the way
an unvalidated port is: a non-empty but unresolvable protocol (an operator typo
like `tcpp`, an unknown name, or an out-of-range number like `999`) is never
rejected by the matcher — it simply fails closed against every
protocol-constrained term, masking the typo as a default-policy verdict instead
of surfacing the error. One shared validator closes this:

- `ValidateProtocol(string) error` — an empty/whitespace token is "unspecified"
  (no protocol constraint — the wildcard, unchanged); a non-empty token must
  resolve via `appid.ProtocolNumber` (a known name/alias `tcp`/`udp`/`icmp`/
  `ospf`/... or a numeric `0..255`); an unknown name or out-of-range/non-numeric
  value is rejected. There is no `any` protocol keyword — omit the token for the
  wildcard (the runtime constrains the protocol dimension only when a resolvable
  protocol is supplied). A single string validator suffices for every surface,
  since each accepts the protocol as a string `matchApp` resolves identically by
  name or number (unlike ports, which arrive both as a numeric gRPC field and as
  operator strings).

This is applied at ALL FOUR simulator surfaces (mirroring the #3116 port wiring):

- REST `matchPoliciesHandler` — `ValidateProtocol(protocol)` → HTTP 400;
- gRPC `MatchPolicies` — `ValidateProtocol(req.Protocol)` → `InvalidArgument`;
- gRPC `ShowText` `test-policy:` (`showTestPolicy`) — `ValidateProtocol` on the
  `proto=` token → an "invalid protocol" diagnostic in the handler output (the
  same way a bad port/src/dst is reported);
- CLI `test policy` + `show security match-policies` (local `pkg/cli`) AND the
  remote `cli` client (`cmd/cli`) — `ValidateProtocol` → a command error.

A VALID protocol (name or `0..255`) and an ABSENT protocol behave exactly as
before; only an explicitly-invalid protocol newly errors. Coverage:
`protocol_test.go` (helper), `pkg/api/rest_filter_failclosed_test.go`,
`pkg/grpcapi/server_proto_validation_test.go` (`MatchPolicies` + `ShowText`
`test-policy:`), `pkg/cli/policymatch_protocol_test.go`, and
`cmd/cli/testpolicy_protocol_test.go`.

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

## Verdict scope and identity (#3331)

A match-policies answer of "policy X matched" is ambiguous: duplicate policy
names are legal across different from-zone/to-zone pairs and the global scope
(Junos), so a name alone cannot be mapped back to the runtime policy, the
session-table policy ID, or the policy-deny/permit audit record. `Result` (and
the REST `MatchPoliciesResult` / gRPC `MatchPoliciesResponse` it feeds) therefore
carries the matched policy's full identity:

- `Global` — true when the match came from a `policy global` rule rather than a
  zone-pair rule.
- `FromZone` / `ToZone` — the SCOPE of the matched policy. For a zone-pair policy
  these are the surrounding `from-zone`/`to-zone` stanza; for a global policy
  they are its optional `match from-zone`/`match to-zone` scope (#3148), empty
  meaning the global policy applies to every zone (rendered `any`).
- `PolicyID` — the stable runtime/RT_FLOW/session-table policy ID, computed by
  the SSOT `dataplane/userspace.RuntimePolicyIDs` (the same span-accumulated
  namespace the dataplane write side and the `show policies` Index column use,
  #3063). `Match` resolves this map once up front and stamps the ID by the
  matched policy's `[policySetID, sliceIndex]` coordinates (a global policy's
  `policySetID` is `len(cfg.Security.Policies)`), so a verdict cross-references
  the session table / audit log even when policy names collide across scopes.

These are meaningful only on a concrete match (`Matched == true`); the
default-policy and host-inbound verdicts leave them zero-valued.

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
(`pkg/dataplane/userspace/policies.go`). Transit precedence, first-match
terminating:

1. **exact zone-pair** (both zones concrete);
2. **single-wildcard tier** (#3090) — `from-zone any to-zone <X>` and
   `from-zone <X> to-zone any`, merged in config order;
3. **both-any** (#3090) — `from-zone any to-zone any`;
4. **global** (`junos-global`), gated by the optional `match from-zone` /
   `match to-zone` scope (#3148): an empty/`any` scope applies to every zone, a
   typo'd/undefined-zone scope fails closed (matches nothing);
5. **configured default-policy**.

The entire transit block (tiers 1-4) is gated on BOTH query zones being
DEFINED (#3355), mirroring the runtime's `from_id != 0 && to_id != 0` guard
(`evaluate_policy_result_with_icmp`): an unconfigured zone name resolves to the
reserved unknown id 0 and is ineligible for zone-pair, wildcard, or global
policies, so a query naming an undefined zone falls straight through to the
default-policy instead of wrongly matching a `from-zone any`/`to-zone any`/
global rule. `zoneKnown` mirrors the runtime UNCONDITIONALLY — a zone is known
iff it is present in `Security.Zones`, with NO empty-Zones leniency: policy.rs
applies the `from_id/to_id != 0` gate on every evaluation, so a config with no
defined zones resolves every name to id 0 and matches nothing in the transit
tiers. A committed config always populates `Security.Zones`. The REST and gRPC
surfaces additionally
REJECT a missing from/to-zone (HTTP 400 / `InvalidArgument`) for parity with
the CLI, which already requires both zones (#3355 H06).

A `to-zone junos-host` query takes the separate **host gate** (#3285,
`matchJunosHost` ↔ `evaluate_junos_host_policy`): exact `from-zone <ingress>
to-zone junos-host` then `from-zone any to-zone junos-host`, with **no** global
or default transit fallback (and `to-zone any` / `from-zone any to-zone any` are
NOT pulled onto the host path). An unmatched host-bound flow returns
`Result.HostInboundUnmatched` — local delivery proceeds (the management lifeline
guarantee), never an inherited transit verdict. The surfaces render this as
"host-inbound: local delivery proceeds (transit global/default-policy NOT
applied)"; the gRPC `MatchPolicies` response carries it as
`host_inbound_unmatched`.

Surface asymmetry (intentional, not a bug): for a host-inbound-unmatched
result the REST `match-policies` response fills `action` with the descriptive
string "host-inbound (local delivery; not governed by transit/global/default
policy)" so a bare REST consumer reads a meaningful verdict, whereas the gRPC
`MatchPolicies` response leaves `action` EMPTY and sets `matched=false` +
`host_inbound_unmatched=true`, delegating the wording to the client (the remote
CLI formats the two-line host-inbound message above). Both convey the same
"no transit verdict applies" fact; they differ only in where the human string is
composed.

Address matching honors literal CIDRs, address
books (recursive set expansion), `any`/`any-ipv4`/`any-ipv6`, source/destination
exclusion (the #2008 empty-excluded fail-closed rule, hardened in #3356 to run
BEFORE the empty-list match-any short-circuit and to gate fail-closed on BOTH
families being empty — so an empty-but-excluded set never inverts to match-all
and a single-family exclusion, e.g. a v6-only `*-excluded` set, does not
over-block the other family), and the live
dynamic-address feed overlay (`Query.FeedOverlay`, supplied by the daemon via
`feeds.Manager.SnapshotForBindings`). Application matching resolves predefined +
user apps via `config.ResolveApplication`, expands application-sets recursively
via `config.ExpandApplicationSet`, compares protocols by IANA number via
`appid.ProtocolNumber` (a protocol-constrained application term fails closed on
an OMITTED or unresolvable query protocol, #3323 — the runtime always carries a
concrete protocol and keys its per-application terms under it, `by_protocol.get
(&protocol)?`, so a protocol-bearing term can only match a packet of that
protocol; an omitted query protocol resolves to `(0,false)` and matches no such
term, falling through to the default-policy. A NAMED application that carries NO
protocol is NOT match-any either: the dataplane cannot represent it and never
enforces it — the snapshot builder fails closed
(`deriveUserspaceCapabilities`, `capabilities.go` returns `ok=false` for
`proto==""` → the `__unsupported__` whole-snapshot reject, #3261) and strict
commit hard-rejects it (`compiler_validate_strict.go`) — so reporting it as a
concrete match would over-report vs the runtime; such an app fails closed in the
simulator too. Only the literal `application any` token is match-any), honors both
source-port and destination-port terms
(a destination-port-constrained term fails closed on an OMITTED query
destination port, #3330 — mirroring the runtime keying exact_dst_ports/range
terms on the concrete packet port; a SOURCE-port-constrained term likewise
fails closed on an OMITTED query source port, #3415 — the runtime always
carries a concrete source port and gates the app on it
(`appid.matchTuple`/`policy.rs CompiledApplications.matches`), so certifying a
permit for an omitted source port over-matches vs the runtime. This supersedes
#3107's earlier "omitted source port stays unconstrained" diagnostic stance;
an unconstrained source-port term still matches any source port), and
enforces ICMP/ICMPv6 type/code constraints (#3284, junos-ping = type 8,
junos-pingv6 = type 128) from `Query.ICMPType` / `Query.ICMPCode`. A
type-constrained application term matches only when the query's type is known
and equal (and the code too, when the term constrains a code); a query that
omits the type fails closed for that term, mirroring the dataplane's
`packet_icmp = None` path. An unconstrained ICMP application (junos-icmp-all) is
unaffected. The surfaces accept the type/code as `icmp_type`/`icmp_code` (REST
query, gRPC `MatchPolicies` optional fields), `icmp-type`/`icmp-code` (CLI
tokens), and `ictype=`/`iccode=` (gRPC `test policy` topic).

Where the runtime and the old simulators disagreed, the runtime wins.

## Not modeled

Scheduler-driven policy `inactive` state is not applied — a scheduled policy is
simulated as if active (matching the pre-#3042 surfaces). This is
operator-diagnostic only; it never touches the dataplane or the snapshot wire.

The regression matrix from the issue is pinned in `policymatch_test.go`
(`TestSharedMatcherRegressionMatrix`), and `TestOldNarrowMatcherDiverges` is
the concrete fail-on-revert artifact proving the old per-surface logic returns
the opposite verdict on the affected cases.
