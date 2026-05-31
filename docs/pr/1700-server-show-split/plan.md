# #1700 — `pkg/grpcapi/server_show.go` intra-package decomposition

Status: DRAFT v1 — pending adversarial plan review

## 1. Issue framing

`pkg/grpcapi/server_show.go` is 2006 LOC, the only `[REFACTOR]`
(>=2000 LOC) entry in `docs/refactoring-audit-current.txt`. #1687
already extracted the byte-identical NAT renderers to `pkg/natshow`;
#1043 (Phases 1-12) already extracted ~57 switch-case bodies into
topic files (`server_show_{nat,flow,system,chassis,security_text,
cluster_text,routes_text,interfaces_text,policies_text,
dhcp_lldp_snmp,firewall,zones_text}.go`). The remaining 2006 LOC are
(a) the `ShowText` dispatcher itself and (b) the case/prefix-handler
bodies that #1043 never reached. This issue finishes that work: pull
the still-inline bodies into topic-cohesive `server_show_*.go` files
so `ShowText` drops below the 1500-LOC audit floor entirely.

NOTE (from #1687): the security show topics are independently-authored
divergent contracts, NOT shareable with the CLI. This is a WITHIN-
grpcapi split along topic seams, not further cross-consumer sharing.

## 2. Honest scope / value framing

Pure code-motion. No behavioral change, no perf change — `ShowText`
is a control-plane RPC handler invoked once per `show` command from
the CLI/gRPC, never on a packet path. The value is purely modularity:
remove the single `[REFACTOR]` audit entry, continue the established
#1043 topic-file layout, and make each show topic independently
navigable/testable. Each extracted helper follows the exact existing
`func (s *Server) showXxx(cfg, &buf)` / `(ctx, req, cfg) (*resp, err)`
convention already used by 57 prior extractions.

If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict. (For a pure-modularity refactor the
relevant question is instead whether the topic seams are clean and the
motion is provably byte-identical; a "no measurable win" kill does not
apply to an audit-floor refactor, but a "seams don't decompose cleanly"
or "not byte-identical" kill does.)

## 3. What's already shipped / partially batched

- #1043 Phases 1-12: 57 case bodies already delegate to `s.showXxx`
  helpers in 12 existing `server_show_*.go` files. Each carries a
  `// #1043 Phase N: case body extracted to <file>` breadcrumb.
- #1687: NAT renderers → `pkg/natshow` (cross-consumer share).
- This plan composes with both: new extractions land in the SAME
  existing topic files where a topic already has a home (e.g. `ike`
  → `server_show_security_text.go` alongside `showIPsecStatistics`),
  and create a small number of new files only for topics with no
  existing home (routing-options/forwarding-options/vlans →
  `server_show_routing_text.go`; the route-* / test-* / firewall-
  filter / class-of-service / screen-* prefix handlers →
  `server_show_prefix.go`).

## 4. Concrete design

`ShowText` keeps its current top-to-bottom dispatch shape (prefix
handlers first, then `switch req.Topic`, then default). The body of
each still-inline branch moves verbatim into a method; the branch is
replaced by a one-line call, identical to the #1043 pattern.

Two branch shapes exist and each maps to one helper signature:

1. **`switch` case bodies that only write to `buf`** (alg, dynamic-
   address, address-book, backup-router, ike, event-options, routing-
   options, forwarding-options, forwarding-options-port-mirroring,
   vlans, routing-instances, routing-instances-detail, route-instance,
   login, screen, internet-options, root-authentication, buffers,
   buffers-detail, bfd-peers, route-map, core-dumps, task,
   ipv6-router-advertisement). These become:

   ```go
   func (s *Server) showAlg(cfg *config.Config, buf *strings.Builder)
   ```

   matching the dominant existing signature. `log` and the default
   block call `exec`/return errors — see (2).

2. **Prefix handlers + error-returning bodies** (route-table:,
   route-protocol:, route-prefix:, class-of-service[:], screen-ids-
   option:, screen-statistics:, screen-statistics-all, screen-ids-
   option-detail:, test-policy:, test-routing:, test-zone:,
   firewall-filter:, and the trailing default `monitor-security-flow`
   / `log:` / unknown-topic block). These already `return
   &pb.ShowTextResponse{...}, nil` or `return nil, status.Errorf(...)`
   early. They become:

   ```go
   func (s *Server) showRouteTable(req *pb.ShowTextRequest,
       cfg *config.Config) (*pb.ShowTextResponse, error)
   ```

   and `ShowText` becomes, for each prefix branch:

   ```go
   if strings.HasPrefix(req.Topic, "route-table:") {
       return s.showRouteTable(req, cfg)
   }
   ```

   The error-returning `switch` cases that currently do
   `if err := s.showX(...); err != nil { return nil, err }` are
   ALREADY one-liners and stay as-is (no change needed) — they were
   extracted in #1043. Only the still-inline ones move.

The trailing default block (`monitor-security-flow` / `log:` /
unknown) returns errors; it becomes a helper returning
`(*pb.ShowTextResponse, error)` and the default case becomes
`default: return s.showDefaultTopic(req, &buf)`. Because the default
already may have written `buf` content earlier? — NO: inspection
confirms the default branch is reached only when no prior case
matched, and it writes only its own content before the shared
`return &pb.ShowTextResponse{Output: buf.String()}, nil`. The
`monitor-security-flow` arm writes to `buf` then falls through to the
shared return; the `log:` arm `buf.Write(out)` then shared return;
the else arm returns an error. The helper must reproduce exactly:
write to its own buffer and return the response, OR take `&buf` and
return only `(handled, err)`. To preserve byte-identity with zero
risk, the default helper takes `*strings.Builder` and returns
`error`; `ShowText` keeps the final `return &pb.ShowTextResponse{
Output: buf.String()}, nil` so the default arm is:

   ```go
   default:
       if err := s.showDefaultTopic(req, &buf); err != nil {
           return nil, err
       }
   ```

This is identical in structure to existing error-returning cases
(e.g. `commit-history`, `route-all`).

### File assignment (topic seams)

| New/existing file | Helpers moved in |
|---|---|
| `server_show_prefix.go` (NEW) | route-table/route-protocol/route-prefix; class-of-service; test-policy/test-routing/test-zone; firewall-filter; default (monitor-security-flow/log:/unknown) |
| `server_show_security_text.go` (existing) | screen-ids-option/screen-statistics/screen-statistics-all/screen-ids-option-detail prefix handlers; `screen` case; `ike` case; alg; dynamic-address; address-book |
| `server_show_routing_text.go` (NEW) | routing-options; forwarding-options; forwarding-options-port-mirroring; vlans; routing-instances; routing-instances-detail; route-instance; bfd-peers; route-map |
| `server_show_system.go` (existing) | backup-router; login; internet-options; root-authentication; core-dumps; task; buffers; buffers-detail; ntp-adjacent system topics; `log` case |
| `server_show_flow.go` (existing) | ipv6-router-advertisement (RA is flow/interface-adjacent) — OR `server_show_interfaces_text.go`; reviewer call |
| `server_show_events.go` (existing) | event-options |

Exact home for a couple of borderline topics (ipv6-router-
advertisement, screen prefix handlers) is an open question for
reviewers (§11). The `screenSYNCookieCounterRows`,
`firewallFilterTermExpansionCount`, and `writeRPMConfig` free
functions move with their consuming topic (screen-* → security_text;
firewall-filter → prefix; writeRPMConfig stays where `rpm`-adjacent
helpers live or moves to system).

## 5. Public API preservation

`ShowText(ctx, req)` signature is unchanged — it remains the single
exported gRPC entry point. No exported symbols are added or removed.
All new helpers are unexported methods on `*Server`. The set of
recognized `req.Topic` values and the exact bytes returned for each
are unchanged.

## 6. Hidden invariants the change must preserve

- **Byte-identical output** for every topic — guarded by golden
  tests (§9). `cfg := s.store.ActiveConfig()` is read once at the top
  of `ShowText` and passed into helpers; helpers must NOT re-fetch
  (re-fetch could observe a different active config mid-call). All
  helpers receive `cfg` as a parameter — no helper calls
  `s.store.ActiveConfig()`.
- **Dispatch order** — prefix handlers run before the switch; the
  switch order is irrelevant (exact-match) but the prefix `if`-chain
  order is preserved (no prefix is a prefix of another that would
  reorder; verified: route-table:/route-protocol:/route-prefix: are
  disjoint).
- **Error propagation** — every `return nil, status.Errorf(...)`
  path preserved with identical codes/messages.
- **`ctx` threading** — `chassis-hardware` recurses via `s.ShowText(
  ctx, ...)`; `chassis-forwarding` passes `ctx` to
  `s.showChassisForwarding(ctx, &buf)`. Any extracted helper that
  needs `ctx` (the default `log:`/`monitor` block does not; test-*
  prefix handlers do not) takes it explicitly.
- **No new imports leak** — imports used only by moved code migrate
  to the new file; `goimports`/`go build` enforces.

## 7. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Pure code-motion; golden tests assert byte-identity per topic. |
| Lifetime / borrow (N/A Go) → import/visibility | LOW | Same package; unexported methods on `*Server`; `go vet` + build catch stray imports. |
| Performance regression | NONE | Control-plane, once-per-command; no hot path. |
| Architectural mismatch (#961/#946-P2) | LOW | This is the SAME proven pattern #1043 ran 12 times; not a new architecture. The only judgement call is file-to-topic assignment (§11). |

## 8. Test plan

- `go build ./...` clean.
- `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./pkg/grpcapi/...`
  green (includes existing ShowText golden/firewall/buffers tests).
- Full Go suite `go test ./...` green (30 packages).
- **Golden byte-identity guard**: add a table-driven test that drives
  `ShowText` for every recognized topic against a representative
  `Server`/active-config fixture and asserts the output bytes match a
  golden captured on `origin/master` BEFORE the split (captured into
  the test as the master baseline). This is the load-bearing gate for
  "output MUST be byte-identical". Covers sessions/security/flow per
  the issue's explicit list plus routing/system/cluster topics.
- 5x flake check on the new golden test.
- `make audit-check` regenerated: `bash scripts/refactoring-audit.sh
  > docs/refactoring-audit-current.txt` — server_show.go drops below
  1500 and leaves the audit list; verify no NEW file crosses 1500
  (each topic file stays well under).
- Control-plane only → **NO cluster smoke** (stated explicitly per
  issue: "Control-plane only → no cluster smoke (Go test suite +
  golden)").

## 9. Golden-test construction (byte-identity proof)

Before touching `ShowText`, on the pre-split tree, run `ShowText`
over the full topic list with a fixture config and capture each
output into a `map[topic]want` baked into a new
`server_show_golden_test.go`. After the split, the same test re-runs
`ShowText` and asserts equality. Because the baseline is captured
pre-split and the test is committed in the FIRST commit (before any
extraction), every subsequent extraction commit is gated by it. Any
topic whose output can't be reproduced deterministically with a
fixture (e.g. `storage` shells out to `df`, `core-dumps` lists
`/var/cores`, `task` reads runtime) is covered by a structural assert
(non-empty / no panic) plus manual diff of the moved code, and that
limitation is documented in the test. The topics that DO render
purely from `cfg` (the large majority: alg, ike, vlans, routing-*,
forwarding-*, screen, address-book, etc.) get exact byte asserts.

## 10. Out of scope (explicitly)

- Any change to topic output text or dispatch semantics.
- Cross-consumer sharing with the CLI (ruled out by #1687).
- Touching the already-extracted #1043 helper files except to RECEIVE
  newly-moved helpers.
- Reworking the `ShowText` dispatch into a topic→handler map/registry
  (a larger redesign; this PR keeps the if-chain + switch and only
  moves bodies). Could be a follow-up.

## 11. Open questions for adversarial review

1. **Is the default-block extraction byte-safe?** The default arm
   shares the final `return &pb.ShowTextResponse{Output: buf.String()}`
   with all switch cases. My design has the default helper write to
   the SAME `&buf` and return only `error`, preserving the shared
   return. Is there any path where the default block currently relies
   on `buf` already containing content from a prior branch? (My read:
   no — default is mutually exclusive with all cases.) Confirm.
2. **Prefix-handler return shape.** Extracting each prefix handler as
   `(req, cfg) (*pb.ShowTextResponse, error)` changes the call site
   from inline `return &pb.ShowTextResponse{...}, nil` to `return
   s.showX(req, cfg)`. Each handler builds its OWN local `buf`. Is
   there any cross-handler `buf` sharing? (My read: each prefix branch
   builds on the shared `buf` which is empty at that point because
   prefix handlers are the first thing checked. Confirm the shared
   `buf` is provably empty when each prefix handler runs — it is
   declared `var buf strings.Builder` at line 97 and nothing writes
   before the first prefix check.) If a handler must keep using the
   shared `buf`, the signature should instead be `(req, cfg, buf)
   (*resp, error)` to avoid a second allocation and any divergence.
   Which is correct?
3. **File-to-topic assignment.** Is `ipv6-router-advertisement` better
   in `server_show_interfaces_text.go` than flow? Is the `screen*`
   prefix family better split from the `screen` case? Push back if the
   seams are wrong.
4. **`cfg` single-fetch invariant.** Confirm no extracted helper
   should call `s.store.ActiveConfig()` itself, and that passing the
   once-fetched `cfg` is strictly behavior-preserving (it is the
   current behavior — `cfg` is fetched once at top).
5. **Golden test sufficiency.** Is a fixture-config-driven golden
   table over all cfg-rendered topics + structural asserts for the
   shell-out topics a sufficient byte-identity proof, or is there a
   topic whose extraction can silently diverge undetected? Name it.
6. **Does this decompose cleanly at all?** If the reviewer believes
   the topics do NOT decompose along clean seams (e.g. helpers share
   too much local state with the dispatcher), PLAN-KILL is the right
   call.
