# #1700 — `pkg/grpcapi/server_show.go` intra-package decomposition

Status: v2 — PLAN-READY (Claude-SMR + AGY PLAN-READY/MINOR; Codex
PLAN-NEEDS-MAJOR on v1 doc-text staleness only, all invariants
confirmed). v2 incorporates: zero new files (AGY+Codex#1), consistent
shared-`*strings.Builder` helper shapes (Codex#2), runtime-branch
golden coverage via deterministic stubs + normalizer (Codex#3+AGY#6),
and ShowText-local (not package-wide) cfg single-fetch phrasing
(Codex caveat).

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
- This plan composes with both. **v2: ZERO new files** (AGY + Codex
  finding #1) — every helper lands in an EXISTING domain file (see §4
  table), all of which have ample room below the 1500-LOC floor
  (largest receiver post-move ~850 LOC per Codex's audit).

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
   early.

   **v2 helper shape (Codex finding #2 — pick ONE shape):** every
   prefix handler takes the SHARED `buf` and returns
   `(*pb.ShowTextResponse, error)`, because the shared `buf` is
   provably empty at first-prefix-check (line 97 declares it, nothing
   writes before line 100) and reusing it avoids a redundant
   `strings.Builder` allocation (AGY refinement #2):

   ```go
   func (s *Server) showRouteTable(req *pb.ShowTextRequest,
       cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error)
   ```

   and `ShowText` becomes, for each prefix branch:

   ```go
   if strings.HasPrefix(req.Topic, "route-table:") {
       return s.showRouteTable(req, cfg, &buf)
   }
   ```

   The error-returning `switch` cases that currently do
   `if err := s.showX(...); err != nil { return nil, err }` are
   ALREADY one-liners and stay as-is — extracted in #1043. Only the
   still-inline ones move.

**Default block.** The trailing default (`monitor-security-flow` /
`log:` / unknown) is mutually exclusive with every case (no
`fallthrough`; confirmed by AGY + Codex) and writes only its own
content before the shared
`return &pb.ShowTextResponse{Output: buf.String()}, nil` (~line 1982).
For consistency with the existing error-returning cases
(`commit-history`, `route-all`), the default helper takes the shared
`*strings.Builder` and returns only `error`; `ShowText` keeps the
final shared return:

   ```go
   default:
       if err := s.showDefaultTopic(req, &buf); err != nil {
           return nil, err
       }
   ```

This is the SINGLE consistent rule: switch-case bodies and the
default take `(cfg, *buf)` / `(req, *buf)` and write to the shared
buf; prefix handlers take `(req, cfg, *buf)` and return the response
directly (they are early-returns). No helper allocates its own
buffer.

### File assignment (topic seams) — v2, ZERO new files

Per AGY refinement #1 + Codex finding #1, no new files. Every helper
lands in an existing domain file (post-move LOC stays well under 1500;
largest receiver ~850 per Codex):

| Existing file | Helpers moved in |
|---|---|
| `server_show_routes_text.go` | route-table:/route-protocol:/route-prefix: prefix handlers; test-routing:; routing-options; routing-instances; routing-instances-detail; route-instance; route-map; bfd-peers |
| `server_show_firewall.go` | firewall-filter: prefix handler; test-policy: prefix handler; `firewallFilterTermExpansionCount` already lives here / moves here |
| `server_show_interfaces_text.go` | class-of-service[:] prefix handler; vlans; ipv6-router-advertisement |
| `server_show_zones_text.go` | test-zone: prefix handler |
| `server_show_forwarding.go` | forwarding-options; forwarding-options-port-mirroring |
| `server_show_security_text.go` | screen-ids-option:/screen-statistics:/screen-statistics-all/screen-ids-option-detail: prefix handlers; `screen` case; `ike`; alg; dynamic-address; address-book; `screenSYNCookieCounterRows` |
| `server_show_system.go` | backup-router; login; internet-options; root-authentication; core-dumps; task; buffers; buffers-detail; `log` case; default (monitor-security-flow/log:/unknown); `writeRPMConfig` |
| `server_show_events.go` | event-options |

Free functions move with their consuming topic:
`screenSYNCookieCounterRows` → security_text;
`firewallFilterTermExpansionCount` → firewall;
`writeRPMConfig` → system (RPM-adjacent).

## 5. Public API preservation

`ShowText(ctx, req)` signature is unchanged — it remains the single
exported gRPC entry point. No exported symbols are added or removed.
All new helpers are unexported methods on `*Server`. The set of
recognized `req.Topic` values and the exact bytes returned for each
are unchanged.

## 6. Hidden invariants the change must preserve

- **Byte-identical output** for every topic — guarded by golden
  tests (§9). **ShowText-local** invariant (NOT package-wide — Codex
  caveat: existing helpers `showRPM`, `showAlarms` already re-fetch
  config independently): `cfg := s.store.ActiveConfig()` is read once
  at the top of `ShowText` and the still-inline bodies being extracted
  here all read that single `cfg` and NONE re-fetch. The extracted
  helpers therefore receive `cfg` as a parameter and must NOT call
  `s.store.ActiveConfig()` themselves — preserving the current
  single-fetch behavior of these specific branches.
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
extraction), every subsequent extraction commit is gated by it.

**v2 — runtime-branch coverage (Codex finding #3 + AGY refinement
#6).** A cfg-only fixture is NOT a sufficient byte-identity proof: a
silent-divergence hazard exists for topics with output behind RUNTIME
state, not just `cfg`. Specifically:
- `dynamic-address` (server_show.go:839/855) renders prefix counts
  and "Last fetch ... ago" from `s.feedsFn` + `time.Since`. With
  `feedsFn == nil` the whole inner branch is skipped and a regression
  there goes undetected.
- `screen-statistics:` / `screen-statistics-all` / `firewall-filter:`
  hit-count rows and `ipv6-router-advertisement` status read runtime
  counters / RA-manager state.

The golden fixture therefore wires deterministic stubs so these
branches are EXERCISED with stable output: set `s.feedsFn` to a fixed
`map[string]feeds.FeedInfo` with a FIXED `LastFetch` timestamp; seed
counter/RA state where the test `Server` allows. A **normalizer**
(regex substitution of any residual dynamic tokens — durations,
timestamps, sizes, goroutine/alloc numbers — to `<DATE>`/`<NUM>`/
`<SIZE>` placeholders) is applied to BOTH the baseline and the
post-split output so even the genuinely non-deterministic shell-out
topics (`storage`→`df`, `core-dumps`→`/var/cores`, `task`→runtime,
`log:`→`tail`) get a normalized byte-assert rather than a weak
non-empty/no-panic check. Where a topic cannot be made deterministic
even after normalization, that exact topic is named in the test with
a documented rationale and falls back to a structural assert.

Topics that render purely from `cfg` (the large majority: alg, ike,
vlans, routing-*, forwarding-*, screen, address-book, etc.) get exact
byte asserts directly.

## 10. Out of scope (explicitly)

- Any change to topic output text or dispatch semantics.
- Cross-consumer sharing with the CLI (ruled out by #1687).
- Touching the already-extracted #1043 helper files except to RECEIVE
  newly-moved helpers.
- Reworking the `ShowText` dispatch into a topic→handler map/registry
  (a larger redesign; this PR keeps the if-chain + switch and only
  moves bodies). Could be a follow-up.

## 11. Adversarial-review resolutions (round 1)

All six round-1 open questions were resolved by Claude-SMR + AGY +
Codex with quoted-line evidence; no PLAN-KILL counterexample found.

1. **Default-block byte-safety** — CONFIRMED safe by AGY + Codex.
   Default is mutually exclusive (no `fallthrough`), `buf` empty on
   entry (server_show.go:1954-1982), helper writes only its own
   content. Resolved.
2. **Prefix-handler shape** — RESOLVED to `(req, cfg, *buf) (*resp,
   error)` reusing the shared (provably-empty, line 97→100) buf; no
   redundant allocation, no divergence. Single consistent rule for all
   helper shapes (§4).
3. **File-to-topic assignment** — RESOLVED to ZERO new files (AGY #1 +
   Codex #1); §4 table assigns every helper to an existing domain
   file; largest receiver ~850 LOC, none crosses 1500.
4. **`cfg` single-fetch** — CONFIRMED ShowText-local (Codex caveat:
   not package-wide; existing `showRPM`/`showAlarms` re-fetch). No
   extracted helper re-fetches; §6.
5. **Golden-test sufficiency** — Codex named `dynamic-address`
   (runtime `feedsFn`/`time.Since` branch) and screen/firewall-filter
   counters / RA status as silent-divergence hazards under a cfg-only
   fixture. RESOLVED: §9 wires deterministic stubs (fixed `feedsFn`
   + `LastFetch`) and a normalizer over both baseline and post-split
   output so runtime + shell-out topics get normalized byte-asserts.
6. **Clean decomposition?** — CONFIRMED: same proven #1043 pattern,
   opaque same-package body motion; not a #961/#946-P2 trap.
