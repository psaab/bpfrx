# #1687 — Shared security/NAT/flow presentation package

**Status:** DRAFT v1 — pending adversarial plan review. **Author leans PLAN-KILL** (see verdict thesis); inviting reviewers to refute with a viable narrower seam.

## Issue framing

#1687 (promoted from #1661 backlog item 3) asks to factor the
"duplicated" security/NAT/flow presentation logic in
`pkg/grpcapi/server_show.go` (2006 LOC) and
`pkg/cli/cli_show_security.go` (1986 LOC) into a **shared presentation
package** consumed by both the gRPC and CLI show paths — "a real
shared-rendering seam, NOT more dispatcher files." The issue states a
hard invariant: **the two consumers must produce byte-identical output
post-split**, proven by golden tests on both paths. The issue itself
authorizes PLAN-KILL "if the duplication isn't cleanly factorable."

## Honest scope/value framing

If the two paths genuinely produced the same output, a shared renderer
would delete ~1-2K LOC of duplication and make the operator-facing show
contract single-sourced. That would be real value.

**But the core premise is false on master.** The gRPC and CLI security
presenters are *independently authored, structurally divergent*
renderers that only superficially resemble each other. They do not
produce byte-identical output today, and several do not even produce
*feature-equivalent* output. A "shared package" that preserved both
behaviors would need consumer-specific branches at nearly every
field — i.e. no real shared seam, just a parameterized fork. That is
precisely the #961 PacketContext / #1544 file-motion dead-end the issue
and the project's standing rules warn against.

*If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict.* Here the relevant axis is not perf
but **architectural fit + contract risk**: forcing the shared seam
requires either (a) changing operator-visible CLI or gRPC output to
make them match (a behavior change, not a refactor, and a regression to
whichever side loses its richer output), or (b) a branch-everywhere
"shared" type that adds indirection without removing real duplication.

## What's already shipped / structure on master

- `server_show.go` is **already a topic dispatcher** (`ShowText`): most
  cases delegate to extracted helpers `server_show_{nat,flow,firewall,
  security_text,zones_text,...}.go` (the #1043 phased decomposition).
  The remaining inline cases (alg, address-book, ike, screen-*,
  routing-options, event-options, backup-router) write to a
  `*strings.Builder`.
- `cli_show_security.go` is a set of `(c *CLI) showX()` methods that
  print directly to **stdout** via `fmt.Println` / `fmt.Printf`, routed
  by `cli_show_security_dispatch.go`. The CLI does **not** call gRPC
  `ShowText` for these topics — it has fully independent local
  renderers.
- There is **no** existing shared presentation package, and no import
  of one from either side.

## Evidence: the two render paths are divergent, not duplicated

Four representative parallel pairs, read end-to-end on master:

### 1. `screen-ids-option`
- gRPC (`server_show.go:194-254`): hardcoded column spacing —
  `"  Name                                        Value\n"` and
  `"  TCP land attack                             enabled\n"` (literal
  spaces baked into each string).
- CLI (`cli_show_security.go:514-584`): `fmt.Printf("  %-45s %s\n",
  "Name", "Value")` and `fmt.Printf("  %-45s %s\n", "TCP land attack",
  "enabled")`.
- **Verdict:** `%-45s` width vs hand-counted literal spacing → NOT
  byte-identical. A shared renderer must pick one; either changes the
  other consumer's output.

### 2. `alg`
- gRPC (`server_show.go:824-833`): 4 lines —
  `"SIP:  %s\n" / "FTP: / "TFTP: / "DNS:` via `boolStatus()`.
- CLI (`cli_show_security.go:1848-1885`): header `"ALG Status:"`, then
  16 protocols (`DNS FTP H323 MGCP MSRPC PPTP RSH RTSP SCCP SIP SQL
  SUNRPC TALK TFTP IKE-ESP TWAMP`) via `"  %-9s: %s\n"` with
  "Enabled"/"Disabled".
- **Verdict:** completely different content (4 vs 16 protocols),
  different header, different format. Not factorable without changing
  one side's behavior.

### 3. `address-book`
- gRPC (`server_show.go:868-885`): `"Addresses:\n"` + `"  %-20s %s\n"`;
  `"Address sets:\n"` + `"  %-20s members: %s\n"`. Map iteration (no
  sort), no name filter, no nested-set `set:` prefix, no member-detail
  expansion, no empty fallback.
- CLI (`cli_show_security.go:784-845`): `"  %-24s %s\n"`; name-filter
  support; nested address-sets shown as `set:NAME`; member-detail
  expansion when filtered; `"Address book is empty"` fallback.
- **Verdict:** different column width (20 vs 24) AND the CLI has
  features gRPC lacks (filter, nested-set prefix, member detail). Not
  even feature-equivalent.

### 4. `applications`
- gRPC (`server_show_security_text.go:230-275`): header
  `"Applications:"`, dense single line `"  %-24s proto=%-6s
  dst-port=... src-port=... timeout=... alg=... (desc)"`.
- CLI (`cli_show_security.go:846-973`): header `"User-defined
  applications:"`, `detail` + `<name>` filter sub-commands, multi-line
  detail block (`Application:`, `  Description:`, `  IP protocol:`, ...),
  brief format `"  %-24s protocol: %-6s port: %s"`.
- **Verdict:** different header text, different field syntax
  (`proto=tcp` vs `protocol: tcp`), CLI has detail/filter modes gRPC
  lacks. Not byte-identical, not feature-equivalent.

Across all four sampled pairs the output diverges. The "duplication" is
**parallel evolution of two distinct operator contracts**, not a single
contract copy-pasted.

## Why the issue's stated invariant cannot be met by a refactor

The issue's acceptance gate is *byte-identical output before/after on
both consumers*, proven by golden tests. Golden tests written against
master would capture two **different** golden files per topic. A shared
renderer can reproduce at most one of them per topic; reproducing both
requires per-consumer branches keyed on caller identity at nearly every
field — which is not a shared seam, it is a fork with a shared name. So:

- **Pure code-motion is impossible** (the outputs differ, so you cannot
  move one body and call it from both).
- **A genuine shared seam is impossible** without first *unifying the
  output contract*, which is a behavior change to the CLI and/or gRPC
  operator-facing surface — out of scope for a refactor, and a
  regression for whichever side loses its richer output (the CLI's
  filter/detail/nested-set features, the gRPC's distinct formats).

This matches the documented dead-ends: #961 PacketContext (forced a
shared abstraction that didn't fit), #1544 lesson (file-motion that
isn't a real seam), and the project's standing rule to kill
"Refactor: <Pattern>" issues that don't fit codebase reality.

## Concrete design (the only honest options)

1. **PLAN-KILL (recommended).** The duplication is not cleanly
   factorable; the byte-identical invariant is already false on master.
   Label `plan-kill`, close, comment verdicts.

2. **Narrow salvage, IF reviewers find one** — extract only the handful
   of *genuinely identical, pure config→string helpers* that are
   byte-for-byte equal on both sides (candidate: `boolStatus`,
   `firewallFilterTermExpansionCount` vs `filterTermExpansionCount`,
   `screenSYNCookieCounterRows` which both already delegate to
   `dpuserspace.FormatSYNCookieCounterRows`). This would be a tiny,
   honest dedup (tens of LOC), NOT the "shared presentation package"
   the issue scopes, and would barely move the audit LOC. Reviewers must
   confirm each candidate is byte-identical before it qualifies.

3. **Re-scope to contract-unification (out of scope here).** A separate,
   non-refactor work item could *intentionally* unify the CLI and gRPC
   output for these topics (deciding which format wins per topic), then
   build the shared renderer on the unified contract. That is a
   behavior-change project requiring operator sign-off, not #1687.

## Public API preservation

N/A under option 1. Under option 2, only internal unexported helpers
move; no exported gRPC/CLI signatures change.

## Hidden invariants

- Operator-visible output of every `show` topic on BOTH consumers must
  not change (the whole point — and the reason the broad split fails).
- CLI prints to stdout; gRPC accumulates into `*strings.Builder` and
  returns over the wire. Any shared helper must take an `io.Writer` /
  `*strings.Builder` sink, not print directly — another structural
  mismatch the broad split would have to paper over.

## Risk assessment

| Class | Level | Note |
|-------|-------|------|
| Behavioral regression | **HIGH** | Forcing a shared renderer changes one consumer's operator-visible output for nearly every sampled topic. |
| Lifetime/borrow (Go: aliasing) | LOW | Go; not the issue. |
| Performance | N/A | Control-plane show path, not hot path. |
| **Architectural mismatch (#961/#1544)** | **HIGH** | Two divergent contracts; "shared" type would be a branch-everywhere fork. This is the kill axis. |

## Test plan (if any option 2 salvage proceeds)

- `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` all green.
- Golden/snapshot tests on BOTH `grpcapi` `ShowText` and `cli` show
  paths for every touched topic, asserting output is byte-identical
  before/after (captured on master first). Any candidate helper that
  changes either golden is disqualified.
- `make audit-check` green on rebased branch; regen
  `docs/refactoring-audit-current.txt`.
- No cluster smoke (control-plane only) — state explicitly in PR.

## Out of scope

- Unifying the CLI/gRPC output contract (behavior change; needs its own
  issue + operator sign-off).
- The broader grpcapi package restructure (#1661 addendum-4 #24
  `server_sessions`, addendum-9).
- #1686 (dataplane/maps.go) — disjoint file scope; no conflict.

## Open questions for adversarial review (each invitable to PLAN-KILL)

1. Are the four sampled pairs representative, or is there a large
   subset of topics where gRPC and CLI **are** byte-identical and
   cleanly shareable? (If a real shared majority exists, the kill is
   wrong — produce the list with file:line proof.)
2. Is option 2 (narrow byte-identical-helper dedup) worth doing at all,
   or is it churn below the noise floor that should just be left alone?
3. Does the issue's "byte-identical output post-split" invariant
   *actually* mean "identical to the consumer's own pre-split output"
   (my reading), or "identical to each other" (which is already false
   and would require a behavior change)? Either reading supports KILL of
   the broad split; confirm.
4. Is re-scoping to contract-unification (option 3) the right follow-up,
   or should #1687 simply be closed as not-cleanly-factorable?
5. Is there any seam I'm missing — e.g. a shared *data-model* (typed
   intermediate structs) feeding two thin per-consumer formatters —
   that would dedup the config-walking logic without touching the
   divergent formatting? Quantify how much of each function is
   config-walk vs format-emit before answering.

   **Author's answer (steelman, then rejected):** the config-walk in
   these functions is trivial (~3 lines: build name slice,
   `sort.Strings`, range) — there is almost nothing to dedup. The bulk
   is per-field format-emit, which diverges. Worse, where the walk *is*
   non-trivial it also diverges: the CLI `address-book` walk has
   name-filter + nested-`set:` expansion + member-detail that the gRPC
   walk lacks, so a shared data-model would itself need consumer-keyed
   walk parameters. And the one genuinely cross-cutting renderer
   (`FormatSYNCookieCounterRows` + `SumSYNCookieCounters`) is **already
   shared** in `pkg/dataplane/userspace/statusfmt.go:39,56` — both
   consumers already call it. The factorable duplication was already
   factored. The data-model seam does not exist here. Reviewers: refute
   with a concrete typed-struct design + the per-function walk/format
   LOC split if you disagree.
