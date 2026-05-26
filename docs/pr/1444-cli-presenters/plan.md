# #1444 De-monolithize `pkg/cli/cli.go` into Logical Operational Presenters

## Status
DRAFT v2 — revised after Codex (PLAN-NEEDS-MAJOR) and Gemini (PLAN-NEEDS-MINOR)
v1 reviews. Pending re-review.

## v1 reviewer findings addressed

- **Codex r1 / Gemini r1**: do not create `cli_completion.go`; `pkg/cli/completion.go`
  already exists. The completer engine merges INTO that file.
- **Codex r1 / Gemini r1**: naming convention is mixed in `pkg/cli/` — 5 of 22
  non-test files already use bare names (`completion.go`, `monitor.go`,
  `monitor_interface.go`, `runtime.go`, `session_display.go`). Follow the user's
  Wave-1 bare-name rule for new generic utility files. Keep `cli_show_*` only
  when extending the existing show convention.
- **Codex r1**: `readFabricRedirectCounters` + `fabricRedirectCounters` type
  → move to `cli_show_cluster.go` (it is consumed only by the cluster show
  presenter at `cli_show_cluster.go:168`).
- **Codex r1**: `topTalkerEntry` → move to `cli_show_flow.go` (consumer is
  `showTopTalkers` at `cli_show_flow.go:721`, `:744`, `:781`).
- **Codex r1**: security helpers (`enabledStr`, `parsePolicyZoneFilter`,
  `resolveAddressDetail`, `printAppDetail`) all have their only consumers in
  `cli_show_security.go` — move them there alongside `handleShowSecurity` and
  `handleShowScreen` in a security-dispatcher file.
- **Codex r1**: do not append `handleShowSecurity` (250 LOC) +
  `handleShowScreen` (23 LOC) to the already-1986-LOC `cli_show_security.go`.
  Create a dedicated dispatcher file `cli_show_security_dispatch.go` instead.
- **Codex r1**: `resolveAddress`, `resolveAppName`, `capitalizeFirst` are
  dead code. Verified by `grep -rn '\bresolveAddress\b' pkg/cli/` — only the
  definition matches. We move them with their natural domain anyway
  (security/app/util) to preserve pure-code-motion scope; dead-code removal
  is a separate PR.
- **Codex r1**: build + test still required before attestation. Wave-1
  batch-merge omits dataplane smoke only; `go build ./...`, `go test
  ./pkg/cli/...`, and `go test ./...` remain non-negotiable gates.

## Issue framing
`pkg/cli/cli.go` is 1999 LOC and contains:
- The `CLI` struct + `New` constructor + ~12 setter methods (legitimate entry).
- A readline completer (`cliCompleter` + `Do` + `completeConfigWithDesc` +
  `resolveCommand` + `formatAmbiguousMatches`) — supporting helpers already
  live in `completion.go`.
- The interactive `Run()` loop (legitimate entry).
- Seven `handleShow*` dispatcher methods (`handleShowSecurity`,
  `handleShowScreen`, `handleShowNAT`, `handleShowRoute`,
  `handleShowProtocols`, `handleShowClassOfService`, `handleShowServices`)
  that were never moved when their worker `showX` methods migrated to
  sibling `cli_show_*.go` files.
- Domain utilities: `sessionFilter` matcher + parser, `builtinApps` map +
  `resolveAppName`, link-speed helpers, chrony rendering, protocol-name
  lookups, address resolution, `applyToDataplane`, `reloadSyslog`, cluster
  peer dialing, fabric redirect counters, `topTalkerEntry`.

Wave-1 goal: pure code motion to relocate non-core concerns into sibling
files inside `pkg/cli/`, shrinking `cli.go` to roughly 600-700 LOC of
struct + setters + `Run()` + prompts. Public API does not change.

## Honest scope / value framing
Maintainability refactor on the Go control-plane CLI. NOT on the dataplane
hot path. Win is qualitative:
- `cli.go` drops from ~1999 LOC to ~600-700 LOC.
- The misplaced `handleShow*` dispatchers move next to their worker
  methods.
- The completer engine ends up unified in `completion.go`.

If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict. (Perf gain is zero by design; the
justification is code organization.)

## What's already shipped
- `cli_show.go` — top-level `handleShow` router.
- `cli_show_chassis.go`, `cli_show_cluster.go`, `cli_show_flow.go`,
  `cli_show_interfaces.go`, `cli_show_nat.go`, `cli_show_routing.go`,
  `cli_show_security.go`, `cli_show_services.go`, `cli_show_system.go` —
  domain worker methods.
- `cli_show_shared.go` — cross-domain help text.
- `cli_config.go`, `cli_clear.go`, `cli_request.go`, `cli_dispatch.go`,
  `cli_helpers.go` — non-show commands and dispatcher.
- `completion.go` — completion supporting helpers (will absorb the
  completer engine in this PR).
- `runtime.go`, `monitor.go`, `monitor_interface.go`, `session_display.go`
  — ancillary subsystems with bare-name convention.

What's left in `cli.go` is the residue: CLI core + completer engine +
seven stragger `handleShow*` dispatchers + various domain helpers.

## Concrete design

### Naming convention used in this PR

Per the user's Wave-1 rule and the reviewers' v1 feedback:
- **Bare aspect names** for new generic utility files (`peer.go`,
  `apply.go`, `session_filter.go`, `app_resolve.go`, `link.go`,
  `chrony.go`, `proto.go`, `permissions.go`).
- **Extend the existing `cli_show_*` convention** where moving a
  show-dispatcher next to existing show workers (`cli_show_security_dispatch.go`,
  appending to `cli_show_nat.go`, `cli_show_routing.go`,
  `cli_show_services.go`, `cli_show_flow.go`, `cli_show_cluster.go`).

A directory-wide rename sweep is **out of scope** for Wave-1; the
existing 16 `cli_*` files keep their names.

### Target file layout

| Target file | Symbols moved from cli.go (with source line numbers) | Disposition |
|-------------|------------------------------------------------------|-------------|
| `cli.go` (residual) | `CLI` struct (47), `New` (108), `applyResult` (135), `dataplaneLoaded` (142), 12 `Set*` setters (176-236), prompt helpers `refreshPrompt` (1119) `clusterPrefix` (1931) `operationalPrompt` (1946) `configPrompt` (1950), `Run()` (566) | Stays |
| `completion.go` (extend, existing) | `completionNode` alias (353), `operationalTree` var (356), `configTopLevel` var (359), `cliCompleter` type (362), `cliCompleter.Do` (367), `completeConfigWithDesc` (462), `resolveCommand` (522), `formatAmbiguousMatches` (551) | Merge |
| `peer.go` (new, bare) | `dialPeer` (240), `requestPeerSystemAction` (295) | New |
| `permissions.go` (new, bare) | `checkPermission` (317) | New |
| `apply.go` (new, bare) | `applyToDataplane` (1175), `reloadSyslog` (1132) | New |
| `session_filter.go` (new, bare) | `sessionFilter` type (1336), `parseSessionFilter` (1357), `matchesV4` (1459), `matchesV6` (1497), `hasFilter` (1535), `ifaceMatches` (1543), `resolveEgressIface` (1552), `fetchPeerSessions` (1561), `fetchPeerSessionSummary` (1607) | New |
| `app_resolve.go` (new, bare) | `builtinApp` type (1265), `builtinApps` var (1271), `resolveAppName` (1291, dead-but-moved), `resolveAddress` (821, dead-but-moved) | New |
| `link.go` (new, bare) | `readLinkSpeed` (1730), `readLinkDuplex` (1743), `formatSpeed` (1752), `formatDuplex` (1760), `dhcpLease` (1720) | New |
| `chrony.go` (new, bare) | `printChronyTracking` (1771) | New |
| `proto.go` (new, bare) | `protoNameFromNum` (1819), `protoNameToID` (1843), `splitAddrPort` (1862), `uint32ToIP` (1887), `sessionStateName` (1893), `ntohs` (1919), `monotonicSeconds` (1925), `capitalizeFirst` (839, dead-but-moved) | New |
| `cli_show_cluster.go` (extend) | `fabricRedirectCounters` type (146), `readFabricRedirectCounters` (154) | Move (consumed at `:168`) |
| `cli_show_flow.go` (extend) | `topTalkerEntry` type (1626) | Move (consumed at `:721`, `:744`, `:781`) |
| `cli_show_security_dispatch.go` (new, follows existing convention) | `handleShowSecurity` (846), `handleShowScreen` (1096), `parsePolicyZoneFilter` (757), `resolveAddressDetail` (770), `printAppDetail` (781), `enabledStr` (750) | New (avoid +273 LOC append to 1986-LOC cli_show_security.go) |
| `cli_show_nat.go` (extend) | `handleShowNAT` (1633) | +35 LOC |
| `cli_show_routing.go` (extend) | `handleShowRoute` (1664), `handleShowProtocols` (1698) | +60 LOC |
| `cli_show_services.go` (extend) | `handleShowClassOfService` (1954), `handleShowServices` (1966) | +25 LOC |

### Residual cli.go layout (post-move)

- Lines 1-45: trimmed import block.
- Lines 47-105: `CLI` struct definition with field comments.
- Lines 108-238: `New`, `applyResult`, `dataplaneLoaded`, 12 `Set*` methods.
- Lines 240-435 (approx): the `Run()` interactive loop.
- Lines 437-470 (approx): prompt helpers (`refreshPrompt`, `clusterPrefix`,
  `operationalPrompt`, `configPrompt`).

Target final size: ~600-700 LOC. If `cli.go` exceeds 800 LOC after the
move, the partition is wrong and the plan must be re-reviewed.

### Mechanical method

1. For each target file, write a `package cli` header + a doc comment
   noting the file's scope.
2. Move blocks one-by-one, preserving every line verbatim (no signature
   changes, no logic edits, no inlining).
3. After each batch of moves: `go build ./pkg/cli/...` to surface
   missing imports or duplicate decls. Fix imports per file before next
   batch.
4. After the full move: `go build ./...` + `go test ./pkg/cli/...` +
   `go test ./...`.

### Import scope per file

Each new file imports only what its moved symbols need:
- `peer.go`: context, fmt, log/slog, net, syscall, time, grpc,
  credentials/insecure, metadata, golang.org/x/sys/unix, pb.
- `permissions.go`: fmt, config.
- `apply.go`: context, fmt, log/slog, os, time, config, dataplane,
  frr, ipsec, routing, etc. (largest imports — apply touches many
  subsystems).
- `session_filter.go`: net, strconv, strings, time, config, dataplane,
  pb.
- `app_resolve.go`: fmt, strings, config, appid.
- `link.go`: fmt, os, strconv, strings, dhcp.
- `chrony.go`: fmt, strconv, strings.
- `proto.go`: encoding/binary, fmt, net, strings, time.
- `completion.go` (extend): add cmdtree, sort imports if missing.

After every file is moved, run `goimports -w pkg/cli/*.go` to settle
the import sets minimally.

## Public API preservation

Verified externally consumed symbols (single consumer:
`pkg/daemon/daemon_run.go`):

- `cli.New(store, dp, eventBuf, eventReader, rm, fm, im, dm, dr, cm) *CLI`
- `(*CLI).SetVersion(string)` and 11 other `Set*` methods
- `(*CLI).Run() error`

All stay in `cli.go`. No signature changes. The daemon consumer compiles
unchanged.

## Hidden invariants the change must preserve

1. **`Run()` setup ordering**: readline init, completer wiring, terminal
   mode setup, signal handling, prompt refresh, central rollback handler
   wiring are unchanged.
2. **Completer state ownership**: `cliCompleter` carries `*CLI` pointer;
   moving it to `completion.go` is package-internal — visibility and
   ownership are unchanged.
3. **Allocation rules**: no new allocations; method bodies move verbatim.
4. **`sessionFilter` lifetime**: type allocated by `parseSessionFilter`,
   consumed by `fetchPeerSessions`, `handleShowFlow`, matcher methods —
   all stay in `package cli`.
5. **`builtinApps` initialization**: package-level map literal, no
   ordering dependency. Verified: there are no `init()` functions in
   `pkg/cli/`; all package vars are independent.
6. **Test file visibility**: all 12 `*_test.go` files declare `package
   cli`, so cross-file package-private moves remain accessible. The
   most directly affected test is `session_display_test.go:85` which
   touches `sessionFilter`/`ifaceMatches`/`matchesV4` — all stay in
   package and continue to compile.
7. **No new `init()` functions**.

## Risk assessment

| Risk class | Level | Notes |
|------------|-------|-------|
| Behavioral regression | LOW | Pure code motion. Go's compiler enforces compile-time soundness. |
| Borrow / lifetime | N/A | Go has GC. |
| Performance regression | NIL | Control-plane CLI, not the hot path. |
| Architectural mismatch | LOW | Completes a partial split rather than introducing a new pattern. |
| Naming convention churn | RESOLVED | Bare names for new utility files; extend `cli_show_*` for show-dispatcher additions. No directory-wide rename. |
| Test coverage | LOW | All test files are `package cli`; moves stay visible. |
| Dead code carriage | KNOWN | `resolveAddress`, `resolveAppName`, `capitalizeFirst` are dead. Moved with domain to keep pure-motion scope. Removal is a separate PR. |

## Test plan

1. `go build ./...` — clean. (Required before attestation per Codex r1.)
2. `go test ./pkg/cli/...` — 14 test files pass.
3. `go test ./cmd/cli/...` — remote CLI builds clean (separate dispatcher,
   doesn't import pkg/cli).
4. `go test ./...` — full Go suite passes (640+ tests across 20+ packages).
5. `grep -rln 'psaab/xpf/pkg/cli\"' --include='*.go'` still resolves to one
   consumer (`pkg/daemon/daemon_run.go`) and compiles.
6. `wc -l pkg/cli/cli.go` confirms shrink to ~600-700 LOC; reject if >800.
7. `goimports -l pkg/cli/*.go` produces no output (settled imports).
8. No dataplane smoke required (Wave-1 batch-merge rules; CLI changes do
   not touch dataplane).

## Out of scope (explicitly)

- Renaming the existing 16 `cli_*` files to drop the prefix. Cosmetic
  follow-up.
- Deleting `resolveAddress`, `resolveAppName`, `capitalizeFirst` dead code.
  Pure motion only; deletion is a separate PR.
- Extracting a `presenter` interface or a `pkg/cli/shell/` subpackage.
  Wave-1 rules prohibit subpackage hierarchy.
- Refactoring `handleShowX` dispatchers (switch-table cleanup, arg parsing
  consolidation).
- Sharding the security dispatcher by subdomain
  (policies/zones/screen/ipsec/ike/firewall/address-book/dynamic-address).
  Plan creates `cli_show_security_dispatch.go` as a single file holding the
  two handlers + four helpers; further subdivision is a future PR.
- Touching `cmd/cli/` — separate dispatcher, doesn't import pkg/cli.

## Open questions for adversarial review v2

1. **Is `cli_show_security_dispatch.go` the right name?** Alternatives:
   `security_dispatch.go` (bare-name consistency) or
   `cli_show_security_handlers.go`. Picked the longer name to make the
   relationship to `cli_show_security.go` obvious without diff churn on
   the existing file.

2. **Should the `_dispatch` suffix extend to other show domains?** No —
   handleShowNAT (35 LOC), handleShowRoute+handleShowProtocols (60 LOC),
   handleShowClassOfService+handleShowServices (25 LOC) are small enough
   to append to their respective existing files without harming
   cohesion. Only `handleShowSecurity` justifies a dedicated dispatcher
   file because it is 250 LOC against an already-1986-LOC sibling.

3. **`app_resolve.go` carries dead code (`resolveAppName`,
   `resolveAddress`).** Should we delete in this PR? Plan says no
   (pure motion). Reviewer can disagree.

4. **`builtinApps` ends up in `app_resolve.go` even though most callers
   are gone.** Should the map definition move with the dispatcher
   that uses it? Inspection: `builtinApps` is used only inside
   `resolveAppName` (which is itself dead). Keeping both together
   preserves a coherent dead-code island for the eventual cleanup PR.

5. **`cli_show_cluster.go` absorbs the fabric counters type.** Codex
   noted the type is small (5 fields) and only consumed at one site.
   Is type-with-consumer a good principle here? Plan says yes; the
   alternative (a separate `fabric.go`) creates a tiny file for one
   type+method.

6. **Residual `cli.go` will still be ~600-700 LOC.** Is this small
   enough? Plan argues yes — it's a coherent entry-point file (struct
   + 12 setters + Run loop + prompts). Reviewer can demand `Run()`
   move out; trivial follow-up.

7. **Codex flagged the v1 sentence about Go init order as "too
   casual".** Plan v2 tightens: there are no `init()` functions in
   pkg/cli; all package vars are independent map/slice literals.
   Initialization order across files is irrelevant.
