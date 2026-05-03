# Plan: #1044c Phase 1 — cli.go split

## Status
- #1044a (compiler.go): shipped via #1092 (3,509 → 1,663 LOC).
- #1044b (daemon.go):   shipped via #1091 (2,851 → 346 LOC).
- #1044c (cli.go):      this PR. 2,661 → target ~1,696 LOC.

## Scope
Move four large handler functions from `pkg/cli/cli.go` into existing
sibling files in `pkg/cli/`. Pure relocation — same methodology as
#1043 server_show.go split. No new files; no architectural change.

(Originally drafted as five functions; `handleShowSecurity` was
removed from scope after measuring `cli_show_security.go` at 1,978
LOC pre-PR. See the table below.)

## Mapping

| Function | LOC | Target file (already exists) |
|----------|-----|------------------------------|
| `handleShow`          | 215 | `cli_show.go`          |
| `handleShowSystem`    | 209 | `cli_show_system.go`   |
| `valueProvider`       | 166 | `completion.go`        |
| `handleConfigShow`    | 124 | `cli_config.go`        |

Total cli.go drop: ~714 LOC. Final: 2,661 → 1,952 LOC (under
the 2,000 LOC modularity-discipline threshold).

**`handleShowSecurity` (251 LOC) is intentionally LEFT in cli.go.**
The natural target `cli_show_security.go` was already 1,978 LOC
before this PR; appending the 251-LOC dispatcher would push that file
over the same threshold. Splitting `cli_show_security.go` further is
a separate follow-up — not in scope here.

## Methodology

1. **Verbatim move.** Each function body is moved as-is. Receivers
   and signatures unchanged: `(c *CLI) handleX(args []string) error`.
2. **Imports redistributed.** Each target file picks up only what
   its newly-moved function needs; cli.go drops imports that lose
   their last user.
3. **Helper functions stay** unless moving them is required for the
   move (e.g. a private helper used only by the relocated function
   should follow it). Inspect each handler's transitive helper
   dependency before deciding.
4. **No `else { … }` flatten** unless trivially safe — the cli.go
   handlers are larger and have richer control flow than the
   server_show.go switch cases. Flattening adds review surface; skip
   it.

## Verification

| Check | How |
|-------|-----|
| `go build ./...` | local build, must be clean |
| `go test ./...`  | 880+ unit tests still pass |
| Deploy           | `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env ./test/incus/cluster-setup.sh deploy all` |
| v4 smoke         | `iperf3 -c 172.16.80.200 -t 6` from `loss:cluster-userspace-host` — 0 retr |
| v6 smoke         | `iperf3 -c 2001:559:8585:80::200 -t 6` — 0 retr |

The CLI is not directly exercised by the iperf smoke (the cluster
runs `xpfd` as a service, not interactively). Smoke confirms the
daemon still starts, BPF programs still load, and traffic still
flows after the binary rebuild. The unit tests in `pkg/cli/`
exercise the handlers directly.

## Risks

- **Low.** Target sibling files already exist in this exact pattern
  (e.g. `cli_show_security.go` already houses `handleShowSecurityX`
  helpers; the orphan `handleShowSecurity` itself is in cli.go for
  no good reason).
- The 166-LOC `valueProvider` move may need to bring along its
  receiver-private helpers if any exist; check before moving.

## NOT in scope

- The `Run()` handler (183 LOC) — it owns the readline loop and is
  cohesive in cli.go.
- Any architectural change. This is pure relocation.
- Tier-D refactor families that overlap (#946 pipeline, #963 editor,
  #961 PacketContext) — those are separate work.
