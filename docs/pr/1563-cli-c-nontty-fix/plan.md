# #1563 cli -c segfault on readline.SetPrompt in non-TTY mode

**Status:** DRAFT v2 — addresses Codex PLAN-NEEDS-MAJOR + AGY PLAN-NEEDS-MINOR (round 1)

## Round-1 review summary

- **AGY (PLAN-NEEDS-MINOR):** call-site enumeration confirmed
  complete; asked for bufio.NewScanner fallback on `load terminal`
  instead of hard-error; asked for explicit fake gRPC client
  pattern in test plan.
- **Codex (PLAN-NEEDS-MAJOR):** flagged that `configure` mutates
  daemon state (`EnterConfigure` RPC) before the cosmetic SetPrompt
  fires, so nil-guarding the prompt risks leaving the daemon with
  an exclusive config holder if the client disconnects without
  ExitConfigure. Required: prove daemon cleanup on disconnect,
  hard-error `configure` in -c, OR add guaranteed cleanup. Also
  asked for actual recorded grep inventory + tests that exercise
  real dispatch surface with a fake client.

This v2 addresses both reviewers in full.

## Issue framing

`cli -c "<command>"` segfaults when invoked from non-TTY contexts
(`incus exec`, scripted CI, cron). Crash site is
`cmd/cli/shared.go:225` — `c.rl.SetPrompt(c.configPrompt())` panics
because `c.rl == nil`.

Root cause confirmed by reading `cmd/cli/main.go:67-76`: the `-c`
fast path dispatches the command **before** `readline.NewEx()` runs
(`c.rl = rl` is at main.go:132). Any code path inside dispatch that
touches `c.rl` will nil-deref.

## Codex's `configure` state-mutation concern — resolved

Codex flagged that `cli -c configure` calls `EnterConfigure` RPC
before the SetPrompt panics, so a nil-guard would convert
"crash-after-side-effect" to "success-after-side-effect" and
could leave the daemon's config locked.

**Verified resolution: the daemon already auto-releases on client
disconnect.** Quote from `pkg/grpcapi/server.go:214-228`:

```go
// configLockInterceptor auto-releases stale config locks when a gRPC client
// disconnects (context cancelled) without calling ExitConfigure.
func (s *Server) configLockInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
    resp, err := handler(ctx, req)
    // If the client's context was cancelled (disconnect, Ctrl-C), release any
    // config lock held by this connection.
    if ctx.Err() != nil {
        sessionID := peerSessionID(ctx)
        if sessionID != "" {
            if s.store.ExitConfigureSession(sessionID) {
                slog.Info("auto-released config lock on client disconnect", "session", sessionID)
            }
        }
    }
    return resp, err
}
```

When `cli -c configure` exits, `defer conn.Close()` in
`cmd/cli/main.go:37` closes the gRPC connection, the context
cancels, and `configLockInterceptor` calls `ExitConfigureSession`.
The lock is released cleanly.

**Conclusion:** nil-guarding the SetPrompt in `configure` is safe.
The "state leak" Codex worried about does not exist on master.

This also addresses the boundary-classification concern: the
SetPrompt IS purely cosmetic because the daemon owns the canonical
config-mode state and self-cleans.

## Recorded `c.rl` call-site inventory

`grep -n 'c\.rl' cmd/cli/*.go` against worktree HEAD (dd05de380):

```
cmd/cli/main.go:105:    fmt.Fprintln(c.rl.Stdout(), "  (no help available)")
cmd/cli/main.go:122:    cmdtree.WriteHelp(c.rl.Stdout(), candidates)
cmd/cli/main.go:132:    c.rl = rl
cmd/cli/main.go:379:    line, err := c.rl.Readline()
cmd/cli/shared.go:225:  c.rl.SetPrompt(c.configPrompt())
cmd/cli/shared.go:283:  c.rl.SetPrompt(c.configPrompt())
cmd/cli/shared.go:289:  c.rl.SetPrompt(c.configPrompt())
cmd/cli/shared.go:297:  c.rl.SetPrompt(c.configPrompt())
cmd/cli/shared.go:414:  c.rl.SetPrompt(c.operationalPrompt())
cmd/cli/shared.go:437:  if c.rl != nil {
cmd/cli/shared.go:439:      c.rl.SetPrompt(c.configPrompt())
cmd/cli/shared.go:441:      c.rl.SetPrompt(c.operationalPrompt())
cmd/cli/shared.go:530:  cmdtree.WriteHelp(rc.ctl.rl.Stdout(), candidates)
cmd/cli/request.go:37:  c.rl.SetPrompt("")
cmd/cli/request.go:38:  line, err := c.rl.Readline()
cmd/cli/request.go:39:  c.rl.SetPrompt(c.operationalPrompt())
cmd/cli/request.go:55:  c.rl.SetPrompt("")
cmd/cli/request.go:56:  line, err := c.rl.Readline()
cmd/cli/request.go:57:  c.rl.SetPrompt(c.operationalPrompt())
cmd/cli/request.go:77:  c.rl.SetPrompt("")
cmd/cli/request.go:78:  line, err := c.rl.Readline()
cmd/cli/request.go:79:  c.rl.SetPrompt(c.operationalPrompt())
```

Categorisation:

| Site | Category | Action |
|------|----------|--------|
| main.go:105, 122 | inside readline Listener callback (`?` key) | unreachable in -c (Listener registered by readline.NewEx) — no change |
| main.go:132 | init | no change |
| main.go:379 | `load <mode> terminal` interactive read | switch to bufio.NewScanner(os.Stdin) when rl==nil |
| shared.go:225, 283, 289, 297, 414 | cosmetic SetPrompt | nil-guard each call |
| shared.go:437-442 | refreshPrompt (already guarded) | no change |
| shared.go:530 | autocomplete WriteHelp via `rc.ctl.rl.Stdout()` | unreachable in -c (`Do()` driven by readline) — no change |
| request.go:37-39, 55-57, 77-79 | yes/no confirmation prompts | factor `confirmYes()` helper that hard-errors when rl==nil |

**Total touched sites:** 5 in shared.go + 3 in request.go + 1 in
main.go = 9. All other references are init, the dual-guard pattern
already in place, or fire only inside the readline read loop.

## Two fix candidates

### Option A — guard c.rl != nil at the existing call sites

Adopted. Details below.

### Option B — denylist interactive commands at -c entry

Rejected for the same reasons as v1, now reinforced:

- Codex agreed Option A is directionally right.
- Option B would block future multi-command `-c`
  (`cli -c "configure; set X; commit"`).
- The boundary problem Codex raised (`configure` mutates state
  before cosmetic call) is moot because the daemon self-cleans on
  disconnect.

## Concrete design (v2)

### shared.go — 5 cosmetic SetPrompt sites

Wrap each in the same nil-guard already used by `refreshPrompt`:

```go
if c.rl != nil {
    c.rl.SetPrompt(c.configPrompt())  // or operationalPrompt()
}
```

Sites: lines 225, 283, 289, 297, 414. All pure UI updates.
`c.configMode` / `c.editPath` state is updated independently and
is harmless when discarded at -c exit.

### request.go — 3 confirmation sites

Factor a `confirmYes` helper that hard-errors in non-TTY mode:

```go
func (c *ctl) confirmYes(prompt string) (bool, error) {
    if c.rl == nil {
        return false, fmt.Errorf(
            "this command requires interactive confirmation (TTY); " +
            "not available in -c mode")
    }
    fmt.Print(prompt)
    c.rl.SetPrompt("")
    line, err := c.rl.Readline()
    c.rl.SetPrompt(c.operationalPrompt())
    if err != nil {
        return false, nil
    }
    return strings.TrimSpace(strings.ToLower(line)) == "yes", nil
}
```

Each request.go confirmation becomes:

```go
ok, err := c.confirmYes(fmt.Sprintf("%s the system? [yes,no] (no) ", strings.Title(args[1])))
if err != nil {
    return err
}
if !ok {
    fmt.Printf("%s cancelled\n", strings.Title(args[1]))
    return nil
}
```

Hard-error is correct here: `request system reboot` from a script
without confirmation MUST NOT proceed silently. The clear error
tells the operator to invoke `pb.BpfrxServiceClient.SystemAction`
directly via gRPC if non-interactive operation is required.

### main.go handleLoad — bufio.NewScanner fallback (per AGY)

In `handleLoad`, when `source == "terminal"` and `c.rl == nil`,
read stdin via bufio.NewScanner so the canonical pipe pattern
works:

```go
if source == "terminal" {
    var lines []string
    if c.rl != nil {
        fmt.Println("[Type or paste configuration, then press Ctrl-D on an empty line]")
        for {
            line, err := c.rl.Readline()
            if err != nil {
                break
            }
            lines = append(lines, line)
        }
    } else {
        // Non-TTY: read piped config directly from stdin.
        scanner := bufio.NewScanner(os.Stdin)
        // Default scanner buffer is 64 KiB which is too small for
        // a Junos-style override. Bump to 1 MiB.
        scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
        for scanner.Scan() {
            lines = append(lines, scanner.Text())
        }
        if err := scanner.Err(); err != nil {
            return fmt.Errorf("load %s: stdin read: %v", mode, err)
        }
    }
    content = strings.Join(lines, "\n")
}
```

This unlocks `echo "set system hostname foo" | cli -c "load merge terminal"`.

## Public API preservation

- `ctl` struct: unchanged.
- `confirmYes`: new unexported helper.
- `-c` flag semantics: unchanged externally — it just no longer
  crashes.
- All other dispatch paths in TTY mode behave identically.

## Hidden invariants the change must preserve

- Interactive `cli` (TTY) behaviour MUST be identical. Every
  SetPrompt that fires today still fires when `c.rl != nil`.
  Verified by guard pattern: `if c.rl != nil { existing-call }`.
- Confirmation prompts in TTY mode still demand "yes" — the
  `confirmYes` helper preserves the exact existing logic
  (read, compare lowercased+trimmed, exact match "yes").
- Error-on-no-rl in interactive-input sites surfaces a non-zero
  exit so scripts can detect the failure: main.go:71-74 already
  does `os.Exit(1)` on dispatch error.
- Daemon-side EnterConfigure cleanup is preserved by existing
  configLockInterceptor (pkg/grpcapi/server.go:214-228).
- No new goroutines, no new locks, no new allocations on the hot
  path.

## Risk assessment

| Risk class | Level | Notes |
|------------|-------|-------|
| Behavioural regression (TTY) | LOW | Each guard is `if rl != nil { existing-call }`; in TTY mode rl is non-nil so behaviour is unchanged. |
| Lifetime / borrow-checker | N/A | Go, not Rust. |
| Performance regression | NEGLIGIBLE | CLI is cold path; one nil-check per cosmetic SetPrompt. |
| Architectural mismatch | LOW | Pattern already in use at shared.go:437; we're propagating it consistently. |
| State leak via `cli -c configure` | LOW (verified) | Daemon auto-releases on conn close via configLockInterceptor. |
| stdin-stream encoding for piped `load terminal` | LOW | bufio.NewScanner with 1 MiB buffer covers realistic configs; CRLF handled by Scanner.Text() stripping the trailing newline character. |

## Test plan (v2)

### Unit tests

Add `cmd/cli/cdash_nontty_test.go` (or extend `main_test.go`)
using the interface-embedding fake gRPC client pattern that AGY
suggested:

```go
type fakeBpfrxClient struct {
    pb.BpfrxServiceClient // embed interface; nil for unused methods
}

func (f *fakeBpfrxClient) EnterConfigure(
    ctx context.Context, in *pb.EnterConfigureRequest, opts ...grpc.CallOption,
) (*pb.EnterConfigureResponse, error) {
    return &pb.EnterConfigureResponse{}, nil
}
func (f *fakeBpfrxClient) ExitConfigure(
    ctx context.Context, in *pb.ExitConfigureRequest, opts ...grpc.CallOption,
) (*pb.ExitConfigureResponse, error) {
    return &pb.ExitConfigureResponse{}, nil
}
// ... other RPCs as needed, all returning the empty response.
```

Test cases (every site that nil-derefs today):

1. `TestDispatchOperational_ConfigureNoTTY` — ctl{rl: nil} +
   fakeBpfrxClient; call `dispatchOperational("configure")`; must
   not panic, must return nil, must set `c.configMode = true`.
2. `TestDispatchConfig_EditTopUpExitNoTTY` — ctl{rl: nil,
   configMode: true}; call each of `edit foo`, `top`, `up`,
   `exit`; must not panic, must return nil; verifies all four
   shared.go SetPrompt sites (283, 289, 297, 414).
3. `TestConfirmYes_NoTTYError` — ctl{rl: nil}; call
   `confirmYes("?")`; must return (false, non-nil error).
4. `TestHandleRequestSystem_NoTTY` — ctl{rl: nil}; call
   `handleRequestSystem([]string{"system", "reboot"})`; must
   return the no-TTY error, must NOT call SystemAction RPC
   (verify with a fake that increments a counter and asserts
   it's still zero).
5. `TestHandleLoad_TerminalNoTTYReadsStdin` — ctl{rl: nil};
   redirect os.Stdin to a pipe containing
   `"set system hostname foo\n"`; call `handleLoad(
   ["override", "terminal"])`; verify the fake's Load was called
   with the piped content. Use `os.Pipe()` + `os.Stdin =
   readEnd` (save/restore for cleanup).

### Integration / smoke tests

- `make build && make build-ctl`: clean.
- `go vet ./cmd/cli/...`: clean.
- `go test ./cmd/cli/...`: all green, including 5 new tests.
- `go test ./...`: full Go suite green (30 packages).
- Manual repro:
  - `incus exec loss:xpf-userspace-fw0 -- /usr/local/sbin/cli -c "show version"` — must print version, exit 0.
  - `incus exec loss:xpf-userspace-fw0 -- /usr/local/sbin/cli -c "configure"` — must succeed, exit 0, daemon auto-releases config lock.
  - `incus exec loss:xpf-userspace-fw0 -- bash -c 'echo "set system hostname testxxx" | /usr/local/sbin/cli -c "load merge terminal"'` — must succeed, exit 0; check `cli -c "show configuration system"` confirms the hostname change.
  - `incus exec loss:xpf-userspace-fw0 -- /usr/local/sbin/cli -c "request system reboot"` — must return error, exit non-zero, MUST NOT reboot.
- TTY regression: `make test-ssh` and run interactive `cli`,
  verify `configure` / `edit foo` / `top` / `up` / `exit` still
  update the prompt visually.

### Smoke matrix

This is a CLI binary fix, not a dataplane change. The full Pass A +
Pass B per-class CoS matrix from triple-review is not required.
But we still run the standard userspace cluster smoke (v4 + v6,
push + reverse, multi-stream) to confirm we haven't broken
anything by linking against the modified `cli` binary.

## Out of scope

- Multi-command `-c` support (e.g. `cli -c "configure; set X; commit"`).
  Separate issue.
- Refactoring `request system <action>` confirmations to read
  stdin directly. The hard-error in non-TTY mode is correct for
  destructive operations; allowing piped "yes" input would
  reduce the protection.
- Adding a `--yes` / `--non-interactive` flag for destructive
  actions. Separate issue.

## Open questions for adversarial review (round 2)

1. **`load terminal` stdin EOF handling.** bufio.NewScanner stops
   on EOF. Is there any case where stdin is a pipe that never
   closes (e.g. interactive heredoc)? My read: `cli -c "load merge
   terminal"` users will pipe a finite payload; if they want
   open-ended interactive, they don't pass `-c`. Acceptable?
2. **Should the 1 MiB scanner buffer be tunable?** I picked 1 MiB
   because Junos override configs are usually <100 KiB. Edge
   case: someone pipes a multi-MB config. Should we bump to 16
   MiB by default, or fail loudly when the buffer is exceeded?
   Default scanner behaviour with buffer-exceeded is to fail with
   `bufio.ErrTooLong`, which we'll surface as "load: stdin read".
3. **Test pattern: interface embedding vs gomock vs full fake.**
   AGY suggested embedding. Codex asked for "real dispatch
   surface plus fake client". Embedding satisfies both —
   confirmed acceptable?
4. **Should `cli -c "configure"` emit an info note** that the
   command has no effect at exit, since the daemon auto-releases?
   My read: silence is correct because there's no follow-up
   command anyway. Counter-argue?
5. **`request system in-service-upgrade` shape.** Same confirmYes
   treatment, but ISSU specifically is the kind of thing
   automation might want to drive. The current "must use gRPC
   SystemAction RPC" error message is accurate. Counter-argue?
