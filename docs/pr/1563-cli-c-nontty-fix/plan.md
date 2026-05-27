# #1563 cli -c segfault on readline.SetPrompt in non-TTY mode

**Status:** DRAFT v3 — addresses Codex R2 PLAN-NEEDS-MAJOR + AGY R2 PLAN-NEEDS-MINOR

## Review history

- **AGY R1 (PLAN-NEEDS-MINOR):** add bufio fallback to `load terminal`;
  specify fake gRPC client pattern. Both adopted in v2.
- **Codex R1 (PLAN-NEEDS-MAJOR):** flagged `configure` state-mutation
  before crash → lock-leak concern. v2 attempted to refute via
  configLockInterceptor.
- **AGY R2 (PLAN-NEEDS-MINOR) + Codex R2 (PLAN-NEEDS-MAJOR) — CONVERGED:**
  v2's configLockInterceptor argument is **wrong**. The interceptor
  is a Unary Interceptor; it only fires *during* RPC execution.
  After EnterConfigure returns and the connection later closes, no
  cleanup hook ever runs. The lock leaks permanently. Both reviewers
  independently caught this.
- **Codex R2 additional finding:** `EnterConfigureExclusive` sets
  `exclusiveHolder` not `configHolder`. `ExitConfigureSession`
  refuses to release if session doesn't match `configHolder`. So
  even an explicit `client.ExitConfigure(...)` call from a `-c`
  cleanup path **would not release an exclusive lock**.
- **Codex R2 additional finding:** `load merge terminal` is **not
  reachable** from `cli -c`. `-c` starts with `c.configMode = false`
  → dispatches operational → operational has no `load` case →
  "unknown command: load". The v2 bufio/io.ReadAll plan was solving
  an unreachable code path.

## Converged-on architecture (v3)

The reviewers' converged answer is: **hard-error `configure` when
`c.rl == nil`** at the dispatchOperational layer. This:

1. Stops the segfault dead in its tracks (the crash site at
   shared.go:225 is never reached because `EnterConfigure` is never
   issued).
2. Stops the lock leak dead in its tracks (no RPC issued → no
   server-side `EnterConfigure` to leak).
3. Stops the exclusive-lock leak dead in its tracks (same).
4. Is a 4-line change instead of a multi-site refactor.
5. Makes the cosmetic-SetPrompt sites in shared.go (283, 289, 297,
   414) and the `load terminal` path **unreachable in `-c` mode**
   by construction, because `c.configMode` can never become true.

For belt-and-suspenders defense in depth we still nil-guard those
cosmetic SetPrompts, but the guards are dead code in `-c` mode
once `configure` errors out. They remain useful if any future
caller constructs a `ctl` with `rl == nil` for some other reason.

The `request system <action>` confirmation paths in request.go
remain reachable from `-c` mode (`request` is an operational
command). They must hard-error in non-TTY mode.

## Final concrete design

### 1. dispatchOperational (shared.go:215) — hard-error configure when rl==nil

```go
case "configure":
    if c.rl == nil {
        return fmt.Errorf("configuration mode requires an interactive terminal (TTY); not available in -c mode")
    }
    exclusive := len(parts) >= 2 && parts[1] == "exclusive"
    _, err := c.client.EnterConfigure(c.ctx(), &pb.EnterConfigureRequest{
        Exclusive: exclusive,
    })
    if err != nil {
        return fmt.Errorf("%v", err)
    }
    c.configMode = true
    c.rl.SetPrompt(c.configPrompt())  // safe — guarded by the nil-check above
    if exclusive {
        ...
```

Rationale: the gRPC `EnterConfigure` RPC is never issued, so the
daemon never enters config mode for this client. No lock, no leak,
no segfault. Operator sees a clear error.

### 2. shared.go dispatchConfig — defensive nil-guards (dead code in -c but cheap)

Wrap SetPrompt at lines 283, 289, 297, 414 with `if c.rl != nil`.
These paths are now formally unreachable from `-c` (since
`c.configMode` can never become true). Keep the guards anyway as
defense-in-depth.

### 3. request.go — confirmYes helper

`request` is operational and reachable from `-c`. Destructive
confirmations must hard-error in non-TTY mode rather than wait
for input on a stream that will never deliver "yes".

Factor a helper (placed in `cmd/cli/request.go`):

```go
// confirmYes prompts the operator for a yes/no answer. In non-TTY
// (`-c`) mode there is no readline instance, so we hard-error
// rather than silently waiting on stdin for input that will
// never come — and certainly never proceed with a destructive
// action.
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

Three sites in request.go become:

```go
case "reboot", "halt", "power-off":
    ok, err := c.confirmYes(fmt.Sprintf("%s the system? [yes,no] (no) ", strings.Title(args[1])))
    if err != nil {
        return err
    }
    if !ok {
        fmt.Printf("%s cancelled\n", strings.Title(args[1]))
        return nil
    }
    ...
```

Similar for `zeroize` and `software in-service-upgrade`.

### 4. main.go handleLoad — REMOVED from plan

`load` is not in operational dispatch. `cli -c "load merge terminal"`
returns "unknown command: load" today and after the fix. There is
no segfault to repair here. Drop the bufio/io.ReadAll work.

If a future feature wants `cli -c "load merge <file>"` to work,
that becomes a separate issue (add `load` to operational dispatch
+ define how it interacts with non-TTY mode).

## Public API preservation

- `ctl` struct: unchanged.
- `confirmYes`: new unexported helper, placed in `cmd/cli/request.go`.
- `-c` flag semantics: unchanged externally — `cli -c "show version"`
  and similar operational commands work; `cli -c "configure"` now
  exits with a clear error code 1; destructive confirmations exit
  with a clear error code 1.

## Hidden invariants the change must preserve

- Interactive `cli` (TTY) behaviour MUST be identical. Every path
  that fires today still fires when `c.rl != nil`. The
  `dispatchOperational` `configure` case adds a guard that is
  bypassed in TTY mode.
- Confirmation prompts in TTY mode still demand "yes" — the
  `confirmYes` helper preserves the exact existing logic.
- No new RPC issued in non-TTY mode for configure → no daemon
  state to clean up → no lock leak.
- No new goroutines, no new locks, no new allocations.

## Risk assessment

| Risk class | Level | Notes |
|------------|-------|-------|
| Behavioural regression (TTY) | LOW | `c.rl` is non-nil in TTY mode so all hard-errors are bypassed. |
| Lifetime / borrow-checker | N/A | Go. |
| Performance regression | NEGLIGIBLE | CLI cold path; one nil-check per invocation of `configure` / `confirmYes`. |
| Architectural mismatch | LOW | Pattern matches existing `if c.rl != nil` at shared.go:437. |
| Daemon lock leak | ZERO (was HIGH in v2) | No `EnterConfigure` RPC issued in `-c` mode. |
| Lost feature: `cli -c configure` | NONE | This was never a usable feature — `-c` runs a single command, then exits, so entering config mode without a follow-up command was pointless. |

## Test plan

### Unit tests

Add to `cmd/cli/main_test.go` (or a new `cmd/cli/cdash_nontty_test.go`)
using the interface-embedding fakeBpfrxClient pattern AGY suggested:

```go
type fakeBpfrxClient struct {
    pb.BpfrxServiceClient // embed; nil for unused methods

    // Recorders
    enterConfigureCalls int
    systemActionCalls   int
}

func (f *fakeBpfrxClient) EnterConfigure(
    ctx context.Context, in *pb.EnterConfigureRequest, opts ...grpc.CallOption,
) (*pb.EnterConfigureResponse, error) {
    f.enterConfigureCalls++
    return &pb.EnterConfigureResponse{}, nil
}

func (f *fakeBpfrxClient) SystemAction(
    ctx context.Context, in *pb.SystemActionRequest, opts ...grpc.CallOption,
) (*pb.SystemActionResponse, error) {
    f.systemActionCalls++
    return &pb.SystemActionResponse{Message: "ok"}, nil
}
```

Test cases (every site touched by the fix):

1. **`TestDispatchOperational_ConfigureNonTTYHardErrors`** — ctl{rl: nil}
   + fakeBpfrxClient; call `dispatchOperational("configure")`; must
   return a non-nil error matching "requires an interactive
   terminal", must NOT increment `enterConfigureCalls` (verifies no
   RPC issued → no daemon-side lock leak).
2. **`TestDispatchOperational_ConfigureInteractive`** — ctl with a
   non-nil rl stub (use `&readline.Instance{}` via a tiny shim, OR
   skip this test on platforms where readline can't be constructed
   in tests; alternatively add a small interface for "SetPrompt"
   that we can stub). Validates that the TTY path is unchanged.
   *If the readline.Instance is too awkward to fake, settle for the
   non-nil case being covered by the existing CLI integration via
   `make test-ssh` manual repro — note this in the test file.*
3. **`TestConfirmYes_NoTTYError`** — ctl{rl: nil}; call
   `confirmYes("?")`; must return (false, non-nil error matching
   "requires interactive confirmation").
4. **`TestHandleRequestSystem_NoTTYBlocksDestructive`** — ctl{rl: nil}
   + fakeBpfrxClient; call `handleRequest([]string{"system",
   "reboot"})`; must return the no-TTY error AND must NOT have
   incremented `systemActionCalls`. Repeat for `zeroize` and
   `software in-service-upgrade`.

### Build / suite gates

- `go vet ./cmd/cli/...` — clean.
- `go build ./cmd/cli` — clean.
- `go test ./cmd/cli/...` — all green, including the new tests.
- `go test ./...` — full Go suite green (30 packages).

### Manual repro on cluster (after deploy)

- `incus exec loss:xpf-userspace-fw0 -- /usr/local/sbin/cli -c "show version"`
  — must print version, exit 0. (segfault fix proved.)
- `incus exec loss:xpf-userspace-fw0 -- /usr/local/sbin/cli -c "configure"`
  — must exit non-zero with the "requires an interactive terminal"
  error. Verify `show system configuration-database` on the daemon
  shows no lingering config holder (lock leak prevention proved).
- `incus exec loss:xpf-userspace-fw0 -- /usr/local/sbin/cli -c "request system reboot"`
  — must exit non-zero with the "requires interactive confirmation"
  error and MUST NOT reboot.
- TTY regression: `make test-ssh` and run interactive `cli`,
  verify `configure` / `edit foo` / `top` / `up` / `exit` work
  unchanged and the prompt updates as before.

### Smoke matrix

CLI binary fix, not a dataplane change. Full per-class CoS matrix
not required. Standard userspace cluster smoke (v4 + v6, push +
reverse, multi-stream) to confirm we haven't broken the deployment
itself.

## Out of scope

- `cli -c "configure; set X; commit"` multi-command support. Would
  require explicit teardown sequencing in `-c` mode plus fixes to
  `ExitConfigureSession` to handle `exclusiveHolder` (Codex R2
  finding #2). Separate issue.
- `cli -c "load merge <file>"` support (or `load merge terminal`
  via stdin). Would require adding `load` to operational dispatch.
  Separate issue.
- `--yes` / `--non-interactive` flag for destructive operations.
  Separate audited-automation feature.
- Fixing `ExitConfigureSession` exclusive-vs-non-exclusive asymmetry
  in `pkg/configstore/store.go`. Pre-existing daemon-side bug;
  worth a separate issue.

## Open questions for adversarial review (round 3)

1. **Is hard-erroring `configure` an acceptable UX?** Today
   `cli -c configure` segfaults. After fix it returns a clean
   error. Operators who currently rely on the crash to detect
   "I'm in non-TTY mode" (cargo-cult) will need to read the new
   error message. Acceptable?
2. **Should we also gate `dispatchConfig` itself with a nil-check
   at the top, returning the same error?** It would never trigger
   given the new `configure` guard, but it'd be a stronger
   structural invariant. My read: the per-case nil-guards on
   SetPrompt are sufficient as defense in depth; adding a
   top-level guard would be redundant.
3. **Test #2 readline.Instance stubbing.** The chzyer/readline
   instance is hard to construct in unit tests without a real
   TTY. Acceptable to rely on manual `make test-ssh` for the TTY
   regression rather than a unit test?
4. **Confirmation tests** — should they also assert the printed
   stdout matches "X cancelled" pattern, or is "no RPC issued"
   sufficient? My read: assert no RPC AND assert no cancellation
   message (because cancellation message implies we got past the
   confirm point, which we shouldn't).
