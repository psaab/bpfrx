# #1563 cli -c segfault on readline.SetPrompt in non-TTY mode

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY)

## Issue framing

`cli -c "<command>"` segfaults when invoked from non-TTY contexts
(`incus exec`, scripted CI, cron). Crash site is
`cmd/cli/shared.go:225` — `c.rl.SetPrompt(c.configPrompt())` panics
because `c.rl == nil`.

Root cause confirmed by reading `cmd/cli/main.go:67-76`: the `-c`
fast path dispatches the command **before** `readline.NewEx()` runs
(`c.rl = rl` is at line 132). Any code path inside dispatch that
touches `c.rl` will nil-deref.

## All currently-broken `c.rl` call sites under `-c`

Verified by `grep -n 'c\.rl' cmd/cli/*.go`:

| File:line | Code | Category |
|-----------|------|----------|
| shared.go:225 | `c.rl.SetPrompt(c.configPrompt())` (in `configure`) | cosmetic prompt update |
| shared.go:283 | `c.rl.SetPrompt(c.configPrompt())` (in `edit`) | cosmetic prompt update |
| shared.go:289 | `c.rl.SetPrompt(c.configPrompt())` (in `top`) | cosmetic prompt update |
| shared.go:297 | `c.rl.SetPrompt(c.configPrompt())` (in `up`) | cosmetic prompt update |
| shared.go:414 | `c.rl.SetPrompt(c.operationalPrompt())` (in config `exit`/`quit`) | cosmetic prompt update |
| shared.go:437-442 | `if c.rl != nil { ... }` (refreshPrompt) | already guarded |
| shared.go:530 | `cmdtree.WriteHelp(rc.ctl.rl.Stdout(), ...)` (Do completer) | unreachable in `-c` (no readline = no completer driven) |
| main.go:105, 122 | `c.rl.Stdout()` inside readline Listener (`?` key) | unreachable in `-c` (Listener only fires inside Readline()) |
| main.go:132 | `c.rl = rl` | init |
| main.go:179 | `rl.SetPrompt(...)` (local `rl`, not `c.rl`) | unreachable in `-c` (in the read loop) |
| request.go:37, 39 | `c.rl.SetPrompt("")` + `c.rl.Readline()` (reboot confirm) | **interactive input** |
| request.go:55, 57 | same (zeroize confirm) | **interactive input** |
| request.go:77, 79 | same (in-service upgrade confirm) | **interactive input** |
| main.go (handleLoad):379 | `c.rl.Readline()` for `load <mode> terminal` | **interactive input** |

Pipe-output pathway (`dispatchWithPipe` shared.go:133) doesn't touch
`c.rl`, so `cli -c "show version | match foo"` would work if the
underlying dispatch did.

## Two fix candidates

### Option A — guard `c.rl != nil` everywhere it's touched

- Adds `if c.rl != nil { c.rl.SetPrompt(...) }` around the 5
  cosmetic SetPrompt sites in shared.go.
- For interactive-input sites (3 confirmation prompts in
  request.go + 1 `load terminal` in main.go), return a clear error
  in non-TTY mode: e.g.
  `return fmt.Errorf("request system %s requires an interactive TTY; not available in -c mode", args[1])`.
- Behaviour:
  - `cli -c "show version"` works.
  - `cli -c "configure"` flips `c.configMode = true` and prints
    "Entering configuration mode" but the prompt is never shown so
    the cosmetic SetPrompt being a no-op is invisible. Then `-c`
    exits — the configMode state is discarded. Side-effect-free.
  - `cli -c "request system reboot"` returns a clean error instead
    of waiting on stdin for a yes/no that will never come (or
    worse, crashing).

### Option B — structural: `-c` rejects interactive commands up front

Add a denylist in `main.go` before dispatch:

```go
if isInteractiveOnly(*cmdFlag) {
    fmt.Fprintln(os.Stderr, "error: this command requires an interactive TTY")
    os.Exit(1)
}
```

This sidesteps the question of what `configure`/`edit`/etc.
"mean" in `-c` mode by forbidding them entirely.

### Choice: **Option A**

Rationale:

1. **Smaller blast radius.** Option A touches only the call sites
   that today nil-deref. Option B requires a denylist that we'd
   have to maintain alongside the dispatch tables.
2. **Pipe-friendly.** Operators may legitimately want to do
   `cli -c "configure; set X; commit"` once we add multi-command
   `-c` support (separate issue, not in scope here). Option A
   doesn't preclude that.
3. **Consistent with existing pattern.** `refreshPrompt`
   (shared.go:437) already uses `if c.rl != nil { ... }`. The five
   shared.go cosmetic SetPrompt sites are simply missing the same
   guard.
4. **Confirmation prompts get a real error**, not a hang. Option B
   would also error, but at the dispatch-table layer, away from
   the specific reason (no stdin for confirmation), making the
   error message less precise.

## Concrete design

### shared.go — five cosmetic SetPrompt sites

Wrap each in the same nil-guard already used by `refreshPrompt`:

```go
if c.rl != nil {
    c.rl.SetPrompt(c.configPrompt())  // or operationalPrompt()
}
```

Sites: lines 225, 283, 289, 297, 414. All are pure UI updates; the
in-memory `c.configMode` / `c.editPath` state is updated
independently of the prompt.

### request.go — three confirmation sites

The three `request system <action>` confirmations (`reboot`, `halt`,
`power-off`, `zeroize`, `software in-service-upgrade`) need an
interactive yes/no. In `-c` mode that input is impossible.

Factor a small helper:

```go
func (c *ctl) confirmYes(prompt string) (bool, error) {
    if c.rl == nil {
        return false, fmt.Errorf("this command requires an interactive TTY (not available in -c mode); use the gRPC SystemAction RPC if scripting")
    }
    fmt.Print(prompt)
    c.rl.SetPrompt("")
    line, err := c.rl.Readline()
    c.rl.SetPrompt(c.operationalPrompt())
    if err != nil {
        return false, nil  // treat read error as "no"
    }
    return strings.TrimSpace(strings.ToLower(line)) == "yes", nil
}
```

Each of the three sites becomes:

```go
ok, err := c.confirmYes("Reboot the system? [yes,no] (no) ")
if err != nil {
    return err
}
if !ok {
    fmt.Println("Reboot cancelled")
    return nil
}
```

### main.go handleLoad — terminal source

For `load <mode> terminal` with no `c.rl`, return:

```go
return fmt.Errorf("load %s terminal requires an interactive TTY; use 'load %s <file>' or pipe via gRPC", mode, mode)
```

### `cli -c "configure"` — what happens

After the fix:
1. `configure` RPC succeeds (or fails — independent of TTY).
2. `c.configMode = true`.
3. SetPrompt is a no-op (rl is nil).
4. Print messages go to stdout.
5. `-c` path exits because there are no further commands.

The in-memory configMode is discarded. The daemon-side
EnterConfigure was issued; ExitConfigure is NOT issued in the `-c`
path. **This is a pre-existing leak** unrelated to the segfault — a
script that does `cli -c "configure"` would leave the daemon in
exclusive-config mode held by the disconnected client. Out of
scope for this fix (note in PR body); the segfault must come out
either way.

## Public API preservation

No public signatures change. `ctl` struct unchanged. `confirmYes`
is an unexported helper. The `-c` flag semantics are unchanged
externally — it just no longer crashes.

## Hidden invariants the change must preserve

- Interactive `cli` (TTY) behaviour MUST be identical. Every
  SetPrompt that fires today must still fire when `c.rl != nil`.
  Verified by guard pattern: `if c.rl != nil { existing-call }`.
- Confirmation prompts in TTY mode must still demand "yes" — the
  `confirmYes` helper preserves that exactly.
- Error-on-no-rl in interactive-input sites must surface a
  non-zero exit so scripts can detect the failure: main.go's `-c`
  path already does `os.Exit(1)` on dispatch error (line 73).
- No new goroutines, no new locks, no new allocations on the hot
  path. (CLI is cold path anyway.)

## Risk assessment

| Risk class | Level | Notes |
|------------|-------|-------|
| Behavioural regression (TTY) | LOW | Each guard is `if rl != nil { existing-call }`; in TTY mode rl is non-nil so behaviour is unchanged. |
| Lifetime / borrow-checker | N/A | Go, not Rust. No lifetime hazards. |
| Performance regression | NEGLIGIBLE | CLI is cold path; one nil-check per cosmetic SetPrompt. |
| Architectural mismatch | LOW | Pattern already in use at shared.go:437; we're propagating it consistently. |

## Test plan

1. **`go vet ./cmd/cli/...`** clean.
2. **`go build ./cmd/cli`** clean.
3. **`go test ./cmd/cli/...`** — existing tests pass. Add a new
   table-driven test for the `-c` path: construct a `ctl` with
   `rl == nil`, call `dispatchOperational("configure")`,
   `dispatchConfig("edit X")`, `dispatchConfig("top")`,
   `dispatchConfig("up")`, `dispatchConfig("exit")` — must not
   panic, must return nil error (gRPC client can be a stub or
   nil-checked path; use a fake client).
4. **`go test ./...`** — full suite green.
5. **Manual repro on cluster**: deploy and run
   `incus exec loss:xpf-userspace-fw0 -- /usr/local/sbin/cli -c "show version"`
   — must print version and exit 0, no segfault.
6. **TTY regression check**: `make test-ssh` and run interactive
   `cli`, verify `configure` / `edit foo` / `top` / `up` / `exit`
   still update the prompt visually.
7. **Confirmation-error path**: `cli -c "request system reboot"`
   on the test VM — must return the clear-TTY error and exit
   non-zero, NOT reboot.

## Out of scope

- Multi-command `-c` support (e.g. `cli -c "configure; set X; commit"`).
- The daemon-side EnterConfigure leak when `cli -c "configure"` is
  issued without follow-up. Pre-existing; addressed in a separate
  issue.
- Refactoring `request system <action>` confirmations to read
  stdin directly (instead of via readline). Pre-existing coupling;
  out of scope.

## Open questions for adversarial review

1. **Is Option A really safer than Option B?** Could there be a
   call site that touches `c.rl` and is NOT in our enumerated
   list? `grep -n 'c\.rl' cmd/cli/*.go` ran on the worktree at
   commit e07f733a6 — please re-grep against the head you review
   to confirm coverage.
2. **`cli -c "configure"` state leak** — is fixing the segfault
   without fixing the leak acceptable for this PR, or should both
   ship together? My read: segfault is a crash bug, leak is a
   resource bug. Crash-fix should not be gated on leak-fix.
3. **Confirmation-prompt error wording.** The proposed error
   suggests "use the gRPC SystemAction RPC if scripting" — is that
   the right pointer, or should it say "use REST POST
   /api/v1/system" or "drop this command from the script"?
4. **Should `load <mode> terminal` in `-c` mode be a hard error,
   or silently fall back to reading from `os.Stdin`?** The pipe
   shape `echo "config..." | cli -c "load merge terminal"` could
   conceivably work if we used `bufio.NewReader(os.Stdin)` instead
   of `c.rl.Readline()`. I propose hard error for now (smaller
   blast radius) but note the alternative.
5. **Test coverage** — should the new test exercise every shared.go
   SetPrompt path or just one canary site? My read: hit every
   path that today nil-derefs (5 sites in shared.go + 3 in
   request.go + 1 in handleLoad). Cost is one table entry each.
