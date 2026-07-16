# Triage Result — ps-review-040-A10-b1

- **Subsystem**: Area A10 Batch 1 — remote CLI (`cmd/cli/`), local CLI (`pkg/cli/`),
  BPF headers, xpfd cmd, shimverify (module-by-module defensive sweep).
- **Base == current master?**: YES. Triaged against `origin/master` @ `95b33d49634d56086269a62a92e213dae7926f88` (freshly fetched).
- **Repo**: real bpfrx. Cited paths use the `/home/ps/git/gemini-xpf/` fork prefix, but the
  relative paths map 1:1 onto bpfrx and the cited symbols exist on bpfrx master — NOT confabulated.
- **Findings in file**: 1 positive finding + a large "NEGATIVE RESULTS" module sweep (no positives).
- **Outcome counts**: 1 GENUINE-RESIDUAL, 0 already-fixed, 0 not-material, 0 confabulated, 0 dup.
  (Negative-result sweep: nothing to triage — all self-reported clean.)

---

## Finding 1 — Leaked stdin reader goroutine in remote CLI interactive monitor steals a keystroke

- **Disposition**: **GENUINE-RESIDUAL** (novel, reachable, not a dup, not fixed on master).
- **Severity**: **LOW-MED** (review said Medium; low end of Medium — see justification).
- **Lane**: go.
- **File:line**: `cmd/cli/monitor.go:34-46` (`setMonitorRawMode` VMIN=1/VTIME=0) and
  `cmd/cli/monitor.go:128-140` (the keyreader goroutine inside
  `handleInteractiveMonitorInterfaceSummary`).

### Why GENUINE (verification trail)

1. **Symbol exists on master**: `handleInteractiveMonitorInterfaceSummary` is defined at
   `cmd/cli/monitor.go:117` and reached from `handleMonitorInterface` (`monitor.go:90`) when
   `req.InterfaceName == "" && monitorInputIsTTY(os.Stdin)`. So `monitor interface` (bare) or
   `monitor interface traffic` on a TTY in the remote `cli` binary reaches it — **reachable**.

2. **The pre-fix pattern is present verbatim**:
   - `setMonitorRawMode` sets `raw.Cc[unix.VMIN] = 1` and `raw.Cc[unix.VTIME] = 0` — a
     **blocking** single-byte read (no poll timeout).
   - The goroutine loops `n, err := os.Stdin.Read(buf)`; only *after* a successful read does it
     enter `select { case keyCh <- buf[0]: case <-doneCh: return }`. While parked in the blocking
     `Read`, it **cannot observe `doneCh`**.
   - The function does `defer close(doneCh)` and `defer restoreMonitorTermMode`, but there is **no
     join/WaitGroup/`sync.Once` stop** that waits for the goroutine to drain (confirmed by grep —
     the only `doneCh` reference in the body is the select case).
   - On quit (`isMonitorQuitKey(key)` → `return nil`), `close(doneCh)` fires but the goroutine
     stays parked in `os.Stdin.Read`. It only wakes on the **next** byte, consumes it, sees
     `doneCh` closed, and returns — discarding that byte.

3. **This is exactly the #3985 bug, and #3985 fixed ONLY the local-CLI copy.** Commit `23ecc4a0c`
   ("cli: stop the monitor stdin-reader goroutine on exit (#3985)") switched
   `pkg/cli/monitor_interface.go` to `VMIN=0/VTIME=1` poll-with-timeout, extracted a testable
   `keyReader(r, keyCh, done)` that re-checks `done` on each idle poll, added
   `startKeyReader → (keyCh, stop)` where `stop` closes `done` **and waits** for the goroutine
   (idempotent via `sync.Once`), and both local monitors now `defer stop()` ordered *before*
   the terminal restore. `git show --name-only 23ecc4a0c` touches **only**
   `pkg/cli/monitor_interface.go` + its test — **`cmd/cli/` was never touched**. The remote CLI's
   `monitor.go` still carries `VMIN=1/VTIME=0` and has no `startKeyReader`/`stopKeys`/`keyReader`.
   No later commit (`git log --since=2026-07-04 -- cmd/cli/monitor.go`) fixes it either — only the
   rename (`b67f80edf`) and the main.go split (`976ccce77`).

4. **Materiality trace**: remote CLI interactive loop returns to `rl.Readline()`
   (`cmd/cli/main.go:170`) after the monitor command. The leaked goroutine still holds an
   `os.Stdin.Read` and races readline for the first byte of the next command; if the goroutine
   wins, that byte is dropped → the operator's next command is truncated ("unknown command"), and
   each `monitor interface` invocation stacks another competing reader (the #3985 commit message
   itself calls this out). The finding's refutation-attempt is correct: a TCSETS termios change
   does **not** interrupt an in-flight blocking tty read, so restoring cooked mode does not free
   the parked reader.

### Severity justification (LOW-MED, low end of the review's "Medium")

- Genuine operator-facing correctness + resource-leak bug, and the project already deemed the
  identical local-CLI variant worth a dedicated fix + regression test (#3985) — consistency argues
  for fixing the remote copy.
- Bounded impact: only the interactive remote CLI session, only the immediately-following command
  (recoverable by re-typing), no crash, no dataplane/forwarding/HA/security impact, no persistence.
  In `-c` one-shot mode the process exits before any "next command," so the steal never
  materializes there (leak is harmless at exit). Hence not a full Medium — LOW-MED.

### Fix direction (as the review states, mirroring #3985)

Port the #3985 remedy from `pkg/cli/monitor_interface.go` to `cmd/cli/monitor.go`: set
`VMIN=0/VTIME=1` in `setMonitorRawMode`, replace the inline goroutine with a `keyReader`
that `continue`s on `n==0` and discards a post-`done` byte, add `startKeyReader → (keyCh, stop)`
with a `sync.Once`-guarded `stop` that closes done AND waits for the goroutine, and `defer stop()`
ordered before `restoreMonitorTermMode`. (Ideal: extract the shared helper into `pkg/termutil` —
the existing `// TODO` at `monitor.go:31` already flags the duplication.)

### Dedup

Not a dup: the finding's own "Prior finding 1" note (packet-drop out-of-range port) is a different
issue in a different batch. No open/merged bpfrx change addresses the `cmd/cli/monitor.go`
goroutine — the #3985 work is scoped to `pkg/cli` only.

---

## NEGATIVE-RESULTS module sweep (lines 76-501)

No positive findings — the reviewer reports every file in `bpf/headers/`, `cmd/cli/`,
`cmd/shimverify/`, `cmd/xpfd/`, docs probes, and `pkg/cli/` as clean. Nothing to triage. Spot-note:
several of the "clean" claims are consistent with hardened state (e.g. `pkg/cli/monitor_interface.go`
"correctly sets VMIN=0/VTIME=1 and stops the key reader goroutine" — that is precisely the #3985 fix
that Finding 1 shows was NOT applied to the remote-CLI sibling).
