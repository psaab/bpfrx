# Claude SMR — #1961 wire-type fix, code review (PR #1976)

**Posture:** hostile domain SMR (serialization / Go-Rust interop). 4th reviewer.

**Verdict: MERGE-READY** (functional code), conditional on the plan's live Q1
gate. Codex MERGE-NEEDS-MINOR (whitespace nit — fixed) + AGY MERGE-READY +
Copilot COMMENTED (one real doc nit fixed; three assignability claims refuted).

## What I verified directly

- **MarshalJSON never base64s.** `wire_uint8list.go:40` builds the array with
  `strconv.AppendUint` and never calls `json.Marshal([]uint8)` (which would
  re-trigger the stdlib base64 special-case and recreate the bug). nil/empty →
  `[]`, which is *safer* than Go's default nil-`[]uint8` → `null` (a `Vec<u8>`
  with `#[serde(default)]` decodes `[]` but not `null`). Verified by test.
- **`omitempty` preserved.** `encoding/json` checks slice length before invoking
  a field's MarshalJSON, so an empty `WireUint8List` is still dropped — minimal
  configs keep publishing. Confirmed by `TestWireUint8ListMarshalsNumericArray`
  + the integration test omitting empties.
- **UnmarshalJSON** handles numeric array (via `[]uint16` + `>255` reject),
  legacy base64, `null`, and leading whitespace. The `case 'n'` → null is safe:
  the only valid JSON value starting with `n` is `null`, and `json.Unmarshal`
  only invokes the method on a validated complete value.
- **All three typed fields converted** (protocol.go:194/205/417); assignment
  sites unchanged because unnamed `[]uint8` is assignable to a named slice type
  with the same underlying type. Proven by `go build` + full Go suite green.
- **Reflection guard** walks the real `ControlRequest`/`ControlResponse` graph,
  is cycle-safe (visited set), and skips only the `ConfigSnapshot.Config`
  passthrough (Rust `serde_json::Value`, untyped → base64 harmless). It already
  earned its keep: it surfaced the config-package DSCP `[]uint8` reachable via
  the passthrough, which I confirmed is decoded as an opaque Value and excluded.
- **Rust tests** decode a *full* `ControlRequest` (not leaf structs) and the
  negative test proves a base64 string aborts the whole-request decode.
- **Hardening** is behavior-preserving: lifecycle.rs only adds logging; the Go
  EOF enrichment wraps `io.EOF`/`io.ErrUnexpectedEOF` with `%w`, no import cycle.

## Hostile findings (all resolved)

1. Copilot's three "must update assignment sites" comments are **false
   positives** — Go named-type assignability makes them unnecessary, proven by a
   clean build + full suite + Codex + AGY both confirming. Refuted, not actioned.
2. Copilot's base64 doc-example inconsistency (`"LAo="` ≠ [46,10]) — **real,
   fixed** (`6df92a8c5`).
3. Codex whitespace `git diff --check` nit in the saved AGY doc — **fixed**
   (`52a982df3`); `git diff --check` now clean.
4. The pre-existing flake `concurrent_recovery_processes_each_command_exactly_once`
   (worker_queue, untouched here) passed 3/3 + 5/5 clean — not a regression.

## Q5 audit outcome (the one thing reviewers should weigh)

The plan-mandated Go↔Rust type-parity audit (19-agent workflow) found **12
FATAL_DECODE siblings** — Go signed `int` → Rust `u16`/`u32`/`u64` across 9 flow/
flow-export fields — where an out-of-range value (e.g. an operator typo
`tcp-mss-gre-in 70000`) triggers the *same* whole-snapshot decode abort, with no
commit-time validation. These are a **distinct class** (numeric range, not
base64) triggered by *abnormal* values, vs this PR's `[]uint8` bug which triggers
on a *normal* config. Scoped out to **#1977** with full evidence, keeping this PR
focused on the reported #1961 root cause. This is a deliberate split, not an
oversight.

## Outstanding gate

Q1 (live): does virtio actually forward once `apply_snapshot` publishes? The fix
is proven necessary (VM-free repro + suites + new tests) but its *sufficiency*
for transit is the plan's hard gate — to be confirmed on a 26.04 plain-virtio VM
before declaring #1961 fixed. The code is mergeable independent of Q1's outcome
(Q1=fail would reopen the XSK-delivery plan as a separate follow-up, not revert
this fix).
