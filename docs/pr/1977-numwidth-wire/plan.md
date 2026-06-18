# #1977 — NUM_WIDTH Go↔Rust snapshot wire mismatches (flow/flow-export)

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)
**Base:** origin/master (`28e7309f7`, post-#1976)
**Issue:** #1977 (sibling class of #1961, found by the #1961 Q5 type-parity audit)

## 1. Issue framing

#1961 fixed the `[]uint8`→base64 wire-type bug. The Q5 audit that accompanied it
found a **second fatal-decode class**: nine `FlowSnapshot` / `FlowExportSnapshot`
fields are Go signed `int` on the wire but Rust **unsigned** `u16`/`u32`/`u64`.
A negative or out-of-range value serializes fine from Go but makes
`serde_json::from_str::<ControlRequest>` ERROR (`invalid value: integer X,
expected uN`). Because the helper decodes the whole request in one `from_str`
(`server/handlers/mod.rs`), the entire `apply_snapshot` is rejected before
`snapshot::apply` runs — the exact #1961 failure mode (helper unconfigured,
forwarding silently broken, Go sees a bare EOF — now logged after #1961's Q3
hardening).

### The nine fields

| Go (`pkg/dataplane/userspace/protocol.go`) | Rust | wire range | source |
|---|---|---|---|
| `FlowSnapshot.TCPMSSIPsecVPN` (int) | `u16` | 0–65535 | `cfg.Security.Flow.TCPMSSIPsecVPN` |
| `FlowSnapshot.TCPMSSGreIn` (int) | `u16` | 0–65535 | `cfg.Security.Flow.TCPMSSGreIn` |
| `FlowSnapshot.TCPMSSGreOut` (int) | `u16` | 0–65535 | `cfg.Security.Flow.TCPMSSGreOut` |
| `FlowSnapshot.TCPSessionTimeout` (int) | `u64` | ≥0 | `cfg.Security.Flow.TCPSession.EstablishedTimeout` |
| `FlowSnapshot.UDPSessionTimeout` (int) | `u64` | ≥0 | `cfg.Security.Flow.UDPSessionTimeout` |
| `FlowSnapshot.ICMPSessionTimeout` (int) | `u64` | ≥0 | `cfg.Security.Flow.ICMPSessionTimeout` |
| `FlowExportSnapshot.CollectorPort` (int) | `u16` | 1–65535 | sampling `flow-server` port |
| `FlowExportSnapshot.ActiveTimeout` (int) | `u32` | ≥0 | v9 template `flow-active-timeout` |
| `FlowExportSnapshot.InactiveTimeout` (int) | `u32` | ≥0 | v9 template `flow-inactive-timeout` |

The most operator-reachable triggers are the **u16** fields with a value
`>65535` (a plausible typo, e.g. `set services flow tcp-mss-gre-in 70000` or
`flow-server <addr> port 70000`). Negatives need a more contrived path. None of
these leaves currently carry a commit-time validator (the project pattern
`ValidateInteger(min,max)` exists — e.g. `schema_chassis.go` — but is absent
here; `compiler_services.go` parses with `strconv.Atoi` and no range check).

## 2. Honest scope/value framing

Closes a latent class that silently disables the entire dataplane on a
plausible operator typo, with only a (now-logged) EOF as the signal. The win is
correctness + operator UX (a clear commit error instead of a dead dataplane).
*If reviewers conclude the build-boundary guard alone suffices and the
per-leaf commit validation is not worth the churn — or vice-versa — narrowing
to one layer is an acceptable outcome.*

## 3. What's already shipped

#1961 (merged): the `[]uint8`/base64 fix, the reflection guard (catches the
`[]uint8` class only — it cannot see the int→unsigned class), and the helper
decode-error logging (so a recurrence of THIS class now logs `control request
failed: ... invalid value: integer ...` instead of a silent EOF).

## 4. Concrete design (two complementary layers; reviewers weigh)

### Layer A — build-boundary guard (the guarantee)

`buildFlowSnapshot` / `buildFlowExportSnapshot` (`flow.go`) are the single
chokepoint before the wire, covering **every** input path (CLI, gRPC config,
file load, future). Coerce each of the nine fields into its Rust wire range
before it is placed on the snapshot, so a bad value can never abort the decode:

- **u16 MSS** (`TCPMSS*`): out-of-range → treat as `0` (= "disabled", the
  field's documented zero-default; dropped by `,omitempty`). A negative or
  `>65535` MSS is meaningless anyway.
- **u16 CollectorPort**: out-of-range (`<1` or `>65535`) → **skip the
  flow-export feature** for that server (extend the existing `server.Port == 0`
  skip), since exporting to an invalid port is wrong, not clampable.
- **u32/u64 timeouts**: negative → `0` (= "use built-in default"); `>` the Rust
  type max → clamp to the max. (u32 max for Active/Inactive; u64 for session
  timeouts — realistically unreachable, but the guard makes it total.)
- Log a single `slog.Warn` when a value is coerced, naming the field + the
  offending value, so the operator sees it even on a non-CLI path.

This is behavior-preserving for every in-range config (the vast majority) and is
the property the regression test pins.

### Layer B — commit-time validation (operator UX)

Add `ValidateInteger` typed-leaf validators to the config schema leaves so the
CLI rejects the bad value at `commit check` with a clear message (the project
pattern), instead of relying on silent coercion:

- `security flow tcp-mss {ipsec-vpn|gre-in|gre-out|all-tcp}` → `ValidateInteger(0, 65535)`
  (`schema_security.go`)
- `security flow tcp-session established-timeout`, and the udp/icmp session
  timeouts → `ValidateInteger(0, MaxDurationSeconds)` (locate exact leaves)
- `services …/forwarding-options sampling … flow-server <addr> port` →
  `ValidateInteger(1, 65535)` (`schema_routing.go`)
- `services flow-monitoring … flow-active-timeout` / `flow-inactive-timeout`
  → `ValidateInteger(0, <u32 max or a sane cap>)` (`schema_system.go:434/443`)

## 5. Public API / wire preservation

No wire-shape change — these stay numeric JSON. The fix only ensures the value
is always in the Rust type's range. New Go → old Rust and old Go → new Rust are
both unaffected for in-range configs (the only ones that ever worked). Mixed
HA (#1917): no change to session-sync wire.

## 6. Hidden invariants

- Zero-value semantics preserved: `0` means "disabled"/"use default" for these
  fields; the guard must not turn a valid `0` into anything else.
- `,omitempty` still drops zero values (minimal-config publish unchanged).
- The build-boundary coercion must be deterministic and allocation-free on the
  config-commit path (not hot path; trivial).

## 7. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | In-range configs unchanged; only out-of-range values (previously fatal) are coerced/rejected. |
| Lifetime/borrow | N/A | No Rust change. |
| Performance | NONE | Config-commit time only. |
| Architectural mismatch | LOW | Adds validation + a guard; no structural change. |

## 8. Test plan

1. Go unit tests: for each of the 9 fields, a config with an out-of-range value
   (`-1` and `70000` where the type is u16) → `buildFlowSnapshot` /
   `buildFlowExportSnapshot` produces a snapshot whose marshaled JSON has the
   field in range (or the feature skipped for CollectorPort), and `json.Marshal`
   of the full `ControlRequest` decodes... (Go can't run serde, so) assert the
   numeric value is within `[0, typeMax]`.
2. Go schema test: `commit check` (SchemaValidate) **rejects** `tcp-mss-gre-in
   70000`, `flow-server … port 70000`, `flow-active-timeout -1`, etc. with a
   clear error (Layer B).
3. Rust test: extend the #1961-style full-`ControlRequest` decode test with a
   FlowSnapshot/FlowExportSnapshot carrying max-range values (65535 / u32 max)
   — confirm they decode; and a negative value is rejected (documents the
   mechanism this PR defends against).
4. `cargo test --release` + `go test ./...` full suites.
5. Loss-cluster smoke (CoS off + on, v4+v6, push+reverse multi-stream) — no
   regression. The loss config exercises flow/CoS; confirm publish + line rate.
   Optionally add an out-of-range flow value to a scratch config and confirm
   `commit check` now rejects it (Layer B) live.

## 9. Out of scope

- A general "audit every Go int↔Rust unsigned wire field" sweep beyond the 9
  confirmed (the Q5 audit covered the snapshot surface; these 9 are the
  confirmed FATAL_DECODE set).
- Changing the Rust types (they are correctly bounded; the fix is input-side).

## 10. Open questions for adversarial review

- **Q1:** Layer A coercion semantics per field — is `0`/skip/clamp the right
  choice for each (MSS→0, port→skip, timeout→0/clamp)? Any field where silent
  coercion hides a real operator error worse than a commit rejection?
- **Q2:** Do we need BOTH layers, or is the build-boundary guard (which covers
  all input paths) sufficient, with commit-time validation as a separate
  follow-up? (Codex #1961 leaned "don't over-scope.")
- **Q3:** Exact ranges — MSS min (0 vs 64/536 per Junos), port min (0 vs 1),
  timeout caps. Should MSS validate against the IP-MTU-derived max rather than
  the u16 max?
- **Q4:** Are there MORE than these 9 int→unsigned wire fields once #1961
  merged? Re-confirm against current `protocol.go` vs the Rust structs (the Q5
  audit predates the merge but #1976 didn't touch these fields).
- **Q5:** Should a class-level guard (analogous to #1961's reflection test) be
  added — e.g. a Go↔Rust contract test or a build-boundary assertion that every
  numeric snapshot field is range-checked? Or is that over-engineering?
