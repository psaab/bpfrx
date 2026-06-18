# #1977 — NUM_WIDTH Go↔Rust snapshot wire mismatches (flow/flow-export)

**Status:** PLAN-READY v2.1 (converged 2026-06-18). AGY r2 PLAN-READY + Codex r2
PLAN-NEEDS-MINOR (3 doc-precision minors — Q1 usize-count wording,
`address_count` is status-side, `TCPMSSAllTCP` test via helper — all folded) +
Claude SMR r2 PLAN-READY. Design unanimously sound. Inventory **11** fields
(`TCPMSSAllTCP` + `SamplingRate` added in r1); session-timeout cap
`MaxDurationSeconds` (Codex r2 confirmed `9.22e9 × 1e9 < u64max`, saturating
downstream); per-field coercion explicit; **Layer B (commit-time validation)
deferred to a follow-up** (target schema nodes are `children: nil`; Layer A
alone is the dataplane-safety guarantee on all paths).
**Base:** origin/master (`28e7309f7`, post-#1976)
**Issue:** #1977 (sibling class of #1961, found by the #1961 Q5 type-parity audit)

## 1. Issue framing

#1961 fixed the `[]uint8`→base64 wire class. The Q5 audit found a second
fatal-decode class: `FlowSnapshot`/`FlowExportSnapshot` fields that are Go
signed `int` on the wire but Rust **unsigned**. A negative or out-of-range value
serializes fine from Go but makes `serde_json::from_str::<ControlRequest>` ERROR
(`invalid value: integer X, expected uN`); because the helper decodes the whole
request in one `from_str` (`server/handlers/mod.rs`), the entire `apply_snapshot`
is rejected — the #1961 failure (helper unconfigured, forwarding silently
broken; now logged after #1961's Q3 hardening).

### The eleven fields (corrected from 9 — Codex + AGY r1)

| Go (`pkg/dataplane/userspace/protocol.go`) | Rust | wire range | builder-reachable? |
|---|---|---|---|
| `FlowSnapshot.TCPMSSIPsecVPN` (int) | `u16` (snapshot.rs:140) | 0–65535 | yes (`cfg.Security.Flow.TCPMSSIPsecVPN`) |
| `FlowSnapshot.TCPMSSGreIn` (int) | `u16` (146) | 0–65535 | yes |
| `FlowSnapshot.TCPMSSGreOut` (int) | `u16` (148) | 0–65535 | yes (Rust 0 ⇒ MTU-derived MSS, not pure-disabled — forwarding/mod.rs:784) |
| `FlowSnapshot.TCPMSSAllTCP` (int) | `u16` (143) | 0–65535 | **no** (not set by `buildFlowSnapshot` today ⇒ always 0; coerced defensively) |
| `FlowSnapshot.TCPSessionTimeout` (int) | `u64` (150) | 0–`MaxDurationSeconds` | yes (`TCPSession.EstablishedTimeout`) |
| `FlowSnapshot.UDPSessionTimeout` (int) | `u64` (152) | 0–`MaxDurationSeconds` | yes |
| `FlowSnapshot.ICMPSessionTimeout` (int) | `u64` (154) | 0–`MaxDurationSeconds` | yes |
| `FlowExportSnapshot.CollectorPort` (int) | `u16` (security.rs:157) | 1–65535 | yes (sampling flow-server port) |
| `FlowExportSnapshot.SamplingRate` (int) | `u32` (158) | 1–4294967295 | **yes, reachable** (`inst.InputRate`, only `<=0→1` today — `flow.go:56`) |
| `FlowExportSnapshot.ActiveTimeout` (int) | `u32` (161) | 0–4294967295 | yes (v9 `flow-active-timeout`) |
| `FlowExportSnapshot.InactiveTimeout` (int) | `u32` (163) | 0–4294967295 | yes (v9 `flow-inactive-timeout`) |

Most operator-reachable: the **u16** fields with a value `>65535` (typo, e.g.
`tcp-mss-gre-in 70000`, `flow-server … port 70000`) and a `sampling input rate`
exceeding u32. No commit-time validator exists on these leaves today
(`compiler_services.go` parses with `strconv.Atoi`, no range check).

## 2. Honest scope/value framing

Closes a latent class that silently disables the entire dataplane on a plausible
operator typo. *If reviewers conclude even Layer A is unjustified at the current
incidence, PLAN-KILL is acceptable — but the dataplane-disable blast radius
(total forwarding loss, no clean error pre-#1961) argues for the guard.*

## 3. What's already shipped

#1961 (merged): the `[]uint8` fix, the reflection guard (catches `[]uint8`
only — cannot see int→unsigned), and helper decode-error logging (so a
recurrence of THIS class now logs `control request failed: … invalid value:
integer …` instead of a silent EOF).

## 4. Concrete design — Layer A (build-boundary coercion), the guarantee

`buildFlowSnapshot` / `buildFlowExportSnapshot` (`flow.go`) are the **sole**
pre-wire constructor of these structs (verified: called only from
`buildSnapshot`/`buildSnapshotWithSchedulerState`, builder.go:45,59;
`FlowExportSnapshot{}` built only at flow.go:53 — confirmed by Codex r1 #6, AGY
r1, Claude SMR r1). Coercing here covers **every** input path (CLI, gRPC, file).
A small helper coerces each field to its Rust wire range and `slog.Warn`s once
when it clamps, naming the field + offending value:

- **u16 MSS** (IPsecVPN, GreIn, GreOut, AllTCP): `v<0 || v>65535` → `0` (=
  disabled; for GRE-out, Rust 0 means MTU-derived MSS — acceptable fail-open).
  AllTCP is not builder-populated today; coerced defensively in case it is wired
  later.
- **u16 CollectorPort**: `v<1 || v>65535` → **skip that server, continue
  scanning** the remaining flow-servers (matches the existing `server.Port == 0`
  skip; do not abort the whole export).
- **u32 SamplingRate**: keep the current `<=0 → 1` normalization; additionally
  `v>4294967295` → `4294967295` (cap) + warn.
- **u32 ActiveTimeout / InactiveTimeout**: `v<0` → `0` (= default); `v>4294967295`
  → `4294967295`. (u32max × 1e9 fits in u64, so no Rust-side overflow.)
- **u64 session timeouts** (TCP/UDP/ICMP): `v<0` → `0` (= default); `v >
  MaxDurationSeconds` → `MaxDurationSeconds`. **Not u64-max**: Rust
  `SessionTimeouts::from_seconds` multiplies `secs * 1_000_000_000` **unchecked**
  (session/mod.rs:75); `MaxDurationSeconds` (= `MaxInt64/1e9` ≈ 9.2e9) keeps the
  product within u64 (Codex r1 #3).

This is behavior-preserving for every in-range config and is the property the
regression test pins.

### Layer B (commit-time `ValidateInteger`) — DEFERRED to a follow-up

Both reviewers (Codex r1 #4, AGY r1 #2) found the target schema nodes
(`security flow tcp-session`/`udp-session`/`icmp-session`/`tcp-mss`,
`forwarding-options sampling …`/`flow-server`) are modeled `children: nil`
(opaque/free-form) — the schema walker does not descend into them, so attaching
`ValidateInteger` requires first expanding each node to define its child
keywords (or adding a custom strict validator). That is a non-trivial schema
restructuring and is **operator UX, not dataplane safety** (Layer A already
makes the decode abort impossible). Ship Layer A here; file Layer B as a
follow-up issue. Layer B must NOT ship without Layer A (it would leave the
gRPC/file paths exposed).

## 5. Public API / wire preservation

No wire-shape change — fields stay numeric JSON, only guaranteed in-range. New
Go → old Rust and old Go → new Rust unaffected for in-range configs (the only
ones that ever worked). No HA session-sync wire change (#1917).

## 6. Hidden invariants

- Zero-value semantics preserved: `0` = "disabled"/"use default"; the guard must
  not turn a valid `0` into anything else, nor a valid in-range value.
- `,omitempty` still drops zero values (minimal-config publish unchanged). Note
  `sampling_rate` has no `omitempty` and is always emitted ≥1 (existing
  `<=0→1`), so the cap is the only added behavior.
- Coercion is deterministic, allocation-free, config-commit-time only.

## 7. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | In-range configs unchanged; only previously-fatal out-of-range values are coerced. |
| Lifetime/borrow | N/A | No Rust change. |
| Performance | NONE | Config-commit time only. |
| Architectural mismatch | LOW | Adds a coercion helper at the existing chokepoint. |

## 8. Test plan

1. Go unit tests covering **all 11 fields**. For the 10 builder-populated fields,
   feed a config with `-1` and (for u16) `70000` / (for SamplingRate) `>u32max` /
   (for session timeouts) `> MaxDurationSeconds` through the **real**
   `buildFlowSnapshot` / `buildFlowExportSnapshot`, marshal the full
   `ControlRequest`, and assert each numeric is within `[0, typeMax]` (≤
   `MaxDurationSeconds` for u64 timeouts), and that an out-of-range CollectorPort
   skips that server. `TCPMSSAllTCP` is NOT populated by `buildFlowSnapshot`
   today (Codex r2 #3) — cover its coercion with a direct helper/table test
   (contract-only defensive coverage), not via the real builder.
2. Rust test (extends the #1961 full-`ControlRequest` decode test): a
   FlowSnapshot/FlowExportSnapshot with max-valid values (65535, u32max,
   MaxDurationSeconds) decodes; a negative `sampling_rate`/timeout is rejected
   (documents the mechanism this PR defends against).
3. `cargo test --release` + `go test ./...` full suites.
4. Loss-cluster smoke (CoS off + on, v4+v6, push+reverse multi-stream) — the
   loss config exercises flow + CoS; confirm publish + line rate, no regression.

## 9. Out of scope

- **Layer B** (commit-time `ValidateInteger` + schema-node expansion) → follow-up
  issue.
- Tighter-than-wire Junos semantic ranges (MSS MTU-derived min/max, etc.) — a
  config-correctness improvement, not needed to stop the decode abort.
- Changing the Rust types (correctly bounded; the fix is input-side).

## 10. Open questions for adversarial review

- **Q1:** Inventory completeness — RESOLVED (Codex r1/r2 + AGY + SMR). Other
  request-side `int` json fields split into: (a) Rust **signed** (`vlan_id`,
  `mtu`, `ttl`, `ifindex`, `parent_ifindex`, `queue` = `i32`; no mismatch); and
  (b) Rust **usize** but **builder-derived counts** that are never negative or
  out-of-range — `SnapshotSummary` interface/zone/policy/scheduler counts
  (protocol.go:115 → snapshot.rs:25), `InterfaceSnapshot.RXQueues`/`UnitCount`
  (snapshot.rs:50), `FabricSnapshot.RXQueues` (snapshot.rs:298). None are
  operator-controlled, so none is reachable-FATAL. (`SourceNatPoolSnapshot.
  address_count` is **status-side**, not a `ControlRequest` field — out of scope
  for the decode path.) ⇒ the 11 flow/flow-export fields are the complete
  **reachable-FATAL** set; the usize count fields are a non-reachable theoretical
  tail noted for the record.
- **Q2:** Coercion semantics per field (§4) — all safe fail-open? Any field
  where clamping silently corrupts worse than the (deferred) commit rejection?
  Specifically: SamplingRate cap vs reject; GRE-out 0⇒MTU-derived.
- **Q3:** Is deferring Layer B acceptable, given Layer A closes the safety hole
  on all paths and Layer B needs a separate schema-expansion design?
- **Q4:** `MaxDurationSeconds` (≈9.2e9 s) as the u64 session-timeout cap — does
  any other Rust consumer of these seconds do arithmetic that overflows even at
  that cap? (from_seconds × 1e9 is safe; verify no further unchecked scaling.)
- **Q5:** Should a lightweight Go range-table guard test be added so a future
  int→unsigned snapshot field is caught (analogous to #1961's reflection guard,
  but hand-maintained since cross-language range isn't reflectable)?
