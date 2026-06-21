# Plan of Action — #2129 + #2130 NetFlow v9 export: exporter gating + Rust dead-code scope

- **Revision:** r2 (folds 3-way hostile review — Claude SMR + 2 hostile Claude
  plan-reviewers; all three converged PLAN-CHANGES-REQUIRED on r1 over the same
  blocking finding: the gate fix breaks existing tests; r2 scopes that.)
- **Issues:** #2129 (MEDIUM, gating bug), #2130 (LOW, dead Rust code)
- **Base:** origin/master `325d106838` (issue text says `5fa964c13`; the
  `pkg/flowexport`/`userspace-dp/src` files are **bit-identical** between the
  two SHAs — `git diff 5fa964c13 325d106838 -- pkg/flowexport ...` is empty.
  TWO commits sit between them: `b1747e4e4` (unrelated DHCP-relay test) and the
  merge `325d10683`. Neither touches flow export.)
- **Mode:** `/research` — STOP at PLAN-READY/PLAN-KILL. No code ships from this
  doc.

---

## 1. Problem statement

Two related campaign-2 audit findings about NetFlow v9 / IPFIX flow export:

- **#2129 (gating):** the NetFlow v9 Go exporter starts whenever
  `forwarding-options sampling` has a flow-server, *ignoring whether
  `services flow-monitoring version9` is configured*. An IPFIX-only operator
  gets an unrequested v9 stream; an operator with both v9 and IPFIX pointed at
  one collector gets every sampled session exported twice (v9 + v10) with
  independent 1-in-N counters.

- **#2130 (dead code):** the Rust dataplane has a complete `FlowExporter`
  (`userspace-dp/src/flowexport.rs`) plus a `flow_export_config` field that the
  Go control plane populates over the wire — but the field is write-only and the
  exporter is constructed only by tests. The dataplane emits no flow packets.

The two are coupled: the dead Rust path is the *only* functional consumer of the
per-flow-server `Version9Template` *timeouts*, which masks that the live Go
exporter ignores the same per-server selector. Diagnosing one without the other
produces a wrong fix.

---

## 2. Ground truth (verified against `325d106838`)

### 2.1 What actually emits flows today: the Go side. Confirmed.

- `pkg/flowexport/netflow.go` `Exporter` is the **live v9 emitter**.
  `sendTemplates()` writes `nfHeader{Version: 9, ...}` (netflow.go:504);
  `NewExporter` → `dialCollectors` opens UDP sockets (netflow.go:434);
  `ExportSessionClose` queues a record (netflow.go:469); `Run` flushes batches
  + templates on tickers (netflow.go:444-466).
- `pkg/flowexport/ipfix.go` `IPFIXExporter` is the **live v10 emitter**
  (`ipfixHeader{Version: 10}`, ipfix.go:371; `dialCollectors`, ipfix.go:308).
- Both are driven by `pkg/logging.EventReader` **SESSION_CLOSE** callbacks
  registered once in `pkg/daemon/daemon_flowexport.go`
  (`flowExportCallback` / `ipfixExportCallback`, lines 271-310). The dataplane
  feeds those events through the logging ring; flow export is a control-plane
  consumer of session-close events, **not** a per-packet dataplane path.
- Lifecycle owner: `reconcileFlowExporters` (daemon_flowexport.go:111), added in
  **#2075** (merged as PR #2101, `5e240695f`). It runs at boot (after the
  EventReader exists, daemon_run.go:839-857) and on every commit
  (daemon_apply.go:1209), hash-gated per family.

**Conclusion:** NetFlow v9 export **works today**, and it is **Go-side**. The
recent #2101 reconcile work is correct and orthogonal to both bugs — it
faithfully reflects whatever `BuildExportConfig`/`BuildIPFIXExportConfig`
return.

### 2.2 The Rust dataplane export path is genuinely dead. Confirmed.

- `grep -rn flow_export_config userspace-dp/src` → **one write**
  (`forwarding_build/mod.rs:251`), **zero reads**. Field declared
  `pub(in crate::afxdp) flow_export_config: Option<...>`
  (`afxdp/types/forwarding.rs:86`).
- `FlowExporter` (`flowexport.rs:91`) and its impl (`flowexport.rs:106`) carry
  `#[allow(dead_code)]`. Constructed only from `flowexport_tests.rs` (6 sites);
  never from `main.rs`, the session-create path, or the forwarding hot path.
- Wire field still travels: `builder.go:59` → `FlowExportSnapshot`
  (protocol.go:481) → Rust `snapshot.flow_export` (protocol/snapshot.rs:259) →
  stored into the dead field. So the Go control plane builds + validates a wire
  contract the dataplane silently ignores.
- History: `flowexport.rs` was added in `324d6b9d1` ("eliminate nearly all eBPF
  fallbacks from userspace dataplane") — a speculative dataplane-side export
  that was never wired. When #1373/#1476 made the userspace dataplane the
  forwarding path, flow export stayed Go-side. The Rust path is **vestigial**,
  not an in-progress migration.

**Conclusion:** there is **no double-export from the dataplane** (the Rust path
emits nothing), so #2130 is *not* a forwarding/correctness bug — it is contract
drift + dead code. #2130's LOW severity is correct.

### 2.3 The #2129 gating bug. Confirmed, exactly as filed.

- `BuildExportConfig` (manager.go:53-56) returns non-nil based **only** on
  `fo.Sampling != nil && len(fo.Sampling.Instances) > 0` + at least one resolved
  collector (lines 124-126). It reads `svc.FlowMonitoring.Version9` **only** to
  pull optional template timeouts/extensions (lines 64-83); it never gates on
  `Version9 != nil`.
- Contrast `BuildIPFIXExportConfig` (manager.go:149-151): it **does** gate —
  `if svc == nil || svc.FlowMonitoring == nil || svc.FlowMonitoring.VersionIPFIX
  == nil { return nil }`. So IPFIX is correctly gated; v9 is the asymmetric
  outlier.
- Consequence #1 (IPFIX-only operator gets unwanted v9): a config with
  `version-ipfix` but no `version9` still produces a non-nil v9 ExportConfig →
  `reconcileV9Exporter` starts a v9 exporter (daemon_flowexport.go:121-196) →
  v9 datagrams to the collector alongside the intended IPFIX.
- Consequence #2 (double-export when both configured): `BuildExportConfig` and
  `BuildIPFIXExportConfig` each build a collector set from the **same**
  forwarding-options flow-servers, and both `NewExporter` and
  `NewIPFIXExporter` independently `dialCollectors` the same address:port.
  Each registers its own SESSION_CLOSE callback with its **own**
  `ec.sampleCounter` (manager.go:42), so each sampled session is exported twice
  with mismatched 1-in-N selection.

### 2.4 The per-flow-server version selector is parsed, displayed, and discarded.

- `FlowServer.Version9Template` (types_system.go:741) is parsed by the compiler
  (compiler_services.go:1039-1047).
- It is read for **display** in `cli_show_routing.go:1071`,
  `cli_show_flow.go:1150`, `grpcapi/server_show_forwarding.go:118`.
- Its **timeouts** are consumed **only** by the dead Rust wire builder
  (`flow.go:217-223`, inside `buildFlowExportSnapshot`).
- The **live Go exporter ignores it entirely**: `BuildExportConfig` uses the
  *first* `version9` template globally (manager.go:81 `break // use first
  template`) and `BuildIPFIXExportConfig` likewise (manager.go:167). Junos binds
  each flow-server to exactly one export version+template; xpf flattens all
  flow-servers into one global collector set per version.

> Note: #2130's text says "Version9Template's only functional consumer is this
> dead snapshot field." Refined: it has three *display* consumers + the dead
> wire builder is the only consumer of its *timeouts*. The substantive point
> stands — no live emission path honors the per-server binding.

### 2.5 No commit-check / schema warning exists for the version binding today.

`flow-monitoring` typed leaves exist in setSchema (the #1977 NUM_WIDTH timeout
validators, `schema_validate_flow_numwidth_test.go`), but there is **no**
commit-check warning when a flow-server lacks a version binding or when v9 and
IPFIX both target the same address:port.

---

## 3. Decision

**PLAN-READY**, scoped as **two coupled fixes on one PR**:

- **#2129 = real bug, PARTIALLY fix it.** #2129 has TWO harms: (1) an
  IPFIX-only operator gets an *unrequested* v9 stream, and (2) a both-versions
  operator gets *double-export to one collector* with mismatched 1-in-N. This
  PR fixes harm (1) — the broader, higher-incidence defect (an operator who
  never asked for v9 at all) — by gating v9 export on `Version9 != nil` (mirror
  the existing IPFIX guard). Harm (2) requires the per-flow-server version-
  binding redesign and is **explicitly deferred** (§8). The issue comment and
  PR must state #2129 is *partially* fixed and link the concrete follow-up — do
  NOT imply #2129 is fully resolved. (Both v9 and IPFIX still pass their gates
  when both stanzas are present, so the both-configured double-export survives
  this PR by design; that is arguably correct Junos "you asked for two streams"
  behavior until the per-server binding lands.)

- **#2130 = dead code, REMOVE it (Option A below).** Flow export is
  *intentionally and permanently Go-side*. The Rust path is vestigial (added
  pre-eBPF-retirement, never wired, no migration in flight). Removing it
  eliminates the contract-drift hazard and the misleading "the dataplane has a
  flow exporter" signal. We do **not** wire the Rust exporter (that would be a
  large, unjustified architecture change — see Path Options).

The per-flow-server `Version9Template`-binding fix (true Junos one-version-per-
flow-server semantics) is **explicitly out of scope** for this PR and is
**deferred to a follow-up** (see §8). This PR fixes the *presence* gate
(#2129's primary defect) and removes dead code (#2130); it does not rebuild the
collector-resolution model.

---

## 4. Path Options (the design space, with the chosen path marked)

### Path A — Remove the dead Rust path; keep Go-side export. **CHOSEN.**

Delete `userspace-dp/src/flowexport.rs`, `flowexport_tests.rs`, the
`flow_export_config` field, the `mod flowexport;` declaration, and the
`forwarding_build/mod.rs:251` writer. Decide the fate of the Go→Rust
`FlowExportSnapshot` wire field (see §5.2 — keep-documented vs remove).

- **Pro:** smallest, safest; removes the drift hazard; matches the actual
  architecture (export is a control-plane consumer of session-close events).
- **Con:** if a future "export from the dataplane hot path" need ever arises,
  it must be re-implemented. Acceptable — git history preserves the code, and
  the current Go path is the correct design for session-close-driven export.

### Path B — Wire the Rust FlowExporter; remove the Go exporter. **REJECTED.**

Construct `FlowExporter` from `flow_export_config`, call `should_sample` /
`record_flow` at session create, `finalize_flow` at expiry, `tick`/`flush`
periodically; then delete `pkg/flowexport`'s emitters.

- **Pro:** export co-located with the dataplane; no Go-side session-close
  round-trip.
- **Con (fatal):** enormous blast radius. The Go path already does per-zone
  direction sampling (`BuildSamplingZones`/`ShouldExport`), IPv6 records,
  IPFIX (v10), conditional template fields (`V9TemplateOpts`, flow-dir
  extension), source-address bind, multi-collector fan-out, and HA-safe
  lifecycle. The Rust `FlowExporter` implements **none** of that (IPv4-only,
  single collector, v9-only, no zone filter, no source-address). Wiring it
  means re-implementing the entire mature Go feature set in Rust **and** adding
  a per-session hot-path cost to the dataplane — a multi-week rewrite to move a
  working feature for no functional gain. Rejected.

### Path C — Leave both; only fix #2129; document the Rust path as vestigial. **REJECTED for #2130.**

Fix the gating bug, add a doc note that the Rust exporter is dead-but-retained.

- **Pro:** minimal churn.
- **Con:** keeps a ~490-line dead module + a write-only wire field that future
  readers will mistake for a live path (exactly the audit's complaint).
  Documentation-only is weaker than deletion when the code provides zero value.
  We prefer deletion (Path A) but list this as the fallback if a reviewer argues
  the wire field must stay for forward-compat.

---

## 5. Implementation scope (Path A)

### 5.1 #2129 — gate v9 export on `Version9` presence (PRIMARY)

`pkg/flowexport/manager.go`, `BuildExportConfig` — add the guard mirroring
`BuildIPFIXExportConfig`:

```go
func BuildExportConfig(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) *ExportConfig {
	if fo == nil || fo.Sampling == nil || len(fo.Sampling.Instances) == 0 {
		return nil
	}
	if svc == nil || svc.FlowMonitoring == nil || svc.FlowMonitoring.Version9 == nil {
		return nil // #2129: v9 export only when `services flow-monitoring version9` is configured
	}
	...
```

- This makes v9 symmetric with IPFIX. After it, an IPFIX-only config produces a
  nil v9 ExportConfig → `reconcileV9Exporter` stops/never-starts the v9 exporter
  (daemon_flowexport.go:146-156 already handle nil ec correctly, including the
  hash-gate sentinel).
- **Behavior-change call-out:** a config that previously had *only* `sampling` +
  flow-server and *no* `flow-monitoring` stanza at all used to get v9 export.
  After the fix it gets *no* export (neither v9 nor IPFIX). This is the correct
  Junos behavior (export requires a `flow-monitoring` version stanza) and
  matches IPFIX's existing gate, but it IS an observable change for any operator
  relying on the bug. **Must be release-noted.** (See §6 risk.)

### 5.2 #2130 — remove the dead Rust export path

Delete / edit, Rust side (`flowexport.rs` is **352 lines**, `flowexport_tests.rs`
is **137 lines** — 489 total; the deletable *executable module* is 352):
- `userspace-dp/src/flowexport.rs` — delete file (352 lines).
- `userspace-dp/src/flowexport_tests.rs` — delete file (137 lines).
- `userspace-dp/src/main.rs:11` — remove `mod flowexport;`.
- `userspace-dp/src/afxdp/types/forwarding.rs:86` — remove the
  `flow_export_config` field (struct is built field-by-field; no `..Default`
  shorthand covers it, so removing the decl + the one writer is sufficient).
- `userspace-dp/src/afxdp/forwarding_build/mod.rs:251-261` — remove the writer
  block.
- **(review r1 finding — required) `userspace-dp/src/protocol/snapshot.rs:259`:**
  after the writer at mod.rs:251 is removed, `snapshot.flow_export` is read ONLY
  from `#[cfg(test)]` code (`protocol/tests.rs:1735`) under 5.2-keep, so a
  `--release` build emits a NEW `dead_code` warning on the field. There is no
  `#![deny(warnings)]` / `RUSTFLAGS=-D warnings` in the Makefile
  `build-userspace-dp` target, so the build does NOT fail — but the warning must
  be pre-empted with `#[allow(dead_code)]` on `snapshot.flow_export`, matching
  the existing same-pattern precedent (`gre_acceleration` /
  `power_mode_disable`, `forwarding.rs:78`/`:85`, "held for config truth/parity").
  (Not needed under 5.2-remove — the field is gone.)

**Decision point (flag to reviewers): the Go↔Rust `FlowExportSnapshot` wire
field.** Two sub-options:

- **5.2-keep (recommended default):** keep `FlowExportSnapshot` in
  `protocol.go` / `protocol/security.rs` / `snapshot.rs` and keep
  `buildFlowExportSnapshot` *producing* it, but document it as a
  **reserved/vestigial wire field the dataplane currently ignores**. Rationale:
  removing a wire field is a cross-language protocol change; the #1977
  NUM_WIDTH decode-safety tests (`protocol/tests.rs:1708-1769`) guard exactly
  this field against a malformed-Go-value decode abort (#1961 failure class).
  Keeping the field + tests preserves that safety net and avoids a wire-version
  skew during rolling upgrade (an old helper sending the field to a new helper,
  or vice versa). The cost is one `#[serde(... default)]` Option that
  deserializes and is dropped.
- **5.2-remove (only if a reviewer insists the field must go):** also delete
  `FlowExportSnapshot` (Go + Rust), the `flow_export` snapshot field,
  `buildFlowExportSnapshot`, `builder.go:59`, and the #1977 tests. This is a
  clean wire-contract removal but is a larger, rolling-upgrade-sensitive change.

**Recommendation: 5.2-keep.** Remove the dead *executable* path (the
`FlowExporter` + the consumer field) but retain the *wire field* as documented
reserved space. This kills the misleading "dataplane has a flow exporter"
signal (the audit's actual complaint) while keeping the decode-safety tests and
avoiding a protocol break. Reviewers may push to 5.2-remove; either is
defensible. The plan converges on **5.2-keep** unless a reviewer makes the
forward-compat/rolling-upgrade case moot.

### 5.3 Docs (required by #2130 + CLAUDE.md doc-contract rule)

- `pkg/flowexport/README.md` — already says export is Go-side off the
  EventReader; add one sentence: "The userspace dataplane does NOT emit flow
  records; flow export is entirely control-plane, driven by SESSION_CLOSE
  events." (Pre-empts the next reader's same confusion.)
- `pkg/dataplane/README.md` — add a short note: "Flow export (NetFlow v9 /
  IPFIX) is owned by `pkg/flowexport` on the control plane; the dataplane does
  not emit flow packets. The `flow_export` snapshot field is reserved/ignored
  (see #2130)." (Under 5.2-keep.) Under 5.2-remove, the note says the field was
  removed.
- `_Log.md` — log the Write/Edit actions per CLAUDE.md.

---

## 6. Risk & blast radius

- **Behavior change (operator-visible):** §5.1 — configs relying on the gating
  bug lose v9 export. MEDIUM-severity issue → the fix IS the point, but it must
  be release-noted. No silent data-path change; export is observability only, so
  no traffic/forwarding risk.
- **Tests (BLOCKING — convergent r1 finding from all three reviewers): the
  §5.1 guard BREAKS 9 existing tests that encode the current buggy behavior.**
  The test work is NOT purely additive — the guard invalidates the foundational
  helper the entire v9-reconcile suite is built on. In-scope edits, verified
  against source:
  - `pkg/flowexport/exporter_test.go` — THREE tests call
    `BuildExportConfig(nil, fo)` (svc=nil) and assert non-nil:
    `TestBuildExportConfig_InlineJflowSourceAddress` (call at :30),
    `TestBuildExportConfig_FlowServerSourceAddressTakesPrecedence` (:166),
    `TestBuildExportConfig_DistinctSourceAddressesAreNotDeduped` (:198). After
    the guard, `svc==nil → return nil` → each hits its `t.Fatal`. Fix: pass a
    non-nil `*config.ServicesConfig` with `FlowMonitoring.Version9` set instead
    of `nil` (these tests assert source-address handling, orthogonal to gating).
  - `pkg/daemon/daemon_flowexport_reconcile_test.go` — the base helper
    `flowSamplingConfig` (lines 19-35) sets NO `Services.FlowMonitoring` at all
    (only `ipfixSamplingConfig` at :40-50 adds a `VersionIPFIX` stanza). SIX
    tests drive `flowSamplingConfig` and assert the v9 exporter STARTS:
    `TestReconcileFlowExporterAddAfterBoot` (:66), `...RemoveAfterBoot` (:92),
    `...HashGate` (:119), `TestReconcileV9IPFIXIndependence` (:177),
    `...RetriesAfterCreateFailure` (:220, via `flowSamplingConfigSrc` which
    also lacks `Version9`), `TestApplyConfigLockedReconcilesFlowExporters`
    (:254). Fix: add `Services.FlowMonitoring.Version9 = &config.NetFlowV9Config{
    Templates: map[string]*config.NetFlowV9Template{"t": {Name: "t"}}}` to
    `flowSamplingConfig` (and `flowSamplingConfigSrc`) — ONE edit fixes all six.
    (`TestReconcileFlowExporterNoCallbackLeak` at :155 — re-check after the
    helper edit; it should follow the helper.)
  - **New positive/negative cases to ADD:** "sampling + flow-server WITHOUT
    `version9` → nil v9 ExportConfig (no v9 exporter starts)" and "WITH
    `version9` → non-nil"; and a daemon-level case asserting that an
    IPFIX-only config (`ipfixSamplingConfig`) starts the IPFIX exporter but
    NOT the v9 exporter (the #2129 regression guard).
  - Rust — deleting `flowexport_tests.rs` removes 6 tests of dead code (zero
    coverage loss for live behavior). Under 5.2-keep, the #1977 wire-decode
    tests (`protocol/tests.rs:1708-1769`) stay and must still pass.
  - Confirm `config.NetFlowV9Config` / `NetFlowV9Template` field names at
    /engineer time (the IPFIX helper uses `NetFlowIPFIXConfig` /
    `NetFlowIPFIXTemplate`; the v9 analogues live in `types_system.go`).
- **Rolling upgrade (HA):** under 5.2-keep, no wire change → no skew risk.
  Under 5.2-remove, a mixed-version cluster could see one node sending the
  `flow_export` field and the other not parsing it — `#[serde(default)]` +
  `,omitempty` make this benign in practice, but it's a reason to prefer
  5.2-keep.
- **Compile:** removing the Rust module must leave zero `flow_export_config` /
  `flowexport::` references — `cargo build` is the gate (`grep` after edit).
- **No HA/VRRP/session-sync/failover code touched** → `make test-failover` is
  not strictly mandated by the touched-files rule, but a smoke (build + a
  config that exercises both gating branches + confirm v9 datagrams appear only
  with `version9`) is appropriate at `/engineer` time.

---

## 7. Validation plan (for /engineer, not now)

1. `make test` (Go) — the 9 updated existing tests (§6) + new positive/negative
   gating cases pass; all other flowexport/daemon tests pass.
2. `make build-userspace-dp` (Rust) — compiles after dead-code removal. Explicit
   grep gate (must return ZERO hits except the documented reserved field):
   `grep -rn 'FlowExporter\|FlowExportConfig\|crate::flowexport\|mod flowexport\|flow_export_config' userspace-dp/src`
   — after removal, the ONLY remaining `flow_export`-family reference is
   `snapshot.flow_export` (the reserved wire field, 5.2-keep) + its `#[cfg(test)]`
   reader; there must be NO `FlowExporter`, `FlowExportConfig`,
   `crate::flowexport`, `mod flowexport`, or `flow_export_config` left.
3. Functional: on a VM, configure (a) sampling + flow-server + `version9` →
   confirm v9 datagrams (`version field == 9`) at the collector; (b) sampling +
   flow-server + `version-ipfix` only (NO version9) → confirm **no** v9
   datagrams, only v10; (c) both → confirm one v9 + one v10 stream (note: this
   PR does NOT de-dup the double-export-to-same-collector case — that's the §8
   follow-up; the gate fix only stops the *unrequested* v9 stream).
4. `_Log.md` updated.

---

## 8. Explicit follow-ups (NOT in this PR)

- **#2129 part 2 (per-flow-server version binding + double-export de-dup) —
  MUST be filed as a concrete GitHub issue BEFORE this PR merges** (review
  finding: don't leave it as prose that evaporates). Resolve the collector set
  *per flow-server* from its version selector (`FlowServer.Version9Template` /
  a per-server protocol field) so each flow-server is bound to exactly one
  export protocol (Junos semantics), and add a commit-check warning when v9 and
  IPFIX both target one address:port. This is a larger collector-resolution
  redesign (touches `BuildExportConfig` / `BuildIPFIXExportConfig` collector
  loops + `FlowServer.Version9Template` consumption + a new schema/commit-check
  warning). The presence-gate fix in §5.1 addresses #2129's *primary* observable
  defect (unrequested v9 stream) without it; this follow-up closes the remainder.
- If 5.2-keep is chosen: optionally a later cleanup to remove the
  `FlowExportSnapshot` wire field once a wire-version bump is otherwise required.

---

## 9. Summary for the issue comment

- **NetFlow v9 export works today and is Go-side** (`pkg/flowexport`, driven by
  SESSION_CLOSE EventReader callbacks; lifecycle by #2075/#2101
  `reconcileFlowExporters`). The Rust dataplane emits nothing.
- **#2129** is a real gating asymmetry (v9 not gated on `version9`; IPFIX is
  gated on `version-ipfix`). Fix = guard mirroring the IPFIX gate. This is the
  PARTIAL fix — it stops the *unrequested* v9 stream (the broader defect) but
  leaves the both-versions double-export for the §8 follow-up. The guard breaks
  9 existing tests that encode the buggy behavior (3 `BuildExportConfig(nil,..)`
  + 6 driving the `Version9`-less `flowSamplingConfig` helper) — these are
  in-scope edits, NOT additive (§6). Operator-visible behavior change →
  release-note.
- **#2130** is genuine dead code (Rust `FlowExporter` + write-only
  `flow_export_config`), not a forwarding bug. Fix = remove the dead executable
  path; retain the wire field as documented-reserved (5.2-keep) to preserve the
  #1977 decode-safety tests and avoid a protocol break. Add `#[allow(dead_code)]`
  to `snapshot.flow_export` so the build stays warning-clean after the consumer
  is removed.
- **Out of scope / follow-up (file as a concrete issue before merge):** true
  per-flow-server version binding + double-export de-dup (#2129 part 2).
