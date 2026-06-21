# Claude SMR — hostile plan review r2 (#2129 + #2130)

Posture: HOSTILE confirmation pass on r2 (`a1e2a4949`). r1 verdict was
PLAN-CHANGES-REQUIRED (all three reviewers, same blocking finding). I re-checked
every folded change against source.

## r1 findings — resolution check

- **F1 (partial-fix framing) — RESOLVED.** §3 now states #2129 has two harms and
  this PR fixes only harm (1) (unrequested v9 for IPFIX-only); §8 requires the
  double-export de-dup follow-up to be filed as a concrete issue before merge;
  §9 summary echoes "PARTIAL fix." No longer implies #2129 fully resolved.

- **BLOCKING (test blast radius, raised by both hostile reviewers) — RESOLVED.**
  §6 now enumerates all 9 in-scope test edits with verified line numbers:
  - `pkg/flowexport/exporter_test.go` BuildExportConfig(nil, fo) at :30/:166/:198
    — I confirmed all three pass `nil` svc and assert non-nil (would hit
    `t.Fatal` after the guard). Prescribed fix (pass non-nil svc with Version9)
    is correct and orthogonal to what those tests assert (source-address).
  - `pkg/daemon/daemon_flowexport_reconcile_test.go` — I confirmed the base
    `flowSamplingConfig` (lines 19-35) sets NO `Services.FlowMonitoring`; only
    `ipfixSamplingConfig` (:40-50) adds `VersionIPFIX`. The 6 driving tests
    (:66/:92/:119/:177/:220/:254) assert the v9 exporter starts. The one-edit
    fix (add `Version9` to `flowSamplingConfig` + `flowSamplingConfigSrc`) is
    correct. r2 also flags `TestReconcileFlowExporterNoCallbackLeak` (:155) to
    re-check after the helper edit. Accurate.
  - New positive/negative cases prescribed (no-version9 → nil; IPFIX-only starts
    IPFIX but NOT v9 — the #2129 regression guard).

- **F3/grep gate — RESOLVED.** §7 has the explicit
  `grep -rn 'FlowExporter\|FlowExportConfig\|crate::flowexport\|mod flowexport\|flow_export_config'`
  gate.

- **dead_code warning (5.2-keep, raised by reviewer B) — RESOLVED.** §5.2 adds
  `#[allow(dead_code)]` on `snapshot.flow_export` (protocol/snapshot.rs:259) with
  the gre_acceleration/power_mode_disable precedent, and correctly notes no
  `-D warnings` in the Makefile so the build is warning-not-error. I confirmed
  the Makefile `build-userspace-dp` target carries no `RUSTFLAGS=-D warnings`.

- **NITs (line counts, base-commit count) — RESOLVED.** §5.2 now says 352 + 137;
  the header says two commits between the SHAs.

## Independent re-verification of r2's new content

- v9 config type names in r2's test guidance: `NetFlowV9Config` (types_system.go:651),
  `NetFlowV9Template` (:656), `FlowMonitoringConfig.Version9 *NetFlowV9Config`
  (:632) — all exist. No invented symbol.
- No new error introduced. The plan does not touch production code (research
  mode); all citations check out.

## Verdict reasoning

Every r1 finding is folded and verified against source. Diagnosis was already
correct; the only gap (test scope) is now fully enumerated. The plan is a
faithful, implementable spec: gate v9 on Version9 (mirror IPFIX), fix the 9
encoded-buggy tests, remove the dead Rust executable path + allow-dead the
reserved wire field, document both READMEs, defer + file the double-export
de-dup. Nothing left that would derail /engineer.

VERDICT: PLAN-READY
