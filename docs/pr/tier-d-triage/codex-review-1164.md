# Codex hostile PLAN review — Tier D issue #1164

Source rollout: `rollout-2026-05-04T23-21-22-019df6cc-6075-7693-bb68-e5fc4235f5c1.jsonl`

---

**Verdict: PLAN-NEEDS-MAJOR**

Reject the triage’s current #1164 rationale. It correctly shows “not per-packet,” but it overreaches by saying the issue premise is wrong and “startup-only.”

Findings:

- The cited surface still exists: `ConfigSnapshot`, `InterfaceSnapshot`, `String`/`Vec` fields, Go/Rust JSON control protocol, and `apply_snapshot` are all present on `master`.
- It is not on the packet hot path. JSON encode/decode is in Go `requestDetailedLocked()` and Rust server request handling; snapshots are published from `Compile()` and `syncSnapshotLocked()` on the 1 Hz status loop, not from `poll_binding_process_descriptor`.
- But the issue’s control-plane claim holds up. `docs/snapshot-publish-redesign.md` explicitly describes the userspace control socket as a serialized bottleneck, full snapshot JSON publishes blocking session installs, and 50 ms-class snapshot publishes during route convergence. That directly contradicts “premise is wrong.”
- The prescribed mitigation has mostly already shipped, but not as `session_delta.rs`: content-hash snapshot dedup, lightweight `bump_fib_generation`, `update_neighbors`, a dedicated session socket with `sessionMu`, and binary session event stream are all present.
- “Startup snapshot” is too narrow. Full JSON snapshots still happen on config compile/startup/replan paths; FIB churn has been moved to lighter update paths.

The triage can probably still land as “no new refactor justified absent fresh measurements; prior control-plane fixes already addressed the dangerous case,” but it must stop claiming #1164 was a bogus hot-path/per-packet issue. That is a major rewrite, not a minor wording fix.
