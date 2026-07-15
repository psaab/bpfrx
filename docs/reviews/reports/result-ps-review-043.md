# Triage result: ps-review-043 (refactor / modularity audit — hot-path-preserving)

**Type:** REFACTOR/modularity audit (not security). Base 4e0c7f74c -> verified against CURRENT origin/master cd1dea6ab.
**Signal note:** refactor audits are low-priority (band 3) and the refactor backlog is largely stale; the review's own dedup maps the major monoliths to existing issues.

## Gate outcome
- **1 NEW material finding filed:** forwarding/mod.rs (2795 prod LOC, 80 fns, 5 fused god-fns) — F-A1e-02. Distinct from #4421 (which covers the ForwardingState STRUCT, not the file). In the >2000 smell band, trending up. Filed as a hot-path-preserving refactor (disasm-diff + smoke-gated, /triple-review).
- **ALREADY FILED (not re-filed, per report dedup + my check):** poll_descriptor 4796-LOC god-fn -> #4404; Daemon god-struct -> #4407; tx/dispatch + cos/queue_service waterfill -> #4408; NAT allocator/source -> #4409; ForwardingState god-struct (now 66 fields), policy.rs, nat64.rs, neighbor.rs (2036), SnapshotIntegrityError, SessionTable (session/mod.rs 2114), flowexport, firewall-filter, rules.go -> #4421 (broad refactor-backlog umbrella); event_stream/mod.rs -> #4651; tcp_segmentation -> #4652; format/buffers.go -> #4661; daemon_run.go Run() -> #4662; test-only splits -> #4663-#4670.
- **WITHIN modularity discipline (NOT material, sub-2000 prod LOC):** frame/inspect.rs (1960), wg/engine.rs (1805), types/cos.rs (1786), frame/mod.rs (1772), shared_cos_lease/lease.rs (1460), nat/source.rs (1523, also #4409), session_glue (1277). The project threshold is 2000 prod LOC (docs/engineering-style.md); these are under it.
- **DELIBERATE (not refactor targets):** worker/loop_body/mod.rs (1784, intentionally inline per #1776); worker/mod.rs (1631, already #959-decomposed into 11 submods); forwarding_build/ (8 files, already #1342-decomposed).

## Note
Refactor findings only; no bugs. The single new file (forwarding/mod.rs) is a smell-band (not mandatory >3000) monolith — driveable via /triple-review with hot-path preservation, low priority relative to the security/correctness backlog.
