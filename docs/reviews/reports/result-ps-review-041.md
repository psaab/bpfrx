# Triage result — ps-review-041 (HFT Refactor / Modularity audit of the Rust AF_XDP hot path + Go compilers)

## Header / provenance
- **Review:** ps-review-041 — Refactor/Modularity audit (poll_descriptor, cos/queue_service+waterfill, SessionTable, policy.rs, screen/frame, nat, plus Go daemon/cluster/routing/metrics/api/config).
- **Base commit:** `95b33d49` — a REAL bpfrx commit (shared history). **Triaged against current `origin/master` = `0b5e9cb4c`** (advanced substantially from base; several cited files changed size).
- **Fork tell:** run in `/home/ps/git/avacado-xpf` (`git rev-parse --show-toplevel`), worktrees `/tmp/review-wt-ps-041-*`. Every cited Rust/Go file/symbol was re-verified against bpfrx `origin/master` — **all cited files DO exist on bpfrx master** (no confabulation found; this fork shares history).
- **Final-file truncation:** `/tmp/ps-review-041.md` is a 36-line stub (header + dedup summary, cuts off at "## File-size / shape inventory"). All findings were read from the 10 batch files `ps-a1a..a1g,a2,a3,a4` in `/tmp/review-work-ps-041/`.
- **Outcome counts:** CONFABULATED 0 · ALREADY-TRACKED (dedup list / #2158 / #4406) ~majority · NOT-MATERIAL (under the ~2000-LOC bar / hot-path deliberate / DRY-nit) ~large tail · **GENUINE-NOVEL filed: 2 (#4845, #4846)**.

## NEW issues filed
- **#4845** — `pkg/config/compiler_validate_warn.go` 3,600 LOC warn-validator monolith → split per-domain (mirror the #4405 strict split). Over the ~3,000-LOC "must split" line; not named in any existing issue.
- **#4846** — `pkg/config/compiler_nat.go` 2,565 LOC tri-fused NAT compiler (helpers + 5 strict validators + per-family compile) → split by concern + relocate strict validators into the existing `compiler_validate_strict_nat.go`. Over 2,000; not named in any existing issue.

---

## Per-finding disposition

### ps-a1a-b1 — poll_descriptor/mod.rs (mod.rs 6,053 LOC; `poll_binding_process_descriptor` ~4,724 LOC)
- **H1 SlowPathCtx muts, H2 34-recycle invariant, M1 Junos-order triplication, M2 debug-log icache, L1 tri-split state machine, L2 PBR override dup** — ALL are decomposition angles of the **same** `poll_binding_process_descriptor` god-function. **ALREADY-TRACKED → #4404** (poll_descriptor/mod.rs god-function; now CLOSED but explicitly on the task dedup list — do not re-file). The reviewer itself marks each "Extends #4404". No novel file here.

### ps-a1b-b1 — TX path
- **H-1 cos_classify.rs (1,335 LOC, 7 responsibilities)** — NOT-MATERIAL: 1,335 < 2,000 prod-LOC bar. Real 7-way mix but under threshold; the reviewer's own split is a "reduce onboarding cost" argument, not a monolith crossing.
- **H-2 tx/tcp_segmentation.rs (309 LOC single fn)** — ALREADY-TRACKED/NOT-MATERIAL: dedup to **#4652** (segment-fn-by-phase, CLOSED). 309-LOC file is under bar; #[cold] single fn — split concept already tracked.
- **H-3 dispatch/mod.rs (1,486 LOC, fabric scatter + direct-TX)** — ALREADY-TRACKED → **#4408** (`enqueue_pending_forwards`). Reviewer explicitly scopes it as "remaining after #4408 inc1".
- **M-1 drain/mod.rs 594, M-2 rings.rs 415, M-3 transmit/mod.rs 365** — NOT-MATERIAL: all far under the 2,000 bar (594/415/365). "300-LOC target" is the reviewer's stricter aspiration, not project discipline.
- **M-4 dispatch test-only thread-locals in prod files (~40 LOC), L-1 CoS const location, L-2 orphan-accounting DRY** — NOT-MATERIAL: Class C nits, no monolith.

### ps-a1c-b1 — CoS TX drain
- **F1 waterfill 432-LOC god-fn** — ALREADY-TRACKED → **#4408** (names `cos/queue_service waterfill`).
- **F2 queue_service/mod.rs 2,057 LOC module** — ALREADY-TRACKED: on the **#2158** watch-list (title: "+queue_service … watch-list", with suggested `build.rs`/`guarantee.rs`/`surplus.rs` decomposition) AND its headline waterfill is #4408. Crossed 2,000 since #2158 (was 1,880) but is a named tracked file — not re-filed to avoid a duplicate.
- **F3 CoSInterfaceRuntime 28-field struct (types/cos.rs)** & **F4 tx_completion.rs 1,080** — NOT-MATERIAL: `cos/tx_completion.rs` is 1,080 (<2,000); `types/cos.rs` is 1,786 (<2,000, see a1g F3). Under bar.

### ps-a1d-b1 — session
- **F1 SessionTable god-struct** — ALREADY-TRACKED → **#4421** (body: "SessionTable god-struct (27 fields, 6 responsibilities)"). Reviewer marks "Extends #4421".
- **F2 SessionEntry/SessionMetadata Arc clone** — NOT-MATERIAL (for this audit): a per-packet **perf** micro-opt (remove `Arc<PolicyRuleCounter>` clone), not a modularity monolith; entry.rs is 284 LOC. Also #4421 lists "SessionEntry hot/cold fusion — eliminate the Arc metadata.clone()".
- **F3 session_glue/mod.rs 1,277 LOC** — NOT-MATERIAL: 1,277 < 2,000; the first split was #1346, remaining file is under bar.

### ps-a1e-b1 — forwarding / neighbor / worker
- **F1 ForwardingState 66-field god-struct** — ALREADY-TRACKED → **#4421** ("ForwardingState god-struct (55 fields) — split hot FIB from cold config").
- **F2 forwarding/mod.rs 2,795 LOC, 80 fns, 3× ~190-LOC god-fns** — over 2,000 and genuinely large, BUT ALREADY-TRACKED: **#2158** title explicitly watch-lists "forwarding" (was 1,761 there) with a suggested decomposition; the *module* has now crossed the 2,000 bar (2,795, small inline tests only). Named-with-decomposition in an existing (closed) tracker → not re-filed to avoid duplicating #2158. **Flagged: this graduated from the #2158 watch-list and now hard-exceeds the threshold — belongs re-actioned under #2158.**
- **F3 neighbor.rs 2,036 LOC, 4 responsibilities** — ALREADY-TRACKED → **#4421** ("neighbor.rs (1901 LOC) — split by concern").
- **F4 worker/loop_body INLINE invariant** — DELIBERATE: reviewer's own recommendation is "do NOT further split" — the per-tick loop stays inline (Codex r1-4 guard, 10K–100K ticks/s). D-negative, nothing to file.

### ps-a1f-b1 — screen / frame / policy
- **F1 inspect.rs IPv6 EH-walker 5× duplication** — NOT-MATERIAL (as modularity): a DRY/SSOT follow-up to #4517 (values) / #2150 (dup), not a >2,000 file split; inspect.rs is 1,813 LOC. Consolidation is a correctness-maintainability nit, already value-fixed in #4517.
- **F2 screen/mod.rs god-fn + 22-field ScreenState** & **F6 SYN-flood cold config** — NOT-MATERIAL: screen/mod.rs 1,540 < 2,000. `check_packet_with_zone_id_opts` (331 LOC) is a real long fn but a cohesive per-packet screen verdict pipeline (5 SYN-flood phases kept inline by design); under the file bar.
- **F3 frame/mod.rs 6-resp kitchen sink** — NOT-MATERIAL: 1,710 < 2,000; continuation of the prior #988/#1352/#1440 wave, under bar.
- **F4 AppCatalog zero-coupling, F5 policy.rs counters/eval split** — ALREADY-TRACKED → **#4421** ("policy.rs too broad — split into submodules"). Reviewer states "this IS #4421 … implementation plan".

### ps-a1g-b1 — misc large files
- **F1 wg_control.rs 2,280→1,579** — NOT-MATERIAL on current master: the reviewer measured 2,280 at base `95b33d49`; on `0b5e9cb4c` it is **1,579 LOC** (already split/reduced). Under bar.
- **F2 server/helpers.rs 1,304, F3 types/cos.rs 1,786, F4 event_stream/mod.rs 1,693** — NOT-MATERIAL: all under 2,000. (event_stream/*mod.rs* is distinct from event_stream/codec.rs = #4651 CLOSED.)
- **D-negatives (engine.rs, cookie.rs, forwarding.rs, binding.rs, event_emit.rs, lease.rs, cold_path_hist.rs)** — DELIBERATE: reviewer justifies each keep (crypto invariant / fail-closed secret / wire-compat DTO / MaybeUninit safety / atomic-ordering coupling). `codec.rs` → #4651. Nothing to file.

### ps-a2-b1 — NAT (Rust + Go)
- **F1 PortAllocator god-struct (nat/allocator.rs), F2 match_source_nat_result_for_tuple god-fn (nat/source.rs)** — ALREADY-TRACKED → **#4409** ("nat/allocator.rs PortAllocator god-struct + nat/source.rs"). Reviewer marks both "#4409 filed".
- **F3 config/compiler_nat.go + dataplane/compiler_nat.go tri-fused** — **GENUINE-NOVEL (Go config side) → filed #4846.** `pkg/config/compiler_nat.go` = 2,565 LOC on master, over threshold, in no existing issue, strict-validator home (`compiler_validate_strict_nat.go`) already exists. (`pkg/dataplane/compiler_nat.go` is 1,258 < 2,000 — under bar, not part of the filed split.)

### ps-a3-b1 — Go config compilers
- **F1 compiler_validate_warn.go 3,600 LOC** — **GENUINE-NOVEL → filed #4845.** Over the ~3,000 "must split" line; strict side already split (#4405 CLOSED); no existing issue names it.
- **F4 compiler_nat.go 2,565** — **GENUINE-NOVEL → filed #4846** (same as a2 F3).
- **F2 compiler_system.go 1,888, F3 compiler_services.go 1,821, F5 compiler_interfaces.go 1,279, F7 types_system.go 1,553** — NOT-MATERIAL: all under 2,000 on current master.
- **F6 compiler_validate_strict_filter.go 1,660** — DELIBERATE/ALREADY-TRACKED → **#4406** dedup note flags it as an already-per-domain-split result (do-not-re-split, Class D).
- **F8 compiler.go 2,110** — ALREADY-FIXED: **#4406** (CLOSED) already decomposed `compiler.go` 4,336→2,110; the remainder is the orchestrator/dispatch hub (a2's own D-negative agrees orchestrator pattern is fine). Not a monolith.

### ps-a4-b1 — Go dataplane/daemon/cluster/routing/metrics/api
- **A4-01 compiler_validate_warn.go** — → filed **#4845** (dup of a3 F1).
- **A4-02 protocol.go 3,064 LOC 78-type wire monolith** — ALREADY-TRACKED → **#4839** (prior-watcher just-filed; on the task dedup list).
- **A4-03 metrics_descriptors.go 2,013 LOC / 279 NewDesc** — NOT-MATERIAL (borderline): just crossed 2,000 (2,013), and it is a single **declarative** descriptor factory (one cohesive concern: "all Prometheus descriptors"), not a god-function with unrelated algorithmic responsibilities. Held below the file-a-new-issue bar per the audit's "do not manufacture" steer; flagged as first-to-watch if it grows.
- **A4-04 sync_conn.go 1,858, A4-05 tunnel.go 1,889, A4-07 policy_render.go 1,938** — NOT-MATERIAL: all under 2,000 on current master (close, but under). sync_conn/tunnel are also Class-B ordering-sensitive where a premature split adds risk without crossing the size bar.
- **A4-06 daemon_apply.go `applyConfigLocked` 1,148-LOC god-fn** — ALREADY-TRACKED → **#4407** (task dedup list: "daemon.go god-struct + applyConfigLocked (1,148 LOC)").
- **D-negatives (maps_sync.go, vrrp/instance.go, daemon god-struct #4407, daemon_run.go #4662, format/buffers.go #4661, flowexport/rules.go/Surface-A #4421)** — DELIBERATE / ALREADY-TRACKED as the reviewer notes.

---

## Confabulation check
Zero confabulated symbols. Spot-verified on `origin/master 0b5e9cb4c`: all cited files exist with the claimed shapes; the only material drift is size (base `95b33d49` vs now): `wg_control.rs` 2,280→1,579 (already reduced), `forwarding/mod.rs` 1,761(#2158)→2,795 (grew), `compiler_validate_warn.go` 3,330→3,600 (grew), `compiler_nat.go` 2,529→2,565. Line numbers in the two filed issues were re-pinned against current master.

## Bottom line
Two genuine, novel, >2,000-LOC Go config-compiler monoliths were filed (#4845, #4846). Everything else in this large audit dedups to the existing trackers (#4404/#4406/#4407/#4408/#4409/#4421/#4839/#4651/#4652/#4661/#4662 and the #2158 ~2,000-LOC watch-list) or sits under the project's ~2,000 prod-LOC modularity bar / is a deliberate hot-path-inline guard. Note surfaced (not re-filed): `forwarding/mod.rs` (2,795) has graduated from the #2158 watch-list and now hard-exceeds threshold.
