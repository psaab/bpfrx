# Triage result — ps-review-039-a1a

- **Subsystem:** RUST-HOT — per-packet orchestrator (`poll_descriptor/mod.rs` +
  `poll_stages.rs`) + cold-path siblings (`reject_reply.rs`, `filter.rs`)
- **Review base:** f70146951583823a5ace87b0b11a2e58f46e8db9 (2026-07-07)
- **Triaged against master:** 95b33d49634d56086269a62a92e213dae7926f88
  — base IS a direct ancestor of master (23 commits behind); no divergence,
  every cited line is stable modulo ~+11-line drift from later edits.
- **Repo:** real bpfrx (paths are `userspace-dp/src/afxdp/...`; zero `avacado`
  references in the review; base commit is in bpfrx history).
- **Review class:** refactor / modularity audit (file-size + decomposition
  seams). This is NOT a correctness-bug review — no finding asserts an
  input→wrong-output defect on current master.

## Outcome counts
- DUP: 1 (Finding 1 — self-admitted dup of OPEN #4404)
- NOT-MATERIAL / negative-result: 2 (Findings 2, 3 — explicit DO-NOT-SPLIT)
- GENUINE-RESIDUAL: 0
- CONFABULATED / ALREADY-FIXED-correctness: 0

## Symbol-existence proof (all present on master)
| Cited artifact | Master status |
|---|---|
| `poll_descriptor/mod.rs` | EXISTS, 6053 LOC (review said 6042 @ base — +11 drift) |
| `poll_binding_process_descriptor` | EXISTS, `pub(super) fn` @ mod.rs:603 |
| `poll_stages.rs` | EXISTS, 3527 LOC (identical) |
| `reject_reply.rs` | EXISTS, 2174 LOC (identical) |
| `filter.rs` | EXISTS, 1201 LOC (identical) |
| `flow_cache_hit.rs` / `stage_flow_cache_hit` | EXISTS, 533 LOC, fn present |
| `debug_log_throttle.rs` / `session_miss_debug_log_allowed` | EXISTS (already extracted — matches "#4404 inc1 done") |
| `flowless_local_delivery_verdict`, `flowless_base_resolution`, `host_inbound_gated_lo0_action`, `junos_host_local_policy`, `junos_host_policy_eval`, `filter_terminal`, `evaluate_non_pbr_input_filter`, `enqueue_reject_reply`, `stage_screen_check`, `stage_link_layer_classify`, `ipsec_passthrough_decision` | ALL present |
| `DBG SESS_MISS` eprintln inside session-miss | present @ mod.rs:2006-2057 (review said ~2004 @ base) |
| recycle sites in fn body | 34 `scratch_recycle.push` + 3 `RecycleAndContinue` (review counted 34 + 5 @ base; count-window drift, invariant claim intact) |

## Per-finding disposition

### Finding 1 — `poll_binding_process_descriptor` god-function (4724 LOC) → **DUP**
- **Why DUP:** The finding self-admits it: "#4404 filed poll_descriptor/mod.rs
  god-function ... this finding should merge as its hot-path-preservation
  annex." Verified **#4404 is OPEN** on GitHub: *"refactor: poll_descriptor/mod.rs
  (5,759 LOC) — decompose the poll_binding_process_descriptor god-function
  (1,368 LOC, 15+ responsibilities) (ps-review-010 R1)"*. Same file, same
  function, same decomposition intent. The new material here (4724-LOC
  re-measurement of the full 603..~5326 span vs #4404's 1,368; the 39
  recycle-site / 11 mutable-local / 3× Junos-order-duplication seam analysis;
  the ordered A/C/B PR ladder) is a **refinement of #4404's decomposition
  plan**, not a new defect. It belongs as a comment/annex on #4404.
- **Not a correctness residual:** Severity is stated as "Critical
  (maintainability, build-cost, review-cost)" — a refactor-cost severity, not
  an exploitable/wrong-output severity. Refactor class (B) REQUIRES GUARDRAILS.
  The past-bug references it cites (#3485 host-inbound-before-lo0, #3292/#3064
  flowless fail-open, #2145 priority-tagged VID-0, #3022 VLAN logical-ifindex)
  are cited as **already-guarded historical regressions the refactor must not
  reintroduce** — none is claimed broken on master, and the guarding symbols
  (`host_inbound_gated_lo0_action`, `flowless_local_delivery_verdict`,
  `stage_screen_check`) are all present. No live defect.
- **Disposition:** DUP of OPEN #4404. No new issue warranted; fold measurements
  into #4404 if that refactor is ever scheduled.

### Finding 2 — `poll_stages.rs` production is cohesive → **NOT-MATERIAL (negative result)**
- **Why not material:** This is an explicit **(D) DO-NOT-SPLIT** negative
  result — Severity Low / informational. It recommends NO change to production
  code and warns against re-splitting `stage_screen_check` (304 LOC) because
  that would duplicate the zone-resolve / `l3_off` priority-tag logic that
  previously caused #2145 / #3022. It proposes only an *optional* test-module
  split "when file exceeds 4000 LOC" (currently 3527) — i.e. no action due now.
- **Verification:** All named production stage fns exist and the module is the
  #946-Phase-1 extraction as described. There is no defect to file; filing an
  issue that says "do nothing" would be noise. Record as reviewed / no-action.
- **Disposition:** NOT-MATERIAL — informational confirmation, no defect, no
  actionable change on master.

### Finding 3 — `reject_reply.rs` + `filter.rs` correctly extracted → **NOT-MATERIAL (negative result)**
- **Why not material:** Same as Finding 2 — explicit **(D) DO-NOT-SPLIT**,
  Severity Low / informational. It affirms the #1697 (filter cold-path) and
  #2089 (reject-reply synthesis) extractions are sound and warns that further
  splitting would fragment the reject 5-stage pipeline (H11/H12 feasibility-
  before-consume ordering, #3656) and the `host_inbound_gated_lo0_action`
  Junos order (#3485). All cited functions/attributes (`#[cold]
  #[inline(never)]` entry points, per-function inline policy header) exist on
  master. Only *optional* test relocation is suggested for a future size
  threshold (files currently 2174 / 1201 LOC, thresholds 2500 / 1500).
- **Disposition:** NOT-MATERIAL — informational confirmation of a good pattern,
  no defect, no actionable change on master.

## Bottom line
Zero genuine residuals. This batch is one self-admitted DUP of the already-open
refactor tracker #4404 plus two DO-NOT-SPLIT negative results. Consistent with
the ps-039/040 expectation: this hot path is well-hardened and the audit surface
here is maintainability-only, not correctness. If anyone acts on it, the only
move is appending the new decomposition measurements to #4404 — no new issue.
