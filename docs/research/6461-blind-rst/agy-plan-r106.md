# AGY hostile plan-review — round 106 (v10.23.0)

Reviewer: AGY (direct binary). Verdict: SOUND — report transport chain, normalization point, consumer set, preimage threading all verified.

## Verbatim review

SOUND

### Staff Engineer Design-Document Consistency Review: `#6461` (v10.23.0)

**Workspace:** `/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst`  
**Commit:** `f729eef1dc35`  
**Document:** `docs/research/6461-blind-rst/plan.md` (v10.23.0 — The Terminal Cut)

---

### Executive Summary & Verification Findings

The v10.23.0 plan incorporates the round-106 folds into a cohesive, mechanically enforceable design for the Part-A dataplane demote gate and wire-free local HA rules. All code citations, line ranges, call chains, and data structures specified in the plan have been verified against the repository codebase.

Below is the itemized review corresponding to your checklist:

---

### 1. Checklist Verification

#### (a) Report Transport Chain
* **Producer:** `materialize_shared_session_hit` ([`userspace-dp/src/afxdp/session_glue/mod.rs:1092-1121`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1092-L1121)) returns `(SessionLookup, MaterializeReport)`.
* **Report Structure:** `MaterializeReport { site: Option<MaterializeSite>, validation: Option<CloseValidation>, transition: TransitionResult, displaced: DisplacedSet }`.
  * `site` is `Some(Site2c)` for the site-2c reactive materialize, and `None` for non-materializing lookup hits (local hit, shared-forward-wire hit).
  * `site 2b` (reverse-NAT companion synthesizer) is explicitly outside `MaterializeReport` and communicates outcome via `(resolved, reverse_installed)` ([`session_glue/mod.rs:1264-1284`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1264-L1284)).
* **Carriage:** `resolve_flow_session_decision` ([`session_glue/mod.rs:1143-1261`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1143-L1261)) embeds `report` into `ResolvedFlowSessionDecision` ([`userspace-dp/src/session/shared_ops.rs:563-578`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/shared_ops.rs#L563-L578)).
* **Poller Ingestion:** `poll_descriptor_process_descriptor` ([`userspace-dp/src/afxdp/poll_descriptor/mod.rs:509`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L509)) extracts `resolved.report` at the `install_failed` hoist and attaches it to the per-descriptor dispatch context prior to reducing `resolved.decision` at line 883.

#### (b) Producer-Side Normalization & Materialize/Promote Ordering
* **Call Sequence:** In `resolve_flow_session_decision` ([`session_glue/mod.rs:1194-1253`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1194-L1253)):
  1. Line 1197: `materialize_shared_session_hit` executes first. It normalizes any out-of-product report tuple to `(site preserved, validation preserved, transition := OverdueSkipped)` before returning.
  2. Lines 1238–1252: `maybe_promote_synced_session` is called downstream of materialization.
* **Effectiveness:** Because normalization is enforced AT the producer inside `materialize_shared_session_hit` (line 1197), any invalid state is converted to `OverdueSkipped` *prior* to evaluating or running promotion. `OverdueSkipped` suppresses promotion, making the out-of-product fail-closed invariant mechanically unavoidable.

#### (c) Consumer Set & Composition
* **5 Normative Consumers (§5.8):**
  1. *Terminal Teardown* ([`poll_descriptor/mod.rs:698-714, :768-784, :824-840`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L698-L714)): Skipped for `OverdueSkipped` and `UpsertRefused`.
  2. *Anchor Commit Hook:* Suppressed for `OverdueSkipped`, `UpsertRefused`, or `Refused` close validation.
  3. *Flow-Cache Insert* ([`poll_descriptor/mod.rs:3900-3959`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L3900-L3959)): Suppressed on `OverdueSkipped` or `UpsertRefused`.
  4. *Probation Clear+Refresh:* Gated out on `OverdueSkipped`.
  5. *Ownership Promotion:* Guarded by `probation=true` on $K$ and suppressed on `OverdueSkipped`.
* **MissingNeighbor Composition:** An `OverdueSkipped` or `UpsertRefused` outcome with a `MissingNeighbor` disposition routes to the live-backed `ExistingResolved` buffer-only arm, bypassing the common seed-install block ([`poll_descriptor/mod.rs:4662-4829`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4662-L4829)).

#### (d) Preimage Capture & Threading Chain
* **Capture Site:** Inside `update_session` ([`userspace-dp/src/session/mod.rs:1344-1348, :1393-1396`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1344-L1348)), the pre-overwrite state (`old_origin`, `old_nat`, `old_is_reverse`, `old_owner_rg`) is captured into an OUT parameter (`displaced_preimage`).
* **Threading Path:**
  * `promote_synced_with_origin` ([`session/mod.rs:1673-1675`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1673-L1675)) passes the OUT parameter up to `maybe_promote_synced_session` ([`userspace-dp/src/afxdp/session_glue/promote.rs:99-140`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs#L99-L140)).
  * `maybe_promote_synced_session` merges the captured preimage into `report.displaced`.
* **Uniqueness Proof Precision:** Promotion CAN modify NAT and orientation via `update_session` reindexing ([`session/mod.rs:1373-1381`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1373-L1381)). The proof correctly states that $K$'s pre-image family and the resulting $S_2$ family are two distinct members of the bounded $\le 3$-family set:
  $$\text{DisplacedSet} \subseteq \{P \text{ (shadowed placeholder)}, K \text{ (pre-image)}, S_2 \text{ (new/adopted entry)}\}$$

#### (e) Surviving Surface Analysis
* **Sibling Fan-Out Location:** Invalidation fan-out across sibling bindings is correctly specified at the `poll_binding` loop level over `left + right` ([`userspace-dp/src/afxdp/worker/lifecycle.rs:53-55, :209-225`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/lifecycle.rs#L53-L55)), executing once per batch before the next RX poll, and avoiding the reap routine ([`worker/loop_body/mod.rs:1481-1521`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs#L1481-L1521)).
* **Purge Path Parity:** The transient-purge class remains master-identical in dispatch. The demote gate's sole delta on this path is refusing the closing mark on anchorless peer-synced entries during pre-purge lookup ([`session_glue/mod.rs:1157-1196`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1157-L1196)), leaving the companion on its ordinary peer-synced trajectory.

#### (f) Full-Document Consistency Sweep
* All sections (1–11) in `plan.md` are aligned with the v10.23.0 terminal cut. No dangling references to excised machinery (such as fence ledgers, floor sync, or incarnation tokens) remain in the active architecture sections.

---

### 2. Specific Line-Trace Verification Table

| Location in `plan.md` | Cited Path & Line Range | Codebase Reality & Status |
| :--- | :--- | :--- |
| **§3.1, §5.8** | `session_glue/mod.rs:1092-1121` | `materialize_shared_session_hit` function definition; confirmed. |
| **§3.1, §5.8** | `session_glue/mod.rs:1235-1253` | Promotion block in `resolve_flow_session_decision`; confirmed. |
| **§3.1, §5.8** | `session/mod.rs:1344-1348, :1393-1396` | `update_session` entry snapshot and update; confirmed. |
| **§3.1, §5.8** | `session/mod.rs:1673-1675` | `promote_synced_with_origin` wrapper; confirmed. |
| **§3.1, §5.8** | `session_glue/promote.rs:99-140` | `maybe_promote_synced_session` publish/replicate execution; confirmed. |
| **§3.1, §5.6** | `worker/lifecycle.rs:53-55, :209-225` | `poll_binding` batch-level sibling split and process dispatch; confirmed. |
| **§3.1, §5.8** | `poll_descriptor/mod.rs:509, :883` | Hoist site for `install_failed`/report and decision reduction; confirmed. |

---

### 3. Conclusion & Recommendation

The design document `docs/research/6461-blind-rst/plan.md` (v10.23.0) is **SOUND**. It is ready for manual approval via `/engineer 6461`.
