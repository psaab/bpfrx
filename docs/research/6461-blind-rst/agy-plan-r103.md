# AGY hostile plan-review — round 103 (v10.20.0)

Reviewer: AGY (direct binary). Verdict: UNSOUND with two precise findings: (1) §5.6 :1445-1446 kept the pre-r103 EMPTY-set phrasing (contradicting the shadowed-placeholder carriage); (2) §5.8 bullet (i) omitted UpsertRefused from the explicit teardown-skip enumeration. Everything else verified sound, including the inline-carrier/batch-accumulator split against the binding/batch ownership, the six-variant outcome semantics, and the refusal consumer walk. Folded in v10.20.1.

## Verbatim review

UNSOUND

### Design-Document Consistency Review: `#6461` (plan.md v10.20.0, Round-103 Folds)

---

### Numbered Findings

1. **`docs/research/6461-blind-rst/plan.md:1445-1446` vs `plan.md:1757-1759`, `:2345-2347` — Internal Contradiction in Section 5.6 on `OverdueSkipped` Displaced-Set Carriage**
   - **Trace:** In Section 5.6 (`plan.md:1445-1446`), the text states:
     > `PLUS any shadowed placeholder's key family (a refusal or an OverdueSkipped transition carries the EMPTY set — nothing was displaced).`
   - **Defect:** This directly contradicts the Round-103 Fold 3 fold definition, the Section 5.8 SSOT (`plan.md:1757-1759`), Section 9 (`plan.md:2345-2347`), and Section 9 test (x) (`plan.md:2367`), which all specify that `OverdueSkipped` carries the shadowed placeholder's key family when a lookup shadows a fabric placeholder, and is *only* empty when no shadowed placeholder exists. Section 5.6 (`:1445-1446`) was left as an un-updated pre-round-103 straggler.

2. **`docs/research/6461-blind-rst/plan.md:1724` vs `plan.md:1699` — Incomplete Consumer Enumeration in Section 5.8**
   - **Trace:** In Section 5.8 under *"Consumers (all five, normative)"* (`plan.md:1723-1725`), bullet (i) states:
     > `(i) the terminal teardown at ALL THREE sites (poll_descriptor/mod.rs:698-714, :768-784, :824-840) is SKIPPED for OverdueSkipped...`
   - **Defect:** While line 1699 explicitly specifies that `UpsertRefused` gates the *same* authority consumers as `OverdueSkipped` (teardown, cache, commit), bullet (i) at line 1724 omits `UpsertRefused` from its explicit enumeration of outcomes that skip terminal teardown. Bullet (i) must list both `OverdueSkipped` and `UpsertRefused` to maintain internal normative completeness.

---

### Checklist & Fold Verification Walkthrough

#### (a) Verification of Round-103 Folds Against the Codebase

1. **Inline Carrier & Batch Accumulator (`DisplacedSet` / `WorkerScratch`):**
   - Verified `userspace-dp/src/afxdp/session_glue/mod.rs:1254-1261` and `:1330-1344`: `ResolvedFlowSessionDecision` is constructed at exactly these two sites in `resolve_flow_session_decision`. Placing `displaced: DisplacedSet` (inline array, $\le 3$ families, zero allocation) on `ResolvedFlowSessionDecision` initialized empty at both constructors allows value-passing through resolution without heap allocation or `WorkerScratch` reference-lifetime issues.
   - Verified `userspace-dp/src/afxdp/worker/scratch.rs:19-32` and `userspace-dp/src/afxdp/mod.rs:278-281`: `WorkerScratch` is preallocated per binding, and `RX_BATCH_SIZE` is fixed at 64. A separate batch accumulator vector on `WorkerScratch` (capacity $3 \times 64$ descriptor slots) cleanly receives the union of inline sets across the batch.
   - Verified `userspace-dp/src/afxdp/worker/lifecycle.rs:53-55` and `:209-225`: `bindings.split_at_mut(binding_index)` exposes `left` and `right` sibling bindings, allowing `poll_binding` to run the once-per-batch sibling fan-out after descriptor processing completes for the batch.

2. **Six-Variant `MaterializeOutcome` & Refusal Semantics:**
   - Verified variants: `None`, `Installed`, `AdoptedPreservingDeadline`, `ValidatorRefused`, `UpsertRefused`, `OverdueSkipped`.
   - Verified `UpsertRefused` site at `userspace-dp/src/session/install.rs:310-315`: `if matches!(self.entry_by_key(&key), Some(existing) if !existing.origin.is_peer_synced()) && !allow_replace_local { return false; }`. Capacity refusal belongs to `install.rs:123-125` on the fresh `install_with_protocol_with_origin` path; `upsert_synced_with_origin` has no capacity check and refuses *only* non-peer predecessors.
   - Verified `ValidatorRefused` site at `session_glue/mod.rs:1092-1121`: Close validation refusal on a site-2c shared hit installs the copy alive (`closing=false, reset=false`, `probation=true`) at probation timeout.

3. **`OverdueSkipped` & Shadowed Placeholder Identity:**
   - Verified `userspace-dp/src/afxdp/shared_ops.rs:602-610` and `:614-626`: `is_fabric_wire_placeholder` checks if a local entry is a fabric wire placeholder and replaces it with a shared forward wire match (`lookup_shared_forward_wire_match`). When `OverdueSkipped` occurs on a lookup that shadowed such a placeholder, the shadowed placeholder's key family is placed into `displaced` so its stale cache aliases are invalidated.

4. **Section 9 Test Coverage & Parity Qualifications:**
   - Verified test plan structure (§9 lines 2343-2380): tests (vii)–(x) explicitly assert `ValidatorRefused` with canonical predecessor, `UpsertRefused` non-peer predecessor survival + consumer gating, upsert-refused promotion displacement, and `OverdueSkipped` with shadowed placeholder cache eviction.

---

#### (b) Consumer Set Walk for `ValidatorRefused` and `UpsertRefused`

Walking each authority consumer explicitly across table state and dispatch identity:

* **`UpsertRefused` (Non-Peer Predecessor Refusal):**
  - **Table State vs. Dispatch Identity:** `upsert_synced_with_origin` returns `false` (`install.rs:310-315`). The local table retains the non-peer predecessor under its own key/NAT $P_1$. `materialize_shared_session_hit` returns shared $S_2$'s decision ($P_2$) for **forwarding only**.
  - **Consumer 1 — Terminal Teardown (`poll_descriptor/mod.rs:698-714`, `:768-784`, `:824-840`):** **MUST BE SKIPPED.** If `delete_terminal_filtered_session` ran under $S_2$'s identity (`session_glue/mod.rs:477-581`), it would attempt to look up companions and remove table/BPF/shared state under $S_2$, which diverges from the stored $P_1$ entry, potentially deleting unrelated sessions or mis-clearing allocations.
  - **Consumer 2 — Anchor Commit Hook:** **MUST NOT WRITE.** The committed packet's sequence numbers belong to $S_2$, while the table entry is $P_1$. Writing $S_2$'s anchor to $P_1$ would pollute $P_1$'s anchor.
  - **Consumer 3 — Flow-Cache Insert (`:3900-3959`):** **MUST BE SUPPRESSED.** Caching $S_2$'s decision for a flow whose table entry is $P_1$ would bypass session resolution on subsequent packets and mask table divergence.
  - **Consumer 4 — Probation Clear/Refresh:** **NOT APPLICABLE / SUPPRESSED.** $P_1$ is a live non-peer entry, not a probation entry.
  - **Consumer 5 — Ownership Promote (`maybe_promote_synced_session`):** **MUST BE SUPPRESSED.** $P_1$ is non-peer (`!origin.is_peer_synced()`), so promotion cannot alter $P_1$.

* **`ValidatorRefused` (Site-2c Close Validation Refusal):**
  - **Table State vs. Dispatch Identity:** Site 2c installs an alive probation entry ($S_2$, `closing=false, reset=false`, `probation=true`) into `SessionTable`. If a canonical predecessor existed, `upsert_synced_with_origin` removes it (`install.rs:322`).
  - **Consumer 1 — Terminal Teardown:** **MUST RUN IF DROPPED.** Because $S_2$ *was* installed into `SessionTable`, if host-inbound or policy deny drops the packet, `delete_terminal_filtered_session` must execute to remove the newly installed $S_2$ probation entry.
  - **Consumer 2 — Anchor Commit Hook:** **MUST NOT WRITE.** Closing segments never update anchors (Rule 1), and imported replicas carry no trusted baseline.
  - **Consumer 3 — Flow-Cache Insert:** **ALLOWED WITH PROBATION FLAG / SUPPRESSED UNTIL COMMITTED.**
  - **Consumer 4 — Probation Clear/Refresh:** **DEFERRED.** Requires a subsequent committed non-close packet to clear `probation=true` and refresh the entry.
  - **Consumer 5 — Ownership Promote:** **SUPPRESSED BY PROBATION FLAG.** `probation=true` blocks origin promotion until a committed non-close packet clears the flag.

---

#### (c) Displaced-Set Producers vs Discard Points

Verifying every location in the pipeline where an identity family is replaced or shadowed:

1. **Canonical Predecessor Replacement:** `upsert_synced_with_origin` calls `self.remove_entry(&key)` at `install.rs:322`. The discarded `_previous` entry's full alias family (canonical key, reverse companion `reverse_session_key(key, nat)`, reverse-translated aliases, forward-wire aliases) is captured in `displaced`.
2. **Shadowed Fabric Placeholder:** `lookup_session_across_scopes` at `shared_ops.rs:602-610` and `:614-626` shadows a local fabric wire placeholder in favor of a shared forward wire match. The shadowed placeholder's key family is captured in `displaced`.
3. **New $S_2$ Alias Family:** Upon any site-2c install or adopt, the newly installed $S_2$ alias family is captured in `displaced`.
4. **Promote Re-indexing:** When `maybe_promote_synced_session` converts a local entry (`SharedPromote`), any displaced local key/NAT identity is captured in `displaced`.

---

#### (d) Surviving Surface Stress & Parity Boundaries

* **Purged Class Dispatch (Master Parity):** On a transient purge hit (`promote.rs:48-59`), the local lookup runs prior to purge. Closing segments are refused demotion on anchorless peer-synced entries. The purge then removes local/shared keys. Subsequent packet dispatch runs master-split:
  - *Warm next hop:* Forwards on retained lookup (`session_glue/mod.rs:1194-1196`) without install.
  - *Cold next hop:* Takes master's transient `MissingNeighborSeed` transaction (merging retains $P_1$ fields per `nat/mod.rs:123-133`).
  - *Clean miss:* A later cache-missing packet clean-misses and installs `ForwardFlow` with a fresh derivation.
* **Replica Lifetime Delta:** For an anchorless peer-synced entry undergoing transient purge, refusing the close mark leaves its unpurged local reverse companion on its ordinary peer-synced trajectory rather than master's 2 s/30 s closing window. This is the documented, bounded $\le 20$ s / inactivity timeout lingering residual.

---

#### (e) Full-Document Consistency Sweep

Aside from Findings 1 and 2, all sections (§1–§11) are internally aligned:
- **§1–§3:** Parity model, RFC 5961/9293 alignment, and master drift citations ($\text{fff7a4ab5}$) verified.
- **§5.1–§5.5:** 40 B `TcpSeqAnchor` layout, 3-leg established gate, OPENING immutable bounds, commit-point observation hooks, and post-borrow mark restructuring are consistently specified.
- **§5.6–§5.8:** Constructor gating, probation adopt-preserve min() deadline encoding, local-only probation reap, and the six-variant outcome contract are detailed.
- **§7–§10:** Hidden invariants, pre-existing races (#6522, #6599, #6600), and Phase 2 boundaries are preserved verbatim.

---

### Summary for Next Revision

To bring `plan.md` to a fully `SOUND` state:
1. Update `plan.md:1445-1446` to remove the outdated parenthetical `(a refusal or an OverdueSkipped transition carries the EMPTY set — nothing was displaced)` and replace it with the normative rule: `EMPTY only for an OverdueSkipped with no shadowed placeholder or a no-predecessor refusal`.
2. Update `plan.md:1724` (bullet (i) under Consumers) to explicitly list `UpsertRefused` alongside `OverdueSkipped`: `is SKIPPED for OverdueSkipped and UpsertRefused`.
