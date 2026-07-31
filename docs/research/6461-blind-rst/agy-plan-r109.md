# AGY hostile plan-review — round 109 (v10.26.0)

Reviewer: AGY (direct binary). Verdict: SOUND with two textual-consistency findings: (1) effective_transition was omitted from the struct declaration and the consumer gates still read raw transition; (2) two unqualified probation-clear statements remained in section 5.5/5.6. Both folded in v10.26.1.

## Verbatim review

SOUND

### 1. Findings

1. **`plan.md:1733-1735`, `plan.md:1746`, `plan.md:1755-1758`, `plan.md:1816`, `plan.md:1818`** (Code trace: `userspace-dp/src/afxdp/session_glue/mod.rs:1092-1121`, `userspace-dp/src/afxdp/session_glue/promote.rs:86-139`, `userspace-dp/src/afxdp/poll_descriptor/mod.rs:509`, `:698-714`, `:3900-3959`):
   *Inconsistency in contract block between `effective_transition` rule, struct declaration, and consumer specifications.*
   Line 1757 mandates that *"every consumer, INCLUDING the pre-resolved-result promotion, reads the effective transition, never the raw fields"*. However:
   - The `MaterializeReport` struct declaration at lines 1733–1735 omits `effective_transition` (`MaterializeReport { site: Option<MaterializeSite>, validation: Option<CloseValidation>, transition: TransitionResult, displaced: DisplacedSet }`).
   - The promotion path consumer at lines 1746 and 1818 explicitly specifies checking `report.transition == OverdueSkipped` (reading the raw `transition` field), directly contradicting line 1757.
   - The commit-time refresh consumer at line 1816 explicitly specifies checking `report.transition == OverdueSkipped` (reading the raw `transition` field).
   *Remediation*: Update line 1735 to include `effective_transition: TransitionResult` (or `pub fn effective_transition(&self) -> TransitionResult`) in the struct definition, and update lines 1746, 1816, and 1818 to specify `report.effective_transition() == OverdueSkipped` / `effective_transition != OverdueSkipped`.

2. **`plan.md:1225`, `plan.md:1528`** (Code trace: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:509`, `:1528`):
   *Unqualified probation clear statements in §5.5 and §5.6 outside the SSOT.*
   While round-109 fold 4 updated lines 1398–1399, 1814–1815, and 2557 to explicitly qualify probation clear claims with `effective_transition != OverdueSkipped`, §5.5 (line 1225: *"until a committed non-close packet clears the flag"*) and §5.6 (line 1528: *"clears `probation` AND applies the ordinary established refresh"*) remain unqualified.
   *Remediation*: Append `(when effective_transition != OverdueSkipped)` to lines 1225 and 1528 for complete document-wide consistency.

---

### 2. Detailed Checklist Verification

#### (a) Verification of Round-109 Folds Against the Code and Design

1. **Post-State S2 Alias Family as First-Class Producer in Displaced Set** (§5.8 lines 1855–1888, §9 lines 2470–2510; `userspace-dp/src/afxdp/flow_cache.rs:352-358`, `:1105-1120`, `userspace-dp/src/afxdp/poll_descriptor/mod.rs:298-327`):
   - *Verification*: A FIN/RST segment bypasses the flow cache (`flow_cache.rs:352-358`), allowing a closing segment to materialize S2 while an older cache entry under S2's alias remains active in the cache. A subsequent ACK segment consults the flow cache before session resolution (`poll_descriptor/mod.rs:298-327`). If S2 were not included in `displaced`, a `(Refused, Installed)` transition with no placeholder P and no predecessor K would produce an empty `displaced` set, leaving the stale cache entry to incorrectly serve subsequent packets. Including S2 as a first-class producer ensures `flow_cache.rs:1105-1120` (`invalidate_slot`) purges S2's exact-key aliases immediately. Total capacity remains 3 (P, K, S2). Sound and verified.

2. **Derived `effective_transition` Written by Producer** (§5.8 lines 1755–1762; `userspace-dp/src/afxdp/session_glue/mod.rs:1092-1121`, `userspace-dp/src/afxdp/session_glue/promote.rs:86-139`):
   - *Verification*: `materialize_shared_session_hit` evaluates validation and overdue checks before state-changing upserts. Deriving `effective_transition` enforces the by-construction invariant before pre-resolved-result promotion runs (`promote.rs:86-139`). For an out-of-product site-2c report (e.g. `(Some(Site2c), Accepted, Installed)`), `effective_transition` evaluates to `OverdueSkipped`, blocking both promotion and teardown. Sound (subject to textual consistency Finding 1).

3. **Site-Qualified Second MissingNeighbor Composition Clause** (§5.8 lines 1829–1838, lines 1945–1953; `userspace-dp/src/afxdp/poll_descriptor/mod.rs:4662-4829`, `:5057-5068`, `neighbor_dispatch.rs:272-292`):
   - *Verification*: Requiring `report.site == Some(Site2c)` for `OverdueSkipped` or `UpsertRefused` composition to the live-backed `ExistingResolved` buffer-only arm prevents non-materializing paths (`site == None`, such as purged retained lookups) from erroneously hitting the buffer-only arm and replaying released tuples. Verified against `poll_descriptor/mod.rs:4662-4829`.

4. **Document-Wide Qualification of Probation Clear/Install Claims** (§5.8 lines 1398–1399, 1814–1815, 2557):
   - *Verification*: Every clear/install claim in the SSOT now explicitly requires `effective_transition != OverdueSkipped`, preventing overdue probation entries from resurrecting on committed packets. Verified (subject to editorial Finding 2).

---

#### (b) Contract Block Review (§5.8 lines 1696–1980)

Walking the contract block top-to-bottom as an implementer:
- **Fields & Structure**: `MaterializeReport` separates validation (`Option<CloseValidation>`) and transition (`TransitionResult`), avoiding precedence ambiguity on `(Refused, Installed)` and `UpsertRefused`.
- **Producer Invariant**: `materialize_shared_session_hit` pre-calculates validation and overdue state. Out-of-product combinations map to `effective_transition = OverdueSkipped`.
- **Internal Consistency**: Aside from Finding 1 (where lines 1746, 1816, and 1818 reference `report.transition` instead of `report.effective_transition`), the flow of metadata from materializer $\rightarrow$ `ResolvedFlowSessionDecision` $\rightarrow$ descriptor dispatch context is linear, deterministic, and unambiguous.

---

#### (c) Consumer Set & Legal Phase-1 Product Walkthrough

1. **Legal Phase-1 Product**:
   - `(site: None, validation: None, transition: None)` — Non-materializing paths (local hit, clean miss).
   - `(site: Some(Site2c), validation: None, transition: Installed | AdoptedPreservingDeadline | UpsertRefused | OverdueSkipped)` — Non-close site-2c materialization.
   - `(site: Some(Site2c), validation: Some(Refused), transition: Installed | AdoptedPreservingDeadline | UpsertRefused | OverdueSkipped)` — Closing site-2c materialization.
   - `validation: Some(Accepted)` has no Phase-1 producer. Site 2b is outside `MaterializeReport`.

2. **Consumer Behaviors**:
   - **Terminal Teardown** (`poll_descriptor/mod.rs:698-714`, `:768-784`, `:824-840`): Skipped when `effective_transition` is `OverdueSkipped` or `UpsertRefused`.
   - **Anchor Commit Hook**: No update when `effective_transition` is `OverdueSkipped` or `UpsertRefused`.
   - **Flow-Cache Insert** (`poll_descriptor/mod.rs:3900-3959`): Suppressed when `effective_transition` is `OverdueSkipped` or `UpsertRefused`.
   - **Probation Clear & Commit-Time Refresh**: Suppressed when `effective_transition == OverdueSkipped`. Runs only when `effective_transition != OverdueSkipped`.
   - **Ownership Promotion** (`promote.rs:86-139`): Suppressed when `effective_transition == OverdueSkipped` OR `validation == Some(Refused)` OR when K has `probation = true`.

---

#### (d) Surviving Surface Stress Analysis

1. **Displaced Set Bounding & Deduplication**:
   - Capacity of 3 identity families per dispatch is exact and sufficient:
     1. Shadowed placeholder P (if substituted at site 2c).
     2. Canonical predecessor K (if replaced during upsert or promotion).
     3. Installed S2 (added on any successful install/adopt or promotion).
   - Invalidation timing (inline current-binding drain immediately post-resolution + single batch accumulator for sibling fan-out at `poll_binding` level) guarantees no same-batch descriptor consumes stale aliases while preventing accidental eviction of newly installed S2 entries.

2. **Overdue Probation Entry GC Alignment**:
   - When a materialize hit occurs against an overdue probation entry K ($D \le \text{now\_ns}$), upsert is skipped wholesale. K remains in place with its existing wheel slot for GC reap, while the packet forwards using S2's decision. This eliminates current-tick re-queue spinning ($D = \text{now\_ns} \implies \text{expires\_after\_ns} = 0$).

3. **Purged-Class Master Parity**:
   - For transient-purge events, warm next hops forward on retained lookups (`session_glue/mod.rs:1194-1196`), cold next hops execute master's seed transaction, and subsequent clean misses install `ForwardFlow` with Open. Closing packets purge flag-agnostically, maintaining strict parity with master.

---

#### (e) Full-Document Consistency Sweep

Outside of Findings 1 and 2, all line citations, helper signatures (`tcp_seg_view`, `close_seq_plausible`), provenance matrices, test specifications (§9), and excised machinery descriptions (§10.6) are consistent throughout `plan.md`.
