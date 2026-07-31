# AGY hostile plan-review — round 101 (v10.18.0)

Reviewer: AGY (direct binary). Verdict: SOUND — full verification of the v10.18.0 mechanical contracts (producer/transport, displaced-identity set, invalidation timing, artifact removals).

## Verbatim review

SOUND

### 1. Producer/Transport Contract Verification (`OverdueSkipped` & `MaterializeOutcome`)
- **Producer Signature & Early Availability:** `materialize_shared_session_hit` ([`userspace-dp/src/afxdp/session_glue/mod.rs:1092-1122`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1092-L1122)) is updated to return `(SessionLookup, MaterializeOutcome)`. In the shared-hit branch of `resolve_flow_session_decision` ([`userspace-dp/src/afxdp/session_glue/mod.rs:1197-1234`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1197-L1234)), the `MaterializeOutcome` is computed prior to evaluating `maybe_promote_synced_session` ([`userspace-dp/src/afxdp/session_glue/mod.rs:1238-1253`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1238-L1253)).
- **Transport Field & Default Initialization:** `ResolvedFlowSessionDecision` ([`userspace-dp/src/afxdp/shared_ops.rs:563-578`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs#L563-L578)) incorporates `pub(super) materialization: MaterializeOutcome`. All non-materializing construction sites (such as `local_query` / `local` helpers in [`userspace-dp/src/afxdp/shared_ops.rs:530-561`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs#L530-L561) and reverse flow synthesis in [`userspace-dp/src/afxdp/session_glue/mod.rs:1330-1344`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1330-L1344)) initialize this field to `MaterializeOutcome::None`.
- **Poller Hoist & Carried Context:** The poller hoists `materialization` at [`userspace-dp/src/afxdp/poll_descriptor/mod.rs:509`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L509) alongside `created` and `install_failed`, carrying it on the per-descriptor dispatch context past the decision reduction at line `:883` ([`userspace-dp/src/afxdp/poll_descriptor/mod.rs:883`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L883)).

---

### 2. Downstream Consumer Walk for `OverdueSkipped`
- **Teardown Sites (`delete_terminal_filtered_session`):** The three terminal teardown triggers — host-inbound deny ([`userspace-dp/src/afxdp/poll_descriptor/mod.rs:698-714`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L698-L714)), lo0 policy deny ([`userspace-dp/src/afxdp/poll_descriptor/mod.rs:768-784`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L768-L784)), and host-local dropped ([`userspace-dp/src/afxdp/poll_descriptor/mod.rs:824-840`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L824-L840)) — explicitly check `materialization != MaterializeOutcome::OverdueSkipped` before invoking teardown, preventing deletion of the un-upserted overdue row `K`.
- **Flow-Cache Insert:** The cache insertion path ([`userspace-dp/src/afxdp/poll_descriptor/mod.rs:3900-3959`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L3900-L3959)) gates population on `materialization != MaterializeOutcome::OverdueSkipped`, suppressing stale decision caching.
- **Commit Hooks & Probation Clear/Refresh:** Final admission commit arms skip anchor updates and probation clear/refresh when `materialization == MaterializeOutcome::OverdueSkipped`. Overdue entry `K` is not resurrected for a full established timeout.
- **Ownership Promotion:** When `OverdueSkipped` occurs, `K` remains installed in `SessionTable` with `K.probation == true`. The probation guard in `maybe_promote_synced_session` ([`userspace-dp/src/afxdp/session_glue/mod.rs:1238-1253`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1238-L1253)) inspects `K.probation` and suppresses ownership promotion.
- **MissingNeighbor Arm Composition:** In [`userspace-dp/src/afxdp/poll_descriptor/mod.rs:4034`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4034), `OverdueSkipped` maintains `K` in table, causing resolution to return a live-backed `ExistingResolved` outcome. The arm buffers the packet with the stored decision and skips the seed block ([`userspace-dp/src/afxdp/poll_descriptor/mod.rs:4662-4829`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4662-L4829)).

---

### 3. Displaced-Identity Set & Discard Points
- **Set Construction:** Every site-2c transition result carries a `displaced_identities` set containing:
  1. The new `S2` alias family (canonical, reverse companion, reverse-translated, forward-wire, reply-match tuples).
  2. The removed canonical predecessor `_previous`'s alias family, captured from `upsert_synced_with_origin` ([`userspace-dp/src/session/install.rs:295-322`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L295-L322)).
  3. Any shadowed placeholder's key family, captured prior to discarding `ResolvedSessionLookup` or placeholder substitution ([`userspace-dp/src/afxdp/shared_ops.rs:522-560`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs#L522-L560), [`:602-628`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs#L602-L628)).
- **Refusal / OverdueSkipped:** Returns an empty `displaced_identities` set, as no identities are replaced or installed.
- **Escape Audit:** Capturing the set directly at the transition site prevents any displaced alias from escaping invalidation when internal structures drop `_previous` or shadowed placeholders.

---

### 4. Invalidation Mechanical Timing & Ownership Alignment
- **Current-Binding Invalidation:** Executed at the poller ([`userspace-dp/src/afxdp/poll_descriptor/mod.rs:110-131`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L110-L1131)) immediately after resolution and prior to early exits, cache insertion, or processing subsequent descriptors in the batch.
- **Batch Accumulation & Sibling Fan-Out:** Displaced sets from transitions within the batch accumulate on worker scratch state. Sibling binding fan-out runs once per RX batch via the reap path ([`userspace-dp/src/afxdp/worker/loop_body/mod.rs:1467-1520`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs#L1467-L1520)), explicitly excluding the current binding to prevent double invalidation or premature eviction of freshly inserted `S2` entries.

---

### 5. Full-Document Consistency Sweep & Artifact Cleanups
- **Cold-Seed Parity:** Section 9 correctly documents that both closing and non-closing cold-seed packets execute master's exact seed transaction on raw flags ([`userspace-dp/src/afxdp/poll_descriptor/mod.rs:4787-4795`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4787-L4795), [`userspace-dp/src/session/install.rs:179-180`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L179-L180)).
- **Pre-Purge Lookup Engagement:** Phrasing across §3 table row 9, §5.6, §7, and §9 accurately states that while the demote gate engages on the pre-purge lookup, it does not alter master's flag-agnostic purge or constructor-side Open behavior on subsequent clean miss dispatches.
- **Refused-Close Inertness:** Refused-close inertness is scoped strictly to gate effects (no `closing`/`reset` mark, no `last_seen_ns` stamp, no wheel re-queue).
- **Citations & Master Drift:** All `file:line` citations accurately reference base `023f17a606d8`, with master deltas up through `fff7a4ab5` correctly tabulated in §3.1.
