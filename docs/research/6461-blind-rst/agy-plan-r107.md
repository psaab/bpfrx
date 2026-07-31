# AGY hostile plan-review — round 107 (v10.24.0)

Reviewer: AGY (direct binary). Verdict: SOUND — pre-upsert ordering, promote gate, consumer set, single-carrier/drain all verified.

## Verbatim review

SOUND

### 1. Pre-upsert ordering verification (§5.6, §5.8; `userspace-dp/src/afxdp/session_glue/mod.rs:1092-1261`, `userspace-dp/src/session/install.rs:310-322, :345-400`)

The round-107 construction ordering in `materialize_shared_session_hit` ([`session_glue/mod.rs:1092-1121`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1092-L1121)) evaluates the validation verdict and overdue check against the local session table before calling `upsert_synced_with_origin` ([`install.rs:310-322, :345-400`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L310-L400)):

- **Overdue pre-check:** For an existing local probation entry $K$, if $D \le \text{now\_ns}$ (where $D = \text{min}(K.\text{deadline}, S_2.\text{timeout\_deadline})$), `materialize_shared_session_hit` selects `TransitionResult::OverdueSkipped` immediately. The state-changing `upsert_synced_with_origin` call is bypassed entirely: $K$ retains its existing slot without restamping or index mutation, and $S_2$ is returned for forwarding only.
- **Validation pre-check:** For closing-flagged segments on site 2c, validation against the local anchor is evaluated prior to upsert. Because an imported shared replica carries no trusted anchor, validation yields `CloseValidation::Refused`. The transition action is selected prior to any mutation.
- **Construction invariant:** Invalid product states (e.g., state-changing upsert executed prior to validation/overdue decision) are rendered unreachable by construction at the producer rather than normalized post-upsert.

### 2. Promotion gate verification (§5.5, §5.8; `userspace-dp/src/afxdp/session_glue/promote.rs:86-107`)

In [`promote.rs:86-107`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs#L86-L107), `maybe_promote_synced_session` checks `report.transition == TransitionResult::OverdueSkipped` (and `CloseValidation::Refused` for site 2c materialization) at the function entry alongside `!origin.is_promotable_synced()` and disposition checks.

- When `report.transition == OverdueSkipped` or `validation == Some(Refused)`, `maybe_promote_synced_session` returns `metadata` unmodified without invoking `promote_synced_with_origin` ([`promote.rs:99`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs#L99)), BPF session-map publishing ([`promote.rs:110`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs#L110)), shared map insertion ([`promote.rs:131`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs#L131)), or peer replication ([`promote.rs:138`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs#L138)).
- This gate operates independently of $K$'s `probation` flag, ensuring a non-probation $K$ is never overwritten, published, or replicated on an overdue or refused materialization report.

### 3. Consumer set audit (§5.8; `userspace-dp/src/afxdp/poll_descriptor/mod.rs:509, :698-840, :3900-3959, :4662-4829`)

Re-verified the 5 gated consumers and the 2 non-gated consumers of `MaterializeReport`:

1. **Terminal teardown** ([`poll_descriptor/mod.rs:698-714, :768-784, :824-840`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L698-L840)): Skipped for both `OverdueSkipped` and `UpsertRefused`, preventing teardown dispatch under $S_2$'s identity when $S_2$ was not installed.
2. **Anchor commit hook:** Bypassed on `OverdueSkipped`, `UpsertRefused`, and `Refused` reports; anchor sequence tracking does not update from unvalidated or skipped segments.
3. **Flow-cache insert** ([`poll_descriptor/mod.rs:3900-3959`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L3900-L3959)): Suppressed for `OverdueSkipped`, `UpsertRefused`, and `Refused`.
4. **Probation clear+refresh:** Suppressed on overdue entries; an overdue entry cannot be refreshed to established timeout by a pre-admission materialize attempt.
5. **Ownership promote** ([`promote.rs:86-107`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs#L86-L107)): Guarded by `OverdueSkipped` and `Refused`.

**Non-gated consumers:**
- Packet accounting ([`poll_descriptor/mod.rs:3494-3503`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L3494-L3503), [`session/mod.rs:1177-1210`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L1177-L1210)) runs on the packet tuple per #2501 semantics.
- Decision forwarding / buffering / replay ([`poll_descriptor/mod.rs:5057-5068`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L5057-L5068)) consumes $S_2$'s decision.
- **MissingNeighbor composition** ([`poll_descriptor/mod.rs:4662-4829`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L4662-L4829)): An `OverdueSkipped` or `UpsertRefused` report with `ForwardingDisposition::MissingNeighbor` composes to the live-backed `ExistingResolved` buffer-only arm, bypassing the seed block so $K$ is not clobbered via `install.rs:139`.
- **`site = None` scoping:** Non-materializing paths (`site = None`, e.g., purged retained lookups) do not trigger fail-closed `OverdueSkipped` handling, preventing purged lookups from falsely taking the buffer-only arm and replaying released tuples.

### 4. Single-carrier and single-drain verification (§5.8; `userspace-dp/src/afxdp/worker/lifecycle.rs:53-55, :209-225`)

- **Carrier single-ownership:** `DisplacedSet` is carried exclusively within `MaterializeReport.displaced`, which is embedded in `ResolvedFlowSessionDecision.report`. `ResolvedFlowSessionDecision` contains no standalone `displaced` field.
- **Current-binding drain:** The descriptor poller drains `report.displaced` for the current descriptor immediately post-resolution ([`poll_descriptor/mod.rs:110-131`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L110-L131)), invalidating local flow-cache slots before executing cache insertion for $S_2$ or moving to the next descriptor in the batch.
- **Sibling fan-out drain:** Sibling cache invalidation is backed by `WorkerScratch` (`afxdp/mod.rs:278-281`), which union-accumulates displaced families across all descriptors in the batch. Fan-out executes once per batch at the `poll_binding` level over `left + right` bindings ([`lifecycle.rs:53-55, :209-225`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/lifecycle.rs#L53-L225)) prior to processing the next RX batch.

### 5. Section-9 empty-case and surviving surface stress (§5.8, §9)

- **Section-9 empty-case correction:** On `UpsertRefused` where $S_2$ fails to replace a non-peer predecessor $K$ ([`install.rs:310-315`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L310-L315)) and the promotion attempt no-ops (e.g., disposition is not `ForwardCandidate`, [`promote.rs:86-90`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs#L86-L90)), no entries are removed or replaced. Provided no placeholder $P$ was shadowed, `MaterializeReport.displaced` is empty, and $K$'s aliases remain valid.
- **Transient-purge master parity:** Closing-flagged segments hitting transient-purge entries follow master's flag-agnostic purge and retained-lookup forwarding without creating unvalidated local close marks.
- **Provenential isolation:** `ReplacedSyncedLocal` primary installs branch on closing flags prior to `take_synced_local` ([`lookup.rs:407-418`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L407-L418)), delivering closing packets locally without displacing synced local session state.

### 6. Full-document consistency sweep

- All section citations (§1–§11), file:line references (`session_glue/mod.rs:1092-1261`, `promote.rs:86-107`, `install.rs:310-322, :345-400`, `lifecycle.rs:53-55, :209-225`), and round-107 fold descriptions are internally consistent across the plan.
- The document accurately specifies Phase-1 Option A requirements and invariants without remaining terminology or structural contradictions.
