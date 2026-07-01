# pkg/eventengine

Event-driven automation engine implementing Junos-style `event-options`
policies. Matches RPM probe events against policy clauses (with optional
temporal `within` windows) and triggers commit-and-apply actions.

## Entry points

- `Engine` — `engine.go`.
- `New(store, commitFn)` — `engine.go`.
- `Apply(policies []*config.EventPolicy)` — `engine.go`. Loads policies,
  RECONCILING per-policy runtime state (see cooldown survives reload, below).
- `HandleEvent(evt)` — `engine.go`. Called by the RPM event callback. Evaluates
  under lock, pre-classifies the action, and enqueues it onto the single worker.
- `Close()` — `engine.go`. Stops the action worker; called from daemon shutdown.
- `Stats()` — `engine.go`. Counter snapshot for the `xpf_event_actions_*`
  metrics.
- `CommitFn` — `engine.go`. The atomic commit-and-apply hook.

## Callers

`pkg/daemon` (event loop, RPM results). `pkg/api` reads `Stats()` for metrics.

## Dependencies

`pkg/config`, `pkg/configstore`, `pkg/rpm`.

## Transactional batch (#2139)

A `change-configuration` action's `then` commands are applied as an
all-or-nothing transaction:

1. **Pre-classify** the `then` commands into a typed plan BEFORE touching the
   candidate. An unparseable `set`/`delete` or an unknown command type rejects
   the WHOLE batch immediately (no lock taken, no queue slot) and bumps
   `xpf_event_actions_rejected_total`.
2. **Apply to the candidate** (`EnterConfigure` clones the active config — the
   candidate IS the rollback). Any op error discards the candidate
   (`ExitConfigure`) and rejects the batch. **No partial apply ever commits.**
3. **Validate the whole candidate** with `CommitCheck()` before committing; a
   failure discards cleanly.
4. **Commit** through the daemon's atomic commit+apply (`CommitFn`, #846) so it
   serializes with operator commits.

A `delete` of a missing path is a **tolerated exception** (logged at Debug):
Junos `change-configuration` semantics, and a missing delete target is not a
half-applied batch.

## Cooldown / window state survives a config reload (#2140)

Per-policy temporal state (sliding `within` windows + last-trigger time) is
held in a `policyRuntime` record separate from the immutable policy config.
`Apply` RECONCILES this state rather than recreating it (the proven
`pkg/ipmon` pattern): for each policy it carries the previous runtime forward
when `(policy name, semantic revision)` is unchanged, and resets it when the
policy is new, removed, or semantically changed. The semantic revision is a
hash of the match/action fields (`Events`, sorted `AttributesMatch`,
`WithinClauses`, `ThenCommands`); the policy name is the stable identity.

This fixes the self-wipe: the daemon calls `Apply` on every commit, including
the engine's own remediation commit. With the old recreate-on-Apply, a policy
erased its own cooldown the instant it remediated, so the same event re-fired
with the cooldown defeated. Now the self-triggered commit re-applies the SAME
policy set (same revision) → state survives → the cooldown holds.

Note: if a remediation's `change-configuration` edits the event-options stanza
of the *triggering* policy itself, that policy's revision changes and its state
legitimately resets — a redefined policy re-arms.

The cooldown is **armed on a SUCCESSFUL commit, not at evaluate time** (#2157
SMR finding 3). `evaluateEvent` still *checks* the cooldown to avoid flooding
the queue, but the timestamp is written by the worker after a successful
commit, so a dropped/rejected action does NOT consume the cooldown — the next
legitimate trigger can retry.

## Revalidate a queued action before commit (#3750)

A pre-classified `plannedAction` sits in the worker queue (and may retry for up
to 60 s on a held config lock) before it commits. Between enqueue and commit the
policy set can change under an operator commit, and the cooldown can be armed by
a sibling commit — so the action must be **revalidated against live engine state
immediately before it commits**, not applied blind.

Each action is stamped with the policy's **semantic revision as of the evaluate
that produced it** (`plannedAction.semRev`, captured under `e.mu` in
`evaluateEvent`). The worker's `applyOnce` calls `staleReason(a)` right after
`EnterConfigure` succeeds — while it holds the config lock, so **no operator
commit (hence no `Apply` that could remove or redefine the policy) can
interleave** until `ExitConfigure`. If the action is stale it is dropped (the
candidate is never touched), `applyOnce` returns the `errStaleAction` sentinel,
and `runAction` counts it on `xpf_event_actions_dropped_total{reason="stale"}`
and does **not** retry (staleness is terminal). Three fail-opens fold into this
one gate:

- **Policy removed (H1):** `e.semRev` has no entry for the policy. An operator
  committed a config that dropped this event-options policy while its remediation
  was queued/retrying; committing the stale batch would mutate config no active
  policy authorizes. Dropped.
- **Policy redefined (H2):** the live semantic revision differs from the action's
  stamped `semRev`. A same-name redefinition changed the policy's meaning; the
  OLD command set must not commit under the new definition. Dropped.
- **Cooldown active (H3):** a successful commit of the SAME policy is within the
  30 s cooldown window. The enqueue-time cooldown check in `evaluateEvent` races
  the arm-on-commit timing (the cooldown is armed only after a commit, and
  `enqueue` dedups a same-policy duplicate ONLY when the queue is full), so a
  duplicate can slip into the queue while the worker is blocked. Re-enforcing the
  cooldown here at commit time suppresses the within-window duplicate instead of
  double-committing — restoring the documented "not more than once in any 30 s
  window" invariant even under lock contention.

Legitimate remediations are unaffected: distinct policies and a re-fire AFTER the
cooldown elapses pass the gate and commit. Regression-locked (fail-on-revert) by
`TestStale_*_3750` in `engine_stale_revalidate_3750_test.go` — removing the
`staleReason` gate makes the removed/redefined/duplicate batches commit and the
H1/H2/H3 tests go RED.

## attributes-match (regex, #2008 M7) — fail-closed at runtime (#2141)

`attributes-match "<event>.<attribute> matches <pattern>"` filters policy
triggering on a **regex** match of `<pattern>` against the event attribute
(Junos `matches` semantics). `<pattern>` is an RE2 regular expression.

- Unanchored patterns are substring matches (`Com` matches `Comcast`); anchor
  with `^...$` for an exact match.
- Supported attributes are `test-owner` and `test-name`, defined once in
  `config.EventAttributesKnownFields` (the single source of truth consumed by
  both the commit-time validator and the runtime matcher — a drift-guard test
  keeps them identical).
- **Strict at commit (#2141):** `config.ValidateEventAttributesMatchStrict`
  rejects at commit not only an uncompilable regex (#2008 M7) but also a
  malformed line (no ` matches ` / no `.`) and an unknown `<field>` name. These
  were previously fail-OPEN: the runtime matcher silently DROPPED the
  constraint, turning targeted remediation into broad config mutation while
  commit succeeded.
- **Lenient on LOAD:** the tolerant load/peer-sync path downgrades the same
  error to a warning so an upgrading node boots through a config persisted by an
  older binary (mirrors every sibling validator).
- **Fail-CLOSED at runtime (#2124 doctrine):** a malformed/unknown line that
  slipped through a lenient load makes the policy NOT fire (rather than dropping
  the constraint and over-firing). This is surfaced by the boot-time
  lenient-compile warning plus `xpf_event_attributes_match_invalid_total`.
  **Behavior change:** a legacy config that booted with a typo'd constraint now
  *stops* firing that policy instead of over-firing — the safe direction.
- Compiled regexes are cached at `Apply()` time keyed by pattern string, so the
  event hot path never recompiles.

## Fail-safe action queue (#2157)

Remediation actions run on a **single serialized worker goroutine**, not on the
RPM probe goroutine that fired the event. Because `fireEvent` runs on per-probe
goroutines, two probes failing at once previously both raced into
`EnterConfigure` and one action was silently dropped. With the single worker,
only the worker ever enters configure mode on the engine's behalf, so that race
cannot occur.

- **Held config lock:** if `EnterConfigure` fails with
  `configstore.ErrConfigLocked` (an operator or REST/gRPC session holds the
  candidate), the worker RETRIES with bounded exponential backoff
  (200 ms → 5 s) up to a 60 s deadline, bumping
  `xpf_event_actions_retried_total`, instead of dropping. After the deadline it
  bumps `xpf_event_actions_dropped_total{reason="lock_held"}`. The sentinel is
  matched with `errors.Is`, not a fragile string match. The backoff sleep uses
  an explicit `time.NewTimer` + `Stop()` (via `newRetryTimer`), NOT
  `time.After`: when `stopCh` fires before the backoff elapses (daemon shutdown
  or `Apply` churn), the retry stops the timer immediately and releases the
  runtime timer instead of leaking an armed timer until it fires (#2890). With
  a doubling backoff toward the 5 s ceiling, orphaned `time.After` timers would
  otherwise accumulate across restart churn. Regression-locked by
  `TestRetry_TimerStoppedOnEngineStop` (fail-on-revert: it injects `newTimerFn`,
  parks the worker in the retry select under a held lock, closes the engine, and
  asserts the stop func was invoked — reverting to `time.After` never consults
  the seam and the test goes RED).
- **Bounded queue, dedup-by-policy:** the queue holds at most one pending
  action per policy — a newer trigger supersedes an older queued one (no value
  in applying a stale remediation twice). Overflow bumps
  `xpf_event_actions_dropped_total{reason="queue_full"}` **exactly once per
  dropped action**. When the queue is full of unrelated policies and there is no
  stale same-policy entry to evict, the genuinely-unfittable new arrival is
  dropped (the older FIFO survivors are kept) and counted once by `enqueue` —
  `supersede()` does NOT also count that overflow in its refill loop (it only
  counts a SURVIVOR it could not re-place). Loss is always counted, never silent,
  and never double-counted (#2869).
- **FIFO ordering across policies (#2869):** the queue is FIFO. When the queue
  is full and `supersede()` drains/refills it to drop a stale same-policy entry,
  it re-enqueues the surviving OTHER-policy actions in their original order and
  places the new (superseding) action at the **TAIL** — never the head.
  Prepending the new action would let the newest event jump ahead of every older
  queued remediation (LIFO), starving older policies under sustained event
  frequency and reordering remediation against the order events were observed.
  Supersede therefore only ever drops/replaces the stale same-policy entry; it
  does not reorder unrelated policies. Locked by
  `TestSupersede_PreservesFIFOPlacesNewAtTail` (fail-on-revert: a prepend lands
  the new action at index 0 and the test goes RED).
- A non-lock error (bad apply / CommitCheck reject) is a permanent failure: no
  retry, bumps `xpf_event_actions_rejected_total`.

## Cancellable remediation commit (#2868)

A remediation commit (`CommitFn`) drives netlink updates, an FRR reload, and
Rust dataplane sync — seconds of work. The engine threads an **engine-lifetime
context** into `commitFn` (built in `New`, returned by `commitContext`, and
passed through `applyOnce`). `Close()` closes `stopCh` AND cancels that context
(`lifeCancel`), so a remediation commit in flight at daemon shutdown is
cancelled cleanly instead of running under an uncancellable `context.Background`
that would block termination past the systemd `TimeoutStopSec` SIGKILL. The
standalone (no-`commitFn`) `store.Commit()` branch is unaffected (it does not
take a context). Regression-locked by `TestCommit_CancelledOnEngineStop`, which
blocks a `commitFn` on `ctx.Done()` and asserts `Close()` aborts it with
`context.Canceled` (fails on the timeout if reverted to `context.Background`).

## Metrics (`pkg/api`)

`Engine.Stats()` backs:

- `xpf_event_actions_committed_total`
- `xpf_event_actions_rejected_total`
- `xpf_event_actions_retried_total`
- `xpf_event_actions_dropped_total{reason="lock_held"|"queue_full"|"stale"}`
  (`stale` = revalidate-before-commit dropped a removed/redefined-policy or
  within-cooldown action, #3750)
- `xpf_event_attributes_match_invalid_total`
- `xpf_event_action_queue_depth` (gauge)

## Gotchas

- 30 s policy cooldown (`policyCooldown`, `engine.go`). The same policy will not
  trigger more than once in any 30 s window. Armed on successful commit, CHECKED
  both at evaluate (`evaluateEvent`) AND re-checked at commit (`staleReason`,
  #3750) — the commit-time re-check is what holds the invariant when a duplicate
  slips into the queue during lock contention (the evaluate-time check races the
  arm-on-commit timing).
- Temporal `within` clauses keep a sliding window of timestamps per
  (policy, event) pair, **pruned on every append** so a cooldown-suppressed
  event can never grow the window unbounded. This holds for the cases #2216
  flagged: a no-within policy (bounded to the 60s default horizon) and a
  `within N { trigger on M }` policy whose threshold is never met (bounded to
  the clause horizon). Pruning is NOT gated behind the trigger-success path.
  Regression-locked by `TestWindow_*_2216A`.
- A single event that matches several policies fires EVERY matching policy's
  action — `HandleEvent` enqueues each triggered policy onto the single worker,
  which applies them serially, so none is dropped racing the config lock (the
  #2216-B all-but-one drop the pre-#2157 per-probe `executeCommands` path had).
  The cross-goroutine drop race is regression-locked by the pre-existing
  `TestQueue_ConcurrentProbesSerialize` (8 concurrent `HandleEvent` callers);
  `TestConcurrent_OneEventMatchesManyPolicies_2216B` adds the complementary
  single-event fan-out invariant (one event → all N matching policies commit).
- `CommitFn` holds the apply semaphore across both commit and apply (#846) so
  event-triggered commits serialize with operator commits.
- The engine holds no engine-level lock (`e.mu`) while in configure/commit
  (preserves the #846 deadlock-avoidance contract); the worker reads the
  pre-classified plan, not live engine state.
