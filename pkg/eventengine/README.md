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
  matched with `errors.Is`, not a fragile string match.
- **Bounded queue, dedup-by-policy:** the queue holds at most one pending
  action per policy — a newer trigger supersedes an older queued one (no value
  in applying a stale remediation twice). Overflow bumps
  `xpf_event_actions_dropped_total{reason="queue_full"}`. Loss is always
  counted, never silent.
- A non-lock error (bad apply / CommitCheck reject) is a permanent failure: no
  retry, bumps `xpf_event_actions_rejected_total`.

## Metrics (`pkg/api`)

`Engine.Stats()` backs:

- `xpf_event_actions_committed_total`
- `xpf_event_actions_rejected_total`
- `xpf_event_actions_retried_total`
- `xpf_event_actions_dropped_total{reason="lock_held"|"queue_full"}`
- `xpf_event_attributes_match_invalid_total`
- `xpf_event_action_queue_depth` (gauge)

## Gotchas

- 30 s policy cooldown (`policyCooldown`, `engine.go`). The same policy will not
  trigger more than once in any 30 s window. Armed on successful commit.
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
  Regression-locked by `TestConcurrent_OneEventMatchesManyPolicies_2216B`.
- `CommitFn` holds the apply semaphore across both commit and apply (#846) so
  event-triggered commits serialize with operator commits.
- The engine holds no engine-level lock (`e.mu`) while in configure/commit
  (preserves the #846 deadlock-avoidance contract); the worker reads the
  pre-classified plan, not live engine state.
