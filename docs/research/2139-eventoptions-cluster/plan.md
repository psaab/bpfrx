# Plan: event-options robustness cluster — transactional batch, cooldown survives reload, strict attributes-match, fail-safe queue (#2139 / #2140 / #2141 / #2157)

Status: PLAN-READY (all four bugs). Single coordinated change to
`pkg/eventengine` (+ a strict-validate gate in `pkg/config`). Control-plane
only — review-class, no smoke. Verified against master `0498b5143`.

## 1. Problem

`pkg/eventengine` turns RPM probe events into Junos `event-options policy
... then change-configuration` remediation. Four defects, all in the same
~370-line `engine.go`, make that automation unsafe:

- **#2139 (HIGH) — non-transactional batch.** `executeCommands`
  (engine.go:300-372) enters configure mode, then applies each `then`
  command best-effort: a failed `set` parse/apply logs and *continues*
  (321-325), a failed `delete` parse logs and *continues* (328-332), a
  delete-exec failure logs and *continues* (334-343), an unknown command
  type logs and *continues* (344-347). After the loop it commits whatever
  subset succeeded (350-371). A typo in the middle of a multi-command
  remediation commits a half-applied config — dangerous for RPM-triggered
  failover / automated route changes that look atomic in the config.

- **#2140 (HIGH) — cooldown/window state wiped on every apply.** `Apply`
  (engine.go:70-98) unconditionally `e.windows = make(...)` and
  `e.lastTrigger = make(...)` on *every* call. The daemon calls
  `eventEngine.Apply(cfg.EventOptions)` on every commit
  (`daemon_apply.go:1213`), and the engine's own remediation routes through
  `commitAndApply` → another apply → another `Apply()`
  (`daemon_run.go:953`). So a policy triggers, runs `change-configuration`,
  commits, and that commit erases its own `lastTrigger`. The same event
  re-fires with the 30 s cooldown defeated. Unrelated operator commits also
  wipe every policy's `within ... trigger until` window memory.

- **#2141 (MEDIUM-HIGH) — malformed/unknown attributes-match silently
  dropped (FAIL-OPEN).** `ValidateEventAttributesMatch`
  (event_options_match.go:55-77) and `attributesMatch` (engine.go:177-219)
  both `if !ok { continue }` on a line that doesn't parse into `<field>
  matches <pattern>`, and `attributesMatch` `default: continue` on an
  unknown field name (188-195). Dropping a constraint **broadens** the
  policy. A typo (`test-ower` for `test-owner`, or a missing ` matches `)
  turns targeted remediation into broad config mutation, and commit
  succeeds with no error. This is the same fail-open anti-pattern #2124
  flagged for the policy matcher — correctness gaps must fail CLOSED.

- **#2157 (MEDIUM) — remediation silently dropped when the config lock is
  held.** `executeCommands` calls `e.store.EnterConfigure()` (engine.go:307)
  which fails with "configuration is locked by another user" whenever an
  operator (`configure`) or a REST/gRPC session holds the candidate
  (store.go:675-681). The engine logs a warning and `return`s — the
  automated action is lost, with no queue, no retry, no counter. Worse, the
  issue's own correction understates the concurrency: `fireEvent` is invoked
  from **per-probe goroutines** (`rpm.go:298` `go func(p,t,k)` →
  `runProbeLoop` → `fireEvent`), so two probes failing at once both call
  `HandleEvent` → `executeCommands` → `EnterConfigure` concurrently. One
  wins the lock, the other's remediation is dropped. The within-event loop
  is sequential (engine.go:105-107), but cross-event/cross-probe contention
  is real.

These are siblings by construction (one subsystem, one filing batch,
codex-review-016 / agy-review-016) and share the same fix surface
(`executeCommands`, `Apply`, the parse seam). Fixing them piecemeal would
re-touch the same functions three times; fixing them as one coordinated
change is cheaper and lets the design be internally consistent (e.g. the
#2139 transaction and the #2157 queue are the same code path; the #2140
state-identity key and the #2141 strict compile both key off policy
identity).

## 2. Hypothesis

All four are fixable inside `pkg/eventengine` plus one strict-validate
hook in `pkg/config`, by reusing machinery the codebase already has:

1. **#2139** — the configstore *already* exposes a candidate→compile→commit
   pipeline with `CommitCheck()` (validate without applying,
   store.go:1132-1147) and a strict `compileTree`. The engine's `commitFn`
   already serializes with operator commits under `applySem`
   (`commitAndApply`). The fix is to *validate the whole batch before
   committing*, and discard the candidate (`ExitConfigure`) on any failure
   instead of committing the residue. No new transaction primitive is
   needed.

2. **#2140** — the `pkg/ipmon` engine *already* solves the identical
   "preserve runtime state across an unrelated commit" problem: its `Apply`
   (ipmon.go:204-241) builds a fresh policy map but **carries forward**
   `failed`/`since`/`transitions` from the previous entry when
   `prev.cfg.MatchRPMProbe == pol.MatchRPMProbe` (a semantic-identity
   check). The event engine should copy that reconcile-not-recreate
   pattern, keyed by policy name + a semantic revision of the match/action.

3. **#2141** — the strict commit path *already* calls
   `ValidateEventAttributesMatch` from `CompileConfig` (compiler.go:690).
   The gap is only that the validator (and the runtime matcher) tolerate
   malformed/unknown lines via `if !ok { continue }`. Tightening the
   validator to reject malformed grammar + unknown fields on the strict
   path (keeping the lenient LOAD path tolerant, mirroring the existing
   `lenientEventAttributesMatch` downgrade) closes it fail-closed.

4. **#2157** — once #2139 makes `executeCommands` build a validated plan
   *before* touching the candidate, "lock held" becomes a *deferrable*
   condition: enqueue the (policy-identity, plan) and retry with bounded
   backoff, surfaced by a counter, rather than dropping. A single-worker
   serialized queue also removes the cross-probe `EnterConfigure` race.

## 3. Goal / acceptance criteria

- **#2139:** A `change-configuration` action with two valid commands and one
  invalid in the middle commits **NO** candidate change; the rejected action
  is surfaced (log + counter + status). All-or-nothing.
- **#2140:** A cooldown policy whose action commits a harmless change;
  trigger the same event twice with no time advance → the **second trigger
  is suppressed**. An unrelated operator commit does **not** reset another
  policy's cooldown / within-window state. Removing or semantically changing
  a policy **does** drop its state.
- **#2141:** Committing a policy with `attributes-match "test-ower matches
  ^x$"` (unknown field) or a missing ` matches ` token **fails commit** with
  a field-specific error. The tolerant LOAD/SyncApply path downgrades to a
  warning (boot-through), matching the existing `lenientEventAttributesMatch`
  doctrine. Runtime matcher no longer silently drops a malformed line.
- **#2157:** When `EnterConfigure` fails because the lock is held, the
  validated action is **queued and retried** with bounded backoff (not
  dropped); concurrent probe-goroutine triggers serialize through one
  worker; a counter (`xpf_event_actions_*`) makes drops/queue depth/retries
  observable. A bounded queue with a drop-oldest policy + drop counter
  prevents unbounded growth under a stuck lock.
- No regression to the #846 atomic-commit serialization or the #2008 M7
  regex-cache hot path. `make test` green; `go test -race ./pkg/eventengine/...`
  green (concurrency is the core of #2157/#2140).

## 4. Approach

The change is internal to `pkg/eventengine`; the public surface
(`New`, `Apply`, `HandleEvent`, `CommitFn`) is preserved. One new strict
flag is threaded through `pkg/config`.

### 4.1 #2139 — validate-then-commit-or-discard (transactional batch)

Reuse the existing candidate machinery; do **not** invent a new transaction
type. Rework `executeCommands` into a two-phase apply against the candidate:

1. **Pre-parse / pre-classify (before any candidate mutation).** Compile
   `pol.ThenCommands` into a typed plan: each entry is `{kind: set|delete,
   path: []string}`. An unknown command prefix, an unparseable `set`, or an
   unparseable `delete` makes the **whole plan invalid** — abort, log, bump
   `xpf_event_actions_rejected_total`, surface in status, and return without
   entering configure mode. This is the cheapest place to reject (no lock
   taken).
2. **Apply to candidate.** `EnterConfigure()`; apply every planned op to the
   candidate (`store.Set` / `store.Delete`). Any op error (e.g.
   `store.Set` rejects a value the parser accepted but the candidate
   doesn't) ⇒ `ExitConfigure()` (discard the candidate), log, bump
   rejected, return. **Do not commit a partial batch.**
   - Decision: a `delete` of a missing path stays *tolerated* (logged at
     Debug) — that is existing, intentional behavior (engine.go:335-338) and
     a missing delete target is not a half-applied batch. Document it
     explicitly so it is a deliberate exception, not the old blanket
     best-effort.
3. **Validate the whole candidate** via `store.CommitCheck()` before
   committing. If it fails, `ExitConfigure()` and reject. (Belt-and-braces:
   `Commit`/`commitFn` re-compile anyway, but CommitCheck lets us discard
   cleanly instead of relying on Commit's failure leaving the candidate —
   and gives a single reject path.)
4. **Commit** via `commitFn` (atomic commit+apply, #846) or `store.Commit`
   in the nil-commitFn test path, exactly as today. Success bumps
   `xpf_event_actions_committed_total`.

Why reuse the candidate, not a hand-rolled rollback: the candidate IS the
rollback. `EnterConfigure` clones `active`; discarding the candidate
(`ExitConfigure`) reverts everything with zero bespoke undo logic. This is
strictly simpler and matches Junos semantics (change-configuration is a
config transaction). The only subtlety is that we must classify-all *before*
mutating so we never enter a state where some ops are applied and we then
discover the batch is bad — but since discard reverts the whole candidate,
even a mid-apply failure (step 2) is safe; we still `ExitConfigure`. The
pre-classify (step 1) is an optimization + earlier operator feedback, not a
correctness requirement.

### 4.2 #2140 — split immutable config from runtime state; reconcile on Apply

Mirror `pkg/ipmon`'s reconcile-not-recreate. Introduce a per-policy runtime
state record and carry it forward across an `Apply` when the policy's
identity AND semantics are unchanged:

```
type policyRuntime struct {
    windows     map[string][]time.Time // event name -> sliding window
    lastTrigger time.Time
}
// engine field:
runtime map[string]*policyRuntime // keyed by policy NAME
```

`Apply` becomes reconcile:

```
next := make(map[string]*policyRuntime)
for _, pol := range policies {
    rev := policySemanticRevision(pol)         // see below
    if prev, ok := e.runtime[pol.Name]; ok && e.lastRev[pol.Name] == rev {
        next[pol.Name] = prev                  // CARRY FORWARD live counters
    } else {
        next[pol.Name] = &policyRuntime{windows: map[string][]time.Time{}}
    }
    nextRev[pol.Name] = rev
}
e.runtime = next   // policies absent from the new set drop their state
```

**Identity key (the design decision).** Policy **name** is the stable
identity that survives a reload (Junos `event-options policy <name>` —
operator-meaningful, stable across edits). But carrying `lastTrigger`
forward unconditionally would be wrong if the operator *changed* the
policy's match or action — a redefined policy should re-arm. So the carry is
gated on a **semantic revision**: a cheap deterministic hash of the
match/action-relevant fields (`Events`, sorted `AttributesMatch`,
`WithinClauses`, `ThenCommands`). If the revision matches, the policy is
"the same policy" and its cooldown/window memory is preserved; if it
changed, state is reset (re-arm). Removed policies drop their state (not in
`next`). This is exactly ipmon's `prev.cfg.MatchRPMProbe == pol.MatchRPMProbe`
test, generalized to the full match+action.

This also fixes the self-wipe: the engine's own remediation commit calls
`Apply` with the *same* policy set (same revision) → state carried forward →
`lastTrigger` survives → cooldown holds. (Edge case, called out by SMR
finding 2: if a remediation's `change-configuration` edits the
event-options stanza of the *triggering* policy itself, that policy's
revision changes and its state legitimately resets — a redefined policy
re-arms. That is correct; document it.)

**Prune-on-append (SMR finding 1).** `evaluateEvent` appends to
`windows[name][event]` (engine.go:130) BEFORE the cooldown / within checks,
and `pruneWindows` only runs when `withinMatches` reaches its tail
(engine.go:258). A perpetually-cooldown-suppressed event therefore appends
forever without pruning — a latent unbounded-growth leak the carry-forward
would preserve across reloads. Since this change owns this code, prune the
window on append (or immediately before the early returns) so a suppressed
event can never grow the window unboundedly. Cheap, removes the latent leak,
no behavior change for the matching cases.

The compiled-regex cache (`regexCache`, #2008 M7) is still rebuilt every
`Apply` (it is derived purely from `AttributesMatch`, cheap, and not runtime
state) — no change to the hot path.

### 4.3 #2141 — strict-validate malformed/unknown attributes-match at commit

Two coordinated edits, keeping the strict/lenient split that already exists:

1. **`pkg/config` validator.** Add strict checks to the commit path
   (compiler.go:690 region), gated by the existing `opts.lenient...` flag so
   only the strict (operator-authored) commit rejects; the LOAD/SyncApply
   tolerant path downgrades to a warning (boot-through, mirrors #2008 M7 /
   #2063). New rejects:
   - A line that does **not** parse into `<field> matches <pattern>` (no
     ` matches `, or no `.` in the field spec) — currently silently skipped.
   - A **field name** not in the known set (`test-owner`, `test-name`).
     Decision: maintain the known-field set in **one** exported place in
     `pkg/config` (e.g. `EventAttributesKnownFields`) so the validator and
     the runtime matcher's `switch` (engine.go:188-195) cannot drift — the
     same single-source-of-truth doctrine the parse seam already follows.
   - (Invalid regex is already rejected — unchanged.)
   Rename/extend `ValidateEventAttributesMatch` or add
   `ValidateEventAttributesMatchStrict`; the lenient variant keeps today's
   tolerance. Error messages are field-specific and name the offending line.
2. **`pkg/eventengine` runtime matcher.** With commit now rejecting
   malformed/unknown lines, the runtime `if !ok { continue }` (engine.go:180)
   and `default: continue` (193) can only be hit on the lenient LOAD path
   (a config persisted by an older binary). Decision: on the runtime path,
   a malformed/unknown line should fail the policy **CLOSED** (treat the
   constraint as unsatisfiable → policy does not trigger), NOT skip it open.
   Rationale: a dropped constraint broadens an automation that mutates
   config; #2124 doctrine says broadening is the dangerous direction.
   Concretely: a line that returns `ok=false`, or a field not in the known
   set, makes `attributesMatch` return `false` (with a throttled Warn), so
   the suspicious policy does not fire until the operator fixes it on the
   next strict commit. (This is a behavior change for legacy configs that
   booted through with a typo'd constraint — they will now *stop* firing
   rather than fire-on-everything. That is the safe direction and is
   surfaced via the boot-time warning the lenient compile already emits.)

   - **Open question for reviewers (OQ-2141):** fail-closed at runtime vs
     warn-and-skip. Recommendation: fail-closed (above). The counter-argument
     is "an upgraded node with a legacy typo'd policy silently stops
     remediating." Mitigations: the lenient compile already emits a
     boot-time warning naming the bad line; we add a counter
     (`xpf_event_attributes_match_invalid_total`). Net: a policy that
     *over-fires* (current behavior) is more dangerous than one that
     *stops* firing and is loudly flagged.

### 4.4 #2157 — fail-safe action queue with bounded retry + observability

Replace the drop-on-lock-held with a single-worker serialized queue:

- A buffered channel `actions chan plannedAction` (bounded, e.g. 64) plus a
  single goroutine `actionWorker` started in `New` (or lazily). `HandleEvent`
  no longer calls `executeCommands` inline; it enqueues the validated plan
  (built per §4.1's pre-classify, so a malformed action is rejected *before*
  queuing — never occupies a slot).
- The worker pulls one action at a time and runs the §4.1 apply. This makes
  all remediation **serial** by construction — the cross-probe
  `EnterConfigure` race disappears (only the worker ever enters configure
  for the engine).
- **Lock-held handling.** If `EnterConfigure` fails with a lock-held error,
  the worker does NOT drop: it retries with bounded exponential backoff
  (e.g. 200 ms → cap 5 s) up to a deadline/attempt cap, bumping
  `xpf_event_actions_retried_total`. On final give-up it bumps
  `xpf_event_actions_dropped_total` and logs. (A non-lock error — e.g.
  CommitCheck reject — is a *permanent* failure: do not retry, bump
  rejected.)
  - Distinguish lock-held from other errors: `EnterConfigure` returns a
    plain `fmt.Errorf("configuration is locked by another user")`. Decision:
    add a sentinel `ErrConfigLocked` in `pkg/configstore` and return it from
    `EnterConfigureSession` so the engine can `errors.Is` it instead of
    string-matching (the engine already string-matches "path not found" at
    engine.go:336 — we avoid adding a second fragile string match). This is a
    small, safe configstore change.
- **Bounded queue / overload.** If the queue is full (lock held a long
  time), enqueue drops the OLDEST queued action for the same policy
  (dedup-by-policy: a newer trigger of the same policy supersedes an older
  queued one — there is no value in applying a stale remediation twice) and
  bumps `xpf_event_actions_dropped_total{reason="queue_full"}`. Dedup-by-policy
  also naturally bounds the queue to one pending action per policy.
- **Cooldown arm timing (SMR finding 3 — design refinement).** Today the
  cooldown is armed at *evaluate* time (`e.lastTrigger[pol.Name] = now`,
  engine.go:140), before the action runs. With an async queue that can DROP
  an action (lock held past deadline), arming at evaluate means a *dropped*
  action still suppresses the policy for 30 s even though nothing was
  applied — which defeats the #2157 "don't silently lose remediation"
  guarantee. Decision: **arm the cooldown on SUCCESSFUL commit, not at
  evaluate.** `evaluateEvent` still *checks* the cooldown (to avoid
  enqueuing a flood), but the timestamp is written by the worker after a
  successful `commitFn`. A dropped/rejected action does NOT consume the
  cooldown, so the next legitimate trigger can retry. The queue's
  dedup-by-policy + the cooldown *check* at evaluate still bound a flapping
  probe (at most one queued action per policy; subsequent triggers within
  cooldown are filtered at evaluate). This is the one genuine behavior
  refinement vs the literal current code; it is required for #2157's
  no-silent-loss property to hold.
- **Counters** (Prometheus, via `pkg/api` collector, names TBD-reviewed):
  `xpf_event_actions_committed_total`, `_rejected_total`, `_retried_total`,
  `_dropped_total{reason}`, and a `xpf_event_action_queue_depth` gauge.
  These make the silent loss observable — the explicit ask in #2157.
- **Shutdown.** The worker drains/stops on a `Close()`/context cancel wired
  from the daemon's existing event-engine lifecycle. Decision: add an engine
  `Close()` called from daemon shutdown; the existing `New` site
  (daemon_run.go:953) gets a paired stop.

  - **Open question (OQ-2157):** queue+retry (recommended) vs "transient
    transaction that serializes with operator sessions." The latter would
    need a configstore primitive that lets a non-interactive committer apply
    a delta without taking the operator-visible candidate lock — a much
    bigger, riskier change to the candidate model (two writers to one
    candidate). The queue is bounded, observable, and contained to
    `pkg/eventengine` + one sentinel error. Recommendation: queue+retry.

### 4.5 Concurrency model (ties #2140 + #2157 together)

- Evaluation (`evaluateEvent`) stays under `e.mu` and is the only place that
  reads/writes `runtime` (windows/lastTrigger) — unchanged locking, now on
  the reconciled map.
- Command execution moves OFF the `HandleEvent` caller goroutine onto the
  single `actionWorker`. So: many probe goroutines may call `HandleEvent`
  concurrently (each grabs `e.mu` briefly to evaluate + enqueue), but only
  one goroutine ever drives configure/commit. This removes the lock race
  *and* keeps the existing "don't hold e.mu across commit" invariant
  (the worker holds no engine lock while in configure/commit).

## 5. Alternatives rejected

- **#2139 manual rollback (snapshot the candidate, replay deletes on
  failure).** Rejected: the candidate already is the snapshot; `ExitConfigure`
  is the rollback. Manual replay is more code and more bug surface.
- **#2139 commit-per-command.** Rejected: that is the opposite of atomic and
  is exactly the current bug.
- **#2140 persist runtime state to disk.** Rejected: the bug is about a
  *reload* (in-memory `Apply`), not a *restart*. ipmon-style in-memory
  carry-forward is sufficient and matches the established pattern. (A daemon
  restart legitimately re-arms cooldowns; that is acceptable and Junos-ish.)
- **#2140 stop calling Apply on unrelated commits (hash-gate it).** Partially
  attractive (and we *could* additionally hash-gate to avoid even the
  reconcile churn), but the reconcile is the correct fix regardless: the
  self-triggered commit applies the *same* config, so a pure hash-gate would
  still need the reconcile to be correct for genuine same-policy reloads.
  Reconcile subsumes it. We may add a cheap "policies unchanged → skip
  rebuild" fast path as an optimization, not the primary fix.
- **#2141 warn-and-skip at runtime only (no commit reject).** Rejected as
  primary: leaves the fail-open commit. Strict-reject-at-commit is the
  operator-visible fix; fail-closed-at-runtime is the defense for legacy
  loads.
- **#2157 transient non-interactive transaction.** Rejected (see OQ-2157):
  too large a change to the candidate ownership model for a MEDIUM bug.
- **Four separate PRs.** Rejected: they re-touch the same functions and the
  designs interlock (queue == transaction path; identity key == strict
  validate key). One coordinated PR is cheaper and self-consistent. (If the
  reviewer prefers, #2141 — the smallest, ENGINEER-NOW-classed validator
  tightening — could land first as a standalone, with the other three as the
  main PR. Noted as a split option in §11.)

## 6. Files touched

- `pkg/eventengine/engine.go` — split runtime state from config; reconcile
  `Apply`; pre-classify + transactional `executeCommands`; action queue +
  worker + backoff; counters; `Close()`. (Primary.)
- `pkg/eventengine/engine_test.go` — new tests (§7). Existing #2008 M7
  attributesMatch tests preserved (the runtime fail-closed change touches
  `TestAttributesMatch_UnknownFieldIgnored` — that test asserts the OLD
  fail-open behavior and **must be updated** to assert fail-closed; call it
  out in the PR).
- `pkg/eventengine/README.md` — document transactional batch, cooldown
  survives reload (and arms on successful commit), strict attributes-match,
  queue/retry, new counters. Specifically update README.md:34 ("Other
  attributes are silently ignored") and the gotchas section — the runtime is
  now fail-closed on malformed/unknown lines, and the cooldown survives a
  reload.
- `pkg/config/event_options_match.go` — strict validator (malformed +
  unknown-field reject) + exported `EventAttributesKnownFields` SSOT.
- `pkg/config/event_options_match_test.go` — strict reject tests + lenient
  downgrade test.
- `pkg/config/compiler.go` — wire strict vs lenient at the existing
  `ValidateEventAttributesMatch` call site (compiler.go:690).
- `pkg/configstore/store.go` — `ErrConfigLocked` sentinel from
  `EnterConfigureSession` (small, additive).
- `pkg/api/metrics*.go` + collector — new `xpf_event_actions_*` counters and
  queue-depth gauge (follow the existing const-metric pattern). The engine
  has no collector hook today: add a small `Engine.Stats()` accessor so
  `pkg/api` reads the counters without a package global (SMR finding 5).
- `pkg/daemon/daemon_run.go` — pair the engine `New` with a `Close()` on
  shutdown (queue worker lifecycle).

Blast radius is small and contained: the only external callers of the engine
are `daemon_run.go` (New/Apply/HandleEvent wiring) and `daemon_apply.go:1213`
(Apply on commit). The public method signatures are unchanged except the
additive `Close()`.

## 7. Test strategy

All unit-level (control-plane, no smoke). Run with `-race` — concurrency is
the heart of #2157/#2140.

- **#2139:** plan with two valid + one invalid command in the middle →
  assert NO candidate committed (active config unchanged) and
  `rejected_total` incremented and nothing applied. A valid-only batch →
  committed. A `delete` of a missing path inside an otherwise-valid batch →
  still commits (documented exception).
- **#2140:** policy with a harmless `change-configuration` + cooldown;
  fire the same event twice with no time advance, with the engine's `Apply`
  invoked between them (simulating the self-triggered commit) → second
  trigger suppressed. Separately: an unrelated `Apply` (different policy
  set including this policy unchanged) preserves `lastTrigger`. Changing the
  policy's `ThenCommands` (revision change) resets it. Removing the policy
  drops its state.
- **#2141:** `ValidateEventAttributesMatchStrict` rejects
  `"x.test-ower matches ^y$"` (unknown field) and `"x.test-owner foo"`
  (no ` matches `) with field-specific errors; the lenient variant
  downgrades to a warning. Runtime `attributesMatch` returns **false**
  (fail-closed) for an unknown field / malformed line (update the existing
  `TestAttributesMatch_UnknownFieldIgnored`). SSOT: a test asserts the
  validator's known-field set equals the matcher's `switch` cases (drift
  guard).
- **#2157:** with a held lock (`store.EnterConfigure()` from the test before
  triggering), an event action is queued and retried, then committed once the
  test releases the lock; assert `retried_total > 0` and eventual commit.
  Lock held past the deadline → `dropped_total` incremented, action not
  applied. Concurrency: spawn N goroutines calling `HandleEvent` for
  distinct triggering policies under `-race` → all serialize through the
  worker, no race, each commits once (or queues). Queue-full → oldest
  same-policy action superseded, `dropped_total{reason=queue_full}`.

## 8. Invariants

- `executeCommands`/worker never commits a partially-applied batch: either
  the whole plan commits or nothing does (candidate discarded).
- The engine holds no engine-level lock (`e.mu`) while in configure/commit
  (preserves the #846 deadlock-avoidance contract).
- Only the single `actionWorker` goroutine ever enters configure mode on
  behalf of the engine (no self-induced lock race).
- Runtime cooldown/window state is preserved across an `Apply` iff
  `(name, semanticRevision)` is unchanged; dropped for removed/changed
  policies.
- The known attributes-match field set has exactly one definition
  (`pkg/config`), consumed by both the validator and the runtime matcher.
- Strict commit rejects malformed/unknown attributes-match; lenient
  LOAD/SyncApply downgrades to a warning (no boot blackout, mirrors #2008
  M7 / every sibling validator).
- The action queue is bounded; loss is always counted, never silent.

## 9. Risk

- **Behavior change (#2141 runtime fail-closed):** a legacy config that
  booted with a typo'd constraint will now *stop* firing that policy instead
  of over-firing. This is the safe direction but is a behavior change for
  existing deployments — must be called out in the PR + README + a boot
  warning. Mitigation: the lenient compile already warns at boot; add a
  counter.
- **Cooldown carry-forward correctness (#2140):** if the semantic-revision
  hash is too coarse (misses a relevant field) a redefined policy could keep
  a stale cooldown; if too fine (includes an irrelevant field) it re-arms
  on noise. Mitigation: hash exactly the match/action fields, with a
  drift-guard test enumerating them; default to *reset* if in doubt (resetting
  is the conservative direction — it never suppresses a legitimate trigger).
- **Queue starvation (#2157):** a permanently-held operator lock means
  remediation is deferred until the deadline then dropped (counted). This is
  strictly better than today (silent immediate drop) and is observable. The
  operator holding the lock is the operator who can fix it.
- **Async execution (#2157):** moving command execution off the caller
  goroutine changes timing — a test that assumed synchronous apply after
  `HandleEvent` must wait on the counter/commit. Existing tests use
  `commitFn=nil` and call `attributesMatch` directly, so they are unaffected;
  new tests synchronize on counters.
- **configstore sentinel (`ErrConfigLocked`):** additive; the only behavior
  change is the error *value* (string preserved). Low risk; covered by a
  test asserting `errors.Is`.

## 10. Rollout / validation

- `make test` + `go test -race ./pkg/eventengine/... ./pkg/config/... ./pkg/configstore/...`.
- Control-plane only — no cluster smoke required per all four issues'
  disposition (review-class). The change does not touch forwarding, HA,
  VRRP, or session sync, so `make test-failover` is **not** required.
- Reviewer quad (Codex + AGY + Claude SMR + Copilot) per engineering-style;
  emphasis on the concurrency (`-race`) and the #2141 behavior-change
  call-out.

## 11. Disposition

- **#2139 — PLAN-READY.** Transactional batch via validate-then-commit-or-
  discard on the existing candidate; pre-classify before mutate; discard on
  any failure. Reuses configstore, no new transaction primitive.
- **#2140 — PLAN-READY.** Reconcile-not-recreate runtime state keyed by
  `(policy name, semantic revision)`, copying the proven `pkg/ipmon` pattern.
  Fixes both the self-wipe and the unrelated-commit wipe.
- **#2141 — PLAN-READY.** Strict-reject malformed/unknown attributes-match at
  commit (lenient downgrade on LOAD); fail-CLOSED at runtime for legacy
  loads, per #2124 doctrine. Single SSOT for the known-field set.
- **#2157 — PLAN-READY.** Bounded action queue + single worker + backoff
  retry on `ErrConfigLocked` + drop/retry/commit counters; eliminates the
  cross-probe lock race as a side effect. Recommend queue+retry over a new
  configstore transaction primitive.

Recommended sequencing for /engineer: land as **one coordinated PR**
(#2139+#2140+#2157 interlock through the queue/transaction path; #2141 rides
along cleanly). Acceptable alternative: split #2141 (smallest, validator-only,
ENGINEER-NOW) as a fast first PR, with the other three as the main PR — noted
for the engineer's discretion.

## Reviewer verdicts

- **Claude SMR r1 (`claude-smr-plan-r1.md`): PLAN-READY (all four), pending
  three §4 refinements — now folded.** SMR verified every claim against
  source (the #2140 self-wipe end-to-end, the #2157 cross-probe goroutine
  race, #2139 partial-commit, the ipmon precedent) and explicitly refuted
  the directive's "#2140 reload may be rare/by-design" PLAN-KILL probe (the
  reload is the common path). Three refinements raised and folded:
  prune-window-on-append (latent leak this change owns), self-edit re-arm
  documentation, and — the one genuine design refinement — **arm the
  cooldown on successful commit, not at evaluate**, so a dropped/queued
  action does not consume the cooldown (required for #2157's no-silent-loss
  guarantee). With these folded the plan is converged.
- **Codex: companion lane degraded this session** (per the research
  directive, a companion-free converged plan with a rigorous self-review is
  acceptable). The SMR pass was deliberately hostile (default-refute,
  source-verified, PLAN-KILL probes run and refuted) to stand in for the
  missing second lane. If a Codex plan pass is run before /engineer, fold its
  verdict here.
