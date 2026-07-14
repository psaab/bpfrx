# codex-review-159 - event-options automation queue/lifecycle audit

Agent: codex
Base checkout: /home/ps/git/codex-bpfrx
Base commit: fc6049c05
Date: 2026-07-01

## Duplicate Suppression

Read the audit instruction file at `/home/ps/git/agy-do-review-audit.txt`.
Scanned prior `/tmp/codex-review*.md`, `/tmp/agy-review*.md`, and repo issue
history docs for eventengine/event-options/RPM automation duplicates.

Known closed or already-covered event-options classes deliberately avoided:

- #2139 transactional batch / partial commit.
- #2140 cooldown survives same-revision Apply.
- #2141 malformed/unknown attributes-match fail-closed.
- #2157 held config lock retry / bounded queue.
- #2216 temporal window unbounded growth and one-event-many-policy drop.
- #2868 cancellable remediation commit.
- #2869 FIFO supersede / single drop count.
- #2890 retry timer Stop on engine shutdown.

This report focuses on second-order gaps in the current implementation.

## Module Checklist

Inspected modules/features:

1. `pkg/eventengine/engine.go`: Apply/revision model, queue, worker, retry,
   commit, cooldown, attribute matching, within-window logic.
2. `pkg/eventengine/*_test.go`: existing regression scope and blind spots.
3. `pkg/eventengine/README.md`: stated invariants versus current code.
4. `pkg/config/compiler_services.go`: event-options parsing.
5. `pkg/config/schema_system.go`: schema validation shape.
6. `pkg/config/event_options_match.go`: attributes-match parser and validator.
7. `pkg/daemon/daemon_run.go` and `pkg/daemon/daemon_apply.go`: lifecycle and
   day-2 apply wiring.
8. `pkg/rpm/rpm.go`: callback registration, first-cycle event emission, probe
   loop ordering.
9. `pkg/api/metrics_system.go` and `pkg/api/metrics_descriptors.go`:
   event-options observability.

Temporary executable probes run and removed:

- `go test ./pkg/eventengine -run TestCodexAudit159 -count=1`
  - Proved queued actions commit after policy removal.
  - Proved queued actions use old commands after same-name redefinition.
  - Proved a duplicate queued before first commit bypasses cooldown recheck.
- `go test ./pkg/eventengine -run TestCodexAudit159AttributeEventPrefixIgnored -count=1`
  - Proved the event prefix in `attributes-match` is ignored.

The temporary test file was deleted. `git status --short` was clean before
writing this report.

## High Confidence Findings

### H1 - Queued remediation commits after its policy is removed

Evidence:

- `plannedAction` stores only `policyName` and `ops`, with no policy revision or
  existence token: `pkg/eventengine/engine.go:104-110`.
- `Apply(nil)` drops runtime/semRev maps for removed policies:
  `pkg/eventengine/engine.go:272-294`.
- `runAction` applies the action without checking whether the policy still
  exists or has the same semantic revision: `pkg/eventengine/engine.go:525-535`.
- `armCooldown` silently no-ops if runtime was removed:
  `pkg/eventengine/engine.go:691-699`.

Runtime trace:

1. Policy `p` triggers while an operator holds the config lock.
2. Worker picks the action and retries on `ErrConfigLocked`.
3. Operator commits a config that removes `event-options policy p`; `Apply(nil)`
   deletes runtime state.
4. Lock is released.
5. Worker commits the old pre-classified commands even though no active policy
   authorizes them.

Impact:

An operator can remove an unsafe automation policy and still have its old
remediation mutate config after removal.

Suggested issue:

Track policy generation in `plannedAction` and revalidate under `e.mu` before
each apply. Drop and count stale actions if policy is absent or revision-mismatched.

### H2 - Same-name policy redefinition can commit the old command set

Evidence:

- Same data path as H1: `plannedAction` lacks `semRev`.
- `Apply` resets runtime on semantic change but does not invalidate queued or
  in-flight actions: `pkg/eventengine/engine.go:283-291`.

Runtime trace:

1. Policy `p` with `ThenCommands = old` triggers under held config lock.
2. Operator redefines `p` with `ThenCommands = new`.
3. `Apply` creates a fresh runtime for the new revision.
4. Old action eventually commits `old`, not `new`.

Impact:

Same policy name becomes a stale authorization channel. This is worse than a
duplicate commit because the committed config can contradict the active
event-options policy.

Suggested issue:

Add `policyRevision string` to `plannedAction`, compare against `e.semRev[name]`
immediately before `applyOnce`, and drop stale actions with a new metric reason
such as `stale_revision`.

### H3 - Queued duplicate can bypass cooldown after first commit

Evidence:

- Cooldown is checked only in `evaluateEvent`: `pkg/eventengine/engine.go:742-746`.
- It is armed only after the worker commits: `pkg/eventengine/engine.go:531-534`.
- `runAction` does not re-check cooldown before applying:
  `pkg/eventengine/engine.go:525-535`.

Runtime trace:

1. First event triggers policy `p`; worker is blocked retrying on held config
   lock, so cooldown is not armed yet.
2. A second event for `p` arrives and queues while first action is in flight.
3. Lock releases; first action commits and arms cooldown.
4. Already-queued second action commits immediately anyway because the worker
   does not re-check cooldown.

Impact:

The advertised "same policy will not trigger more than once in any 30s window"
(`pkg/eventengine/README.md:181-184`) is false under lock contention or slow
commit/apply. Automated remediations can double-commit back-to-back.

Suggested issue:

Before `applyOnce`, re-check both revision and cooldown under the engine lock.
If the action is now cooled down, drop it with an explicit counter.

### H4 - `attributes-match` ignores the event name prefix

Evidence:

- Parser takes only the field after the last dot:
  `pkg/config/event_options_match.go:51-67`.
- Runtime switch matches only `test-owner`/`test-name` from the current event:
  `pkg/eventengine/engine.go:801-807`.
- Strict validator checks field and regex but not that the left event name is
  one of the policy events or the current runtime event:
  `pkg/config/event_options_match.go:124-148`.

Runtime trace:

1. Policy has `events [ event_a event_b ]`.
2. Policy has `attributes-match "event_a.test-owner matches ^owner$"`.
3. Runtime receives `event_b` with `TestOwner=owner`.
4. `eventMatches` accepts `event_b`; `attributesMatch` ignores `event_a` and
   checks only `test-owner`; policy fires for `event_b`.

Impact:

Per-event attributes can accidentally constrain or permit the wrong event in a
multi-event policy. This is a feature-completeness and correctness gap versus
Junos-style event attribute scoping.

Suggested issue:

Parse `attributes-match` into `(eventName, field, pattern)`, validate eventName
against policy events at commit, and at runtime require it to match `ev.Name`.

### H5 - Day-2 commit adding the first event-options policy never starts the engine

Evidence:

- Startup creates `d.eventEngine` only if the boot config already has policies:
  `pkg/daemon/daemon_run.go:967-980`.
- Day-2 apply only calls `Apply` if `d.eventEngine != nil`:
  `pkg/daemon/daemon_apply.go:1357-1360`.
- No other `eventEngine` constructor or reconcile function exists in
  `pkg/daemon` (`rg eventEngine`).

Runtime trace:

1. Daemon boots without `event-options`.
2. Operator commits first `event-options policy`.
3. Config compiles and applies.
4. `d.eventEngine` is nil, so no engine is created and no RPM callback is
   registered.
5. The policy is inert until daemon restart.

Impact:

Day-2 enablement of automation silently fails. This is the inverse of the LLDP
commented pattern nearby, where the manager is always created to support day-2
enablement.

Suggested issue:

Introduce `reconcileEventOptions(cfg)` that lazily creates the engine, registers
or clears the RPM callback, applies policy changes, and stops/closes the worker
when policies are removed.

### H6 - Boot wires RPM probes before registering the event callback

Evidence:

- Startup calls `d.reconcileRPM(cfg)` at `pkg/daemon/daemon_run.go:948-949`.
- Event engine and RPM callback are registered later:
  `pkg/daemon/daemon_run.go:967-979`.
- `rpm.Apply` starts probe goroutines and immediately runs the first probe:
  `pkg/rpm/rpm.go:326-346` and `pkg/rpm/rpm.go:383-399`.
- RPM emits `ping_probe_failed`, `ping_test_failed`, and `ping_test_completed`
  through the callback only if one is already installed:
  `pkg/rpm/rpm.go:272-278`, `pkg/rpm/rpm.go:489`,
  `pkg/rpm/rpm.go:541-549`.

Runtime trace:

1. Boot config contains RPM and event-options.
2. `reconcileRPM` starts probe goroutines.
3. First probe cycle runs immediately.
4. Any failure/completion before `SetEventCallback` is dropped.
5. Event-options may not remediate until the next test interval or until a
   future status transition.

Impact:

Boot-time failover automation can miss the exact first edge it exists to handle.
For long `test-interval` values, that can materially delay remediation.

Suggested issue:

Construct and register event engine callback before starting RPM probes, or make
RPM retain/replay the latest initial transition when a callback is installed.

### H7 - Shutdown can silently discard queued remediations

Evidence:

- `actionWorker` selects `stopCh` and returns before draining queued actions:
  `pkg/eventengine/engine.go:508-518`.
- `enqueue` drops silently on stop: `pkg/eventengine/engine.go:431-436`.
- Metrics include no shutdown/stale/drop reason except lock-held and queue-full:
  `pkg/eventengine/engine.go:73-80`,
  `pkg/api/metrics_descriptors.go:473-481`.

Runtime trace:

1. One or more actions are queued.
2. Daemon begins shutdown and closes `stopCh`.
3. Worker select may choose `<-stopCh` before reading buffered actions.
4. Buffered remediations are lost without counter/log.

Impact:

The README says loss is counted and never silent for the fail-safe queue
(`pkg/eventengine/README.md:132-141`), but shutdown drops are not observable.

Suggested issue:

On Close, either drain and apply already-queued actions until empty or drain and
count them under a `shutdown` drop reason.

### H8 - After `Close`, `HandleEvent` can enqueue into a stopped worker

Evidence:

- `Close` closes `stopCh` and waits; `startOnce` is permanently consumed:
  `pkg/eventengine/engine.go:397-409`.
- `HandleEvent` always calls `startOnce.Do(e.startWorker)` and then evaluates:
  `pkg/eventengine/engine.go:373-388`.
- In `enqueue`, when `stopCh` is closed and the buffered channel has capacity,
  both the send and `<-stopCh` cases are ready; Go chooses randomly:
  `pkg/eventengine/engine.go:431-436`.

Runtime trace:

1. Engine has been closed.
2. A late RPM callback or test invokes `HandleEvent`.
3. No worker can restart because `startOnce` already ran.
4. `enqueue` may still send into `actions`, incrementing `QueueDepth`.
5. The queued action will never be processed.

Impact:

Late events after shutdown can create misleading queue depth and stale buffered
actions. This is mostly lifecycle-hardening, but automation code should be
deterministic around shutdown.

Suggested issue:

Have `HandleEvent` fast-return when stopped, using an atomic closed flag or a
non-racy stop check before evaluation/enqueue.

### H9 - Event-options removal leaves an idle callback/worker installed

Evidence:

- Day-2 apply with empty policies calls `eventEngine.Apply(nil)` if an engine
  already exists: `pkg/daemon/daemon_apply.go:1357-1360`.
- `Apply(nil)` clears runtime but does not close the worker or unregister RPM
  callback: `pkg/eventengine/engine.go:272-321`.
- RPM callback registration has only `SetEventCallback(fn)`:
  `pkg/rpm/rpm.go:197-202`.

Runtime trace:

1. Boot or earlier commit had event-options.
2. Operator removes all policies.
3. Engine remains registered with RPM forever.
4. Every RPM event still calls `HandleEvent` and may start/keep an idle worker,
   even though the feature is disabled.

Impact:

This is not a packet-drop bug, but it creates stale control-plane work and makes
metrics/lifecycle state ambiguous. It also contributes to H8 during shutdown.

Suggested issue:

`reconcileEventOptions` should unregister the callback and close the engine when
the active config has zero event policies.

### H10 - Event remediation commits have no audit description

Evidence:

- Daemon passes `commitAndApply(ctx, comment, false)` through the event engine:
  `pkg/daemon/daemon_run.go:973-975`.
- `applyOnce` always calls `e.commitFn(ctx, "")`:
  `pkg/eventengine/engine.go:638-640`.
- `commitAndApply` uses `CommitWithDescription` only when comment is non-empty:
  `pkg/daemon/daemon_apply.go:201-205`.

Runtime trace:

1. Event policy fires and mutates config.
2. Commit history receives a normal commit with no description.
3. Operator cannot tell from rollback/history which event policy made the
   change or why.

Impact:

For a security appliance/router, autonomous configuration changes need strong
forensics. Empty descriptions make event-triggered changes look like ordinary
unattributed commits.

Suggested issue:

Pass a deterministic description such as
`event-options policy <name>: <event>/<owner>/<test>` and consider including a
hash/count of the command batch.

### H11 - Event-options parser silently converts bad numeric clauses to zero

Evidence:

- `within` seconds parse ignores `Atoi` errors and leaves zero:
  `pkg/config/compiler_services.go:1629-1633`.
- `trigger on/until` parse ignores `Atoi` errors and leaves zero:
  `pkg/config/compiler_services.go:1637-1663`.
- Schema only declares generic placeholders, no integer/range validator:
  `pkg/config/schema_system.go:872-881`.

Runtime trace:

1. Operator writes `within bogus { trigger on typo; }`.
2. Compiler accepts it as `Seconds=0`, `TriggerOn=0`, `TriggerUntil=0`.
3. `withinMatches` sees no active trigger constraints and returns true:
   `pkg/eventengine/engine.go:861-887`.

Impact:

A typo in a temporal gate can turn a gated remediation into an always-triggering
one. That is fail-open automation.

Suggested issue:

Strictly validate positive integer `within`, `trigger on`, and `trigger until`
values at commit. Lenient load can downgrade if needed.

### H12 - Negative and huge `within` values are accepted

Evidence:

- Same parser/schema gaps as H11.
- Runtime multiplies unbounded `int` seconds by `time.Second`:
  `pkg/eventengine/engine.go:861-863` and `pkg/eventengine/engine.go:899-903`.

Runtime trace:

1. Operator or loaded config sets `within -1` or a huge integer.
2. Negative duration makes the window nonsensical; huge values can overflow
   `time.Duration`.
3. Trigger and pruning behavior becomes implementation-dependent rather than
   commit-rejected.

Impact:

Temporal failover policy should have deterministic bounds. Overflow/negative
time gates are a correctness and security hardening gap.

Suggested issue:

Gate seconds to a sane positive range, e.g. `1..86400`, and reject anything
that cannot be represented as `time.Duration`.

### H13 - A clause can specify both `trigger on` and `trigger until`

Evidence:

- Compiler fills both fields when both tokens exist:
  `pkg/config/compiler_services.go:1637-1663`.
- Runtime applies both tests as an AND:
  `pkg/eventengine/engine.go:872-884`.

Runtime trace:

1. Config says `within 30 { trigger on 3; trigger until 4; }`.
2. Runtime fires only while count is `>=3` and `<4`.
3. This creates a narrow one-count band that is probably not what an operator
   intended and is not surfaced as ambiguous.

Impact:

Ambiguous automation triggers should fail commit, not rely on accidental AND
semantics.

Suggested issue:

Reject a single `within` clause that has both `trigger on` and `trigger until`,
or document and test the intended combined semantics.

### H14 - Attribute matching cannot express common RPM event attributes

Evidence:

- Known fields are only `test-owner` and `test-name`:
  `pkg/config/event_options_match.go:33-36`.
- RPM events carry only those fields today:
  `pkg/rpm/rpm.go:113-117`.

Impact:

Compared with a vSRX/Junos event-options model, this cannot match useful
attributes such as probe target, routing instance, destination interface,
result status, loss threshold, RTT/jitter, or failure reason. Operators must
encode many distinct probe names instead of matching attributes.

Suggested issue:

Expand `rpm.Event` and attributes-match SSOT to include routing-instance,
target, probe-type, status, failure kind, and measured latency fields.

## Medium Confidence Findings

### M1 - `trigger on N` can retrigger continuously after the threshold

Evidence:

- Runtime checks `count < TriggerOn` and otherwise allows the policy:
  `pkg/eventengine/engine.go:872-876`.
- It does not track a crossing edge for the window.

Runtime trace:

1. `trigger on 3` fires when the third event lands.
2. After cooldown expires but the window still contains at least three events,
   the next event also fires.
3. The trigger is level-triggered, not edge-triggered.

Why medium:

This may be intended, but Junos-style "trigger on" often reads as threshold
crossing, not level condition. It needs explicit semantics and tests.

Suggested issue:

Document and regression-test edge versus level semantics; if edge is intended,
record per-clause last-fired count/window anchor.

### M2 - `trigger until N` likely excludes the Nth event

Evidence:

- Current event is appended before `withinMatches`:
  `pkg/eventengine/engine.go:733-738`.
- `trigger until N` returns false when `count >= N`:
  `pkg/eventengine/engine.go:879-883`.

Runtime trace:

For `trigger until 1`, the first event makes count=1 and the policy does not
fire at all.

Why medium:

If intended semantics are "fire until N occurrences have happened, excluding
the Nth", this is correct. If operator expectation is "fire through the Nth",
it is off by one.

Suggested issue:

Pin Junos parity for `trigger until` and add boundary tests for N=1 and N=2.

### M3 - Multiple `within` clauses use undocumented AND semantics

Evidence:

- Runtime loops all clauses and returns false on any failed clause:
  `pkg/eventengine/engine.go:861-887`.
- README does not state how multiple within clauses compose.

Impact:

If Junos treats multiple within clauses as independent event sequences or OR
alternatives, this implementation under-fires.

Suggested issue:

Research Junos semantics for multiple `within` clauses and document/test the
chosen behavior.

### M4 - Event window pruning retains burst capacity forever

Evidence:

- Pruning uses `timestamps[:0]` and stores the resulting slice:
  `pkg/eventengine/engine.go:910-917`.

Runtime trace:

1. A flapping probe produces a large burst.
2. Pruning reduces length but retains the backing array capacity.
3. Memory high-water remains until policy revision/removal.

Impact:

Closed #2216 fixed unbounded length, but not retained capacity. On a long-lived
router, bursts can leave unnecessary heap retained.

Suggested issue:

When `cap(timestamps)` is much larger than retained length, allocate a compact
slice or use a ring buffer.

### M5 - `evaluateEvent` does O(policies * clauses * window)` work under one mutex

Evidence:

- `evaluateEvent` holds `e.mu` for the entire policy iteration:
  `pkg/eventengine/engine.go:707-709`.
- For each matching policy, `withinMatches` scans timestamps:
  `pkg/eventengine/engine.go:859-870`.

Impact:

High RPM event rates plus long windows can serialize all RPM event callbacks on
one lock and produce latency spikes in the control plane.

Suggested issue:

Use per-policy locks or per-policy ring counters, and index policies by event
name to avoid scanning unrelated policies.

### M6 - Policy lookup is a linear scan on every event

Evidence:

- `evaluateEvent` iterates every policy and `eventMatches` iterates every event
  name: `pkg/eventengine/engine.go:713-718` and `pkg/eventengine/engine.go:760-768`.

Impact:

This is acceptable for a handful of policies, but router automation configs can
grow. It also increases lock hold time from M5.

Suggested issue:

At `Apply`, build `map[eventName][]policyRuntimeRef` and evaluate only policies
subscribed to the incoming event.

### M7 - Commit path compiles/checks the candidate twice

Evidence:

- Event engine calls `CommitCheck` before commit:
  `pkg/eventengine/engine.go:622-627`.
- Daemon `commitAndApply` then runs device-map preflight on `CompileCandidate`
  and `store.Commit`: `pkg/daemon/daemon_apply.go:187-205`.

Impact:

Every automated remediation pays extra compile/preflight cost while holding the
config lock. This is not a correctness bug, but it matters under flapping
failure automation.

Suggested issue:

Add a daemon commit hook that accepts an already-checked candidate or make the
event engine rely on `Commit` atomicity after pre-classification.

### M8 - Event engine holds the config lock while waiting for apply semaphore

Evidence:

- `applyOnce` enters configure before calling `commitFn`:
  `pkg/eventengine/engine.go:591-599`.
- `commitFn` is daemon `commitAndApply`, which first acquires `applySem`:
  `pkg/daemon/daemon_apply.go:158-184`.

Runtime trace:

1. Event worker enters configure and edits candidate.
2. Another apply is already holding `applySem`.
3. Event worker waits for `applySem` while holding the config lock.
4. Operator sessions cannot enter configure during that wait.

Impact:

This is a control-plane priority inversion. It may be necessary for atomicity,
but it should be documented and bounded.

Suggested issue:

Measure worst-case wait and consider acquiring apply serialization before
EnterConfigure for event remediations.

### M9 - Missing-delete tolerance uses a string match

Evidence:

- The exception checks `strings.Contains(err.Error(), "path not found")`:
  `pkg/eventengine/engine.go:600-612`.

Impact:

Changing configstore error wording can turn a tolerated Junos delete into a
batch reject, or accidentally tolerate a different error containing that text.

Suggested issue:

Expose and use a typed/sentinel configstore error for missing delete path.

### M10 - Runtime attributes-match cache miss recompiles every event

Evidence:

- On cache miss, `attributesMatch` compiles the regex but never stores it:
  `pkg/eventengine/engine.go:815-827`.

Impact:

Normal strict paths cache at Apply, so this is mostly tolerant-load/defensive
path overhead. Still, a legacy config with many events can repeatedly compile.

Suggested issue:

Store successful lazy compiles back into `regexCache` under lock or remove the
lazy compile path and fail closed consistently.

### M11 - Global invalid-attributes warning throttle can hide distinct policies

Evidence:

- One `lastInvalidWarn` timestamp throttles all policies:
  `pkg/eventengine/engine.go:836-847`.

Impact:

A noisy bad policy can suppress warnings for a second bad policy for 10s. The
counter increments, but logs lose policy-level visibility.

Suggested issue:

Throttle by `(policy, attr, reason)` or include sampled suppressed counts.

### M12 - Event-options metrics are global, not policy-labelled

Evidence:

- Stats are aggregate counters only: `pkg/eventengine/engine.go:73-80`.
- Prometheus descriptors for event actions have no `policy` label:
  `pkg/api/metrics_descriptors.go:450-499`.

Impact:

Operators can see that automation is dropping/retrying/rejecting, but not which
policy is failing without log correlation.

Suggested issue:

Add bounded-cardinality policy-labelled counters or a top-N/last-error status
endpoint for event-options policies.

## Low Confidence / Triage Findings

### L1 - Event policy names are assumed unique but not validated in this compiler

Evidence:

- `Apply` keys runtime by `pol.Name`: `pkg/eventengine/engine.go:277-294`.
- `compileEventOptions` appends policies without local duplicate detection:
  `pkg/config/compiler_services.go:1609-1684`.

Why low:

The AST may merge same-name paths before compile in common set syntax. Still,
the compiler and engine are fragile if duplicate named instances reach them.

Suggested issue:

Add an event-options-specific duplicate-name commit test or a generic named
instance uniqueness validator if one is intended.

### L2 - Empty policy/action stanzas commit but do nothing silently

Evidence:

- Empty `Events` means `eventMatches` never fires:
  `pkg/eventengine/engine.go:760-768`.
- Empty `ThenCommands` causes `HandleEvent` to continue without any metric:
  `pkg/eventengine/engine.go:384-386`.

Impact:

Operators can commit inert automation without feedback.

Suggested issue:

Warn or reject policies with no events or no change-configuration commands,
unless no-op policies are explicitly supported.

### L3 - `within 0` match/prune semantics are inconsistent

Evidence:

- `withinMatches` uses a zero-second window directly:
  `pkg/eventengine/engine.go:861-870`.
- `pruneWindow` treats maxWindow zero as default 60 seconds:
  `pkg/eventengine/engine.go:899-908`.

Impact:

If zero reaches runtime via bad parse or tolerant load, matching and retention
use different time horizons.

Suggested issue:

Reject zero at commit and treat zero as invalid on tolerant load/runtime.

### L4 - Reordering event names resets cooldown even though event OR semantics are unchanged

Evidence:

- Semantic revision hashes `pol.Events` in configured order:
  `pkg/eventengine/engine.go:338-341`.
- Event matching treats order as irrelevant OR:
  `pkg/eventengine/engine.go:760-768`.

Impact:

A config-only reorder can re-arm automation cooldown.

Suggested issue:

Sort event names in `policySemanticRevision`, like attributes are sorted.

### L5 - Reordering equivalent within clauses resets cooldown

Evidence:

- Semantic revision hashes `WithinClauses` in order:
  `pkg/eventengine/engine.go:348-357`.
- Runtime combines clauses as an order-independent AND:
  `pkg/eventengine/engine.go:861-887`.

Impact:

If multiple clauses are intended as AND, reordering them should not re-arm the
policy.

Suggested issue:

Canonicalize within clauses for revision hashing once semantics are documented.

### L6 - Event action queue has a hard-coded depth with no operator knob

Evidence:

- `actionQueueDepth = 64`: `pkg/eventengine/engine.go:53-58`.

Impact:

Large automation deployments cannot tune queue capacity or retry behavior.

Suggested issue:

Expose event-options queue depth/retry deadline as system knobs, with safe
bounds and metrics.

### L7 - Engine constructor accepts nil store and can panic if actions run

Evidence:

- Tests use `New(nil, nil)` for matcher/queue paths.
- `applyOnce` unconditionally dereferences `e.store`:
  `pkg/eventengine/engine.go:591-599`.

Impact:

Not production in current daemon wiring, but the package API is foot-gunny.

Suggested issue:

Validate `store != nil` before accepting policies with actions, or split a
matcher-only test constructor from the production constructor.

## Negative Results

- Transactional pre-classification itself looks sound for `set`/`delete`
  commands and already has strong tests.
- Held-lock retry, retry timer Stop, FIFO supersede ordering, and single-count
  overflow have targeted tests and match the documented fixes.
- Attributes-match invalid regex/malformed/unknown-field strict rejection is
  covered by config tests and runtime fail-closed logic.
- Day-2 apply order for an already-created event engine is better than boot
  order: `eventEngine.Apply` runs before `reconcileRPM`, so updated policies
  are in place before RPM is restarted on day-2 commits.

## Suggested Issue Titles

1. event-options: drop stale queued actions after policy removal or revision change
2. event-options: re-check cooldown at worker apply time
3. event-options: parse and enforce attributes-match event-name prefix
4. daemon: day-2 enabling first event-options policy does not start engine
5. daemon/rpm: register event-options callback before starting initial RPM probe cycle
6. event-options: count or drain queued actions on shutdown
7. event-options: prevent HandleEvent enqueue after Close
8. event-options: unregister RPM callback and stop worker when policies removed
9. event-options: add audit descriptions to automated commits
10. config: strict-validate event-options within/trigger numeric values
11. config: reject ambiguous event-options trigger on+until clauses
12. event-options: expand RPM event attributes for vSRX/Junos parity
13. event-options: pin trigger on/until edge semantics with parity tests
14. event-options: replace window slices with compact ring buffers
15. event-options: index policies by event name for lower latency
16. event-options: avoid redundant compile/check work on automated commits
17. event-options: avoid holding config lock while waiting for apply semaphore
18. configstore: expose typed missing-delete-path error for change-configuration
19. event-options: add policy-level metrics/status for action failures
20. event-options: validate or warn on inert policies with no events/actions
