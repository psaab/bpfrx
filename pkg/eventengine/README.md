# pkg/eventengine

Event-driven automation engine implementing Junos-style `event-options`
policies. Matches RPM probe events against policy clauses (with optional
temporal `within` windows) and triggers commit-and-apply actions.

## Entry points

- `Engine` — `engine.go`.
- `New(store, commitFn)` — `engine.go`.
- `Apply(policies []*config.EventPolicy)` — `engine.go`. Loads policies, resets temporal
  state.
- `HandleEvent(evt)` — `engine.go`. Called by the RPM event
  callback.
- `CommitFn` — `engine.go`. The atomic commit-and-apply hook.

## Callers

`pkg/daemon` (event loop, RPM results).

## Dependencies

`pkg/config`, `pkg/configstore`, `pkg/rpm`.

## attributes-match (regex, #2008 M7)

`attributes-match "<event>.<attribute> matches <pattern>"` filters policy
triggering on a **regex** match of `<pattern>` against the event attribute,
matching Junos `matches` semantics. `<pattern>` is an RE2 regular expression.

- Unanchored patterns are substring matches (`Com` matches `Comcast`); anchor
  with `^...$` for an exact match.
- Supported attributes today are `test-owner` and `test-name` (the only
  fields on `rpm.Event`). Other attributes are silently ignored.
- The pattern is validated at **commit time** (`config.ValidateEventAttributesMatch`
  via `CompileConfig`): an uncompilable regex is rejected with a precise error
  rather than being silently dropped at runtime.
- Compiled regexes are cached at `Apply()` time keyed by pattern string, so the
  event hot path (`HandleEvent` → `attributesMatch`) never recompiles.

> Behavior note: this was a literal-equality matcher before #2008 M7. The
> switch to regex is the correct Junos behavior but is **not** behavior-
> preserving for an existing stored literal containing regex metacharacters
> (e.g. a literal `.` now matches any character). The parse/validate seam is
> shared between the compiler and the engine (`config.ParseEventAttributesMatch`)
> so they cannot drift.

## Gotchas

- 30 s policy cooldown (`engine.go`). The same policy will not
  trigger more than once in any 30 s window.
- Temporal `within` clauses keep a sliding window of timestamps per
  (policy, event) pair. Old timestamps are pruned on every evaluation so
  the window is bounded.
- `CommitFn` holds the apply semaphore across both commit and apply — the
  same primitive HTTP/gRPC commits use (#846) — so event-triggered
  commits serialize with operator commits.
- Policy evaluation runs under a lock; command execution (the actual
  shell-out for `then ...` actions) releases the lock first to avoid
  deadlocking on a self-triggered apply.
