# Next Feature: `security pre-id-default-policy`

Date: 2026-03-02 (status corrected 2026-06-29, #3413)  
Status: Partial — accepted-but-inert in the userspace dataplane (#2509)

## Config Evidence
- Present in vSRX configs as `pre-id-default-policy { then log ...; }`
- Junos syntax is accepted by the parser and config schema

## Current State
- **Parsed and stored**: `pre-id-default-policy then log session-init/session-close`
  is parsed into `SecurityConfig.PreIDDefaultPolicy.LogSessionInit` /
  `LogSessionClose` (`pkg/config/compiler_security.go:226-237`,
  type `pkg/config/types_security.go:209-213`).
- **Schema-completable**: the stanza is in the config-mode set schema
  (`pkg/config/schema_security.go:757`), so tab-completion and commit-check
  validation accept it.
- **No runtime consumer (inert)**: the logging flags have NO consumer in the
  userspace dataplane after the eBPF retirement (#1373/#1476). The only reader
  was the retired eBPF compiler, which packed the bits into
  `FlowConfigValue.AppFlags` (`pkg/dataplane/compiler.go:1109-1116`) and wrote
  them via `SetFlowConfig` — but `SetFlowConfig` is a no-op stub on the
  userspace path (`pkg/dataplane/loader.go:400`,
  `userspaceShimCompileDataplane.SetFlowConfig` returns `nil`), so this is a
  dead write to a map that no longer exists. The legacy wiring
  (`bpf/xdp/xdp_policy.c`) was deleted in #1476 (commit `13fa1009e`).
- **Commit-time warning**: the operator is told at commit that the stanza is
  inert — `validatePreIDDefaultPolicyLogWarnings`
  (`pkg/config/compiler_validate_warn.go:859-882`) emits:
  > security pre-id-default-policy `then log ...` is accepted for
  > compatibility but is inert in the userspace dataplane (no
  > pre-identification session-admit path exists to emit the RT_FLOW
  > session log)

## Why It Is Inert (#2509)
On the userspace dataplane there is no pre-identification session-admit path:
app-id is best-effort labeling of already-admitted sessions, not a "default
policy admits the session before app-id resolves, then re-evaluate" pipeline.
There is therefore no session on which to stamp the pre-ID log mode — unlike
the per-policy #2508 path, which stamps the admitting policy's `then log
session-init/session-close` flags onto the session at install
(`userspace-dp/src/policy.rs`, `userspace-dp/src/session/entry.rs`). The
stanza commits and is silently inert; #2509 (closed) is the source of truth
for the missing consumer.

## Problem
When application identification is in progress, vSRX can apply explicit
pre-ID default handling (including session-init/session-close logging for
unknown/pre-ID sessions). xpf parses and stores the stanza but does NOT yet
honor the configured logging behavior — pre-ID unknown-app sessions are not
logged. The config is accepted for compatibility and the operator is warned at
commit time.

## Proposed Implementation Scope
1. Treat `app_id == 0` while AppID is enabled as the unknown/pre-ID state.
2. OR the configured `session-init` / `session-close` flags into new sessions
   in that state, emitting the RT_FLOW session log via the existing event
   stream producer (mirror the per-policy #2508 stamping path).
3. Preserve normal policy behavior for non-pre-ID sessions.
4. Keep richer pre-ID transition/counter work as future follow-up if full DPI
   is added.

## Acceptance Criteria
- `session-init` and `session-close` logging under pre-ID policy occurs when
  configured (and the commit-time inert-warning is removed once wired).
- No behavior change when `pre-id-default-policy` is not configured.
- Scope is explicit: this is unknown/pre-ID logging parity, not full staged DPI
  policy enforcement.
