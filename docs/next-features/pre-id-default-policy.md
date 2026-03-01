# Next Feature: `security pre-id-default-policy`

## Config Evidence
- Present in `/home/ps/git/bpfrx/vsrx.conf:21128` as `pre-id-default-policy { ... }`

## Current State
- Parsed into `SecurityConfig.PreIDDefaultPolicy`: `pkg/config/compiler.go`
- Struct exists in `pkg/config/types.go`
- Not referenced by policy evaluation or dataplane flow pipeline

## Problem
When application identification is in progress, vSRX can apply explicit pre-ID default handling (including session-init/session-close logging). bpfrx currently ignores this policy at runtime.

## Proposed Implementation Scope
1. Add pre-ID phase marker to new sessions when AppID is enabled.
2. Apply `pre-id-default-policy` actions during pre-ID state (starting with logging parity).
3. Transition to final policy decision once app is identified or timeout expires.
4. Add counters for pre-ID decisions and transitions.

## Acceptance Criteria
- `session-init` and `session-close` logging under pre-ID policy occurs when configured.
- Pre-ID behavior is deterministic and transitions to normal policy once classification completes.
- No behavior change when `pre-id-default-policy` is not configured.
