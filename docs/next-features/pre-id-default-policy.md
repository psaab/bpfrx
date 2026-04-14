# Next Feature: `security pre-id-default-policy`

Date: 2026-03-02  
Status: Implemented

## Config Evidence
- Present in `/home/ps/git/xpf/vsrx.conf:21128` as `pre-id-default-policy { ... }`

## Current State
- Parsed into `SecurityConfig.PreIDDefaultPolicy`: `pkg/config/compiler.go`
- Wired into flow config/runtime flags: `pkg/dataplane/compiler.go`, `bpf/xdp/xdp_policy.c`, `dpdk_worker/policy.c`
- Session init/close logging is now applied to unknown-app sessions when AppID is enabled

## Problem
When application identification is in progress, vSRX can apply explicit pre-ID default handling. xpf now honors the configured logging behavior for unknown/pre-ID sessions instead of ignoring the stanza entirely.

## Proposed Implementation Scope
1. Treat `app_id == 0` while AppID is enabled as the unknown/pre-ID state.
2. OR the configured `session-init` / `session-close` flags into new sessions in that state.
3. Preserve normal policy behavior for non-pre-ID sessions.
4. Keep richer pre-ID transition/counter work as future follow-up if full DPI is added.

## Acceptance Criteria
- `session-init` and `session-close` logging under pre-ID policy occurs when configured.
- No behavior change when `pre-id-default-policy` is not configured.
- Scope is explicit: this is unknown/pre-ID logging parity, not full staged DPI policy enforcement.
