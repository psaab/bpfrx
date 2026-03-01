# Next Feature: `system license autoupdate url`

## Config Evidence
- Present in `/home/ps/git/bpfrx/vsrx.conf:98-99` under `license { autoupdate { url ... } }`

## Current State
- Parsed into `SystemConfig.LicenseAutoUpdate`: `pkg/config/compiler.go`
- Field exists in type model: `pkg/config/types.go`
- No runtime consumer or scheduler for update flow

## Problem
Configuration can specify a license auto-update endpoint, but bpfrx currently ignores it. This leads to silent no-op behavior and operational confusion.

## Proposed Implementation Scope
1. Decide bpfrx behavior model (explicit unsupported warning vs. pluggable entitlement updater).
2. If implementing updater: add safe fetch loop with TLS validation, backoff, and explicit trust roots.
3. Add observability for last-success/last-failure and next-attempt timestamps.
4. Ensure feature can be disabled cleanly and does not block normal dataplane startup.

## Acceptance Criteria
- Configured license autoupdate URL produces explicit runtime behavior (implemented updater or explicit unsupported warning).
- Network failures are retried with bounded backoff and clear logs.
- No sensitive token/URL secrets leak in logs.
