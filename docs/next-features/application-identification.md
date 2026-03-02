# Next Feature: `services application-identification`

Date: 2026-03-02  
Status: Proposed

## Config Evidence
- Present in `/home/ps/git/bpfrx/vsrx.conf:214` as `application-identification;`

## Current State
- Parsed into config flag: `pkg/config/compiler.go` (`compileServices`)
- Exposed in show output: `pkg/cli/cli.go`, `pkg/grpcapi/server.go`
- Not wired into dataplane/session classification (no L7 AppID engine, no app signature pipeline)

## Problem
Policies can only match L3/L4 application objects today. Enabling `application-identification` has no enforcement or telemetry effect, which creates behavior drift from vSRX expectations.

## Proposed Implementation Scope
1. Add per-session app classification state (unknown, probing, identified) to session metadata.
2. Introduce classifier hook (XDP/TC + userspace assist) with signature cache for first packets.
3. Emit AppTrack-style logs/metrics for identified sessions.
4. Gate feature behind explicit config enable and fail-safe fallback to existing L3/L4 behavior.

## Acceptance Criteria
- With `services application-identification` enabled, sessions transition from `unknown` to identified app when signatures match.
- Policy/log output can expose identified app name for matched sessions.
- Feature-off path has no measurable regression in throughput/latency baseline.
