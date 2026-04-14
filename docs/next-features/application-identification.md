# Next Feature: `services application-identification`

Date: 2026-03-02  
Status: Implemented (Partial)

## Config Evidence
- Present in `/home/ps/git/xpf/vsrx.conf:214` as `application-identification;`

## Current State
- Parsed into config flag: `pkg/config/compiler.go` (`compileServices`)
- Compiler now expands the broader app catalog when enabled: `pkg/dataplane/compiler.go`, `pkg/appid/runtime.go`
- Session display/filtering now uses real stored `app_id` values: `pkg/cli/cli.go`, `pkg/grpcapi/server.go`
- eBPF and DPDK now both preserve `session.app_id` and emit it in events/session state
- Still no full L7 DPI or signature package pipeline

## Problem
Before this change, enabling `application-identification` had no runtime effect. xpf now has real runtime application tracking for its L3/L4 application catalog, but it still does not implement Junos-style L7 DPI/AppSecure signatures.

## Proposed Implementation Scope
1. Compile the broader application catalog when `services application-identification` is enabled.
2. Store `app_id` in session/event state on both dataplanes.
3. Report unknown sessions as `UNKNOWN` instead of guessing by port when AppID is enabled.
4. Keep full L7 DPI/signature work as future follow-up rather than pretending parity already exists.

## Acceptance Criteria
- With `services application-identification` enabled, sessions and session filters use the stored dataplane `app_id`.
- Unknown sessions are explicitly shown as `UNKNOWN` instead of silent empty output.
- Feature-off path preserves the prior heuristic port-based display behavior.
- Full L7 DPI/signature parity remains open follow-up work.
