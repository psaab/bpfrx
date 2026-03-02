# Next Feature: `system ntp threshold <ms> action <accept|reject>`

Date: 2026-03-02  
Status: Proposed

## Config Evidence
- Present in `/home/ps/git/bpfrx/vsrx.conf:109` as `threshold 400 action accept;`

## Current State
- Parsed into `SystemConfig.NTPThreshold` and `NTPThresholdAction`: `pkg/config/compiler.go`
- Runtime NTP apply only writes chrony server lines and reloads sources: `pkg/daemon/daemon.go` (`applySystemNTP`)
- Threshold/action values are currently ignored

## Problem
Time discipline behavior differs from operator intent in configs that rely on explicit threshold policy. Failover and session-sync systems can be sensitive to clock behavior, so silently ignoring this knob is risky.

## Proposed Implementation Scope
1. Map threshold/action into chrony-compatible controls (or enforce in bpfrxd wrapper logic if chrony mapping is insufficient).
2. Expose active threshold mode in operational output.
3. Emit warning when configured value cannot be represented exactly.
4. Add tests for accept/reject behaviors and config rendering.

## Acceptance Criteria
- Configured threshold/action changes runtime NTP behavior deterministically.
- `show` output reflects effective threshold policy.
- Unsupported combinations produce explicit warning, not silent ignore.
