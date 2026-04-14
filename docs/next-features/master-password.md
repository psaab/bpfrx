# Next Feature: `system master-password`

Date: 2026-03-02  
Status: Implemented

## Config Evidence
- Present in `/home/ps/git/xpf/vsrx.conf:111` as `master-password { pseudorandom-function ... }`

## Current State
- Parsed into `SystemConfig.MasterPassword`: `pkg/config/compiler.go`
- Field exists in type model: `pkg/config/types.go`
- `configstore` now encrypts active/candidate/rollback config trees at rest when configured: `pkg/configstore/db.go`, `pkg/configstore/crypto.go`

## Problem
Before this change, configuration accepted `master-password` with no runtime effect. xpf now uses the configured PRF to derive an at-rest encryption key from a node-local master key and encrypt persisted config trees.

## Proposed Implementation Scope
1. Treat `master-password` as the configstore encryption policy knob.
2. Derive a per-node encryption key using the configured PRF plus a node-local master key.
3. Encrypt persisted active/candidate/rollback trees instead of trying to maintain a hand-curated secret field list.
4. Preserve normal runtime config behavior after decrypting on load.

## Acceptance Criteria
- Configured master-password has a clear runtime effect.
- No secret/plaintext leakage in logs, config diffs, or telemetry.
- Unit/integration tests cover config parse, storage, and reload behavior.
