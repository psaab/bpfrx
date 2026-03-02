# Next Feature: `system master-password`

Date: 2026-03-02  
Status: Proposed

## Config Evidence
- Present in `/home/ps/git/bpfrx/vsrx.conf:111` as `master-password { pseudorandom-function ... }`

## Current State
- Parsed into `SystemConfig.MasterPassword`: `pkg/config/compiler.go`
- Field exists in type model: `pkg/config/types.go`
- No runtime consumer in daemon/auth pipeline

## Problem
Configuration accepts and stores master-password settings but they do not influence credential handling. This creates false parity and potential operator assumptions about password/key derivation behavior.

## Proposed Implementation Scope
1. Define bpfrx-compatible semantics for master-password handling (explicitly scoped to local auth and secret storage paths).
2. Wire master-password to secret at-rest encryption wrapper or document strict no-op policy with warning.
3. Ensure commit/rollback path preserves secure handling and avoids plaintext leakage.
4. Add operational visibility (configured/enabled status without exposing secret material).

## Acceptance Criteria
- Configured master-password has a clear runtime effect (or explicit unsupported warning).
- No secret/plaintext leakage in logs, config diffs, or telemetry.
- Unit/integration tests cover config parse, storage, and reload behavior.
