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

## Commit-time validation (#4578)
`system master-password` is the encryption policy knob, so a typo must FAIL the
commit rather than silently disable encryption. Two scoped guards enforce this
(both on the strict commit path; downgraded to warnings on tolerant Load /
SyncApply):

- The `master-password` subtree is closed-world (`schemaNode.closedWorld`,
  #4313 mechanism; `pkg/config/schema_system.go`). It is leaf-complete — xpf
  models and consumes exactly one leaf, `pseudorandom-function` — so a typo in
  the KEYWORD (`pseudo-random-fnuction`) is rejected instead of committing clean
  and letting `configstore.masterPasswordPRF` fall through to its empty default
  (encryption silently OFF).
- The `pseudorandom-function` value slot is enum-validated
  (`config.ValidateMasterPasswordPRF` against `config.MasterPasswordPRFNames`,
  matched case-insensitively) so an unknown PRF selector VALUE is rejected. The
  name set mirrors `configstore.prfHash` (the SSOT for the name→hash mapping);
  `pkg/configstore/crypto_prf_sync_4578_test.go` drift-guards the two.

This is scoped strictly to the master-password subtree — the broader `system`
open-world schema behaviour (#4515/X-1) is intentionally left as-is, because a
blanket `system` closed-world would false-reject valid-but-unmodeled leaves.
