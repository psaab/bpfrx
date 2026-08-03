# Independent SMR-method hostile plan review - round 5

Target commit: `fdd7bbf06157ef18b295026d4b245c08c23e1090`

Reviewer agent: `019fc7c8-7fb4-7fa0-828e-a0e65451c2de`

## Provenance limitation

The Claude Code CLI was invoked against the locked detached worktree but failed
before analysis because the account had reached its monthly spend limit. No
Anthropic-model verdict exists for this round. This document records an
independent reviewer applying the skill's hostile SMR method and is not
represented as a Claude-model review.

## Verbatim verdict

`PLAN-NEEDS-MAJOR`

## Major findings

1. **Confirm recovery has contradictory ordering and omitted restart states.**
   `DB.ReadConfirm` cannot recursively validate a target and also let Store
   discard a stale hash before interpreting that target. Every non-absence read,
   decrypt, or decode failure must latch; guarded-hash comparison must use the
   raw active representation; and recovery must run even when active tolerant
   compilation fails.
2. **SNMP authority, compatibility, and diagnostic publication are undefined.**
   Hierarchical `system { snmp { ... } }` is currently compiled and is present
   in the shipped Incus configuration, so tolerant rejection is a migration
   break. Repeated roots currently replace rather than merge, and rejected-only
   configuration bypasses the code that would compute runtime diagnostics.
3. **The RG limit is an unapproved product contraction.** Current strict
   validation and tests accept definitions through 255, session-sync
   architecture preserves RG >=16, and Rust has a node fallback. A 0..15
   global hard error can wedge mixed-version HA unless the product explicitly
   chooses a migration, preserves 0..255 control identities while narrowing
   bindings, or expands the dataplane ABI.
4. **`LoadOverride` has inconsistent public empty-input behavior.** CLI, REST,
   gRPC, and Store disagree on empty and whitespace-only input. The plan must
   select one public contract and test parity plus complete candidate metadata
   preservation after rejection.

## Accepted workstreams

The reviewer accepted A, B, D, H, J, K, L, and M. DDNS was mechanically closed
subject to defining no-authority as reconcile failure and strengthening the
multi-generation wire-state test. F remains blocked only at the public
entrypoint contract. RG and SNMP remain conditional on the decisions above.

## Optional polish

- Specify single-flight DDNS reconcile while provider I/O drops the manager
  mutex.
- Define whether `UpdateRGActive` requires inventory membership.
- State that normalized lifecycle `Action == "n/a"` is the applicability
  carrier.
- Test confirm discard racing a new confirmed commit under `Store.mu`.
