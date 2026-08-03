# Codex hostile plan review - round 4

Target commit: `26843cb0f4870b89c4849bcb1f24ff7dc0ec658d`

Reviewer session: `019fc7a6-106a-7210-8797-a6e63e869f18`

## Verbatim verdict

`PLAN-NEEDS-MAJOR`

## Major findings

1. **DDNS drops same-credential retry authority.** Revision 4 advances the
   previous anchor to the new endpoint before reconciliation. If an A -> B
   transition deletes the forward RR through A but the PTR delete fails, the
   row remains while the next pass has only B in current and previous slots.
   The row can never retry through A. A disabled family can also construct a
   live updater while producing an empty fingerprint and poison the anchor;
   fixed-updater rows carry empty fingerprints and become undeletable. The plan
   needs explicit anchor lifetime, disabled-endpoint identity, and fixed-seam
   authority rules plus multi-cycle failure tests.
2. **RG validation has no canonical effective view or pre-effect runtime
   boundary.** The proposed AST gate runs without interface-range expansion,
   so it can miss inherited bindings or reject member overrides. Repeated
   chassis roots are compiled with replacement semantics, so a raw union can
   validate references absent from the final typed config. Userspace compile
   performs pin cleanup, shim selection/compile, generation advancement, and
   attachment synchronization before the currently implied inventory check.
   The plan must define compiler-equivalent local/peer normalization and a
   typed-config gate before the first dataplane side effect.
3. **Confirm recovery is not a complete state machine.** A persisted
   `FirstCommit=true` record can carry a populated tree, skip compilation, and
   later promote it as a nil-compiled bootstrap target. Active load rewrites
   retired dataplanes and sanitizes control characters before tolerant compile,
   while confirm recovery does neither, so identical trees receive different
   compatibility treatment. The proposed degraded latch also has no named
   durable remediation operation or clearing transition.
4. **SNMP top-level and `system snmp` behavior are not equivalent.** Only the
   top-level stanza is schema-linked. Flat `set system snmp ...` becomes a
   packed leaf that the child-only compiler silently lowers to empty, so generic
   AST fixtures would miss the production `SetPath` trace. Rejected-only
   listener behavior is left as an option even though current enablement
   deterministically stops the agent when no community or valid v3 user
   remains. Compiler and runtime rejection metadata also lack a defined union,
   identity, nil-value, and key/name mismatch contract.

## Accepted workstreams

The reviewer accepted A, B, D, F, H, J, K, L, and M as implementable. It also
accepted the corrected RG numeric domains, same-family DDNS goal, non-first
confirm compile ordering, SNMP intent-first direction, and both-node hard-gate
requirement; the blockers concern the missing execution boundaries above.

## Optional polish

Add quoted comment-marker/brace cases for override classification, nil
policy-options behavior for route-map counting, and synthesized EventRecord
compatibility tests for lifecycle output. These are not plan blockers.
