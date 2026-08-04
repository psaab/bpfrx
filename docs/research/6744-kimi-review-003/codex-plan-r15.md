# Codex hostile plan review - round 15

**Verdict: PLAN-NEEDS-MAJOR**

Review target: detached, locked, clean checkout at
`47b32a033e756316e5c24ba1e74442e58047968a`.

## Findings

1. **CRITICAL - receiver batching loses the sender's NAT release/acquire
   boundary.** A valid tail containing `Delete(B,T)`, `Open(A,T)`, and
   `Open(B,U)` fits in one 256-operation receiver batch. Whole-batch preflight
   sees T still owned by B and rejects A/T. The plan needs a receiver-visible
   phase boundary with release commit before acquisition, or a fully specified
   cross-key reservation-transfer transaction.
2. **CRITICAL - capable demotion excludes the sessions required by its own
   handoff.** Demotion quarantines rows and marks them ineligible for export,
   but the only capable handoff path exports owner-RG candidates and excludes
   those quarantined rows. Either TailAck certifies a bulk missing the rows or
   the handoff can never finish. Add target- and serial-bound handoff-exportable
   provenance or freeze/export before quarantine.
3. **HIGH - the static-DNAT transition has no implementable journal capacity,
   deadline, or API.** A capacity-valid transition can touch millions of keys,
   while the plan only calls its exact rollback journal "bounded." Define its
   row/byte ceiling, allocation strategy, Begin/Commit/Abort token, worker ACK,
   cancellation owner, deadline, and before/after-first-mutation failures.

Workstreams A-H and J-M were accepted. Workstream I is blocked by the three
findings above. The round-14 migration-lifetime, ambiguity-escrow,
monotonic-loss, provenance, map-capacity, and ACK-fence objections were accepted
as materially addressed.

Final verification found detached HEAD at the exact target, with empty staged
and unstaged diffs. The reviewer modified no files.
