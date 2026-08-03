# Codex hostile plan review - round 5

Target commit: `fdd7bbf06157ef18b295026d4b245c08c23e1090`

Process session: `22870`

Reviewer session: `019fc7c7-881c-7181-a0e0-88b35f1d1b6b`

## Verbatim verdict

`PLAN-NEEDS-MAJOR`

## Major findings

1. **`FirstCommit` still aliases two different rollback classes.** A tolerant
   load compile failure retains a populated active tree with a nil compiled
   config. A later confirmed commit therefore writes a populated rollback
   target as `FirstCommit=true`; live rollback clears committed history while
   restart recovery would quarantine the same record. The writer, live timer,
   and restart path need one explicit rollback-target classification rather
   than inferring bootstrap from a nil compiled pointer.
2. **The stale-first recovery order cannot be implemented through the proposed
   `DB.ReadConfirm`.** The DB method would recursively validate `PrevTree`
   before Store can compare `GuardedHash`, so an irrelevant malformed target in
   a stale record is quarantined instead of durably discarded. Envelope decode,
   stale classification, and target interpretation must be separate stages.
3. **The guarded hash uses the wrong active representation.** The record is
   armed against the raw promoted tree, but boot rewrites retired syntax and
   sanitizes values before recovery. Comparing against the prepared active tree
   can delete a live confirm record as stale and make an unconfirmed config
   permanent. Recovery must retain and compare the raw persisted active hash.
4. **Confirm quarantine is not a closed state machine.** Active compile failure
   returns before confirm classification, non-absence read failures do not
   latch, and a quarantined record has no in-memory timer for ordinary commit or
   SyncApply to supersede. The plan must specify transitions under load failure,
   ordinary commit, authoritative sync, explicit discard, external repair, and
   restart.
5. **DDNS co-ownership is endpoint-blind.** Same tuple on two different DNS
   authorities is treated as co-owned, allowing one endpoint's durable row to
   be dropped without wire deletion and allowing its only old-authority anchor
   to rotate away. Co-ownership must include authoritative endpoint identity on
   both DDNS surfaces.
6. **Fixed-updater provenance is not persisted.** After restart, a different
   caller-supplied updater is trusted for every empty-fingerprint row merely
   because the constructor is in fixed mode. The plan must either define that
   broad trust as the public contract or persist stable updater identity.
7. **DDNS persisted-state validation is incomplete.** Deletion also trusts
   `PTRName`, pending `PriorAddrText`, and `Scope.Family`; the plan validates
   only family, current address, and forward type. It needs complete
   surface-specific action-bearing shapes and stateful partial-wire tests.
8. **Malformed peer RG identities can still alias RG0.** Lowering ignores
   `Atoi` failure while the raw identity validator remains lenient in peer mode.
   Nonnumeric or overflowing peer-only identities can therefore lower as zero
   and pass the typed range gate. The effective hard gate must reject malformed
   definition and node identities before lowering.
9. **SNMP runtime validation does not reproduce the compiler credential
   matrix.** Protocol/password iff constraints are missing, permitting
   configured authentication or privacy intent to lower to no-auth. Compiler
   rejection must also dominate a runtime-valid duplicate so installed and
   omitted identity sets remain disjoint.
10. **Rejected-only SNMP diagnostics are unreachable.** The proposed boolean
    enablement predicate stops before `NewAgent`/`UpdateConfig`, where runtime
    rejection metadata would be created. One pure evaluation result must drive
    installability, rejection union, diagnostics, and listener lifecycle;
    operational projections must use canonical map-key identity and be
    nil-safe.
11. **The quarantine-remediation security boundary is overstated.** Existing
    `SystemAction` is immediately executed over a trusted local gRPC channel;
    interactive confirmation is a CLI property, not server-enforced wire
    authorization. The plan must explicitly select that threat model or design
    a server capability/protocol.

## Accepted workstreams

The reviewer found no additional material blockers in A, B, D, F, H, J, K, L,
or M. Factory-mode exact DDNS fingerprint matching and the general
compiler-equivalent/pre-side-effect RG direction were accepted; the findings
above concern missing authority and state transitions.

## Optional polish

- Add a peer-effective RG differential oracle and invocation-order spies.
- Prefer a collision-resistant endpoint digest and define IPv4-mapped IPv6
  normalization.
- Define the SNMP rejection path-token grammar.
- Exercise lifecycle action omission on human-text projections as well as the
  normalization helper.
