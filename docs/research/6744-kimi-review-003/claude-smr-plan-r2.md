# Independent SMR-method hostile plan review - round 2

Target commit: `01b67530e53016cf127d43c4a28c0582513718f8`

Reviewer agent: `019fc76c-3cfa-7393-88b1-2970cd07f410`

## Provenance limitation

The Claude Code CLI was invoked against the locked detached worktree but failed
before analysis because the account had reached its monthly spend limit. No
Anthropic-model verdict exists for this round. This document records an
independent reviewer applying the skill's SMR checklist and is deliberately not
represented as a Claude-model review.

## Verbatim verdict

`PLAN-NEEDS-MAJOR`

## Major findings

1. **The RG tolerant-load state machine is unsafe and internally
   contradictory.** `ForwardingSupported=false` is a class-II semantic-gap
   signal that disarms forwarding before publication. It cannot mean “reject
   this snapshot and retain previous-good.” Inventory and map mutation can also
   occur before the proposed publication boundary, and the plan validated RG
   definitions without proving every interface binding was in range.
2. **SNMP validation runs after configured intent can be erased.** The compiler
   records a password only when it is nested under a recognized protocol node.
   A legitimate noAuthNoPriv user and malformed password-only input can
   collapse to the same typed `SNMPv3User`. Validation must inspect the expanded
   AST before lowering and preserve non-secret rejection metadata for runtime
   reconciliation.
3. **DDNS fingerprint-keyed authority is insufficient for credential
   rotation.** The backend fingerprint intentionally excludes the TSIG secret.
   A bad new credential can replace the only working historical updater under
   the same fingerprint, permanently losing executable withdrawal authority.
4. **Persisted-tree validation omits `confirm.json`.** `ReadConfirm` embeds a
   `PrevTree` that boot recovery can compile or persist. The same recursive
   shape validation must cover active, candidate, rollback, and confirm
   rollback-target ingress.
5. **The override classifier remains ambiguous.** “No recognized flat verb
   means hierarchy” lets a singleton typo such as `sett system host-name fw`
   become an implicit hierarchy leaf at EOF. Hierarchical fallback needs
   positive structural evidence; otherwise nonempty brace-less content must be
   rejected.

## Minor finding

The lifecycle-action surface description was not an exact matrix. The local
CLI already omits lifecycle action while the remote CLI text path includes it,
and SSE has both structured and text renderers. The implementation contract
must state every surface and whether action is omitted or emitted as `"n/a"`.

## Required revision

- Make invalid RG identifiers an action-agnostic compile failure before any
  snapshot or actuator mutation; test definition and binding paths, fresh boot,
  previous-good live sync, and recovery to a later valid generation.
- Validate SNMPv3 intent on the expanded AST, reject duplicate/conflicting
  single-valued credential leaves, and carry only path/name/reason metadata
  after secrets are lowered.
- Keep multiple process-local authority generations per DDNS fingerprint and
  bind each owned record to the exact generation that published it.
- Validate all persisted `ConfigTree` ingress, including
  `confirmRecord.PrevTree`, while preserving the loaded active config when the
  confirm record is corrupt.
- Require braces as positive hierarchical evidence for a nonempty override
  body with no recognized flat verb.
- Replace the lifecycle prose with an exhaustive per-surface matrix and a
  positive allowlist of event kinds that genuinely carry forwarding actions.
