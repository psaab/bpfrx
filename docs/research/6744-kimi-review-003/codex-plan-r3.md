# Codex hostile plan review - round 3

Target commit: `d746944992d3d91763e79498ba5bf5b139eff943`

Reviewer session: `019fc783-c0c7-7e13-b9e9-9e6e9c336aeb`

## Verbatim verdict

`PLAN-NEEDS-MAJOR`

## Major findings

1. **DDNS authority is modeled at the wrong granularity.** One generation ID
   per owned row cannot represent a forward mutation followed by a PTR
   authentication failure. Reverse NOTAUTH/REFUSED is also swallowed inside
   the RFC2136 backend before a manager-level retry classifier can observe it.
   The uncapped authority slices and unenforced durable-record ceiling do not
   establish the claimed memory or restart bound, and settled rows do not
   automatically reassert after restart to acquire a generation binding.
2. **RG definitions and bindings have different domains.** Definitions may use
   0..15, while binding value zero means unbound/standalone. Bindings must be
   1..15, must reference a defined RG, and must be validated in both node0- and
   node1-effective configurations before promotion.
3. **SNMPv3 validation is incomplete and its result has no concrete dataflow.**
   Both top-level `snmp` and accepted `system snmp` forms need coverage. Empty
   usernames/passwords are semantic failures, valid noAuthNoPriv requires a
   nonempty username with no protocol declarations, and the plan must carry
   rejected names through lowering, projections, hashing, and runtime swap.
   A repeated scalar password cannot be detected after current `SetPath`
   replacement, so that proposed invariant must be removed or enforced before
   tree mutation.
4. **Hard AST gates are local-node-only.** Peer-only invalid security identity,
   RG, SNMP, or policy data can pass a node0 commit and then hard-fail standby
   sync. Strict promotion needs a shared both-node-effective preflight.
   Repository history contains no authentic legacy nested policy fixture, so
   only the exact canonical four-key zone-pair form should be accepted.
5. **The lifecycle surface matrix is incomplete.** Daemon `slog` still derives
   action from the raw event before record normalization. The plan must include
   it and must not claim every real action is rendered by every formatter when
   SCREEN_DROP trace intentionally omits action.

## Minor findings

1. Define single-line `/* ... */` behavior in the override classifier instead
   of saying both that block comments are rejected and comments-only input is
   accepted.
2. Specify a persistent confirm-corruption health latch and add the same
   empty-Keys compiler belt to sampling, not only interfaces.

## Required revision

Use component-aware DDNS operation outcomes and numeric caps; split RG
definition/binding contracts and require referential plus peer-effective
validation; specify the complete SNMP intent-result plumbing; validate and
compile confirm rollback targets before mutation or timer arming; resolve the
policy compatibility choice to canonical-only; and complete the lifecycle and
override/persistence contracts.
