# Independent SMR-method hostile plan review - round 3

Target commit: `d746944992d3d91763e79498ba5bf5b139eff943`

Reviewer agent: `019fc784-3d6b-7aa3-b49a-ce3979b219b3`

## Provenance limitation

The Claude Code CLI was invoked against the locked detached worktree but again
failed before analysis because the account had reached its monthly spend
limit. No Anthropic-model verdict exists for this round. This document records
an independent reviewer applying the skill's hostile SMR method and is not
represented as a Claude-model review.

## Verbatim verdict

`PLAN-NEEDS-MAJOR`

## Major findings

1. **RG zero is not a dataplane binding.** It is the unbound/standalone sentinel
   in Go, BPF, and Rust. Definitions may be 0..15, but interface and other data
   bindings must be 1..15.
2. **Strict validation remains local-node-only.** Node1-only invalid security,
   SNMP, RG, or policy content can commit on node0 and permanently fail standby
   sync. The new gates need a shared both-node-effective strict preflight.
3. **Confirm rollback targets receive only structural validation.** Every
   non-first-commit `PrevTree` must compile and pass semantic preflight before
   active-state mutation or timer arming. Failure must preserve active and
   compiled state, retain the forensic record, arm no timer, and raise
   persistent degraded health.
4. **SNMP rejection metadata has no compiler/runtime plumbing.** The plan must
   define signatures carrying preflight results through section compilation,
   skip rejected users during lowering, project nonsecret metadata, and return
   typed runtime rejections before atomic swap.
5. **DDNS authority is not operationally bounded.** Define and enforce numeric
   ownership and authority-generation caps, reject publication before capacity
   overflow, preserve existing withdrawal authority, expose an alarm, and test
   restart exactly at the limit.

## Accepted workstreams

The reviewer found A, D, F, H, J, K, and L adequately planned. It also agreed
that canonical policy AST handling and failed-sync acknowledgment retry
semantics were mechanically understood, subject to the peer-effective gate
above.
