# Claude SMR plan review - round 7

Target commit: `c952d74ef6ea8bea994b44f1697b412353577d6d`

## Reviewer availability

The Claude Code CLI process session `84187` failed before analysis with the
account monthly-spend-limit error. No Anthropic-model verdict exists for this
round. The findings below are from an independent SMR-method fallback and are
not represented as a Claude model review.

Fallback reviewer session: `019fc81e-a775-7061-b83a-214a6169c308`

## Verbatim fallback verdict

`PLAN-NEEDS-MAJOR`

## Major findings

1. The session epoch check is not linearizable with config apply. Independent
   atomics allow an install to pass its epoch check, race the apply fence and
   sweep, and then mutate state after the sweep. The install path and apply
   path need one synchronization protocol.
2. `BulkStart` clears the config-generation baseline, invalidating both the
   rejected-generation fence and stable reconnect recovery.
3. `confirm.json` is another persisted malformed-AST ingress. `ReadConfirm`
   checks only that `PrevTree` is nonnil before recovery compiles it. The
   bounded tree-shape validator must run in `ReadConfirm` without broadening
   this issue into a confirm transaction redesign.
4. The terminal Ctrl-C `LoadOverride` acceptance test contradicts the plan's
   explicit #6548 ownership boundary.

## Accepted portions

The fallback accepted A, B, C, D, E, H, J, K, L, and M. It blocked F, G, and I
only on the findings above.
