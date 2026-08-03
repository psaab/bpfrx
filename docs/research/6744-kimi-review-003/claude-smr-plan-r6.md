# Claude SMR plan review - round 6

Target commit: `cab8851171889b6e97d518d6fe9540341fc942f7`

## Reviewer availability

The Claude Code CLI failed before analysis with the account monthly-spend-limit
error. No Anthropic-model verdict exists for this round. The findings below are
from the independent SMR-method fallback and are not represented as a Claude
model review.

Fallback process session: `97542`

Fallback reviewer session: `019fc7f3-a8e6-7991-b571-a6278971328a`

## Verbatim fallback verdict

`PLAN-NEEDS-MAJOR`

## Major findings

1. DDNS teardown is not linearizable. The stale-snapshot double-release trace
   is real, and a final delete can also race an unlocked peer publication.
   Surface A advertises only one of two possible crash-window targets.
2. The election uses the wrong ownership unit and incomplete authority:
   Surface-B PTR/DHCID components, conflict policy, domain/view identity, HTTP
   authority inputs, legacy generations, and duplicate durable keys are not
   represented. The narrow same-family authority fix is sound and should be
   separated from this generalized protocol.
3. Commit-confirmed needs a transition record covering both possible active
   generations and all `fsatomic` cut points. Reversing the two file writes is
   insufficient.
4. Confirm binding requires a versioned, validated hash and a durable
   generation or resolution marker. Content hash alone cannot distinguish a
   byte-identical authoritative supersession, and absent-active recovery is
   undefined.
5. Committed-uncompiled rollback cannot be represented compatibly by the old
   nil-config API. The plan also needs a downgrade/refusal policy and an RBAC
   decision for irreversible confirm quarantine discard.
6. SNMP has four contradictions: hierarchical display-set round-trip,
   repeated-root deep merge, closed-world credential grammar, and preservation
   of the administrative `snmpd disable` lifecycle gate.
7. RG control inventory must be separated from fixed-slot dataplane inventory,
   and mixed-version behavior must accurately preserve or deliberately change
   the current manual-transfer versus crash-takeover policy.

## Accepted workstreams

The fallback accepted A, B, D, F's core classifier, H, J, K, L, and M. It
accepted structural AST validation in G but not the appended confirm protocol.
