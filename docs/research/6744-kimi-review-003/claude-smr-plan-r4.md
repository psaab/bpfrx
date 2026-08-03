# Independent SMR-method hostile plan review - round 4

Target commit: `26843cb0f4870b89c4849bcb1f24ff7dc0ec658d`

Reviewer agent: `019fc7a6-0d99-7d23-964f-90014234a599`

## Provenance limitation

The Claude Code CLI was invoked against the locked detached worktree but again
failed before analysis because the account had reached its monthly spend
limit. No Anthropic-model verdict exists for this round. This document records
an independent reviewer applying the skill's hostile SMR method and is not
represented as a Claude-model review.

## Verbatim verdict

`PLAN-NEEDS-MAJOR`

## Major findings

1. **The fixed-updater constructor contradicts the fingerprint rule.**
   `NewManager` installs a caller-supplied fixed updater and fixed mode publishes
   rows with an empty backend fingerprint. Revision 4 simultaneously preserves
   that seam and requires a nonempty exact fingerprint for every withdrawal.
   Expiry or disable would therefore retain every fixed-mode row forever. The
   plan must explicitly define whether the fixed constructor is trusted
   authority for its empty-fingerprint rows, gains an endpoint identity, or
   loses withdrawal compatibility. This is not test-only reachability:
   `pkg/dhcpserver.NewDDNSManager` exports the fixed constructor.
2. **Invalid family values can alias the IPv4 slot.** Existing `famIdx` maps
   every value other than 6 to index zero, while persisted-state validation
   checks addresses but not `Family`. A malformed family 0 or 5 row could
   therefore satisfy a fingerprint comparison and be deleted through the IPv4
   backend. State loading and the authority selector both need an explicit
   `{4,6}` fail-closed contract before any array lookup or DNS operation.

## Accepted conclusions

The reviewer accepted the deliberately narrow aggregate DDNS API posture once
those authority defects are closed: RFC2136 may mutate the forward RR before a
PTR result and exposes only one aggregate error, so no second-credential retry
is justified. It also accepted the revision-four RG domains, both-node B/C/I/M
gates, SNMP intent-result plumbing, pre-mutation confirm target compilation,
lifecycle normalization, override classifier, canonical policy shape, and the
bounded A, D, H, J, and K workstreams.

## Required revision

Define an explicit fixed-updater compatibility authority rule without weakening
production factory-mode fingerprint checks. Reject invalid persisted families
at load and again before updater selection, with negative tests proving no DNS
operation occurs.
