# Codex hostile plan review - round 1

Target commit: `78891c3242a80b719bebdddc702087c07543e05b`

Task: `task-msd4pdsh-0u4bb0`
Session: `019fc752-45cb-7ce2-9e8e-95097ebc3624`

## Verbatim verdict

`PLAN-NEEDS-MAJOR`

## Claim audit

Codex confirmed K003-01/03/04/06/07/08/09/11/13/14/15/16, confirmed
K003-10 as partial, confirmed K003-02 as an exact #6548 duplicate, agreed
K003-12 is refuted, and agreed the unpreserved 128-item cohort is
unactionable. It downgraded K003-16 from High to Medium because the proven
impact is timing-dependent daemon availability loss, not persistence or a
demonstrated external exploit.

Codex rejected one disposition: #4313 is a cross-cutting closed-world doctrine
and explicitly says concrete domain gaps are driven separately. K003-05's
claimed vSRX syntax is unsupported, but silently accepting and omitting that
nested security-policy shape is still a concrete honesty/security gap. It must
be rejected as unsupported under its own linked workstream or explicitly killed;
it is not an exact duplicate.

## Blocking findings

1. **DDNS needs multi-fingerprint authority.** A -> B partial cleanup -> C can
   leave A and B ownership simultaneously. One previous slot is insufficient;
   test that fallback resolution never advances or erases the authority needed
   by an older record.
2. **Persisted-tree failure taxonomy contradicts the plan.** Structural JSON
   corruption belongs to `ErrConfigDBUnreadable` and fatal startup refusal,
   while compile failures use lifeline recovery. Choose one and test it.
3. **RG lenient quarantine can fail open.** Dropping a high-ID RG binding can
   make an interface appear standalone. Use whole-snapshot previous-good
   retention/fresh-boot default-deny and make the 0..15 product limit explicit.
4. **Flat override needs an exact artifact grammar.** Define supported verbs,
   ordering, missing targets, comments, semicolon forms, and mixed-syntax
   rejection; arbitrary edit replay on an empty tree is not valid.
5. **Route-map term counts and trailing defaults are conflated.** A context-free
   exact API is impossible. Define term-count versus highest-sequence/fit
   concepts and migrate every gate and render belt.
6. **Public and runtime contracts are undecided.** Specify SNMP valid -> invalid
   replacement with no stale user, lifecycle JSON/gRPC representation, exact
   address-book merge semantics, and helper-only VIP locking.

## Required negative gates

- Global empty identity before normalization, previous-good retention, and
  first-boot behavior.
- DDNS A -> B partial cleanup -> C with both old fingerprints owned.
- LoadOverride verb ordering, missing targets, comments, semicolon variants,
  and mixed syntax.
- Null/empty persisted descendants and exact daemon classification.
- Route-map dual-family expansion, trailing-default reservation, and ceiling.
- RG -1/15/16/255/256 across every mode, unused definitions, previous-good,
  and first boot.
- SNMP valid -> invalid runtime transition and observable warning/status.
- REST/SSE/gRPC/CLI/filter lifecycle-action compatibility goldens.

The review concluded the plan is salvageable and should be revised rather than
killed.
