# Claude SMR — hostile plan review r1 of `plan.md` v6-r1 (#2387)

Reviewed at `e80db2eae`. I am the author of the plan under review, so the bar for
this pass is that it must produce findings that **change the plan**, not confirm it.
It does: one of them (SMR-1) invalidates the plan's central design recommendation as
written.

## SMR-1 — MAJOR. The plan is blind to a prescribed chain it is the middle link of.

The plan treats #2387 as a standalone decision. It is not. Issue **#5804**
("GRE: implement key and call-ID session identity") carries a maintainer-directed
scoping decision stating that **#4983, #2387 and #5804 are one decision** — all three
widen the same `SessionKey` — and prescribing a **chain, not parallel lanes**:

> **#4983 → #2387 → #5804**

with the rationale that parallel lanes would *"manufacture conflicts in one struct and
produce three partial answers to one question"*, and that **#2387 is the designated
owner of the HA-wire decision, paid for once**.

State of the chain, verified:

| Issue | State | Branch / PR |
|---|---|---|
| #4983 — sessions lack true ingress-interface identity | **OPEN**, `plan-deferred` | none |
| **#2387** — this issue | OPEN, `plan-deferred-operator` | research only |
| #5804 — GRE key / call-ID identity | **OPEN**, `plan-deferred-research` | none pushed; uncommitted worktree work that touches neither `SessionKey` nor the wire |

**Why this changes the plan, not just its framing.** §5's C-P3 proposes appending
`routing_domain` as a trailing VALUE field — a *bespoke, single-field* widening. If
#2387 ships that, **#5804 is forced into a second wire mechanism later**, which is
precisely the duplicated-hard-break outcome the chain ordering exists to prevent.
C-P3 must instead be specified as a mechanism #5804 can **extend** — a versioned or
field-tagged encoding — even though #2387 alone would not need one.

**Required change:** add a section on chain position; rewrite C-P3 as an extensible
mechanism; state whether #4983 is a hard blocker.

**My assessment of the blocker question** (the plan must answer it, so I will):
#4983 is a **sequencing preference, not a hard technical dependency**. Its stated
value is that it is VALUE-only and old-peer-safe, so it proves the
meta→logical-ingress resolution plumbing in a place where a bug is *cosmetic* rather
than a forwarding fault. That is a genuine risk argument and I would honour it — but
#2387 does not import a symbol or a wire field from #4983, so calling #2387 BLOCKED
would be false precision.

## SMR-2 — MAJOR. §4.3 is right for #2387 and would be dangerously wrong if generalized.

The plan proves the trailing-field append is additive and concludes the upgrade stays
rolling. I verified that independently and it holds **for this discriminator**. But the
plan states the safety property too broadly, and the chain makes that dangerous:

- **#2387 `routing_domain`:** an old peer omits the field → decodes to 0 → 0 is
  interned as the *default* routing-instance → a domain-N packet **fails to match** →
  the flow re-establishes. Identity **narrows**. **Fail-closed.**
- **#5804 GRE discriminator:** an old peer omits the field → decodes to 0 → two
  distinct keyed tunnels both present as "key 0" → they **alias onto one session**.
  Identity **widens**. **Fail-open — a security fault.**

Same mechanism, opposite safety polarity. #5804's own acceptance criteria demand
"mixed-version **reject**, not widen", which the bare trailing-field mechanism cannot
provide.

**And the plan failed to answer a question it was asked:** *is there a
negotiated-capability path already in the tree to reuse?* **There is not.**
`performSyncHandshake` is **auth-only** — there is no feature or capability
negotiation on the session-sync channel today. The plan must say this plainly, because
it means C-P3 is not merely "append a field": for the chain to work, #2387 is the
issue that must **introduce** capability negotiation, and that is real scope the plan
currently prices at zero.

**Required change:** split §4.3's conclusion into "safe for a narrowing discriminator"
vs "unsafe for a widening one"; record that no capability negotiation exists; move the
negotiation mechanism into C-P3's cost.

## SMR-3 — MODERATE. Path B is structurally forced, and the plan under-argues it.

The plan rejects Path B (DENY) on *semantic* grounds — not Junos parity, hands a
tenant a DoS primitive. Those stand, but there is a stronger structural argument the
plan misses: `SessionTable.key_to_handle` is `SeededKeyMap<u32>`
(`userspace-dp/src/session/mod.rs:548`) — strictly **1:1, one live session per key**.

So a non-key discriminator under a 1:1 map has exactly two possible behaviours —
evict the other context's session, or refuse to create yours — and **both are
cross-tenant faults**. Path B is not a cheaper design point on a spectrum; it is the
only thing a 1:1 map *can* do. Any non-key approach first requires converting
`key_to_handle` to 1:N and re-auditing every reader that assumes one-session-per-key
(the assumption is documented at `userspace-dp/src/session/README.md:409-415`).

This makes the plan's own §5 sub-argument ("decline-and-fall-through collapses into
Path C") sharper and correct, but the plan should cite the 1:1 map as the reason
rather than only the unconditional `remove_entry`.

## SMR-4 — MODERATE. The byte budget is measured in isolation; the chain blows through it.

§4.4 measures 40 → 44 bytes for #2387 alone. Across the chain:

- 40 today
- 44 with `routing_domain: u32`
- **48 with #5804's discriminator too** (+20%)
- **past 48** if #5804 picks the *typed* `TunnelDiscriminator` enum it lists as its own
  architecture question — an enum costs 8 bytes on its own (discriminant + padding).

**Required change:** state the budget across the chain, and prescribe the constraint
it implies — **all discriminators must be plain fixed-width integers, with anything
variable (VRF name, tunnel identity) interned to an id at config-compile time.** The
plan already says this for `routing_domain`; it needs to say it as a *chain-wide*
rule, because it is a constraint #2387 imposes on #5804.

Also under-counted: the key is compared on **every flow-cache hit**
(`flow_cache.rs:204`) and feeds `set_index` bucket derivation (`flow_cache.rs:870`),
whose distribution shifts for **all** protocols — not only those carrying a
discriminator. §4.4's "one extra `write_u32` per hash" is right but incomplete.

## SMR-5 — MINOR. Literal count.

The plan says **301** `SessionKey {` sites; an independent sweep scoped to
`userspace-dp/src` counts **297**. The difference is my inclusion of `userspace-xdp`
and test files. The number is directionally right and the conclusion (a third are test
fixtures; most of the 743 references are `&SessionKey` parameter passing needing no
edit) is unaffected. Reconcile the figure and state the grep scope.

## SMR-6 — the recommendation, re-tested.

I attacked my own Path-C recommendation and it survives, but only in amended form.
Path A (do nothing) still contradicts the shipped A.1 warning text. Path B is now
*more* clearly wrong, not less (SMR-3). Path D's config-stability hazard remains the
sharpest open question and I have not resolved it — a domain id derived from a
config-analysis result can change under a live session, and the plan owes a re-key or
generation-pinning answer.

But the recommendation as written — "Path C with D's rollout discipline" — is
**incomplete**, because it prices C-P3 as a bare append when the chain requires it to
carry capability negotiation (SMR-2). That is not a wording fix; it is added scope.

## Verdict

The defect is real and I re-verified its reachability first-hand. The wire retraction
is correct. But the plan is missing its own chain position, under-prices C-P3 by the
cost of the negotiation mechanism that does not yet exist, and measures the byte
budget in isolation.

**VERDICT: PLAN-NEEDS-REVISION**

Required for r2:
1. Add the chain section (#4983 → #2387 → #5804); state #4983 is a sequencing
   preference, not a hard blocker; state that #2387 owns the wire decision for all three.
2. Split §4.3 into narrowing-vs-widening safety; record that `performSyncHandshake` is
   auth-only and **no capability negotiation exists**; move that mechanism into C-P3 cost.
3. Cite the 1:1 `key_to_handle` map as the structural reason Path B is forced.
4. State the chain-wide byte budget and the "plain fixed-width integers, interned at
   config-compile time" rule; add the flow-cache compare and `set_index` distribution.
5. Reconcile 301 vs 297 and state the grep scope.
6. Give Path D's config-stability hazard an actual answer or promote it to a blocking
   open question.
