# Claude SMR — hostile plan review r2 of `plan.md` v6-r2 (#2387)

Reviewed at `e80db2eae`. r1 findings SMR-1..SMR-6 were folded. This round has one
**new MAJOR** that I found while constructing the r2 attack on my own fix — the r1
remedy for Path D is itself defective — plus two smaller items.

## SMR-7 — MAJOR (NEW). "Static deterministic interning" does not fix Path D's hazard. It relocates it.

r1 (via AGY) refuted Path D because domain ids derived from a config-analysis result
can move under a live session. v6-r2 replaced it with:

> Domain interning must be **static and deterministic across all routing-instances**

**That phrase, as written, reintroduces the same class of fault by a different route.**
"Deterministic across all routing-instances" most naturally means *derived from the set
of RIs* — e.g. sorted RI names mapped to 1, 2, 3… Under that reading:

- **RI deletion renumbers its successors.** Delete the alphabetically-first
  routing-instance and every higher-numbered RI shifts down by one. Every live session
  in every one of those RIs is now keyed on an id that denotes a **different VRF**.
  This is strictly worse than what AGY refuted: not a failure to match (self-DoS) but a
  **match against the wrong VRF** — i.e. #2387's original cross-forwarding bug,
  re-created by the fix, and triggered by an ordinary unrelated commit.
- **Id reuse after delete/re-add** has the same shape even without renumbering: a
  recycled id lets a stale session match a new, unrelated tenant.

The v6-r2 text is ambiguous enough to be implemented this way, and the ambiguity is on
the security-critical side. **This is a plan defect, not a wording nit** — the whole
point of rejecting Path D was id stability, and the replacement does not deliver it.

**Required for v6-r3 — the property must be stated as an invariant, not an adjective:**

> A `routing_domain` id is **allocated once per routing-instance identity and never
> re-derived from the current RI set**. Ids come from a monotonic allocator with a
> persisted name→id table carried in config state. Deleting an RI **retires** its id;
> a retired id is **never reissued**. On RI deletion, sessions in that domain are
> explicitly flushed rather than left to age out under an id that no longer denotes
> anything.

Note this also has to survive a **daemon restart** and a **config rollback** — the
name→id table is persistent state, so it belongs with the config store, and a
`rollback` must not renumber. That is real scope the plan currently prices at zero,
and it should be called out in C-P0.

## SMR-8 — MODERATE. §4.3a's fail-closed claim is asserted for the forward direction only.

§4.3a claims an absent/zero domain always **narrows** identity. I believe that is
right, but the plan asserts it rather than demonstrating it, and it is only obviously
true for the forward direct-primary lookup. The three paths that need the same argument
explicitly:

1. the **reverse companion** built by `build_reverse_session_from_forward_match`;
2. the **NAT-translated alias** resolved via `reverse_translated_index` — note this
   index is a **1:N multimap** with validate-on-lookup (`#4438`), a different structure
   from the 1:1 `key_to_handle`, so the "1:1 forces the fault" reasoning in §5 does
   **not** transfer to it;
3. **peer-synced** sessions imported at domain 0 on a VRF cluster.

For a *narrowing* discriminator each of these should still only fail to match. But
"should" is the word doing the work. **Required:** state the argument per-path, or
demote the claim from "fail-closed" to "fail-closed on the primary path; the alias and
reverse paths need a test".

## SMR-9 — MINOR. The plan still does not choose between §11 Q2's (i) and (ii).

§4.3a correctly identifies that the chain needs a capability signal and that #2387
owns the wire decision, then leaves (i) introduce-the-bit vs (ii) defer-to-#5804 open
for reviewers. That is honest, but a converged plan has to land it, because the two
answers give materially different cost estimates for C-P3. My own read: **(ii)**, with
the rationale written down — #2387's polarity is fail-closed, so it does not need the
bit; forcing it to build one for a *future* consumer inflates the PR that already
carries the most risk, and the F23 handshake's PSK gating means the bit would not
protect unkeyed clusters anyway. But the plan must say so rather than leaving it to
`/engineer`.

## Verdict

The chain finding, the Path D withdrawal and the polarity split all landed correctly.
But the replacement for Path D is under-specified in exactly the direction that matters,
and as written it admits an implementation that re-creates the original
cross-forwarding bug through routine config churn. That has to be nailed down before
this is a plan someone can build from.

**VERDICT: PLAN-NEEDS-REVISION**

Required for r3:
1. Replace "static deterministic interning" with the allocate-once / never-reissue /
   flush-on-delete invariant, including its persistence, restart and rollback
   obligations, and put that scope in C-P0.
2. Make §4.3a's fail-closed claim per-path (primary, reverse companion, NAT-translated
   alias via the 1:N `reverse_translated_index`, peer-synced), or demote it.
3. Land §11 Q2 on (i) or (ii) with a written rationale.
