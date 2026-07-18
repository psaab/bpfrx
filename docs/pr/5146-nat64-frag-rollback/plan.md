# #5146 — NAT64 first-fragment association published pre-commit

## Problem

`nat64_install_forward_fragment_assoc` (the #2562 cross-family fragment
cache) was called at NAT64 **source-allocation** time — inside the
`Ok((snat_v4, translated_port))` arm right after
`decision.nat = Nat64State::forward_decision(...)` — which is BEFORE the
flow commits. The commit gates that follow it are:

- the hop-limit / ICMP-TE bounce (`build_local_time_exceeded_request`),
- the `sessions.can_admit` admission preflight,
- the forward session install.

Every one of those has a rollback arm that calls
`crate::nat64::rollback_nat64_allocation`, which releases **only the pool
port**. `Nat64FragAssoc` had no exact-key remove, so a pre-published
association stayed LIVE for `NAT64_FRAG_TTL_NS` (~2s). A non-first
fragment of a rolled-back / dropped first fragment then:

1. inherited a **rolled-back decision** (a verdict the anchor did not
   commit to), and
2. inherited a **released, now-reusable translation** (the pool port was
   freed and can be handed to a different flow) → cross-flow NAT64
   fragment ambiguity under port reuse.

Invariant violated: shared fragment state must become visible ONLY after
the anchor fragment commits to the outcome it authorizes.

## Fix — Option A (delay the install to post-commit)

Move the install to the single POST-COMMIT site — inside
`if forward_installed { ... }`, next to the ordinary same-family install
`nat_install_forward_fragment_assoc`. A rolled-back / dropped / denied
first fragment never publishes an association.

- `nat64_install_forward_fragment_assoc` now self-gates on
  `decision.nat.nat64` (mirrors the ordinary-NAT helper's inverse gate),
  so both installs can be called at the one commit site and exactly one
  populates the table.
- Removed the pre-commit call; the NAT64 `Ok` arm still returns its
  `Nat64ReverseInfo`.

### Enumerated rollback arms now leaving NO live association

| Arm | Site | Reaches post-commit install? |
|---|---|---|
| hop-limit ICMP-TE bounce | rollback @ `local_icmp_te` Some | No — never enters the `else` that installs |
| `can_admit` refusal | rollback @ admission preflight | No — `continue`s before install |
| install-partial (post-`can_admit`, impossible-by-construction) | rollback @ `!forward_installed` | No — `continue`s before install |
| `track_in_userspace == false` (LocalDelivery / DNS fast-path) | rollback @ else | N/A — install helper's ForwardCandidate gate already blocked it; NAT64 self-gate also blocks DNS fast-path |
| **commit** (`forward_installed == true`) | POST-COMMIT install | **Yes — the only path that publishes** |

## Not HA

`Nat64FragAssoc` is per-process (Arc-shared across workers, NOT
session-synced — nat64.rs lines 325-331: "HA does NOT sync it: transient,
sub-second"). No wire-protocol / session-sync surface is touched.

## Test (fail-on-revert, target-count 1)

`src/afxdp/tests_nat64_tunnel.rs`, driven through the real
`poll_binding_process_descriptor`:

- `nat64_committed_first_fragment_publishes_frag_assoc_and_nonfirst_inherits_5146`
  (SUCCESS path preserved): a committed NAT64 first fragment publishes
  exactly one association (`frag_assoc.len() == 1`) and a non-first
  fragment inherits + is NAT64-translated (`nat64_translations == 1`).
- `nat64_rolled_back_first_fragment_publishes_no_frag_assoc_5146`
  (FAIL-ON-REVERT): a NAT64 first fragment refused at `can_admit`
  (`set_max_sessions_for_test(0)`) leaves `frag_assoc.len() == 0`, and a
  subsequent non-first fragment MISSES — `nat64_translations == 0` (does
  not inherit the released translation) and drops fail-closed
  (`dbg.tx == 0`, no v6 route for the synthetic prefix).

Reverting the fix (pre-commit install) makes the rolled-back first
fragment publish → `frag_assoc.len() == 1` and the non-first fragment
inherit + translate → `nat64_translations == 1`: both assertions flip
RED. Exactly one test.
