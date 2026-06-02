# Claude-SMR r2 + round-2 reconciliation — #1748 plan @ 47db3a4f4

**Round-2 verdict: PLAN-NEEDS-MAJOR (converging, salvageable).**
Codex r2 = NEEDS-MAJOR (3 verified holes). Claude-SMR = concur. AGY r2 pending.

## The real shape of the problem (both rounds, both reviewers)

The research plan's premise — "the session substrate already replicates to all
workers, so a re-pin needs **no migration code**" — is now **falsified twice
over**. A re-pin is a genuine **session-ownership transfer** from W_old to
W_new, and the system's GC/sync/HA state machine assumes exactly one owner. v1
missed it entirely; v2 fixed the *premature-cleanup* half but Codex r2 proved
v2 created a *never-cleanup* leak and missed two more shared-state sites. The
controller cannot be an additive module — it must correctly hand off ownership
through the origin/GC/sync/export/demote/refresh paths, which are the most
HA-critical code in the tree.

## Verified holes still open after v2 (all code-confirmed)

1. **Conntrack mirror delete (5th site).** `delete_session_map_entry_..._with_origin`
   deletes conntrack unconditionally (`bpf_map/mod.rs:1032,1037`) and the
   redirect-key helper ignores origin (`:952`); W_new will NOT recreate it
   (conntrack publish gated on `resolved.created`, `poll_descriptor/mod.rs:253`).
   → suppression must cover conntrack, and the redirect helper must become
   origin-aware.
2. **No close-delta owner after the move (the v2-induced leak).** W_new's replica
   is `WorkerLocalImport` = peer-synced ⇒ its eventual real expiry is ALSO
   delta-suppressed (`session/mod.rs:431`). So after W_old→RebalancedOut and
   W_new→(silent), **nobody** cleans up the shared map / emits the peer Close
   when the flow truly ends → shared-state leak. The move needs an explicit
   **target-side ownership promotion**: W_new's entry becomes a close-OWNING
   origin (emits Close on real expiry, deletes shared map, broadcasts) WITHOUT
   re-running NAT allocation. This is the crux v3 must design.
3. **`RebalancedOut` leaks into HA/export paths.** `demote_owner_rg()` rewrites
   non-peer-synced owner-RG sessions to `SyncImport` (`session/mod.rs:1030,1039`)
   → erases the marker before GC. `refresh_owner_rgs` republishes without origin
   exclusion (`:32,80`). Peer export emits Open deltas for non-peer forward
   sessions (`session_glue/mod.rs:420,436`). RebalancedOut (and the new owning
   origin) must be excluded from demote/refresh/export/delta-sync.

## Refinements (not blocking, fold into v3)
- **Eligibility**: "age > sync interval" is insufficient; require a **fresh
  target-worker replica ack immediately before rule install**
  (`shared_ops.rs:376` is the hit path that avoids the miss/NAT route).
- **Thrash bound is `≤ gap/2`, not `≤ gap`** (Codex): moving a flow larger than
  half the source-dest gap makes the destination the new hottest. Plus
  ε-band on projected CoV improvement → monotone, terminating.
- **ethtool ioctl direction CONFIRMED CORRECT** (Codex cross-checked kernel
  UAPI): `ethtool_rx_flow_spec{h_u/m_u, ring_cookie, location}` +
  `ethtool_rxnfc{rule_locs}`, `SRXCLSRLINS/DEL/ALL` are ioctl-only; netlink lacks
  them. The mechanism is sound; the risk is the ownership state machine, not the
  ioctl.

## Scope assessment (the honest part)
- **Mechanism: proven** (R1: CoV 16.8%→2.3–4.2%, aggregate up; ioctl path
  confirmed). This is real and the only lever that fixes cross-worker fairness
  without aggregate loss.
- **Controller: a session-ownership-transfer protocol on HA-critical paths.**
  Implementable, but it touches the origin/GC/sync/export/demote/refresh state
  machine — the most delicate, failover-critical code in userspace-dp. Both
  reviewers found real correctness holes in two rounds; a third round + the
  implementation itself will be high-care work, and `make test-failover` +
  HA-crash coverage become mandatory gates, not nice-to-haves.

This is a legitimate go/hold decision for the author: drive v3 → implement the
ownership-transfer protocol (substantial, high-value, HA-critical), or bank the
proven mechanism + this precisely-mapped design as the research outcome and
schedule the implementation deliberately.
