# Claude-SMR hostile plan review r1 — #1748 controller plan @ c84523b27

**Verdict: PLAN-NEEDS-MINOR** (architecture validated by R1; four refinements
required before code, none fatal).

I entered hostile, expecting to find a kill in R4. I did not — R1 empirically
forecloses the obvious kill — but I found a sharp correctness refinement the
plan currently hand-waves.

## The one that matters — move-eligibility must gate on session replication (R4/R3)

The plan leans on research §0 ("replicas exist on all sibling workers, so the
moved flow forwards correctly"). That is true for a *fully-replicated* session,
but the code has a whole family of session-MISS handlers that fire when a worker
does **not** have the session: `forwarding/mod.rs:1026
interface_nat_local_resolution_on_session_miss`, `:1057
install_helper_local_session_on_miss`, `:1164
ingress_interface_local_resolution_on_session_miss`. If the controller steers a
flow to a worker whose replica has not landed yet (a young flow, or a
replication gap), the target worker takes the on-miss path → **NAT
re-resolution** → a fresh SNAT binding → server sees a new source port → RST.
That is the real correctness hazard, and "replicas exist" is not a sufficient
guarantee on its own.

R1 did not hit this because it moved flows that had run ~14 s (well-replicated).
The controller must encode that as an explicit invariant, not luck:
**move-eligibility = flow age > (session-sync interval + margin) AND the target
worker's replica is confirmed present.** Add this to §4.2 step 2 as a hard
precondition. This also bounds R3: only long-lived elephants move (exactly the
ones worth moving), and they are the ones with warm replicas → flow-cache miss
on the target resolves to the EXISTING session, no NAT realloc, bounded reorder.

This is NEEDS-MINOR, not KILL: the mechanism is proven correct for the eligible
set; the plan just has to define the eligible set precisely.

## Three more refinements

2. **ethtool_rxnfc UAPI (§4.1)** — the sketch omits the `h_u`/`m_u` union
   (`ethtool_tcpip4_spec` for `flow_type=TCP_V4_FLOW`) and the `ring_cookie`
   semantics (the action queue is the low bits of a u64 `ring_cookie`, with
   special values like `RX_CLS_FLOW_DISC`). Get this exactly right or rules
   silently mis-steer. Require a compile-time `size_of`/offset assertion against
   the kernel UAPI AND a round-trip test (insert → `GRXCLSRLALL` → read back the
   spec) on the live NIC in the test plan, not just a size check.

3. **Selection convergence (§4.2, Q4)** — "heaviest flow on hottest worker → 
   least-loaded" is greedy and can oscillate when two elephants are
   near-equal (move A to q5, next tick q5 is now hottest, move A back). The
   cooldown is mentioned but not specified. Require: a per-flow cooldown ≥
   several rebalance intervals AND a hysteresis band (do not move unless the
   projected post-move max-worker byte-rate improves by > ε). State the stop
   condition as "no single move reduces the byte-rate CoV by > ε" and prove it
   terminates (finite flows, monotone objective under the ε-band).

4. **Scope honesty (Q6)** — forward-only + single-node + default-OFF IS a
   coherent shippable unit: it directly fixes the operator's `-P12` push symptom,
   it is opt-in, and post-failover it degrades to RSS (fairness, not
   correctness). But §9 must state the post-failover behavior in the OPERATOR
   docs, not just the plan — an operator who enables it and sees fairness vanish
   after a failover needs that documented. Acceptable to ship; document the
   limitation.

## What I verified
- `forwarding/mod.rs:541` owner-RG gate is per-RG, not per-worker (confirms no
  per-worker forwarding gate — research §0 holds for the forwarding decision).
- The on-session-miss family at `:1026-1164` is the real NAT-realloc hazard the
  eligibility gate must avoid.
- `umem/mod.rs:387 tx_bytes: AtomicU64` exists as the byte-rate signal;
  `coordinator/status.rs:195-206` already has the per-(ifindex,queue,worker)
  aggregation the controller reads — so no new control-socket caller (Q5 OK).

## Not blocking
R2 (reverse) and R4-continuity (peer mirroring) deferral is fine given default-
OFF + documented failover behavior. ethtool genetlink-crate exclusion is
correctly verified (flow rules are ioctl-only).
