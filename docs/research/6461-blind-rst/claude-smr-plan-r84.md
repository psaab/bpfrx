# Claude SMR hostile plan-review — round 84 (v10.1.0 → v10.1.1 fold verification)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I authored the
v10.1.0 folds of Codex r83's three BLOCKERs; this pass attacks the folds.
Verdict: **PLAN NO for v10.1.0** — two precision nits (both folded as
v10.1.1); no LOW or above. Codex r83's findings are individually verified
against the code below.

## Codex r83 finding verification (against this branch's code)

- **B1 (MissingNeighbor raw-flags replace) — CONFIRMED on master.**
  `poll_descriptor/mod.rs:4787` installs
  `MissingNeighborSeed(..., meta.tcp_flags)` unconditionally in the
  common disposition arm; `install_with_protocol_with_origin`
  `remove_entry`s the existing key (`install.rs:140`) and seeds
  `closing`/`reset`/timeout from raw flags (`install.rs:179-180`). The
  #4400 guard (`poll_descriptor/mod.rs:1640-1650`) covers only the
  ForwardCandidate/MissingNeighbor miss class. The resolve layer can
  return MissingNeighbor for a live entry (session_glue/mod.rs:128,
  :155). So a refused close on a hit with a cold next hop was re-demoted
  by the dispatch arm — the gate's verdict was not terminal. The
  v10.1.0 provenance gate closes it; I verified no SECOND arm
  installs/replaces from raw flags on a hit (ForwardCandidate arm
  installs on miss only, promote path covered by rule 5, LocalDelivery
  re-evals policy but installs on miss only, FabricRedirect/NoRoute
  never install).
- **B2 (probation global teardown) — CONFIRMED on master.**
  `worker/loop_body/mod.rs:1491-1504` releases NAT for every expired
  entry unconditionally; `bpf_map/mod.rs:633/:704` deletes the family
  keys; the allocator release is not ref-counted
  (`nat/allocator.rs:1318`). The zombie shares the live family's
  process-global state. The v10.1.0 local-only reap (ExpiredSession
  carries probation; skip release + BPF delete + delta) is the right
  local rule and is strictly safer than master's born-dying copy.
  Residual I checked and accept: a CLEARED probation entry (committed
  non-close) reaps with master's normal cleanup — that is #6522's
  pre-existing class, not the zombie window, and the plan's re-scope of
  #6522 stands.
- **B3 (admitted-hit drop) — CONFIRMED as designed behavior of
  v10.0.1's always-re-resolve.** Master transmits the buffered decision
  (`neighbor_dispatch.rs:272`); the entry can expire during the ARP
  wait; the fresh re-resolution then misses and #4400 drops the
  admitted close. The v10.1.0 interim-expiry hold (expiry pass skips
  entries with a pending packet; bounded by the pending timeout) closes
  it without re-admitting stale decisions.
- **M4 (drop-oldest tail)** — verified (`tx/drain/mod.rs:33, :56`;
  enqueue push-then-bound at `tx/dispatch/mod.rs:665, :786`); the
  documented-residual disposition matches the plan's existing async-tail
  posture. **L5/L6/nit** — folded (open_valid && open_trusted explicit;
  phase2-brief cleanup line; header claims).

## Finding 1 (nit — the provenance mechanism was unnamed)

v10.1.0 stated the site-9 rule ("gated on a genuine top-level session
MISS") without the mechanism; an implementer could gate on disposition
(which does not distinguish hit from miss — the whole point of the
finding). Folded at v10.1.1: the arm receives the resolve outcome's
provenance (`resolved_from_live_entry: bool`) and skips the seed install
whenever it is true.

## Finding 2 (nit — non-expiry removals during a pend were unstated)

The B3 hold covers the expiry pass only. An operator control-socket
session delete during a pend produces a re-resolve-to-miss drop (master
transmits the buffered decision); an RG vacate produces a fresh
standard-dispatch. Both are defensible, but the plan's never-drop
invariant needs the carve-out stated. Folded at v10.1.1.

## Bottom line

Codex r83 was the round the cut needed: three LOCAL dispatch-path
defects, all verified against master code, all folded with local rules
(provenance gate, local-only probation reap, bounded interim-expiry
hold) — zero protocol growth. The two nits above are folded at v10.1.1.
If Codex r84 verifies the folds and finds nothing new at LOW+, this plan
is at convergence.
