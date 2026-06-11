# Claude SMR hostile plan review — #1879 round 3 (convergence)

Plan reviewed: DRAFT v3 @ `67e4753f3`.

## My round-2 dispositions

- N1 (renames persist) — ADDRESSED. Step 4a closes with the explicit
  "renames persist deliberately" semantics and re-bases T1 assertions
  on reachability + zero-claims.
- N2 (reconcile-to-empty subsystem semantics) — ADDRESSED, and
  superseded by the stronger Codex r2-2 disposition: 4a is now an
  ordered cleanup sequence with the manager.go:641
  helper-resurrection rationale, the FRR/VRRP clearing citations, and
  the "any subsystem that cannot shrink to zero gets its residue
  enumerated and accepted explicitly" clause.
- N3 (gate scope note) — ADDRESSED in step 4 (first-commit ≠
  first-takeover, Junos-consistent).

## Hostile check of the v3 edits themselves

- Step 0's daemon-owned transaction correctly states the atomicity
  constraint (applySem across promotion + apply) while deferring the
  configstore hook shape — the right altitude for a research plan;
  the dedicated serialization test is named in §9.
- The never-committed marker correctly distinguishes the three
  states (never-committed / operator-committed-empty /
  committed-nonempty) and states the #1799 persist-failure
  constraint on the representation.
- PCI+MAC lifeline keying resolves the AGY r2 rename-staleness hole;
  the resolve-at-reconcile-time rule keeps the protected set correct
  through arbitrary rename sequences. Non-PCI NICs (none in any
  supported topology today, but USB/virtio-mmio exist) fall back to
  MAC — adequate.
- 4a ordering is sound: networkd first (restores lifeline-only
  surface), control-plane renderers second, dataplane teardown last;
  nothing in the sequence depends on a subsystem removed earlier in
  the sequence.
- Nit (non-blocking, /engineer checklist item): if the unconfirmed
  first commit enabled chassis-cluster subsystems (heartbeat,
  session-sync), 4a's generic residue clause covers them but they
  are worth naming in the /engineer-phase teardown audit alongside
  FRR/VRRP/helper.

## Verdict

PLAN-READY.

The plan reuses the right primitives, every load-bearing safety
claim now carries either a cited mechanism or a named test, costing
is honest (M1a 3-5 d / M1b 1-2 w / M2 2-3 w spike-gated), and the
recommendation (Path D staged: M1a deb + M1b safe-bootstrap → M2
image → M3 installer) survives the operator-pinned C-first challenge
on dependency-ordering grounds (the image consumes the deb; the
spike keeps C from sliding).
