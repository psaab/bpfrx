# Claude SMR hostile plan review — #1760 stage-2 revisit, round 1

**Verdict: PLAN-NEEDS-MINOR** (concrete revisions below; the evidence base
is sound — I verified every §2 claim against the worktree myself — but two
findings materially weaken Path A1 and one weakens the W2 design as
written. None of them changes the recommended Path W direction; all must be
folded into v2.)

## Findings

### F1 (Medium) — Path A1 as sketched has a cross-worker TOCTOU the plan
### does not state; this further strengthens W over A1

§5/Path A1 says the guard checks the local table plus a presence check on
`shared_nat_sessions`. But the guard (a read) and the publish (a write)
are separate critical sections: `publish_shared_session`
(`shared_ops.rs:648`) takes the mutex AFTER local install and BPF publish
(`poll_descriptor/mod.rs:1284-1316` ordering). Two workers installing two
colliding flows in the same poll interval both run the guard (both see K
absent), both admit, both publish — the collision is admitted exactly in
the window where the per-worker architecture makes it most likely
(near-simultaneous flows hash to different workers). A race-free A1 needs
an atomic check-and-reserve under the shared-map mutex BEFORE local
commit, i.e. the guard-before-commit reordering is not just "move the
check earlier" but "invert the commit order around the shared lock".
That is more rework than §5's sketch implies. **Required: state this in
§5/§8, and let it weigh in §11 Q5.** (It does not affect Path W, which
only observes.)

### F2 (Medium) — W2's preconditions are asserted, not verified

W2 assumes the loss-cluster active config interface-SNATs LAN→WAN traffic
with no port rewrite. The issue text says interface-mode SNAT "is used by
the HA smoke config itself", but that claim is from 2026-06-04 and config
deploys wipe/replace state regularly (deploy wipes CoS is a standing
gotcha). **Required: W2's first step must be `show security nat source`
(or config grep) on the live cluster to confirm interface-mode SNAT on
the LAN→WAN policy, and the harness must assert the SNAT'd flows actually
traverse (reverse path works for flow 1 before flow 2 starts) so a refusal
of the construction is distinguishable from a routing failure.** Also
note: the two flows must originate from two distinct source IPs whose
RSS placement does not matter (any worker pair is fine per §2.3 — good),
but both must egress the SAME node (active RG), so the harness pins to
the active node's LAN path.

### F3 (Low) — §2.7 math needs the cross-host correction in the main text

Expected concurrent collisions ≈ C(F,2)/28232 over-counts by including
same-host pairs, which cannot collide (kernel 4-tuple uniqueness per
source IP). With H equal-traffic hosts the cross-host fraction is
(1 − 1/H); for H≥10 the correction is <10% and immaterial, but the plan
cites the formula as load-bearing for "routinely" — put the correction in
§2.7, not just as an aside in Q6.

### F4 (Low) — W1's eprintln is on a worker thread; say why that is safe

`eprintln!` writes to stderr → journald socket; a blocked journald
back-pressures the writer. At ≤1 write/60s/worker this is the accepted
project pattern (`xpf-ha:` eprints), but the plan should say so explicitly
since the hook is inside the poll loop's tick path.

### F5 (Low) — the W-vs-K decision criterion should be made explicit

Path W's value is conditional on a future multi-host deployment (the lab
population cannot collide, §2.2 — W does not change that). If the
operator's honest posture is "lab-only for the foreseeable future", Path K
(close as accepted-risk) dominates W. The plan hints at this in §5/K but
the recommendation line should state the conditional: **W if production
deployment is anticipated; K/close if not.** This is an operator call, not
a reviewer call — surface it.

## Claims I verified directly (no findings)

- §2.3 self-correction is right: `replicate_session_upsert`
  (`session_glue/mod.rs:596-607`) unconditionally queues `UpsertSynced` to
  every sibling; `handle_upsert_synced` always reaches
  `upsert_synced_with_origin` (HAInactive only skips the resolution
  update, `upsert_synced.rs:55-61`); the `allow_replace_local`
  early-return (`session/mod.rs:782-786`) keys on the SAME forward key and
  cannot suppress a colliding (different-key) replica; indexing always
  runs (`session/mod.rs:810` → `:1393-1406`). Coverage holds; multiplicity
  makes it an upper bound as documented.
- §2.4 is right: the shim's only verdicts for transit are XSK-redirect or
  kernel-pass-for-local-delivery (`userspace-xdp/src/lib.rs:530-690`);
  `live_userspace_session_action` (`:1331`) is a map lookup, not an
  offload; WG/GRE/NDP branches are local-control shapes. SYN-ACK/ACK of
  transit flows reach userspace. The prior round's AGY refutation is dead.
- §2.5 wart confirmed at `poll_descriptor/mod.rs:1340-1445` (reverse
  install + forward proceed not gated on `forward_installed`).
- §2.6 blast radius: `reply_matches_forward_session` introduces no field
  beyond K (`session/key.rs:24`), so verify passes for the wrong session;
  walk is correct.
