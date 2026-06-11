# #1861 Claude SMR hostile plan review — round 1

**Reviewer:** Claude (domain SMR: dataplane/session-table/NAT + CPU-arch + SW design)
**Target:** `docs/research/1861-install-txn/plan.md` v1 @ `d4f182696`
**Stance:** hostile — graded against source at origin/master `6d8fa810d`, not against the plan's own claims.

## Verdict: PLAN-NEEDS-MINOR

Path A's core argument survives hostile reading: both installs hit the same
single-threaded `&mut SessionTable`, the only failure mode is the cap check
(`session/mod.rs:690`), and nothing mutates `len()` between preflight and
the second install inside one descriptor iteration (GC `expire_stale_entries`
runs in the worker loop at `worker/loop_body/mod.rs:567`, worker commands in
`apply_worker_commands` — both outside `poll_binding_process_descriptor`).
So preflight-as-transaction is sound. But the plan's severity headline is
over-scoped and the interleaving table misses one production install pair.

## Findings

### F1 (MAJOR — severity scoping): I2's "unreserved tuple aliasing" is pool-mode-only

The plan's §2 headline ("wire-level tuple aliasing — the same cross-flow
reply-misdelivery class as #1760") silently assumes a port-translating
allocator. **Interface-mode SNAT — the default mode and the smoke config's
mode — rewrites the source address only and allocates nothing**:

- `nat/source.rs:442-452`: `if rule.interface_mode { ... rewrite_src, rewrite_dst: None, ..default }` — no `rewrite_src_port`, no allocator call.
- `nat/source.rs:357-365`: `release_source_nat_allocation_with_mode` returns
  early on `rewrite_src_port == None` — the "rollback" in the failure arm
  (`poll_descriptor/mod.rs:1341`) is a **no-op** for interface mode.

So for interface SNAT there is no allocation to leak and no free-list to
desynchronize; the flow-cache entry for a refused flow forwards with
(egress-IP, original sport) — the identical wire tuple a *successful*
install would have used. The cross-flow collision exposure in that mode is
exactly the pre-existing #1760 reverse-key collision surface, not a new
hole. **I2's non-self-healing allocator aliasing is real only for pool-mode
SNAT** (`allocate_translation`, `nat/source.rs:453+` — port-translating,
flow-keyed, genuinely freed by the rollback at `mod.rs:1341` while the
cached descriptor keeps using it). Pool mode is fully supported production
config, so the finding stands — but plan §2 and row I2 must scope the claim,
and the "this alone upgrades the fix" sentence must be re-weighed against
the narrower blast radius. Q8's kill-test arithmetic changes accordingly.

### F2 (MAJOR — missing interleaving): local-tunnel UpsertLocal pair ignores install result

`tunnel.rs:309-331` (`maybe_enqueue_local_tunnel_session`): publishes the
forward+synthesized-reverse pair to the shared maps **unconditionally**,
then enqueues `WorkerCommand::UpsertLocal` ×2 to every worker. The apply
site discards the result:

- `session_glue/mod.rs:556-569`: `WorkerCommand::UpsertLocal(entry) => { sessions.install_with_protocol_with_origin(...); }` — return value dropped.

At cap, the pair is silently not installed in any worker table while the
shared maps already hold both entries — a shared-map/local-table divergence
the plan's I10/I11 rows don't cover. Self-heals via per-packet shared-map
lookups (degraded), and the 1 ms `wait_for_local_tunnel_session_install`
just times out. Needs a row (I13) and a disposition (document + optional
counter; NOT part of the txn fix — same uncapped-sync debate as I11).

### F3 (MEDIUM): at-cap pool-allocator churn is unchanged and unstated

Plan §5.2 places the preflight after the SNAT decision (forced by
`dns_fastpath_admit` needing `decision.nat`). Consequence: at cap, every
refused pool-mode packet still does allocate→rollback round-trips against
the pool allocator's mutex'd state. Acceptable (cold path, overload
condition), but the plan should say so explicitly and note the future
option of a cheap `len() >= max` early-out before NAT evaluation.

### F4 (MEDIUM — behavioral honesty): Path A converts "limps along statelessly" into "sheds"

Today a refused flow whose policy permits **both** directions (permissive
intrazone configs) can pass traffic statelessly at cap (forward via
new-flow path/flow cache; reply via its own policy-permitted new-flow
evaluation). Path A drops such flows until capacity frees. That is the
intended Junos-parity shedding and the right call under overload, but §9's
"behavioral regression MED" row should name this concrete scenario so the
verdict is informed, not discovered post-ship. (For the common
deny-inbound case the reply is policy-dropped today anyway —
`mod.rs:1616-1631` policy-deny arm — so nothing is lost there.)

### F5 (MINOR): Open-delta claim verified — correct

`session/mod.rs:728-737`: delta pushed for `!is_reverse && !is_peer_synced
&& !is_transient_local_seed` — ForwardFlow qualifies; refused flows emit
nothing. Plan §8's "HA peers never learn of refused flows" holds. No action.

### F6 (MINOR): refusal arm must handle `source_nat_release_key == None`

The §5.2 snippet rolls back only `if let Some(release_key)` — correct, but
note the existing failure arm at `mod.rs:1341-1349` uses
`source_nat_release_key.as_ref().unwrap_or(&flow.forward_key)` (rollback
attempted even with no release key, keyed by forward key). The new arm
should match the existing call shape to avoid a silent semantics fork
between the preflight-refusal arm and the residual arm.

### F7 (answering §11 questions)

- **Q1**: match the existing conservative quirk (no replacement credit).
  Replacement-at-cap refusal is pre-existing behavior; crediting it
  introduces a second semantics for zero observed benefit.
- **Q2**: cap-1 refusal of paired flows is acceptable; 131,071 vs 131,072
  per worker is noise, and the alternative (one-sided forward) is the
  defect being fixed.
- **Q5**: fix `created: true` over-count in the same PR only if it is a
  one-line `installed` propagation; otherwise file separately — telemetry
  skew at cap is secondary to the correctness fix.
- **Q8 (kill test)**: with F1's scoping, the kill case is stronger than
  plan v1 admits for interface-SNAT-only deployments — but pool-mode SNAT
  + the unguarded latent I3 + Junos drop-parity still justify Path A's
  ~30-line cold-path change. NOT a kill, provided v2 reframes I2 honestly.

## Required for PLAN-READY

1. §2 + I2 row scoped to pool-mode SNAT (F1) with interface-mode no-op
   rollback stated.
2. I13 row added (F2).
3. F3/F4 wording added to §5.2/§9.
4. F6 call-shape note in §5.2.
