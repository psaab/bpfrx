# #1866 plan review — Claude SMR (hostile), round 4

Reviewer: Claude (domain SMR). Target: plan.md v4 @ 677566943 (+ the
shared-hydration-helper precision added before this review).

## Round-3 resolution check

Codex r3's residual (same-id identity change under defer with an
existing tombstone) is closed by the snapshot-coherent respawn
condition: I re-ran the S0/S1 sequence against v4 — at the sweep, the
stored snapshot's row for id 1 carries identity B while the forwarding
endpoint carries A ⇒ mismatch ⇒ skip; the tombstone survives untouched
until the deferred bring-up reconciles forwarding to B and the
apply-time spawn pass creates the B thread coherently. Test 6c pins it.

## Round-4 questions (§11)

1. **Comparison soundness/completeness.** The tuple matches
   `wg_identity_unchanged` field-for-field (listen_port, local privkey,
   peer pubkey, allowed-ips, endpoint, keepalive). Two drift hazards
   existed and are both addressed: (a) allowed-ips skip-invalid and
   endpoint-parse semantics must equal hydration's — handled by the
   factored `hydrate_wg_identity` helper shared with populate (added to
   §5); (b) `state.snapshot` is the latest ACCEPTED snapshot —
   `apply_snapshot` stores it on every accepted branch (same-plan both
   legs, not-same-plan both legs) BEFORE `refresh_status`, and rejected
   snapshots (version gate, integrity preflight) return without storing,
   under the same guard. No window where the sweep sees an older
   snapshot than the one last accepted.
2. **Remaining incoherent-spawn sequences.** Enumerated creation sites
   are unchanged from r3 (apply-time only) plus the now-guarded sweep.
   Helper restart with persisted state: fresh process has an empty map;
   threads appear only via reconcile/bringup from the stored snapshot —
   coherent. The one acknowledged residual is pre-existing master
   behavior (a LIVE thread keeps its old identity through a defer window
   until the deferred bring-up replaces it) — bounded, unchanged by this
   plan, and out of scope by design.
3. **Anything else.** No. The plan's defect inventory (D1-D4) is closed,
   observability (D3) gives the §4c recurrence capture, scope stays
   tight to teardown/lifecycle (no counters, no TUN delete, no wire
   changes), and sequencing/test gates are explicit.

## Verdict

**PLAN-READY** — v4 with the shared-hydration precision. Three review
rounds of strictly-narrowing fixes; no remaining counterexample
constructible from the enumerated lifecycle surfaces.
