PLAN NO

Reviewed v9 at `968bc1d4a`; no files were edited.

## Findings

1. **BLOCKER — A stale E1 Close can erase replacement E2 locally**

   V9 fences `DeleteSynced` and the Go-side delete, but does not require incarnation checks for the local Close consumer ([plan.md:837](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:837)). The worker reaps E1 and queues its Close at [loop_body/mod.rs:811](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:811), processes packets—and can install same-key E2—at [loop_body/mod.rs:887](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:887), then drains E1’s Close at [loop_body/mod.rs:970](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:970).

   The stale Close then key-deletes queued traffic, BPF/conntrack/DNAT state, current shared aliases, and peer replicas at [session_delta.rs:84](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:84) and [session_delta.rs:406](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_delta.rs:406); `remove_shared_session` removes whichever incarnation currently occupies the key at [shared_ops.rs:960](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:960).

   Thus an accepted blind close on E1 can still be followed by E2 re-seeding and stale E1 cleanup destroying E2’s forwarding/NAT state. Every local Close mutation must compare the expected incarnation, or GC Close deltas must be fully flushed before packet polling.

2. **BLOCKER — The commit-time stale-clone guard covers materialization only**

   V9 adds its incarnation/reservation recheck specifically to `materialize_shared_session_hit` ([plan.md:807](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:807)). Shared-NAT lookup nevertheless returns a detached clone at [shared_ops.rs:491](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:491) and [shared_ops.rs:638](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:638).

   Reverse synthesis consumes that clone without rechecking at [session_glue/mod.rs:1264](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:1264) → [shared_ops.rs:824](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:824). Embedded ICMP consumes it directly at [nat_match_v4.rs:41](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/icmp_embed/nat_match_v4.rs:41) and [nat_match_v6.rs:66](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/icmp_embed/nat_match_v6.rs:66).

   Race: E1 is cloned; its reservation is released; E2 reuses and publishes the reverse tuple at [shared_ops.rs:918](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:918); the detached E1 decision still installs or forwards. An E2 reply can therefore be translated using E1’s internal destination. The commit validator must cover every detached shared-state consumer.

3. **HIGH — “A blind close can never mark/emit Close” is not the implemented security claim**

   The absolute claim appears at [plan.md:23](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:23), [plan.md:1640](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1640), and [phase2-brief.md:14](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/phase2-brief.md:14). V9 elsewhere correctly admits approximately 1/6,554–1/10,923 blind acceptance per packet and sustained-spray success at [plan.md:185](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:185) and [plan.md:261](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:261).

   A blind guess landing in any admitted interval passes [plan.md:984](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:984), takes the accepted mark/propagation path at [plan.md:1093](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1093), and later satisfies the Close predicate at [plan.md:1270](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1270). Its HA and SNAT effects are intentional validated-close behavior.

   I found no ungated path by which a refused, out-of-window, or no-baseline live-session close marks through lookup, promotion, materialization, reverse synthesis, fabric, tunnel ingress, or LocalDelivery. The correct claim is probabilistic reduction from one-packet-anytime to sustained window guessing—not that the cluster-kill capability is impossible.

4. **HIGH — The “retain probe” has no atomic lifetime contract, and #6522 is confirmed**

   Every expired forward invokes release without an origin/holder gate at [loop_body/mod.rs:1481](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1481). Source NAT returns early only for reverse or untranslated entries at [nat/source.rs:789](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs:789), and the first exact release removes the sole allocation at [allocator.rs:1318](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1318). Sibling reservations are idempotent, not refcounted, at [allocator.rs:1664](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1664). Filing #6522 separately is correct.

   However, the materialization guarantee at [plan.md:810](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:810) still relies on a “retain probe.” A boolean liveness check can race an immediate release/reuse. Part B must either require #6522 first or define an atomic per-worker/per-incarnation holder token transferred to the installed entry and rolled back on failure.

5. **HIGH — Queued `UpsertSynced` entries are another unchecked detached-clone path**

   Activation prewarm clones shared entries under lock at [shared_ops.rs:304](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:304), then publishes and enqueues after unlocking at [shared_ops.rs:357](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/shared_ops.rs:357). Normal replication also queues clones at [session_glue/mod.rs:838](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs:838).

   The worker installs first at [upsert_synced.rs:64](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:64), ignores reservation failure at [upsert_synced.rs:80](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:80), and still publishes the stale decision at line 112. A delayed E1 command can therefore overwrite E2 even when E1 can no longer reserve E2’s port. Command consumption needs the same incarnation plus atomic-reservation commit check.

6. **HIGH — `expires_after_ns` does not follow OPENING→ESTABLISHED**

   V9 copies the timeout only at publication and describes later pushes as updating `last_touch_ns` ([plan.md:760](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:760)). A SYN publishes the short opening timeout from [install.rs:157](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:157) through [poll_descriptor/mod.rs:2560](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2560). Handshake processing later gives the worker entry its established/application timeout at [lookup.rs:146](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:146), without a specified shared-timeout update.

   Consequently, a quiet established flow can be swept at `K × opening_timeout` while its worker entry remains valid much longer. A worker restart or steering change then loses the aliases and can force a new SNAT decision. Liveness pushes must carry a conservative incarnation-conditional family timeout, with an explicit OPENING→ESTABLISHED test.

7. **HIGH — Non-NAT stale authorization remains indefinitely renewable**

   Materialization is a clock-stamping event at [plan.md:769](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:769), although the surrounding text claims blind/refused reads cannot refresh stale aliases. A closing shared hit still materializes an alive copy on refusal at [plan.md:1151](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1151).

   After that local copy naturally expires, another tuple-matching close can rematerialize and restamp the same non-NAT/static decision; there is no reservation check for this class. An obsolete permit or route can therefore survive indefinitely without current-policy evaluation. Refused materialization cannot count as family liveness until a committed non-close packet proves use, or the design needs fresh-policy admission.

8. **MEDIUM — Reverse-synth producer semantics improved, but the normative text and tests disagree**

   For Phase 1, the new rule is sound in the common case: a shared match has no anchor and refuses; an accepted local match has a forward entry that can be marked ([plan.md:1121](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1121)). I found no remaining Phase-1 zero-producer in that path.

   However, [plan.md:1126](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1126) says the forward is marked atomically, while [plan.md:717](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:717) and the test at [plan.md:1452](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1452) retain the former reverse-only/next-hit story. “Mark” must explicitly include sticky bits, `last_seen`, reset-before-timeout recomputation, wheel push, and incarnation matching.

9. **MEDIUM — Residual, cleanup, and test contracts are not yet internally consistent**

   The poisoned-walk bound is correctly “spray duration plus one timeout” at [plan.md:1696](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1696). It is not a new pin primitive: ordinary non-close tuple hits already refresh at [lookup.rs:150](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs:150). But [plan.md:491](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:491) and [plan.md:1528](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1528) still state the old one-timeout argument.

   Additional inconsistencies:

   - The sweep names canonical/NAT/wire/index deletion only, omitting the `dnat_table` side effect created at [session_import.rs:122](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:122) and removed by normal cleanup at [session_import.rs:273](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/ha/session_import.rs:273).
   - The additive shared schema list omits the newly required `expires_after_ns` at [plan.md:1225](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1225).
   - The test plan retains obsolete Phase-2 versions, owner epochs, wire marks, zero-hazard release, and old fence tuples at [plan.md:1470](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1470).
   - The residual inventory names LocalDelivery bare-close seeds, but current LocalDelivery caches TCP only with SYN at [local_delivery.rs:20](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/forwarding/local_delivery.rs:20). Conversely, SYN-bearing closes pass #4400 at [session_admission.rs:53](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/session_admission.rs:53) and raw-seed flags at [install.rs:179](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs:179).
   - The Phase-2 brief preserves the major clock, ownership, version, mark, readiness, adoption, and capacity questions, but should also carry the shared-anchor reverse-synth producer case and activation-between-validation-and-reap authority transition.

## Round-12 dispositions

1. **R12-1 — partially.** #6522 is correctly verified/filed and immediate purge is disabled until last-holder accounting exists; the retain contract still depends on that missing machinery.

2. **R12-2 — partially.** Direct materialization gained a recheck; reverse synthesis, embedded ICMP, asynchronous upserts, and local Close cleanup did not.

3. **R12-3 — deferred-to-phase2-track.** Cross-node clock normalization is preserved in the brief.

4. **R12-4 — deferred-to-phase2-track.** Wire-mark payload and immediate/retried emission remain explicit research questions.

5. **R12-5 — deferred-to-phase2-track.** Owner/process version namespacing is preserved.

6. **R12-6 — partially.** Reverse-only canonical clocks and a timeout field are folded; timeout evolution and external-map cleanup remain missing.

7. **R12-7 — not resolved.** Packet-driven materialization can still renew obsolete non-NAT authorization indefinitely.

8. **R12-8 — partially.** Incarnation propagation and peer fences are described, but local Close consumption, queued upserts, and all constructors are not end-to-end fenced.

9. **R12-9 — deferred-to-phase2-track.** Overlap authority is preserved; activation between validation and reap should also be carried into that track’s tests.

10. **R12-10 — partially.** Atomic forward-family marking is added for Phase 1, but producer exceptions and the old reverse-only text/tests remain.

11. **R12-11 — partially.** The final inventory has the correct spray-plus-timeout bound; the main analysis and mandatory test still use the old bound.

12. **R12-12 — deferred-to-phase2-track.** Secondary-stream readiness is preserved in the brief.

13. **R12-13 — deferred-to-phase2-track.** Payload, flush-rate, and aggregate-capacity accounting are preserved.

14. **R12-14 — not resolved.** Normative tests still combine obsolete Phase-2, cleanup, fencing, producer, and poisoning contracts.

Bottom line: Part A’s refusal gate has converged—no refused/no-baseline/out-of-window live-session close path was found that promotes, marks, or accelerates reap—and Phase 2 may remain a separate research track. V9 is nevertheless not shippable because Part B is not incarnation-safe end to end: a queued E1 Close can delete E2’s local family, detached shared-NAT clones can misdirect E2 traffic, queued replicas bypass commit validation, and the family clock can purge live state or renew stale policy. Those defects preserve the issue’s SNAT/reseed harm after an accepted blind close, so Part B needs uniform commit/delete fencing, atomic holder semantics, corrected timeout propagation, and a rewritten test contract before approval.

Codex session ID: 019f95f3-c124-7c60-9d1b-198b9629c197
Resume in Codex: codex resume 019f95f3-c124-7c60-9d1b-198b9629c197
