# Codex hostile plan-review — round 48 (plan v48 @ 3b1b98330)

Task: task-msa0lwgp-ns7h20 (session 019fbc19-4131-7713-8b0a-aa495a0b15c9).
Verdict: NEEDS-REVISION (5 MAJOR, 2 MINOR; fold verification 2 FOLDED / 5 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:

1. PARTIAL — The live H2 protocol advances the epoch with the provisional reservation before enqueue and never rolls it back (plan.md:4157-4166,4193-4200,4291-4299), closing the fast-consumer publication race; leg (f) checks visibility at the send seam (plan.md:6772-6778). But §5.1, formal step (3), and JOIN leg (h) still specify advancement on “successful reservation” only (plan.md:5486-5489,6603-6614,6792-6803), leaving nil/full behavior contradictory and untested.

2. PARTIAL — Requiring no post-restart apply failure logically closes the same-text DHCP/nft counterexample (plan.md:4490-4507,6715-6724; pkg/daemon/daemon_dhcp.go:231-245; pkg/daemon/daemon_nft.go:262-272; pkg/configstore/store.go:797-809). The plan commits to adding new daemon health state, not rendering existing state (plan.md:5498-5507), but leaves its lifetime, comparison, instrumentation, and tests undefined.

3. FOLDED — Both copies order window resolution, event-options quiescence, moratorium, then capture, and require recapture after any later commit (plan.md:4040-4065,6553-6565), closing the stale T1→rollback-to-T0 capture construction (pkg/configstore/store_commit.go:427-461,503-524; pkg/configstore/store_persist.go:21-55).

4. PARTIAL — A successful local deactivation is serialized: queued actions revalidate after acquiring the config lock and stale-drop once Apply removes the policy (pkg/eventengine/engine.go:393-487,870-897; pkg/eventengine/engine_stale_revalidate_3750_test.go:45-83). No other post-step-(1) autonomous config-DB committer was found: RPM emits callbacks, while feeds, DHCP, ip-monitoring, and DHCP server only reapply runtime state (pkg/rpm/rpm.go:309-335; pkg/daemon/daemon_feeds.go:26-42; pkg/daemon/daemon_dhcp.go:73-95; pkg/daemon/daemon_ipmon.go:230-262). The quiesce nevertheless is not guaranteed on both nodes or after an apply abort, as detailed below.

5. PARTIAL — Both copies pin encrypted restore to the origin node, with cleartext alone portable (plan.md:4400-4408,6685-6691). Byte-exact origin restore remains decryptable with its surviving master.key and preserves the committed marker (pkg/configstore/crypto.go:34-36,443-454; pkg/configstore/db.go:319-350; pkg/configstore/envelope.go:135-162,206-214), but the recovery instructions still require restoration “onto the authority” in an admitted origin-secondary case.

6. PARTIAL — Normative text starts residual (iii) at the preflight’s first sub-read (plan.md:4327-4339). Formal acceptance identifies the split `/health` and cluster-status reads (plan.md:6567-6572) but still says only “between the peer preflight and the peer stop” (plan.md:6642-6650), so the explicit widening is absent from that copy.

7. FOLDED — Both copies correctly describe active.json as an opaque config-DB artifact containing a magic-header framing line and possibly encrypted JSON body, preserved byte-for-byte (plan.md:4393-4396,6678-6683), matching pkg/configstore/envelope.go:78-99 and pkg/configstore/db.go:445-450.

New findings:

MAJOR 1 — The epoch contract remains internally inconsistent. The live runbook requires provisional advancement with no rollback (plan.md:4193-4200,4293-4298), while the concrete inventory and two formal-acceptance locations retain “successful reservation” semantics (plan.md:5486-5489,6603-6614,6792-6803). Leg (f) proves visibility for a receivable send, but no leg requires nil/full attempts to advance permanently. An implementor therefore cannot derive one authoritative epoch algorithm or acceptance result.

MAJOR 2 — The apply-failure predicate is not executable. Current compile health is compile-specific (pkg/daemon/daemon.go:871-880; pkg/daemon/daemon_health.go:79-125), while ConfigsApplyFailed covers only SessionSync callbacks (pkg/cluster/sync.go:110-119; pkg/cluster/sync_conn_config.go:351-379); DHCP/boot and feeds use separate wrappers (pkg/daemon/daemon_apply.go:49-86). The plan merely names new state (plan.md:4503-4507,5500-5506), omits it from the daemon type inventory (plan.md:5375-5380), and supplies no sticky same-text regression in §9 (plan.md:6742-6811). A baseline at (1b) is wrong because restart replaces daemon state: specify a counter initialized before the restarted process’s boot apply, require failure-count == 0 plus a successful last outcome, and instrument every full-apply entry centrally.

MAJOR 3 — The quiesce permanently changes the configuration it later blesses. The runbook commits `deactivate event-options` and captures afterward (plan.md:4043-4065), although it later calls the artifact the pre-procedure committed intent and claims the procedure changes no configuration (plan.md:4385-4392,4440-4446,6671-6677). Deactivation marks the tree changed and persists, syncs, and excludes the subtree from application (pkg/configstore/store_command.go:111-129; pkg/config/inactive.go:5-10). There is no reactivation/commit/verification step, so either the digest and operator text disagree or successful completion leaves automation disabled.

MAJOR 4 — The event-options quiesce is not an effective two-node fence. Operator commits sync only from the RG0 authority, and the push is suppressed when ConfigSync is disabled (pkg/daemon/daemon_apply_commit.go:578-601; pkg/daemon/daemon_ha_sync.go:336-370); after the authority is stopped, a retained-policy secondary becomes writable on promotion and may commit locally with syncPeer=false (pkg/daemon/daemon_ha.go:438-450; pkg/daemon/daemon_apply_tail.go:446-455). Independently, Store promotion can persist before apply aborts ahead of tail step 17, leaving the durable tree inactive while the live engine retains its policies (pkg/daemon/daemon_apply.go:282-309,404-409; pkg/daemon/daemon_apply_tail.go:194-202). Neither runbook copy requires both-node effective deactivation, and the preflight checks no event-engine state (plan.md:4040-4053,6553-6574).

MAJOR 5 — The encrypted fallback is non-executable when the correct origin is the read-only secondary and operator text is unavailable. The plan admits that intended holder (plan.md:4383-4385), forbids moving its encrypted artifact to another node (plan.md:4400-4408), then mandates file restoration onto the authority (plan.md:4417-4426). It needs explicit stop/election/restart choreography that makes the origin authoritative before any older peer can overwrite it.

MINOR 1 — Formal acceptance still fails to pin residual (iii) to the first preflight sub-read: compare plan.md:4327-4339 with plan.md:6642-6650. The post-restart predicate bounds the outcome, but the two normative copies describe different windows.

MINOR 2 — The counter itself balances on nil/full rollback, but the mandatory rebaseline loop need not terminate. The plan claims the stopped peer makes the epoch settle (plan.md:4208-4213) while admitting unkeyed third-party or stale-process ingress advances the same dispatch path (plan.md:4230-4235,4510-4516; pkg/cluster/sync_auth.go:321-334). Continuous ingress can keep advancing the never-rolled-back epoch indefinitely; this is fail-closed, but the runbook must fence all ingress or declare stopped remediation unavailable while pulses continue.

Structure confirmation: §4.7 stands; plan.md:5326-5369 clearly separates PR-1 and keeps G+H+H2 together in the follow-up.

NEEDS-REVISION

Codex session ID: 019fbc19-4131-7713-8b0a-aa495a0b15c9
Resume in Codex: codex resume 019fbc19-4131-7713-8b0a-aa495a0b15c9
