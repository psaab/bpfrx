# Codex hostile plan-review — round 47 (plan v47 @ b677e3a74)

Task: task-ms9z6ra6-0fcorx (session 019fbbf4-d92c-7df1-8824-563ad084334b).
Verdict: NEEDS-REVISION (5 MAJOR, 2 MINOR; fold verification 3 FOLDED / 3 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:

1. PARTIAL — Node-lifetime placement and preservation close the SessionSync-replacement ABA (plan.md:4093-4117,5367-5379; pkg/daemon/daemon_apply_tail.go:238-255), and re-baselining is explicit. However, only the counter is normatively published before enqueue; the epoch is merely incremented on a “successful reservation” (plan.md:4035-4046,4106-4110,6623-6652), leaving the publication race detailed below.

2. PARTIAL — ActiveApplied exposure and the confirm-pending/dirty terms are folded (plan.md:4357-4376,6565-6581; pkg/configstore/store_commit.go:796-800; pkg/configstore/store_lock.go:334-338; pkg/grpcapi/server_config.go:98-103). The same-text rebuttal at plan.md:4377-4388 is false for configuration-derived enforcement that also depends on dynamic state.

3. PARTIAL — The canonical digest and operator-owned text correctly cover comparison and normal re-convergence, while active.json is not load-override input and preserves committed-marker semantics on its original node (plan.md:4283-4314; pkg/configstore/store_command.go:304-309; pkg/configstore/db.go:105-116,435-460). The encrypted fallback is not portable to another authority because its key is node-local.

4. FOLDED — The g1 reader-wins and g2 Stop-wins legs cover the two orders admitted by the shared exclusion (plan.md:6628-6640; current seams pkg/cluster/sync_conn_read.go:321-331 and pkg/cluster/sync_conn.go:349-385). The former impossible “freeze inside the mutex while Stop drains” seam is gone.

5. FOLDED — The live procedure uses only load override; remaining “load replace” occurrences are revision history or explicit statements that it does not exist (plan.md:4306-4310; cmd/cli/main.go:549-590; pkg/grpcapi/server_config.go:220-244).

6. FOLDED — Live claims are scoped to REGISTERED readers and DISPATCHED frames (plan.md:4121-4147,4168-4195,5305-5351,5395-5405,6443-6467). The inventory is coherent: configstore/daemon/cluster own the accessor, injection, and rendering, while grpcapi/cli remain code-untouched FormatStatus relays (plan.md:5362-5384,5525-5530; pkg/grpcapi/server_show_cluster_text.go:66-74; pkg/cli/cli_show_cluster.go:213-217).

New findings:

MAJOR — The epoch still has a false-idle publication window. The plan recognizes that a channel send becomes receivable before the send-arm continuation and therefore reserves the counter pre-enqueue (plan.md:4035-4046), but says the epoch increments on each successful reservation and tests only counter visibility at that seam (plan.md:4106-4110,6623-6627). A conforming implementation can observe E0/C0, reserve C=1, send successfully, pause before epoch++, let the independent consumer apply and retire C=0, and let check (3) observe E0/C0 before the producer publishes E1 (pkg/cluster/sync_conn_read.go:321-324; pkg/cluster/sync_conn_config.go:325-351). “Same critical section” does not order that consumer or the status reader. The epoch must advance with the provisional pre-enqueue reservation and never roll back; nil/full attempts must be accepted as conservative epoch false positives, and acceptance leg (f) must assert epoch visibility too.

MAJOR — The same-text ActiveApplied rebuttal has a concrete stale-wire counterexample. Boot can successfully apply and mark text T (pkg/daemon/daemon_run_bringup.go:516-520; pkg/daemon/daemon_apply.go:56-70). A later DHCP lease change reapplies the same T (pkg/daemon/daemon_dhcp.go:73-90), specifically to build address-scoped host-inbound enforcement for the newly reachable address (pkg/daemon/daemon_dhcp.go:231-245). If nft installation fails, the exact prior kernel generation remains and covers only its former destinations (pkg/daemon/daemon_nft.go:262-272); the error returns without clearing the old digest (pkg/daemon/daemon_apply_tail.go:83-89,316-327; pkg/daemon/daemon_apply.go:56-70). Because ActiveApplied compares only H(T), it remains true (pkg/configstore/store.go:772-809) while the new address lacks current enforcement. Every proposed done field can therefore pass with stale enforcement on the wire.

MAJOR — Capture is not ordered after window resolution and commit admission closure. The plan captures “before the fence” (plan.md:4283-4298,6536-6548), while resolving any live confirmed window and refraining from commits occur at steps (1) and (2) afterward (plan.md:3975-3980,6427-6432). Concrete failure: capture T1 while a commit-confirmed window is live; CommitConfirmed has already persisted active.json with committed=1 before separately writing confirm.json (pkg/configstore/store_commit.go:427-461,503-524; pkg/configstore/db.go:105-116); step (1) rolls back to T0; later re-convergence uses the stale T1 digest/text or restores its active.json without the timer record. Load then treats T1 as committed (pkg/configstore/store_persist.go:21-55), and the final predicate can bless the formerly unconfirmed configuration. The runbook must resolve step (1), enforce the moratorium, and only then capture one digest/artifact pair.

MAJOR — “Operator refrains” does not fence autonomous local commits. Event-options independently stages and commits configuration (pkg/eventengine/engine.go:920-948), wired through commitAndApply without peer sync (pkg/daemon/daemon_apply_tail.go:446-455). Such a commit is invisible to ConfigSyncOutstanding and the dispatch epoch and can land after capture or after check (3), outside the three admitted residuals (plan.md:4221-4231). Stop is not an admission barrier either: shutdown drains applySem before closing and cancelling the event engine (pkg/daemon/daemon_run_shutdown.go:25-59,121-125), whose lifetime context originates from Background and is cancelled only by Close (pkg/eventengine/engine.go:354-367,583-595). The fence needs a local commit-admission barrier covering automation through process termination.

MAJOR — The encrypted active.json fallback fails on the exact cross-authority branch it is meant to recover. The plan permits the intended holder to be the read-only secondary, then directs the artifact onto the RG0 authority (plan.md:4270-4314). Encryption derives from the source node’s local master.key (pkg/configstore/crypto.go:262-298), which is independently random when created (pkg/configstore/crypto.go:457-480); destination Load reads its own key and AEAD-authenticates with it (pkg/configstore/crypto.go:307-356,443-455). Copying only active.json to a different authority therefore fails closed. The fallback must be pinned to its origin node or include an explicit, securely handled matching-key recovery procedure.

MINOR — Peer preflight is split across /health and cluster-status without a coherent boundary (plan.md:4153-4163,6432-6437). Health can read clean, then a frame can promote, fail persistence, and retire before the counter RPC returns zero (pkg/configstore/store.go:687-746), so (2a) passes even though the peer became unclean during the preflight. A lone peer epoch sample adds nothing; either bracket all preflight reads with epoch-before/epoch-after and retry, or widen residual (iii) from the first preflight sub-read through Stop. The post-restart closure already handles that outcome, making this a proof-boundary defect rather than a new unrecoverable state.

MINOR — active.json is not literally “a JSON envelope” as stated at plan.md:4291-4297,6543-6548. Its outer compatibility envelope is a non-JSON magic-header line followed by a possibly encrypted JSON body (pkg/configstore/envelope.go:78-99; pkg/configstore/db.go:445-450). The runbook should call it an opaque config-DB artifact so operators preserve the framing byte-for-byte.

Structure confirmation: §4.7 stands: PR-1 remains the synchronized-accessor core, while G+H+H2 remain together in the follow-up (plan.md:5207-5242), with dissent preserved at plan.md:5243-5250.

NEEDS-REVISION

Codex session ID: 019fbbf4-d92c-7df1-8824-563ad084334b
Resume in Codex: codex resume 019fbbf4-d92c-7df1-8824-563ad084334b
