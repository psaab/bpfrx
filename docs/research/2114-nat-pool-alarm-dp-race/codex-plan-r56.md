# Codex hostile plan-review — round 56 (plan v56 @ 269b4c70c)

Task: task-msa8wbcm-2zstda (session 019fbced-b3ad-7d31-9380-8f9c707aa29f).
Verdict: NEEDS-REVISION (8 MAJOR, 3 MINOR; fold verification 2 FOLDED / 5 PARTIAL / 1 NOT-FOLDED). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:

1. PARTIAL — v56 adds provider identity and send-success publication (`plan.md:4999-5026`), but does not define identity or serialize it through the send: `getSessionSync` releases `clusterCommsMu` before use (`pkg/daemon/daemon_ha_sync.go:594-607`), while replacement uses that lock independently (`:658-667,1405-1410`). It also leaves `QueueConfig`’s nil-connection/error return mapping unpinned (`pkg/cluster/sync_conn_config.go:234-250`).

2. PARTIAL — the authority-generation concept (`plan.md:5010-5015`) closes the sender demote/re-promote construction only if a captured generation is stored in the marker and bumped on every RG0 transition, but no field, owner, bump point, or locking is defined for `applyRG0OwnershipTransition` (`pkg/daemon/daemon_ha.go:438-475`). Restart reset is safe because the marker itself is process-local and also resets (`pkg/daemon/daemon.go:420-424`), old goroutines die, and a fresh connection advances the new epoch (`pkg/daemon/daemon_ha_sync.go:51-57`).

3. FOLDED — current `configSyncMu` sites are the marker helper (`pkg/daemon/daemon_ha_sync.go:407-414`) and reconciler (`:479-489`); the normative rule makes one function the locked-send owner and the helper lock-assuming (`plan.md:4999-5002,5027-5032`), eliminating recursive locking.

4. PARTIAL — the six full-apply entries and admission order are complete (`pkg/daemon/daemon_apply_commit.go:172-218,332-354,528-571,630-645`; `pkg/daemon/daemon_apply.go:50-56,84-86`), covering every production `applyConfigLocked` caller (`daemon_apply_commit.go:246,489,697`). But the void rollback has no defined terminal outcome across no-op, bootstrap-teardown, apply-failure, and session-clear-failure branches (`daemon_apply_commit.go:645-708`).

5. NOT-FOLDED — manager-side registration does not atomically select/install the correct tokened callback. The daemon still performs separate check/set operations (`pkg/daemon/daemon_apply_interfaces.go:61,98-109`), the manager locks them separately (`pkg/dataplane/userspace/manager.go:424-433`), and status can launch the old callback between them (`pkg/dataplane/userspace/maps_sync.go:451-456`); the callback API remains tokenless (`pkg/daemon/daemon_ha_userspace.go:10-13`).

6. PARTIAL — v56 states atomic supersession/re-registration (`plan.md:6254-6264`) but supplies no atomic transaction. A debt can complete after the manager snapshot and before daemon registration—e.g. `pendingWorkerArm` clears at `pkg/dataplane/userspace/manager_worker_arm_5134.go:79-96`—stranding a new-token registration.

7. FOLDED — returning detach errors through `Compile`/`ApplyConfig` (`pkg/dataplane/userspace/manager_compile.go:211-214,567-591`; `manager.go:348-357`) produces an ordinary #5679 deferred error: later reconciles still run, the tail joins it, and the commit fails (`pkg/daemon/daemon_apply_dataplane.go:141-159`; `daemon_apply_tail.go:316-327`). That is the intended terminal health outcome and blast radius.

8. PARTIAL — the primary no-pending predicate and tri-state are fixed (`plan.md:5182-5184,6267-6279,7730-7734`), the two-second deadline placement is accurate (`pkg/cluster/sync.go:88`; `sync_protocol.go:59-74`), the existing JOIN-COHERENCE legs stand (`plan.md:7783-7832`), and the send-boundary legs exist (`:7867-7880`). The promised contention regression is absent, and post-reactivation/status summaries again omit pending (`:5200-5204,6413-6419,7765-7769`).

New findings:

MAJOR 1 — Send success is not receiver acceptance. `QueueConfig` can report only completion of the local write (`pkg/cluster/sync_conn_config.go:234-250`); receipt is queued asynchronously (`pkg/cluster/sync_conn_read.go:298-330`), and the receiver can later reject because it considers itself primary (`pkg/daemon/daemon_ha_sync.go:544-548`). There is no config-ACK message (`pkg/cluster/sync.go:38-76`). During dual-primary, A can publish its marker after B rejects the frame; if only B demotes, A’s authority generation remains unchanged and suppresses all same-connection retries. An apply-level ACK or receiver-demotion re-drive is required.

MAJOR 2 — Provider identity is not a linearizable boundary. A pointer comparison through `getSessionSync` necessarily releases `clusterCommsMu` before sending (`pkg/daemon/daemon_ha_sync.go:594-607`), while transport replacement independently nils/publishes the provider (`:658-667,1405-1410`; `pkg/daemon/daemon_apply_tail.go:238-255`). Replacement after the check but before/during the send is therefore legal. The provider generation must participate in the marker and be checked after the send, or replacement must share the send exclusion.

MAJOR 3 — Authority invalidation can itself race marker publication. RG0 transitions currently take neither `configSyncMu` nor any stated authority-generation lock (`pkg/daemon/daemon_ha.go:438-475`). If demotion clears/bumps state while a send is in progress, the sender can return afterward and republish unless it records the pre-send generation and marker comparison rejects it. `plan.md:5010-5015` never defines that capture/publication rule.

MAJOR 4 — Rollback health has an unresolved false-green/false-pending fork. A stale timer returns without applying (`pkg/daemon/daemon_apply_commit.go:645-649`); a nil rollback target mutates active state but only logs teardown failure (`:651-683`; `pkg/daemon/bootstrap.go:314-320,356-370`); normal apply and session-clear failures are likewise only logged (`daemon_apply_commit.go:697-708`). After minting, treating every void return as success falsely blesses failures, while leaving no-op returns unfinished strands the predicate. The plan needs explicit neutral/success/failure outcomes and an accumulator.

MAJOR 5 — OnXSKBound can still register the wrong work under the right token. Callback installation happens before the new dataplane `ApplyConfig` (`pkg/daemon/daemon_apply.go:278-287`; `daemon_apply_dataplane.go:137-142`). Attempt B can observe “not notified,” status can launch callback A and set the one-shot flag, then B installs a callback that can never fire (`pkg/dataplane/userspace/maps_sync.go:451-456`). Registration atomicity alone does not fix callback identity; one manager operation must install the tokened callback, handle already-bound state, register, and launch atomically.

MAJOR 6 — Debt transfer has both a stale-snapshot race and global admission latency. `statusLoop` holds `m.mu` across its whole poll (`pkg/dataplane/userspace/process_status.go:160-255`), including status IPC and deferred snapshot publication (`:167,183-186`). IPC permits a two-second dial and up to a 120-second round trip (`pkg/dataplane/userspace/process_control.go:34-56,129-142`). The mint query therefore blocks after acquiring `applySem`, stalling every commit, sync, and rollback, yet releasing `m.mu` before daemon re-registration permits completion to invalidate the snapshot. Use a short-held debt ledger with a single retoken transaction and explicit lock order.

MAJOR 7 — The binding contracts were not synchronized. Formal acceptance retains the v55 protocol—no provider identity, authority generation, success-only publication, or lock-assuming helper (`plan.md:7651-7658`)—while §5.1 inventories neither the concrete authority/provider state nor the required userspace changes (`:6072-6298,6334-6443`). Section 6 also claims `fwdstatus.NewSampler` is the only signature change (`:6773-6778`), contradicting the new `QueueConfig` return (`:5020-5026`) and token additions to exported `ConfigSink`/`LinkController` (`:6237-6239`; `pkg/dataplane/apply.go:37-40,130-134`).

MAJOR 8 — §9 does not test the v56 concurrency mechanisms. The design requires six tokened arms plus terminal attachment detach (`plan.md:6174-6193`), but the attempt-token leg covers only four arms (`:7887-7895`). It lacks the old/new OnXSKBound callback interleave, PrepareLinkCycle registration, completion-versus-next-mint transaction, slow-poll mint behavior, and returned DetachXDP/DetachTC failure. The authority leg also stops at demotion (`:7878-7880`) without re-promotion, marker-state, and retry assertions.

MINOR 1 — The claimed send-lock bound is not pinned. `QueueConfig` waits on untimed `writeMu.Lock` before the two-second deadline begins (`pkg/cluster/sync_conn_config.go:241-243`; `pkg/cluster/sync_protocol.go:59-74`), while `plan.md:5033-5039` promises a §9 contention regression that does not exist.

MINOR 2 — “COMPLETE” post-reactivation checks omit pending state (`plan.md:5200-5204,7765-7769`), and the pkg/cluster rendering inventory lists outcome/count but not pending (`:6413-6419`). Because PENDING deliberately leaves the failure count unchanged (`:6267-6270`), these are not equivalent predicates.

MINOR 3 — The detach conversion must preserve attempt-all cleanup. Current code attempts every stale XDP and TC detach (`pkg/dataplane/userspace/manager_compile.go:567-591`); the plan should require collecting failures with `errors.Join`, rather than returning on the first error and skipping later detachments.

Structure confirmation: §4.7 stands unchanged: PR-1 remains the accessor core, with G+H+H2 together in the follow-up (`plan.md:6023-6058`).

NEEDS-REVISION

Codex session ID: 019fbced-b3ad-7d31-9380-8f9c707aa29f
Resume in Codex: codex resume 019fbced-b3ad-7d31-9380-8f9c707aa29f
