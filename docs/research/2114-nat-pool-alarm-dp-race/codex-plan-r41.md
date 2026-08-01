# Codex hostile plan-review — round 41 (plan v41 @ 4a331d5a6)

Task: task-ms26jz51-kdzutm (session 019f9fdc-897b-74b2-8d77-982dada9bad8).
Verdict: NEEDS-REVISION (4 MAJOR, 1 MINOR; fold verification 1 FOLDED / 2 NOT-FOLDED — both NOT-FOLDEDs are the v41 queue-length + gen-fence pair, replaced in v42 by the gap-free outstanding-sync counter). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:

1. NOT-FOLDED — The proposed pair is not a barrier: dequeue precedes flag publication (`pkg/cluster/sync_conn_config.go:325-350`), legacy gen-0 applies leave the flag zero (`pkg/cluster/sync_conn_config.go:289-309`; `pkg/cluster/sync_protocol.go:704-712`), and bulk reset can clear it during an apply (`pkg/cluster/sync_conn_read.go:183-195`; `pkg/cluster/sync_conn_gen.go:340-362`). This defeats `docs/research/2114-nat-pool-alarm-dp-race/plan.md:3598-3609`, including an indefinitely applySem-blocked callback (`pkg/daemon/daemon_apply_commit.go:326-335`).

2. NOT-FOLDED — The local indicator is peer→local receiver state (`pkg/cluster/sync.go:576-616`), whereas local→peer sends bypass it through `QueueConfig` (`pkg/cluster/sync_conn_config.go:230-250`) and remain asynchronously triggerable (`pkg/daemon/daemon_ha_sync.go:417-522`). Thus the conclusion at `plan.md:3602-3605` is directionally false.

3. FOLDED — The operative request says “current design” (`plan.md:6063-6069`), and the retained `down em0` alternative is marked WITHDRAWN with the correct fabric fallback rationale (`plan.md:1426-1429`; `pkg/daemon/daemon_ha_sync.go:774-785,820-860`).

New findings:

MAJOR 1 — Even a live indicator can falsely report idle. Between dequeue and `beginConfigApply`, both values are zero; gen-0 remains invisible throughout; and `resetRecvGen` can lower a nonzero flag while its callback is still blocked. Exposing the existing channel length and generation fence, as required by `plan.md:3598-3601`, cannot cover the indefinite-applySem case. The design needs a gap-free outstanding/apply-busy counter or boolean independent of generation and epoch reset.

MAJOR 2 — Neither direction is actually drained. Local→peer writes can start after the local observation and land after the peer debt-only preflight; peer→local writes can start after LOCAL DRAIN because the peer remains running until `plan.md:3615-3617`. The final local check examines debts only, not queue/apply state (`plan.md:3618-3624`). A merely enqueued or applySem-blocked sync has not yet raised debt; that occurs only during `SyncApply` (`pkg/configstore/store.go:687-746`). Process exit then abandons retry (`pkg/configstore/store_persist.go:397-401`), while degraded health is election-neutral and crash takeover remains ungated (`pkg/cluster/readiness.go:20-24`; `pkg/cluster/election.go:427-432`).

MAJOR 3 — The promised peer full-state read is not designed on the gRPC/CLI surface. The peer is still running at preflight, so availability ordering itself is consistent (`plan.md:3610-3617`), but the concrete design wires `ConfigPersistDegradedState()` only into `pkg/api` health and leaves `pkg/grpcapi`/`pkg/cli` untouched (`plan.md:4608-4654`). Current cluster information exposes only config-sync counters (`pkg/cluster/status.go:340-356`). No command or data path exposes the exact peer debt mask and active-persist state required by the runbook.

MAJOR 4 — The formal acceptance copy remains stale and contradictory: `plan.md:5553-5569` still specifies peer preflight → peer stop → capped timer wait and claims that wait drains the receiver, omitting LOCAL DRAIN and the new indicator from the normative sequence at `plan.md:3598-3624`.

MINOR 1 — Current status queries are fresh per invocation (`pkg/cluster/sync_state.go:54-63`), but v41 never pins LIVE-at-check-time or coherent sampling semantics. `Stats()` is merely point-in-time and releases `s.mu` before loading snapshot fields (`pkg/cluster/sync.go:946-958`); the proposed channel length and atomic flag are not jointly protected. No indicator-specific implementation or regression-test entry appears in `plan.md:4484-4654`.

Structure confirmation: CONFIRMED — PR-1 remains the synchronized-dataplane core and G+H+H2 remain together in the follow-up (`plan.md:4437-4472`).

NEEDS-REVISION

Codex session ID: 019f9fdc-897b-74b2-8d77-982dada9bad8
Resume in Codex: codex resume 019f9fdc-897b-74b2-8d77-982dada9bad8
