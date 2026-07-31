# Round ledger — #6461 blind-RST research

| Round | Reviewer | Task/job ID | Verdict | Doc |
|---|---|---|---|---|
| r1 | Codex (gpt-5.5 via codex-companion) | thread 019f952c-…-2e9730f74491 (task-mrz7t8wa-aablct, stalled ~40min silent log, cancelled); relaunched task-mrza0i98-835fl8 (preamble-only turn); resumed task-mrzaywtx-abznu0 (session 019f9565-46be-7830-9ecd-9be29d6690d4) — completed | PLAN NO (6 BLOCKER, 4 HIGH, 2 MEDIUM) | codex-plan-r1.md |
| r1 | AGY (Antigravity/jetski 1.1.6) | companion runs rescue-mrz863vu (flag derail), rescue-mrz8vtiv + rescue-mrz9bzbe + rescue-mrz9gb6l (headless command-permission denial), direct-binary runs out6/out7 (denial), out8 (flag derail), out9 (Q1+Q2, 5m timeout mid-Q3), out10 (tool-call noise), out11 (Q3+Q4), out12 (Q5+Q6), out13 (Q7) | No single verdict line (partial coverage); Q7 run: "Option A first" | agy-plan-r1.md |
| r1 | Claude SMR | in-conversation (this agent) | PLAN NO, 13-section adjudication + v2 checklist | claude-smr-plan-r1.md |
| r2 | AGY (Antigravity/jetski 1.1.6, direct binary) | out1 (v2 review, full 6-finding verdict) | PLAN NO (2 BLOCKER: LocalDelivery blind spot, permanent stall; 2 HIGH, 1 MEDIUM, 1 LOW) | .scratch/r2-agy-out1.txt (folded into v3) |
| r2 | Codex (gpt-5.5 via codex-companion) | task-mrzfkngy-ocvr2e (17m30s, turn failed at final assembly — content-filter infra error; partial output = PASS_TO_KERNEL finding); resumed task-mrzg8a40-gwcq3m (session 019f95f3-c124-7c60-9d1b-198b9629c197, 8m44s, completed) | PLAN NO (4 BLOCKER, 5 HIGH, 1 MEDIUM) | codex-plan-r2.md |
| r2 | AGY convergence pass on v3 (direct binary) | out2 (headless command-permission denial, 303B), out3 (built-in-tools-only retry, full) | PLAN NO (1 BLOCKER post-failover kill, 1 HIGH seed race, 1 MEDIUM arithmetic; all 6 r2 folds verified resolved) | agy-plan-r2.md |
| r2 | Claude SMR | in-conversation | PLAN NO (2 BLOCKER: no-baseline fail-open + materialize constructor; 1 HIGH seed race; 1 MEDIUM arithmetic) | claude-smr-plan-r2.md |
| r3 | Codex (gpt-5.5 via codex-companion, resumed session) | task-mrzhtb46-hwfisv (26m05s, completed; session 019f95f3-…-198b9629c197) | PLAN NO (4 BLOCKER, 4 HIGH, 2 MEDIUM) | codex-plan-r3.md |
| r3 | AGY (direct binary, built-in-tools-only preamble) | r3-agy-out1 (single run, full coverage) | PLAN YES (1 MEDIUM: OPENING windowed-vs-exact; 1 LOW accepted residual) | agy-plan-r3.md |
| r3 | Claude SMR | in-conversation | PLAN NO for v4.2 — all ten Codex findings confirmed + folded into v5; one documented dissent (segment-wide weak auth kept; per-field deadlock proof) | claude-smr-plan-r3.md |
| r4 | Codex (gpt-5.5 via codex-companion, resumed session) | task-mrzjrykr-7io911 (2m47s, content-filter turn failure while reading the plan); resumed task-mrzjwgox-olobll (28m11s, completed) | PLAN NO (4 BLOCKER, 4 HIGH, 1 MEDIUM, 1 LOW) | codex-plan-r4.md |
| r4 | AGY (direct binary, built-in-tools-only preamble) | r4-agy-out1 (single run, full coverage) | PLAN YES (1 LOW: metrics-surface export for tcp_close_seq_rejected) | agy-plan-r4.md |
| r4 | Claude SMR | in-conversation | PLAN NO for v5 — all ten Codex findings confirmed + folded into v6; v5 dissent withdrawn (own-ack close leg replaces segment-wide adoption) | claude-smr-plan-r4.md |
| r5 | Codex (gpt-5.5 via codex-companion, resumed session) | task-mrzlgpx5-odo1nx (19m33s, completed) | PLAN NO (3 BLOCKER, 4 HIGH, 1 MEDIUM, 1 LOW) | codex-plan-r5.md |
| r5 | AGY (direct binary, built-in-tools-only preamble) | r5-agy-out1 (single run, full coverage) | PLAN YES (0 findings) | agy-plan-r5.md |
| r5 | Claude SMR | in-conversation | PLAN NO for v6 — all nine Codex findings confirmed + folded into v7 (activation-time authority, immutable OPENING endpoints, real AnchorUpdate pipeline, per-stream slack, three-leg arithmetic) | claude-smr-plan-r5.md |
| r6 | Codex (gpt-5.5 via codex-companion, resumed session) | task-mrzmtihg-eo9gek (19m22s, completed) | PLAN NO (5 BLOCKER, 3 HIGH, 1 MEDIUM, 1 LOW) | codex-plan-r6.md |
| r6 | AGY (direct binary, single-question runs after 4 documented 5m timeouts) | out1-out4 (timeouts), out5 (Phase-2 pipeline), out6 (activation authority) | Q1 UNSOUND (volume cap needed, fixed v7.1), Q3 UNSOUND (lazy authority window, fixed v7.1/v7.2), Q2/Q4/Q5 SOUND | agy-plan-r6.md |
| r6 | Claude SMR | in-conversation | PLAN NO for v7/v7.1 — all ten Codex findings confirmed + folded into v7.2 (shared-delete race authority, full Phase-2 contract, trust decay + re-baseline, final-admission commit + pending-neigh token, narrowed ack-stall residual, open_valid predicate, 1/6554 arithmetic) | claude-smr-plan-r6.md |
| r7 | Codex (gpt-5.5 via codex-companion, resumed session) | task-mrzomipt-t7v4xi (24m07s, completed) | PLAN NO (6 BLOCKER, 2 HIGH, 2 MEDIUM, 1 LOW) | codex-plan-r7.md |
| r7 | AGY (direct binary, scoped single-question run) | r7-agy-out1 | Q1 UNSOUND (ticket coverage — folded wrong in v7.3, corrected in v7.4), Q2 SOUND (atomic delete), Q3 UNSOUND (idle decay kills the target class — heartbeat folded v7.3/v7.4) | agy-plan-r7.md |
| r7 | Claude SMR | in-conversation | PLAN NO for v7.2/v7.3 — all eleven Codex findings confirmed + folded into v7.4 (race narrowed to true HA-import origins, session_id CAS ticket, per-side writer ownership, phase byte, Go end-to-end protocol, lease decay, pending-neigh re-resolve) | claude-smr-plan-r7.md |
| r8 | Codex (gpt-5.5 via codex-companion, resumed session) | task-mrzpy4kp-52b8bu (18m59s, completed) | PLAN NO (6 BLOCKER, 3 HIGH, 1 MEDIUM, 1 LOW) | codex-plan-r8.md |
| r8 | AGY (direct binary, scoped run) | r8-agy-out1 | 3xSOUND (ticket narrowing/origin disjointness, per-side writer totality, owner-only lease renewal), no contradictions | agy-plan-r8.md |
| r8 | Claude SMR | in-conversation | PLAN NO for v7.4 — 5 of 6 blockers confirmed + folded into v7.5; Codex 5 (split steering) re-adjudicated to master-parity on verification (master's propagation is local-table-only) | claude-smr-plan-r8.md |
| r9 | Codex (gpt-5.5 via codex-companion, resumed session) | task-mrzr3o36-444ag1 (19m36s, completed) | PLAN NO (7 BLOCKER, 3 HIGH, 2 MEDIUM, 1 LOW) — the round that killed the v7.x ticket tower | codex-plan-r9.md |
| r9 | AGY (direct binary, scoped run) | r9-agy-out1 | 4xUNSOUND (owner_rg unstamped, worker-bit mint divergence, equal-epoch baseline overwrite, 3 text contradictions) — all folded v7.6/v8 | agy-plan-r9.md |
| r9 | Claude SMR | in-conversation | PLAN NO for v7.5/v7.6 — answered by DELETION (v8: marked-only emission + TTL sweep + id-conditional Go fence + RX-worker commit + Phase-2 bundles/floor/freshness) | claude-smr-plan-r9.md |
| r10 | Codex (gpt-5.5 via codex-companion, resumed session) | task-mrzsb8yw-3oxx15 (25m22s, completed) | PLAN NO (6 BLOCKER, 3 HIGH, 3 MEDIUM, 1 LOW) | codex-plan-r10.md |
| r10 | AGY (direct binary, scoped run) | r10-agy-out1 | Q1 SOUND (single producer + exactly-one Close), Q2 UNSOUND (TTL purges live-but-quiet — liveness push folded v8.1), Q3 UNSOUND (stale v7.2 test text — swept) | agy-plan-r10.md |
| r10 | Claude SMR | in-conversation | PLAN NO for v8/v8.1 — all twelve Codex findings adjudicated; v8.2 folds (one emission predicate with the normative sticky mark, TTL liveness clock + compare-delete, flow_incarnation_id, writer_gen + owner-epoch gate, fresh-at-write-time, marked-sibling emission with exactly-once via delete propagation, dominated async residual) | claude-smr-plan-r10.md |
| r11 | Codex (gpt-5.5 via codex-companion, resumed session) | task-mrztzy3r-cn3tgd (18m56s, completed) | PLAN NO (7 BLOCKER, 1 HIGH, 3 MEDIUM) | codex-plan-r11.md |
| r11 | AGY (direct binary, scoped run) | r11-agy-out1 | 3xUNSOUND (mark rules vs raw seeds — enforcement at constructors stated; reservation released ~3T before alias purge — release drives purge v8.3; text contradictions — swept) | agy-plan-r11.md |
| r11 | Claude SMR | in-conversation | PLAN NO for v8.2/v8.3 — all eleven Codex findings adjudicated; v8.4 folds (no read-touch, one canonical family clock + lock order, mark on the Phase-2 tail, owner gate by node identity, coordinator-sequenced bundles, AnchorStreamStart + typed observed_ns freshness + atomic epoch activation, forward-mint inheritance + conditional DeleteSynced + Close codec fields, honest resource-retention framing, ~104B cost) | claude-smr-plan-r11.md |
| r12 | Codex (gpt-5.5 via codex-companion, resumed session) | task-mrzvbi3h-3kaqng (6m03s, content-filter turn failure mid-analysis); resumed task-mrzvmwvx-xz909e (6m45s, completed) | PLAN NO (5 BLOCKER, 4 HIGH, 4 MEDIUM) — the round that triggered the v9 restructure; found the pre-existing NAT release bug (filed #6522) | codex-plan-r12.md |
| r12 | AGY (direct binary, scoped run) | out1 (agent error), out2 (retry, full) | 3xSOUND (mutation inventory, overlap flap safety, non-owner poisoning blocked) + 1 text contradiction (fixed v8.4.1) | agy-plan-r12.md |
| r12 | Claude SMR | in-conversation | PLAN NO for v8.4-as-single-ship — answered by the v9 CONVERGENCE RESTRUCTURE (Part A ships the gate, Part B minimal machinery, Phase 2 split to its own research track, #6522 filed and verified) | claude-smr-plan-r12.md |

Infra notes (per feedback_codex_infra_must_retry — all retries documented):
- Codex: 10m client timeout kill → job found alive server-side → polled 25+ min →
  stall detected (silent log) → cancel → background relaunch → preamble-only turn →
  --resume with continue directive → completed. Total 4 invocations.
- Codex r2: background task → 17m30s analysis → turn failed with content-filter
  error at final assembly (analysis complete, verdict un-emitted) → --resume with
  defensive-framing continue directive → completed 8m44s. Total 2 invocations.
- AGY: companion `rescue` path derails the model on ANY extra CLI flag
  (`--print-timeout`, `--dangerously-skip-permissions` — the agent answers about the
  flag instead of the prompt) and headless mode auto-denies `command(...)` tools.
  Working invocation found empirically: `agy --print "<prompt>"` with NO other flags,
  run via `env -C <worktree>`, prompt instructing built-in file tools only.
  5m default timeout caps each run → split Q1–Q7 across 4 runs.
- AGY r2 convergence: first attempt hit the headless command-permission denial
  (model invoked a shell tool); retry with an explicit built-in-file-tools-only
  preamble produced the full review.

## Rounds 13-31 (v9.x convergence tail — ledger backfilled at r31)

Codex ran as one resumed session per arc (019f95f3-c124-7c60-9d1b-198b9629c197
for r13-r27; 019f990b-7ec8-7f01-872a-275842ade004 for r28-r31). AGY ran via the
working direct-binary invocation (`agy --print`, no flags, `env -C <worktree>`,
built-in-file-tools-only preamble). Claude SMR ran in-conversation; rounds
13-30 SMR verdicts were the fold decisions themselves (each Codex finding
adjudicated and folded, evidenced by the per-round commit messages); the r31
SMR review is written as a file (claude-smr-plan-r31.md). Per-round review
outputs for r13-r30 were backfilled from .scratch/ into
docs/research/6461-blind-rst/ at r31 (codex-plan-r<N>.md / agy-plan-r<N>.md);
r22/r23 Codex outputs were not separately preserved — their substance is
captured in the r24 Codex final's disposition chain (which re-verifies and
dispositions every open finding each round).

| Round | Codex verdict | AGY verdict | Plan version folded to |
|---|---|---|---|
| r13 | PLAN NO (2B) — v9 restructure follow-ups | PLAN YES | v9.1/v9.2 |
| r14 | PLAN NO (2B) | PLAN YES | v9.3/v9.4 |
| r15 | PLAN NO (3B) — token lifecycle | PLAN YES | v9.5/v9.6 |
| r16 | PLAN NO (1B) | PLAN YES | v9.7 |
| r17 | PLAN NO (2B) | PLAN YES | v9.8 |
| r18 | PLAN NO (2B) | PLAN YES | v9.9 |
| r19 | PLAN NO (1B) — temporal cuts | PLAN YES | v9.9.3/v9.9.4 |
| r20 | PLAN NO (2B) | PLAN YES | v9.9.4/v9.9.5 |
| r21 | PLAN NO (3B) — selector/generation | PLAN YES | v9.9.5 |
| r22 | (not separately preserved; see r24 dispositions) | PLAN YES | v9.9.6/v9.9.7 |
| r23 | (not separately preserved; see r24 dispositions) | PLAN YES | v9.9.8 |
| r24 | PLAN NO (4B) — mixed-version kill, durable escrow | PLAN YES | v9.9.9 |
| r25 | PLAN NO (3B) — legacy Close, atomic snapshot | PLAN YES | v9.9.10 |
| r26 | PLAN NO (3B) — row-version pipeline | PLAN YES | v9.9.11 |
| r27 | PLAN NO (4B) — config epoch, cohort | PLAN YES | v9.9.12 |
| r28 | PLAN NO (4B) — in-place refresh, persistent migration, temporary stop | PLAN YES | v9.9.13 |
| r29 | PLAN NO (2B) — cutover fence, mixed-version matrix | PLAN YES | v9.9.14 |
| r30 | PLAN NO (3B/1H/1M) — mode collision, persistent INSTALL, temp stop, §9 matrix, selector inventory (session 019f990b-…-275842ade004) | PLAN YES | v9.9.15 |
| r31 | (running — resumed session 019f990b-…-275842ade004) | PLAN YES (4xSOUND, no new traces) | — |
| r31 SMR | — | — | claude-smr-plan-r31.md: PLAN NO for v9.9.15 — 2 self-found precision defects (persistent ADDRESS-ONLY lease arm unnamed in B2 fold; "never wire-carried in Phase 1" straggler), 3 state-explicitly nits |
| r80 | PLAN NO (3B/4H) — atomic snapshot, incumbent overwrite, scoped keys, counted vector, floor ACK id, backfill ACK | PLAN NO (second attempt — first hit an infra timeout) | v9.9.54.35 |
| r81 | PLAN NO (6B/2H) — atomic domain, active-copy overwrite, RootRef scope, predecessor totality, floor ACK id, CONFIG_APPLIED_ACK; mint linearization | PLAN NO (2xUNSOUND: frame size bound + digest canonicalization; preflight lease ambiguity; backfill adoption ambiguity + 3 new traces) | v9.9.54.36 |
| r81 SMR | — | — | claude-smr-plan-r82.md: PLAN NO for v9.9.54.36 — 7 nits, none LOW (third consecutive all-nit SMR round) |
| r82 | (terminal-cut decision round — no fold) | (terminal-cut decision round — no fold) | **v10.0.0 — THE TERMINAL CUT**: plan restructured from 9,603 lines to the Part-A gate + wire-free Part-B rules; the RG-incarnation/retirement/fence protocol KILLED (§10.6); #6522 re-scoped to its own issue; Phase 2 remains split (phase2-brief.md). Rationale: 70 rounds (r13-r82) of non-convergence, ALL findings in the machinery layer, none in the gate (stable since v6, "substantially converged" per Codex r12) |

## Rounds 83-89 (v10.x terminal-cut arc)

| Round | Codex verdict | AGY verdict | SMR verdict | Plan version folded to |
|---|---|---|---|---|
| r83 | PLAN NO (3B/1M/2L) | PLAN YES | PLAN NO (1L/5nit) | v10.0.2/v10.1.x |
| r84 | PLAN NO (4B/1H/1M) — pending-neighbor RETREAT | PLAN YES | PLAN NO (2nit) | v10.1.1/v10.2.0 |
| r85 | PLAN NO (4B) | PLAN YES | PLAN NO (2nit) | v10.3.0 |
| r86 | PLAN NO (5B/1H/1L) — seed-lifecycle RETREAT | PLAN YES | PLAN NO (2nit) | v10.4.0 |
| r87 | PLAN NO (2B/1L + editorials) | PLAN YES | PLAN NO (2nit) | v10.4.1 |
| r88 | PLAN NO (1B/1L + editorials) — probation pre-filter refresh pins zombies | PLAN YES (6th consecutive) | PLAN NO (3nit) | v10.5.0 |
| r89 | PLAN NO (3B/2L) — RWoLB/ReplacedSyncedLocal SYN-close constructor gap; materialize re-upsert bypass; probation retention fence; §3.1 table corrections (thread 019fa3e0-cef9-7ef2-876f-3686dfc22ddf, job task-ms8s878t-chbkk4) | infra-blocked this session: MCP agy_rescue headless command-denial (attempt 1); safety refusal on adversarial framing (attempt 2) and on defensive framing (attempt 3); backend stall x2 (attempts 4-5); RESOURCE_EXHAUSTED 429 x2 (attempts 6-7) — retries continue next round per feedback_codex_infra_must_retry; AGY r83-r88 were 6 consecutive PLAN YES | PLAN YES (r89, v10.5.0 — the arc's first SMR YES) | v10.5.1 (master-drift fold) + v10.6.0 (Codex r89 folds) |
| r90 | PLAN NO (2B/2H/1L) — owned-RWoLB probation cleanup unsound (leak/split-brain); cleared no-Open probation = gen-zero delete authority (sync_conn_gen.go:176/:263); materialize probe decision-incomplete; companion propagation an unlisted refresh path; §3.1 row nits (job task-ms8ts2yt-yfnmas) | SOUND at r89 (7th consecutive; covered the v10.6.0 folds explicitly — sections 4(b)/4(c)) | PLAN YES (r90 fold verification) | v10.7.0 (skip-install+rollback replaces alive-probation-install; adopt-S2-preserve-deadline; propagation skip; §3.1 rows) |
| r91 | PLAN NO (2B/1H/2L) — v10.7.0 rollback-then-forward freed-tuple race (allocator.rs:1617 collision via PendingNeighPacket/neighbor_dispatch); destructive purge = one-shot provenance (close #2 FreshPrimary+Open overwrite); fence protected targets not matched rows; adopt-S2 extension; impossible counter test (jobs task-ms8vf884-ce8wnv content-filter kill + task-ms8voay9-uhouz9 resume) | SOUND at r90 (8th consecutive; verified all three v10.7.0 folds + spray neutrality + wheel arithmetic + cleared-probation emission authority) | PLAN YES (r91 fold verification, claude-smr-plan-r91.md) | v10.8.0 (close-aware transient purge; matched-probation mark gate; adopt-S2 min() deadline; §9 wording) |
| r92 | PLAN NO (1B/1H/2L) — close-aware purge not an absorbing fence (spoofed non-close SYN takes master's purge+Open path; re-scoped to #6599); import-window reservation race (re-scoped to #6600); adopt-S2 encoding/oracle conflict; §9 byte-identity overstatement (jobs task-ms8wrnp0-vrwxgg content-filter + task-ms8ww8sa-5qx84b resume) | SOUND at r91 (9th consecutive; v10.8.0 folds verified incl. spray bounds + ordering interleaves; 1 editorial nit folded) | PLAN YES (r92 fold verification, claude-smr-plan-r92.md) | v10.9.0 (document+re-scope #6599/#6600; adopt-S2 encoding; §9 oracle narrowing) |

Follow-up issues filed this arc: #6522 (NAT release, round 82), #6599 (transient-purge/Open provenance-integrity, round 92), #6600 (import-window reservation race, round 92).
| r93 | PLAN NO (2B/1H/2M/1L) — same-dispatch re-entry collapsed #6599 from 2 packets to 1 (master retains hit.lookup post-purge, session_glue/mod.rs:1194-1196); overdue-K adopt pins via current-tick re-queue; close-retention amplifies #6600 for reservation-failed rows; §9 oracle/producer-invariant/citation nits. FRESH thread (job task-ms8ymxmb-r4jxbv) after the resumed thread hit the content filter twice (task-ms8yfjb8-2egd0h, task-ms8ykbrl-erek5p) | SOUND at r92 (10th consecutive; re-scope traces verified step-by-step; adopt-S2 algebra proved; five-location consistency) | PLAN YES (r93 fold verification, claude-smr-plan-r93.md) | v10.10.0 (install-free re-entry; reservation-succeeded retention; overdue-K skip; oracle repairs) |
| r93 (AGY) | — | UNSOUND (2 editorial: stale same-dispatch-install stragglers at plan.md:2175-2178 and :694/:700; all three substantive folds code-verified) — first AGY non-SOUND in 10 rounds | — | v10.10.1 (stragglers re-scoped to the deferred install) |
| r94 | PLAN NO (5B/2H/1M) — install-free dismantled: reservation-failed fallback drops deliverable closes; derivation strands unowned P2; no-cache rule accelerates #6599 for the cache-eligible subclass; cached success bit not a live fence (unrefcounted shared token); overdue-K skip resurrects split-brain (job task-ms8zw4fz-ykbkkc) | — | PLAN YES (r94 fold verification, claude-smr-plan-r94.md → r95 for the retraction) | **v10.11.0 — THE RWoLB RETRACTION**: re-entry removed entirely (master-verbatim retained-lookup dispatch); close-aware purge gate with unconditional retention is the only departure; overdue-K adopts S2 in place without re-queue |
| r94 (AGY) | — | UNSOUND (4 editorial stragglers: §5.8 reservation-condition fragment, §11 Q1 list, §11 Q3(a) prompt, §3 site-row-3 name; ALL substance verified sound — parity confirmed, close walk zero-mutation, stress tests pass) | — | v10.11.1 (stragglers excised) |
| r95 | PLAN NO (5B/1M/1L) — v10.11.0's master-verbatim claim wrong for the cold path (master runs the seed transaction; retained-decision buffering would replay the released P1); retention bound wrong (shared rows have no deadline); overdue-K adopt needed atomic reindex + field contract; inertness claim needed the accounting scope; one-decision claim scoped (job task-ms911f15-3lat79) | UNSOUND at r94 (4 editorial stragglers, folded v10.11.1; substance sound) | PLAN YES (r95 fold verification → r96 doc) | v10.12.0 (master-SPLIT purged dispatch: warm retained-forward / cold seed transaction; corrected #6600 bound; reindex-shaped overdue adopt; scoped claims) |
| r96 | PLAN NO (6B/1H/1M) — master's cold merge keeps released P1 over P2 (nat/mod.rs:123-133) falsifying 'correct because master'; close-then-ACK not end-state-equivalent; RG-activation crossover promotes conflicted P1; retention-bound straggler + cache-outlives-delete; in-place adopt authority/accounting hazards; arm-head outcome naming (job task-ms92domw-83bege) | SOUND at r95 (v10.12.0, full stress coverage incl. capacity-exhaustion rollback) | PLAN YES (r96 fold verification → r97 doc) | v10.13.0 (parity-not-correctness + purge-aftermath documentation; purge-dispatch cache-insert suppression; overdue-K local-only remove; outcome rename) |
| r97 | PLAN NO (3B/3H/1M/1L) — unconditional cache suppression history-blind (#6599 acceleration for ACK-first flows); overdue-K remove-locally broke pre-admission discipline + commit-clear path; sessionless-cache timing; no close→ACK packet parity / re-import livelock; #6522-reachability; cold-path seed-HIT + 10×/150× delta; contradictions (job task-ms93o3kt-x5xp48) | SOUND at r96 (v10.13.0, full stress coverage) | PLAN YES (r97 fold verification → r98 doc) | v10.14.0 (close-retained MARKER on the shared row + marker-conditioned suppression; overdue-K skip-wholesale + never-refresh-on-overdue guard; documentation exact) |
| r98 | PLAN NO (6B/3H/1L) — marker has no identity-safe lifecycle (unlocked-clone lookup, separate generation check, blind publication replace), cannot survive worker-replica topology or reach the cache gate, existing ACK cache bypasses it; OverdueSkipped not carried to consumers; GC-invalidation claim false for canonical keys/unsafe for aliases; cold end-state prolongs conflicted seed; packet-three failures proposal-created (job task-ms94ulgb-ennkbc) | SOUND at r97 (v10.14.0, marker-lifecycle analysis) | PLAN YES (r98 fold verification → r99 doc) | **v10.15.0 — THE PURGE-PATH RETRACTION**: close-aware gate + marker + suppression all retracted (full master parity, closes included); close-on-purged-provenance documented as #6599-family; typed OverdueSkipped outcome (teardown/anchor/cache suppression) + alias-complete cache invalidation at probation reap |
| r98 (AGY) | — | UNSOUND (3 specification-completeness findings: §11 stale phrasing; reverse-companion key omitted from the alias invalidation; §5.8 OverdueSkipped enumeration incomplete — everything else verified SOUND incl. the full consumer walk) | — | v10.15.1 (all three folded) |
| r99 | PLAN NO (5B/1H/1L) — FULL MASTER PARITY behaviorally false (local lookup precedes the purge; the demote refusal is a deliberate delta with a replica-lifetime cost); OverdueSkipped needed transport + composition + accounting rule; alias set incomplete (reverse-translated, reply-match; S1 at adopt time); conceded-chain rationale wrong for the SYN-close variant; saturating spelling (job task-ms96f72v-019zd8) | UNSOUND at r98 (3 specification findings, folded v10.15.1) | PLAN YES (r99 fold verification → r100 doc) | v10.16.0 (scoped parity claim; OverdueSkipped transport/composition/five-consumer set; full alias sets at adopt+reap; corrected rationale; saturating spelling) |
