PLAN NO

Review pinned to `d8b4077a2`; no files were edited. Part A remains converged.

1. **BLOCKER — compatible in-place allocator migration lacks a cutover fence.**

   The new rule mandates compatible changes migrate in place ([plan.md:1070](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1070)). Today allocator B is built while A remains worker-visible ([snapshot_refresh.rs:212](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:212)), B is published later at `:397`, and workers retain A until their per-loop Arc refresh ([loop_body/mod.rs:467](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/worker/loop_body/mod.rs:467)).

   Concrete trace: migration snapshots A; a worker still holding A admits E1 and claims P afterward through the live allocation path ([allocator.rs:999](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:999)); B is published without P; E2 then claims P in B. Independent allocator bitmaps issuing the same tuple produce the documented reverse-NAT misdelivery ([compiler_tailgates.go:212](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/config/compiler_tailgates.go:212)). “Reserve before A is dropped” does not serialize post-snapshot A allocations. Compatible refresh needs quiescence, or an explicit freeze/dual-write bridge plus acknowledgement that no worker can still allocate through A.

2. **BLOCKER — the temporary `stop()`/rebind escrow fold is absent.**

   The plan’s two-phase mechanism remains expressly scoped to “the reconcile sequence” ([plan.md:881](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:881)); its drain rule otherwise discusses a permanent/full-helper stop ([plan.md:949](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:949)). No text routes temporary stop/rebind through escrow.

   `stop_workers` explicitly anticipates rebind but calls `afxdp.stop()` ([stop_workers.rs:7](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/server/handlers/stop_workers.rs:7)); `stop()` reaches `stop_inner(true)` ([coordinator/mod.rs:429](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/mod.rs:429)), joins/drops worker state at `:645`, and clears synced/NAT/wire state at `:709`. Thus a temporary link-cycle can drop E1’s final reservation; after rebind, E1 re-resolves or E2 obtains P, causing the prohibited mid-flow SNAT swap/collision. Temporary stop must use handoff, durable escrow, replay, and rebind-consumption confirmation.

3. **HIGH — the persistent-lease API contract remains contradictory.**

   The new paragraph correctly requires migration of the persistent lease object, including key, timeout, and co-holder semantics ([plan.md:920](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:920)). The later operative restore rule still prescribes `reserve_flow`/`reserve_address_only` for PAT and address-only reservations without excluding persistent allocations ([plan.md:1088](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1088)).

   Following that later rule reproduces the prior trace: `reserve_flow(F1,P)` creates a reservation with no persistent key; `reserve_flow(F2,P)` fails because P is occupied ([allocator.rs:1654](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs:1654), `:1682-1701`). F2 then lacks the shared lease and can re-resolve to another port. The later clause must restrict the generic APIs to non-persistent allocations and explicitly dispatch persistent PAT/address-only migration through the lease-object API.

4. **HIGH — normative §5.8 still omits both policy selectors.**

   The main design requires imported entries to inherit `stable_rule_id_hash` and `admission_config_version` through the INSTALL tail ([plan.md:1299](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1299)). But “normative, consolidated” §5.8 still lists only `(origin_process_nonce, flow_incarnation_id)` and snapshots only `(BPF/NAT row, identity, row_version)` ([plan.md:1921](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1921)); the shared-schema inventory still lists only clock/incarnation fields ([plan.md:1981](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1981)).

   The selectors cannot be reconstructed from the BPF projection ([bpf_session_value.go:168](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/bpf_session_value.go:168)), whose positional policy ID is rewritten during reorder ([bpf_map/mod.rs:384](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/bpf_map/mod.rs:384)). A literal §5.8 implementation therefore retains the numeric-ID selection at [daemon_policy_invalidate.go:311](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/daemon_policy_invalidate.go:311): a surviving rule’s E2 can alias a deleted rule’s old position and be companion-deleted through [session_store.go:391](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/session_store.go:391).

5. **HIGH — §9 still contradicts new→legacy Close suppression.**

   The strong rule correctly suppresses every incarnation-dependent new→legacy delete ([plan.md:1398](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:1398), [plan.md:2214](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2214)). However, §9 still says new-sender→old-receiver has its tail ignored ([plan.md:2287](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2287)) and generically says mixed-version pairs fall back to generation deletes ([plan.md:2329](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:2329)).

   If that matrix is followed for DELETE, A’s E1 Close reaches legacy B; B decodes key plus generation ([sync_conn_read.go:150](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_read.go:150)), accepts the equal/fresh generation ([sync_conn_gen.go:263](/home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go:263)), and key-deletes current same-key E2 plus companions at `sync_conn_gen.go:493-506`. The matrix must distinguish “new→old INSTALL tail ignored” from “new→old identity-dependent DELETE suppressed.”

### r21–r28 dispositions

- **r21:** B1 selector/generation **partially**; B2 install identity **resolved**; B3 owner gate **resolved**; H4 permit linearization **resolved**; H5 identity tuple **resolved**; M6 cursor **resolved**; M7 contract sweep **partially**.
- **r22:** a install identity **resolved**; b mixed delete **partially**; c selector **partially**; d permit/escrow **resolved** for reconcile; e cursor **resolved**; f contract sweep **partially**.
- **r23:** 1/c install identity **resolved**; 2/a mixed delete **partially**; 3/d selector **partially**; 4/b permit lifetime **resolved**; 5 cursor **resolved**; 6 contract sweep **partially**.
- **r24:** B1 mixed delete **partially**; B2 install identity **resolved**; B3 durable escrow **partially**—reconcile is covered, temporary stop is not; B4 selector **partially**; M5 cursor **resolved**; L6 sweep **partially**.
- **r25:** B1 legacy Close **partially**; B2 atomic install snapshot **resolved**; B3 policy stamp **partially**; H4a rejection cleanup **resolved** by the complete-cohort design; H4b allocator migration **partially**; M5 cursor **resolved**; LOW contract reconciliation **partially**.
- **r26:** B1 identity/row-version pipeline **resolved**; B2 capability suppression **partially** because §9 conflicts; B3 cleanup **resolved**; H4 allocator migration **partially**; H5 selector carriage **partially**; M5 cursor **resolved**.
- **r27:** B1 config generation **resolved**; B2 atomic identity source **resolved**; B3 complete cohort **resolved**; Close contract **partially**; allocator migration **partially**; H6 mixed-policy operational gate **resolved**; schema inventory **not resolved**; cursor **resolved**.
- **r28:** B1 config epoch **resolved**; B2 in-place migration **partially**; B3 persistent migration **partially**; B4 install-only mixed bulk **resolved**; H5 Close contract **partially**; H6 selector schema **not resolved**; H7 temporary stop/rebind **not resolved**.
- **Deferred-to-phase2-track:** only the explicitly accepted imported-anchor/reimport fast-reap residual. None of findings 1–5 is deferred.

The old “#6522 filed separately” status/open-question wording remains part of the partially resolved contract sweep, but I did not count it as a sign-off finding because the operative Part-B requirements explicitly include the holder refcount.

### Bottom line

No blind-demote DoS trace remains against Part A, and the config-epoch lifecycle, atomic identity snapshot, complete-cohort cleanup, install-only legacy bulk, and cursor folds now close their prior traces. But concrete SNAT collision/port-swap traces remain in compatible in-place refresh and temporary stop/rebind, while the selector schema and mixed-version matrix can still implement HA-propagated deletion of a replacement E2. Therefore final sign-off remains **PLAN NO**.

Codex session ID: 019f990b-7ec8-7f01-872a-275842ade004
Resume in Codex: codex resume 019f990b-7ec8-7f01-872a-275842ade004
