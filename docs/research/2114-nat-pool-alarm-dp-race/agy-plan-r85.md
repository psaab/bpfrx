# AGY adversarial plan-review — round 85 (plan v86 @ cee81d0b1b0f)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY (PR-1 ONLY) — "PR-1 in plan v86 is complete, rigorous, and fully converged"; no blocking issues. Raw output follows verbatim.

---

### Adversarial PLAN Review Verdict for #2114 (Round 85 / Plan v86 @ `cee81d0b1b0f`)

**Verdict**: **PLAN-READY** (PR-1 ONLY)

---

### Hostile Audit & Verification Report

#### 1. THE TYPED PAIR (`lookupMapLocked` / `lookupProgramLocked`)
- **Production Site Audit**: Grepped every `m.maps[...]` and `m.programs[...]` production reference across `pkg/dataplane` ([`compiler.go:353`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/compiler.go#L353), [`loader.go:495,609,700,730,831,880,890,910,928,957,989,1086,1152,1157,1162`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/loader.go#L495), [`maps_counters.go:28,82,181,202,233`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_counters.go#L28), [`maps_fabric.go:19,29,39,54,79`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_fabric.go#L19), [`maps_filter.go:17..129`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_filter.go#L17), [`maps_flow.go:33,42`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_flow.go#L33), [`maps_mirror.go:16,30`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_mirror.go#L16), [`maps_nat.go:20..135`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/maps_nat.go#L20)).
- **Shape Sufficiency**: Every single production read site is a single-key lookup by `name string`. Zero map/program iterations (`range m.maps` / `range m.programs`) exist in production code. 
- **Type-Aware Pair**: `lookupMapLocked(name string) (h *ebpf.Map, present bool, st registryState)` and `lookupProgramLocked(name string) (p *ebpf.Program, present bool, st registryState)` ([`plan.md:4818-4820`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4818-L4820)) cleanly handle the type distinction between `*ebpf.Map` and `*ebpf.Program` (e.g. `loader.go:495`, `:609`, `:1086`, `:1156`).
- **Presence vs Handle**: Returning `present bool` (comma-ok) correctly preserves present-but-nil fixture semantics (e.g., [`xdp_shim_decouple_test.go:321`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/xdp_shim_decouple_test.go#L321)).
- **Canary Allowlist & Anti-Escape**: Direct map/program container indexing outside the allowlist (`lookupMapLocked`, `lookupProgramLocked`, `publishShimRegistryLocked`) is forbidden by the AST canary ([`plan.md:4810-4840`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4810-L4840)). The map containers (`m.maps`, `m.programs`) never escape.

#### 2. PER-CLASS OUTCOME RULES (Matrix Verification)
- **Cell Enumeration**: State $\in \{\text{fresh}, \text{retained}, \text{armed}\} \times \text{present} \in \{\text{true}, \text{false}\}$.
  - **Class 1 (Fallible Map-Required)**:
    - $\text{fresh} \times \text{false}$: Returns `ErrDataplaneNotArmed`. (Only intentional behavior change replacing map-not-found / nil-map panic).
    - $\text{retained} \times \text{true}$: Proceeds with handle (master behavior).
    - $\text{armed} \times \text{true}$: Proceeds with handle (master behavior).
    - *Carve-out*: Pre-existing loaded-check set (`AttachXDP`, `AttachTC`, `CompileConfig`) preserves master's pre-registry rejections on both fresh and retained states ([`plan.md:3703-3720`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3703-L3720)).
  - **Class 2 (Neutral Outcome)**:
    - $\text{fresh} \times \text{false}$: Returns master's neutral value ($0$, `nil`, empty) byte-for-byte.
    - $\text{retained} \times \text{true}$: Proceeds with handle.
    - $\text{armed} \times \text{true}$: Proceeds with handle.
  - **Class 3 (Go-Side Side-Effect Hybrids)**:
    - Executes Go counter resets under lock / prior to lookup, then proceeds with BPF lookup; on missing map returns master's exact error string (`"interface_counters map not found"`).
  - **Class 4 (Escaping Getters)**:
    - $\text{fresh}$: Returns `nil` (or `(nil, ErrDataplaneNotArmed)` for `NewEventSource`).
    - $\text{retained} / \text{armed}$: Returns handle.
- **Verification**: No cell alters master's observable behavior on `armed` or `retained` states, nor on neutral `fresh` paths.

#### 3. DECISION/USE SPLIT
- **Atomic Under-Lock Classification**: `lookupMapLocked` and `lookupProgramLocked` compute `st` ($\text{armed}$ if `loaded=true`, $\text{fresh}$ if `len(m.maps)==0`, else $\text{retained}$) and fetch `(h, present)` under a single acquisition of `m.mu` ([`plan.md:4818-4825`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4818-L4825)).
- **Post-Unlock Safety**: The caller receives `(h, present, st)` and makes a pure, deterministic gate decision. The container `m.maps` is indexed strictly inside the helper under lock. The handle `h` (`*ebpf.Map`) represents an OS file descriptor that is safe for concurrent BPF syscall operations post-unlock. No stale classification or post-unlock map-indexing race is possible.

#### 4. THE NEVER-ARMED-CLOSE QUALIFICATION
- **Site Audit**: Verified all three teardown-summary sites:
  1. §4 `loaded` mechanics bullet ([`plan.md:3898-3910`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L3898-L3910))
  2. §4.7 delivery bullet ([`plan.md:4065-4071`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4065-L4071))
  3. §7 Invariant 12 ([`plan.md:4520-4526`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L4520-L4526))
- **Consistency**: All three sites (plus §1 status notes at [`plan.md:14-18`](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L14-L18)) accurately qualify that for a never-armed `Manager` (`len(m.maps)==0`), `Close()`'s entry `loaded.Store(false)` leaves `st == fresh` (since `len(m.maps)==0`), so entry `Store(false)` changes nothing. For an armed `Manager` (`len(m.maps) > 0`), ordinary methods classify `retained` and proceed per master, while the loaded-check set (`AttachXDP`, `AttachTC`, `CompileConfig`) rejects `!loaded`.
- No un-scoped or overclaiming teardown statements remain in the plan.

#### 5. PR-1 CORE SCOPE & OUT-OF-SCOPE BOUNDARIES
- **PR-1 Scope**: Work item A1 (`d.dp` accessor + `CachedStatusProvider` sampler narrowing) + Work item A3 (armed-state admission gate, `atomic.Bool` loaded, typed helper pair, method classification matrix) + CANARIES (`dpCell` canary, registry canary).
- **Out of Scope**: G+H+H2 (§4.7 / §10) are cleanly isolated in `followup-seed.md` and do not block PR-1.

---

### Blocking Issues for PR-1
**None.** PR-1 in plan v86 is complete, rigorous, and fully converged.
