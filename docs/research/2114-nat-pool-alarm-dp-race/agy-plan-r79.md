# AGY adversarial plan-review — round 79 (plan v80 @ 91dbcb631)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-NEEDS-MINOR (0 MAJOR, 3 MINOR — two stale phrases confirmed real (class-1's acquire-load opening at :3605; 5.1's 'acquire-load rule' at :4071); the third (a Store(true)-at-Close typo at :4422) is a MISREAD — line 4422 correctly reads Store(false), verified with a full-document sweep; not folded). Raw output follows verbatim.

---

# Adversarial PLAN Review for #2114 — Round 79 (v80 @ 91dbcb631)

**Verdict**: **PLAN-NEEDS-MINOR**  
**Verdict Surface**: **PR-1 ONLY** (Work items G+H+H2 in `followup-seed.md` out of scope).  
**Implementation Blocker**: **NO**. The core mechanism (A1 publication cell, A3 uniform `m.mu` registry helper, whole-batch publication, 2-state predicate, 4-leg oracle, and carve-out set) is **sound, feasible, and implementable**. Only three residual text contradictions/typos in `plan.md` require text edits for full-document convergence.

---

## Hostile Verification Report

### 1. FULL-DOCUMENT CONSISTENCY AUDIT

Reading §4 A1's A3 block, §5.1, §5.5, §6, §7 item 12, §9 item 4a, and §10 as **one document**, three residual text contradictions/typos were found:

1. **[TEXT CONTRADICTION] §4 A1 Class 1 (`plan.md:3605`)**:
   - **Text**: `acquire-load m.loaded BEFORE THE FIRST Start-state access; pre-arm return the typed ErrDataplaneNotArmed`
   - **Defect**: This sentence survives from the v70-era pre-uniform gate design. It contradicts lines `3615-3623` (where Class 1 enters the registry helper under `m.mu` to classify fresh/retained/armed atomically) and line `3647` (where the gate requires checking `loaded == false` **and** `m.maps` empty under `m.mu`). Acquire-loading `m.loaded` before `m.mu` or without checking `m.maps` would see `loaded == false` on a RETAINED manager and return `ErrDataplaneNotArmed`, suppressing retained state. Line `3683` explicitly deleted this phrase for Class 2, but it was missed in Class 1.
   - **Fix**: Delete `acquire-load m.loaded BEFORE THE FIRST Start-state access;` from line 3605 to match lines 3615-3623.

2. **[TEXT CONTRADICTION] §5.1 Class 2 (`plan.md:4071`)**:
   - **Text**: `class-2 neutral-outcome ANY signature WITH the acquire-load rule (class-2 joins the blocked-Start overlap);`
   - **Defect**: In §4 A1 line `3683`, the plan explicitly states that the acquire-load-then-return reading was **deleted** (`"(the uniform rule — the acquire-load-then-return reading is deleted, r78 Codex M1: it contradicted the under-lock classification and would again suppress retained state)"`) and replaced with *"WITH the synchronization rule"*. §5.1 was not updated and still states `"WITH the acquire-load rule"`.
   - **Fix**: Update line 4071 to read `class-2 neutral-outcome ANY signature WITH the synchronization rule`.

3. **[TYPO] §7 Item 12 (`plan.md:4422`)**:
   - **Text**: `the Store(true) at Close()'s entry (:1206) gates new FRESH-state entrants`
   - **Defect**: `Close()` sets `loaded = false` via `Store(false)` at entry (`loader.go:1206`), as correctly documented in §4 A1 (`plan.md:3568, 3842`), §5.1 (`plan.md:4060`), and §10 (`plan.md:4752`). Writing `Store(true)` at `Close()` entry is a typo.
   - **Fix**: Change `Store(true)` to `Store(false)` at `plan.md:4422`.

---

### 2. THE FOUR-LEG ORACLE
- **Legs**: (1) Quiescent FRESH, (2) Quiescent RETAINED, (3) Blocked FRESH-Start, (4) Blocked RETAINED-re-Start.
- **Consistency & Implementability**: **100% SOUND**.
  - On **quiescent FRESH**, Class 1 returns `ErrDataplaneNotArmed`, Class 2 returns neutral outcomes, Class 3 executes side-effects + pinned legacy outcomes, Class 4 returns `nil`/error.
  - On **quiescent RETAINED** (`loaded == false`, `m.maps` populated), Class 1 methods without pre-existing loaded checks enter the registry helper, observe non-empty `m.maps`, bypass the fresh-state gate, and proceed against retained maps (= master). Preserved loaded-check methods (`AttachXDP` `:490`, `AttachTC` `:1082`, `CompileConfig` `compiler.go:182`) check `!loaded`, evaluate `true`, and return their master error ("eBPF programs not loaded" / "dataplane not loaded") before registry selection (= master).
  - On **blocked legs** (3 & 4), readers enter the registry helper and block on `m.mu` held by the synthetic loader. `Store(true)` is the final step inside the `m.mu` hold. Upon release, readers acquire `m.mu`, observe `loaded == true`, and see the fully populated registry.
  - **Hook Placement (`plan.md:4585-4588`)**: Explicitly specified. Callers of preserved loaded-check methods before `Store(true)` evaluate `!loaded` and return immediately; callers after `Store(true)` pass the precheck and block on `m.mu`.

---

### 3. SEAM FEASIBILITY
- **Analysis**: The synthetic loader acquires `m.mu`, populates the registry, signals `entered <- struct{}{}`, and waits on `<-resume`.
- **Deadlock Check**:
  1. Test thread waits on `<-entered`.
  2. Test thread launches/signals the reader goroutine.
  3. Reader goroutine calls a gated method and invokes `m.mu.Lock()`. It blocks on `m.mu.Lock()` without holding any locks required by the writer or test thread.
  4. Test thread closes `resume`.
  5. Synthetic loader resumes, executes `m.loaded.Store(true)`, and releases `m.mu`.
  6. Reader acquires `m.mu`, completes successfully, and releases `m.mu`.
- **Conclusion**: Feasible, robust, and zero self-deadlock risk.

---

### 4. FRESH ATTACK ON PR-1 CLAIMS
- **Retirement Canary & AST Checks**: `pkg/dataplane/retirement_boundary_canary_test.go` and `pkg/daemon/daemon_dp_canary_test.go` properly cover generic instantiation (`*ast.IndexExpr`/`*ast.IndexListExpr`) and enforce complete access routing through accessors.
- **Structural Sampler Narrowing**: `fwdstatus.NewSampler` accepting `CachedStatusProvider` ensures the backend cannot be misrouted into `Build` paths.
- **Precedence & Categorization**: The 157 exported `*Manager` methods are strictly partitioned across Class 1-4, Category L, F, and G using the escape-first precedence rule.

---

## Summary of Findings (file:line)

| # | Severity | File:Line | Issue Description |
|---|---|---|---|
| 1 | **MINOR** | `plan.md:3605` | Stale `acquire-load m.loaded BEFORE THE FIRST Start-state access;` phrase in §4 A1 Class 1 text. |
| 2 | **MINOR** | `plan.md:4071` | Stale `WITH the acquire-load rule` phrase in §5.1 Class 2 text (should be `WITH the synchronization rule`). |
| 3 | **MINOR** | `plan.md:4422` | Typo `Store(true)` at `Close()` entry in §7 item 12 (should be `Store(false)`). |

Once these 3 text edits land in v81, PR-1 is **PLAN-READY**.
