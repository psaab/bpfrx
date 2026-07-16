# Triage result — ps-review-036-cohort8 (Firewall filters + PBR + Routing)

- **Cohort:** 8 — firewall filters + PBR + routing (RE-AUDIT; ps-024 + ps-033 covered it prior)
- **Review base:** 33b891d11 (Merge PR #4563)
- **Current master:** 0b4109522
- **Stale-base check:** base is 3 commits behind current master. `git diff --stat 33b891d11..origin/master` shows those 3 commits touch ONLY `pkg/cluster/`, `pkg/vrrp/`, `userspace-dp/src/nat*`, `session_glue/` (NAT64 HA #4512, VRRP #4548/#4549, dup-node-id #4549). **Zero cohort-8 files** (`userspace-dp/src/filter/**`, `pkg/routing/rules.go`, `pkg/config/compiler_firewall.go`, `forwarding/mod.rs`, `dataplane/userspace/filters.go`) changed. → Base is functionally current for cohort 8; **no stale-base false-opens possible**.
- **Outcome counts:** 9 findings total →
  - **NOVEL GENUINE-RESIDUAL: 0**
  - DUP / KNOWN-TRACKED (low, defense-in-depth): 3 (F-001, F-002, F-003)
  - NEGATIVE / ALREADY-FIXED (verified on master): 6 (F-004..F-009)
  - CONFABULATED: 0
- **Bottom line:** The review is an honest self-terminating re-audit. It reports **0 new High/Med fail-opens** and explicitly dedups its 3 residuals against the pre-existing finding corpus (F-236/F-129/F-127 in `/tmp/all_findings.txt`). Every cited symbol was confirmed present on `origin/master`; every claimed fix maps to a CLOSED issue with the fix symbol live. Nothing to file.

---

## Per-finding disposition (with reasoning)

### F-001 — flex_mask==0 turns flexible-match-range into match-all → **DUP (F-236) / NOT-MATERIAL**
- **Symbol check (EXISTS):** `userspace-dp/src/filter/engine/matching.rs:149` — `(val & term.flex_mask) == term.flex_value`. Confirmed via `git show origin/master`. The doc comment at :101 explicitly says the value is "pre-masked."
- **Refutation / why not-material:** The Go compiler re-defaults a zero mask before it ever reaches the Rust boundary. `git show origin/master:pkg/config/compiler_firewall.go` line 1000-1010: `if fm.Mask == 0 { ... if fm.BitLength >= 32 { fm.Mask = 0xFFFFFFFF } else { fm.Mask = (1<<BitLength)-1 } }`. So a committed config can NEVER emit `mask==0`. Value is also pre-masked (`value & mask`), so for the only reachable `mask==0` case value is also 0, and `(any & 0)==0` is the *correct* Junos match-all semantics for an all-zero mask. A match-nothing fail-open (mask=0, value!=0) requires a hand-forged snapshot that bypasses the Go compiler — not reachable via commit or peer-sync (peer-sync payloads are Go-built too).
- **Dedup:** Exactly the task's pre-disposition ("flex_mask==0 match-all — compiler re-defaults mask; ps-024/033 NOT-MATERIAL, do NOT re-file"). Present in `/tmp/all_findings.txt:236` as F-236 [UNKNOWN]. The review itself labels it CONFIRMED-known/low, not new. **Do not file.**

### F-002 — filter_term_semantics_match omits flex_* fields → **DUP (F-129) / NOT-MATERIAL**
- **Symbol check (EXISTS):** `cache_sensitive.rs` `filter_term_semantics_match` compares ~30 fields but not the six `flex_*`. Confirmed. `has_per_packet_l4_match()` at `mod.rs:267-277` **does** include `|| self.flex_enabled` (verified — line 276, with the `#3077` comment).
- **Refutation / why not-material:** Because `has_per_packet_l4_match` includes `flex_enabled`, any filter using flexible-match forces the flow-cache to **DECLINE** (`flow_cache.rs` `interface_input/output_filter_has_per_packet_l4_match` → `return None`). With no cached verdict ever installed for a flex filter, there is no stale entry for the omitted-field equality check to fail to invalidate. The omission is pure defense-in-depth (would only bite if the decline gate were later removed). Full-eval always re-reads packet bytes.
- **Dedup:** Matches task pre-disposition ("F-003/M-02 filter_term_semantics_match omits flex_* — moot, flex forces flow-cache decline; do NOT re-file"). Present as F-129 [UNKNOWN] in `/tmp/all_findings.txt:129`. **Do not file.**

### F-003 — CachedThreeColorPolicers hard-caps at 2 runtimes → **DUP (F-127) / KNOWN-TRACKED, low**
- **Symbol check (EXISTS):** `userspace-dp/src/filter/mod.rs:451-466`. Verified `push()` body: dedups by `id`, fills `first` then `second`, and a third distinct policer is **silently dropped** (no `else`, no warn, no error). `len()` caps at 2, `for_each` iterates ≤2.
- **Is it a real residual?** Yes, mechanically: on the **cached TX-selection replay** path a flow that matched >2 distinct `then policer` terms via #2544 fall-through meters only the first two; the 3rd+ policer never meters that flow → rate-limit under-enforcement for that one policer. NOT a permit/deny bypass — filter verdict is unaffected; the uncached full-eval path meters all.
- **Why low / why not escalated as NOVEL:** (1) It is pre-existing and already tracked as **F-127 [UNKNOWN]** in `/tmp/all_findings.txt:127` — not a discovery of this re-audit. (2) Reachability is atypical: needs ≥3 distinct policer terms all matching one flow through fall-through; typical filters carry 1-2 policers/flow. (3) Blast radius is bounded to rate-limit slack on the cached path for the surplus policer, not a security fail-open. The adjacent counter path (#2573) already uses a `SmallVec<[_;2]>` that spills to heap for >2 — the policer slot could adopt the same pattern, or a commit-time validator could reject >2 policers/term-chain. Candidate hardening follow-up, **not a novel/material fail-open**. Consistent with ps-024 N-18 (intentional 2-slot inline). **Do not file as new.**

### F-004 — Three-color policer color-blind default → **ALREADY-FIXED (#4535), NEGATIVE**
- **Symbol check + fix:** `pkg/config/compiler_firewall.go:175-176` — `if !tcp.ColorBlindConfigured && !tcp.ColorAwareConfigured { tcp.ColorBlind = true }`. Confirmed live on master. Issue **#4535 CLOSED**. Correctly not re-reported.

### F-005 — PBR discard/reject kernel-mirror fail-open → **ALREADY-FIXED (#4534), NEGATIVE**
- **Symbol check + fix:** `pkg/routing/rules.go:790-793` — `if term.Action == "discard" || term.Action == "reject" { ...deny wins (mirroring the userspace drop, #4392) — no steering... ; continue }`. Confirmed live. Issue **#4534 CLOSED**. Correctly not re-reported.

### F-006 — Single-rate policer unenforced → **ALREADY-FIXED (#4514), NEGATIVE**
- Issue **#4514 CLOSED** (single-rate token-bucket lowering). Compiler lowering path present. Correctly not re-reported.

### F-007 — Family-any IPv6 arm → **ALREADY-FIXED (#4287/#4296/#4426), NEGATIVE**
- Issues **#4287 CLOSED**, **#4426 CLOSED** (family-any dual-compile + prefix-list family gate). Correctly not re-reported.

### F-008 — is-fragment match on non-first fragment → **NEGATIVE (correct by design)**
- `is_fragment` is L3-derived and intentionally NOT gated by `l4_present`; non-first fragments keep `is_fragment=true` while L4 terms fail closed. Verified correct in `matching.rs` / `inspect.rs`. No bug.

### F-009 — Flex match-start payload rejected at commit → **NEGATIVE (intentional divergence)**
- `compiler_firewall.go` accepts only `layer-3`/`layer-4`, records `UnknownFlexMatch` otherwise → strict validator rejects. Documented intentional. No bug.

---

## Confabulation / weight-verification sweep
- Every symbol the review cites (`matching.rs:149`, `compiler_firewall.go` mask default + color default, `mod.rs` CachedThreeColorPolicers, `rules.go:790` PBR skip, `has_per_packet_l4_match` flex) was confirmed to EXIST on `origin/master`. **No confabulated file:line.**
- All 7 dedup issue numbers (#4534/#4535/#4514/#4392/#4287/#4426/#3843) resolve to real CLOSED issues via `gh issue view`.
- No finding claims a fail-open/mis-steer that lacks a real code path. The one behaviorally-real residual (F-003) traces to real code but is low-severity rate-limit slack, already tracked, not a steering/permit bypass.

## Cross-check vs task dedup ledger
- Filed/merged list (#4534/#4535/#4514/#4555/#4392/#4498/#4287/#4296/#4426/#3843/#3776): none re-reported as new — all appear only as NEGATIVE/FIXED confirmations. ✔
- ps-024/033 NOT-MATERIAL set (flex_mask==0, next-table no-iif, filter_term_semantics_match flex omission): the review re-confirms them as known/moot, does NOT re-file. ✔
- OPEN tracked (#2387 5-tuple, #4478 IPIP): correctly listed as OPEN, not re-reported. ✔

**No new issue should be opened from this cohort.** If the parent wants a hardening backlog item, F-003 (>2 policer cap, F-127) is the only candidate, but it is pre-existing/tracked and low severity — not a novel finding of this audit.
