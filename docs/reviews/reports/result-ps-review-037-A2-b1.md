# Triage Result — ps-review-037-A2-b1 (NAT / NAT64 / NPTv6)

- **Review file:** `/tmp/ps-review-037-A2-b1.md`
- **Cohort:** ps-037, A2 Batch 1 (Rust dataplane NAT/NAT64/NPTv6), Codex audit
- **Base:** d4506d4450e2 == **current origin/master d4506d4450e23f9a3fc572206b3c82f6b6c99029** (FRESH base, not stale)
- **Context:** 5th NAT audit of the cohort (ps-028/034/036 each found 0-1 residuals — path is well-hardened). Weight-verified HARD against the merged/open NAT backlog.
- **Outcome:** **0 NOVEL GENUINE-RESIDUALs.** The single "NEW HIGH" (F-02) is REFUTED by the #2344 flowless chokepoint. Everything else is a self-declared DUP, a reviewer-confirmed NEGATIVE, or a self-scoped LOW/INFO that is deliberate/immaterial.

## Outcome counts
| Disposition | Count | Findings |
|---|---|---|
| GENUINE-RESIDUAL (novel) | 0 | — |
| DUP (open issue) | 2 | F-01 (#4559), F-03 (#4565) |
| NOT-MATERIAL / REFUTED | 3 | F-02 (refuted HIGH), F-08 (deliberate), F-09 (cosmetic) |
| NEGATIVE (reviewer-correct, no action) | 4 | F-04, F-05, F-06, F-07 |
| CONFABULATED | 0 | — (all cited symbols exist; F-07 snippet paraphrased but real) |

All cited symbols exist on origin/master — no confabulation. F-07's code snippet used non-Rust camelCase (`sameRule`, `ruleSetName`), i.e. the reviewer PARAPHRASED the source inaccurately, but the underlying fix exists (see F-07). No finding invents an absent symbol.

---

## F-01 — DUP #4559 (deterministic CGNAT advisory, still OPEN)
**Reviewer disposition:** "CONFIRM OPEN #4559." Correct — this is a known open item, in the dedup list (`#4559 CGNAT advisory`).
**Verified:** `pkg/config/compiler_validate_warn.go:759-787` — the `#4559` warning block exists exactly as cited (deterministic `port deterministic block-size` accepted-but-NOT-enforced by the userspace dataplane; warns so operator is not silently misled). `SourceNatRule` in `nat/source.rs` has no block-allocation fields; `PortAllocator::new` (allocator.rs) takes only `num_addresses/port_low/port_high`. The advisory is the current, deliberate mitigation; full block-allocator enforcement is the tracked #4559 follow-up.
**Why not novel:** Identical scope to open #4559 — deterministic block allocation unported to userspace-dp, advisory-only. Do NOT re-file, do NOT close. No new information beyond #4559.

## F-02 — NOT-MATERIAL / REFUTED (the only "NEW HIGH")
**Claim:** NAT64 non-first IPv6 fragment reaches `nat64.allocate_source` (poll_descriptor:2639) with no non-first-fragment guard (unlike the #1852 SNAT belt), claiming a stateful port + session is leaked per malicious fragment → single-host NAT64 pool exhaustion / DoS. Severity HIGH.

**Refutation (disproving code-path + trace):**
1. The ONLY caller of `nat64.allocate_source` in the tree is `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2639` (git-grep on origin/master — zero other callers).
2. Line 2639 is inside `let mut decision = if let Some(flow) = flow.as_ref() {` at **poll_descriptor/mod.rs:858** (the flow branch). `nat64_match` itself is computed at line 1514, also inside this `Some(flow)` arm (it reads `flow`'s dst). The flowless (`flow == None`) branch begins ~line 3433 and never calls `allocate_source`.
3. `flow` is produced solely by `stage_parse_flow_and_learn` → `parse_session_flow_from_bytes` (`userspace-dp/src/afxdp/frame/inspect.rs:942`). The FIRST statement (lines 955-957, **#2344**) is:
   ```rust
   if frame_is_non_first_fragment(frame, meta) { return None; }
   ```
   documented as "the single chokepoint that also defeats the meta fast path below … Returning `None` makes the fragment flowless."
4. `frame_is_non_first_fragment` (inspect.rs:904) resolves L3 and calls the SAME `is_non_first_fragment(slice, addr_family)` predicate that the #1852 SNAT belt uses at poll_descriptor:2618. So any genuine non-first fragment → `flow = None` → flowless branch → **never reaches line 2639**. The NAT64 path is protected by the #2344 upstream chokepoint exactly as the SNAT path is; the #1852 SNAT belt is now redundant defense-in-depth, and its absence on the NAT64 leaf is NOT a hole because #2344 already made the fragment flowless before either NAT stage runs.
5. The reviewer's own "Refutation attempt" is **factually wrong**: it asserts "frag header still has next proto, parser builds flow … Even if flowless, `allocate_source` still called." The parser does the OPPOSITE — `parse_session_flow_from_bytes` returns `None` for non-first fragments (#2344), and `allocate_source` is call-gated behind `if let Some(flow)`. There is no flowless path to `allocate_source`.

FEATURES.md corroborates: NAT64 allocation "is deferred to the Permit branch" on a real flow, and non-first fragments "are dropped both directions … the round-robin SNAT pool + port-keyed sessions cannot consistently map a port-less fragment."

**Disposition:** REFUTED (no port/session leak; NAT64 non-first fragment is flowless before allocation). This corresponds to the task's N-01 negative HOLDING for NAT64, not failing. Not a residual, not filed.

## F-03 — DUP #4565 (NAT64 HA reverse-translation, still OPEN; #4512 port-reservation MERGED)
**Reviewer disposition:** "CONFIRM OPEN #4512/#4565." Correct and in the dedup list (`#4564/#4512 nat64 HA reserve-on-standby MERGED`, `#4565 nat64 reverse-translation follow-up`).
**Verified:** `userspace-dp/src/afxdp/ha.rs:792` sets `nat64_reverse: None` on the synced entry. `nat64.rs:150-159` documents the exact scope: #4512 closed the port-COLLISION harm (standby reserves the translated port via `reserve_synced_nat64_allocation`), while reverse-TRANSLATION still needs `Nat64ReverseInfo{orig_src_v6, orig_dst_v6}` carried on the sync payload — "a separate wire-field follow-up." That follow-up is tracked as open #4565.
**Why not novel:** Exactly the documented #4565 gap; #4512's port-reservation slice is already merged. No new information. Do NOT re-file.

## F-04 — NEGATIVE (reviewer-correct)
NAT64 pool exhaustion fail-closed (N-02). `nat64.rs allocate_source` returns `Err(reason)` on exhausted/invalid pool; poll_descriptor:2659 `Err(reason)` → `record_nat64_source_failure(reason)` → recycle + `continue` (drop, no session, no translation) — no fail-open fallback. Counter split (#4520) attributes `AllocatorExhausted`→`nat64_pool_exhausted` vs empty/config→`nat64_no_source_pool`. Correct; no action.

## F-05 — NEGATIVE (reviewer-correct on SNAT)
SNAT non-first fragment no leak (N-01 SNAT). Confirmed: SNAT gates via the #1852 belt AND the #2344 flowless chokepoint; `pool_snat_non_first_fragment_refused_no_allocation` test pins it. The finding's tacked-on "NAT64 leaks" is the F-02 claim, which is refuted above. SNAT is safe; NAT64 is ALSO safe (via #2344). No action.

## F-06 — NEGATIVE (reviewer-correct)
PortAllocator integer safety: `port_low + (val % range) as u16 <= port_high <= 65535`, v4 `1u64 << host_bits` with `host_bits <= 32` fits u64, v6 guards `host_bits >= 64` before shift. Reviewer MED confidence, no overflow/truncation. No action.

## F-07 — NEGATIVE (reviewer-correct; snippet paraphrased)
NPTv6 host-bits (#4519, in dedup list) + self-overlap (#4339). **Verified real code:** `nptv6.rs:193` — `if words[prefix_words..8].iter().any(|&w| w != 0) { return None; }` fails CLOSED on host bits (module header #4519 at lines 29-40 documents the prior silent-widen bug and the fail-closed fix). `find_overlap` at nptv6.rs:414, overlap tracking at 227. NOTE: the reviewer's quoted snippet uses non-Rust camelCase (`sameRule`, `ruleSetName`, `prev.ruleName`) — that is a PARAPHRASE, not the actual source (real identifiers are snake_case + `find_overlap`/`rule_name`). Disposition (fixed) is correct; the transcription is loose but the symbols exist. No action.

## F-08 — NOT-MATERIAL / DELIBERATE (self-scoped LOW)
Synthetic `protocol==0` path `try_next_port` "bypasses owner tracking." **Verified deliberate + immaterial** at `nat/source.rs:1064-1070`:
> "`protocol == 0` is the synthetic 'L4 tuple unknown' sentinel used by the address-only `match_source_nat` callers (never a real packet). It keeps its historical behavior — a round-robin port via `try_next_port` with no flow-keyed mapping — because the packet rewriters gate every L4 write on `has_l4_ports`, so the port it returns can never be written to a frame."
The `tuple_unknown` port is never installed as a session and never frame-written; the production forwarding path uses `allocate_translation` (flow-keyed, `owner_by_translated`). The reviewer themselves rated it LOW / "no security boundary crossing." Not a NAT residual (no leak, no mistranslation). No action beyond optional cosmetic cleanup.

## F-09 — NOT-MATERIAL (cosmetic INFO)
`nat64.rs:197 pool_index: AtomicUsize` retained (used by test-only `allocate_v4_source` at line 550; prod `allocate_source` uses the `PortAllocator`). A harmless retained atomic field — no vulnerability, reviewer self-rated INFO. No action.

---

## Bottom line
The NAT/NAT64/NPTv6 surface remains well-hardened (consistent with the 4 prior cohort audits). The one novel HIGH (F-02, NAT64 fragment port leak) does not hold: non-first fragments are made flowless at the #2344 single chokepoint (`parse_session_flow_from_bytes` → `None`) before the sole `allocate_source` caller, which is call-gated behind `if let Some(flow)`. F-01/#4559 and F-03/#4565 are known open follow-ups already in the backlog. No new issue to file.
