# Triage result — ps-review-034 (Cohort 5: NAT / NAT64 / NPTv6) RE-AUDIT

- **Cohort:** 5 — NAT / NAT64 / NPTv6
- **Review base:** 8cd816e35 (snapshot stated); **fresh triage base:** current
  `origin/master` = `ce004a41eab47aac4b1d86e3e344c2e7ea2e6ac8` (fetched this run).
  8cd816e35 ≈ current master; the deterministic-NAT code cited is present on both.
- **Repo confirmed real bpfrx** (NOT avacado): every cited symbol resolves on
  `origin/master` (`applyDeterministicKeys`, `DeterministicNATConfig`,
  `pkg/dataplane/compiler_nat.go:473`, `frame_is_non_first_fragment`,
  `SourceNatLookup::Unavailable`, `from_snapshots_with_previous`,
  `is_zero_adjustment`, `record_nat64_source_failure`). No confabulation.
- **Prior triage of same cohort:** ps-review-028 (base b1bd96fb6) found 0 genuine
  residuals (3 not-material). This re-audit surfaces exactly **1 novel finding**
  plus 2 explicit negative (coverage-proof) results.

## Outcome counts

| Disposition | Count | IDs |
|---|---|---|
| GENUINE-RESIDUAL (novel) | 1 | M-01 |
| NEGATIVE (coverage proof, no bug) | 2 | L-01, L-02 |
| CONFABULATED | 0 | — |
| DUP / ALREADY-FIXED | 0 new (M-01 explicitly distinguished from #3864) | — |

The snapshot's §3 dedup table (14 CLOSED PRs + 4 OPEN excluded incl. #4512) is
correct and self-consistent with my task's known-merged list (#4518/#4519/#4520/
#4542/#4511/#4506/#4399/#4438/#4388/#4521) and the in-flight #4512. Those are NOT
re-reported by the review and I did not need to re-triage them. Only the 3
below-the-line items carry a disposition.

---

## [M-01] Deterministic NAT (CGNAT) silently unenforced on userspace dataplane — **GENUINE-RESIDUAL, Medium, NOVEL**

**Claim:** `security nat source pool P port deterministic block-size N host
address CIDR` parses + validates + commits clean in the Go compiler and
populates the retired BPF `NATPoolConfig`, but is **never wired into the
userspace-dp snapshot or the Rust dataplane** (the only runtime). It silently
no-ops → SNAT still happens via plain round-robin/sticky PortAllocator instead
of deterministic port blocks. CGNAT compliance logging is broken with zero
operator signal.

**Verification (all confirmed on origin/master):**

1. **Parse + validate exists and ACCEPTS** —
   `pkg/config/compiler_nat.go:1275 applyDeterministicKeys`,
   `:1302 applyDeterministicChildren`, `:1326 applyDeterministicHost`,
   `DeterministicNATConfig` (`pool.Deterministic`). Validation block
   `compiler_nat.go:1634-1688` checks only internal consistency (block-size>0,
   host required, capacity, mutual-exclusion with persistent-nat /
   address-persistent) and then **returns success** — I read the full block;
   there is **no** `unsupported-on-userspace` reject and **no** `cfg.Warnings`
   entry. So the config commits clean. Confirmed.

2. **BPF compile path exists but is dead for userspace** —
   `pkg/dataplane/compiler_nat.go:473-496` compiles `pool.Deterministic` into
   `poolCfg.BlockSize/BlocksPerIP/Deterministic/HostBase/HostBaseV6/HostCount`
   and writes BPF maps. The userspace runtime consumes control-socket snapshots,
   not BPF maps → this write reaches no consumer. Confirmed.

3. **Userspace snapshot builder ignores it** — `git grep -n
   "Deterministic\|BlockSize\|HostBase\|CGNAT"
   pkg/dataplane/userspace/nat_source.go` → **0 hits**. `SourceNATRuleSnapshot`
   carries no deterministic fields. Confirmed.

4. **Rust dataplane has no deterministic NAT** — `git grep -in
   "deterministic\|CGNAT\|BlockSize\|HostBase" userspace-dp/src/nat/*` → only
   comments about "deterministic ordering / sticky_pool_index / deterministic
   tests", **zero** CGNAT port-block logic. `allocator.rs` does claim/assign/
   recycle/sticky/persistent — no block math. Confirmed.

5. **Docs are contradictory (stale)** — `docs/feature-gaps.md:291` claims
   "**Done** (74e1d17, 439cd3f)" but those are the retired BPF + DPDK dataplanes
   (#1373 BPF retirement, #1525 DPDK retirement). `docs/vsrx-gaps.md:121` lists
   "PAT Pool with Address Shifting / Deterministic NAT (predictable port
   mapping) | Medium | **No**" and `docs/vsrx-gaps.md:25` lists deterministic /
   address-shifting as an open §2 NAT gap. So the authoritative parity doc
   agrees it is NOT implemented; feature-gaps.md is the stale outlier.

**Why NOT a dup of #3864 (the reason this is novel):** #3864 (CLOSED, fable-161
F-002) was the flat-set **PARSE** bug — deterministic NAT was *un-configurable*
because sibling `port deterministic` leaves overwrote each other and `host
address` was never parsed, so the documented quick-start **hard-failed commit**
("block-size must be > 0" / "host address required"). Its RED-on-revert asserts
only that the config now "COMMITS CLEAN and compiles the deterministic mapping"
(i.e. into `pool.Deterministic` + the BPF typed config). #3864's fix therefore
**exposes** M-01: by making the config commit clean, it converts a loud
commit-reject into a silent runtime no-op on the userspace plane. #3864 did not
touch userspace-dp enforcement. M-01 is a distinct, untracked residual.

**Not tracked by any OPEN issue:** searched `deterministic`, `CGNAT`,
`block-size`, `port block allocation`, `deterministic NAT userspace`. The only
deterministic-NAT issue is #3864 (CLOSED, parse). #2008 (vsrx-parity umbrella)
and #4228 (CoS) do not cover it. No open enforcement-gap issue exists.

**Severity reasoning — Medium (agree with review), lean Low-Medium:**
- **Exploitability / trigger:** operator-config-driven, not attacker-driven.
  Requires an operator to configure `port deterministic` (a niche ISP/CGNAT
  feature). Then commits clean with no warning → silent.
- **Blast radius:** limited to deterministic-NAT deployments. Traffic that
  matches the pool is STILL source-NAT'd via round-robin/sticky — **no traffic
  drop, no security bypass, no fail-open widening.** The concrete harm is:
  (a) CGNAT compliance logging (subscriber→fixed-port-block mapping for lawful
  intercept / abuse attribution) is broken; (b) zero operator signal.
- **Why not HIGH:** no packet leak, no policy bypass, no fail-open — SNAT
  enforcement itself is intact; only the *allocation pattern* differs. It is a
  compliance/parity gap, not a security fail-open, despite the review's
  "unenforced-control" label.
- **Why not LOW/dismiss:** it is a documented Junos feature that commits clean
  with no signal, and this project consistently treats "config parsed + stored
  with NO runtime consumer (silent no-op)" as a Medium parity defect worth a
  gate-or-implement (cf. #2079 pool-utilization-alarm — "previously parsed+
  stored with NO consumer (silent no-op)"; the fable-167 X-1 silently-inert-leaf
  class). The contradictory docs (Done vs No) compound the operator-deception.

**Fix direction (sound as written):** either (1) port block allocation to
`userspace-dp/src/nat/allocator.rs` + `SourceNATRuleSnapshot` +
`nat_source.go`, or (2) short-term: add a commit-time advisory/capability
warning when `pool.Deterministic != nil` on the userspace runtime (mirror the
"#4228 Gap 2 accepted-but-inert" advisory pattern already used for
`shaping-rate percent`) and correct the two docs. Option 2 removes the silent-
no-op deception cheaply; Option 1 is the full parity fix. Note: if filed,
reconcile `docs/feature-gaps.md:291` (stale "Done") with
`docs/vsrx-gaps.md:121` ("No").

---

## [L-01] NAT64 non-first-fragment port allocation — **NEGATIVE (no bug), confirmed**

Review's own disposition: negative result / coverage proof, severity N/A. Cited
chokepoint `frame_is_non_first_fragment` exists
(`userspace-dp/src/afxdp/frame/inspect.rs` region + `forward_request.rs`);
`parse_session_flow_from_bytes` returns `None` for non-first fragments (#2344),
routing them to the flowless path which never reaches NAT64 `allocate_source`
→ no PortAllocator claim → no leak. Symbols verified present; the reasoning
matches the #2344 single-chokepoint design and the #2562 OPEN issue (which
tracks the *separate* stateful frag-id→SNAT cache enhancement, not a leak). No
action — this is a proof that the #4381 BIB allocator did not regress fragment
handling.

## L-02 NAT pool exhaustion (SNAT / NAT64 / NPTv6) all fail CLOSED — **NEGATIVE (no bug), confirmed**

Review's own disposition: negative / correct behavior, severity N/A. Cited
symbols verified: `SourceNatLookup::Unavailable` (drop + counter),
`Nat64Match::MatchUnavailable` (empty pool → drop), `AllocatorExhausted` +
`record_nat64_source_failure` (#4520 split → drop + `nat64_pool_exhausted`),
`try_from_snapshots`/NPTv6 overlap/host-bits (`is_zero_adjustment`,
`parse_prefix` None) → reject-whole-snapshot → keep previous live state. All
exhaustion arms drop rather than fail-open-widen. The `NoMatch`/`NoPrefixMatch`
"continue / forward untranslated" arms are correct Junos "no rule matched"
behavior, not a fail-open. Aligns with merged #4519/#4520/#4542/#2291/#2240/
#2241/#4339. No action.

---

## Bottom line

This re-audit is clean and disciplined. ps-028 remains correct that the NAT
*forwarding/security* core has no fail-open residuals; the two negatives here
re-prove the exhaustion + fragment paths are fail-closed against the newer
#4381/#4518/#4519/#4520 changes. The **one novel actionable item** is **M-01**:
deterministic (CGNAT) NAT is parse-complete + commit-clean + BPF-compiled but
absent from the userspace-dp runtime — a silent no-op parity/compliance gap,
Medium, untracked, distinct from the CLOSED parse fix #3864 and not covered by
#4512 or any merged NAT PR. Recommend filing (implement-or-gate + doc
reconciliation). No security fail-open, no HIGH/CRITICAL, no confabulation.
