# Triage Result — ps-review-036-cohort5 (Cohort 5: NAT / NAT64 / NPTv6)

**Cohort:** 5 — NAT source/dest/static/allocator, NAT64, NPTv6, Go compiler NAT,
snapshot builders, HA session-sync
**Base in review:** 33b891d11 (claimed == master)
**Verified master SHA:** `33b891d110a98267c67eb272dec8c39c81613501` (origin/master, exact
match — base **IS** current master, NOT stale, NOT avacado)
**Repo confirmed:** real bpfrx (every cited Rust/Go symbol resolves via
`git show origin/master:<path>`; no avacado-fork tells — no redacted templates, no
`/home/ps/git/xpf` paths, no confabulated symbols)
**Pass:** 4th NAT cohort re-audit (after ps-028 Cohort-5, ps-034-NAT, and the merged
NAT PR wave). This is the review AUTHOR's own honestly self-dedup'd report — it filed
**0 HIGH**, and every MEDIUM/LOW carries a dedup note pointing at an existing issue.

## Outcome counts

| Disposition | Count |
|-------------|-------|
| GENUINE-RESIDUAL (novel) | **0** |
| DUP (existing/in-flight issue) | 3 (MEDIUM-01, LOW-01, LOW-03) |
| NOT-MATERIAL / DELIBERATE | 1 (LOW-02) |
| ALREADY-FIXED | 0 |
| CONFABULATED | 0 |
| NEGATIVE (fail-closed / no finding) | HIGH=None + 10 exhaustive negatives |

**Headline: NO novel genuine residual. Nothing to file.** Every actionable item is
already tracked (#4512/#4564 in-flight, #4559 deferred, #2562 deferred) or is a
deliberate/documented invariant. The review is internally consistent with the task's
DEDUP list.

---

## Per-finding disposition

### [HIGH] None — NEGATIVE
The review explicitly states no new fail-open / crash-OOB / leaked-secret in the cohort.
I independently confirmed the fail-closed posture on the paths I sampled (NAT64 empty vs
exhaustion split, NPTv6 host-bits→None, pool-exhaustion→drop). No disagreement. Accepted
as NEGATIVE.

---

### [MEDIUM-01] NAT64 HA standby PortAllocator not reserved → **DUP #4512 / #4564** (in-flight)

**Symbols verified (all EXIST on master):**
- `userspace-dp/src/nat64.rs:211` `struct Nat64ReverseInfo { orig_src_v6, orig_dst_v6 }` — present, stores only original v6 addrs (no translated tuple). ✔
- `userspace-dp/src/nat64.rs:161` `struct Nat64Prefix { … port_allocator: PortAllocator }` (line 180) — per-prefix allocator present. ✔
- `userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:87-94` — reserves ONLY `source_nat_rules`; no nat64 reserve. ✔ (verified full block, lines 80-100)

**Trace independently corroborated.** The forward-reserve asymmetry is REAL on master:
`delete_synced.rs:37` already calls `release_nat64_allocation(&forwarding.nat64, …)` on the
teardown side, but `upsert_synced.rs:88` reserves only `source_nat_rules` — so a synced
NAT64 flow's translated `(pool_v4, port)` is NOT reserved in `forwarding.nat64.prefixes[]
.port_allocator` on the standby. After promotion, a fresh local NAT64 flow can re-claim
that port → two sessions on one `(snat_v4, port)` → v4→v6 reply mis-delivery. The
mechanism is sound (same class as SNAT #4388, which was fixed for `source_nat_rules` only).

**Why DUP, not GENUINE.** This is EXACTLY the in-flight work the task flagged
`do-NOT-dup`:
- Task: "#4564/#4512 (nat64 HA reserve-on-standby, being validated in a failover wave)."
- Master's OWN docstrings name this scope verbatim:
  - `nat64.rs:131`: "The COMPLEMENTARY cross-node HA-failover reservation sync
    (`Nat64ReverseInfo` + reserve-on-standby) is tracked in #4512; this is the same-node
    reload path only."
  - `nat64.rs:334`: "The COMPLEMENTARY HA-failover path — syncing `Nat64ReverseInfo` and
    **reserving the translated port on the standby** so the reservation survives a
    cross-node failover — is tracked separately in #4512."

The review's dedup note tries to slice "#4512 = reverse-translation (orig v6 addrs)" from
"this finding = forward-path allocator reservation." That split is **not valid**: #4512's
own tracked scope, as written in master's code comments, is literally "reserving the
translated port on the standby." There is no residual slice left uncovered — the reserve-
on-standby PortAllocator work IS #4512/#4564, currently being validated in a failover
wave. The same-node half (#4518 `reuse_allocator`) is already merged; the cross-node half
is the in-flight PR. Re-filing would duplicate an open, being-validated issue.

**Severity sanity (if it were novel):** the review's Medium is defensible — post-failover
NAT64 reply mis-delivery / session interleave, but bounded (needs a failover event + a
colliding new local flow landing on the same pool addr + same 16-bit port from a fresh
allocator; NAT64 forward flows are v6→v4 only). Not a fail-open, not a bypass. But this is
moot: DUP of in-flight #4512/#4564. **Do not file.**

---

### [LOW-01] Deterministic NAT (CGNAT) wire gap → **DUP #4559** (full impl deferred)

**Symbols verified (all EXIST):**
- `pkg/config/compiler_validate_warn.go:760-794` — the `#4559 (ps-034 M-01)` advisory
  WARNING ("`port deterministic block-size` … accepted but NOT enforced"). ✔
- `pkg/config/compiler_nat.go:1269-1421` — `applyDeterministicKeys`/`applyDeterministicChildren`
  parse+validate; `types_security.go:728,766-767` `DeterministicNATConfig`. ✔
- `pkg/dataplane/userspace/nat_source.go` — **0** deterministic refs (grep count 0),
  confirming `SourceNATRuleSnapshot` carries no deterministic field. ✔
- `docs/feature-gaps.md:291` — documents "Config-accepted, runtime-inert on userspace
  (#4559) … Full block-allocation enforcement in `userspace-dp` remains a follow-up
  (#4559)." ✔

**Why DUP.** The task states `#4559 → advisory MERGED #4560, full impl deferred`. The
review's own dedup note concedes: "SAME gap as OPEN #4559 … still same issue … Listed for
audit completeness." The "new angle" it claims (Go→Rust snapshot missing the deterministic
field) is not a distinct bug — it is one sub-item of the very "full impl still needed"
scope #4559 already carries (snapshot field + Rust block allocator + metrics). Not a
security bypass — SNAT still occurs, just round-robin instead of deterministic blocks
(compliance/parity gap). **Do not re-file; covered by #4559.**

---

### [LOW-02] Source NAT synthetic protocol==0 `try_next_port` untracked → **NOT-MATERIAL / DELIBERATE**

**Symbols verified (all EXIST):**
- `userspace-dp/src/nat/source.rs:14-17, 1056-1057, 1080-1081, 1137-1138` — the
  `protocol == 0` synthetic "tuple-unknown" sentinel + `try_next_port` gate. ✔
- `userspace-dp/src/nat/allocator.rs:295-309` `try_next_port` — `counter.fetch_add` on
  `shared.counters[addr_index]`, does NOT insert into `owner_by_translated` (line 126/253
  is the tracked insert path, a DIFFERENT function). ✔

**Why NOT-MATERIAL (and DELIBERATE).** I checked the claim that `match_source_nat` (the
only proto==0 caller) is off the forwarding hot path — and it holds, more strongly than the
review stated:
- Its one non-test caller, `match_source_nat_for_flow` (`forwarding/mod.rs:326-345`), is
  annotated `#[cfg_attr(not(test), allow(dead_code))]` — i.e. **dead code in production
  builds**. Every other caller is under `nat/tests_*.rs`.
- The real forwarding path uses `match_source_nat_result_for_tuple` with the real
  `meta.protocol` (6/17/1/58), never 0.
- Even if `try_next_port` returned a port, the frame rewriters gate every L4 write on
  `has_l4_ports(protocol)`, and `has_l4_ports(0) == false`, so proto==0 never writes a port
  to the wire (`source.rs:16-17` documents exactly this invariant).
- `try_next_port` bumps `shared.counters[]` (AtomicU32) which is a DIFFERENT store than the
  Mutex-guarded `live.next_port_offset_by_addr[]` used by the real claim path — no cursor
  alias, no exhaustion (it never inserts an owner, so it can't leak a reservation).

This is a deliberate, comment-documented legacy invariant (`source.rs:8-17`), reachable only
via test/dead-code. It matches the "3 not-material dead-code" outcome ps-028 already
recorded for this cohort. The review itself dispositions it "intentional, not a bug." No
issue to file. **NOT-MATERIAL + DELIBERATE.**

---

### [LOW-03] NAT64 non-first fragment needs stateful cache → **DUP #2562** (deferred, fail-closed)

**Symbols verified (all EXIST):**
- `userspace-dp/src/nat64.rs:1067` `if ipv6_is_non_first_fragment(packet) { return None; }`
  and `:1301` `if v4_offset_units != 0 { return None; }` — both fail-CLOSED (drop). ✔

**Why DUP.** Task/review both track this as OPEN #2562. Non-first fragment carries no L4
header → cannot translate without a first-fragment decision cache → current behavior is a
correct fail-closed drop, NOT a fail-open. Availability/parity gap, deferred. The review
lists it "for audit completeness, not re-filed." **Do not re-file; covered by #2562.**

---

## Negatives (§5, 10 items) — all NEGATIVE, spot-checked

Reviewer's exhaustive fail-closed list (pool exhaustion→drop; NAT64 empty-vs-exhaustion
counter split; NPTv6 host-bits→None; NPTv6 0xFFFF collapse #3233; deterministic advisory
visible; proto==0 never writes port; DNAT-off short-circuit; static prefix-name resolution;
NAT64 same-node reload reuse #4518; EH walkers include mobility/HIP/Shim6 #4517). Sampled
several against master — consistent. No action.

---

## Bottom line

This 4th NAT re-audit surfaced **zero novel genuine residuals**. The single MEDIUM is the
in-flight #4512/#4564 reserve-on-standby (master's own docstrings name it), the two
substantive LOWs are DUPs of #4559 and #2562, and the last LOW is a deliberate dead-code
invariant (matching ps-028's not-material outcome). Base is exact-current master, real
bpfrx, no confabulation, no fail-open. Nothing to file, nothing to drive.
