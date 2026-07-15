# Triage result — ps-review-035 (all-cohort SYNTHESIS roll-up)

## Header
- **Review**: ps-review-035, "xpf firewall deep security audit — all-cohort
  synthesis". A SYNTHESIS/roll-up across 14 cohorts + 9 parallel agents. Not a
  fresh discrete-finding review; a coverage/dedup summary. **Snapshot is
  truncated at §4** (125 lines) — the detailed §5 (findings) and §6 (deterministic
  NAT NEW) bodies referenced in the text are NOT in this snapshot, so only what
  §4's cohort inventory surfaces is triageable here.
- **Review base**: 8cd816e35 (Merge #4545). Delta from prior audit base b1bd96fb6
  is only #4540/#4541 (both LOW, both merged). ≈ current master.
- **Master triaged against**: `6b46d78d51ff4700e31537d85a2d5b778fdeb4b0` (fetched).
- **Real bpfrx or avacado?**: REAL bpfrx. Every cited symbol resolved on
  origin/master (navigatePath@ast.go, auth.go const-time path, ast_format.go
  callers, the cohort issue set). No avacado-fork tells (no nftables
  host-inbound, no /home/ps/git/xpf path, correct Rust userspace-dp module map).
- **Outcome counts**: 1 NOVEL GENUINE-RESIDUAL (LOW, display-only) · 8 DUP of
  this-session/older issues · 4 ALREADY-FIXED (merged this session or earlier) ·
  3 NOT-MATERIAL/refuted · rest NEGATIVE (per-cohort "No new High/Med").
  **Of the substantive items, ~8 are DUPs of already-filed session issues** —
  as predicted for a synthesis roll-up.

## Nature of this file
A synthesis DUPs the per-cohort findings by design. Its only unique value is a
**cross-cutting finding no single cohort surfaced**. I focused verification there.
Exactly one item is flagged NEW by the synthesis itself and survives verification
as a genuine (LOW) residual: **cohort-14 H-01 navigatePath intermediate multi-key**.
Everything else is a restatement of an already-tracked issue or a verified negative.

---

## NOVEL GENUINE-RESIDUAL (the synthesis's cross-cutting value)

### N-1 — navigatePath intermediate multi-key node descends into first match only → scoped `show configuration` / `| display set` can omit config living in a duplicate context block
- **Disposition**: GENUINE-RESIDUAL, **LOW**. NOT a dup — no existing issue
  mentions the intermediate branch; #3980 (CLOSED) fixed only the *terminal*
  single-key case; the multi-key *terminal* case was fixed in 3de2705d7. This
  intermediate residual is the display-side sibling of the #3980/#3842/#2419
  "read-all-siblings" class, un-filed.
- **File:line (current master)**: `pkg/config/ast.go:211` — in the multi-key
  match branch, when the path is NOT terminal at the multi-key node:
  ```
  i += consumed
  if i >= len(path) { return matched }   // ast.go:209 — terminal: returns ALL matches
  current = matched[0].Children          // ast.go:211 — INTERMEDIATE: first match only
  continue
  ```
  When `matched` has >1 sibling sharing the same full multi-key prefix and the
  display path continues deeper, only `matched[0]`'s children are walked; the
  other siblings' subtrees are dropped. (The single-key intermediate branch at
  ast.go:242 has the same first-only `break` — same class.)
- **Callers / blast radius**: navigatePath is **display-only**. All 5 callers are
  in `pkg/config/ast_format.go` (lines 39/155/185/446/473 — `show configuration
  <path>`, `| display set`, display-inheritance). The COMPILER reads the full
  AST directly and never calls navigatePath, so **enforcement is unaffected** —
  a policy hidden from a scoped display is still compiled and enforced. This is an
  observability / backup-completeness lie, not a forwarding/security bypass. Same
  failure MODE #3980 called out: a *scoped* `| display set` backup could silently
  drop the hidden statement on restore.
- **Scenario (specific input → wrong output)**: a hand-authored HIERARCHICAL
  config with two genuinely duplicate context blocks, e.g.
  `security policies { from-zone untrust to-zone trust { policy A } from-zone
  untrust to-zone trust { policy B } }` → two sibling nodes with identical 4-key
  `["from-zone","untrust","to-zone","trust"]`. Then
  `show configuration security policies from-zone untrust to-zone trust policy B`
  (a path that descends PAST the 4-key node) matches both siblings, sets
  `current = matched[0].Children` (the block holding policy A), and policy B is
  never found → the scoped display / display-set omits it.
- **Severity justification — LOW (not the "Med observability lie" the synthesis
  hedged as "NEW?")**:
  - *Exploitability/trigger*: not attacker-reachable. Requires (a) a local
    operator to have authored duplicate identical multi-key context blocks in
    HIERARCHICAL syntax — flat-set `SetPath` MERGES same-key containers into one
    node, so the flat-set path never produces the duplicate siblings — AND (b) a
    scoped display path that goes THROUGH the multi-key node into a deeper leaf.
  - *Blast radius*: one display/backup rendering path; the omitted statement is
    still enforced. Fails toward UNDER-showing (config present but not printed),
    the benign direction — no traffic that should drop passes.
  - *Bounding factors*: an UNSCOPED `show configuration` (empty/short path)
    renders the whole tree and is unaffected — so the full-config backup is
    intact; only a path-scoped display-set is at risk. Junos/xpf normally present
    a single merged context, so duplicate identical 4-key siblings are an unusual
    hand-authored shape.
  - *Why not higher*: no enforcement impact and no remote/unauth trigger; needs a
    rare hand-authored duplicate-context precondition. *Why not lower/dismiss*: it
    is a real residual in an already-recognized bug class (#3980 fixed the
    terminal cases but left the intermediate descent first-only), and the harm —
    a scoped display-set backup dropping a real policy on restore — is the exact
    harm #3980 was filed to stop. Worth an issue; LOW priority.
- **Fix sketch**: in the intermediate branch, accumulate children across ALL
  `matched` siblings (`current = append(matched[0].Children, matched[1:]...
  .Children)` conceptually) instead of `matched[0].Children`; mirror for the
  single-key intermediate branch at ast.go:242. Same pattern as #3980's terminal
  fix, applied to the descent.

---

## DUP of already-filed / merged session issues (no new trace)

| Cohort item | Disposition | Why (issue + proof) |
|---|---|---|
| C5 "deterministic NAT unenforced (CGNAT), see §6" | **DUP #4559** (OPEN) | Title verbatim: "nat: deterministic NAT (CGNAT port block-size) validated+committed but silently unenforced on userspace dataplane (ps-034 M-01)". The §6 NEW that the snapshot advertises is exactly #4559, already filed this session. (Parser side #3864 CLOSED — parse-only, not enforcement — the synthesis correctly distinguishes.) |
| C13 "M-01 rollback n=0 MED hardening" | **DUP #4556** (OPEN) | #4556 "cli/api/config: 3 LOW hardening residuals (rollback n=0 message+gRPC, monitor-filter quote-strip, validateMultiValueLeaf 'to'-gate) (ps-034)". Synthesis's own note says "not new". |
| C14 "validateMultiValueLeaf 'to'-gate" | **DUP #4556** (OPEN) | Same #4556 bundle, listed item 3. |
| C6/C7 "S-001 / V-01 bare 5-tuple session" | **DUP #2387** (OPEN) | #2387 "session/flow identity is the bare 5-tuple — omits logical ingress (VLAN/zone/VRF)". Synthesis explicitly maps S-001→#2387. |
| C7 "M-02 XDP EH 6vs8 LOW perf" | **DUP #4555** (OPEN) | #4555 "MAX_EXT_HDRS=6 vs MAX_IPV6_EXT_HEADERS=8 — 7+ EH IPv6 flow misses XDP fast path (ps-030 M-02)". Fail-CLOSED parity, low. |
| C10 "IPIP decap no zone enforcement" | **DUP #4478** (OPEN) | #4478 "IPIP (proto-4/41) decap has no userspace zone enforcement (fail-open, parallel to GRE)". |
| C10 "FRR sanitize / Origin" | **DUP #4498** (OPEN) | #4498 "FRR sanitize-belt residual + #4482 test completeness". |
| C9/C11 "0 novel — WG/IPsec/VRRP/HA hardening" | **DUP #4546/#4547/#4548(#4552)/#4549(#4558)** | Synthesis explicitly maps each: #4546 (WG rekey, MERGED), #4547 (dyn-hostname DNS), #4548/#4552 (VRRP MaxAdverInt clamp), #4549/#4558 (4 crypto/HA LOW). All filed this session. |

## ALREADY-FIXED (merged this session or earlier — synthesis lists them as CLOSED, verified against master)

| Cohort item | Disposition | Proof symbol/PR |
|---|---|---|
| C13 "13-01 Basic-auth timing STILL PRESENT? Verify" | **ALREADY-FIXED #4157** | The synthesis hedged with "Verify"; verification REFUTES a live bug. `pkg/api/auth.go:82` compares the Basic-auth password via `subtle.ConstantTimeCompare(...)==1`; the API-key path OR-s per-key `subtle.ConstantTimeCompare` results (auth.go:110-112). Dedicated regression test `pkg/api/auth_consttime_4157_test.go` present. #4157 (CLOSED) "auth uses non-constant-time comparison" is the fix. No timing side channel remains → not a residual. |
| C6/C7 "flow-cache NAT reuse (Med)" | **ALREADY-FIXED #3776** | #3776 (CLOSED) "session expiry/removal does not invalidate the cache — stale-descriptor forward + released-SNAT reuse". Synthesis itself notes "N-01 flow-cache NAT reuse already FIXED #3776". |
| C4 "S-03 IPv4 options TLV break-on-malformed" | **ALREADY-FIXED #4543** (CLOSED this session) | Screen source-route walk fix merged. |
| C3 "H-01 duplicate host-inbound-traffic block loses tokens" | **ALREADY-FIXED #4544** (CLOSED this session) | load-override dup-block token loss merged. |
| C13 "M-02 writeJSON" / "L-01 monitor keyword" | **ALREADY-FIXED #4541 / #4540** | Both in base delta b1bd96fb6→8cd816e35, MERGED. |
| C6 "S-003/S-004 PSH DoS (partially #4539)" | **ALREADY-FIXED #4539** (CLOSED this session) | should_cache_local_delivery non-handshake TCP caching hardened. |

## NOT-MATERIAL / refuted

| Cohort item | Disposition | Disproving mechanism |
|---|---|---|
| C12 "H-01 DHCP quote bypass (defense-in-depth)" | **NOT-MATERIAL** | Synthesis itself: "not exploitable, `--` holds". tcpdump/monitor arg injection is gated by the `--` separator; related root-file-write vector already closed by #4524 (MERGED). Belt-and-suspenders LOW, not a live bypass. |
| C7 "H-02 tiny fragment" | **NOT-MATERIAL / NEGATIVE** | Synthesis: "NOT exploitable". No trace of a fail-open in the snapshot; recorded as a verified negative. |
| C2 "NEW-01, NEW-02 config (2 Low)" | **NOT-MATERIAL** | Synthesis's OWN triage marked both "NOT-MATERIAL/dup per triage". No §5 body in the snapshot to re-derive a concrete input→wrong-output; nothing to file. If §5 detail surfaces later it can be re-triaged, but on the visible evidence there is no material claim. |
| C6 "S-002 STILL PRESENT (Med DoS)" | **KNOWN-RESIDUAL (carry-over), not novel** | Labeled "STILL PRESENT" (previously identified, already tracked), not "NEW". No §6 detail in the snapshot to pin the exact symbol; falls in the session-table/5-tuple DoS class already tracked by #2387 / #4539. Not a synthesis-unique finding; flagged here for completeness but not fileable without the truncated §6 body. |

## NEGATIVE (verified-correct cohorts)
Cohorts 1 (policy, 23 negatives), 8 (filters/PBR — "No NEW High/Med, all verified
fixed/already filed"), 9 (IPsec/WG — "0 NOVEL"), 11 (HA/cluster — "0 NOVEL")
report clean. Consistent with this session's prior per-cohort triage. Nothing to
file.

## Method note
- Base FRESH (≈ current master; 2-commit LOW delta). Snapshot is a synthesis and
  is **truncated at §4** — I could not read the §5/§6 detail bodies, so items that
  live only there (S-002 exact symbol, the "3 known/residual" NAT items) are
  triaged from the §4 inventory labels alone. This is a limitation of the
  snapshot, not the codebase.
- Weight-verify: the ONE synthesis-flagged NEW (navigatePath intermediate) is
  genuine but LOW after tracing callers (display-only) and reproducibility
  (needs hierarchical duplicate contexts; flat-set merges). The synthesis's other
  self-flagged uncertainty ("basic-auth timing STILL PRESENT? Verify") is REFUTED
  by const-time code on master (#4157) — the hedge was appropriate and the
  answer is: fixed.
- No CONFABULATIONS: every cited symbol exists on origin/master.
- Over/under-scoping: the synthesis over-hedged navigatePath as "Med NEW?"; LOW
  is correct (display-only, no enforcement impact, rare precondition).
