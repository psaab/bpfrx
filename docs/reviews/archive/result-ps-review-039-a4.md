# Triage result — ps-review-039-a4

- **Subsystem**: Go dataplane + daemon + cluster + routing — monolith/modularity audit (Batch A4)
- **Review base**: f70146951583823a5ace87b0b11a2e58f46e8db9 (ANCESTOR of current master, 23 commits behind)
- **Current master SHA**: 95b33d49634d56086269a62a92e213dae7926f88
- **Repo**: real bpfrx (`git@github.com:psaab/xpf.git`) — NOT the avacado-xpf fork
- **Nature of review**: This is a *file-size / modularity* audit only. Every finding is a
  "this file is a monolith, split it" refactor recommendation. There are **zero correctness
  claims that survive** (the one embedded deadlock hint in F-039-02 is a documented NON-bug).

## Outcome counts

- GENUINE-RESIDUAL (correctness): **0**
- NOT-MATERIAL (real, novel, file-worthy tech-debt / no failure scenario): **5** (F-039-01..05)
- Negatives authored by the reviewer (keep-as-is verdicts, no action): **3** (D-01, D-02, D-03)
- ALREADY-FIXED / DUP / CONFABULATED: **0**

**Every factual claim in the review verified TRUE on current master.** The findings are accurate
and not dup — but they are tech-debt reviewability items, not correctness residuals, so none
belong in the correctness-residual output. They are legitimately file-worthy as `refactor` issues
alongside the existing modularity backlog (#4421, #4404-#4409, #4651-#4671) — NOT dismissed.

---

## Per-finding disposition

### F-039-01 — `protocol.go` 2979→3011 LOC wire-format monolith → NOT-MATERIAL (accurate tech-debt)
- **Exists?** YES. `pkg/dataplane/userspace/protocol.go` = 3011 LOC on master (grew from the
  cited 2979). `grep -c '^type'` = **78** (review said 72; grew). Not confabulated.
- **Already-fixed?** NO — file not split; larger than when reviewed.
- **Dup?** NO — `#4421` modularity backlog lists policy.rs/nat64.rs/neighbor.rs/flowexport/
  rules.go etc., NOT `protocol.go`. `gh issue list --search "protocol.go in:title"` = 0 open.
- **Why NOT-MATERIAL (not a residual):** pure code-motion refactor. No input produces wrong
  output — the JSON wire format is unchanged, the file is just large. Severity is
  reviewability/merge-conflict only (the reviewer itself rates it Medium, cold-path). There is no
  failure scenario to trace, so it cannot be a correctness residual. File-worthy as a `refactor`
  issue; belongs to the #4421 family.

### F-039-02 — `sync_conn.go` 1858 LOC HA-sync monolith (rated HIGH) → NOT-MATERIAL; embedded deadlock claim is a NON-bug
- **Exists?** YES. `pkg/cluster/sync_conn.go` = 1858 LOC on master. `handleDisconnect` at
  line 1717. Not confabulated.
- **Already-fixed / dup?** NO split; not filed.
- **The one concrete correctness claim — refuted on master.** The review says (F-039-02 "Why it
  matters"): *"handleDisconnect bulk re-drive holds s.mu while spawning goroutine that re-locks
  s.mu via getActiveConn inside doBulkSync — deadlock risk is invisible."* Read of
  `sync_conn.go:1809-1857` shows this is **explicitly and correctly handled**:
  - The re-drive is deliberately a **goroutine** (`go func(){...}` at line 1835), with the
    load-bearing comment at lines 1825-1830: *"This MUST be a goroutine, not inline:
    handleDisconnect holds s.mu, and doBulkSync -> BulkSync/sendBulkMarkers -> getActiveConn
    re-locks s.mu (self-deadlock if run inline)."*
  - A `bulkRedriveInFlight.CompareAndSwap(false,true)` gate (line 1831) bounds re-drives to one
    in-flight, preventing a flap storm; the flag resets on goroutine return (line 1837).
  - The #4090/#4360 outbound-bulk-acked re-check (lines 1844-1846) is present.
  So there is **no actual deadlock** — the code does exactly what the review's own text admits is
  correct. The review's HIGH rating is an assessment of *refactor importance / review difficulty*
  ("hard to see if there's a bug when the file is one unit"), NOT a confirmed correctness residual.
  It does not assert a live bug; it asserts the monolith makes the (correct) invariant hard to
  verify.
- **Why NOT-MATERIAL:** pure code-motion refactor with an ordering caveat; the gen-guard
  (#2170/#2221/#2198/#2995) and #4090/#4360 re-drive invariants are intact on master. No failure
  scenario. File-worthy as a `refactor`/`ha` issue, but not a correctness residual.

### F-039-03 — `tunnel.go` 1877→1889 LOC (5 responsibilities) → NOT-MATERIAL (accurate tech-debt)
- **Exists?** YES. `pkg/routing/tunnel.go` = 1889 LOC (review said 1877; grew). Not confabulated.
- **Already-fixed / dup?** NO split; `#4421` mentions `rules.go`, not `tunnel.go`. 0 open issues.
- **Why NOT-MATERIAL:** cold-path (commit + keepalive tick) code-motion. Keepalive lock-free
  discipline and #1884/#1918/#1919/#4071 invariants are correctness properties that already hold;
  the finding only argues the file is large. No wrong-output scenario. File-worthy as `refactor`.

### F-039-04 — `compiler_validate_warn.go` 3330 LOC warn-validator monolith → NOT-MATERIAL (accurate; asymmetry real)
- **Exists?** YES. 3330 LOC on master, `grep -c '^func'` = **35** (matches review). Not confabulated.
- **Load-bearing asymmetry claim VERIFIED:** the strict counterpart IS already split — master has
  `compiler_validate_strict.go` + 12 per-domain files (application/chassis/cos/filter/ipsec/nat/
  observability/policy/routing/screen/vrrp/zones) + vrf_overlap + wireguard. So the review's core
  argument ("warn is the only validator file that never followed the strict per-domain split") is
  factually correct.
- **Already-fixed / dup?** NO split; 0 open issues; distinct from #4421.
- **Why NOT-MATERIAL:** `ValidateConfig` returns `[]string` warnings, pure functions, cold-path
  (commit-time). Splitting is byte-identical code-motion. No correctness impact / no failure
  scenario. File-worthy as `refactor`/`config`; strong candidate (proven split template exists).

### F-039-05 — `metrics_descriptors.go` 1896 LOC Prometheus descriptor monolith → NOT-MATERIAL (accurate tech-debt)
- **Exists?** YES. 1896 LOC on master; `grep -c prometheus.NewDesc` = **279** (matches review
  exactly). Not confabulated.
- **Already-fixed / dup?** NO split; 0 open issues.
- **Why NOT-MATERIAL:** `newCollector` runs once at daemon start; scrape reads pre-built
  descriptors. Pure allocation, cold-path, no logic. Reviewability/merge-conflict only. No failure
  scenario. Lowest-risk of the five; file-worthy as `refactor`/`metrics`.

### D-01 / D-02 / D-03 — reviewer's own NEGATIVES → no action
- **D-01 `maps_sync.go` 1763 LOC** — reviewer verdict "single responsibility, keep." Concurred;
  not a split candidate. No action.
- **D-02 `vrrp/instance.go` 2417 LOC** — reviewer verdict "single coherent VRRP RFC5798 SM, keep
  (single-goroutine run-loop owns all timers+mu); revisit only past ~2800 LOC." Concurred; the SM
  cohesion is a correctness property worth preserving. No action.
- **D-03 `daemon_run.go` 2329 + `daemon_apply.go` 1935** — reviewer verdict "already filed #4407,
  do not double-file." Concurred. No action.

---

## Summary reasoning

This batch is a modularity/reviewability audit, and it is a *good* one — every LOC count, type
count, func count, and the strict-vs-warn asymmetry check out against current master, and the
dedup claims are accurate (none of the 5 files appear in the existing #4421/#4404-#4409/#4651-#4671
refactor backlog). But the entire file contains **no correctness bug**. The single sentence that
reads like a correctness claim (the `handleDisconnect` self-deadlock in F-039-02) is explicitly
refuted by the code: master deliberately spawns the re-drive as a CAS-guarded goroutine precisely
to avoid the s.mu self-deadlock, with a comment saying so, and the #4090/#4360 fixes present.

Therefore **0 genuine correctness residuals**. The 5 findings are real, novel, non-dup tech-debt
items that should be *filed* as `refactor` issues (per the review-watcher never-dismiss discipline)
into the same modularity backlog family as #4421 — but they carry no failure scenario and do not
belong in the correctness-residual output.
