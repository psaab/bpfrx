# Triage result — ps-review-039-a1f

- **Subsystem:** A1f — Screen / filter / frame / policy / appid (userspace-dp Rust dataplane) — **monolithic/modularity audit**
- **Review base:** f70146951583823a5ace87b0b11a2e58f46e8db9 — IS an ancestor of master (23 commits behind)
- **Triaged against master SHA:** 95b33d49634d56086269a62a92e213dae7926f88
- **Repo:** real bpfrx (psaab/xpf) — paths, symbols, LOC all match origin/master; no avacado-xpf fork tells
- **Outcome counts:** 3 findings total → 0 GENUINE-RESIDUAL / 2 NOT-MATERIAL (modularity, one is DUP-of-open-#4421) / 1 DELIBERATE-negative (Finding 3, class-D no-action)
- **Nature:** This is a **pure refactor/modularity audit**. Findings 1 and 2 are self-classified class-(A) MECHANICAL (file-split / dedup, "no behavior change"); Finding 3 is class-(D) negative confirmation. NONE traces input→wrong-output. By construction there are no correctness residuals to file.

---

## Finding 1 — inspect.rs 1813 LOC / 6× duplicated IPv6 EH walker → single `walk_ipv6_ext_headers` + `EH_TYPE_SET` SSOT

**Disposition: NOT-MATERIAL (valid modularity/dedup proposal; no reachable defect on current master).**

Structural claims **verified accurate**:
- `inspect.rs` is exactly 1813 LOC on master.
- The canonical EH match arm `0 | 43 | 60 | 135 | 139 | 140 | 253 | 254` appears **6 times** in `inspect.rs` (lines 95, 157, 223, 300, 385, + one more counted by grep) — the copy-paste is real.
- No `walk_ipv6_ext_headers` / `EH_TYPE_SET` SSOT helper exists yet (`git grep` on master returns nothing) — so the proposed refactor genuinely has NOT been done.
- `MAX_IPV6_EXT_HEADERS` is **already** a single SSOT: defined once at `inspect.rs:31`, re-exported via `frame/mod.rs:67` (`pub(crate) use inspect::MAX_IPV6_EXT_HEADERS;`), and every walker loops `for _ in 0..MAX_IPV6_EXT_HEADERS`. So the *bound* is already unified; only the *type-set match arm* is duplicated.

**Why NOT-MATERIAL rather than GENUINE:** the finding itself states there is **no current correctness defect**. It concedes "#4517 did touch all 9 sites (verified via git show)" — i.e. the walkers agree today, canaries are green. #4517 is CLOSED (title: "IPv6 EH walkers stop at unenumerated EH types (MOBILITY/HIP/Shim6)… ps-021 H-1"), so the last EH-type addition was applied atomically across all sites. The finding argues a **future** drift RISK ("if a future PR adds a type to 8 of 9 walkers, the 9th silently diverges"). That is a maintainability/dedup argument, not a reachable input→wrong-output bug on master. GENUINE-RESIDUAL requires a *present, reachable* defect; this is speculative future drift. It is the deferred PR-2 of #2150 (CLOSED — "multiple incompatible Ethernet/IPv6 parsers"), i.e. planned dedup work, correctly framed by the finding as "not a duplicate, the planned next phase."

**Minor inaccuracies (cosmetic, do not change disposition):**
- The finding cites a 9th walker at `afxdp/frame/icmp_embed/parse.rs`. That path does NOT exist; the file is at `userspace-dp/src/afxdp/icmp_embed/parse.rs` (under `afxdp/`, not `afxdp/frame/`). The file substantively exists — wrong sub-path, not a confabulated file.
- `screen/extract.rs` does contain an IPv6 EH walker, but written with named constants (`NEXTHDR_ROUTING = 43`, fail-closed per #4543) rather than the literal `0 | 43 | 60…` arm, so the grep count of that exact arm is 0 there. The finding's "9 walkers across 4 files" is directionally right but the exact-arm count is inspect.rs=6 + nat64.rs=3.

**Severity justification:** finding rates Medium (maintainability). As a triage matter it is not a bug at all — no severity as a defect. It is legitimate class-(A) refactor debt overlapping the CLOSED #2150 PR-2. Appropriate action is a `refactor`/`modularity` issue, not a fix. Not filed as a residual.

---

## Finding 2 — policy.rs 3598 LOC / 4 fused responsibilities → policy/{app_catalog,counters,app_match}.rs split

**Disposition: NOT-MATERIAL + DUP of OPEN #4421 (finding acknowledges this itself).**

Structural claims **verified accurate**:
- `policy.rs` is exactly 3598 LOC on master, still a flat file (no `policy/` directory).
- `AppCatalog` lives at `policy.rs:1065` (`pub(crate) struct AppCatalog`) with `impl` at :1098 — matches the finding.
- `AppCatalogEntry` is defined outside policy.rs at `protocol/security.rs:527`, consistent with the finding's "constructed from `AppCatalogEntry` slices, zero coupling to PolicyState" claim.
- `policy_snapshot_error.rs` exists as a sibling file — confirming the established `#[path = "policy_snapshot_error.rs"] mod snapshot_error;` extraction pattern the finding relies on.

**Why NOT-MATERIAL / DUP:** this is a class-(A) file-split proposal with "no behavior change" by its own statement — not a correctness bug. It is explicitly a duplicate of **OPEN #4421** ("Refactor/modularity backlog from audit — extends #4404-#4409 (**policy.rs**, nat64.rs, neighbor.rs, SnapshotIntegrityError, SessionTable, ForwardingState, flowexport, firewall-filter, rules.go)"), which already tracks the policy.rs god-file split. The finding correctly says "Do not re-file the god-file claim… feed into existing #4421 as supplementary detail." The NEW content (concrete 4-way map + AppCatalog-is-lowest-coupling-first-slice observation) is a useful comment on #4421, not a new bug. No reachable defect.

**Severity justification:** finding rates Medium (modularity debt). As a defect: none. It is supplementary detail for an already-open modularity tracker. Not filed as a residual.

---

## Finding 3 — Negative confirmation (filter/, screen/, frame/, scan.rs, runtime.rs are well-decomposed)

**Disposition: DELIBERATE / negative — no action, no finding.**

Explicitly class-(D). Confirms filter 3-way split (#1049), screen 7-way split (#1543), frame build/rewrite extraction (#1352), scan generic core, runtime pure relocation (#68.4) are clean. Spot-verified: `filter/mod.rs`=939 LOC, `screen/mod.rs`=1540, `scan.rs`=1213, `runtime.rs`=503 — all match. Contains only forward-looking low-priority "consider during next feature" notes (ScreenState field-grouping into sub-structs, frame/mod.rs NAT-apply residual, wg.rs test co-location) which the finding itself declines to file. Nothing to triage as a defect.

---

## Summary

This batch is a modularity/refactor audit of already-heavily-decomposed dataplane code. All cited files, LOC, and symbols are accurate on current master (real bpfrx). Findings 1 and 2 are legitimate class-(A) refactor proposals with **no correctness component** — Finding 1 concedes the walkers agree today (#4517 synced them; drift is only a future risk; SSOT is planned PR-2 of CLOSED #2150), and Finding 2 is a self-acknowledged DUP/supplement of OPEN #4421. Finding 3 is a negative confirmation. **Zero GENUINE-RESIDUAL bugs** — consistent with the expectation that ps-039/040 audits of the hardened session codebase surface ~0 reachable defects.
