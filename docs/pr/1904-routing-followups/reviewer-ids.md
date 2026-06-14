# PR #1910 reviewer ledger (#1904 + #1905)

r1 head: 197e37eea0f2 → r2 head: aa46509aa615 → r3 head: 5f0e43b9b4c2
→ r4/final head: 3b36ead01

| Reviewer | Round | Task id | Verdict |
|----------|-------|---------|---------|
| Claude SMR (in-conversation) | r1 | n/a | MERGE-READY at r1 head; identified the interface-level+per-unit coexistence edge but misjudged it consistent-by-design — Codex/AGY correctly rated it High (wrong device for a valid config); concur with fix aa46509aa |
| Codex | r1 | task-mqbdlnod-rx72uu (session 019ebd82-d232-7e63-8e10-9f1cc39c5ecd) | High: TunnelNameMap shadowing (coexistence) + WG Source-empty gate; #1905 audit clean |
| AGY | r1 | adversarial-review-mqbdlvjb-0ifg9r | Same two High findings (independent convergence); #1905 + scope decision verified correct |
| Copilot | r1 | n/a | quota-limited ×3 responses; documented retries 20:24Z, 20:28Z, 20:38Z |
| AGY | r2 | adversarial-review-mqbe30yw-bt0iqy | MERGE-READY at aa46509aa — both r1 Highs resolved for all consumers; #1905 re-PASS. Missed the duplicate-WG-endpoint hazard Codex r2 found |
| Codex | r2 | (session-state lost to runtime churn; re-dispatched under flock, result /tmp/codex-1910-r2-result.md) | NEEDS-CHANGES — High: interface-level WG with multiple units now emits duplicate LIVE userspace endpoints (same ifindex + listen port; pre-fix the wg0.1 row was inert at ifindex 0, dropped by the Go ifaceByName gate AND the Rust populate gate tunnels.rs:17); Rust by_ifindex overwrite + second control thread tombstones on duplicate UDP bind → possible WG blackhole. Fixed in 5f0e43b9b |
| AGY | r3 | adversarial-review-mqbeq0a7-dug6y6 | MERGE-READY at 5f0e43b9b — duplicate-endpoint closure, single-unit-0 byte-identity, consumers (manager_ha.go:854, maps_sync.go:1551, Rust populate) verified. Missed the collision-gate mismatch Codex r3 found |
| Codex | r3 | (flocked inline run, result /tmp/codex-1910-r3-result.md) | NEEDS-CHANGES — Medium: collectTunnelEndpointNamesAST still registered every unit ref of interface-level WG, modeling never-published ids; verified counter-example StableTunnelEndpointID("wg0.1")==("wg341")==14730 falsely rejects commit. Fixed in 3b36ead01 (gate mirrors lowest-numeric-unit pick; builder made config-deterministic per Codex's own next-step) |
| Claude SMR (in-conversation) | r2-r4 | n/a | Hostile-verified Codex r2 High end-to-end before acting (tunnels.rs:17 pre-fix inertness, wg_control.rs:119-128 tombstone); caught that the r3 interim runtime-row fallthrough violated #1873 id purity across HA nodes (folded into 3b36ead01); flat-set mode-extraction shape proven by the new gate tests themselves; MERGE-READY at 3b36ead01 |
| Codex | r4 | (flocked, result /tmp/codex-1910-r4-result.md) | NEEDS-CHANGES — High: leading-zero unit spelling (`unit 01`) hashed raw "wg0.01" instead of the canonical emitted "wg0.1". Fixed in 3a85ba783 (WG-branch canonical %d) |
| AGY | r4 | adversarial-review-mqbf3gv8-jkroid | never ran — dispatch died with the lane agent (spend limit); no job files. Superseded by final-head round below |
| Codex | r5 | (raw-exec, result /tmp/codex-1910-r5-result.md) | NEEDS-CHANGES — High: overflow-only WG unit spellings made the gate hash raw refs while the builder emits the BARE interface ref (iface.Units empty); frozen counterexample wg0/wg34524.0 == 17799 bypasses strict gate. Fixed by making the whole collector parse-gated + canonical (bare-ref registration when no unit parses; "%s.%d" everywhere — also closes the same raw-spelling divergence on the non-WG and unit-level branches) |
| Copilot | r2 | n/a | re-requested at 5f0e43b9b after 4 documented quota failures (3-of-4 fallback armed) |
| AGY | r5 (final-head) | adversarial-review-mqbj4707-n2ww5r | MERGE-READY at 8ad6e8e0f — frozen fold untouched, regressions + constants verified, builder runtime-state decoupling confirmed, no false rejects on common shapes |
| Codex | r6 | task-mqbj3z8o-povvai (session 019ebe0f-fb8b-7900-bcfd-d8d7ad087d4a) | MERGE-NEEDS-MAJOR at 8ad6e8e0f — (a) duplicate unit spellings: gate sticky-OR vs compiler last-wins overwrite (REAL, fixed next commit: overwrite semantics + TestTunnelEndpointIDDuplicateUnitSpellingLastWins); (b) wildcard apply-groups hashed literally → false accept (REAL but PRE-EXISTING since #1873 pre-expansion union design; this PR never touched it; runtime usedIDs belt catches loudly; filed #1914 with verified folds <*>.0=50477, wg78.0=wg1408.0=824); (c) src/dst-incomplete non-WG over-registration (PRE-EXISTING conservative-by-design — AST collector cannot judge src/dst because groups expansion can supply them; folded into #1914) |

Live validation: 10/10 PASS on the loss userspace cluster, build
2443-gcd8b784dc (documented in the PR body): #1904 unit>0 member binds
the real uN device (`gr-0-0-1u1 master vrf-vrf1904`); #1905 configured
fe80 reconciles away while foreign + kernel stable-privacy fe80
survive. The post-r2 commits (5f0e43b9b, 3b36ead01) change
interface-level multi-unit WG endpoint emission + the commit gate only
— covered by unit regressions; the live scenarios exercise neither
shape.

## Convergence (final head 149d6fd1a)
- Codex r7: task-mqbjev0d-ryo6ej (session 019ebe17-b8b9-7720-9c3e-c09c5c32b791) — MERGE-READY, no findings; (a) fix verified against compiler_interfaces.go:203/:646 + tunnels.go:143; regression non-vacuous; (b)/(c) pre-existing adjudication ACCEPTED with origin/master gate-code verification; no new divergence
- AGY delta: adversarial-review-mqbjf0kt-fv6c7w — ready to merge; sticky-OR→overwrite proven non-vacuous both directions; r4 canonical + r5 bare-ref behaviors intact
- Claude SMR: MERGE-READY at 149d6fd1a (in-conversation; independently verified compiler overwrite, expansion ordering, and all frozen folds incl. #1914 repro values)
- Copilot: quota-blocked, documented retries (r1 ×3, r2 ×4) → 3-of-4 fallback per protocol
- Gates: full go test ./... rc=0 at 149d6fd1a (Go-only PR, 0 Rust files)
- Follow-up: #1914 (pre-existing wildcard-groups literal hashing + src/dst over-registration)
