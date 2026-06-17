# #1956 device-map (PR #1959) — reviewer ledger

4-way review: Codex + AGY adversarial + Copilot + Claude SMR.

## Round 1

| Reviewer | Task / session id | Verdict | Disposition |
|----------|-------------------|---------|-------------|
| Claude SMR (in-conversation) | — | found 1 boot-stability bug | Fixed before review dispatch: OriginalName=xpf-tmp-N across temp renames (commit dda981771) |
| AGY adversarial | adversarial-review-mqidx5ad-8qjf39 | 5 findings (2 HIGH, 2 MEDIUM, 1 MINOR) | All fixed (commit 58a9e97b9). Detail: agy-impl-r1.md |
| Codex hostile | session 019ed6c6-55f6-7361-89ea-3da4636619ee | NEEDS-MAJOR (2 HIGH) | All fixed (commit 4e61096b5 + regression c33da5fed). Detail: codex-impl-r1.md |
| Copilot | PR review (copilot-pull-request-reviewer) | 2 inline findings | 1 already-fixed (OriginalName), 1 fixed (MAC-fallback status, commit cc6dd1fba); both replied on-thread |

### R1 findings summary
- AGY HIGH-1: MAC format mismatch (ValidateMAC accepts hyphen/dot, resolver compares colon) -> normalizeMAC in compileDeviceMap.
- AGY HIGH-2: pre-flight used active config's mgmt leaf, not candidate's -> protectedForConfig(cfg).
- AGY MEDIUM-3: temp-rename EEXIST on leftover xpf-tmp-N -> freeTempName().
- AGY MEDIUM-4: non-deterministic multi-port same-PCI -> slice-valued byPCI, ambiguous REFUSE.
- AGY MINOR-5: passive alarm silently bypassed on enumerate failure -> loud warning.
- Codex HIGH-1: topology-change REFUSE bypassable by MAC-first key order -> order-independent pre-check in Resolve().
- Codex HIGH-2: lockout check missed pre-rename steal (mgmt still enp5s0) -> deviceMapStrandsManagement takes lifelineCurrentName.
- Copilot-1: OriginalName=current in current==final branch -> already fixed (SMR).
- Copilot-2: BindBoundViaMAC misreported for MAC-primary entries -> pciTried gate.

## Round 2 (re-review after R1 fixes)

| Reviewer | Task / session id | Verdict |
|----------|-------------------|---------|
| AGY adversarial | adversarial-review-mqieathe-sf3cjh | (pending) |
| Codex hostile | (background agent, session pending) | (pending) |

### R2 verdicts + dispositions
- AGY r2 (adversarial-review-mqieathe-sf3cjh): NEEDS-MAJOR -> after fixes its own re-check said MERGE-READY. 1 CRITICAL: unmapped-mgmt lockout (teardown). Fixed: teardown + scrub skip protected; commit f-block. Detail: agy-impl-r2.md. (AGY wrote a fix into the worktree; reverted per policy and re-implemented with the Codex-r2 cases AGY missed.)
- Codex r2 (session 019ed6cf-d272-7ab0-98b3-fb1009844961): NEEDS-MAJOR. HIGH-A legit-mgmt-remap false reject (Case A rewrite); HIGH-B same-PCI ambiguity bypass under mac key (order-independent pre-check); HIGH-C cross-key same-NIC last-wins (resolver post-pass refuse). All fixed.
- Copilot SWE-agent autonomously pushed 24ec36525 (deriveKernelName fallback for OriginalName= on a fresh box with no prior .link) — a genuine improvement; integrated via rebase.

## Round 3 (re-review after r2 fixes)

| Reviewer | Task / session id | Verdict |
|----------|-------------------|---------|
| AGY adversarial | (pending) | (pending) |
| Codex hostile | (pending) | (pending) |

### R3 verdicts + dispositions
- AGY r3 (adversarial-review-mqiepgva-dkp3qa): NEEDS-MAJOR (reviewed fe798fccb). 1 CRITICAL: networkd.Apply sweep deletes protected mgmt files -> lockout (FIXED: networkd SetProtectedResolver exempts them). MAJOR: deriveKernelName breaks fresh-box ens3 naming (FIXED: deviceMapOriginalNameFor derives only when wearing the logical name). MAJOR B.1: Case C rename collision (FIXED). B.2 absent-lifeline = acceptable per §9.6. Detail: agy-impl-r3.md. All fixed in b083b3445.
- Codex r3: (pending agent return)

### R4 verdicts + dispositions
- Codex r4 (session 019ed6e2-9c63-70d2-a12e-4b26037da5bd): MERGE-READY. Confirmed networkd protected-file preservation, deriveKernelName gating, and CLI order fixes all PASS; no CRITICAL/HIGH (reviewed 4c28cbbda).
- AGY r4 (adversarial-review-mqiezwzh-pv854d): verified deriveKernelName + SetProtectedResolver correct; found CRITICAL false-positive in strand Case C (legit port swap rejected). FIXED by rewriting deviceMapStrandsManagement to two order-free invariants (reachable + no-collision) — commit b6a4eeffa.

## Round 5 (final confirmation on b6a4eeffa)

| Reviewer | Task / session id | Verdict |
|----------|-------------------|---------|
| AGY adversarial | adversarial-review-mqif9rop-046u12 | **MERGE-READY** (all 5 cases a-e verified; topology REFUSE intact) |
| Codex hostile | session 019ed6e2-9c63-70d2-a12e-4b26037da5bd | **MERGE-READY** (all 5 cases a-e PASS; REFUSE short-circuit intact) |

Copilot: 2 inline findings (r1) addressed + Copilot SWE-agent autonomously contributed the deriveKernelName fallback (integrated).

## Convergence: 4-of-4 MERGE-READY
- Codex MERGE-READY (019ed6e2); AGY MERGE-READY (mqif9rop-046u12); Copilot addressed (2 findings + SWE deriveKernelName contribution); Claude SMR MERGE-READY (drove the OriginalName + unified-strand fixes). Final SHA recorded by the engineer run.

## Round 6 (boot-path bug investigation + startup-decision regression test)

Parent flagged a MERGE-BLOCKING bug from a live fresh-VM demo: "device-map
never applies on a normal boot — interfaces stay positional even after
committing a map + rebooting," hypothesised as a stale `ActiveConfig()` read at
`daemon_run.go:348` (active not yet promoted at naming time).

### Investigation outcome — CLAIM REFUTED (no functional bug at HEAD)
- Empirical, on the live `xpf-devmap` VM (snapshot->test->restore):
  - DB-load boot ("configuration loaded from db") -> device-map branch ran,
    "device-map: resolved binding" + renames. WORKS.
  - Bootstrap-from-file boot (device-map placed in `/etc/xpf/xpf.conf`, DB
    wiped) -> device-map branch ran, "device-map: interface naming unchanged".
    WORKS.
  - The ONLY positional boot was the demo's FIRST boot, where `xpf.conf` had no
    device-map and none was committed yet — correct behavior, misread as the bug.
- Code trace (Codex + AGY independently): `Store.Load` sets `s.compiled`
  synchronously (store.go:237-238); `bootstrapFromFile`->`Store.Commit` promotes
  + sets `s.compiled` synchronously (store.go:1101-1105) BEFORE the naming
  decision (`daemon_run.go:241` runs before 348). The "applying active
  configuration" log (611) is the first dataplane APPLY, not the first
  promotion. Bootstrap-exit (`runBootstrapExitStartup`, 1543) takes the
  freshly-committed `cfg` parameter — not a stale read.

### Real gap closed: the missing startup-decision test
The shipped tests exercised `enumerateAndRenameMapped` in isolation, so the
branch SELECTION (the thing that drives boot behavior) was never covered.
Closed across two commits:
- `aa4a9d67d` (Claude): extracted seam `deviceMapNamingActive(cfg)` used at both
  rename sites; predicate + synchronous-promotion regression test.
- `dd610c449` (Copilot SWE agent): centralized the ACTUAL branch into
  `applyStartupNamingPolicy` (single decision site, both boot paths route
  through it) and rewrote the test to STUB `enumerateAndRenameMappedFn` /
  `enumerateAndRenameInterfacesFn` and assert the real mapped-vs-positional
  dispatch (mapped=1/pos=0 for a committed map; mapped=0/pos=1 for
  no-map/empty/nil). This pins the real branch — a drop/inversion inside the
  helper now fails the test. Supersedes Claude's source-level guard (redundant).

| Reviewer | Task / session id | Verdict |
|----------|-------------------|---------|
| Codex hostile | sessions ad42b7d7, a94267060619f3c1f | **MERGE-READY** (seam bit-identical both sites; refutation sound; test gap CLOSED by dd610c449; AGY hidden-risk = pre-existing follow-up) |
| AGY adversarial | adversarial-review-mqiiktwm-5wqzg9 | refutation CORRECT + seam bit-identical; raised test-gap (CLOSED by dd610c449) + Hidden Risk Path (compile-fail+everCommitted -> positional claim-all) |
| Copilot | SWE agent contributed dd610c449 (centralized helper + real-dispatch test) | MERGE-READY (authored the converging fix) |
| Claude SMR | inline | REFUTED-bug; drove seam + investigation; adopted Copilot's stronger helper/test |

### R6 dispositions
- Test-gap (Codex MEDIUM / AGY CRITICAL): CLOSED by dd610c449 —
  `applyStartupNamingPolicy` is the single branch, both sites route through it,
  the test stubs+asserts the real dispatch. Codex re-review confirmed an
  inversion would now fail the test.
- AGY Hidden Risk Path (persisted-DB compile failure with everCommitted=true
  falls back to positional claim-all): adjudicated PRE-EXISTING (predates #1956
  at 5d452736e) and NOT triggerable by a device-map alone (compileTreeLenient
  downgrades device-map errors to warnings, compiler.go:472-474); D1 fail-closed
  is scoped to UNREADABLE DB only. Filed as follow-up issue #1960; NOT a blocker.

## Convergence: MERGE-READY on dd610c449
- Codex MERGE-READY; AGY findings resolved/deferred; Copilot authored the
  converging fix; Claude SMR MERGE-READY. PR stays DRAFT for the user; the
  parent re-runs the live commit->reboot->swap acceptance demo.
