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
| AGY adversarial | adversarial-review-mqif9rop-046u12 | (pending) |
| Codex hostile | (final confirm agent) | (pending) |

Copilot: 2 inline findings (r1) addressed + Copilot SWE-agent autonomously contributed the deriveKernelName fallback (integrated).
