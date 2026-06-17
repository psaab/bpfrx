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
