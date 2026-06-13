# PR #1906 deployment-UX delta — round-4 reviewer ledger

Delta reviewed: 3e985974b..c9d2ef725 (launcher, examples, runbook) — had
NO prior review (rounds 1-3 covered only the image-bake machinery).

| Reviewer | Verdict | Disposition |
|---|---|---|
| Claude SMR (in-conversation) | NEEDS-MINOR | Found the `--help` sed range overshooting the comment header into code (`set -euo pipefail`/`die`/`info`/`SCRIPT_DIR` leaked as help text); fixed with a self-adjusting awk. Verified empty-array guards, spec parser, non-VF mac= rejection, HA config member→rg→monitor wiring. |
| AGY (adversarial-review-mqc0aazf-t8j9y3) | MERGE-NEEDS-MAJOR | 3 findings hostile-verified REAL: (1) `nictype=sriov`/`physical` VM NIC ordering vs virtio not guaranteed — I over-claimed `sriov:` as "recommended, mirrors reference" when the reference uses raw `pci:` for VM VFs; (2) greedy `mac=` parse doesn't strip trailing fields; (3) `--dry-run` not hermetic (re-exec guard runs before parse). All addressed in the fix commit. AGY's other points (sysfs walk robustness, ha-pair asymmetry) reviewed — sysfs walk is correct for the standard layout; ha-pair node0/node1 asymmetry (fab0 vs fab1) is intentional per-node naming, not a bug. |
| Codex | LOST (infra) | Dispatched task under flock; companion lost job state ("No jobs recorded"), no recoverable session jsonl, b6bylz6aa output empty. Per the Codex-infra-blocked exception, proceeding 3-of-4 — but this round is NEEDS-MAJOR regardless, so a re-review round is required before clean. |
| Copilot | re-requested | comment posted on PR #1906. |

## Fixes applied (this round)
- `--help`: sed range → self-adjusting awk (stops at first non-comment).
- `--dry-run` hermeticity: detect `--dry-run` in `$*` before the incus-admin re-exec guard.
- greedy mac: `mac="${mac%%,*}"` strips trailing fields after `,mac=`.
- SR-IOV over-claim: runtime WARNING on `sriov:`/`physical:` (VM NIC
  ordering vs virtio unverified; prefer `pci:<vf-addr>,mac=`); corrected
  ha-sriov.sh header + README framing (dropped "recommended", added the
  ordering caveat).

## NOT yet closed (honest)
- The `nictype=sriov`/`physical` VM NIC ordering-vs-virtio question needs
  a LIVE bake + boot to verify (`show interfaces terse` on a real VM with
  a mixed virtio+VF NIC set). Until then the deterministic dataplane path
  is raw `pci:<vf-addr>,mac=`, which the launcher supports and the docs
  now steer toward. A re-review round on the fix commit is also pending.
