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

## Round-4b — AGY full-report finding #1 (driver-class sort) fixed properly

The AGY summary I first read understated finding #1; the full report
escalated it and it is CONFIRMED against `pkg/daemon/linksetup.go:171-184`:
the guest assigns vSRX names by sorting `(driver-class, PCI-bus)` —
`virtio_net` sortKey 0, all other drivers sortKey 1 — so ALL virtio NICs
are named before ALL hardware NICs regardless of PCI slot. My original
"--nic order = PCI order = name" contract was wrong for mixed orderings,
and I had mis-classified `sriov:`/`physical:` into the virtio group.

Fix (this commit):
- Reclassified `sriov:`/`physical:`/`pci:` as hardware-class; `net:`/
  `bridge:`/`macvlan:` as virtio-class. Hardware devices now named
  `hw00..` (sorts after `eth00..`), virtio `eth00..`.
- The ordering guard now rejects a virtio spec after ANY hardware spec
  (was: only after a `pci:` spec), with an explanation citing the
  guest class sort.
- Docs (README + deploy-quickstart) rewritten: the contract is now
  "all virtio NICs named first, then all hardware NICs, each class in
  launch order", grounded in linksetup.go. Dropped the earlier
  "nictype=sriov ordering unverified" hedge — the class split IS
  code-verified; within-class order uses the same name→PCI mechanism
  the reference cluster relies on, with `show interfaces terse` as the
  acceptance check.
- The three shipped recipes all satisfy virtio-first/hardware-last and
  therefore produce correct names (ha-bridges all-virtio; ha-sriov
  3 virtio + 2 VF; ha-physical all-hardware).

Also fixed from AGY #2/#3/#4 this round:
- empty `nodearg` array expansion (set -u trip on bash <4.4) — replaced
  with an explicit if/else.
- VF MAC pin now brings the PF admininstratively `up` first (ixgbe/i40e
  reject `vf N mac` on a down PF).
- `resolve_vf_parent` PF derivation hardened to use the sysfs glob path
  (`…/net/<PF>/device/virtfnN`) rather than the VF readlink target
  (switchdev representor races).
- `--dry-run` now skips the sysfs VF walk entirely (fully hermetic;
  pci+mac under dry-run prints "(dry-run) would pin" instead of dying).

AGY #5 (ghost bonds from global fab0+fab1) REFUTED: the working
reference `docs/ha-cluster-userspace.conf` defines both fab0 and fab1
globally with member-interfaces identically; the loss cluster runs it,
so the compiler tolerates a fab interface whose members are absent on a
node. `ha-pair.conf` mirrors the proven config.

Status: shellcheck clean; full dry-run matrix correct; configs pass
check-config. Codex r4 remains lost to infra. Live-boot verification of
the realized interface map (esp. within-hardware-class order for
nictype=sriov) is the one open item before this is fully closed.

## Round-5 — operator directive: Python, not shell

Operator: "I don't want shell scripts to do this work, I want python
scripts." Converted the deploy tooling to a single self-contained Python
tool and removed the shell scripts.

- scripts/deploy/xpf-deploy.py: now has subcommands `deploy` (YAML),
  `launch` (imperative --nic, replaces xpf-launch.sh), and `inventory`
  (host NIC/VF/bridge listing, replaces show-host-nics.sh). Builds the
  day-0 config drive in-process (xpfd check-config validation + xorriso,
  no make-config-drive.sh dependency). incus + libvirt; --dry-run
  hermetic.
- Removed: scripts/deploy/xpf-launch.sh, examples/deploy/show-host-nics.sh,
  examples/deploy/ha-{bridges,sriov,physical}.sh (the per-topology bash
  wrappers are redundant with the YAML samples).
- scripts/image/make-config-drive.sh KEPT — it is the image bakery's
  tool (used by validate-image.sh), a separate deliverable; the deployer
  no longer calls it.
- Docs (README, deploy-quickstart, install-images) rewritten Python-only.

Validation: py_compile clean; all 7 YAMLs deploy-dry-run on BOTH
incus and libvirt; launch + inventory subcommands work; real
build_config_drive produces an xpf-config ISO (xpf.conf + node-id)
validated by check-config; example .conf still pass the gate; no
dangling references to the removed scripts.

## Round-6 — image-build tooling converted to Python; upgrade follow-on filed

Operator: "make sure what we use to build the initial bootstrap images is
using python not shell scripts" + "think about how you will upgrade xpf
in the future ... as a follow on issue/pr".

- Filed #1917: in-place xpf upgrade (deploy new xpfd + xpf-userspace-dp
  without re-imaging) — design surface (verify-before-cut #1869, HA
  rolling-failover for dataplane restart, control-plane-only hot-restart,
  wire-protocol compat, atomic swap+rollback, .deb packaging). Tracking;
  needs a /research round.
- Build-host bakery converted shell -> Python:
  - scripts/image/bake.py (was bake-image.sh): full offline pipeline
    (build, Ubuntu discovery + SHA256 verify, virt-resize/customize/
    sysprep/sparsify, metadata, checksums, manifest, validation gate).
  - scripts/image/validate.py (was validate-image.sh): incus first-boot
    scenario matrix a/b/c (factory boot + in-guest verify-dataplane,
    valid + invalid day-0 drives).
  - scripts/image/make_config_drive.py (was make-config-drive.sh):
    importable build_config_drive() + CLI; validate.py imports it.
  - Makefile `image:` -> python3 scripts/image/bake.py; install-images.md
    references updated.
- KEPT as shell (deliberately, flagged): scripts/image/xpf-day0-config
  (the boot-critical in-guest day-0 loader) and incus-agent-setup. These
  run IN the guest at early boot, not on the build host; converting the
  boot path is riskier and needs a live bake+boot to verify, so it is
  offered separately rather than done blind.

Validation: all four Python tools py_compile; make_config_drive builds a
real xpf-config ISO (xpf.conf + node-id); validate.py imports the drive
builder; bake/validate arg-parse + required-arg errors correct; deploy
tool regression green. NOT live-bake-verified (needs root + libguestfs +
incus + boot) — same standing caveat as the rest of #1906.
