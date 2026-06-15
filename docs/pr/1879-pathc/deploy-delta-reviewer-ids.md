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

## /triple-review round (full-PR code review, head ba795ddd9)

Scope: full delta origin/master...HEAD (~2988 insertions): Go day-0
validation gate, Python deploy + image-build tooling, examples/docs.
This PR ships NO forwarding-path code — iperf3 smoke is N/A; the real
acceptance test is a live bake+boot (not run; needs root+libguestfs+incus).

| Reviewer | Verdict | Notes |
|---|---|---|
| Claude SMR | MERGE-READY | gates green (go build+test rc=0, full go test rc=0, all 4 Python py_compile); diffed deleted shell vs Python ports — every functional assert preserved (kernel>=6.18, mellanox driver-set, single-kernel, init_on_alloc=0 cmdline, sshd posture, base SHA256 verify, sparsify); expected_name==assignName; role-validation + dry-run hermeticity + per-backing incus/libvirt translation verified |
| AGY | MERGE-READY | adversarial-review-mqdatgnc-kw4kb7 — SUBSTANTIATED (log shows real inspection of main.go/check.go/store.go/check_test.go + Commit-flow parity, xpf-day0-config, validate.py, xpf-deploy.py, linksetup.go assignName, bake.py, make_config_drive.py + diff of original bake-image.sh; cited artifact). Confirmed: check-config→compileTreeStrict parity, flag.ContinueOnError no exit-collision, expected_name↔assignName, faithful assert preservation, day-0 TOCTOU-safe copy-then-verify + ro,nosuid,nodev,noexec + 0600 |
| Codex | INFRA-BLOCKED | 3 documented attempts: bc3y92yqr + by31w7ilu (flock wrapper swallowed dispatch, no job) ; task-mqdb0f8w-67ghh4 (registered, ran ~16min stuck "running", result un-fetchable). Companion state-broken this session. Per feedback_codex_infra_must_retry → proceed without |
| Copilot | QUOTA-BLOCKED | "unable to review… reached quota limit" on all 8 commits incl. head; 3-of-4 fallback |

Net: 2 substantive MERGE-READY (Claude SMR + AGY); Codex + Copilot both
infra/quota-blocked. NOT auto-merged — held for operator review/merge per
the standing #1879 hold; live bake+boot acceptance test still outstanding.

## Codex r1 (clean runtime) — MERGE-NEEDS-MAJOR, all 5 findings fixed

task-mqdvqqar-e0srt1 (session 019ec688), head 43d010fc0. After the runtime
recovered (/codex:setup green), the independent third pass found 5 real
defects the two MERGE-READYs missed — the quad working as designed:

1. [HIGH] xpf-deploy.py argparse: --dry-run/--hypervisor before the
   subcommand were clobbered (verified: --dry-run launch went into a REAL
   incus init), and the bare-yaml shorthand detector mistook an option
   VALUE (e.g. `--hypervisor libvirt`) for the subcommand token. FIXED:
   rewrote main() to peel globals with a globals-only parse_known_args
   pre-parser (consumes option values; globals work before OR after the
   subcommand). Verified across 5 argv shapes.
2. [HIGH] deploy_incus: plain `incus init` inherited the default profile's
   eth0 NIC → phantom virtio device polluting the positional map. FIXED:
   `--no-profiles` + explicit `-d root,type=disk,pool=<pool>` (pool from
   YAML `pool:`/default "default"). (Note: dev00 sorts before eth0 so fxp0
   was not actually mis-bound, but the phantom NIC is gone now.)
3. [MED] validate.py incus-admin reexec used " ".join not shlex — spaces/
   metachars in qcow2/metadata paths break or inject. FIXED: shlex.quote.
4. [MED] xpf-day0-config persisted node-id without checking the write, then
   stamped success — a node-1 config could boot with node-0 expansion.
   FIXED: guard the write; on failure remove xpf.conf, do NOT stamp, return
   1 so the next boot retries.
5. [MED] bake.py ran `sudo prlimit` with check=False (shell died on
   failure) — silently dropped the RLIMIT_MEMLOCK remediation. FIXED: check
   returncode, die on failure (shell parity).

Codex confirmed PASSED: Go check-config↔compileTreeStrict parity (exit 1
bad-flags / exit 2 reject), the big bake/validate asserts preserved, and
the day-0 loader otherwise boot-safe. All fixes py_compile + dry-run
verified; incus-runtime fixes (2,4) still want live-boot confirmation.

## Codex r2 (verify fixes @ fb8de66ea) — INFRA-STUCK; fixes locally proven

Codex r2 (task-mqdwa2px-nxam1f) was dispatched to re-verify the 5 r1
fixes. The companion runtime degraded again mid-session: the job sat in
"running" for >32 min across two status-first poll cycles and never
completed / its result was never fetchable (the r1 review under the same
session DID complete, so this is intermittent runtime flakiness, not a
verdict). Not re-dispatched a third time — the fixes are locally proven:

- Finding 1 (argparse): verified across 5 argv shapes — globals work
  before AND after the subcommand; `--hypervisor libvirt` no longer
  mistaken for the subcommand; bare-yaml shorthand routes to deploy.
- Finding 2 (incus profile): dry-run shows `incus init … --no-profiles …
  -d root,type=disk,pool=default,path=/` — no phantom profile NIC.
- Finding 3 (shlex): validate.py reexec now shlex.quotes every token.
- Finding 4 (node-id): xpf-day0-config guards the write — removes
  xpf.conf, no stamp, returns 1 on failure (shellcheck clean).
- Finding 5 (prlimit): bake.py dies on prlimit failure (shell parity).

py_compile clean on all 4 Python tools; full dry-run matrix (both
hypervisors) green; example .conf still pass check-config.

Standing for #1906: Claude SMR + AGY MERGE-READY; Codex r1 findings all
fixed + locally verified (r2 confirmation infra-stuck); Copilot
quota-blocked. Held for operator merge; live bake+boot still outstanding.

## LIVE BAKE + BOOT (the outstanding acceptance gate) — GREEN after fixing a real bug

Ran the full bake+boot on this build host (KVM via the kvm group; boot on
local incus, vm-capable). It caught a ship-blocking defect no review found:

- Bake 1 → boot scenario A FAILED: "more than one kernel in /lib/modules".
  Root cause: Ubuntu 26.04 cloudimg already runs -generic (7.0.0-15), so
  `apt install linux-generic` pulls a newer point release (7.0.0-22) and
  leaves the original; the old narrow-regex purge missed 26.04's
  per-version packages (linux-main-modules-zfs-*, linux-headers-*) + depmod
  leftovers.
- Fix (committed): purge every non-newest kernel VERSION via apt glob
  (linux-*<ver>*) + rm -rf the /lib/modules/<ver> dir & /boot files, plus a
  HARD in-bake single-kernel assert (caught a 2-kernel image on bake 2,
  proving the assert works).
- Bake 3 → single kernel (7.0.0-22-generic); full matrix GREEN:
  A factory boot + IN-GUEST verify-dataplane PASS (kernel 7.0.0-22-generic,
    -generic, full driver set, init_on_alloc=0, sshd posture, no stray cfg);
  B valid day-0 drive installed + committed + NOT re-applied on reboot;
  C invalid day-0 (dataplane-type ebpf) REJECTED, factory fallback reachable.

This closes the "needs a live bake+boot" caveat that stood on #1906. The
image actually boots, ships exactly one ≥6.18 kernel with the full driver
set, passes its own verifier gate, and the day-0 loader behaves to spec.

## Doc /triple-review (image-validation runbook + deploy docs)

Codex (task-mqfff19j-sa2jzp) MERGE-NEEDS-MAJOR — 7 real copy-paste/accuracy
defects; AGY (adversarial-review-mqfffbz9) MERGE-READY (missed them);
Claude SMR verified the embedded config + commands. All 7 fixed:

1. Tier-2: iperf3 installed only on wanhost (lanhost is the client) +
   tcpdump uninstalled + v6 SNAT proof missing → install iperf3 on both,
   tcpdump on wanhost, added the fd66:2::1 v6 tcpdump filter.
2. Tier-3: `incus restart fw1` restarts the SECONDARY (ha-pair.conf:
   node0=200/node1=100 for RG1/RG2) → fails to test failover; changed to
   `incus stop fw0` (the data-path primary) + failback note.
3. HA network names didn't match the shipped YAML sources → image-
   validation Tier-3, deploy-quickstart, and README now create the exact
   br-mgmt/ha-control/ha-fabric/br-lan/br-wan (and the -sriov path's
   PFs); deploy unedited.
4. README no-YAML launch used `--config standalone.conf` (fails from repo
   root; launch resolves from cwd) → `examples/deploy/standalone.conf`.
5. Naming docs conflated config slash form (ge-0/0/0) with the Linux dash
   form (ge-0-0-0) assignName returns → added the distinction in both docs.
6. Tier-1 table overclaimed: "mlx5/i40e driver set" (validate.py only
   checks the Mellanox dir as the modules-extra sentinel) and "0600" (the
   scenario checks exists/non-empty, not mode) → softened to match the
   harness.
7. virtio "native (vhost)" contradicted xpf-deploy.py inventory's
   "no (generic)" → aligned both docs to generic-class.

Codex VERIFIED OK: the xpf-deploy.py CLI surface matches the docs; the
Tier-2 router config + standalone.conf + ha-pair.conf (both node-ids)
pass check-config; incus syntax valid (6.21); cross-refs resolve.

## Live Tier-2 deployment (virtio incus) — image/control-plane GREEN, forwarding venue-blocked

Ran the documented Tier-2 standalone deploy against the baked image.
- FIXED: incus init `-d root,...` single-flag syntax was invalid; now three
  -d flags. --no-profiles + explicit root confirmed: VM boots, no phantom NIC.
- GREEN: image boot; day-0 loader installed router-test.conf; xpfd committed;
  ge-0/0/0=10.66.1.1/24+fd66:1::1, ge-0/0/1=10.66.2.1/24+fd66:2::1 up;
  positional naming correct; lanhost->gateway ping 0-loss (control plane).
- BLOCKED (venue, not image bug): AF_XDP helper loops `libxdp private bind:
  Device or resource busy` on virtio multi-queue; can't reduce channels
  ("too low for existing zerocopy AF_XDP sockets"); 0 transit sessions.
  Forwarding needs mlx5-VF (loss) / i40e-PF (standalone VM). Doc corrected.
