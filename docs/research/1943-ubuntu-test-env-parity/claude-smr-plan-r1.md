# Claude SMR hostile plan review — #1943 r1

Reviewer: Claude SMR (domain SMR + CPU/OS arch + tooling). Hostile pass per
`feedback_triple_review_includes_claude_smr`. I tried to KILL this plan.

## Verdict: PLAN-NEEDS-WORK (minor) — not a kill, but r1 has gaps to close.

The plan is directionally correct and the blast radius is genuinely tiny
(test-env only, env-overridable rollback). I could not find an architectural
reason to kill it. But several concrete gaps must be closed before PLAN-READY.

## Findings

### F1 (MAJOR — must fix): `setup.sh` does NOT pin to Debian unstable only for the kernel — it ALSO disables init_on_alloc via a `/etc/default/grub` sed that the plan correctly flags, BUT the plan understates that on the **Debian** path the sed *works*, while the migration changes the mechanism. Verify the grub.d drop-in actually takes effect on the linuxcontainers `images:ubuntu/26.04` stream.
`setup.sh:303` seds `GRUB_CMDLINE_LINUX_DEFAULT` in `/etc/default/grub` and
calls `update-grub` (:304). §6.2 says switch to the bake.py grub.d drop-in form.
That is correct for cloud-images.ubuntu.com — but the *linuxcontainers*
`images:ubuntu/26.04` stream may NOT carry the same
`/etc/default/grub.d/50-cloudimg-settings.cfg` override (it is a distinct image
build, not the official cloudimg). So the plan's footgun fix may be solving a
problem that doesn't exist on V1's stream, OR the stream may have a *different*
override file. **Action:** the §8 probe must confirm, on the actual V1 image,
whether `init_on_alloc=0` reaches `/proc/cmdline` after the chosen mechanism.
Don't assume the cloudimg quirk transfers to the linuxcontainers stream.

### F2 (MAJOR — must fix): V1/V2 image-stream confusion is the load-bearing risk and §4 only half-addresses it.
The plan repeatedly notes `images:ubuntu/26.04` (linuxcontainers) ≠ the
cloud-images.ubuntu.com base bake.py uses. §4 gates the *kernel* on a probe.
But kernel is not the only divergence: default packages, grub override files
(F1), cloud-init presence, and the EFI/varstore layout can all differ. The
plan should state explicitly that **V1 is "Ubuntu-family parity," not
"byte-identical-to-prod parity."** If the user wants true prod-fidelity boot-path
validation, that is V2 (baked qcow2) — which the plan already recommends for
#1930 work. **Action:** sharpen §2 success criterion 1 to "Ubuntu 26.04 base
matching bake.py's *release*, V1 stream; V2 for byte-fidelity boot-path runs."
The current wording "matching bake.py's base" overclaims for V1.

### F3 (MEDIUM): Secure-Boot + AF_XDP shim — the plan's reassurance is half-right but misses module signing.
§9 says "shim is kernel-verifier-gated, not module-signed." True for the AF_XDP
`.o`. BUT the test VM also installs `linux-headers` + `clang`/`llvm`
(`setup.sh:281`) and historically may build/load *out-of-tree* artifacts. Under
Secure-Boot with kernel lockdown, loading an unsigned kernel module is refused.
The plan must confirm xpfd/userspace-dp loads **zero** out-of-tree kernel
modules at runtime (AF_XDP + native XDP are in-tree; the shim is BPF, not a
module — so this is *likely* fine). **Action:** add an explicit §8 check: boot
SB VM, run xpfd, confirm dataplane loads with `lockdown` active (or confirm
lockdown is not engaged). If SB breaks anything, SB2 (toggle, default-off)
isolates it — the plan already lists SB2 as the fallback, good.

### F4 (MEDIUM): `make test-destroy` / profile lifecycle not covered for the secureboot profile change.
`setup.sh` `create_vm_profile` deletes+recreates `xpf-vm` (:108-113). If SB1
adds `security.secureboot` to the existing `xpf-vm` profile, fine. But if SB2
introduces a *new* profile, `cmd_destroy` must clean it up too (else stale
profiles accumulate). The plan picks SB1 (single profile) which sidesteps this —
but should state that destroy-path is unaffected by SB1. **Action:** one line in
§6.4 confirming SB1 reuses `xpf-vm` so no destroy-path change is needed.

### F5 (MINOR): `golang` vs `golang-go` and `linux-perf` vs `linux-tools-generic` — plan flags these but the test VM may not even need a Go toolchain in-VM.
`setup.sh:281` installs `golang` in the VM, but builds happen on the *host*
(`make build` then `test-deploy` pushes the binary). Why is `golang` installed
in the VM at all? If it's vestigial, the migration is a chance to drop it
entirely rather than rename it. Same question for `build-essential clang llvm
libbpf-dev` — these were needed for the legacy in-VM eBPF build (deleted in
#1476). **Action:** the plan should ask whether the in-VM build toolchain is
still needed post-#1476; if not, the package delta shrinks to near-zero and the
`golang` naming question disappears. This is a real simplification the plan
misses.

### F6 (MINOR): version pinning default — agree with the plan's reasoning (pin, don't auto-latest) but the default value `26.04` will silently rot.
§6.1 hardcodes `XPF_BASE_RELEASE:-26.04`. When prod bumps to 26.10/28.04, this
test default must be bumped in lockstep — but nothing enforces that. bake.py
auto-discovers; the test VM pins. They will drift the moment prod bumps.
**Action:** add a note that the bump is a deliberate paired change, and consider
reading the *last-baked* release from a committed artifact (bake.py writes
`base_release: {rel}` to its manifest at `bake.py:571`) rather than a hardcoded
literal, so test tracks the last actual bake. This closes the drift loop the
issue is literally about.

## Things the plan got RIGHT (hostile pass, credit where due)
- Correctly identified the only production distro gate (`install.sh:75`
  `*debian*|*ubuntu*`) and that production is distro-agnostic. Verified.
- Correctly gated kernel-dance removal behind an empirical probe (§4) — does not
  assume the floor.
- Correctly scoped out the HW-watchdog early-hang case (incus OVMF can't do it).
- C1/C2 cluster-scope split correctly weights the smoke-gating-env risk.
- Rollback story (`IMAGE_VM=images:debian/13`) is genuinely a one-liner.

## Required for PLAN-READY
F1 + F2 (sharpen the V1-vs-prod-fidelity claim + probe the grub mechanism on the
actual stream), F3 (SB+lockdown module check in test plan), and address F5
(question the vestigial in-VM toolchain — likely shrinks the delta). F4/F6 are
one-line clarifications.
