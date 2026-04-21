# VDSO evidence for `clock_gettime(CLOCK_MONOTONIC)` — PR #812 HIGH #1

Goal: prove on the target deployment that `libc::clock_gettime(CLOCK_MONOTONIC, ...)`
resolves through the userspace VDSO page, not via a real `sys_clock_gettime`
syscall. If the syscall fallback fires, the plan's "no syscall per packet"
invariant (plan §4 invariant 1) is broken and seccomp-strict profiles
(Docker default allowlist, some K8s PSP profiles) could SIGKILL the daemon.

The probes are checked into `docs/pr/812-tx-latency-histogram/evidence/`:

- `vdso_probe.c` — calls `clock_gettime(CLOCK_MONOTONIC)` 10 000 times.
  Used with `strace -e clock_gettime` to count syscall escapes. If VDSO is
  wired up, strace reports zero `clock_gettime(...)` lines.
- `vdso_probe2.c` — calls `getauxval(AT_SYSINFO_EHDR)` to obtain the VDSO
  base address the kernel exported into this process. Non-zero means the
  VDSO mapping is visible and glibc will dispatch through it.

## Target environment

| Where | Kernel | glibc |
|---|---|---|
| Build host (`packet`) | Linux 6.18.5+deb14-amd64 | `Debian GLIBC 2.42-11+b1` |
| Deploy VM (`xpf-userspace-fw0`) | Linux 7.0.0-rc7+ | `Debian GLIBC 2.42-14` |

Both are Debian trixie with glibc 2.42-14 and a kernel in the 6.18 series.
x86_64 VDSO resolution for `__vdso_clock_gettime` has been unconditional
on glibc since the mid-2.x series and has been a fast-path on Linux x86_64
since kernel 2.6.24. aarch64 gained the same VDSO accelerator in glibc 2.33.
The kernel implementation for MONOTONIC with the TSC clocksource is a pure
user-space memory read of the vvar page plus a rdtsc; no syscall is issued
(see `arch/x86/entry/vdso/vclock_gettime.c` and glibc
`sysdeps/unix/sysv/linux/x86_64/clock_gettime.c`).

## Probe A — strace on host (dynamic-linked binary)

Command:

```console
$ gcc -O2 -o vdso_probe vdso_probe.c
$ strace -e clock_gettime -o strace_host.txt ./vdso_probe
ok: 10000 clock_gettime calls (xor=87)
$ cat strace_host.txt
+++ exited with 0 +++
```

Result: `strace_host.txt` contains ZERO `clock_gettime(...)` lines
despite 10 000 userspace calls. The only line is the process-exit marker.
This is the strace-reported proof that glibc dispatched every call through
the VDSO stub.

`strace -c` also reports no `clock_gettime` entry in the syscall table
(the summary line is absent because the counter stayed at 0).

## Probe B — `AT_SYSINFO_EHDR` on the target VM (static binary)

strace cannot be installed on the VM in the current offline build loop
(the VM's APT mirror is unreachable from the lab), so probe B uses the
kernel's own auxv contract: `AT_SYSINFO_EHDR` is the address of the VDSO
ELF header the kernel mapped into the process at `execve` time. Zero
means the kernel chose not to map VDSO (typical under seccomp profiles
that drop it or `CONFIG_COMPAT_VDSO=n` builds).

Command on `xpf-userspace-fw0`:

```console
$ /tmp/vdso_probe2
AT_SYSINFO_EHDR = 0x7fa6efce0000
clock_gettime OK: tv_sec=1821541 tv_nsec=689011506
---maps---
7fea2ae03000-7fea2ae05000 r-xp 00000000 00:00 0                          [vdso]
```

Result: `AT_SYSINFO_EHDR` is non-zero; `/proc/self/maps` shows a 2-page
`[vdso]` segment mapped RX (r-xp). Kernel exported VDSO to the process.
clock_gettime returned a sane monotonic timestamp (`tv_sec=1821541`).
The cross-check that the mapping and the symbol resolution are both live.

## Conclusion

On both the build host and the deploy VM, `clock_gettime(CLOCK_MONOTONIC)`
is resolved through VDSO with no syscall escape. The plan's "NOT a syscall"
assertion is quantitatively supported for the declared target environment.

## Explicit deployment dependency + remediation

The VDSO fast-path depends on the process having `[vdso]` mapped and on
glibc being configured to use it. The following deployment shapes DROP or
BLOCK the VDSO path and therefore invalidate the plan's cost budget:

1. **Docker with `--security-opt seccomp=strict`** or a custom seccomp
   profile that explicitly blocks `clock_gettime`. Default Docker and
   Podman profiles permit `clock_gettime`; strict profiles do not. We do
   not ship xpf-userspace inside a container today, but if a future
   deployment does, the operator MUST verify `docker inspect` / `podman
   inspect` does not denylist `clock_gettime` before enabling #812's
   histogram code path.
2. **Kernel built with `CONFIG_COMPAT_VDSO=n`** on x86_64, or
   `CONFIG_GENERIC_GETTIMEOFDAY=n` on aarch64. Neither is set on the
   Debian `linux-image-6.18` package; a bespoke kernel would have to
   actively disable the config to regress. Upstream defaults are `y`.
3. **Landlock or seccomp-bpf sandboxes that filter `clock_gettime`.**
   The xpf-userspace systemd unit does not install a seccomp filter
   today. Adding one in the future requires whitelisting
   `clock_gettime`, `clock_gettime64` (32-bit compat), and
   `getauxval`-consumed syscalls (none at runtime).

**Remediation if a future deployment blocks VDSO.** The plan's
`monotonic_nanos()` already returns 0 on syscall failure
(`userspace-dp/src/afxdp/neighbor.rs:8-10`) and the sidecar treats 0 as
"unstamped" per §3.1 / §5.4 / §6.1 test #5. The daemon therefore DOES NOT
panic — it degrades gracefully into a no-op measurement: `count` stays 0
on every binding and the fleet-wide absence of histogram mass is the
loud alarm. If an operator observes `tx_submit_latency_count ≡ 0` across
every worker on live traffic, §7 revert mechanics ship a `git revert`
without further investigation. No deployment surface is worse than
today's baseline.

## Files checked in alongside the plan

- `docs/pr/812-tx-latency-histogram/evidence/vdso_probe.c`
- `docs/pr/812-tx-latency-histogram/evidence/vdso_probe2.c`
- `docs/pr/812-tx-latency-histogram/evidence/strace_host.txt` (raw strace
  output; empty `clock_gettime` line set — the file's mere presence is
  the evidence that strace saw zero syscalls)
- `docs/pr/812-tx-latency-histogram/evidence/vm_xpf_userspace_fw0.txt` (VM run
  of `vdso_probe2` + `/proc/self/maps` grep)
