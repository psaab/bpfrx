/*
 * VDSO presence + clock_gettime resolution probe.
 *
 * On Linux glibc x86_64 / aarch64, __vdso_clock_gettime is the symbol
 * that glibc's clock_gettime() dispatches to when the kernel exports
 * a usable VDSO mapping. getauxval(AT_SYSINFO_EHDR) returns the base
 * address of that mapping — a non-zero return is the kernel's
 * contract that VDSO is available to this process.
 *
 * Scope: this probe checks only two things — that AT_SYSINFO_EHDR is
 *        non-zero (the VDSO mapping is visible to the process) and that
 *        clock_gettime(CLOCK_MONOTONIC) succeeds. It does NOT dump
 *        /proc/self/maps, resolve __vdso_clock_gettime, or prove that
 *        the call dispatched through the VDSO rather than a syscall
 *        fallback. The sibling vdso_probe.c supplies that syscall-fallback
 *        gate via its 10,000-call `strace` count; run it for the
 *        dispatch-path proof this probe deliberately does not make.
 *
 * Build:  gcc -O2 -o vdso_probe2 vdso_probe2.c
 * Output: prints the VDSO base address (must be non-zero on a
 *         seccomp profile that allows the process to observe it) and the
 *         result of one clock_gettime(CLOCK_MONOTONIC) call.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <time.h>

int main(void)
{
    unsigned long vdso_base = getauxval(AT_SYSINFO_EHDR);
    struct timespec ts;

    printf("AT_SYSINFO_EHDR = 0x%lx\n", vdso_base);
    if (vdso_base == 0) {
        printf("FAIL: VDSO mapping not visible to this process.\n");
        return 1;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        return 2;
    }
    printf("clock_gettime OK: tv_sec=%ld tv_nsec=%ld\n",
           (long)ts.tv_sec, (long)ts.tv_nsec);
    return 0;
}
