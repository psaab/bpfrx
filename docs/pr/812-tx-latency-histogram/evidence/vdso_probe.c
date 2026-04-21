/*
 * Minimal VDSO probe for clock_gettime(CLOCK_MONOTONIC).
 *
 * Purpose: prove that on the target glibc+kernel pair, clock_gettime()
 * does NOT issue a syscall — it resolves to the VDSO user-space stub.
 *
 * Build:  gcc -O2 -o vdso_probe vdso_probe.c
 * Verify: strace -e clock_gettime ./vdso_probe
 *
 * Expected strace output under VDSO resolution:
 *   (no clock_gettime line — all N calls served from VDSO)
 *   +++ exited with 0 +++
 *
 * If strace prints "clock_gettime(...)" lines, glibc fell back to the
 * syscall path and the plan's "no syscall per packet" invariant is
 * broken on this deployment.
 */
#include <stdio.h>
#include <time.h>

int main(void)
{
    struct timespec ts;
    unsigned long i;
    unsigned long sum = 0;

    /* 10k iterations — strace would print 10k lines if any hit the
     * syscall fallback path. */
    for (i = 0; i < 10000; i++) {
        if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
            perror("clock_gettime");
            return 1;
        }
        sum ^= (unsigned long)ts.tv_nsec;
    }
    printf("ok: 10000 clock_gettime calls (xor=%lx)\n", sum);
    return 0;
}
