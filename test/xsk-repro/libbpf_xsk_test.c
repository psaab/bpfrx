/*
 * Minimal libbpf-based AF_XDP test.
 * Uses xsk_socket__create from libbpf — the reference AF_XDP implementation.
 *
 * Build (embeds the XDP object, so run via the Makefile which generates the
 * xdp_pass_redirect_obj.h include from the tracked xdp_pass_redirect.o):
 *   make libbpf-xsk-test
 *
 * Usage:
 *   ./libbpf-xsk-test <interface> <queue> [copy|zerocopy]
 *
 * Must run as root. The XDP program (xdp_pass_redirect.o) is compiled into the
 * binary and loaded from memory (bpf_object__open_mem) — it is NOT read from a
 * predictable /tmp path (#4906 HC-025). The program is attached with
 * XDP_FLAGS_UPDATE_IF_NOEXIST so it never clobbers an XDP program already on
 * the interface (e.g. the firewall dataplane), and detached only if it is still
 * ours (#4906 HC-101).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>

/* Embedded xdp_pass_redirect.o (generated from the tracked object by the
 * Makefile via `xxd -i`). Provides xdp_pass_redirect_o[] + _len. */
#include "xdp_pass_redirect_obj.h"

#define FRAME_SIZE     4096
#define NUM_FRAMES     4096
#define BATCH_SIZE     64

struct xsk_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    void *umem_area;
    unsigned long rx_count;
};

static int load_xdp_prog(const char *iface, int ifindex, int *map_fd_out)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd, err;

    (void)iface; /* interface identified by ifindex; kept for signature parity */

    /* #4906 HC-025: load the object from the compiled-in bytes instead of a
     * predictable, attacker-writable /tmp path. No filesystem read, so there
     * is no symlink/TOCTOU window and no chance of loading a substituted
     * object as root. */
    obj = bpf_object__open_mem(xdp_pass_redirect_o, xdp_pass_redirect_o_len, NULL);
    if (!obj) {
        fprintf(stderr, "bpf_object__open_mem failed\n");
        return -1;
    }
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "bpf_object__load failed: %s\n", strerror(-err));
        return -1;
    }
    prog = bpf_object__find_program_by_name(obj, "xdp_redirect_xsk");
    if (!prog) {
        fprintf(stderr, "program not found\n");
        return -1;
    }
    prog_fd = bpf_program__fd(prog);

    map = bpf_object__find_map_by_name(obj, "xsk_map");
    if (!map) {
        fprintf(stderr, "map not found\n");
        return -1;
    }
    *map_fd_out = bpf_map__fd(map);

    /* #4906 HC-101: attach with XDP_FLAGS_UPDATE_IF_NOEXIST so we never replace
     * an XDP program already on the interface (the firewall dataplane runs one
     * on the live NIC). If one is present the attach returns -EBUSY and we
     * refuse to run — clobbering it, then detaching to none on exit, would
     * strip the interface of its dataplane. */
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err) {
        if (err == -EBUSY)
            fprintf(stderr,
                    "bpf_xdp_attach: interface already has an XDP program; "
                    "refusing to replace it (would clobber the firewall "
                    "dataplane). Detach it first if this is intended.\n");
        else
            fprintf(stderr, "bpf_xdp_attach failed: %s\n", strerror(-err));
        return -1;
    }
    printf("  XDP attached prog_fd=%d map_fd=%d\n", prog_fd, *map_fd_out);
    return prog_fd;
}

static int create_xsk(const char *iface, int queue, int map_fd,
                      int use_copy, struct xsk_info *info)
{
    struct xsk_umem_config umem_cfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 256,
        .flags = 0,
    };
    struct xsk_socket_config xsk_cfg = {
        .rx_size = NUM_FRAMES,
        .tx_size = 256,
        .bind_flags = XDP_USE_NEED_WAKEUP | (use_copy ? XDP_COPY : XDP_ZEROCOPY),
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = 0,
    };
    int err;
    __u32 idx;

    info->umem_area = aligned_alloc(getpagesize(), NUM_FRAMES * FRAME_SIZE);
    if (!info->umem_area) {
        fprintf(stderr, "alloc umem failed\n");
        return -1;
    }

    err = xsk_umem__create(&info->umem, info->umem_area,
                           (unsigned long long)NUM_FRAMES * FRAME_SIZE,
                           &info->fq, &info->cq, &umem_cfg);
    if (err) {
        fprintf(stderr, "xsk_umem__create failed: %s\n", strerror(-err));
        return -1;
    }

    err = xsk_socket__create(&info->xsk, iface, queue,
                             info->umem, &info->rx, &info->tx, &xsk_cfg);
    if (err) {
        fprintf(stderr, "xsk_socket__create failed: %s\n", strerror(-err));
        return -1;
    }

    int xsk_fd = xsk_socket__fd(info->xsk);
    printf("  xsk bound fd=%d %s\n", xsk_fd, use_copy ? "copy" : "zero-copy");

    /* Register in our xskmap */
    __u32 key = queue;
    __u32 val = xsk_fd;
    err = bpf_map_update_elem(map_fd, &key, &val, 0);
    if (err) {
        fprintf(stderr, "  xskmap update failed: %s\n", strerror(-err));
    } else {
        printf("  xskmap[%u] = fd %d\n", key, xsk_fd);
    }

    /* Prime fill ring */
    __u32 ret = 0;
    if (xsk_ring_prod__reserve(&info->fq, NUM_FRAMES, &idx) == NUM_FRAMES) {
        for (int i = 0; i < NUM_FRAMES; i++)
            *xsk_ring_prod__fill_addr(&info->fq, idx + i) = i * FRAME_SIZE;
        xsk_ring_prod__submit(&info->fq, NUM_FRAMES);
        ret = NUM_FRAMES;
    }
    printf("  fill ring primed: %u/%d\n", ret, NUM_FRAMES);

    /* Kick NAPI */
    for (int i = 0; i < 20; i++) {
        struct pollfd pfd = { .fd = xsk_fd, .events = POLLIN };
        poll(&pfd, 1, 1);
        sendto(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    }

    info->rx_count = 0;
    return 0;
}

static unsigned long receive_loop(struct xsk_info *info, int seconds)
{
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    unsigned long total = 0;
    unsigned long polls = 0;

    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - start.tv_sec) +
                         (now.tv_nsec - start.tv_nsec) / 1e9;
        if (elapsed >= seconds) break;

        __u32 idx_rx = 0;
        unsigned int rcvd = xsk_ring_cons__peek(&info->rx, BATCH_SIZE, &idx_rx);
        if (rcvd > 0) {
            /* #4906 HC-069: read the RX descriptor addresses BEFORE releasing
             * them, and use the RX-descriptor accessor (not comp_addr, which is
             * the completion-ring layout). The previous code released first and
             * then read a completion address off the RX ring — recycling stale
             * or wrong offsets into the fill ring (fill-ring starvation /
             * duplicate ownership). rcvd is bounded by BATCH_SIZE. */
            __u64 addrs[BATCH_SIZE];
            for (unsigned int i = 0; i < rcvd; i++)
                addrs[i] = xsk_ring_cons__rx_desc(&info->rx, idx_rx + i)->addr;
            total += rcvd;
            xsk_ring_cons__release(&info->rx, rcvd);
            /* Return the chunk-aligned frame bases to the fill ring. */
            __u32 idx_fq;
            if (xsk_ring_prod__reserve(&info->fq, rcvd, &idx_fq) == rcvd) {
                for (unsigned int i = 0; i < rcvd; i++) {
                    *xsk_ring_prod__fill_addr(&info->fq, idx_fq + i) =
                        addrs[i] & ~((__u64)FRAME_SIZE - 1);
                }
                xsk_ring_prod__submit(&info->fq, rcvd);
            }
        } else {
            polls++;
            int fd = xsk_socket__fd(info->xsk);
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            poll(&pfd, 1, 10);
        }
    }
    printf("  rx=%lu empty_polls=%lu\n", total, polls);
    return total;
}

static void destroy_xsk(struct xsk_info *info, int map_fd, int queue)
{
    __u32 key = queue;
    bpf_map_delete_elem(map_fd, &key);
    if (info->xsk) xsk_socket__delete(info->xsk);
    if (info->umem) xsk_umem__delete(info->umem);
    free(info->umem_area);
    memset(info, 0, sizeof(*info));
}

/*
 * #4906 HC-090: run "ip link set <iface> <state>" without a shell and report
 * whether it actually succeeded. The previous code used system() with an
 * interpolated interface name (shell-injection surface) and ignored the exit
 * status, so phase 2 (rebind) ran even when the link cycle never happened —
 * turning a no-op into a misleading PASS/FAIL. execlp() takes the interface as
 * a bare argv element, so it is never interpreted by a shell.
 */
static int run_ip_link(const char *iface, const char *state)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork (ip link)");
        return -1;
    }
    if (pid == 0) {
        execlp("ip", "ip", "link", "set", iface, state, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid (ip link)");
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "ip link set %s %s failed (status=0x%x)\n",
                iface, state, status);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <queue> [copy|zerocopy]\n", argv[0]);
        return 1;
    }
    const char *iface = argv[1];
    int queue = atoi(argv[2]);
    int use_copy = (argc > 3 && strcmp(argv[3], "copy") == 0);
    const char *mode = use_copy ? "COPY" : "ZERO-COPY";
    int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "interface %s not found\n", iface);
        return 1;
    }

    printf("=== Loading XDP on %s (ifindex %d) ===\n", iface, ifindex);
    int map_fd;
    int prog_fd = load_xdp_prog(iface, ifindex, &map_fd);
    if (prog_fd < 0) return 1;

    /* Start background traffic: ping own IP */
    pid_t child = fork();
    if (child < 0) {
        /* #4906 HC-001: fork() failed (RLIMIT_NPROC / PID exhaustion / memory
         * pressure). Do NOT fall into the unguarded kill(child, 9) at cleanup
         * below — with child == -1 that is kill(-1, SIGKILL), which as root
         * signals every process the caller may signal (the firewall daemon and
         * the host). Warn and run without background traffic; the guarded
         * cleanup skips the kill for child <= 0. */
        perror("fork (background traffic)");
    } else if (child == 0) {
        /* Child: send pings to self */
        char ifarg[64];
        snprintf(ifarg, sizeof(ifarg), "-I%s", iface);
        char *ip = "10.0.61.1"; /* adjust if needed */
        execlp("ping", "ping", ifarg, "-i", "0.1", "-c", "50", "-q", ip, NULL);
        _exit(1);
    }

    struct xsk_info info = {};
    /* #4906 HC-081: rx1/rx2 must be initialized before any `goto cleanup`.
     * They were previously declared past the gotos, so an early failure jumped
     * over their initialization and the cleanup block read indeterminate values
     * — which could print RESULT: PASS on a test that never ran a phase. */
    unsigned long rx1 = 0, rx2 = 0;
    int link_cycled = 0;

    printf("\n=== Phase 1: Initial bind (%s) on %s queue %d ===\n", mode, iface, queue);
    if (create_xsk(iface, queue, map_fd, use_copy, &info) < 0) {
        printf("RESULT: FAIL (cannot create XSK)\n");
        goto cleanup;
    }
    rx1 = receive_loop(&info, 3);
    printf("Phase 1 rx: %lu\n", rx1);
    destroy_xsk(&info, map_fd, queue);

    printf("\n=== Link DOWN/UP on %s ===\n", iface);
    /* #4906 HC-090: only proceed to the rebind phase if the link actually
     * cycled. If `ip` is missing, lacks capability, or the interface refuses
     * the state change, phase 2 is meaningless and must not masquerade as a
     * pass/fail of the rebind path. */
    if (run_ip_link(iface, "down") == 0) {
        usleep(200000);
        if (run_ip_link(iface, "up") == 0)
            link_cycled = 1;
    }
    if (!link_cycled) {
        fprintf(stderr,
                "Link DOWN/UP cycle did not complete — skipping phase 2 "
                "(rebind); result is INCONCLUSIVE.\n");
        goto cleanup;
    }
    printf("  waiting 500ms for NIC reinit...\n");
    usleep(500000);

    printf("\n=== Phase 2: Rebind (%s) on %s queue %d ===\n", mode, iface, queue);
    if (create_xsk(iface, queue, map_fd, use_copy, &info) < 0) {
        printf("RESULT: FAIL (cannot rebind XSK)\n");
        goto cleanup;
    }
    rx2 = receive_loop(&info, 3);
    printf("Phase 2 rx: %lu\n", rx2);
    destroy_xsk(&info, map_fd, queue);

cleanup:
    /* #4906 HC-001: only signal a real child. On fork() failure child < 0 and
     * an unguarded kill(child, 9) becomes kill(-1, SIGKILL) — a host-wide
     * SIGKILL when run as root. Guard on child > 0. */
    if (child > 0) {
        kill(child, 9);
        waitpid(child, NULL, 0);
    }
    /* #4906 HC-101: detach only the program we attached, and only if it is
     * still the one on the interface. XDP_FLAGS_REPLACE + old_prog_fd makes the
     * kernel refuse the detach if something else now owns the hook — so we can
     * never strip an unrelated (firewall) XDP program off the NIC. Because we
     * attached with UPDATE_IF_NOEXIST, prog_fd is only >= 0 here when the attach
     * succeeded on a previously-empty hook. */
    if (prog_fd >= 0) {
        LIBBPF_OPTS(bpf_xdp_attach_opts, dopts, .old_prog_fd = prog_fd);
        int derr = bpf_xdp_detach(ifindex, XDP_FLAGS_REPLACE, &dopts);
        if (derr)
            fprintf(stderr,
                    "XDP detach skipped/failed (%s) — hook not ours anymore\n",
                    strerror(-derr));
        else
            printf("  XDP detached\n");
    }

    printf("\n");
    if (!link_cycled)
        printf("RESULT: INCONCLUSIVE  (link DOWN/UP did not run)  phase1_rx=%lu\n", rx1);
    else if (rx1 > 0 && rx2 > 0)
        printf("RESULT: PASS  phase1_rx=%lu phase2_rx=%lu\n", rx1, rx2);
    else if (rx1 > 0 && rx2 == 0)
        printf("RESULT: FAIL  (broken after link cycle)  phase1_rx=%lu phase2_rx=0\n", rx1);
    else if (rx1 == 0)
        printf("RESULT: FAIL  (no rx on initial bind)  phase1_rx=0 phase2_rx=%lu\n", rx2);
    else
        printf("RESULT: UNEXPECTED  phase1_rx=%lu phase2_rx=%lu\n", rx1, rx2);

    if (!link_cycled)
        return 2; /* inconclusive: distinct from a real pass (0) or fail (1) */
    return (rx1 > 0 && rx2 > 0) ? 0 : 1;
}
