/*
 * Minimal libbpf-based AF_XDP test.
 * Uses xsk_socket__create from libbpf — the reference AF_XDP implementation.
 *
 * Build:
 *   cc -O2 -o libbpf-xsk-test libbpf_xsk_test.c -lbpf -lxdp -lelf -lz
 *   OR (if no libxdp):
 *   cc -O2 -o libbpf-xsk-test libbpf_xsk_test.c -lbpf -lelf -lz
 *
 * Usage:
 *   ./libbpf-xsk-test <interface> <queue> [copy|zerocopy]
 *
 * Must run as root. Loads xdp_pass_redirect.o XDP program.
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

    obj = bpf_object__open("/tmp/xdp_pass_redirect.o");
    if (!obj) {
        fprintf(stderr, "bpf_object__open failed\n");
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

    err = bpf_xdp_attach(ifindex, prog_fd, 0, NULL);
    if (err) {
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
            total += rcvd;
            xsk_ring_cons__release(&info->rx, rcvd);
            /* Return frames to fill ring */
            __u32 idx_fq;
            if (xsk_ring_prod__reserve(&info->fq, rcvd, &idx_fq) == rcvd) {
                for (unsigned int i = 0; i < rcvd; i++) {
                    *xsk_ring_prod__fill_addr(&info->fq, idx_fq + i) =
                        *xsk_ring_cons__comp_addr(&info->rx, idx_rx + i);
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
    if (child == 0) {
        /* Child: send pings to self */
        char ifarg[64];
        snprintf(ifarg, sizeof(ifarg), "-I%s", iface);
        char *ip = "10.0.61.1"; /* adjust if needed */
        execlp("ping", "ping", ifarg, "-i", "0.1", "-c", "50", "-q", ip, NULL);
        _exit(1);
    }

    struct xsk_info info = {};

    printf("\n=== Phase 1: Initial bind (%s) on %s queue %d ===\n", mode, iface, queue);
    if (create_xsk(iface, queue, map_fd, use_copy, &info) < 0) {
        printf("RESULT: FAIL (cannot create XSK)\n");
        goto cleanup;
    }
    unsigned long rx1 = receive_loop(&info, 3);
    printf("Phase 1 rx: %lu\n", rx1);
    destroy_xsk(&info, map_fd, queue);

    printf("\n=== Link DOWN/UP on %s ===\n", iface);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set %s down", iface);
    system(cmd);
    usleep(200000);
    snprintf(cmd, sizeof(cmd), "ip link set %s up", iface);
    system(cmd);
    printf("  waiting 500ms for NIC reinit...\n");
    usleep(500000);

    printf("\n=== Phase 2: Rebind (%s) on %s queue %d ===\n", mode, iface, queue);
    if (create_xsk(iface, queue, map_fd, use_copy, &info) < 0) {
        printf("RESULT: FAIL (cannot rebind XSK)\n");
        goto cleanup;
    }
    unsigned long rx2 = receive_loop(&info, 3);
    printf("Phase 2 rx: %lu\n", rx2);
    destroy_xsk(&info, map_fd, queue);

cleanup:
    kill(child, 9);
    waitpid(child, NULL, 0);
    bpf_xdp_attach(ifindex, -1, 0, NULL);
    printf("  XDP detached\n");

    printf("\n");
    if (rx1 > 0 && rx2 > 0)
        printf("RESULT: PASS  phase1_rx=%lu phase2_rx=%lu\n", rx1, rx2);
    else if (rx1 > 0 && rx2 == 0)
        printf("RESULT: FAIL  (broken after link cycle)  phase1_rx=%lu phase2_rx=0\n", rx1);
    else if (rx1 == 0)
        printf("RESULT: FAIL  (no rx on initial bind)  phase1_rx=0 phase2_rx=%lu\n", rx2);
    else
        printf("RESULT: UNEXPECTED  phase1_rx=%lu phase2_rx=%lu\n", rx1, rx2);

    return (rx1 > 0 && rx2 > 0) ? 0 : 1;
}
