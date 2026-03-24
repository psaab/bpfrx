/*
 * Test xsk_socket__create_shared specifically.
 * The previous test used xsk_socket__create (non-shared) which worked (rx=3).
 * This test uses create_shared to determine if the shared path has a bug.
 *
 * Build: cc -O2 -o libbpf-xsk-shared-test libbpf_xsk_shared_test.c \
 *        -Wl,-Bstatic -lxdp -lbpf -lelf -lz -lzstd -Wl,-Bdynamic -lpthread
 *
 * Usage: ./libbpf-xsk-shared-test <interface> <queue> [copy|zerocopy]
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

#define FRAME_SIZE  4096
#define NUM_FRAMES  4096
#define BATCH_SIZE  64

static int load_xdp(int ifindex, int *map_fd_out)
{
    struct bpf_object *obj = bpf_object__open("/tmp/xdp_pass_redirect.o");
    if (!obj) { fprintf(stderr, "open failed\n"); return -1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "load failed\n"); return -1; }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_redirect_xsk");
    if (!prog) { fprintf(stderr, "prog not found\n"); return -1; }
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "xsk_map");
    if (!map) { fprintf(stderr, "map not found\n"); return -1; }
    *map_fd_out = bpf_map__fd(map);
    int prog_fd = bpf_program__fd(prog);
    if (bpf_xdp_attach(ifindex, prog_fd, 0, NULL))
        { fprintf(stderr, "attach failed\n"); return -1; }
    return prog_fd;
}

static unsigned long test_phase(const char *label, const char *iface,
    int queue, int map_fd, int use_copy, struct xsk_umem *umem,
    struct xsk_ring_prod *umem_fill, struct xsk_ring_cons *umem_comp,
    void *umem_area)
{
    printf("\n=== %s ===\n", label);

    /* Per-socket rings for create_shared */
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    struct xsk_socket *xsk = NULL;

    struct xsk_socket_config cfg = {
        .rx_size = NUM_FRAMES,
        .tx_size = 256,
        .bind_flags = XDP_USE_NEED_WAKEUP | (use_copy ? XDP_COPY : XDP_ZEROCOPY),
        .libxdp_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = 0,
    };

    int err = xsk_socket__create_shared(&xsk, iface, queue, umem,
                                         &rx, &tx, &fill, &comp, &cfg);
    if (err) {
        fprintf(stderr, "  create_shared failed: %s (rc=%d)\n", strerror(-err), err);
        return 0;
    }
    int xsk_fd = xsk_socket__fd(xsk);
    printf("  create_shared ok, fd=%d %s\n", xsk_fd, use_copy ? "copy" : "zerocopy");

    /* Register in xskmap */
    __u32 key = queue, val = xsk_fd;
    bpf_map_update_elem(map_fd, &key, &val, 0);
    printf("  xskmap[%u] = fd %d\n", key, xsk_fd);

    /* Prime the per-socket fill ring */
    __u32 idx;
    if (xsk_ring_prod__reserve(&fill, NUM_FRAMES, &idx) == NUM_FRAMES) {
        for (int i = 0; i < NUM_FRAMES; i++)
            *xsk_ring_prod__fill_addr(&fill, idx + i) = i * FRAME_SIZE;
        xsk_ring_prod__submit(&fill, NUM_FRAMES);
        printf("  fill ring (per-socket) primed: %d\n", NUM_FRAMES);
    } else {
        printf("  fill ring (per-socket) reserve FAILED\n");
        /* Try umem fill ring as fallback */
        if (xsk_ring_prod__reserve(umem_fill, NUM_FRAMES, &idx) == NUM_FRAMES) {
            for (int i = 0; i < NUM_FRAMES; i++)
                *xsk_ring_prod__fill_addr(umem_fill, idx + i) = i * FRAME_SIZE;
            xsk_ring_prod__submit(umem_fill, NUM_FRAMES);
            printf("  fill ring (umem) primed: %d\n", NUM_FRAMES);
        } else {
            printf("  fill ring (umem) ALSO failed to reserve\n");
        }
    }

    /* Kick NAPI */
    for (int i = 0; i < 20; i++) {
        struct pollfd pfd = { .fd = xsk_fd, .events = POLLIN };
        poll(&pfd, 1, 1);
        sendto(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    }

    /* Receive for 3 seconds */
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    unsigned long total = 0, polls = 0;

    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec)/1e9 >= 3.0)
            break;

        __u32 idx_rx = 0;
        unsigned int rcvd = xsk_ring_cons__peek(&rx, BATCH_SIZE, &idx_rx);
        if (rcvd > 0) {
            total += rcvd;
            xsk_ring_cons__release(&rx, rcvd);
            /* Return to per-socket fill ring */
            __u32 idx_fq;
            if (xsk_ring_prod__reserve(&fill, rcvd, &idx_fq) == rcvd) {
                for (unsigned int i = 0; i < rcvd; i++)
                    *xsk_ring_prod__fill_addr(&fill, idx_fq + i) =
                        *xsk_ring_cons__comp_addr(&rx, idx_rx + i);
                xsk_ring_prod__submit(&fill, rcvd);
            }
        } else {
            polls++;
            struct pollfd pfd = { .fd = xsk_fd, .events = POLLIN };
            poll(&pfd, 1, 10);
        }
    }

    printf("  rx=%lu empty_polls=%lu\n", total, polls);

    /* Cleanup */
    bpf_map_delete_elem(map_fd, &key);
    xsk_socket__delete(xsk);
    return total;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <iface> <queue> [copy|zerocopy]\n", argv[0]);
        return 1;
    }
    const char *iface = argv[1];
    int queue = atoi(argv[2]);
    int use_copy = (argc > 3 && strcmp(argv[3], "copy") == 0);
    int ifindex = if_nametoindex(iface);

    printf("=== xsk_socket__create_shared test ===\n");
    printf("interface=%s queue=%d mode=%s\n", iface, queue,
           use_copy ? "copy" : "zerocopy");

    /* Load XDP program */
    int map_fd;
    if (load_xdp(ifindex, &map_fd) < 0) return 1;

    /* Create UMEM */
    void *umem_area = aligned_alloc(getpagesize(), NUM_FRAMES * FRAME_SIZE);
    struct xsk_ring_prod umem_fill;
    struct xsk_ring_cons umem_comp;
    struct xsk_umem *umem;
    struct xsk_umem_config ucfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 256,
    };
    if (xsk_umem__create(&umem, umem_area,
                          (unsigned long long)NUM_FRAMES * FRAME_SIZE,
                          &umem_fill, &umem_comp, &ucfg)) {
        fprintf(stderr, "umem create failed\n");
        return 1;
    }
    printf("umem created\n");

    /* Start traffic */
    pid_t child = fork();
    if (child == 0) {
        char ifarg[64];
        snprintf(ifarg, sizeof(ifarg), "-I%s", iface);
        execlp("ping", "ping", ifarg, "-i", "0.1", "-c", "50", "-q",
               "10.0.61.1", NULL);
        _exit(1);
    }

    /* Phase 1: create_shared */
    unsigned long rx1 = test_phase("Phase 1: create_shared (initial)",
        iface, queue, map_fd, use_copy, umem, &umem_fill, &umem_comp, umem_area);

    kill(child, 9);
    waitpid(child, NULL, 0);

    /* Detach */
    bpf_xdp_attach(ifindex, -1, 0, NULL);
    xsk_umem__delete(umem);
    free(umem_area);

    printf("\n");
    if (rx1 > 0)
        printf("RESULT: PASS  create_shared rx=%lu\n", rx1);
    else
        printf("RESULT: FAIL  create_shared rx=0\n");

    return rx1 > 0 ? 0 : 1;
}
