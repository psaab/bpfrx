// Minimal XDP program: redirect all packets to xskmap slot = rx_queue_index.
// Compile: clang -O2 -g -target bpf -c xdp_pass_redirect.c -o xdp_pass_redirect.o

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsk_map SEC(".maps");

SEC("xdp")
int xdp_redirect_xsk(struct xdp_md *ctx)
{
    __u32 queue = ctx->rx_queue_index;
    // Try redirect to XSK. If no socket registered, pass to kernel.
    if (bpf_map_lookup_elem(&xsk_map, &queue))
        return bpf_redirect_map(&xsk_map, queue, XDP_PASS);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
