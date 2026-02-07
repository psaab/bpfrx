// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx TC egress connection tracking stage.
 *
 * Looks up existing sessions (v4 and v6) and updates last_seen
 * timestamp and reverse-direction counters for egress packets.
 * Tail-calls to the TC NAT stage.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"
#include "../headers/bpfrx_conntrack.h"

SEC("tc")
int tc_conntrack_prog(struct __sk_buff *skb)
{
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return TC_ACT_SHOT;

	__u64 now = bpf_ktime_get_ns() / 1000000000ULL;

	if (meta->addr_family == AF_INET) {
		/* Build session key from egress packet.
		 * Egress packets are the "reverse" direction of inbound sessions,
		 * so try both forward and reverse lookups. */
		struct session_key fwd_key = {};
		fwd_key.src_ip   = meta->src_ip.v4;
		fwd_key.dst_ip   = meta->dst_ip.v4;
		fwd_key.src_port = meta->src_port;
		fwd_key.dst_port = meta->dst_port;
		fwd_key.protocol = meta->protocol;

		struct session_value *sess = bpf_map_lookup_elem(&sessions, &fwd_key);
		if (sess) {
			sess->last_seen = now;
			__sync_fetch_and_add(&sess->fwd_packets, 1);
			__sync_fetch_and_add(&sess->fwd_bytes, meta->pkt_len);
		} else {
			struct session_key rev_key;
			ct_reverse_key(&fwd_key, &rev_key);
			sess = bpf_map_lookup_elem(&sessions, &rev_key);
			if (sess) {
				sess->last_seen = now;
				__sync_fetch_and_add(&sess->rev_packets, 1);
				__sync_fetch_and_add(&sess->rev_bytes, meta->pkt_len);
			}
		}
	} else {
		/* IPv6 path */
		struct session_key_v6 fwd_key = {};
		__builtin_memcpy(fwd_key.src_ip, meta->src_ip.v6, 16);
		__builtin_memcpy(fwd_key.dst_ip, meta->dst_ip.v6, 16);
		fwd_key.src_port = meta->src_port;
		fwd_key.dst_port = meta->dst_port;
		fwd_key.protocol = meta->protocol;

		struct session_value_v6 *sess = bpf_map_lookup_elem(&sessions_v6, &fwd_key);
		if (sess) {
			sess->last_seen = now;
			__sync_fetch_and_add(&sess->fwd_packets, 1);
			__sync_fetch_and_add(&sess->fwd_bytes, meta->pkt_len);
		} else {
			struct session_key_v6 rev_key;
			ct_reverse_key_v6(&fwd_key, &rev_key);
			sess = bpf_map_lookup_elem(&sessions_v6, &rev_key);
			if (sess) {
				sess->last_seen = now;
				__sync_fetch_and_add(&sess->rev_packets, 1);
				__sync_fetch_and_add(&sess->rev_bytes, meta->pkt_len);
			}
		}
	}

	/* Tail call to NAT stage */
	bpf_tail_call(skb, &tc_progs, TC_PROG_NAT);
	return TC_ACT_OK; /* fallthrough = pass */
}

char _license[] SEC("license") = "GPL";
