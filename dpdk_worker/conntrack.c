/* SPDX-License-Identifier: GPL-2.0-or-later
 * conntrack.c — Connection tracking (replaces xdp_conntrack).
 *
 * Session hash lookup/insert with dual entries (forward + reverse),
 * TCP state tracking, and timeout management.
 */

#include <string.h>

#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_tcp.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"
#include "events.h"

/* TCP option kinds */
#define TCPOPT_NOP     1
#define TCPOPT_MSS     2
#define TCPOPT_MSS_LEN 4

/* Incremental checksum update for 16-bit field (from nat.c) */
static inline void
ct_csum_update_u16(uint16_t *csum, uint16_t old_val, uint16_t new_val)
{
	uint32_t c = (~ntohs(*csum)) & 0xFFFF;
	c += (~ntohs(old_val) & 0xFFFF) + ntohs(new_val);
	c = (c >> 16) + (c & 0xFFFF);
	c += c >> 16;
	*csum = htons(~c & 0xFFFF);
}

/**
 * tcp_mss_clamp — Clamp TCP MSS option on SYN packets.
 *
 * Scans TCP options for MSS (kind=2, length=4). If the current MSS
 * exceeds the configured maximum, overwrites it and updates the TCP
 * checksum incrementally.
 *
 * Reference: bpf/headers/bpfrx_helpers.h tcp_mss_clamp().
 */
void
tcp_mss_clamp(struct rte_mbuf *pkt, struct pkt_meta *meta,
              struct pipeline_ctx *ctx)
{
	if (!ctx->shm->flow_config)
		return;

	struct flow_config *fc = ctx->shm->flow_config;
	uint16_t max_mss = fc->tcp_mss_ipsec;
	if (fc->tcp_mss_gre_in > 0 && (fc->tcp_mss_gre_in < max_mss || max_mss == 0))
		max_mss = fc->tcp_mss_gre_in;

	if (max_mss == 0)
		return;

	uint8_t *data = rte_pktmbuf_mtod(pkt, uint8_t *);
	uint32_t data_len = rte_pktmbuf_data_len(pkt);

	/* Ensure at least TCP header + some options are accessible */
	if (data_len < meta->l4_offset + 60)
		return;

	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(data + meta->l4_offset);
	uint8_t tcp_hdr_len = (tcp->data_off >> 4) * 4;

	/* No options if header length is minimum (20 bytes) */
	if (tcp_hdr_len <= 20)
		return;

	uint16_t opts_len = tcp_hdr_len - 20;
	uint8_t *opt_base = data + meta->l4_offset + 20;

	/* Ensure all options bytes are within packet */
	if (data_len < (uint32_t)(meta->l4_offset + 20 + opts_len))
		return;

	uint16_t *mss_ptr = NULL;

	/* Scan for MSS option (kind=2, length=4) at common positions.
	 * Match the BPF approach: check a few common layouts. */

	/* Position 0: MSS at start of options (most common) */
	if (opts_len >= 4 &&
	    opt_base[0] == TCPOPT_MSS && opt_base[1] == TCPOPT_MSS_LEN) {
		mss_ptr = (uint16_t *)(opt_base + 2);
	}
	/* Position 1: NOP + MSS */
	else if (opts_len >= 5 &&
	         opt_base[0] == TCPOPT_NOP &&
	         opt_base[1] == TCPOPT_MSS && opt_base[2] == TCPOPT_MSS_LEN) {
		mss_ptr = (uint16_t *)(opt_base + 3);
	}
	/* Position 2: NOP + NOP + MSS */
	else if (opts_len >= 6 &&
	         opt_base[0] == TCPOPT_NOP && opt_base[1] == TCPOPT_NOP &&
	         opt_base[2] == TCPOPT_MSS && opt_base[3] == TCPOPT_MSS_LEN) {
		mss_ptr = (uint16_t *)(opt_base + 4);
	}
	/* Position: after SACK_PERM (kind=4, len=2) + MSS */
	else if (opts_len >= 6 &&
	         opt_base[0] == 4 && opt_base[1] == 2 &&
	         opt_base[2] == TCPOPT_MSS && opt_base[3] == TCPOPT_MSS_LEN) {
		mss_ptr = (uint16_t *)(opt_base + 4);
	}

	if (!mss_ptr)
		return;

	/* Ensure mss_ptr + 2 is within packet */
	if ((uint8_t *)(mss_ptr + 1) > data + data_len)
		return;

	uint16_t cur_mss = rte_be_to_cpu_16(*mss_ptr);
	if (cur_mss > max_mss) {
		uint16_t old_mss_be = *mss_ptr;
		uint16_t new_mss_be = rte_cpu_to_be_16(max_mss);
		*mss_ptr = new_mss_be;

		/* Update TCP checksum incrementally */
		ct_csum_update_u16(&tcp->cksum, old_mss_be, new_mss_be);
	}
}

/* Conntrack result codes */
#define CT_NEW         0
#define CT_ESTABLISHED 1
#define CT_INVALID     2
#define CT_DNS_REPLY   3

/**
 * ct_tcp_update_state — TCP state machine transition.
 *
 * Matches the BPF implementation in bpfrx_conntrack.h exactly.
 */
static inline uint8_t
ct_tcp_update_state(uint8_t current_state, uint8_t tcp_flags, uint8_t direction)
{
	uint8_t syn = tcp_flags & 0x02;
	uint8_t ack = tcp_flags & 0x10;
	uint8_t fin = tcp_flags & 0x01;
	uint8_t rst = tcp_flags & 0x04;

	if (rst)
		return SESS_STATE_CLOSED;

	switch (current_state) {
	case SESS_STATE_NEW:
		if (direction == 0 && syn && !ack)
			return SESS_STATE_SYN_SENT;
		break;
	case SESS_STATE_SYN_SENT:
		if (direction == 1 && syn && ack)
			return SESS_STATE_SYN_RECV;
		break;
	case SESS_STATE_SYN_RECV:
		if (direction == 0 && ack)
			return SESS_STATE_ESTABLISHED;
		break;
	case SESS_STATE_ESTABLISHED:
		if (fin)
			return SESS_STATE_FIN_WAIT;
		break;
	case SESS_STATE_FIN_WAIT:
		if (fin)
			return SESS_STATE_CLOSE_WAIT;
		break;
	case SESS_STATE_CLOSE_WAIT:
		if (ack)
			return SESS_STATE_TIME_WAIT;
		break;
	}

	return current_state;
}

/**
 * ct_get_timeout — Get session timeout based on protocol and state.
 */
static inline uint32_t
ct_get_timeout(struct pipeline_ctx *ctx, uint8_t protocol, uint8_t state)
{
	if (!ctx->shm->flow_timeouts)
		return 1800;  /* Default 30 minutes */

	switch (protocol) {
	case PROTO_TCP:
		if (state >= SESS_STATE_ESTABLISHED)
			return ctx->shm->flow_timeouts[FLOW_TIMEOUT_TCP_ESTABLISHED];
		return ctx->shm->flow_timeouts[FLOW_TIMEOUT_TCP_INITIAL];
	case PROTO_UDP:
		return ctx->shm->flow_timeouts[FLOW_TIMEOUT_UDP];
	case PROTO_ICMP:
	case PROTO_ICMPV6:
		return ctx->shm->flow_timeouts[FLOW_TIMEOUT_ICMP];
	default:
		return ctx->shm->flow_timeouts[FLOW_TIMEOUT_OTHER];
	}
}

/**
 * is_icmp_error — Check if the packet is an ICMP error type.
 * ICMPv4: type 3 (dest unreach), 11 (time exceeded), 12 (param problem)
 * ICMPv6: type 1 (dest unreach), 3 (time exceeded), 4 (param problem)
 */
static inline int
is_icmp_error(struct pkt_meta *meta)
{
	if (meta->protocol == PROTO_ICMP)
		return (meta->icmp_type == 3 || meta->icmp_type == 11 ||
		        meta->icmp_type == 12);
	if (meta->protocol == PROTO_ICMPV6)
		return (meta->icmp_type == 1 || meta->icmp_type == 3 ||
		        meta->icmp_type == 4);
	return 0;
}

/**
 * handle_embedded_icmp — Extract the embedded original 5-tuple from an
 * ICMP error packet and look up the corresponding session.
 *
 * ICMP error packets contain the original IP header + first 8 bytes of
 * the original L4 header, starting 8 bytes into the ICMP data.
 *
 * Returns CT_ESTABLISHED if a matching session is found, CT_NEW otherwise.
 */
static inline int
handle_embedded_icmp(struct rte_mbuf *pkt, struct pkt_meta *meta,
                     struct pipeline_ctx *ctx)
{
	uint8_t *data = rte_pktmbuf_mtod(pkt, uint8_t *);
	uint32_t data_len = rte_pktmbuf_data_len(pkt);
	uint64_t now = rte_rdtsc() / rte_get_tsc_hz();

	/* Embedded IP header starts 8 bytes after the ICMP/ICMPv6 header */
	uint16_t emb_ip_off = meta->l4_offset + 8;

	if (meta->addr_family == AF_INET) {
		/* Need at least: embedded IPv4 header (20) + L4 ports (8) */
		if (data_len < (uint32_t)(emb_ip_off + 28))
			return CT_NEW;

		struct rte_ipv4_hdr *emb_ip =
			(struct rte_ipv4_hdr *)(data + emb_ip_off);
		uint8_t emb_proto = emb_ip->next_proto_id;
		uint8_t emb_ihl = (emb_ip->version_ihl & 0x0F);
		if (emb_ihl < 5 || emb_ihl > 15)
			return CT_NEW;

		uint32_t emb_src = emb_ip->src_addr;
		uint32_t emb_dst = emb_ip->dst_addr;

		/* Embedded L4 ports */
		uint16_t emb_l4_off = emb_ip_off + emb_ihl * 4;
		if (data_len < (uint32_t)(emb_l4_off + 4))
			return CT_NEW;

		uint16_t emb_src_port = 0, emb_dst_port = 0;
		if (emb_proto == PROTO_TCP || emb_proto == PROTO_UDP) {
			emb_src_port = *(uint16_t *)(data + emb_l4_off);
			emb_dst_port = *(uint16_t *)(data + emb_l4_off + 2);
		} else if (emb_proto == PROTO_ICMP) {
			if (data_len < (uint32_t)(emb_l4_off + 6))
				return CT_NEW;
			emb_src_port = *(uint16_t *)(data + emb_l4_off + 4);
			emb_dst_port = emb_src_port;
		}

		/* Look up the embedded 5-tuple in the session table */
		struct session_key sk = {
			.src_ip = emb_src,
			.dst_ip = emb_dst,
			.src_port = emb_src_port,
			.dst_port = emb_dst_port,
			.protocol = emb_proto,
		};

		int pos = rte_hash_lookup(ctx->shm->sessions_v4, &sk);
		if (pos < 0) {
			/* Try reverse */
			struct session_key rsk = {
				.src_ip = emb_dst,
				.dst_ip = emb_src,
				.src_port = emb_dst_port,
				.dst_port = emb_src_port,
				.protocol = emb_proto,
			};
			pos = rte_hash_lookup(ctx->shm->sessions_v4, &rsk);
		}
		if (pos < 0)
			return CT_NEW;

		/* Touch session to prevent GC expiry */
		ctx->shm->session_values_v4[pos].last_seen = now;
		return CT_ESTABLISHED;

	} else if (meta->addr_family == AF_INET6) {
		/* Need at least: embedded IPv6 header (40) + L4 ports (8) */
		if (data_len < (uint32_t)(emb_ip_off + 48))
			return CT_NEW;

		struct rte_ipv6_hdr *emb_ip6 =
			(struct rte_ipv6_hdr *)(data + emb_ip_off);
		uint8_t emb_proto = emb_ip6->proto;

		/* Only handle direct L4 protocols (no ext header walking) */
		if (emb_proto != PROTO_TCP && emb_proto != PROTO_UDP &&
		    emb_proto != PROTO_ICMPV6)
			return CT_NEW;

		uint8_t emb_src[16], emb_dst[16];
		memcpy(emb_src, &emb_ip6->src_addr, 16);
		memcpy(emb_dst, &emb_ip6->dst_addr, 16);

		/* Embedded L4 ports (40 bytes after embedded IPv6 header) */
		uint16_t emb_l4_off = emb_ip_off + 40;
		if (data_len < (uint32_t)(emb_l4_off + 4))
			return CT_NEW;

		uint16_t emb_src_port = 0, emb_dst_port = 0;
		if (emb_proto == PROTO_TCP || emb_proto == PROTO_UDP) {
			emb_src_port = *(uint16_t *)(data + emb_l4_off);
			emb_dst_port = *(uint16_t *)(data + emb_l4_off + 2);
		} else if (emb_proto == PROTO_ICMPV6) {
			if (data_len < (uint32_t)(emb_l4_off + 6))
				return CT_NEW;
			emb_src_port = *(uint16_t *)(data + emb_l4_off + 4);
			emb_dst_port = emb_src_port;
		}

		if (!ctx->shm->sessions_v6)
			return CT_NEW;

		/* Look up the embedded 5-tuple in the v6 session table */
		struct session_key_v6 sk6;
		memset(&sk6, 0, sizeof(sk6));
		memcpy(sk6.src_ip, emb_src, 16);
		memcpy(sk6.dst_ip, emb_dst, 16);
		sk6.src_port = emb_src_port;
		sk6.dst_port = emb_dst_port;
		sk6.protocol = emb_proto;

		int pos = rte_hash_lookup(ctx->shm->sessions_v6, &sk6);
		if (pos < 0) {
			/* Try reverse */
			struct session_key_v6 rsk6;
			memset(&rsk6, 0, sizeof(rsk6));
			memcpy(rsk6.src_ip, emb_dst, 16);
			memcpy(rsk6.dst_ip, emb_src, 16);
			rsk6.src_port = emb_dst_port;
			rsk6.dst_port = emb_src_port;
			rsk6.protocol = emb_proto;
			pos = rte_hash_lookup(ctx->shm->sessions_v6, &rsk6);
		}
		if (pos < 0)
			return CT_NEW;

		/* Touch session to prevent GC expiry */
		ctx->shm->session_values_v6[pos].last_seen = now;
		return CT_ESTABLISHED;
	}

	return CT_NEW;
}

/**
 * conntrack_lookup — Look up an existing session for this packet.
 *
 * @pkt:  Packet mbuf
 * @meta: Parsed packet metadata
 * @ctx:  Pipeline context
 *
 * Returns:
 *   CT_ESTABLISHED — Session found and updated (fast path)
 *   CT_NEW         — No session found (needs policy check)
 *   CT_INVALID     — Session found but in invalid state
 *
 * On CT_ESTABLISHED, meta->ct_state, ct_direction, nat_flags,
 * nat_src/dst, policy_id are populated from the session.
 */
int
conntrack_lookup(struct rte_mbuf *pkt, struct pkt_meta *meta,
                 struct pipeline_ctx *ctx)
{
	if (!ctx->shm->sessions_v4)
		return CT_NEW;

	/* allow-embedded-icmp: if this is an ICMP error packet and the
	 * flow config enables embedded ICMP matching, extract the
	 * original 5-tuple and look it up in the session table. */
	if (is_icmp_error(meta) &&
	    ctx->shm->flow_config &&
	    ctx->shm->flow_config->allow_embedded_icmp) {
		int emb_result = handle_embedded_icmp(pkt, meta, ctx);
		if (emb_result == CT_ESTABLISHED)
			return CT_ESTABLISHED;
	}

	uint64_t now = rte_rdtsc() / rte_get_tsc_hz();  /* seconds since boot */

	if (meta->addr_family == AF_INET) {
		struct session_key sk = {
			.src_ip = meta->src_ip.v4,
			.dst_ip = meta->dst_ip.v4,
			.src_port = meta->src_port,
			.dst_port = meta->dst_port,
			.protocol = meta->protocol,
		};

		int pos = rte_hash_lookup(ctx->shm->sessions_v4, &sk);
		if (pos >= 0) {
			struct session_value *sv = &ctx->shm->session_values_v4[pos];
			uint8_t dir = sv->is_reverse ? 1 : 0;

			/* Update timestamps */
			sv->last_seen = now;

			/* TCP state transition */
			if (meta->protocol == PROTO_TCP) {
				uint8_t old_state = sv->state;
				sv->state = ct_tcp_update_state(old_state, meta->tcp_flags, dir);
				if (sv->state != old_state) {
					/* Sync state/timeout to paired entry */
					uint32_t new_timeout = ct_get_timeout(ctx, PROTO_TCP, sv->state);
					sv->timeout = new_timeout;
					int rpos = rte_hash_lookup(ctx->shm->sessions_v4, &sv->reverse_key);
					if (rpos >= 0) {
						struct session_value *rsv = &ctx->shm->session_values_v4[rpos];
						rsv->state = sv->state;
						rsv->timeout = new_timeout;
						rsv->last_seen = now;
					}
				}
				if (sv->state == SESS_STATE_CLOSED ||
				    (sv->state == SESS_STATE_TIME_WAIT && old_state != SESS_STATE_TIME_WAIT)) {
					meta->ingress_zone = sv->ingress_zone;
					meta->egress_zone = sv->egress_zone;
					meta->policy_id = sv->policy_id;
					emit_event_with_stats(ctx, meta, EVENT_TYPE_SESSION_CLOSE,
					                      ACTION_PERMIT,
					                      sv->fwd_packets + sv->rev_packets,
					                      sv->fwd_bytes + sv->rev_bytes);
				}
			}

			/* Update counters */
			if (dir == 0) {
				sv->fwd_packets++;
				sv->fwd_bytes += rte_pktmbuf_pkt_len(pkt);
			} else {
				sv->rev_packets++;
				sv->rev_bytes += rte_pktmbuf_pkt_len(pkt);
			}

			/* Copy session info to meta */
			meta->ct_state = sv->state;
			meta->ct_direction = dir;
			meta->policy_id = sv->policy_id;
			meta->ingress_zone = sv->ingress_zone;
			meta->egress_zone = sv->egress_zone;
			meta->log_flags = sv->log_flags;

			/* NAT info */
			meta->nat_flags = sv->flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT | SESS_FLAG_STATIC_NAT | SESS_FLAG_NAT64);
			meta->nat_src_ip.v4 = sv->nat_src_ip;
			meta->nat_dst_ip.v4 = sv->nat_dst_ip;
			meta->nat_src_port = sv->nat_src_port;
			meta->nat_dst_port = sv->nat_dst_port;

			/* FIB cache */
			if (sv->fib_ifindex != 0 && ctx->shm->fib_gen &&
			    sv->fib_gen == *ctx->shm->fib_gen) {
				meta->fwd_ifindex = sv->fib_ifindex;
				memcpy(meta->fwd_dmac, sv->fib_dmac, 6);
				memcpy(meta->fwd_smac, sv->fib_smac, 6);
			}

			return CT_ESTABLISHED;
		}

		/* Try reverse key */
		struct session_key rsk = {
			.src_ip = meta->dst_ip.v4,
			.dst_ip = meta->src_ip.v4,
			.src_port = meta->dst_port,
			.dst_port = meta->src_port,
			.protocol = meta->protocol,
		};

		pos = rte_hash_lookup(ctx->shm->sessions_v4, &rsk);
		if (pos >= 0) {
			struct session_value *sv = &ctx->shm->session_values_v4[pos];

			sv->last_seen = now;
			if (meta->protocol == PROTO_TCP) {
				uint8_t old_state = sv->state;
				sv->state = ct_tcp_update_state(old_state, meta->tcp_flags, 1);
				if (sv->state != old_state) {
					/* Sync state/timeout to paired entry */
					uint32_t new_timeout = ct_get_timeout(ctx, PROTO_TCP, sv->state);
					sv->timeout = new_timeout;
					int fpos = rte_hash_lookup(ctx->shm->sessions_v4, &sv->reverse_key);
					if (fpos >= 0) {
						struct session_value *fsv = &ctx->shm->session_values_v4[fpos];
						fsv->state = sv->state;
						fsv->timeout = new_timeout;
						fsv->last_seen = now;
					}
				}
				if (sv->state == SESS_STATE_CLOSED ||
				    (sv->state == SESS_STATE_TIME_WAIT && old_state != SESS_STATE_TIME_WAIT)) {
					meta->ingress_zone = sv->egress_zone;
					meta->egress_zone = sv->ingress_zone;
					meta->policy_id = sv->policy_id;
					emit_event_with_stats(ctx, meta, EVENT_TYPE_SESSION_CLOSE,
					                      ACTION_PERMIT,
					                      sv->fwd_packets + sv->rev_packets,
					                      sv->fwd_bytes + sv->rev_bytes);
				}
			}

			sv->rev_packets++;
			sv->rev_bytes += rte_pktmbuf_pkt_len(pkt);

			meta->ct_state = sv->state;
			meta->ct_direction = 1;
			meta->policy_id = sv->policy_id;
			meta->ingress_zone = sv->egress_zone;  /* Swap for reverse */
			meta->egress_zone = sv->ingress_zone;
			meta->log_flags = sv->log_flags;

			meta->nat_flags = sv->flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT | SESS_FLAG_STATIC_NAT | SESS_FLAG_NAT64);
			/* For reverse direction, swap NAT src/dst */
			meta->nat_src_ip.v4 = sv->nat_dst_ip;
			meta->nat_dst_ip.v4 = sv->nat_src_ip;
			meta->nat_src_port = sv->nat_dst_port;
			meta->nat_dst_port = sv->nat_src_port;

			if (sv->fib_ifindex != 0 && ctx->shm->fib_gen &&
			    sv->fib_gen == *ctx->shm->fib_gen) {
				meta->fwd_ifindex = sv->fib_ifindex;
				memcpy(meta->fwd_dmac, sv->fib_dmac, 6);
				memcpy(meta->fwd_smac, sv->fib_smac, 6);
			}

			return CT_ESTABLISHED;
		}
	} else if (meta->addr_family == AF_INET6) {
		/* Same logic but with session_key_v6 and sessions_v6 */
		if (!ctx->shm->sessions_v6)
			return CT_NEW;

		struct session_key_v6 sk6;
		memset(&sk6, 0, sizeof(sk6));
		memcpy(sk6.src_ip, meta->src_ip.v6, 16);
		memcpy(sk6.dst_ip, meta->dst_ip.v6, 16);
		sk6.src_port = meta->src_port;
		sk6.dst_port = meta->dst_port;
		sk6.protocol = meta->protocol;

		int pos = rte_hash_lookup(ctx->shm->sessions_v6, &sk6);
		if (pos >= 0) {
			struct session_value_v6 *sv = &ctx->shm->session_values_v6[pos];
			sv->last_seen = now;
			if (meta->protocol == PROTO_TCP) {
				uint8_t old_state = sv->state;
				uint8_t dir = sv->is_reverse ? 1 : 0;
				sv->state = ct_tcp_update_state(old_state, meta->tcp_flags, dir);
				if (sv->state != old_state) {
					uint32_t new_timeout = ct_get_timeout(ctx, PROTO_TCP, sv->state);
					sv->timeout = new_timeout;
					int rpos = rte_hash_lookup(ctx->shm->sessions_v6, &sv->reverse_key);
					if (rpos >= 0) {
						struct session_value_v6 *rsv = &ctx->shm->session_values_v6[rpos];
						rsv->state = sv->state;
						rsv->timeout = new_timeout;
						rsv->last_seen = now;
					}
				}
				if (sv->state == SESS_STATE_CLOSED ||
				    (sv->state == SESS_STATE_TIME_WAIT && old_state != SESS_STATE_TIME_WAIT)) {
					meta->ingress_zone = sv->ingress_zone;
					meta->egress_zone = sv->egress_zone;
					meta->policy_id = sv->policy_id;
					emit_event_with_stats(ctx, meta, EVENT_TYPE_SESSION_CLOSE,
					                      ACTION_PERMIT,
					                      sv->fwd_packets + sv->rev_packets,
					                      sv->fwd_bytes + sv->rev_bytes);
				}
			}

			if (!sv->is_reverse) {
				sv->fwd_packets++;
				sv->fwd_bytes += rte_pktmbuf_pkt_len(pkt);
			} else {
				sv->rev_packets++;
				sv->rev_bytes += rte_pktmbuf_pkt_len(pkt);
			}

			meta->ct_state = sv->state;
			meta->ct_direction = sv->is_reverse ? 1 : 0;
			meta->policy_id = sv->policy_id;
			meta->ingress_zone = sv->ingress_zone;
			meta->egress_zone = sv->egress_zone;
			meta->log_flags = sv->log_flags;

			meta->nat_flags = sv->flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT | SESS_FLAG_STATIC_NAT | SESS_FLAG_NAT64);
			memcpy(meta->nat_src_ip.v6, sv->nat_src_ip, 16);
			memcpy(meta->nat_dst_ip.v6, sv->nat_dst_ip, 16);
			meta->nat_src_port = sv->nat_src_port;
			meta->nat_dst_port = sv->nat_dst_port;

			if (sv->fib_ifindex != 0 && ctx->shm->fib_gen &&
			    sv->fib_gen == *ctx->shm->fib_gen) {
				meta->fwd_ifindex = sv->fib_ifindex;
				memcpy(meta->fwd_dmac, sv->fib_dmac, 6);
				memcpy(meta->fwd_smac, sv->fib_smac, 6);
			}

			return CT_ESTABLISHED;
		}

		/* Try reverse v6 key */
		struct session_key_v6 rsk6;
		memset(&rsk6, 0, sizeof(rsk6));
		memcpy(rsk6.src_ip, meta->dst_ip.v6, 16);
		memcpy(rsk6.dst_ip, meta->src_ip.v6, 16);
		rsk6.src_port = meta->dst_port;
		rsk6.dst_port = meta->src_port;
		rsk6.protocol = meta->protocol;

		pos = rte_hash_lookup(ctx->shm->sessions_v6, &rsk6);
		if (pos >= 0) {
			struct session_value_v6 *sv = &ctx->shm->session_values_v6[pos];
			sv->last_seen = now;
			if (meta->protocol == PROTO_TCP) {
				uint8_t old_state = sv->state;
				sv->state = ct_tcp_update_state(old_state, meta->tcp_flags, 1);
				if (sv->state != old_state) {
					uint32_t new_timeout = ct_get_timeout(ctx, PROTO_TCP, sv->state);
					sv->timeout = new_timeout;
					int fpos = rte_hash_lookup(ctx->shm->sessions_v6, &sv->reverse_key);
					if (fpos >= 0) {
						struct session_value_v6 *fsv = &ctx->shm->session_values_v6[fpos];
						fsv->state = sv->state;
						fsv->timeout = new_timeout;
						fsv->last_seen = now;
					}
				}
				if (sv->state == SESS_STATE_CLOSED ||
				    (sv->state == SESS_STATE_TIME_WAIT && old_state != SESS_STATE_TIME_WAIT)) {
					meta->ingress_zone = sv->egress_zone;
					meta->egress_zone = sv->ingress_zone;
					meta->policy_id = sv->policy_id;
					emit_event_with_stats(ctx, meta, EVENT_TYPE_SESSION_CLOSE,
					                      ACTION_PERMIT,
					                      sv->fwd_packets + sv->rev_packets,
					                      sv->fwd_bytes + sv->rev_bytes);
				}
			}
			sv->rev_packets++;
			sv->rev_bytes += rte_pktmbuf_pkt_len(pkt);
			meta->ct_state = sv->state;
			meta->ct_direction = 1;
			meta->policy_id = sv->policy_id;
			meta->ingress_zone = sv->egress_zone;  /* Swap for reverse */
			meta->egress_zone = sv->ingress_zone;
			meta->log_flags = sv->log_flags;

			meta->nat_flags = sv->flags & (SESS_FLAG_SNAT | SESS_FLAG_DNAT | SESS_FLAG_STATIC_NAT | SESS_FLAG_NAT64);
			/* For reverse direction, swap NAT src/dst */
			memcpy(meta->nat_src_ip.v6, sv->nat_dst_ip, 16);
			memcpy(meta->nat_dst_ip.v6, sv->nat_src_ip, 16);
			meta->nat_src_port = sv->nat_dst_port;
			meta->nat_dst_port = sv->nat_src_port;
			return CT_ESTABLISHED;
		}
	}

	/* allow-dns-reply: permit unsolicited DNS response packets
	 * (UDP src port 53) without a matching session, bypassing policy. */
	if (meta->protocol == PROTO_UDP &&
	    meta->src_port == rte_cpu_to_be_16(53) &&
	    ctx->shm->flow_config &&
	    ctx->shm->flow_config->allow_dns_reply) {
		return CT_DNS_REPLY;
	}

	return CT_NEW;
}

/**
 * conntrack_create — Create a new session (forward + reverse entries).
 *
 * @pkt:  Packet mbuf
 * @meta: Parsed packet metadata (policy_id, NAT info already set)
 * @ctx:  Pipeline context
 *
 * Returns 0 on success, -1 on failure (table full).
 *
 * Creates dual entries in the session hash:
 *   Forward:  (src, dst, sport, dport, proto) -> session_value
 *   Reverse:  (dst, src, dport, sport, proto) -> session_value (is_reverse=1)
 */
int
conntrack_create(struct rte_mbuf *pkt, struct pkt_meta *meta,
                 struct pipeline_ctx *ctx)
{
	(void)pkt;
	uint64_t now = rte_rdtsc() / rte_get_tsc_hz();

	if (meta->addr_family == AF_INET) {
		if (!ctx->shm->sessions_v4 || !ctx->shm->session_values_v4)
			return -1;

		struct session_key fwd_key = {
			.src_ip = meta->src_ip.v4,
			.dst_ip = meta->dst_ip.v4,
			.src_port = meta->src_port,
			.dst_port = meta->dst_port,
			.protocol = meta->protocol,
		};

		uint8_t init_state = SESS_STATE_NEW;
		if (meta->protocol == PROTO_TCP && (meta->tcp_flags & 0x02))
			init_state = SESS_STATE_SYN_SENT;

		struct session_value fwd_val;
		memset(&fwd_val, 0, sizeof(fwd_val));
		fwd_val.state = init_state;
		fwd_val.flags = meta->nat_flags;
		fwd_val.created = now;
		fwd_val.last_seen = now;
		fwd_val.timeout = (meta->app_timeout > 0) ?
			meta->app_timeout :
			ct_get_timeout(ctx, meta->protocol, init_state);
		fwd_val.policy_id = meta->policy_id;
		fwd_val.ingress_zone = meta->ingress_zone;
		fwd_val.egress_zone = meta->egress_zone;
		fwd_val.nat_src_ip = meta->nat_src_ip.v4;
		fwd_val.nat_dst_ip = meta->nat_dst_ip.v4;
		fwd_val.nat_src_port = meta->nat_src_port;
		fwd_val.nat_dst_port = meta->nat_dst_port;
		fwd_val.log_flags = meta->log_flags;
		fwd_val.is_reverse = 0;

		/* FIB cache: store forwarding result from zone_lookup */
		if (meta->fwd_ifindex != 0 && ctx->shm->fib_gen) {
			fwd_val.fib_ifindex = meta->fwd_ifindex;
			fwd_val.fib_vlan_id = meta->egress_vlan_id;
			memcpy(fwd_val.fib_dmac, meta->fwd_dmac, 6);
			memcpy(fwd_val.fib_smac, meta->fwd_smac, 6);
			fwd_val.fib_gen = (uint16_t)*ctx->shm->fib_gen;
		}

		/* Build reverse key */
		fwd_val.reverse_key.src_ip = meta->dst_ip.v4;
		fwd_val.reverse_key.dst_ip = meta->src_ip.v4;
		fwd_val.reverse_key.src_port = meta->dst_port;
		fwd_val.reverse_key.dst_port = meta->src_port;
		fwd_val.reverse_key.protocol = meta->protocol;

		/* Insert forward entry */
		int pos = rte_hash_add_key(ctx->shm->sessions_v4, &fwd_key);
		if (pos < 0)
			return -1;
		ctx->shm->session_values_v4[pos] = fwd_val;

		/* Insert reverse entry */
		struct session_value rev_val = fwd_val;
		rev_val.is_reverse = 1;
		rev_val.reverse_key = fwd_key;
		/* Swap zones for reverse direction */
		rev_val.ingress_zone = fwd_val.egress_zone;
		rev_val.egress_zone = fwd_val.ingress_zone;
		/* Clear FIB cache (forward path cache is wrong for return) */
		rev_val.fib_ifindex = 0;
		rev_val.fib_vlan_id = 0;
		memset(rev_val.fib_dmac, 0, 6);
		memset(rev_val.fib_smac, 0, 6);
		rev_val.fib_gen = 0;

		int rpos = rte_hash_add_key(ctx->shm->sessions_v4, &fwd_val.reverse_key);
		if (rpos < 0) {
			rte_hash_del_key(ctx->shm->sessions_v4, &fwd_key);
			return -1;
		}
		ctx->shm->session_values_v4[rpos] = rev_val;

		emit_event(ctx, meta, EVENT_TYPE_SESSION_OPEN, ACTION_PERMIT);

	} else if (meta->addr_family == AF_INET6) {
		if (!ctx->shm->sessions_v6 || !ctx->shm->session_values_v6)
			return -1;

		struct session_key_v6 fwd_key6;
		memset(&fwd_key6, 0, sizeof(fwd_key6));
		memcpy(fwd_key6.src_ip, meta->src_ip.v6, 16);
		memcpy(fwd_key6.dst_ip, meta->dst_ip.v6, 16);
		fwd_key6.src_port = meta->src_port;
		fwd_key6.dst_port = meta->dst_port;
		fwd_key6.protocol = meta->protocol;

		uint8_t init_state = SESS_STATE_NEW;
		if (meta->protocol == PROTO_TCP && (meta->tcp_flags & 0x02))
			init_state = SESS_STATE_SYN_SENT;

		struct session_value_v6 fwd_val6;
		memset(&fwd_val6, 0, sizeof(fwd_val6));
		fwd_val6.state = init_state;
		fwd_val6.flags = meta->nat_flags;
		fwd_val6.created = now;
		fwd_val6.last_seen = now;
		fwd_val6.timeout = (meta->app_timeout > 0) ?
			meta->app_timeout :
			ct_get_timeout(ctx, meta->protocol, init_state);
		fwd_val6.policy_id = meta->policy_id;
		fwd_val6.ingress_zone = meta->ingress_zone;
		fwd_val6.egress_zone = meta->egress_zone;
		memcpy(fwd_val6.nat_src_ip, meta->nat_src_ip.v6, 16);
		memcpy(fwd_val6.nat_dst_ip, meta->nat_dst_ip.v6, 16);
		fwd_val6.nat_src_port = meta->nat_src_port;
		fwd_val6.nat_dst_port = meta->nat_dst_port;
		fwd_val6.log_flags = meta->log_flags;
		fwd_val6.is_reverse = 0;

		/* FIB cache: store forwarding result from zone_lookup */
		if (meta->fwd_ifindex != 0 && ctx->shm->fib_gen) {
			fwd_val6.fib_ifindex = meta->fwd_ifindex;
			fwd_val6.fib_vlan_id = meta->egress_vlan_id;
			memcpy(fwd_val6.fib_dmac, meta->fwd_dmac, 6);
			memcpy(fwd_val6.fib_smac, meta->fwd_smac, 6);
			fwd_val6.fib_gen = (uint16_t)*ctx->shm->fib_gen;
		}

		fwd_val6.reverse_key.src_port = meta->dst_port;
		fwd_val6.reverse_key.dst_port = meta->src_port;
		fwd_val6.reverse_key.protocol = meta->protocol;
		memcpy(fwd_val6.reverse_key.src_ip, meta->dst_ip.v6, 16);
		memcpy(fwd_val6.reverse_key.dst_ip, meta->src_ip.v6, 16);

		int pos = rte_hash_add_key(ctx->shm->sessions_v6, &fwd_key6);
		if (pos < 0)
			return -1;
		ctx->shm->session_values_v6[pos] = fwd_val6;

		struct session_value_v6 rev_val6 = fwd_val6;
		rev_val6.is_reverse = 1;
		rev_val6.reverse_key = fwd_key6;
		/* Swap zones for reverse direction */
		rev_val6.ingress_zone = fwd_val6.egress_zone;
		rev_val6.egress_zone = fwd_val6.ingress_zone;
		/* Clear FIB cache (forward path cache is wrong for return) */
		rev_val6.fib_ifindex = 0;
		rev_val6.fib_vlan_id = 0;
		memset(rev_val6.fib_dmac, 0, 6);
		memset(rev_val6.fib_smac, 0, 6);
		rev_val6.fib_gen = 0;

		int rpos = rte_hash_add_key(ctx->shm->sessions_v6, &fwd_val6.reverse_key);
		if (rpos < 0) {
			rte_hash_del_key(ctx->shm->sessions_v6, &fwd_key6);
			return -1;
		}
		ctx->shm->session_values_v6[rpos] = rev_val6;

		emit_event(ctx, meta, EVENT_TYPE_SESSION_OPEN, ACTION_PERMIT);
	}

	return 0;
}
