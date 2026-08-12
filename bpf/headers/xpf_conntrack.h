#ifndef __BPFRX_CONNTRACK_H__
#define __BPFRX_CONNTRACK_H__

#include "xpf_common.h"

/* Session key -- 5-tuple. Both forward and reverse entries stored. */
struct session_key {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	__u8   protocol;
	__u8   pad[3];
} __attribute__((packed));

/* Session value -- full connection state. */
struct session_value {
	/* Connection state */
	__u8  state;           /* SESS_STATE_* */
	__u16 flags;           /* SESS_FLAG_* -- __u16: SESS_FLAG_NPTV6 is bit 8
				* (0x100), which does not fit a __u8 (#5460). The
				* compiler inserts one pad byte after `state` and
				* two after `is_reverse`; the C/Rust/Go layouts
				* stay byte-identical (size-asserted 144/192 -- 136/184
				* before #4983 appended the ingress-identity pair). */
	__u8  tcp_state;       /* TCP-specific sub-state */
	__u8  is_reverse;      /* 1 if this is the reverse direction entry */
	__u32 app_timeout;     /* per-application inactivity timeout (seconds), 0=use default */

	__u64 session_id;      /* unique ID, same on both cluster nodes */

	/* Timestamps (seconds since boot) */
	__u64 created;
	__u64 last_seen;
	__u32 timeout;         /* idle timeout in seconds */
	__u32 policy_id;

	/* Zone info */
	__u16 ingress_zone;
	__u16 egress_zone;

	/* NAT translations (original -> translated) */
	__be32 nat_src_ip;
	__be32 nat_dst_ip;
	__be16 nat_src_port;
	__be16 nat_dst_port;

	/* Counters -- forward direction */
	__u64 fwd_packets;
	__u64 fwd_bytes;

	/* Counters -- reverse direction */
	__u64 rev_packets;
	__u64 rev_bytes;

	/* Reverse key for paired entry deletion */
	struct session_key reverse_key;

	/* ALG tracking */
	__u8  alg_type;    /* 0=none, 1=FTP, 2=SIP, 3=DNS */
	__u8  log_flags;
	__u16 app_id;      /* application ID for structured logging */

	/* Cached FIB result (set by xdp_zone, 0 = not cached) */
	__u32 fib_ifindex;
	__u16 fib_vlan_id;
	__u8  fib_dmac[6];
	__u8  fib_smac[6];
	__u16 fib_gen;      /* FIB cache generation (matches fib_gen_map[0]) */

	/* #4983: the ifindex of the binding the session's FIRST packet arrived
	 * on -- the session's TRUE ingress-interface identity, stamped once at
	 * install and never re-derived. Distinct from fib_ifindex above, which
	 * is the resolved EGRESS. 0 means "no ingress identity carried" and is
	 * NOT a valid ifindex: the reverse companion (whose real ingress is the
	 * forward flow's egress, unknown at install), an HA peer-synced session
	 * (an ifindex is node-local -- the peer's number names a different NIC
	 * here), and any pre-#4983 helper all leave it 0. Consumers MUST treat
	 * 0 as "fall back to the zone approximation", never as "matches
	 * nothing" or "matches everything". */
	__u32 ingress_ifindex;
	/* #4983: the 802.1Q VLAN id the session's first packet arrived with, 0
	 * for untagged. Paired with ingress_ifindex it names the LOGICAL ingress
	 * unit -- the same {parent ifindex, vlan} identity the egress side is
	 * already resolved by (fib_ifindex/fib_vlan_id), so two units of one
	 * trunk NIC are distinguishable. The struct tail-pads 2 bytes to its
	 * 8-byte alignment: sizeof grows 136 -> 144, not 136 -> 152. */
	__u16 ingress_vlan_id;
};

/* IPv6 session key -- 5-tuple with 128-bit addresses. */
struct session_key_v6 {
	__u8   src_ip[16];
	__u8   dst_ip[16];
	__be16 src_port;
	__be16 dst_port;
	__u8   protocol;
	__u8   pad[3];
} __attribute__((packed));

/* IPv6 session value -- full connection state with 128-bit addresses. */
struct session_value_v6 {
	/* Connection state */
	__u8  state;           /* SESS_STATE_* */
	__u16 flags;           /* SESS_FLAG_* -- __u16 (see session_value.flags,
				* #5460): SESS_FLAG_NPTV6 (bit 8) overflows __u8. */
	__u8  tcp_state;       /* TCP-specific sub-state */
	__u8  is_reverse;      /* 1 if this is the reverse direction entry */
	__u32 app_timeout;     /* per-application inactivity timeout (seconds), 0=use default */

	__u64 session_id;      /* unique ID, same on both cluster nodes */

	/* Timestamps (seconds since boot) */
	__u64 created;
	__u64 last_seen;
	__u32 timeout;         /* idle timeout in seconds */
	__u32 policy_id;

	/* Zone info */
	__u16 ingress_zone;
	__u16 egress_zone;

	/* NAT translations (original -> translated) */
	__u8  nat_src_ip[16];
	__u8  nat_dst_ip[16];
	__be16 nat_src_port;
	__be16 nat_dst_port;

	/* Counters -- forward direction */
	__u64 fwd_packets;
	__u64 fwd_bytes;

	/* Counters -- reverse direction */
	__u64 rev_packets;
	__u64 rev_bytes;

	/* Reverse key for paired entry deletion */
	struct session_key_v6 reverse_key;

	/* ALG tracking */
	__u8  alg_type;    /* 0=none, 1=FTP, 2=SIP, 3=DNS */
	__u8  log_flags;
	__u16 app_id;      /* application ID for structured logging */

	/* Cached FIB result (set by xdp_zone, 0 = not cached) */
	__u32 fib_ifindex;
	__u16 fib_vlan_id;
	__u8  fib_dmac[6];
	__u8  fib_smac[6];
	__u16 fib_gen;      /* FIB cache generation (matches fib_gen_map[0]) */

	/* #4983: ingress-binding ifindex -- see session_value.ingress_ifindex
	 * for the full contract (0 = no identity carried, fall back to the
	 * zone approximation). */
	__u32 ingress_ifindex;
	/* #4983: ingress 802.1Q VLAN id, 0 = untagged -- see
	 * session_value.ingress_vlan_id. sizeof grows 184 -> 192. */
	__u16 ingress_vlan_id;
};

/* TCP state machine transition. Returns new state. */
static __always_inline __u8
ct_tcp_update_state(__u8 current_state, __u8 tcp_flags, __u8 direction)
{
	__u8 syn = tcp_flags & 0x02;
	__u8 ack = tcp_flags & 0x10;
	__u8 fin = tcp_flags & 0x01;
	__u8 rst = tcp_flags & 0x04;

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

/* Get default session timeout based on protocol and state. */
static __always_inline __u32
ct_get_timeout_default(__u8 protocol, __u8 state)
{
	switch (protocol) {
	case PROTO_TCP:
		switch (state) {
		case SESS_STATE_NEW:
		case SESS_STATE_SYN_SENT:
		case SESS_STATE_SYN_RECV:
			return 30;
		case SESS_STATE_ESTABLISHED:
			return 1800;
		case SESS_STATE_FIN_WAIT:
		case SESS_STATE_CLOSE_WAIT:
			return 30;
		case SESS_STATE_TIME_WAIT:
			return 120;
		default:
			return 10;
		}
	case PROTO_UDP:
		return 60;
	case PROTO_ICMP:
	case PROTO_ICMPV6:
		return 30;
	default:
		return 30;
	}
}

/* Build reverse session key (IPv4). */
static __always_inline void
ct_reverse_key(const struct session_key *fwd, struct session_key *rev)
{
	rev->src_ip   = fwd->dst_ip;
	rev->dst_ip   = fwd->src_ip;
	rev->src_port = fwd->dst_port;
	rev->dst_port = fwd->src_port;
	rev->protocol = fwd->protocol;
	rev->pad[0] = rev->pad[1] = rev->pad[2] = 0;
}

/* Build reverse session key (IPv6). */
static __always_inline void
ct_reverse_key_v6(const struct session_key_v6 *fwd, struct session_key_v6 *rev)
{
	__builtin_memcpy(rev->src_ip, fwd->dst_ip, 16);
	__builtin_memcpy(rev->dst_ip, fwd->src_ip, 16);
	rev->src_port = fwd->dst_port;
	rev->dst_port = fwd->src_port;
	rev->protocol = fwd->protocol;
	rev->pad[0] = rev->pad[1] = rev->pad[2] = 0;
}

#endif /* __BPFRX_CONNTRACK_H__ */
