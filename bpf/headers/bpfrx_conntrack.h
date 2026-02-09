#ifndef __BPFRX_CONNTRACK_H__
#define __BPFRX_CONNTRACK_H__

#include "bpfrx_common.h"

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
	__u8  flags;           /* SESS_FLAG_* */
	__u8  tcp_state;       /* TCP-specific sub-state */
	__u8  is_reverse;      /* 1 if this is the reverse direction entry */

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
	__u8  pad[2];
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
	__u8  flags;           /* SESS_FLAG_* */
	__u8  tcp_state;       /* TCP-specific sub-state */
	__u8  is_reverse;      /* 1 if this is the reverse direction entry */

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
	__u8  pad[2];
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
