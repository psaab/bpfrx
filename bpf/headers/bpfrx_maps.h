#ifndef __BPFRX_MAPS_H__
#define __BPFRX_MAPS_H__

#include "bpfrx_common.h"
#include "bpfrx_conntrack.h"

/* ============================================================
 * Tail call program arrays
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, XDP_PROG_MAX);
	__type(key, __u32);
	__type(value, __u32);
} xdp_progs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, TC_PROG_MAX);
	__type(key, __u32);
	__type(value, __u32);
} tc_progs SEC(".maps");

/* ============================================================
 * Per-CPU scratch space for passing metadata between tail calls
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pkt_meta);
} pkt_meta_scratch SEC(".maps");

/* ============================================================
 * Session table (connection tracking)
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SESSIONS);
	__type(key, struct session_key);
	__type(value, struct session_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} sessions SEC(".maps");

/* ============================================================
 * Zone configuration
 * ============================================================ */

/* Interface ifindex -> zone_id */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_INTERFACES);
	__type(key, __u32);
	__type(value, __u16);
} iface_zone_map SEC(".maps");

/* zone_id -> zone_config */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_ZONES);
	__type(key, __u32);
	__type(value, struct zone_config);
} zone_configs SEC(".maps");

/* ============================================================
 * Policy lookup
 *
 * Two-level:
 *   1. (from_zone, to_zone) -> policy_set via zone_pair_policies
 *   2. policy_set_id * MAX_RULES_PER_POLICY + index -> policy_rule
 * ============================================================ */

struct zone_pair_key {
	__u16 from_zone;
	__u16 to_zone;
};

struct policy_set {
	__u32 policy_set_id;
	__u16 num_rules;
	__u16 default_action;
};

struct policy_rule {
	__u32 rule_id;
	__u32 policy_set_id;
	__u16 sequence;
	__u8  action;     /* ACTION_* */
	__u8  log;

	/* Match criteria -- 0 means "any" */
	__u32 src_addr_id;
	__u32 dst_addr_id;
	__u16 dst_port_low;
	__u16 dst_port_high;
	__u8  protocol;   /* 0 = any */
	__u8  pad[3];

	__u32 app_id;
	__u32 nat_rule_id;
	__u32 counter_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ZONES * MAX_ZONES);
	__type(key, struct zone_pair_key);
	__type(value, struct policy_set);
} zone_pair_policies SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_POLICIES * MAX_RULES_PER_POLICY);
	__type(key, __u32);
	__type(value, struct policy_rule);
} policy_rules SEC(".maps");

/* ============================================================
 * Address book -- LPM trie for prefix matching
 * ============================================================ */

struct lpm_key_v4 {
	__u32 prefixlen;
	__be32 addr;
};

struct addr_value {
	__u32 address_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_ADDRESSES);
	__type(key, struct lpm_key_v4);
	__type(value, struct addr_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} address_book_v4 SEC(".maps");

/* Address membership: (ip, address_id) -> exists */
struct addr_membership_key {
	__be32 ip;
	__u32  address_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ADDRESSES * 8);
	__type(key, struct addr_membership_key);
	__type(value, __u8);
} address_membership SEC(".maps");

/* ============================================================
 * Application table
 * ============================================================ */

struct app_key {
	__u8  protocol;
	__u8  pad;
	__be16 dst_port;
};

struct app_value {
	__u32 app_id;
	__u8  alg_type; /* 0=none */
	__u8  pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_APPLICATIONS);
	__type(key, struct app_key);
	__type(value, struct app_value);
} applications SEC(".maps");

/* ============================================================
 * Counters & statistics (per-CPU for lock-free increments)
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_POLICIES);
	__type(key, __u32);
	__type(value, struct counter_value);
} policy_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_ZONES);
	__type(key, __u32);
	__type(value, struct counter_value);
} zone_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, GLOBAL_CTR_MAX);
	__type(key, __u32);
	__type(value, __u64);
} global_counters SEC(".maps");

/* ============================================================
 * Forwarding -- device map for XDP_REDIRECT
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(max_entries, MAX_INTERFACES);
	__type(key, __u32);
	__type(value, struct bpf_devmap_val);
} tx_ports SEC(".maps");

/* ============================================================
 * Event ring buffer (kernel -> userspace)
 * ============================================================ */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1MB */
} events SEC(".maps");

/* ============================================================
 * NAT tables
 * ============================================================ */

/* Pre-routing NAT table: (proto, dst_ip, dst_port) -> new destination.
 * Used for both static DNAT entries (from config) and dynamic SNAT
 * return entries (created by xdp_policy when SNAT session is established). */
struct dnat_key {
	__u8   protocol;
	__u8   pad[3];
	__be32 dst_ip;
	__be16 dst_port;
	__be16 pad2;
};

struct dnat_value {
	__be32 new_dst_ip;
	__be16 new_dst_port;
	__u8   flags;       /* 0=dynamic/SNAT-return, 1=static/DNAT-config */
	__u8   pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SESSIONS);
	__type(key, struct dnat_key);
	__type(value, struct dnat_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} dnat_table SEC(".maps");

/* Source NAT config: (from_zone, to_zone) -> SNAT IP.
 * Populated by the compiler on commit. */
struct snat_key {
	__u16 from_zone;
	__u16 to_zone;
};

struct snat_value {
	__be32 snat_ip;
	__u8   mode;        /* 0=interface */
	__u8   pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ZONES * MAX_ZONES);
	__type(key, struct snat_key);
	__type(value, struct snat_value);
} snat_rules SEC(".maps");

#endif /* __BPFRX_MAPS_H__ */
