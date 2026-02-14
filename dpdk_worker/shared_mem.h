/* SPDX-License-Identifier: GPL-2.0-or-later
 * shared_mem.h — Shared memory layout for Go <-> DPDK worker communication.
 *
 * All structs here mirror the BPF definitions in bpf/headers/bpfrx_common.h
 * and bpf/headers/bpfrx_conntrack.h exactly. The Go control plane populates
 * tables via CGo; the DPDK worker reads them lock-free.
 */

#ifndef DPDK_SHARED_MEM_H
#define DPDK_SHARED_MEM_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_ether.h>

#define SHM_MAGIC   0x42505258  /* "BPRX" */
#define SHM_VERSION 1

/* ============================================================
 * Address family constants (match Linux AF_*)
 * ============================================================ */

#define AF_INET  2
#define AF_INET6 10

/* ============================================================
 * Protocol numbers
 * ============================================================ */

#define PROTO_TCP   6
#define PROTO_UDP   17
#define PROTO_ICMP  1
#define PROTO_ICMPV6 58
#define PROTO_ESP   50
#define PROTO_AH    51
#define PROTO_VRRP  112

/* ============================================================
 * IP address union (matches struct ip_addr in bpfrx_common.h)
 * ============================================================ */

struct ip_addr {
	union {
		uint32_t v4;
		uint8_t  v6[16];
	};
};

/* ============================================================
 * Interface <-> Zone mapping (matches bpfrx_common.h)
 * ============================================================ */

struct iface_zone_key {
	uint32_t ifindex;
	uint16_t vlan_id;
	uint16_t pad;
};

struct iface_zone_value {
	uint16_t zone_id;
	uint16_t pad;
	uint32_t routing_table;
};

/* Reverse mapping: sub-interface -> parent */
struct vlan_iface_info {
	uint32_t parent_ifindex;
	uint16_t vlan_id;
	uint16_t pad;
};

/* ============================================================
 * Zone configuration (matches bpfrx_common.h)
 * ============================================================ */

struct zone_config {
	uint16_t zone_id;
	uint16_t screen_profile_id;
	uint32_t host_inbound_flags;
	uint8_t  tcp_rst;
	uint8_t  pad[3];
};

/* Host-inbound-traffic service flags */
#define HOST_INBOUND_SSH         (1 << 0)
#define HOST_INBOUND_PING        (1 << 1)
#define HOST_INBOUND_DNS         (1 << 2)
#define HOST_INBOUND_HTTP        (1 << 3)
#define HOST_INBOUND_HTTPS       (1 << 4)
#define HOST_INBOUND_DHCP        (1 << 5)
#define HOST_INBOUND_NTP         (1 << 6)
#define HOST_INBOUND_SNMP        (1 << 7)
#define HOST_INBOUND_BGP         (1 << 8)
#define HOST_INBOUND_OSPF        (1 << 9)
#define HOST_INBOUND_TRACEROUTE  (1 << 10)
#define HOST_INBOUND_TELNET      (1 << 11)
#define HOST_INBOUND_FTP         (1 << 12)
#define HOST_INBOUND_NETCONF     (1 << 13)
#define HOST_INBOUND_SYSLOG      (1 << 14)
#define HOST_INBOUND_RADIUS      (1 << 15)
#define HOST_INBOUND_IKE         (1 << 16)
#define HOST_INBOUND_DHCPV6      (1 << 17)
#define HOST_INBOUND_VRRP        (1 << 18)
#define HOST_INBOUND_ESP         (1 << 19)
#define HOST_INBOUND_ALL         0xFFFFFFFF

/* ============================================================
 * Session / conntrack (matches bpfrx_conntrack.h)
 * ============================================================ */

/* Session states */
#define SESS_STATE_NONE        0
#define SESS_STATE_NEW         1
#define SESS_STATE_SYN_SENT    2
#define SESS_STATE_SYN_RECV    3
#define SESS_STATE_ESTABLISHED 4
#define SESS_STATE_FIN_WAIT    5
#define SESS_STATE_CLOSE_WAIT  6
#define SESS_STATE_TIME_WAIT   7
#define SESS_STATE_CLOSED      8

/* Session flags */
#define SESS_FLAG_SNAT       (1 << 0)
#define SESS_FLAG_DNAT       (1 << 1)
#define SESS_FLAG_LOG        (1 << 2)
#define SESS_FLAG_COUNT      (1 << 3)
#define SESS_FLAG_ALG        (1 << 4)
#define SESS_FLAG_PREDICTED  (1 << 5)
#define SESS_FLAG_STATIC_NAT (1 << 6)
#define SESS_FLAG_NAT64      (1 << 7)

/* Log flags */
#define LOG_FLAG_SESSION_INIT  (1 << 0)
#define LOG_FLAG_SESSION_CLOSE (1 << 1)

struct session_key {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  protocol;
	uint8_t  pad[3];
} __attribute__((packed));

struct session_value {
	uint8_t  state;
	uint8_t  flags;
	uint8_t  tcp_state;
	uint8_t  is_reverse;

	uint64_t created;
	uint64_t last_seen;
	uint32_t timeout;
	uint32_t policy_id;

	uint16_t ingress_zone;
	uint16_t egress_zone;

	uint32_t nat_src_ip;
	uint32_t nat_dst_ip;
	uint16_t nat_src_port;
	uint16_t nat_dst_port;

	uint64_t fwd_packets;
	uint64_t fwd_bytes;
	uint64_t rev_packets;
	uint64_t rev_bytes;

	struct session_key reverse_key;

	uint8_t  alg_type;
	uint8_t  log_flags;
	uint8_t  pad[2];

	uint32_t fib_ifindex;
	uint16_t fib_vlan_id;
	uint8_t  fib_dmac[6];
	uint8_t  fib_smac[6];
	uint16_t fib_gen;
};

struct session_key_v6 {
	uint8_t  src_ip[16];
	uint8_t  dst_ip[16];
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  protocol;
	uint8_t  pad[3];
} __attribute__((packed));

struct session_value_v6 {
	uint8_t  state;
	uint8_t  flags;
	uint8_t  tcp_state;
	uint8_t  is_reverse;

	uint64_t created;
	uint64_t last_seen;
	uint32_t timeout;
	uint32_t policy_id;

	uint16_t ingress_zone;
	uint16_t egress_zone;

	uint8_t  nat_src_ip[16];
	uint8_t  nat_dst_ip[16];
	uint16_t nat_src_port;
	uint16_t nat_dst_port;

	uint64_t fwd_packets;
	uint64_t fwd_bytes;
	uint64_t rev_packets;
	uint64_t rev_bytes;

	struct session_key_v6 reverse_key;

	uint8_t  alg_type;
	uint8_t  log_flags;
	uint8_t  pad[2];

	uint32_t fib_ifindex;
	uint16_t fib_vlan_id;
	uint8_t  fib_dmac[6];
	uint8_t  fib_smac[6];
	uint16_t fib_gen;
};

/* ============================================================
 * Policy (matches bpfrx_maps.h)
 * ============================================================ */

/* Policy actions */
#define ACTION_DENY   0
#define ACTION_PERMIT 1
#define ACTION_REJECT 2

struct zone_pair_key {
	uint16_t from_zone;
	uint16_t to_zone;
};

struct policy_set {
	uint32_t policy_set_id;
	uint16_t num_rules;
	uint16_t default_action;
};

struct policy_rule {
	uint32_t rule_id;
	uint32_t policy_set_id;
	uint16_t sequence;
	uint8_t  action;
	uint8_t  log;

	uint32_t src_addr_id;
	uint32_t dst_addr_id;
	uint16_t dst_port_low;
	uint16_t dst_port_high;
	uint8_t  protocol;
	uint8_t  active;
	uint8_t  pad[2];

	uint32_t app_id;
	uint32_t nat_rule_id;
	uint32_t counter_id;
};

/* ============================================================
 * Address book (LPM keys — DPDK uses rte_lpm/rte_lpm6)
 * ============================================================ */

struct addr_value {
	uint32_t address_id;
};

struct addr_membership_key {
	uint32_t ip;
	uint32_t address_id;
};

/* ============================================================
 * Application table (matches bpfrx_maps.h)
 * ============================================================ */

struct app_key {
	uint8_t  protocol;
	uint8_t  pad;
	uint16_t dst_port;
};

struct app_value {
	uint32_t app_id;
	uint8_t  alg_type;
	uint8_t  pad;
	uint16_t timeout;
};

/* ============================================================
 * Screen/IDS configuration (matches bpfrx_common.h)
 * ============================================================ */

/* Screen option flags */
#define SCREEN_SYN_FLOOD       (1 << 0)
#define SCREEN_ICMP_FLOOD      (1 << 1)
#define SCREEN_UDP_FLOOD       (1 << 2)
#define SCREEN_PORT_SCAN       (1 << 3)
#define SCREEN_IP_SWEEP        (1 << 4)
#define SCREEN_LAND_ATTACK     (1 << 5)
#define SCREEN_PING_OF_DEATH   (1 << 6)
#define SCREEN_TEAR_DROP       (1 << 7)
#define SCREEN_TCP_SYN_FIN     (1 << 8)
#define SCREEN_TCP_NO_FLAG     (1 << 9)
#define SCREEN_TCP_FIN_NO_ACK  (1 << 10)
#define SCREEN_WINNUKE         (1 << 11)
#define SCREEN_IP_SOURCE_ROUTE (1 << 12)
#define SCREEN_SYN_FRAG        (1 << 13)

struct screen_config {
	uint32_t flags;
	uint32_t syn_flood_thresh;
	uint32_t icmp_flood_thresh;
	uint32_t udp_flood_thresh;
	uint32_t syn_flood_src_thresh;
	uint32_t syn_flood_dst_thresh;
	uint32_t syn_flood_timeout;
};

struct flood_state {
	uint64_t syn_count;
	uint64_t icmp_count;
	uint64_t udp_count;
	uint64_t window_start;
};

/* ============================================================
 * NAT (matches bpfrx_maps.h)
 * ============================================================ */

#define MAX_NAT_POOL_IPS_PER_POOL 8
#define SNAT_MODE_OFF             0xFF
#define MAX_SNAT_RULES_PER_PAIR   8

struct nat_pool_config {
	uint16_t num_ips;
	uint16_t num_ips_v6;
	uint16_t port_low;
	uint16_t port_high;
	uint8_t  addr_persistent;
	uint8_t  pad[3];
};

struct nat_pool_ip_v6 {
	uint8_t ip[16];
};

struct dnat_key {
	uint8_t  protocol;
	uint8_t  pad[3];
	uint32_t dst_ip;
	uint16_t dst_port;
	uint16_t pad2;
};

struct dnat_value {
	uint32_t new_dst_ip;
	uint16_t new_dst_port;
	uint8_t  flags;
	uint8_t  pad;
};

struct dnat_key_v6 {
	uint8_t  protocol;
	uint8_t  pad[3];
	uint8_t  dst_ip[16];
	uint16_t dst_port;
	uint16_t pad2;
};

struct dnat_value_v6 {
	uint8_t  new_dst_ip[16];
	uint16_t new_dst_port;
	uint8_t  flags;
	uint8_t  pad;
};

struct snat_key {
	uint16_t from_zone;
	uint16_t to_zone;
	uint16_t rule_idx;
	uint16_t pad;
};

struct snat_value {
	uint32_t snat_ip;
	uint32_t src_addr_id;
	uint32_t dst_addr_id;
	uint8_t  mode;
	uint8_t  pad;
	uint16_t counter_id;
};

struct snat_value_v6 {
	uint8_t  snat_ip[16];
	uint32_t src_addr_id;
	uint32_t dst_addr_id;
	uint8_t  mode;
	uint8_t  pad;
	uint16_t counter_id;
};

/* Static 1:1 NAT */
#define STATIC_NAT_DNAT 0
#define STATIC_NAT_SNAT 1

struct static_nat_key_v4 {
	uint32_t ip;
	uint8_t  direction;
	uint8_t  pad[3];
};

struct static_nat_key_v6 {
	uint8_t ip[16];
	uint8_t direction;
	uint8_t pad[3];
};

struct static_nat_value_v6 {
	uint8_t ip[16];
};

/* ============================================================
 * NAT64 (matches bpfrx_common.h)
 * ============================================================ */

struct nat64_prefix_key {
	uint32_t prefix[3];
};

struct nat64_config {
	uint32_t prefix[3];
	uint8_t  snat_pool_id;
	uint8_t  pad[3];
};

struct nat64_state_key {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  protocol;
	uint8_t  pad[3];
};

struct nat64_state_value {
	uint8_t  orig_src_v6[16];
	uint8_t  orig_dst_v6[16];
	uint16_t orig_src_port;
	uint16_t orig_dst_port;
	uint32_t nat64_idx;
};

/* ============================================================
 * Firewall filter (matches bpfrx_common.h / bpfrx_maps.h)
 * ============================================================ */

/* Filter match flags */
#define FILTER_MATCH_DSCP       (1 << 0)
#define FILTER_MATCH_PROTOCOL   (1 << 1)
#define FILTER_MATCH_SRC_ADDR   (1 << 2)
#define FILTER_MATCH_DST_ADDR   (1 << 3)
#define FILTER_MATCH_DST_PORT   (1 << 4)
#define FILTER_MATCH_ICMP_TYPE  (1 << 5)
#define FILTER_MATCH_ICMP_CODE  (1 << 6)
#define FILTER_MATCH_SRC_PORT   (1 << 7)
#define FILTER_MATCH_SRC_NEGATE (1 << 8)
#define FILTER_MATCH_DST_NEGATE (1 << 9)

/* Filter actions */
#define FILTER_ACTION_ACCEPT  0
#define FILTER_ACTION_DISCARD 1
#define FILTER_ACTION_REJECT  2
#define FILTER_ACTION_ROUTE   3

struct filter_config {
	uint32_t num_rules;
	uint32_t rule_start;
};

struct iface_filter_key {
	uint32_t ifindex;
	uint16_t vlan_id;
	uint8_t  family;
	uint8_t  direction;
};

struct filter_rule {
	uint16_t match_flags;
	uint8_t  dscp;
	uint8_t  protocol;
	uint8_t  action;
	uint8_t  icmp_type;
	uint8_t  icmp_code;
	uint8_t  family;
	uint16_t dst_port;
	uint16_t src_port;
	uint16_t dst_port_hi;
	uint16_t src_port_hi;
	uint8_t  dscp_rewrite;
	uint8_t  log_flag;
	uint8_t  src_addr[16];
	uint8_t  src_mask[16];
	uint8_t  dst_addr[16];
	uint8_t  dst_mask[16];
	uint32_t routing_table;
};

/* ============================================================
 * Counter values (matches bpfrx_common.h)
 * ============================================================ */

struct counter_value {
	uint64_t packets;
	uint64_t bytes;
};

struct iface_counter_value {
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
};

/* ============================================================
 * Flow configuration (matches bpfrx_common.h)
 * ============================================================ */

struct flow_config {
	uint16_t tcp_mss_ipsec;
	uint16_t tcp_mss_gre_in;
	uint16_t tcp_mss_gre_out;
	uint8_t  allow_dns_reply;
	uint8_t  allow_embedded_icmp;
	uint8_t  gre_accel;
	uint8_t  alg_flags;
};

/* ============================================================
 * FIB next-hop entry (populated by Go control plane)
 * ============================================================ */

#define MAX_NEXTHOPS        4096
#define MAX_PORT_MAP        256   /* ifindex -> DPDK port_id mapping */

struct fib_nexthop {
	uint32_t port_id;     /* DPDK port ID for TX */
	uint32_t ifindex;     /* kernel ifindex (for zone lookup) */
	uint16_t vlan_id;     /* egress VLAN ID (0 = untagged) */
	uint8_t  dmac[6];     /* next-hop destination MAC */
	uint8_t  smac[6];     /* source MAC of egress port */
	uint8_t  pad[2];
};

/* ============================================================
 * Event structure for ring buffer export
 * ============================================================ */

#define EVENT_TYPE_SESSION_OPEN  1
#define EVENT_TYPE_SESSION_CLOSE 2
#define EVENT_TYPE_POLICY_DENY   3
#define EVENT_TYPE_SCREEN_DROP   4
#define EVENT_TYPE_ALG_REQUEST   5
#define EVENT_TYPE_FILTER_LOG    6

struct event {
	uint64_t timestamp;
	uint8_t  src_ip[16];
	uint8_t  dst_ip[16];
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t policy_id;
	uint16_t ingress_zone;
	uint16_t egress_zone;
	uint8_t  event_type;
	uint8_t  protocol;
	uint8_t  action;
	uint8_t  addr_family;
	uint64_t session_packets;
	uint64_t session_bytes;
};

/* ============================================================
 * Packet metadata (mirrors struct pkt_meta in bpfrx_common.h)
 * Passed through the userspace pipeline by reference.
 * ============================================================ */

struct pkt_meta {
	struct ip_addr src_ip;
	struct ip_addr dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  protocol;
	uint8_t  tcp_flags;
	uint8_t  ip_ttl;
	uint8_t  addr_family;
	uint8_t  dscp;
	uint8_t  csum_partial;
	uint8_t  meta_flags;
	uint8_t  embedded_proto;

	uint16_t icmp_id;
	uint8_t  icmp_type;
	uint8_t  icmp_code;

	uint32_t tcp_seq;
	uint32_t tcp_ack_seq;

	uint16_t l3_offset;
	uint16_t l4_offset;
	uint16_t payload_offset;
	uint16_t pkt_len;

	uint16_t ingress_zone;
	uint16_t egress_zone;
	uint32_t ingress_ifindex;
	uint16_t ingress_vlan_id;
	uint16_t egress_vlan_id;

	uint8_t  direction;
	uint8_t  is_fragment;
	uint8_t  ct_state;
	uint8_t  ct_direction;

	uint32_t policy_id;

	struct ip_addr nat_src_ip;
	struct ip_addr nat_dst_ip;
	uint16_t nat_src_port;
	uint16_t nat_dst_port;
	uint32_t nat_flags;

	uint32_t fwd_ifindex;
	uint8_t  fwd_dmac[6];
	uint8_t  fwd_smac[6];

	uint32_t routing_table;

	uint8_t  dscp_rewrite;
	uint8_t  ip_ihl;

	uint16_t app_timeout;
};

/* ============================================================
 * Shared memory root — mmap'd hugepage region.
 * Go control plane writes tables; DPDK worker reads them.
 * ============================================================ */

struct lcore_counters;

struct shared_memory {
	/* Magic and version for validation */
	uint32_t magic;
	uint32_t version;

	/* Volatile flag: Go sets to signal config update */
	volatile uint32_t config_generation;
	uint32_t pad;

	/* RX mode (set by Go, read by worker) */
	volatile uint32_t rx_mode;
	volatile uint32_t shutdown;  /* 1 = graceful shutdown requested */

	/* Table pointers — set by allocator, stable for lifetime */
	/* Hash tables (rte_hash handles) */
	struct rte_hash *sessions_v4;
	struct rte_hash *sessions_v6;
	struct rte_hash *iface_zone_map;
	struct rte_hash *zone_pair_policies;
	struct rte_hash *applications;
	struct rte_hash *dnat_table;
	struct rte_hash *dnat_table_v6;
	struct rte_hash *snat_rules;
	struct rte_hash *snat_rules_v6;
	struct rte_hash *static_nat_v4;
	struct rte_hash *static_nat_v6;
	struct rte_hash *address_membership;
	struct rte_hash *iface_filter_map;
	struct rte_hash *nat64_prefix_map;
	struct rte_hash *nat64_state;

	/* LPM tries */
	struct rte_lpm  *address_book_v4;
	struct rte_lpm6 *address_book_v6;

	/* FIB routing tables (populated by Go control plane) */
	struct rte_lpm  *fib_v4;         /* IPv4 FIB: prefix -> nexthop_id */
	struct rte_lpm6 *fib_v6;         /* IPv6 FIB: prefix -> nexthop_id */
	struct fib_nexthop *nexthops;    /* [MAX_NEXTHOPS] next-hop entries */
	volatile uint32_t  nexthop_count;
	uint32_t pad_fib;

	/* Array tables (direct pointers into hugepage) */
	struct zone_config      *zone_configs;
	struct policy_rule      *policy_rules;
	struct screen_config    *screen_configs;
	struct nat_pool_config  *nat_pool_configs;
	uint32_t                *nat_pool_ips_v4;
	struct nat_pool_ip_v6   *nat_pool_ips_v6;
	struct nat64_config     *nat64_configs;
	struct filter_config    *filter_configs;
	struct filter_rule      *filter_rules;
	struct flow_config      *flow_config;
	uint32_t                *flow_timeouts;
	uint8_t                 *default_policy;
	uint32_t                *fib_gen;

	/* Session value arrays (indexed by rte_hash position) */
	struct session_value    *session_values_v4;
	struct session_value_v6 *session_values_v6;

	/* Hash value arrays for other tables */
	struct iface_zone_value *iface_zone_values;
	struct policy_set       *zone_pair_values;
	struct app_value        *app_values;
	struct dnat_value       *dnat_values;
	struct dnat_value_v6    *dnat_values_v6;
	struct snat_value       *snat_values_v4;
	struct snat_value_v6    *snat_values_v6;

	/* Event ring (DPDK worker -> Go) */
	struct rte_ring *event_ring;

	/* Flood state (per-zone, per-lcore) */
	struct flood_state *flood_states;  /* [MAX_LCORES][MAX_ZONES] */

	/* Per-lcore counter pointers (for Go secondary process to aggregate) */
	struct lcore_counters *counter_ptrs[64];  /* MAX_LCORES */
};

#endif /* DPDK_SHARED_MEM_H */
