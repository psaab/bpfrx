#ifndef __BPFRX_COMMON_H__
#define __BPFRX_COMMON_H__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ============================================================
 * Network header definitions for BPF programs.
 * We define these directly to avoid pulling in userspace headers
 * (linux/icmp.h -> linux/if.h -> sys/socket.h) which don't
 * compile under BPF cross-compilation.
 * ============================================================ */

#ifndef AF_INET
#define AF_INET 2
#endif

#define AF_INET6        10

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

/* IPv6 extension header next-header values */
#define PROTO_ICMPV6    58
#define NEXTHDR_HOP     0
#define NEXTHDR_ROUTING 43
#define NEXTHDR_FRAGMENT 44
#define NEXTHDR_AUTH    51
#define NEXTHDR_DEST    60
#define NEXTHDR_NONE    59
#define MAX_EXT_HDRS    6

struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8  ihl:4, version:4;
#else
	__u8  version:4, ihl:4;
#endif
	__u8  tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8  ttl;
	__u8  protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u16 res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#else
	__u16 doff:4, res1:4, cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#endif
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
};

struct icmphdr {
	__u8  type;
	__u8  code;
	__sum16 checksum;
	union {
		struct {
			__be16 id;
			__be16 sequence;
		} echo;
		__be32 gateway;
		struct {
			__be16 __unused;
			__be16 mtu;
		} frag;
	} un;
};

/* IPv6 header structures */
struct in6_addr {
	union {
		__u8   u6_addr8[16];
		__be32 u6_addr32[4];
	};
};

struct ipv6hdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8 priority:4, version:4;
#else
	__u8 version:4, priority:4;
#endif
	__u8  flow_lbl[3];
	__be16 payload_len;
	__u8  nexthdr;
	__u8  hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
};

struct ipv6_opt_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
};

struct frag_hdr {
	__u8   nexthdr;
	__u8   reserved;
	__be16 frag_off;
	__be32 identification;
};

struct icmp6hdr {
	__u8    icmp6_type;
	__u8    icmp6_code;
	__sum16 icmp6_cksum;
	union {
		struct { __be16 id; __be16 sequence; } echo;
		__be32 data32[1];
	} un;
};

/* ============================================================
 * Constants
 * ============================================================ */

/* Maximum values */
#define MAX_ZONES              64
#define MAX_INTERFACES         256
#define MAX_LOGICAL_INTERFACES 512
#define MAX_POLICIES           4096
#define MAX_RULES_PER_POLICY   256
#define MAX_SESSIONS           1048576  /* 1M sessions */
#define MAX_NAT_POOLS          32
#define MAX_NAT_POOL_IPS       256
#define MAX_NAT_RULE_COUNTERS  256
#define MAX_ADDRESSES          8192
#define MAX_APPLICATIONS       1024
#define MAX_SCREEN_PROFILES    64
#define MAX_PORT_SCAN_TRACK    65536
#define MAX_CPUS               256

/* XDP tail call program indices */
#define XDP_PROG_SCREEN        0
#define XDP_PROG_ZONE          1
#define XDP_PROG_CONNTRACK     2
#define XDP_PROG_POLICY        3
#define XDP_PROG_NAT           4
#define XDP_PROG_FORWARD       5
#define XDP_PROG_NAT64         6
#define XDP_PROG_MAX           7

/* TC tail call program indices */
#define TC_PROG_CONNTRACK      0
#define TC_PROG_NAT            1
#define TC_PROG_SCREEN_EGRESS  2
#define TC_PROG_FORWARD        3
#define TC_PROG_MAX            4

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
#define SESS_FLAG_SNAT         (1 << 0)
#define SESS_FLAG_DNAT         (1 << 1)
#define SESS_FLAG_LOG          (1 << 2)
#define SESS_FLAG_COUNT        (1 << 3)
#define SESS_FLAG_ALG          (1 << 4)
#define SESS_FLAG_PREDICTED    (1 << 5)
#define SESS_FLAG_STATIC_NAT   (1 << 6)
#define SESS_FLAG_NAT64        (1 << 7)

/* pkt_meta.meta_flags bits */
#define META_FLAG_EMBEDDED_ICMP  (1 << 0)

/* Per-rule logging flags (policy_rule.log and session_value.log_flags) */
#define LOG_FLAG_SESSION_INIT  (1 << 0)
#define LOG_FLAG_SESSION_CLOSE (1 << 1)

/* Policy actions */
#define ACTION_DENY            0
#define ACTION_PERMIT          1
#define ACTION_REJECT          2

/* Protocol numbers */
#define PROTO_TCP              6
#define PROTO_UDP              17
#define PROTO_ICMP             1
#define PROTO_ESP              50
#define PROTO_AH               51
#define PROTO_VRRP             112

/* Event types for ring buffer */
#define EVENT_TYPE_SESSION_OPEN   1
#define EVENT_TYPE_SESSION_CLOSE  2
#define EVENT_TYPE_POLICY_DENY    3
#define EVENT_TYPE_SCREEN_DROP    4
#define EVENT_TYPE_ALG_REQUEST    5
#define EVENT_TYPE_FILTER_LOG     6

/* Global counter indices */
#define GLOBAL_CTR_RX_PACKETS      0
#define GLOBAL_CTR_TX_PACKETS      1
#define GLOBAL_CTR_DROPS           2
#define GLOBAL_CTR_SESSIONS_NEW    3
#define GLOBAL_CTR_SESSIONS_CLOSED 4
#define GLOBAL_CTR_SCREEN_DROPS    5
#define GLOBAL_CTR_POLICY_DENY     6
#define GLOBAL_CTR_NAT_ALLOC_FAIL      7
#define GLOBAL_CTR_HOST_INBOUND_DENY   8
#define GLOBAL_CTR_TC_EGRESS_PACKETS   9
#define GLOBAL_CTR_NAT64_XLATE        10
#define GLOBAL_CTR_HOST_INBOUND       11
/* Per-screen-type drop counters (indices 12..25). */
#define GLOBAL_CTR_SCREEN_SYN_FLOOD      12
#define GLOBAL_CTR_SCREEN_ICMP_FLOOD     13
#define GLOBAL_CTR_SCREEN_UDP_FLOOD      14
#define GLOBAL_CTR_SCREEN_PORT_SCAN      15
#define GLOBAL_CTR_SCREEN_IP_SWEEP       16
#define GLOBAL_CTR_SCREEN_LAND_ATTACK    17
#define GLOBAL_CTR_SCREEN_PING_OF_DEATH  18
#define GLOBAL_CTR_SCREEN_TEAR_DROP      19
#define GLOBAL_CTR_SCREEN_TCP_SYN_FIN    20
#define GLOBAL_CTR_SCREEN_TCP_NO_FLAG    21
#define GLOBAL_CTR_SCREEN_TCP_FIN_NO_ACK 22
#define GLOBAL_CTR_SCREEN_WINNUKE        23
#define GLOBAL_CTR_SCREEN_IP_SRC_ROUTE   24
#define GLOBAL_CTR_SCREEN_SYN_FRAG       25
#define GLOBAL_CTR_MAX                   26

/* Flow timeout indices for flow_timeouts ARRAY map */
#define FLOW_TIMEOUT_TCP_ESTABLISHED   0
#define FLOW_TIMEOUT_TCP_INITIAL       1
#define FLOW_TIMEOUT_TCP_CLOSING       2
#define FLOW_TIMEOUT_TCP_TIME_WAIT     3
#define FLOW_TIMEOUT_UDP               4
#define FLOW_TIMEOUT_ICMP              5
#define FLOW_TIMEOUT_OTHER             6
#define FLOW_TIMEOUT_MAX               7

/* Screen option flags */
#define SCREEN_SYN_FLOOD         (1 << 0)
#define SCREEN_ICMP_FLOOD        (1 << 1)
#define SCREEN_UDP_FLOOD         (1 << 2)
#define SCREEN_PORT_SCAN         (1 << 3)
#define SCREEN_IP_SWEEP          (1 << 4)
#define SCREEN_LAND_ATTACK       (1 << 5)
#define SCREEN_PING_OF_DEATH     (1 << 6)
#define SCREEN_TEAR_DROP         (1 << 7)
#define SCREEN_TCP_SYN_FIN       (1 << 8)
#define SCREEN_TCP_NO_FLAG       (1 << 9)
#define SCREEN_TCP_FIN_NO_ACK    (1 << 10)
#define SCREEN_WINNUKE           (1 << 11)
#define SCREEN_IP_SOURCE_ROUTE   (1 << 12)
#define SCREEN_SYN_FRAG          (1 << 13)

/* Host-inbound-traffic service flags (zone_config.host_inbound_flags) */
#define HOST_INBOUND_SSH         (1 << 0)
#define HOST_INBOUND_PING        (1 << 1)   /* ICMP + ICMPv6 echo */
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
#define HOST_INBOUND_ALL         0xFFFFFFFF  /* permit all services */

/* ============================================================
 * Address family agnostic IP address.
 * Used in pkt_meta to handle both v4 and v6.
 * For v4: address stored in .v4, v6 bytes zeroed.
 * ============================================================ */

struct ip_addr {
	union {
		__be32 v4;
		__u8   v6[16];
	};
};

/* ============================================================
 * VLAN / logical interface support
 * ============================================================ */

/* Composite key for iface_zone_map (HASH): {ifindex, vlan_id} -> zone + routing table */
struct iface_zone_key {
	__u32 ifindex;
	__u16 vlan_id;
	__u16 pad;
};

/* Value for iface_zone_map: zone assignment + optional VRF routing table */
struct iface_zone_value {
	__u16 zone_id;
	__u16 pad;
	__u32 routing_table;  /* kernel table ID, 0 = main table */
};

#ifndef BPF_FIB_LOOKUP_TBID
#define BPF_FIB_LOOKUP_TBID (1U << 3)
#endif

/* Reverse mapping: sub-interface ifindex -> parent physical info */
struct vlan_iface_info {
	__u32 parent_ifindex;
	__u16 vlan_id;
	__u16 pad;
};

/* ============================================================
 * Packet metadata -- passed between tail call stages via
 * per-CPU scratch map at index 0.
 * ============================================================ */

struct pkt_meta {
	/* Parsed header fields (network byte order for IPs/ports) */
	struct ip_addr src_ip;     /* 16 bytes */
	struct ip_addr dst_ip;     /* 16 bytes */
	__be16 src_port;
	__be16 dst_port;
	__u8   protocol;
	__u8   tcp_flags;
	__u8   ip_ttl;
	__u8   addr_family;  /* AF_INET=2, AF_INET6=10 */
	__u8   dscp;          /* DSCP value (top 6 bits of TOS/traffic-class) */
	__u8   csum_partial;  /* 1 = L4 csum is pseudo-header only (CHECKSUM_PARTIAL) */
	__u8   meta_flags;     /* META_FLAG_* bits */
	__u8   embedded_proto; /* inner protocol for ICMP error rewrite */

	/* ICMP specific */
	__be16 icmp_id;
	__u8   icmp_type;
	__u8   icmp_code;

	/* TCP sequence numbers (for RST generation) */
	__be32 tcp_seq;
	__be32 tcp_ack_seq;

	/* Header offsets from packet start */
	__u16 l3_offset;
	__u16 l4_offset;
	__u16 payload_offset;
	__u16 pkt_len;

	/* Zone classification */
	__u16 ingress_zone;
	__u16 egress_zone;
	__u32 ingress_ifindex;
	__u16 ingress_vlan_id;
	__u16 egress_vlan_id;

	/* Pipeline state */
	__u8  direction;    /* 0=ingress, 1=egress */
	__u8  is_fragment;
	__u8  ct_state;     /* SESS_STATE_* */
	__u8  ct_direction; /* 0=forward, 1=reverse */

	__u32 policy_id;

	/* NAT translations to apply */
	struct ip_addr nat_src_ip;  /* 16 bytes */
	struct ip_addr nat_dst_ip;  /* 16 bytes */
	__be16 nat_src_port;
	__be16 nat_dst_port;
	__u32  nat_flags;

	/* Forwarding decision */
	__u32 fwd_ifindex;
	__u8  fwd_dmac[ETH_ALEN];
	__u8  fwd_smac[ETH_ALEN];

	/* Policy-based routing (set by firewall filter) */
	__u32 routing_table;  /* VRF table ID, 0 = main table */

	/* DSCP rewrite (set by firewall filter, 0xFF = no rewrite) */
	__u8  dscp_rewrite;
	__u8  pad_meta;

	/* Per-application inactivity timeout override (seconds, 0 = use default) */
	__u16 app_timeout;

	/* Port mirroring (set by xdp_forward for TC egress to clone) */
	__u32 mirror_ifindex;  /* 0 = no mirroring */
	__u32 mirror_rate;     /* 1-in-N rate (0 = mirror all) */
};

/* ============================================================
 * Event structure for ring buffer
 * ============================================================ */

struct event {
	__u64  timestamp;
	__u8   src_ip[16];
	__u8   dst_ip[16];
	__be16 src_port;
	__be16 dst_port;
	__u32  policy_id;
	__u16  ingress_zone;
	__u16  egress_zone;
	__u8   event_type;
	__u8   protocol;
	__u8   action;
	__u8   addr_family;  /* AF_INET=2, AF_INET6=10 */
	__u64  session_packets;
	__u64  session_bytes;
};

/* ============================================================
 * Zone configuration
 * ============================================================ */

struct zone_config {
	__u16 zone_id;
	__u16 screen_profile_id;
	__u32 host_inbound_flags;
	__u8  tcp_rst;      /* send TCP RST for non-SYN without session */
	__u8  pad[3];
};

/* ============================================================
 * Counter value (per-CPU)
 * ============================================================ */

struct counter_value {
	__u64 packets;
	__u64 bytes;
};

struct iface_counter_value {
	__u64 rx_packets;
	__u64 rx_bytes;
	__u64 tx_packets;
	__u64 tx_bytes;
};

/* ============================================================
 * Screen/IDS configuration
 * ============================================================ */

struct screen_config {
	__u32 flags;              /* SCREEN_* bitmask */
	__u32 syn_flood_thresh;   /* SYN pkts/sec/zone, 0=disabled */
	__u32 icmp_flood_thresh;
	__u32 udp_flood_thresh;
	__u32 syn_flood_src_thresh;  /* per-source-IP threshold (future) */
	__u32 syn_flood_dst_thresh;  /* per-dest-IP threshold (future) */
	__u32 syn_flood_timeout;     /* flood window duration in seconds (0=1s) */
	__u32 port_scan_thresh;      /* TCP SYN attempts per source IP in window */
	__u32 ip_sweep_thresh;       /* unique dest IPs per source IP in window */
};

struct flood_state {
	__u64 syn_count;
	__u64 icmp_count;
	__u64 udp_count;
	__u64 window_start;       /* ktime_ns / 1e9 (seconds) */
};

/* Per-source-IP tracking for port scan / IP sweep detection.
 * Key: source IPv4 address.  Stored in LRU_HASH for auto-eviction. */
struct scan_track_key {
	__u32 src_ip;
	__u16 zone_id;
	__u16 pad;
};

struct scan_track_value {
	__u32 count;           /* unique attempts in current window */
	__u32 window_start;    /* ktime_ns / 1e9 (seconds) */
};

/* ============================================================
 * NAT pool configuration
 * ============================================================ */

#define MAX_NAT_POOL_IPS_PER_POOL  8  /* max IPs per individual pool */

struct nat_pool_config {
	__u16 num_ips;        /* number of v4 IPs in this pool */
	__u16 num_ips_v6;     /* number of v6 IPs in this pool */
	__u16 port_low;       /* default 1024 */
	__u16 port_high;      /* default 65535 */
	__u8  addr_persistent; /* same src IP always maps to same pool IP */
	__u8  pad[3];
};

struct nat_pool_ip_v6 {
	__u8 ip[16];
};

struct nat_port_counter {
	__u64 counter;
};

/* ============================================================
 * NAT64 configuration
 * ============================================================ */

#define MAX_NAT64_PREFIXES 4

/* Firewall filter limits */
#define MAX_FILTER_CONFIGS 64
#define MAX_FILTER_RULES   512
#define MAX_FILTER_RULES_PER_FILTER 32

/* Filter match flags */
#define FILTER_MATCH_DSCP      (1 << 0)
#define FILTER_MATCH_PROTOCOL  (1 << 1)
#define FILTER_MATCH_SRC_ADDR  (1 << 2)
#define FILTER_MATCH_DST_ADDR  (1 << 3)
#define FILTER_MATCH_DST_PORT  (1 << 4)
#define FILTER_MATCH_ICMP_TYPE (1 << 5)
#define FILTER_MATCH_ICMP_CODE (1 << 6)
#define FILTER_MATCH_SRC_PORT  (1 << 7)
#define FILTER_MATCH_SRC_NEGATE (1 << 8)  /* negate source address match (prefix-list except) */
#define FILTER_MATCH_DST_NEGATE (1 << 9)  /* negate destination address match (prefix-list except) */
#define FILTER_MATCH_TCP_FLAGS  (1 << 10) /* match TCP flags bitmask */
#define FILTER_MATCH_FRAGMENT   (1 << 11) /* match IP fragments */

/* Filter actions */
#define FILTER_ACTION_ACCEPT   0
#define FILTER_ACTION_DISCARD  1
#define FILTER_ACTION_REJECT   2
#define FILTER_ACTION_ROUTE    3  /* routing-instance */

/* DSCP codepoint values */
#define DSCP_EF  46
#define DSCP_AF11 10
#define DSCP_AF12 12
#define DSCP_AF13 14
#define DSCP_AF21 18
#define DSCP_AF22 20
#define DSCP_AF23 22
#define DSCP_AF31 26
#define DSCP_AF32 28
#define DSCP_AF33 30
#define DSCP_AF41 34
#define DSCP_AF42 36
#define DSCP_AF43 38

/* NAT64 prefix lookup key: first 96 bits of IPv6 destination address. */
struct nat64_prefix_key {
	__be32 prefix[3];
};

/* NAT64 prefix config entry:
 * snat_pool_id points to the IPv4 source pool for translated packets. */
struct nat64_config {
	__be32 prefix[3];  /* first 96 bits of NAT64 prefix (3 x 32-bit words) */
	__u8   snat_pool_id;
	__u8   pad[3];
};

/* NAT64 reverse state: keyed by translated IPv4 5-tuple, maps back to
 * original IPv6 client address + port for v4→v6 reverse translation. */
struct nat64_state_key {
	__be32 src_ip;    /* original v4 server IP */
	__be32 dst_ip;    /* our SNAT'd v4 address */
	__be16 src_port;  /* server port */
	__be16 dst_port;  /* our SNAT'd port */
	__u8   protocol;
	__u8   pad[3];
};

struct nat64_state_value {
	__u8   orig_src_v6[16]; /* original IPv6 client address */
	__u8   orig_dst_v6[16]; /* original IPv6 dest (prefix + v4 addr) */
	__be16 orig_src_port;   /* original client port */
	__be16 orig_dst_port;   /* original dest port */
	__u32  nat64_idx;       /* which NAT64 prefix was used */
};

/* ============================================================
 * Firewall filter configuration
 * ============================================================ */

/* Per-filter config: number of rules and where they start in the rules array */
struct filter_config {
	__u32 num_rules;
	__u32 rule_start;   /* index into filter_rules array */
};

/* Interface filter assignment key: {ifindex, vlan_id, family, direction} -> filter_id */
struct iface_filter_key {
	__u32 ifindex;
	__u16 vlan_id;
	__u8  family;     /* AF_INET=2, AF_INET6=10 */
	__u8  direction;  /* 0=input, 1=output */
};

/* Unified filter rule (works for both v4 and v6) */
struct filter_rule {
	__u16  match_flags;     /* FILTER_MATCH_* bitmask */
	__u8   dscp;            /* DSCP/traffic-class value (6 bits) */
	__u8   protocol;        /* IP protocol number, 0=any */
	__u8   action;          /* FILTER_ACTION_* */
	__u8   icmp_type;       /* ICMP type, valid if FILTER_MATCH_ICMP_TYPE */
	__u8   icmp_code;       /* ICMP code, valid if FILTER_MATCH_ICMP_CODE */
	__u8   family;          /* AF_INET or AF_INET6 */
	__be16 dst_port;        /* network byte order, 0=any */
	__be16 src_port;        /* network byte order, 0=any */
	__be16 dst_port_hi;     /* range upper bound, 0=exact match */
	__be16 src_port_hi;     /* range upper bound, 0=exact match */
	__u8   dscp_rewrite;    /* DSCP rewrite value (0xFF = no rewrite) */
	__u8   log_flag;        /* 1 = emit ring buffer event on match */
	__u8   tcp_flags;       /* TCP flags bitmask to match (SYN=0x02, ACK=0x10, etc.) */
	__u8   is_fragment;     /* 1 = match IP fragments */
	__u8   src_addr[16];    /* v4: first 4 bytes, v6: all 16 */
	__u8   src_mask[16];    /* prefix mask */
	__u8   dst_addr[16];
	__u8   dst_mask[16];
	__u32  routing_table;   /* VRF table ID (for FILTER_ACTION_ROUTE) */
};

/* ============================================================
 * Global flow configuration (single-entry array map)
 * ============================================================ */

struct flow_config {
	__u16 tcp_mss_ipsec;   /* TCP MSS clamp for IPsec VPN (0=disabled) */
	__u16 tcp_mss_gre_in;  /* TCP MSS clamp for GRE ingress (0=disabled) */
	__u16 tcp_mss_gre_out; /* TCP MSS clamp for GRE egress (0=disabled) */
	__u8  allow_dns_reply;
	__u8  allow_embedded_icmp;
	__u8  gre_accel;       /* GRE performance acceleration */
	__u8  alg_flags;       /* bit 0: DNS disable, bit 1: FTP disable,
	                          bit 2: SIP disable, bit 3: TFTP disable */
};

/* ============================================================
 * Port mirroring (SPAN) configuration
 * ============================================================ */

struct mirror_config {
	__u32 mirror_ifindex;  /* destination interface ifindex */
	__u32 rate;            /* 1-in-N sampling rate (0 = mirror all) */
};

#endif /* __BPFRX_COMMON_H__ */
