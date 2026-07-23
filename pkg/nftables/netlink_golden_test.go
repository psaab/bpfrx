package nftables

import "testing"

// netlink_golden_test.go is the T1b pure-unit golden test (#6387 §9 / §12.1). It
// builds the netlink []expr.Any for each representative rule and asserts it
// against a golden canonical string. The goldens are DERIVED INDEPENDENTLY from
// the nft-text semantics the oracle emits (each case documents its `nft` text
// and the netfilter constant values it lowers to) — they are NOT captured from
// this builder's own output (the equivalence-TAUTOLOGY trap §12.1 forbids). The
// literal constant values used below (NFT_META_NFPROTO=15, NFT_META_L4PROTO=16,
// NFT_PAYLOAD_NETWORK_HEADER=1, NFT_PAYLOAD_TRANSPORT_HEADER=2, NFT_CMP_EQ=0,
// NFT_CMP_NEQ=1, NFPROTO_IPV4=2/IPV6=10, l4proto tcp=6/udp=17/icmp=1/icmpv6=58,
// NFT_REJECT_TCP_RST=1, NFT_REJECT_ICMPX_UNREACH=2 admin-prohibited code=3,
// NFT_EXTHDR_F_PRESENT=1, NFTA_LOG_PREFIX=2 -> Log.Key=4, verdict accept=1/drop=0)
// come from linux/netfilter/nf_tables.h, not from the builder.
//
// This is the pure-unit safety net for the kernel-gated T1 parity diff: it
// catches a regression in the expr encoding even where `nft`/netns is absent.

func goldenBuild(t *testing.T, build func(p *nlPlan)) string {
	t.Helper()
	p := newBuildPlan(t, "xpf_golden", hostInboundPriority)
	build(p)
	if p.err != nil {
		t.Fatalf("build error: %v", p.err)
	}
	return canonRules(p)
}

func TestGoldenExprEncoding(t *testing.T) {
	cases := []struct {
		name  string
		build func(p *nlPlan)
		want  string
	}{
		{
			// nft: ct state established,related accept
			name:  "ct_established_related_accept",
			build: func(p *nlPlan) { p.rule().ctEstablishedRelated().emit(verdictAccept()...) },
			want:  "r00: ct(key=0,reg=1) bitwise(len=4,mask=06000000,xor=00000000) cmp(op=1,reg=1,00000000) verdict(1)\n",
		},
		{
			// nft: ct state established,related ct direction reply accept
			name:  "ct_direction_reply_accept",
			build: func(p *nlPlan) { p.rule().ctEstablishedRelated().ctDirectionReply().emit(verdictAccept()...) },
			want:  "r00: ct(key=0,reg=1) bitwise(len=4,mask=06000000,xor=00000000) cmp(op=1,reg=1,00000000) ct(key=1,reg=1) cmp(op=0,reg=1,01) verdict(1)\n",
		},
		{
			// nft: meta l4proto { 50, 51 } accept   (ESP/AH exemption)
			name:  "esp_ah_set_accept",
			build: func(p *nlPlan) { p.rule().l4protoSet([]uint8{50, 51}).emit(verdictAccept()...) },
			want:  "r00: meta(key=16,reg=1) lookup(inv=false,set=[32,33]) verdict(1)\n",
		},
		{
			// nft: ip daddr 10.0.1.1 tcp dport 22 accept   (host-inbound ssh)
			name: "hostinbound_ssh_accept",
			build: func(p *nlPlan) {
				p.rule().daddr(famV4, []string{"10.0.1.1"}, false).
					l4Port(protoTCP, "dport", []nlPort{{22, 22}}, false).emit(verdictAccept()...)
			},
			want: "r00: meta(key=15,reg=1) cmp(op=0,reg=1,02) payload(base=1,off=16,len=4,reg=1) cmp(op=0,reg=1,0a000101) meta(key=16,reg=1) cmp(op=0,reg=1,06) payload(base=2,off=2,len=2,reg=1) cmp(op=0,reg=1,0016) verdict(1)\n",
		},
		{
			// nft: ip daddr 10.0.7.1 tcp dport 113 reject with tcp reset (ident-reset)
			name: "ident_reset_reject_tcp",
			build: func(p *nlPlan) {
				p.rule().daddr(famV4, []string{"10.0.7.1"}, false).
					l4Port(protoTCP, "dport", []nlPort{{113, 113}}, false).emit(rejectTCPReset()...)
			},
			want: "r00: meta(key=15,reg=1) cmp(op=0,reg=1,02) payload(base=1,off=16,len=4,reg=1) cmp(op=0,reg=1,0a000701) meta(key=16,reg=1) cmp(op=0,reg=1,06) payload(base=2,off=2,len=2,reg=1) cmp(op=0,reg=1,0071) reject(type=1,code=0)\n",
		},
		{
			// nft: icmpv6 type { 1, 2, 3, 4 } counter name "xpfhia_icmp6_error" accept
			name: "icmpv6_error_set_counter_accept",
			build: func(p *nlPlan) {
				p.rule().icmpType(famV6, []uint8{1, 2, 3, 4}).
					counterRef(HostInboundAcceptCounterName(HostInboundAcceptICMP6Error)).emit(verdictAccept()...)
			},
			want: "r00: meta(key=15,reg=1) cmp(op=0,reg=1,0a) meta(key=16,reg=1) cmp(op=0,reg=1,3a) payload(base=2,off=0,len=1,reg=1) lookup(inv=false,set=[01,02,03,04]) objref(type=1,name=\"xpfhia_icmp6_error\") verdict(1)\n",
		},
		{
			// nft: icmp type { 3, 11, 12 } accept  (v4 error/PMTUD; du=3 te=11 pp=12)
			name:  "icmp4_error_set_accept",
			build: func(p *nlPlan) { p.rule().icmpType(famV4, []uint8{3, 11, 12}).emit(verdictAccept()...) },
			want:  "r00: meta(key=15,reg=1) cmp(op=0,reg=1,02) meta(key=16,reg=1) cmp(op=0,reg=1,01) payload(base=2,off=0,len=1,reg=1) lookup(inv=false,set=[03,0b,0c]) verdict(1)\n",
		},
		{
			// nft: udp dport { 51820, 51821 } accept  (WireGuard listen ports)
			name: "wireguard_udp_dport_set_accept",
			build: func(p *nlPlan) {
				p.rule().l4Port(protoUDP, "dport", portsFromUint16([]uint16{51820, 51821}), false).emit(verdictAccept()...)
			},
			want: "r00: meta(key=16,reg=1) cmp(op=0,reg=1,11) payload(base=2,off=2,len=2,reg=1) lookup(inv=false,set=[ca6c,ca6d]) verdict(1)\n",
		},
		{
			// nft: ip6 dscp cs1   (cs1=8; §12.3 2-byte nibble-spanning encoding)
			name:  "v6_dscp_cs1_accept",
			build: func(p *nlPlan) { p.rule().dscp(famV6, []uint8{8}).emit(verdictAccept()...) },
			want:  "r00: meta(key=15,reg=1) cmp(op=0,reg=1,0a) payload(base=1,off=0,len=2,reg=1) bitwise(len=2,mask=0fc0,xor=0000) cmp(op=0,reg=1,0200) verdict(1)\n",
		},
		{
			// nft: ip dscp ef   (ef=46; v4 TOS byte, mask 0xfc, value<<2 = 0xb8)
			name:  "v4_dscp_ef_accept",
			build: func(p *nlPlan) { p.rule().dscp(famV4, []uint8{46}).emit(verdictAccept()...) },
			want:  "r00: meta(key=15,reg=1) cmp(op=0,reg=1,02) payload(base=1,off=1,len=1,reg=1) bitwise(len=1,mask=fc,xor=00) cmp(op=0,reg=1,b8) verdict(1)\n",
		},
		{
			// nft: tcp flags & (syn | ack) == syn   (syn=0x02 required, ack=0x10 forbidden)
			name:  "tcp_flags_syn_not_ack_accept",
			build: func(p *nlPlan) { p.rule().tcpFlags(0x02, 0x10).emit(verdictAccept()...) },
			want:  "r00: meta(key=16,reg=1) cmp(op=0,reg=1,06) payload(base=2,off=13,len=1,reg=1) bitwise(len=1,mask=12,xor=00) cmp(op=0,reg=1,02) verdict(1)\n",
		},
		{
			// nft: ip frag-off & 0x1fff != 0 drop
			name:  "ip_fragment_drop",
			build: func(p *nlPlan) { p.rule().fragV4().emit(verdictDrop()...) },
			want:  "r00: meta(key=15,reg=1) cmp(op=0,reg=1,02) payload(base=1,off=6,len=2,reg=1) bitwise(len=2,mask=1fff,xor=0000) cmp(op=1,reg=1,0000) verdict(0)\n",
		},
		{
			// nft: exthdr frag exists drop   (v6 fragment ext header, type 44)
			name:  "v6_exthdr_frag_drop",
			build: func(p *nlPlan) { p.rule().exthdrFragV6().emit(verdictDrop()...) },
			want:  "r00: meta(key=15,reg=1) cmp(op=0,reg=1,0a) exthdr(type=44,off=0,len=1,op=0,flags=1,reg=1) cmp(op=0,reg=1,01) verdict(0)\n",
		},
		{
			// nft: th dport 33434-33523 accept  (transport-agnostic range, no l4 guard)
			name:  "th_dport_range_accept",
			build: func(p *nlPlan) { p.rule().thPort("dport", []nlPort{{33434, 33523}}, false).emit(verdictAccept()...) },
			want:  "r00: payload(base=2,off=2,len=2,reg=1) range(op=0,from=829a,to=82f3) verdict(1)\n",
		},
		{
			// nft: ip6 daddr 2001:db8::/32 accept  (SINGLE prefix -> masked cmp,
			// mask = /32, NOT an interval set — matches nft's bare-prefix form)
			name:  "v6_daddr_single_prefix_masked_accept",
			build: func(p *nlPlan) { p.rule().daddr(famV6, []string{"2001:db8::/32"}, false).emit(verdictAccept()...) },
			want:  "r00: meta(key=15,reg=1) cmp(op=0,reg=1,0a) payload(base=1,off=24,len=16,reg=1) bitwise(len=16,mask=ffffffff000000000000000000000000,xor=00000000000000000000000000000000) cmp(op=0,reg=1,20010db8000000000000000000000000) verdict(1)\n",
		},
		{
			// nft: ip daddr { 10.1.0.0/16, 10.2.0.0/16 } accept  (MULTI prefix ->
			// interval set of [network, next) half-open ranges)
			name: "v4_daddr_multi_prefix_interval_accept",
			build: func(p *nlPlan) {
				p.rule().daddr(famV4, []string{"10.1.0.0/16", "10.2.0.0/16"}, false).emit(verdictAccept()...)
			},
			want: "r00: meta(key=15,reg=1) cmp(op=0,reg=1,02) payload(base=1,off=16,len=4,reg=1) lookup(inv=false,set=[0a010000,0a020000,0a020000!end,0a030000!end]) verdict(1)\n",
		},
		{
			// nft: ip saddr != { 192.0.2.10 } drop  (permit-subtraction, inverted lookup)
			name: "saddr_except_set_drop",
			build: func(p *nlPlan) {
				p.rule().saddr(famV4, []string{"192.0.2.10", "192.0.2.11"}, true).emit(verdictDrop()...)
			},
			want: "r00: meta(key=15,reg=1) cmp(op=0,reg=1,02) payload(base=1,off=12,len=4,reg=1) lookup(inv=true,set=[c000020a,c000020b]) verdict(0)\n",
		},
		{
			// nft: log prefix "xpf-lo0 t1: " counter name "xpflo0_c" drop
			name: "log_counter_drop",
			build: func(p *nlPlan) {
				p.rule().logPrefix("xpf-lo0 t1: ").counterRef(Lo0CounterName("c")).emit(verdictDrop()...)
			},
			want: "r00: log(key=4,prefix=\"xpf-lo0 t1: \") objref(type=1,name=\"xpflo0_c\") verdict(0)\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := goldenBuild(t, tc.build)
			if got != tc.want {
				t.Errorf("golden mismatch for %s:\n  got:  %q\n  want: %q", tc.name, got, tc.want)
			}
		})
	}
}

// TestGoldenRejectTermPair asserts the lo0 `reject` term lowers to EXACTLY two
// rules — a TCP-scoped `reject with tcp reset` then a family-agnostic
// `reject with icmpx type admin-prohibited` (plan §5.1 H10) — so a regression
// that collapses the pair (a weaker single reject) is caught.
func TestGoldenRejectTermPair(t *testing.T) {
	p := newBuildPlan(t, "xpf_golden", lo0FilterPriority)
	buildLo0TermNetlink(p, Lo0FilterTerm{Name: "r", Action: "reject"}, famV4)
	if p.err != nil {
		t.Fatalf("build error: %v", p.err)
	}
	got := canonRules(p)
	want := "r00: meta(key=16,reg=1) cmp(op=0,reg=1,06) reject(type=1,code=0)\n" +
		"r01: reject(type=2,code=3)\n"
	if got != want {
		t.Errorf("reject pair mismatch:\n  got:  %q\n  want: %q", got, want)
	}
}
