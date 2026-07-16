package vrrp

// #5088: the AF_PACKET SOCK_RAW cBPF prefilter (vrrpCBPFFilter) used to accept
// only 0x8100 (802.1Q) as the outer VLAN ethertype and kernel-drop 0x88a8
// (802.1ad), even though the Go receiver parser (instance.go) accepts BOTH. On
// an S-tagged / provider-bridged segment the kernel dropped every VRRP advert
// before Go saw it, so both nodes went mutually deaf and could own the same
// VRID/VIPs (split-brain). The fix admits single-tag 0x88a8 (identical layout:
// real ethertype @16) alongside 0x8100, recomputing every downstream relative
// jump for the inserted instruction.
//
// This test ASSEMBLES the exact production filter (vrrpCBPFFilter) and RUNS it in
// a bpf.VM against synthetic frames — it is a behavioral test of the running
// program, not a construction/offset-shape check.
//
// FAIL-ON-REVERT: restore the 0x8100-only outer check (drop the 0x88a8
// instruction / recompute back) and every "802.1ad ... PASS" case below REJECTS
// (vm.Run returns 0) — RED.

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// runVRRPFilter assembles the production cBPF array and runs it against frame,
// returning true if the filter ACCEPTS (non-zero return = bytes to keep).
func runVRRPFilter(t *testing.T, frame []byte) bool {
	t.Helper()
	raw := vrrpCBPFFilter()
	insns := make([]bpf.Instruction, len(raw))
	for i, f := range raw {
		insns[i] = bpf.RawInstruction{Op: f.Code, Jt: f.Jt, Jf: f.Jf, K: f.K}.Disassemble()
	}
	vm, err := bpf.NewVM(insns)
	if err != nil {
		t.Fatalf("assemble vrrpCBPFFilter: %v", err)
	}
	n, err := vm.Run(frame)
	if err != nil {
		t.Fatalf("run filter: %v", err)
	}
	return n > 0
}

// vrrpFrame builds a 60-byte L2 frame. outerEth is the ethertype at offset 12.
// When innerEth != 0 the frame is single-tagged (TCI at 14, real ethertype at
// 16). protoByte is written at protoOff (the IPv4 proto / IPv6 next-header slot
// for the chosen encapsulation).
func vrrpFrame(outerEth, innerEth uint16, protoOff int, protoByte byte) []byte {
	f := make([]byte, 60) // >= any offset used; dst/src MACs left zero
	binary.BigEndian.PutUint16(f[12:14], outerEth)
	if innerEth != 0 {
		binary.BigEndian.PutUint16(f[16:18], innerEth)
	}
	if protoOff > 0 {
		f[protoOff] = protoByte
	}
	return f
}

const (
	ethIPv4    = 0x0800
	ethIPv6    = 0x86DD
	ethARP     = 0x0806
	eth8021Q   = 0x8100
	eth8021ad  = 0x88a8
	protoVRRP  = 112
	protoTCP   = 6
	nhHopByHop = 0 // an IPv6 ext-header that a chained VRRP advert may lead with
)

func TestVRRPCBPFFilter_Accepts8021adAnd8021Q_5088(t *testing.T) {
	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		// --- PASS: every encapsulation the Go parser accepts ---
		{"ipv4 untagged VRRP", vrrpFrame(ethIPv4, 0, 23, protoVRRP), true},
		{"ipv6 untagged VRRP", vrrpFrame(ethIPv6, 0, 20, protoVRRP), true},
		{"ipv6 untagged VRRP hop-by-hop", vrrpFrame(ethIPv6, 0, 20, nhHopByHop), true},
		{"ipv4 802.1Q VRRP", vrrpFrame(eth8021Q, ethIPv4, 27, protoVRRP), true},
		{"ipv6 802.1Q VRRP", vrrpFrame(eth8021Q, ethIPv6, 24, protoVRRP), true},
		// The #5088 fix: 802.1ad (S-tag) must now pass, matching the parser.
		{"ipv4 802.1ad VRRP", vrrpFrame(eth8021ad, ethIPv4, 27, protoVRRP), true},
		{"ipv6 802.1ad VRRP", vrrpFrame(eth8021ad, ethIPv6, 24, protoVRRP), true},

		// --- REJECT: everything the parser would drop must stay kernel-dropped ---
		{"ipv4 untagged TCP", vrrpFrame(ethIPv4, 0, 23, protoTCP), false},
		{"ipv6 untagged TCP", vrrpFrame(ethIPv6, 0, 20, protoTCP), false},
		{"arp", vrrpFrame(ethARP, 0, 0, 0), false},
		{"ipv4 802.1ad TCP (right encap, wrong proto)", vrrpFrame(eth8021ad, ethIPv4, 27, protoTCP), false},
		{"802.1ad inner ARP (non-IP)", vrrpFrame(eth8021ad, ethARP, 0, 0), false},
		{"802.1Q inner ARP (non-IP)", vrrpFrame(eth8021Q, ethARP, 0, 0), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runVRRPFilter(t, tc.frame)
			if got != tc.want {
				verb := "REJECTED"
				if got {
					verb = "ACCEPTED"
				}
				t.Fatalf("filter %s %q; want accept=%v", verb, tc.name, tc.want)
			}
		})
	}
}

// TestVRRPCBPFFilter_8021adIsTheRevertGuard_5088 isolates the exact #5088
// assertion so a revert produces an unambiguous failure: a single-tag 802.1ad
// VRRP advert (v4 and v6) MUST be accepted. Reverting to the 0x8100-only outer
// check makes both REJECT.
func TestVRRPCBPFFilter_8021adIsTheRevertGuard_5088(t *testing.T) {
	if !runVRRPFilter(t, vrrpFrame(eth8021ad, ethIPv4, 27, protoVRRP)) {
		t.Error("802.1ad IPv4 VRRP advert rejected by the cBPF prefilter — the kernel drops it before Go, VRRP is deaf on S-tagged segments (#5088)")
	}
	if !runVRRPFilter(t, vrrpFrame(eth8021ad, ethIPv6, 24, protoVRRP)) {
		t.Error("802.1ad IPv6 VRRP advert rejected by the cBPF prefilter (#5088)")
	}
}

// Guard against an accidental filter length/shape regression: the array must be
// the 32-instruction program (0..31) the offset comments assume.
func TestVRRPCBPFFilter_Length_5088(t *testing.T) {
	if got := len(vrrpCBPFFilter()); got != 32 {
		t.Fatalf("vrrpCBPFFilter has %d instructions, want 32 (0x88a8 insertion + recomputed offsets)", got)
	}
	// unix.SockFilter and bpf.RawInstruction must stay field-compatible.
	var _ = unix.SockFilter{Code: 0, Jt: 0, Jf: 0, K: 0}
}
