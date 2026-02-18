package dataplane

import (
	"testing"
)

func TestNPTv6Adjustment48(t *testing.T) {
	tests := []struct {
		name     string
		internal [6]byte
		external [6]byte
	}{
		{
			name:     "RFC6296 example fd01:0203:0405 -> 2001:0db8:0001",
			internal: [6]byte{0xfd, 0x01, 0x02, 0x03, 0x04, 0x05},
			external: [6]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01},
		},
		{
			name:     "ULA to global fd35:1940:0027 -> 2602:fd41:0070",
			internal: [6]byte{0xfd, 0x35, 0x19, 0x40, 0x00, 0x27},
			external: [6]byte{0x26, 0x02, 0xfd, 0x41, 0x00, 0x70},
		},
		{
			name:     "identical prefixes",
			internal: [6]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01},
			external: [6]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adj := nptv6Adjustment(tt.internal[:], tt.external[:])

			// Verify round-trip: applying adjustment outbound then inbound
			// should recover original address.
			testAddr := [16]byte{
				tt.internal[0], tt.internal[1], tt.internal[2], tt.internal[3],
				tt.internal[4], tt.internal[5], 0xAA, 0xBB,
				0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
			}
			original := testAddr

			// Apply outbound (internal → external)
			applyNPTv6Native(&testAddr, tt.external[:], adj, false, 3)

			// Verify prefix changed to external
			if testAddr[0] != tt.external[0] || testAddr[1] != tt.external[1] ||
				testAddr[2] != tt.external[2] || testAddr[3] != tt.external[3] ||
				testAddr[4] != tt.external[4] || testAddr[5] != tt.external[5] {
				t.Errorf("outbound: prefix not rewritten to external")
			}

			// Apply inbound (external → internal)
			applyNPTv6Native(&testAddr, tt.internal[:], adj, true, 3)

			// Verify we get back the original address
			if testAddr != original {
				t.Errorf("round-trip failed:\n  original: %x\n  got:      %x", original, testAddr)
			}
		})
	}
}

func TestNPTv6Adjustment64(t *testing.T) {
	tests := []struct {
		name     string
		internal [8]byte
		external [8]byte
	}{
		{
			name:     "ULA /64 to global /64",
			internal: [8]byte{0xfd, 0x01, 0x02, 0x03, 0x04, 0x05, 0xbf, 0x01},
			external: [8]byte{0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0xbf, 0x04},
		},
		{
			name:     "identical /64 prefixes",
			internal: [8]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02},
			external: [8]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adj := nptv6Adjustment(tt.internal[:], tt.external[:])

			testAddr := [16]byte{
				tt.internal[0], tt.internal[1], tt.internal[2], tt.internal[3],
				tt.internal[4], tt.internal[5], tt.internal[6], tt.internal[7],
				0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
			}
			original := testAddr

			// Outbound
			applyNPTv6Native(&testAddr, tt.external[:], adj, false, 4)

			// Verify prefix changed
			for i := 0; i < 8; i++ {
				if testAddr[i] != tt.external[i] {
					t.Errorf("outbound: prefix byte %d: got 0x%02x, want 0x%02x",
						i, testAddr[i], tt.external[i])
				}
			}

			// Inbound round-trip
			applyNPTv6Native(&testAddr, tt.internal[:], adj, true, 4)

			if testAddr != original {
				t.Errorf("round-trip failed:\n  original: %x\n  got:      %x", original, testAddr)
			}
		})
	}
}

// applyNPTv6Native simulates the BPF nptv6_translate function exactly.
// prefixWords is 3 for /48 or 4 for /64.
func applyNPTv6Native(addr *[16]byte, newPrefix []byte, adj uint16, inbound bool, prefixWords int) {
	readW := func(i int) uint16 {
		return uint16(addr[i*2]) | uint16(addr[i*2+1])<<8
	}
	writeW := func(i int, v uint16) {
		addr[i*2] = byte(v)
		addr[i*2+1] = byte(v >> 8)
	}

	// Rewrite prefix bytes
	copy(addr[:len(newPrefix)], newPrefix)

	// Apply adjustment to the word after the prefix
	adjWord := prefixWords // 3 for /48, 4 for /64
	a := adj
	if inbound {
		a = ^a
	}

	val := readW(adjWord)
	sum := uint32(val) + uint32(a)
	sum = (sum & 0xFFFF) + (sum >> 16)
	sum = (sum & 0xFFFF) + (sum >> 16)
	result := uint16(sum)
	if result == 0xFFFF {
		result = 0x0000
	}
	writeW(adjWord, result)
}

func TestNPTv6AdjustmentChecksumNeutral(t *testing.T) {
	// Test /48 checksum neutrality
	t.Run("/48", func(t *testing.T) {
		internal := []byte{0xfd, 0x01, 0x02, 0x03, 0x04, 0x05}
		external := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01}
		adj := nptv6Adjustment(internal, external)

		addr := [16]byte{
			0xfd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x12, 0x34,
			0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22,
		}

		sumBefore := onesComplementSum128BE(addr)
		applyNPTv6Native(&addr, external, adj, false, 3)
		sumAfter := onesComplementSum128BE(addr)

		if sumBefore != sumAfter {
			t.Errorf("checksum NOT neutral: before=0x%04x, after=0x%04x", sumBefore, sumAfter)
		}
	})

	// Test /64 checksum neutrality
	t.Run("/64", func(t *testing.T) {
		internal := []byte{0xfd, 0x01, 0x02, 0x03, 0x04, 0x05, 0xbf, 0x01}
		external := []byte{0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0xbf, 0x04}
		adj := nptv6Adjustment(internal, external)

		addr := [16]byte{
			0xfd, 0x01, 0x02, 0x03, 0x04, 0x05, 0xbf, 0x01,
			0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22,
		}

		sumBefore := onesComplementSum128BE(addr)
		applyNPTv6Native(&addr, external, adj, false, 4)
		sumAfter := onesComplementSum128BE(addr)

		if sumBefore != sumAfter {
			t.Errorf("checksum NOT neutral: before=0x%04x, after=0x%04x", sumBefore, sumAfter)
		}
	})
}

// onesComplementSum128BE computes the ones'-complement sum of 8 x 16-bit
// words in big-endian (network) byte order — matching how IP checksums work.
func onesComplementSum128BE(addr [16]byte) uint16 {
	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(addr[i])<<8 | uint32(addr[i+1])
	}
	sum = (sum & 0xFFFF) + (sum >> 16)
	sum = (sum & 0xFFFF) + (sum >> 16)
	return uint16(sum)
}
