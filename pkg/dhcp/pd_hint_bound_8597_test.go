package dhcp

import (
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// #8597 K51. An out-of-range preferred-prefix-length must not egress as a
// degenerate IAPREFIX with wire prefix-length 0.
//
// These cells assert the CONSEQUENCE on the constructed message — what the
// upstream server would receive — not that pdHintPrefixLength returned some
// tuple. A fix that bounded the value but still attached a zero-length
// IAPREFIX would satisfy a mechanism assertion and fail these.
//
// The out-of-range value is reachable: SchemaValidate rejects it, but
// Store.Load / Store.SyncApply compile via compileTreeLenient, which downgrades
// that violation to a warning (#1319). See pdHintPrefixLength.
func TestPDHintPrefixLengthBounds8597(t *testing.T) {
	// iaPrefixLens returns the wire prefix-length of every IAPREFIX carried
	// inside every IA_PD of the built message.
	iaPrefixLens := func(t *testing.T, opts *DHCPv6Options) (lens []byte, sawIAPD bool) {
		t.Helper()
		m := &Manager{
			duids:     make(map[string]dhcpv6.DUID),
			duidTypes: make(map[string]string),
			v6opts:    make(map[string]*DHCPv6Options),
		}
		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeSolicit
		for _, mod := range m.buildDHCPv6Modifiers("eth0", opts) {
			mod(msg)
		}
		for _, opt := range msg.Options.Options {
			iapd, ok := opt.(*dhcpv6.OptIAPD)
			if !ok {
				continue
			}
			sawIAPD = true
			// Read the prefix-length off the SERIALISED IAPREFIX: that is the
			// byte the server parses. net.IPMask(nil).Size() is (0,0), so a
			// nil mask is indistinguishable from a deliberate /0 in the Go
			// struct — only the wire encoding separates them.
			for _, sub := range iapd.Options.Options {
				if sub.Code() != dhcpv6.OptionIAPrefix {
					continue
				}
				b := sub.ToBytes()
				if len(b) == 0 {
					t.Fatalf("IAPREFIX serialised to zero bytes")
				}
				// OptIAPrefix wire layout (RFC 8415 §21.22): preferred-lifetime
				// (4) | valid-lifetime (4) | prefix-length (1) | prefix (16).
				if len(b) < 9 {
					t.Fatalf("IAPREFIX too short to carry a prefix-length: %x", b)
				}
				lens = append(lens, b[8])
			}
		}
		return lens, sawIAPD
	}

	t.Run("positive control: a valid hint is emitted and visible", func(t *testing.T) {
		lens, sawIAPD := iaPrefixLens(t, &DHCPv6Options{
			IATypes:   []string{"ia-pd"},
			PDPrefLen: 56,
		})
		if !sawIAPD {
			t.Fatal("no IA_PD in the built message")
		}
		if len(lens) != 1 || lens[0] != 56 {
			t.Fatalf("valid hint: IAPREFIX prefix-lengths = %v, want exactly [56]", lens)
		}
	})

	t.Run("out-of-range hint sends NO IAPREFIX, not a zero-length one", func(t *testing.T) {
		lens, sawIAPD := iaPrefixLens(t, &DHCPv6Options{
			IATypes: []string{"ia-pd"},
			// Reaches the runtime through the tolerant ingress; a strict
			// commit would have rejected it.
			PDPrefLen: 999,
		})
		if !sawIAPD {
			t.Fatal("IA_PD must still be requested — only the length HINT is dropped")
		}
		for _, l := range lens {
			if l == 0 {
				t.Errorf("out-of-range preferred-prefix-length egressed as an IAPREFIX "+
					"with wire prefix-length 0 (degenerate hint); lens=%v", lens)
			}
		}
		if len(lens) != 0 {
			t.Errorf("out-of-range hint must produce no IAPREFIX at all, got lens=%v", lens)
		}
	})

	t.Run("boundary 128 is valid, 129 is not", func(t *testing.T) {
		for _, tc := range []struct {
			n        int
			wantLens []byte
		}{
			{128, []byte{128}},
			{129, nil},
			{1, []byte{1}},
			{0, nil},
			{-1, nil},
		} {
			lens, _ := iaPrefixLens(t, &DHCPv6Options{
				IATypes:   []string{"ia-pd"},
				PDPrefLen: tc.n,
			})
			if len(lens) != len(tc.wantLens) {
				t.Errorf("PDPrefLen=%d: lens=%v, want %v", tc.n, lens, tc.wantLens)
				continue
			}
			for i := range lens {
				if lens[i] != tc.wantLens[i] {
					t.Errorf("PDPrefLen=%d: lens=%v, want %v", tc.n, lens, tc.wantLens)
				}
			}
		}
	})
}
