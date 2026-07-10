package snmp

import (
	"bytes"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #4924: berEncodeTimeTicks must prepend a 0x00 leading octet for high-bit
// values so an unsigned TimeTicks is never encoded as a negative/non-canonical
// signed BER integer (surfaces after ~248.5 days of uptime).

// decodeAppIntSigned interprets a set of unsigned-application-integer content
// octets exactly the way a strict manager decodes a BER INTEGER body: two's-
// complement, sign-extended from the leading octet. It is how sysUpTime /
// TimeTicks bytes are read off the wire, so a missing unsigned leading zero
// shows up here as a negative value.
func decodeAppIntSigned(t *testing.T, content []byte) int {
	t.Helper()
	v, _, err := berDecodeInteger(berEncodeTLV(tagInteger, content))
	if err != nil {
		t.Fatalf("decode content %v as INTEGER: %v", content, err)
	}
	return v
}

func TestBerEncodeTimeTicks_HighBitLeadingZero_4924(t *testing.T) {
	// Control: a small value keeps its minimal single-octet encoding.
	if got := berEncodeTimeTicks(0x0a); !bytes.Equal(got, []byte{0x0a}) {
		t.Fatalf("berEncodeTimeTicks(0x0a) = %v, want [0x0a]", got)
	}
	// Control: 0x7fffffff has the high bit clear, so no leading zero is added;
	// it stays exactly 4 content octets and decodes to a positive value.
	if got := berEncodeTimeTicks(0x7fffffff); !bytes.Equal(got, []byte{0x7f, 0xff, 0xff, 0xff}) {
		t.Fatalf("berEncodeTimeTicks(0x7fffffff) = %v, want [0x7f 0xff 0xff 0xff]", got)
	}

	// The regression: 0x80000000 hundredths (~248.5 days of uptime) has the
	// high bit set, so the unsigned TimeTicks MUST be prefixed with 0x00. Revert
	// the prepend and this yields the 4-octet form [0x80 0x00 0x00 0x00], which
	// fails both the length/leading-byte checks and the signed round-trip below.
	got := berEncodeTimeTicks(0x80000000)
	want := []byte{0x00, 0x80, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("berEncodeTimeTicks(0x80000000) = %v, want %v (5 octets, leading 0x00)", got, want)
	}
	// Decoded as a signed BER INTEGER (what a strict manager does) it must be
	// the positive value, not the negative that the 4-octet form decodes to.
	if v := decodeAppIntSigned(t, got); v != 0x80000000 {
		t.Fatalf("signed round-trip of 0x80000000 encoding = %d, want %d (non-canonical/negative BER)", v, 0x80000000)
	}

	// 0xffffffff (max, ~497 days) also has the high bit set.
	max := berEncodeTimeTicks(0xffffffff)
	wantMax := []byte{0x00, 0xff, 0xff, 0xff, 0xff}
	if !bytes.Equal(max, wantMax) {
		t.Fatalf("berEncodeTimeTicks(0xffffffff) = %v, want %v", max, wantMax)
	}
	if v := decodeAppIntSigned(t, max); v != 0xffffffff {
		t.Fatalf("signed round-trip of 0xffffffff encoding = %d, want %d", v, 0xffffffff)
	}
}

// TestSysUpTime_HighBitCanonical_4924 drives the real getOIDValueSnap sysUpTime
// path with a start time forced far enough in the past that the uptime crosses
// 0x80000000 hundredths (~248.5 days), and asserts the served TimeTicks value
// is canonical unsigned BER: leading octet high bit clear, positive when a
// strict manager signed-decodes it. Revert the #4924 prepend and the served
// value's leading octet is 0x80 and it decodes negative.
func TestSysUpTime_HighBitCanonical_4924(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	// 260 days of uptime -> ~2.25e9 hundredths, comfortably above 0x80000000.
	a.startTime = time.Now().Add(-260 * 24 * time.Hour)
	val, tag := a.getOIDValueSnap(oidSysUpTime, a.newIfSnapshot())
	if tag != tagTimeTicks {
		t.Fatalf("sysUpTime tag = 0x%02x, want tagTimeTicks (0x43)", tag)
	}
	if len(val) == 0 {
		t.Fatal("sysUpTime returned no value")
	}
	if val[0]&0x80 != 0 {
		t.Fatalf("sysUpTime TimeTicks %v has the high bit set in its leading octet — non-canonical unsigned BER (#4924)", val)
	}
	if v := decodeAppIntSigned(t, val); v < 0 {
		t.Fatalf("sysUpTime decodes as negative (%d) — an unsigned TimeTicks must be positive", v)
	}
}
