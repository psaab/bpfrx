package snmp

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

// #4917/#5264 are the RFC 3411 length-cap guards. #5283 changed the EngineID
// construction to fold a per-device component into a mandatory SHA-256 hash, so
// the historical short-hostname TEXT form no longer exists (every EngineID is
// now the 32-octet hashed form). These tests keep the length-cap RED-on-revert
// intent: whatever the construction, the result must stay within 5..32 octets
// for ALL hostnames, empty or multi-kilobyte.

// engineHash mirrors buildEngineID's payload for assertions:
// prefix(5) || 0x05 || sha256(deviceID || 0x00 || hostname)[:26].
func engineHash(deviceID []byte, hostname string) []byte {
	h := sha256.New()
	h.Write(deviceID)
	h.Write([]byte{0x00})
	h.Write([]byte(hostname))
	sum := h.Sum(nil)
	want := append(append([]byte{}, engineIDPrefix...), engineIDFormatOctets)
	return append(want, sum[:snmpEngineIDMaxLen-6]...)
}

// TestBuildEngineID_AlwaysHashed32 verifies the new (#5283) construction: every
// EngineID is exactly 32 octets — prefix(5) || 0x05 || sha256(...)[:26] — for a
// short hostname, so the length cap holds and the format octet honestly labels
// the binary digest.
func TestBuildEngineID_AlwaysHashed32(t *testing.T) {
	const host = "fw1.example.net" // 15 octets, would have been the text form pre-#5283
	dev := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	got := buildEngineID(host, dev)
	if len(got) != snmpEngineIDMaxLen {
		t.Fatalf("EngineID length %d, want exactly %d", len(got), snmpEngineIDMaxLen)
	}
	if !bytes.Equal(got[:5], engineIDPrefix) {
		t.Fatalf("prefix % x, want % x", got[:5], engineIDPrefix)
	}
	if got[5] != engineIDFormatOctets {
		t.Fatalf("format octet 0x%02x, want octets 0x%02x", got[5], engineIDFormatOctets)
	}
	if !bytes.Equal(got, engineHash(dev, host)) {
		t.Fatalf("EngineID % x != expected hashed form % x", got, engineHash(dev, host))
	}
}

// TestBuildEngineID_LengthCapAllHosts covers empty, boundary, and long
// hostnames. This is the #4917/#5264 RED-on-revert assertion: reverting to the
// unbounded `prefix || hostname` append makes a 300/4096-octet hostname exceed
// 32 octets and fail the len check.
func TestBuildEngineID_LengthCapAllHosts(t *testing.T) {
	dev := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	for _, n := range []int{0, 1, 15, 26, 27, 64, 300, 4096} {
		host := strings.Repeat("h", n)
		got := buildEngineID(host, dev)
		if len(got) < 5 || len(got) > snmpEngineIDMaxLen {
			t.Fatalf("hostname len %d: EngineID length %d out of RFC 3411 range 5..32", n, len(got))
		}
		if len(got) != snmpEngineIDMaxLen {
			t.Fatalf("hostname len %d: hashed EngineID length %d, want exactly %d", n, len(got), snmpEngineIDMaxLen)
		}
	}
}

// TestBuildEngineID_HostnameUniqueness verifies two distinct hostnames with the
// SAME device component produce distinct EngineIDs (SHA-256 collision
// resistance).
func TestBuildEngineID_HostnameUniqueness(t *testing.T) {
	dev := []byte{0x11, 0x22, 0x33}
	a := buildEngineID("node-alpha.example.net", dev)
	b := buildEngineID("node-bravo.example.net", dev)
	if bytes.Equal(a, b) {
		t.Fatal("distinct hostnames produced identical EngineIDs")
	}
}

// TestBuildEngineID_Deterministic verifies a fixed (hostname, deviceID) pair
// yields the same EngineID on every call (stable across restarts: no
// randomness, no timestamp at build time — randomness lives in the persisted
// deviceID).
func TestBuildEngineID_Deterministic(t *testing.T) {
	host := strings.Repeat("determinism-check.", 20) // ~360 octets
	dev := []byte{0xde, 0xad, 0xbe, 0xef}
	first := buildEngineID(host, dev)
	second := buildEngineID(host, dev)
	if !bytes.Equal(first, second) {
		t.Fatal("buildEngineID is not deterministic for a fixed (hostname, deviceID)")
	}
}
