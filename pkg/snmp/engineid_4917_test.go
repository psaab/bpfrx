package snmp

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

// TestBuildEngineID_GoldenShortHost pins the EXACT byte sequence a short
// (<=26 octet) hostname must produce: the historical text form
// prefix(5) || 0x04 || hostname. This is the #4917 migration guard — it goes
// RED if the short path is ever changed, because changing it would invalidate
// every already-localized USM key and manager cache on deployed appliances.
func TestBuildEngineID_GoldenShortHost(t *testing.T) {
	const host = "fw1.example.net" // 15 octets, well under the 26-octet cap
	want := []byte{
		0x80, 0x00, 0x01, 0x86, 0xa3, // enterprise prefix
		0x04, // format: administratively assigned text
		'f', 'w', '1', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'n', 'e', 't',
	}
	got := buildEngineID(host)
	if !bytes.Equal(got, want) {
		t.Fatalf("buildEngineID(%q) = % x, want % x", host, got, want)
	}
	if len(got) < 5 || len(got) > snmpEngineIDMaxLen {
		t.Fatalf("golden EngineID length %d out of RFC 3411 range 5..32", len(got))
	}
}

// TestBuildEngineID_Boundary26 verifies the largest hostname that still fits
// the text form: 26 octets -> header(6) + 26 = 32 octets, still 0x04 text form.
func TestBuildEngineID_Boundary26(t *testing.T) {
	host := strings.Repeat("a", 26)
	got := buildEngineID(host)
	if len(got) != snmpEngineIDMaxLen {
		t.Fatalf("26-octet hostname: EngineID length %d, want %d", len(got), snmpEngineIDMaxLen)
	}
	if got[5] != engineIDFormatText {
		t.Fatalf("26-octet hostname: format octet 0x%02x, want text 0x%02x", got[5], engineIDFormatText)
	}
	// Still the plain-text form: prefix || 0x04 || hostname.
	want := append(append(append([]byte{}, engineIDPrefix...), engineIDFormatText), []byte(host)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("26-octet hostname: EngineID % x, want text form % x", got, want)
	}
}

// TestBuildEngineID_HashedLongHosts covers every >26-octet case. These
// assertions go RED if buildEngineID is reverted to the unbounded
// `prefix(6) || hostname` append: a 27-octet hostname then yields 33 octets and
// the len <= 32 check below fails; a 64-octet hostname yields 70 octets, etc.
func TestBuildEngineID_HashedLongHosts(t *testing.T) {
	for _, n := range []int{27, 64, 300, 4096} {
		host := strings.Repeat("h", n)
		got := buildEngineID(host)

		// RFC 3411 bound: 5..32 octets. len > 32 is exactly the #4917 bug and
		// is the RED-on-revert assertion.
		if len(got) < 5 || len(got) > snmpEngineIDMaxLen {
			t.Fatalf("hostname len %d: EngineID length %d out of RFC 3411 range 5..32 (revert regression)", n, len(got))
		}
		if len(got) != snmpEngineIDMaxLen {
			t.Fatalf("hostname len %d: hashed EngineID length %d, want exactly %d", n, len(got), snmpEngineIDMaxLen)
		}
		// Hashed form: prefix || 0x05 (octets) || sha256(hostname)[:26].
		if !bytes.Equal(got[:5], engineIDPrefix) {
			t.Fatalf("hostname len %d: prefix % x, want % x", n, got[:5], engineIDPrefix)
		}
		if got[5] != engineIDFormatOctets {
			t.Fatalf("hostname len %d: format octet 0x%02x, want octets 0x%02x", n, got[5], engineIDFormatOctets)
		}
		sum := sha256.Sum256([]byte(host))
		if !bytes.Equal(got[6:], sum[:snmpEngineIDMaxLen-6]) {
			t.Fatalf("hostname len %d: payload is not sha256(hostname)[:26]", n)
		}
	}
}

// TestBuildEngineID_EmptyAndShortBounds verifies the lower bound holds for the
// empty and single-octet hostnames (>= 5 octets, still text form).
func TestBuildEngineID_EmptyAndShortBounds(t *testing.T) {
	for _, host := range []string{"", "x"} {
		got := buildEngineID(host)
		if len(got) < 5 || len(got) > snmpEngineIDMaxLen {
			t.Fatalf("hostname %q: EngineID length %d out of RFC 3411 range 5..32", host, len(got))
		}
		if got[5] != engineIDFormatText {
			t.Fatalf("hostname %q: format octet 0x%02x, want text 0x%02x", host, got[5], engineIDFormatText)
		}
	}
}

// TestBuildEngineID_LongHostUniqueness verifies two distinct long hostnames
// produce distinct EngineIDs (SHA-256 collision resistance), so different
// appliances that both exceed the cap are not aliased to one identity.
func TestBuildEngineID_LongHostUniqueness(t *testing.T) {
	a := buildEngineID(strings.Repeat("a", 40) + "-node-alpha")
	b := buildEngineID(strings.Repeat("a", 40) + "-node-bravo")
	if bytes.Equal(a, b) {
		t.Fatal("distinct long hostnames produced identical EngineIDs")
	}
}

// TestBuildEngineID_Deterministic verifies the same long hostname yields the
// same EngineID on every call (stable across restarts: no randomness, no
// timestamp).
func TestBuildEngineID_Deterministic(t *testing.T) {
	host := strings.Repeat("determinism-check.", 20) // ~360 octets
	first := buildEngineID(host)
	second := buildEngineID(host)
	if !bytes.Equal(first, second) {
		t.Fatal("buildEngineID is not deterministic for a fixed hostname")
	}
}
