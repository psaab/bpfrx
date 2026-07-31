package grpcapi

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	dataplane "github.com/psaab/xpf/pkg/dataplane"
)

// #5649 (codex-181 C181-C11): session page tokens were decoded with a `len(b) <
// binary.Size(key)` check, so any oversized/trailing-byte token hex-decoded to
// the same cursor as the canonical key (a noncanonical opaque token), and a
// token near the 16 MiB gRPC limit forced transient base64/hex allocations many
// times the key size before the ABI prefix decode discarded the excess. The
// decoders now require the EXACT ABI length and parsePageToken rejects tokens
// over maxPageTokenLen before any decode.
//
// FAIL-ON-REVERT: changing the exact-length checks in decodeSessionKeyV4/V6
// back to `<` makes the trailing-byte cases decode successfully and go RED;
// removing the maxPageTokenLen guard makes the oversized case decode instead of
// erroring.
func TestPageTokenCanonical_5649(t *testing.T) {
	// A valid round-trip token still decodes cleanly (no false rejects).
	var v4 dataplane.SessionKey
	v4.SrcIP = [4]byte{10, 0, 0, 1}
	v4.DstIP = [4]byte{10, 0, 0, 2}
	v4.SrcPort = 1111
	v4.DstPort = 2222
	v4.Protocol = 6
	kind, kb, err := parsePageToken(encodePageTokenV4(v4))
	if err != nil || kind != "v4" {
		t.Fatalf("valid v4 round-trip: kind=%q err=%v", kind, err)
	}
	if _, err := decodeSessionKeyV4(kb); err != nil {
		t.Fatalf("valid v4 key must decode: %v", err)
	}

	// A token whose hex payload carries a trailing byte beyond the ABI key must
	// be rejected — previously it silently aliased the same cursor.
	raw := make([]byte, binary.Size(v4)+1)
	trailing := "v4:" + hex.EncodeToString(raw)
	tok := base64.RawURLEncoding.EncodeToString([]byte(trailing))
	kind, kb, err = parsePageToken(tok)
	if err != nil || kind != "v4" {
		t.Fatalf("trailing-byte token should still parse as v4: kind=%q err=%v", kind, err)
	}
	if _, err := decodeSessionKeyV4(kb); err == nil {
		t.Fatal("decodeSessionKeyV4 must REJECT a key with a trailing byte (noncanonical token)")
	} else if !strings.Contains(err.Error(), "wrong length") {
		t.Fatalf("trailing-byte reject error %q should mention wrong length", err)
	}

	// The v6 decoder enforces the same exact-length invariant.
	var v6 dataplane.SessionKeyV6
	rawV6 := make([]byte, binary.Size(v6)+1)
	if _, err := decodeSessionKeyV6(rawV6); err == nil {
		t.Fatal("decodeSessionKeyV6 must REJECT an over-length key")
	}

	// An oversized encoded token is rejected before any base64/hex decode.
	// Use a literal length (not the maxPageTokenLen const) so this test still
	// compiles when the fix is reverted for the fail-on-revert gate. 8 KiB is
	// far above any legitimate v4/v6 token and any reasonable cap.
	huge := "v4:" + strings.Repeat("ab", 4096)
	if _, _, err := parsePageToken(huge); err == nil {
		t.Fatal("parsePageToken must REJECT a token far larger than any real cursor")
	} else if !strings.Contains(err.Error(), "too long") {
		t.Fatalf("oversized reject error %q should mention too long", err)
	}
}
