package userspace

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// session_tunnel_discriminator_7188_test.go — #7188.
//
// The discriminator crosses THREE boundaries in this package and each one is a
// separate place it can be dropped: the binary open frame, the binary close
// frame, and the SessionSyncRequest built for the peer helper. A cell per
// boundary, because a green sibling on one leg says nothing about the others.

// TestDecodeSessionEventTunnelDiscriminator7188 covers the binary OPEN frame's
// trailing u64 (the last field, after the #5212 session id).
//
// RED-on-revert: drop the eventstream.go decode and the discriminator reads 0,
// which the peer helper treats as "not carried" and withholds the session on.
func TestDecodeSessionEventTunnelDiscriminator7188(t *testing.T) {
	// v6 SESSION_OPEN layout (see TestDecodeSessionEventRTFlowSessionID5212):
	// off reaches 148 after the #5212 id; the #7188 discriminator is [148:156].
	payload := make([]byte, 156)
	payload[0] = 6  // AddrFamily = v6
	payload[1] = 47 // Protocol = GRE
	// The helper's Keyed(100) encoding: bit 32 set, RFC 2890 key in the low 32.
	want := uint64(1)<<32 | 100
	binary.LittleEndian.PutUint64(payload[148:156], want)

	d, ok := decodeSessionEvent(payload)
	if !ok {
		t.Fatal("decodeSessionEvent returned false")
	}
	if d.TunnelDiscriminator != want {
		t.Fatalf("d.TunnelDiscriminator = %#x, want %#x", d.TunnelDiscriminator, want)
	}

	// A legacy frame stops after the #5212 id. Absent must decode to 0 — the
	// RESERVED "not carried" tag, NOT the None class.
	legacy := make([]byte, 148)
	legacy[0] = 6
	legacy[1] = 47
	dl, ok := decodeSessionEvent(legacy)
	if !ok {
		t.Fatal("decodeSessionEvent returned false for a legacy frame")
	}
	if dl.TunnelDiscriminator != 0 {
		t.Fatalf("legacy frame TunnelDiscriminator = %#x, want 0", dl.TunnelDiscriminator)
	}
}

// The CLOSE frame is a different decoder with a different layout. A close names
// the session to retract, and for protocol 47 the 5-tuple names two tunnels at
// once, so it needs the discriminator as much as the open does.
func TestDecodeSessionCloseEventTunnelDiscriminator7188(t *testing.T) {
	// v4 SESSION_CLOSE layout: 6 fixed + 4 src + 4 dst = 14, + 4 OwnerRGID = 18,
	// + 1 flags = 19, + 4 zone ids = 23, + 8 discriminator = 31.
	payload := make([]byte, 31)
	payload[0] = 4  // AddrFamily = v4
	payload[1] = 47 // Protocol = GRE
	want := uint64(1)<<32 | 200
	binary.LittleEndian.PutUint64(payload[23:31], want)

	d, ok := decodeSessionCloseEvent(payload)
	if !ok {
		t.Fatal("decodeSessionCloseEvent returned false")
	}
	if d.TunnelDiscriminator != want {
		t.Fatalf("close TunnelDiscriminator = %#x, want %#x", d.TunnelDiscriminator, want)
	}

	// A legacy close stops after the #3075 zone ids.
	legacy := make([]byte, 23)
	legacy[0] = 4
	legacy[1] = 47
	dl, ok := decodeSessionCloseEvent(legacy)
	if !ok {
		t.Fatal("decodeSessionCloseEvent returned false for a legacy frame")
	}
	if dl.TunnelDiscriminator != 0 {
		t.Fatalf("legacy close TunnelDiscriminator = %#x, want 0", dl.TunnelDiscriminator)
	}
}

// TestSessionSyncRequestCarriesTheTunnelDiscriminator7188 binds the LAST hop:
// SessionValue -> SessionSyncRequest, the struct the peer helper decodes.
//
// RED-on-revert: drop `req.TunnelDiscriminator = val.TunnelDiscriminator` from
// buildSessionSyncRequestV4/V6 and the helper sees 0 from a peer that is fully
// capable, so it withholds every keyed-GRE session instead of importing it.
func TestSessionSyncRequestCarriesTheTunnelDiscriminator7188(t *testing.T) {
	m := &Manager{}
	want := uint64(1)<<32 | 100

	var key dataplane.SessionKey
	copy(key.SrcIP[:], []byte{198, 51, 100, 7})
	copy(key.DstIP[:], []byte{203, 0, 113, 9})
	key.Protocol = 47
	v4 := m.buildSessionSyncRequestV4("upsert", key,
		&dataplane.SessionValue{TunnelDiscriminator: want})
	if v4.TunnelDiscriminator != want {
		t.Fatalf("v4 request TunnelDiscriminator = %#x, want %#x",
			v4.TunnelDiscriminator, want)
	}

	var keyV6 dataplane.SessionKeyV6
	copy(keyV6.SrcIP[:], []byte{0x20, 0x01, 0x0d, 0xb8})
	copy(keyV6.DstIP[:], []byte{0x20, 0x01, 0x0d, 0xb9})
	keyV6.Protocol = 47
	v6 := m.buildSessionSyncRequestV6("upsert", keyV6,
		&dataplane.SessionValueV6{TunnelDiscriminator: want})
	if v6.TunnelDiscriminator != want {
		t.Fatalf("v6 request TunnelDiscriminator = %#x, want %#x",
			v6.TunnelDiscriminator, want)
	}
}

// A numeric field whose 0 is MEANINGFUL must serialize explicitly, exactly like
// Generation (#1961 wire-type discipline). With `omitempty` the key would
// vanish for the None-class-adjacent value and a new helper could not tell "the
// daemon stated 0" from "the daemon has no such field" — which is the entire
// distinction the fail-closed import rests on.
func TestSessionSyncRequestAlwaysSerializesTheTunnelDiscriminator7188(t *testing.T) {
	blob, err := json.Marshal(SessionSyncRequest{Operation: "upsert"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(blob), `"tunnel_discriminator":0`) {
		t.Fatalf("a zero tunnel_discriminator must serialize EXPLICITLY so the helper "+
			"reads a stated value rather than inferring one from a missing key; got %s",
			blob)
	}
}

// TestSessionDeltaTunnelDiscriminatorWireKeyLockstepWithRust7188 pins the Go
// DECODER's JSON key against the key the Rust JSON producer actually emits.
//
// The two spellings must AGREE; neither is pinned to a literal, because a
// literal encodes which side is trusted. The Rust key is read out of its own
// source, so a rename on either side breaks this rather than silently leaving
// the field absent (serde/encoding-json both quietly decode a missing key to 0,
// and 0 here means "withhold the session").
func TestSessionDeltaTunnelDiscriminatorWireKeyLockstepWithRust7188(t *testing.T) {
	const rustSource = "../../../userspace-dp/src/protocol/binding.rs"
	src, err := os.ReadFile(rustSource)
	if err != nil {
		t.Fatalf("read %s: %v", rustSource, err)
	}
	// The producer's declaration, read from the Rust tree rather than restated.
	const decl = `#[serde(rename = "tunnel_discriminator", default)]`
	if !strings.Contains(string(src), decl) {
		t.Fatalf("%s no longer declares %s on SessionDeltaInfo — the Rust producer's "+
			"wire key changed and this decoder's json tag must follow it",
			rustSource, decl)
	}
	rustKey := "tunnel_discriminator"

	want := uint64(1)<<32 | 100
	blob := []byte(`{"` + rustKey + `":` + itoa7188(want) + `}`)
	var info SessionDeltaInfo
	if err := json.Unmarshal(blob, &info); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if info.TunnelDiscriminator != want {
		t.Fatalf("TunnelDiscriminator = %#x, want %#x. userspace-dp emits the "+
			"discriminator under the key %q; this struct's json tag must match it or "+
			"every session recovered through the JSON leg arrives with 0 and a "+
			"protocol-47 session is withheld from a peer that could express it",
			info.TunnelDiscriminator, want, rustKey)
	}

	// A legacy helper omits the key entirely.
	var legacy SessionDeltaInfo
	if err := json.Unmarshal([]byte(`{}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if legacy.TunnelDiscriminator != 0 {
		t.Fatalf("legacy delta TunnelDiscriminator = %#x, want 0 (not carried)",
			legacy.TunnelDiscriminator)
	}
}

func itoa7188(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
