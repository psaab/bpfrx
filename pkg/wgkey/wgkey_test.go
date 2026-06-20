package wgkey

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// RFC 7748 §6.1 X25519 test vector (Alice). The private scalar and the
// public key it derives are fixed by the standard, so this proves the
// derivation is the real X25519 (not merely self-consistent). If the
// keygen were mis-wired (wrong curve, wrong base point, wrong byte
// order) this vector would not reproduce.
const (
	rfc7748AlicePrivHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	rfc7748AlicePubHex  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// TestPublicKeyFromPrivateRFC7748 pins the derivation to the published
// X25519 test vector. FAILS if the X25519 primitive is removed or the
// base-point/byte-order handling regresses.
func TestPublicKeyFromPrivateRFC7748(t *testing.T) {
	priv := mustHex(t, rfc7748AlicePrivHex)
	wantPub := mustHex(t, rfc7748AlicePubHex)

	gotB64, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	want := base64.StdEncoding.EncodeToString(wantPub)
	if gotB64 != want {
		t.Fatalf("derived public key mismatch:\n got  %s\n want %s", gotB64, want)
	}
}

// TestClampDoesNotChangePublicKey proves the WireGuard-style clamping
// is idempotent under X25519: clamping the private scalar must NOT
// change the derived public key (clamping is applied internally by the
// scalar multiplication). This is why we may clamp the printed private
// key for `wg genkey` parity without breaking derivation.
func TestClampDoesNotChangePublicKey(t *testing.T) {
	priv := mustHex(t, rfc7748AlicePrivHex)
	unclampedPub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("unclamped derive: %v", err)
	}

	clamped := make([]byte, KeyLen)
	copy(clamped, priv)
	clamp(clamped)
	// Sanity: the RFC scalar is not already clamped, so clamping must
	// alter at least one byte (otherwise the test below is vacuous).
	if string(clamped) == string(priv) {
		t.Fatalf("clamp() was a no-op on the RFC scalar; the idempotence test would be vacuous")
	}
	clampedPub, err := PublicKeyFromPrivate(clamped)
	if err != nil {
		t.Fatalf("clamped derive: %v", err)
	}
	if clampedPub != unclampedPub {
		t.Fatalf("clamping changed the derived public key:\n unclamped %s\n clamped   %s",
			unclampedPub, clampedPub)
	}
}

// TestGenerateShapeAndClamp verifies a fresh key pair: both keys are
// 44-char base64 of 32 bytes (the WireGuard render shape), the private
// scalar is clamped (the bit pattern `wg genkey` emits), and the public
// key actually derives from the printed private key (so generate-then-
// configure is self-consistent on top of the RFC-pinned derivation).
func TestGenerateShapeAndClamp(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(kp.PrivateKey)
	if err != nil {
		t.Fatalf("private key not valid base64: %v", err)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(kp.PublicKey)
	if err != nil {
		t.Fatalf("public key not valid base64: %v", err)
	}
	if len(privBytes) != KeyLen || len(pubBytes) != KeyLen {
		t.Fatalf("key length: priv=%d pub=%d, want %d each", len(privBytes), len(pubBytes), KeyLen)
	}
	if len(kp.PrivateKey) != 44 || len(kp.PublicKey) != 44 {
		t.Fatalf("base64 render length: priv=%d pub=%d, want 44 each (WireGuard format)",
			len(kp.PrivateKey), len(kp.PublicKey))
	}

	// Clamp invariants on the printed private scalar — exactly the bits
	// `wg genkey` fixes.
	if privBytes[0]&7 != 0 {
		t.Errorf("private key low 3 bits not cleared: %#x", privBytes[0])
	}
	if privBytes[31]&128 != 0 {
		t.Errorf("private key high bit not cleared: %#x", privBytes[31])
	}
	if privBytes[31]&64 == 0 {
		t.Errorf("private key bit 6 not set: %#x", privBytes[31])
	}

	// The printed public key must derive from the printed private key.
	rederived, err := PublicKeyFromPrivate(privBytes)
	if err != nil {
		t.Fatalf("re-derive from generated private key: %v", err)
	}
	if rederived != kp.PublicKey {
		t.Fatalf("generated public key does not match re-derivation:\n printed   %s\n rederived %s",
			kp.PublicKey, rederived)
	}
}

// TestGenerateUnique guards against a broken RNG path returning the
// same key twice.
func TestGenerateUnique(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatalf("Generate a: %v", err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatalf("Generate b: %v", err)
	}
	if a.PrivateKey == b.PrivateKey {
		t.Fatalf("two Generate() calls produced identical private keys")
	}
}

// TestPublicKeyFromPrivateRejectsWrongLength ensures a malformed input
// is a clean error, not a panic or a silent wrong key.
func TestPublicKeyFromPrivateRejectsWrongLength(t *testing.T) {
	if _, err := PublicKeyFromPrivate([]byte{1, 2, 3}); err == nil {
		t.Fatalf("expected error for short private key, got nil")
	}
}

// TestHexToBase64 pins the hex→WireGuard-base64 conversion used by the
// `show security wireguard public-key` surface against the RFC 7748
// public key (hex on the wire, base64 for the operator).
func TestHexToBase64(t *testing.T) {
	got, err := HexToBase64(rfc7748AlicePubHex)
	if err != nil {
		t.Fatalf("HexToBase64: %v", err)
	}
	want := base64.StdEncoding.EncodeToString(mustHex(t, rfc7748AlicePubHex))
	if got != want {
		t.Fatalf("HexToBase64 = %q, want %q", got, want)
	}
	// Empty input passes through (no key surfaced yet).
	if got, err := HexToBase64(""); err != nil || got != "" {
		t.Fatalf("HexToBase64(\"\") = (%q, %v), want (\"\", nil)", got, err)
	}
	// Malformed hex and wrong length are clean errors.
	if _, err := HexToBase64("zz"); err == nil {
		t.Fatalf("expected error for non-hex input")
	}
	if _, err := HexToBase64("abcd"); err == nil {
		t.Fatalf("expected error for short (2-byte) key")
	}
}
