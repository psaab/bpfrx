package snmp

import (
	"bytes"
	"errors"
	"testing"
)

// #5453 / #5032 — the SNMPv3 privacy encrypt path must FAIL CLOSED when it
// cannot obtain good entropy.
//
// RFC 3826 §3.3 / RFC 3414 §8.1.1.1 model the per-message privacy salt
// (msgPrivacyParameters) as a counter seeded from an arbitrary boot-time value
// and incremented per message. #5032 replaced the pre-existing INDEPENDENT
// per-message random draw with that monotonic counter (Agent.nextPrivSalt),
// seeded ONCE from crypto/rand. The #5453 fail-closed guarantee is preserved but
// relocated to the seed: if the one-time seed draw cannot get entropy (getrandom
// EAGAIN at early boot, a FIPS module error), the salt source has no
// unpredictable start, so nextPrivSalt returns an error, encryptPDU propagates
// it, and buildV3Response drops the datagram (returns nil) rather than emit a
// PDU built from a zero/predictable salt. These tests inject an RNG failure via
// the randRead seam and assert that fail-closed behavior end to end.

// failRandRead is an entropy source that always fails, simulating getrandom
// EAGAIN / a FIPS RNG error. It writes nothing, so the caller's buffer stays
// all-zero — exactly the dangerous state the fix must refuse to seed from.
func failRandRead(b []byte) (int, error) {
	return 0, errors.New("simulated RNG failure")
}

// withFailingRand swaps randRead for the duration of fn and restores it after.
// The snmp package serves requests on a single serial goroutine and the tests
// do not run in parallel, so swapping the package var is safe.
func withFailingRand(t *testing.T, fn func()) {
	t.Helper()
	saved := randRead
	randRead = failRandRead
	defer func() { randRead = saved }()
	fn()
}

// TestPrivSalt_RNGFailClosed asserts that the salt source fails closed when its
// one-time seed draw cannot obtain entropy. A FRESH (never-seeded) agent must
// return an error and NO salt so the caller can drop the response.
func TestPrivSalt_RNGFailClosed(t *testing.T) {
	withFailingRand(t, func() {
		a := &Agent{} // never seeded; first nextPrivSalt triggers the seed draw
		salt, err := a.nextPrivSalt()
		if err == nil {
			t.Fatal("nextPrivSalt must return an error when the seed draw fails (fail closed)")
		}
		if salt != nil {
			t.Fatalf("nextPrivSalt must NOT return a salt on seed failure; got %v", salt)
		}
	})
}

// TestEncrypt_SuppliedSaltRoundTrip is the non-regression guard: given a valid
// 8-byte salt the encrypt paths succeed and round-trip, and a wrong-length salt
// is rejected with no ciphertext (the salt is now a caller-supplied input, so
// its length is validated rather than internally generated).
func TestEncrypt_SuppliedSaltRoundTrip(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	// 32 bytes (multiple of 8) so DES-CBC needs no padding and the roundtrip
	// compares byte-for-byte; AES-128-CFB is a stream cipher and length-agnostic.
	plaintext := []byte("aes-and-des-roundtrip-plaintext!")
	salt := testPrivSalt()

	encD, err := encryptDES(key, plaintext, salt)
	if err != nil || encD == nil {
		t.Fatalf("encryptDES with valid salt failed: %v", err)
	}
	if dec := decryptDES(key, salt, encD); !bytes.Equal(dec, plaintext) {
		t.Fatalf("DES roundtrip failed: got %q", dec)
	}

	encA, err := encryptAES128(key, plaintext, salt, 1, 100)
	if err != nil || encA == nil {
		t.Fatalf("encryptAES128 with valid salt failed: %v", err)
	}
	if dec := decryptAES128(key, salt, encA, 1, 100); !bytes.Equal(dec, plaintext) {
		t.Fatalf("AES128 roundtrip failed: got %q", dec)
	}

	// Wrong-length salt: no ciphertext, explicit error (RFC-mandated salt is 8
	// octets). A short/long salt would silently corrupt the IV construction.
	for _, bad := range [][]byte{nil, make([]byte, 7), make([]byte, 9)} {
		if enc, err := encryptDES(key, plaintext, bad); err == nil || enc != nil {
			t.Fatalf("encryptDES must reject a %d-byte salt (got enc=%v err=%v)", len(bad), enc, err)
		}
		if enc, err := encryptAES128(key, plaintext, bad, 1, 100); err == nil || enc != nil {
			t.Fatalf("encryptAES128 must reject a %d-byte salt (got enc=%v err=%v)", len(bad), enc, err)
		}
	}
}

// TestBuildV3Response_RNGFailClosed drives the response/send path: a manager's
// authPriv request must NOT be answered with a plaintext or zero-salt PDU when
// the salt source cannot seed. A FRESH agent whose very first salt seed fails
// must have buildV3Response return nil (handleV3Packet nil == no datagram, per
// agent.go Start's `if resp != nil` gate), so nothing leaves the agent.
func TestBuildV3Response_RNGFailClosed(t *testing.T) {
	reqFlags := byte(msgFlagAuth | msgFlagPriv)

	// Control: with a working RNG the authPriv response is built and encrypts.
	ctrl, _, _, privKey := newAuthPrivAgent(t, 5, 1000)
	resp := ctrl.buildV3Response(1, reqFlags, ctrl.v3Users["puser"], nil, 1, errNoError, 0, nil)
	if resp == nil {
		t.Fatal("control: authPriv response must be built with a working RNG")
	}
	if !decodeV3AuthPrivResponse(t, resp, privKey) {
		t.Fatal("control: authPriv response must decrypt to a GetResponse")
	}

	// Fail closed: a FRESH agent whose first seed draw fails must drop the
	// response entirely.
	fresh, _, _, _ := newAuthPrivAgent(t, 5, 1000)
	withFailingRand(t, func() {
		r := fresh.buildV3Response(1, reqFlags, fresh.v3Users["puser"], nil, 1, errNoError, 0, nil)
		if r != nil {
			t.Fatalf("authPriv response MUST be dropped when the salt seed fails (fail closed); "+
				"got %d bytes (plaintext/zero-salt leak)", len(r))
		}
	})
}
