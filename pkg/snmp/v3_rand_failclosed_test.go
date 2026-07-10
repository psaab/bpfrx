package snmp

import (
	"bytes"
	"errors"
	"testing"
)

// #5453 — the SNMPv3 privacy encrypt paths must FAIL CLOSED on an RNG error.
//
// RFC 3414 §8.2.1 requires the per-message privacy salt (msgPrivacyParameters)
// to be unpredictable. Before the fix, encryptDES/encryptAES128 ignored the
// error from crypto/rand.Read, so an RNG failure (getrandom EAGAIN at early
// boot, a FIPS module error) left the salt all-zero:
//   - DES:    zero salt -> CBC IV == a deterministic function of the long-term
//             privKey -> repeated-plaintext-prefix leakage across messages.
//   - AES128: zero salt -> the last 8 IV bytes are constant -> CFB IV REUSE for
//             every message in the same (boots,time) second.
// Either way the encrypted scopedPDU loses semantic security. These tests
// inject an RNG failure through the randRead seam and assert the encrypt path
// returns an error with NO ciphertext, and that the response builder drops the
// datagram (fail closed) rather than emitting a zero-salt or plaintext PDU.

// failRandRead is an entropy source that always fails, simulating getrandom
// EAGAIN / a FIPS RNG error. It writes nothing, so the caller's salt buffer
// stays all-zero — exactly the dangerous state the fix must refuse to use.
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

func TestEncryptDES_RNGFailClosed(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	plaintext := []byte("hello world test") // 16 bytes (multiple of 8)
	withFailingRand(t, func() {
		enc, pp, err := encryptDES(key, plaintext)
		if err == nil {
			t.Fatal("encryptDES must return an error on RNG failure (fail closed)")
		}
		if enc != nil {
			t.Fatalf("encryptDES must NOT produce ciphertext on RNG failure; got %d bytes", len(enc))
		}
		if pp != nil {
			t.Fatalf("encryptDES must NOT return a (zero) salt on RNG failure; got %v", pp)
		}
	})
}

func TestEncryptAES128_RNGFailClosed(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	plaintext := []byte("test data for aes encryption roundtrip")
	withFailingRand(t, func() {
		enc, pp, err := encryptAES128(key, plaintext, 1, 100)
		if err == nil {
			t.Fatal("encryptAES128 must return an error on RNG failure (fail closed)")
		}
		if enc != nil {
			t.Fatalf("encryptAES128 must NOT produce ciphertext on RNG failure; got %d bytes", len(enc))
		}
		if pp != nil {
			t.Fatalf("encryptAES128 must NOT return a (zero) salt on RNG failure; got %v", pp)
		}
	})
}

// TestEncrypt_NormalUsesNonZeroSalt is the non-regression guard: with the real
// RNG the encrypt paths still succeed AND use a non-zero (unpredictable) salt.
func TestEncrypt_NormalUsesNonZeroSalt(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	// 32 bytes (multiple of 8) so DES-CBC needs no padding and the roundtrip
	// compares byte-for-byte; AES-128-CFB is a stream cipher and length-agnostic.
	plaintext := []byte("aes-and-des-roundtrip-plaintext!")

	encD, ppD, err := encryptDES(key, plaintext)
	if err != nil || encD == nil {
		t.Fatalf("encryptDES with real RNG failed: %v", err)
	}
	if len(ppD) != 8 || bytes.Equal(ppD, make([]byte, 8)) {
		t.Fatalf("encryptDES produced a zero/short salt with real RNG: %v", ppD)
	}
	if dec := decryptDES(key, ppD, encD); !bytes.Equal(dec, plaintext) {
		t.Fatalf("DES roundtrip failed: got %q", dec)
	}

	encA, ppA, err := encryptAES128(key, plaintext, 1, 100)
	if err != nil || encA == nil {
		t.Fatalf("encryptAES128 with real RNG failed: %v", err)
	}
	if len(ppA) != 8 || bytes.Equal(ppA, make([]byte, 8)) {
		t.Fatalf("encryptAES128 produced a zero/short salt with real RNG: %v", ppA)
	}
	if dec := decryptAES128(key, ppA, encA, 1, 100); !bytes.Equal(dec, plaintext) {
		t.Fatalf("AES128 roundtrip failed: got %q", dec)
	}
}

// TestBuildV3Response_RNGFailClosed drives the response/send path: a manager's
// authPriv request must NOT be answered with a plaintext or zero-salt PDU when
// the RNG fails. buildV3Response must return nil (handleV3Packet nil == no
// datagram written, agent.go Start's `if resp != nil` gate), so nothing leaves
// the agent in the clear.
func TestBuildV3Response_RNGFailClosed(t *testing.T) {
	a, _, _, privKey := newAuthPrivAgent(t, 5, 1000)
	user := a.v3Users["puser"]
	reqFlags := byte(msgFlagAuth | msgFlagPriv)

	// Control: with the real RNG the authPriv response is built and encrypts.
	ctrl := a.buildV3Response(1, reqFlags, user, nil, 1, errNoError, 0, nil)
	if ctrl == nil {
		t.Fatal("control: authPriv response must be built with a working RNG")
	}
	if !decodeV3AuthPrivResponse(t, ctrl, privKey) {
		t.Fatal("control: authPriv response must decrypt to a GetResponse")
	}

	// Fail closed: an RNG failure must drop the response entirely.
	withFailingRand(t, func() {
		resp := a.buildV3Response(1, reqFlags, user, nil, 1, errNoError, 0, nil)
		if resp != nil {
			t.Fatalf("authPriv response MUST be dropped on RNG failure (fail closed); "+
				"got %d bytes (plaintext/zero-salt leak)", len(resp))
		}
	})
}
