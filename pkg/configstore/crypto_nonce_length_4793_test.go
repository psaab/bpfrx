package configstore

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// #4793 RED-on-revert: crypto/cipher's AEAD.Open panics if
// len(nonce) != gcm.NonceSize() instead of returning an error. The nonce
// in an on-disk config-DB envelope comes straight from a base64 decode
// with no length check, so a corrupt or tampered envelope (truncated
// write, hand-edited JSON, bit rot) crashed the daemon inside
// maybeDecryptTreeJSON on every boot -- a boot loop -- instead of
// surfacing a clean error. Reverting the length guard added in
// crypto.go makes this test panic instead of returning an error.
func TestMaybeDecryptTreeJSON_WrongNonceLength_ReturnsErrorNotPanic(t *testing.T) {
	dir := t.TempDir()
	db := &DB{dir: dir}

	// A valid 32-byte master key so the flow reaches gcm.Open instead of
	// failing earlier on key material.
	key := make([]byte, 32)
	if err := os.WriteFile(db.masterKeyPath(), key, 0600); err != nil {
		t.Fatalf("write master key: %v", err)
	}

	env := encryptedTreeEnvelope{
		Format: encryptedTreeFormat,
		PRF:    "sha256",
		Salt:   base64.StdEncoding.EncodeToString(make([]byte, 16)),
		// Standard AES-GCM nonce size is 12 bytes; 4 is deliberately wrong.
		Nonce: base64.StdEncoding.EncodeToString(make([]byte, 4)),
		Data:  base64.StdEncoding.EncodeToString([]byte("does-not-matter-nonce-check-must-fire-first")),
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("maybeDecryptTreeJSON panicked on wrong-length nonce (want clean error): %v", r)
		}
	}()

	_, decrypted, err := db.maybeDecryptTreeJSON(data, nil)
	if err == nil {
		t.Fatalf("expected error for wrong-length nonce, got nil (decrypted=%v)", decrypted)
	}
}
