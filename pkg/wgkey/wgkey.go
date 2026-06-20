// Package wgkey is a small, stateless WireGuard X25519 key utility used
// by the operational `request security wireguard generate-private-key`
// command (#1434 Increment 1).
//
// It generates a fresh Curve25519/X25519 private key, clamps the scalar
// per the WireGuard/Curve25519 convention (priv[0]&=248, priv[31]&=127,
// priv[31]|=64) so the printed private key is byte-identical to what
// `wg genkey` emits, and derives the matching public key the way
// `wg pubkey` does. Keys are rendered in WireGuard-canonical base64
// (44-char base64 of 32 bytes) — the form an operator pastes into a
// peer's `[Peer] PublicKey =` / `[Interface] PrivateKey =`.
//
// This is intentionally pure-Go and daemon-independent: `request`
// commands print, they do not mutate config, and a key generator must
// work even with no dataplane loaded. It uses the standard library
// crypto/ecdh X25519 primitive (no extra dependency); clamping is
// idempotent under X25519 scalar multiplication, so the derived public
// key is the same whether the scalar is clamped or not — we clamp the
// PRIVATE key only so the printed scalar matches `wg genkey`.
package wgkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// KeyLen is the byte length of an X25519 key (private scalar or public
// point).
const KeyLen = 32

// KeyPair holds a freshly generated, WireGuard-canonical base64 key
// pair. PrivateKey is the clamped private scalar (as `wg genkey`
// prints); PublicKey is its derived public key (as `wg pubkey` prints).
type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

// clamp applies the Curve25519 clamping convention in place. WireGuard
// stores and prints the clamped scalar; clamping is idempotent under
// X25519 scalar multiplication, so this does not change the derived
// public key — it only canonicalizes the printed private key.
func clamp(k []byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

// PublicKeyFromPrivate derives the WireGuard-canonical base64 public
// key for a 32-byte private scalar. The scalar is accepted clamped or
// unclamped (clamping is applied internally by X25519); callers that
// hold the snapshot's hex private key should decode it to 32 bytes
// first. Returns an error if priv is not 32 bytes.
func PublicKeyFromPrivate(priv []byte) (string, error) {
	if len(priv) != KeyLen {
		return "", fmt.Errorf("wgkey: private key must be %d bytes, got %d", KeyLen, len(priv))
	}
	pk, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("wgkey: derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pk.PublicKey().Bytes()), nil
}

// HexToBase64 converts a 64-char lowercase hex WireGuard key (the form
// carried on xpf's snapshot/status wire, e.g. local_pubkey_hex) to the
// 44-char WireGuard-canonical base64 an operator pastes into a peer
// config. An empty input returns "" (no key surfaced yet); a malformed
// hex string or wrong length is a clean error rather than a panic.
func HexToBase64(hexKey string) (string, error) {
	if hexKey == "" {
		return "", nil
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", fmt.Errorf("wgkey: decode hex key: %w", err)
	}
	if len(raw) != KeyLen {
		return "", fmt.Errorf("wgkey: hex key must decode to %d bytes, got %d", KeyLen, len(raw))
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// Generate produces a fresh, clamped WireGuard key pair. The private
// key is read from crypto/rand and clamped so the printed scalar is
// byte-identical to `wg genkey`; the public key is the X25519 scalar
// multiplication of the (clamped) private key against the curve base
// point — identical to `echo <privkey> | wg pubkey`.
func Generate() (KeyPair, error) {
	raw := make([]byte, KeyLen)
	if _, err := rand.Read(raw); err != nil {
		return KeyPair{}, fmt.Errorf("wgkey: read random: %w", err)
	}
	clamp(raw)
	pub, err := PublicKeyFromPrivate(raw)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(raw),
		PublicKey:  pub,
	}, nil
}
