package main

import (
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// everything it printed. The remote `request security wireguard
// generate-private-key` path prints directly to stdout, so this is how
// we observe its output without an RPC.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
}

// TestRequestSecurityWireguardGenerateKey_Local verifies the remote CLI
// generates a WireGuard key pair LOCALLY (pure-Go, no gRPC) and prints
// both keys. It must NOT issue any SystemAction RPC — calling one on the
// nil-embedded fake client would panic, which is the guard. #1434
// Increment 1.
func TestRequestSecurityWireguardGenerateKey_Local(t *testing.T) {
	fake := &fakeBpfrxClient{} // un-stubbed: any RPC call panics
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.handleRequest([]string{"security", "wireguard", "generate-private-key"}); err != nil {
			t.Fatalf("handleRequest generate-private-key: %v", err)
		}
	})

	if fake.systemActionCalls != 0 {
		t.Fatalf("generate-private-key issued %d SystemAction RPC(s); must be local-only",
			fake.systemActionCalls)
	}

	priv := extractKey(t, out, "Private key:")
	pub := extractKey(t, out, "Public key:")

	privBytes, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(privBytes) != 32 {
		t.Fatalf("private key not 32-byte base64: %q (err=%v len=%d)", priv, err, len(privBytes))
	}
	pubBytes, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(pubBytes) != 32 {
		t.Fatalf("public key not 32-byte base64: %q (err=%v len=%d)", pub, err, len(pubBytes))
	}
	if priv == pub {
		t.Fatalf("private and public key are identical: %q", priv)
	}
}

func extractKey(t *testing.T, out, label string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, label) {
			return strings.TrimSpace(strings.TrimPrefix(line, label))
		}
	}
	t.Fatalf("output missing %q line:\n%s", label, out)
	return ""
}
