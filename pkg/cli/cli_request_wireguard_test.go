package cli

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestHandleRequestSecurityWireguardGenerateKey verifies the local CLI
// routes `request security wireguard generate-private-key` to the
// pure-Go key generator and prints a valid base64 key pair. #1434
// Increment 1. The keygen correctness itself is pinned in pkg/wgkey;
// this guards the CLI dispatch wiring (a routing regression would fall
// through to "unknown request security target").
func TestHandleRequestSecurityWireguardGenerateKey(t *testing.T) {
	c := &CLI{}

	out := captureStdout(t, func() {
		if err := c.handleRequestSecurity([]string{"wireguard", "generate-private-key"}); err != nil {
			t.Fatalf("handleRequestSecurity wireguard generate-private-key: %v", err)
		}
	})

	priv := cliExtractKey(t, out, "Private key:")
	pub := cliExtractKey(t, out, "Public key:")
	for label, key := range map[string]string{"private": priv, "public": pub} {
		b, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(b) != 32 {
			t.Fatalf("%s key not 32-byte base64: %q (err=%v len=%d)", label, key, err, len(b))
		}
	}
	if priv == pub {
		t.Fatalf("private and public key identical: %q", priv)
	}
}

func cliExtractKey(t *testing.T, out, label string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, label) {
			return strings.TrimSpace(strings.TrimPrefix(line, label))
		}
	}
	t.Fatalf("output missing %q line:\n%s", label, out)
	return ""
}
