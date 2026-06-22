package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// wireguardPubkeyCLIDP is a cliRuntime that returns a seeded WG status
// carrying a known local public key (hex on the wire). It reuses the
// embed-Manager + override-Status pattern of systemBuffersCLIUserspaceDP.
type wireguardPubkeyCLIDP struct {
	*dataplane.Manager
	status dpuserspace.ProcessStatus
}

func (f *wireguardPubkeyCLIDP) Status() (dpuserspace.ProcessStatus, error) {
	return f.status, nil
}

// TestHandleShowSecurityWireguardPublicKeyDispatch drives the LOCAL CLI
// dispatch entry point (`handleShowSecurity` → `case "wireguard"` →
// `public-key`) end-to-end with a seeded WG tunnel whose local pubkey is
// the cd-ladder hex key, and asserts the rendered output contains that
// key in WireGuard-canonical base64. This bites if the `public-key`
// dispatch case at cli_show_security_dispatch.go is removed or renamed
// (it would fall through to the status view, which does not print the
// local key). #1434 Increment 1.
//
// Mutation-verified: changing `args[1] == "public-key"` to any other
// string routes to showSecurityWireguard (the status view), whose output
// has no "Local public key:" line — the assertion below then fails.
func TestHandleShowSecurityWireguardPublicKeyDispatch(t *testing.T) {
	// base64.StdEncoding of bytes.fromhex("cd"*32).
	const wantB64 = "zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0="

	c := &CLI{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp: &wireguardPubkeyCLIDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				WgTunnels: []dpuserspace.WgTunnelStatus{{
					Tunnel:           "wg0",
					TunnelEndpointID: 3,
					ListenPort:       51820,
					LocalPubkeyHex:   strings.Repeat("cd", 32),
					Peers: []dpuserspace.WgPeerStatus{{
						PeerPubkeyHex: strings.Repeat("ab", 32),
					}},
				}},
			},
		},
	}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleShowSecurity([]string{"wireguard", "public-key"})
	})
	if callErr != nil {
		t.Fatalf("handleShowSecurity wireguard public-key error = %v", callErr)
	}
	for _, want := range []string{
		"Tunnel: wg0 (endpoint id 3)",
		"Local public key:   " + wantB64,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("public-key dispatch output missing %q:\n%s", want, out)
		}
	}
	// It must render base64, not the hex on the wire.
	if strings.Contains(out, strings.Repeat("cd", 32)) {
		t.Fatalf("public-key dispatch rendered hex, not base64:\n%s", out)
	}
	// And it must NOT have fallen through to the status view (whose
	// telemetry lines would appear if the dispatch case regressed).
	if strings.Contains(out, "Latest handshake:") || strings.Contains(out, "Peer public key:") {
		t.Fatalf("public-key dispatch fell through to the status view:\n%s", out)
	}
}
