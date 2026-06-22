package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type wireguardUserspaceDP struct {
	*dataplane.Manager
	status dpuserspace.ProcessStatus
}

func (f *wireguardUserspaceDP) Status() (dpuserspace.ProcessStatus, error) {
	return f.status, nil
}

// #1865: the `wireguard` / `wireguard-detail` ShowText topics render
// the helper's per-tunnel telemetry rows via FormatWireguardStatus —
// the same shared formatter the local CLI uses.
func TestShowTextWireguardTopics(t *testing.T) {
	s := &Server{
		store: newConfigStore(t, t.TempDir()+"/xpf.conf"),
		dp: &wireguardUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				WgTunnels: []dpuserspace.WgTunnelStatus{{
					Tunnel:           "wg0",
					TunnelEndpointID: 2,
					ListenPort:       51820,
					Peers: []dpuserspace.WgPeerStatus{{
						PeerPubkeyHex:    strings.Repeat("cd", 32),
						PeerEndpoint:     "198.51.100.7:51820",
						SessionConfirmed: true,
					}},
					HsRxDropsMac1Mismatch: 4,
					EncapMtuDrops:         9,
					DecapPackets:          11,
					EncapPackets:          12,
				}},
			},
		},
	}

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "wireguard"})
	if err != nil {
		t.Fatalf("ShowText(wireguard) error = %v", err)
	}
	out := resp.GetOutput()
	for _, want := range []string{
		"Tunnel: wg0 (endpoint id 2)",
		"Peer endpoint:      198.51.100.7:51820",
		"Session:            session confirmed",
		"Latest handshake:   never",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("ShowText(wireguard) missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "by reason") {
		t.Fatalf("summary topic must not render detail tables:\n%s", out)
	}

	resp, err = s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "wireguard-detail"})
	if err != nil {
		t.Fatalf("ShowText(wireguard-detail) error = %v", err)
	}
	out = resp.GetOutput()
	for _, want := range []string{
		"Handshake drops by reason:",
		"mac1-mismatch            4",
		"mtu-exceeded             9",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("ShowText(wireguard-detail) missing %q:\n%s", want, out)
		}
	}
}

// No WG tunnels configured: both topics render the explicit empty
// message rather than nothing.
func TestShowTextWireguardEmpty(t *testing.T) {
	s := &Server{
		store: newConfigStore(t, t.TempDir()+"/xpf.conf"),
		dp: &wireguardUserspaceDP{
			Manager: dataplane.New(),
		},
	}
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "wireguard"})
	if err != nil {
		t.Fatalf("ShowText(wireguard) error = %v", err)
	}
	if !strings.Contains(resp.GetOutput(), "No WireGuard tunnels configured") {
		t.Fatalf("empty output = %q", resp.GetOutput())
	}
}

// #1434 Increment 1: the `wireguard-public-key` ShowText topic must
// route to showWireguardPublicKey and render the LOCAL public key in
// WireGuard-canonical base64. This pins the gRPC topic-string mapping in
// server_show.go — renaming or removing the case would make the topic
// fall through to the default "unknown" handler (which does NOT emit the
// local key), failing the assertion below.
//
// Mutation-verified: changing the case label in server_show.go from
// "wireguard-public-key" to anything else makes ShowText return the
// unknown-topic output, so the "Local public key:" check fails.
func TestShowTextWireguardPublicKeyTopic(t *testing.T) {
	// base64.StdEncoding of bytes.fromhex("cd"*32).
	const wantB64 = "zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0="

	s := &Server{
		store: newConfigStore(t, t.TempDir()+"/xpf.conf"),
		dp: &wireguardUserspaceDP{
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

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "wireguard-public-key"})
	if err != nil {
		t.Fatalf("ShowText(wireguard-public-key) error = %v", err)
	}
	out := resp.GetOutput()
	for _, want := range []string{
		"Tunnel: wg0 (endpoint id 3)",
		"Local public key:   " + wantB64,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("ShowText(wireguard-public-key) missing %q:\n%s", want, out)
		}
	}
	// Base64, not the hex on the wire; and not a fall-through to status.
	if strings.Contains(out, strings.Repeat("cd", 32)) {
		t.Fatalf("public-key topic rendered hex, not base64:\n%s", out)
	}
	if strings.Contains(out, "Peer public key:") || strings.Contains(out, "Latest handshake:") {
		t.Fatalf("public-key topic fell through to the status view:\n%s", out)
	}
}
