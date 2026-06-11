package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
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
		store: configstore.New(t.TempDir() + "/xpf.conf"),
		dp: &wireguardUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				WgTunnels: []dpuserspace.WgTunnelStatus{{
					Tunnel:                "wg0",
					TunnelEndpointID:      2,
					ListenPort:            51820,
					PeerPubkeyHex:         strings.Repeat("cd", 32),
					PeerEndpoint:          "198.51.100.7:51820",
					SessionConfirmed:      true,
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
		store: configstore.New(t.TempDir() + "/xpf.conf"),
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
