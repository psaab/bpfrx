package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// dashNamedKernelIface finds a real host interface whose kernel name contains a
// '-' and round-trips through LinuxIfName from its slash form, so a Junos-form
// config name resolves to a real netdev. Returns (junos, kernel, true) or skips.
func dashNamedKernelIface(t *testing.T) (junos, kernel string, ok bool) {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", false
	}
	for _, in := range ifaces {
		if in.Name == "lo" || !strings.Contains(in.Name, "-") || strings.Contains(in.Name, "/") {
			continue
		}
		j := strings.ReplaceAll(in.Name, "-", "/")
		if config.LinuxIfName(j) == in.Name {
			return j, in.Name, true
		}
	}
	return "", "", false
}

// #4328: the gRPC text `show interfaces` twins mirror the CLI bug — only the
// terse handler resolved a bondless reth. `ShowInterfacesDetail` (the bare
// `show interfaces reth0` RPC) printed "Not present" (:150), and the ShowText
// `interfaces-detail` / `interfaces-extensive` branches walked netlink and
// never saw a reth. These tests assert the RPC + the text detail path now
// render the aggregate over its physical member.
//
// RED-on-revert: without the RethShowMaps resolution the reth block is dropped
// (raw netdev lookup) and the member name + config addresses vanish.

func rethShowGRPCStore(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/2 {
        gigether-options { redundant-parent reth0; }
    }
    reth0 {
        vlan-tagging;
        unit 50 {
            vlan-id 50;
            family inet { address 172.16.50.8/24; }
            family inet6 { address 2001:559:8585:50::8/64; }
        }
        unit 80 {
            vlan-id 80;
            family inet { address 172.16.80.8/24; }
        }
    }
}
security {
    zones {
        security-zone wan {
            interfaces { reth0.50; reth0.80; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &Server{store: store}
}

func TestShowInterfacesDetailRPCReth4328(t *testing.T) {
	s := rethShowGRPCStore(t)
	resp, err := s.ShowInterfacesDetail(context.Background(), &pb.ShowInterfacesDetailRequest{Filter: "reth0"})
	if err != nil {
		t.Fatalf("ShowInterfacesDetail(reth0): %v", err)
	}
	out := resp.GetOutput()
	if strings.Contains(out, "Not present") {
		t.Errorf("reth0 RPC still reports Not present:\n%s", out)
	}
	for _, want := range []string{
		"Physical interface: reth0",
		"aggregate over member ge-0/0/2",
		"172.16.50.8/24",
		"172.16.80.8/24",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("reth0 RPC missing %q\n%s", want, out)
		}
	}
}

// The bare `show interfaces <member>` RPC surfaces the member's aenet
// aggregation (the member is not zoned, so this exercises the synthetic path).
func TestShowInterfacesDetailRPCRethMember4328(t *testing.T) {
	s := rethShowGRPCStore(t)
	resp, err := s.ShowInterfacesDetail(context.Background(), &pb.ShowInterfacesDetailRequest{Filter: "ge-0-0-2"})
	if err != nil {
		t.Fatalf("ShowInterfacesDetail(ge-0-0-2): %v", err)
	}
	out := resp.GetOutput()
	if strings.Contains(out, "not found") {
		t.Fatalf("member RPC reports not found:\n%s", out)
	}
	for _, want := range []string{"member of reth0", "aenet --> reth0.50"} {
		if !strings.Contains(out, want) {
			t.Errorf("member RPC missing %q\n%s", want, out)
		}
	}
}

// The ShowText `interfaces-detail` twin (used by the remote CLI's
// `show interfaces reth0 detail`) renders the reth aggregate.
func TestShowInterfacesTextDetailReth4328(t *testing.T) {
	s := rethShowGRPCStore(t)
	cfg := s.store.ActiveConfig()
	var buf strings.Builder
	if err := s.showInterfacesDetail(cfg, "reth0", &buf); err != nil {
		t.Fatalf("showInterfacesDetail(reth0): %v", err)
	}
	out := buf.String()
	if strings.TrimSpace(out) == "" {
		t.Fatalf("reth0 text detail empty:\n%s", out)
	}
	for _, want := range []string{"Physical interface: reth0", "ge-0/0/2", "172.16.50.8/24"} {
		if !strings.Contains(out, want) {
			t.Errorf("reth0 text detail missing %q\n%s", want, out)
		}
	}
}

// A NON-reth interface authored in Junos slash form must resolve to its kernel
// netdev on the ShowInterfacesDetail RPC (#4328 Copilot follow-up). RED-on
// -revert: the raw config-name lookup prints "Not present".
func TestShowInterfacesDetailRPCNonRethKernelName4328(t *testing.T) {
	junos, kernel, ok := dashNamedKernelIface(t)
	if !ok {
		t.Skip("no dash-named host interface available to exercise slash->kernel resolution")
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ` + junos + ` { unit 0 { family inet { address 10.9.9.9/24; } } }
}
security { zones { security-zone z { interfaces { ` + junos + `.0; } } } }
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	s := &Server{store: store}
	resp, err := s.ShowInterfacesDetail(context.Background(), &pb.ShowInterfacesDetailRequest{Filter: junos})
	if err != nil {
		t.Fatalf("ShowInterfacesDetail(%s): %v", junos, err)
	}
	out := resp.GetOutput()
	if strings.Contains(out, "Not present") {
		t.Errorf("valid interface %s (kernel %s) rendered Not present:\n%s", junos, kernel, out)
	}
	if !strings.Contains(out, junos) {
		t.Errorf("RPC output missing interface name %s:\n%s", junos, out)
	}
}

// The ShowText `interfaces-extensive` twin lists the reth aggregate too.
func TestShowInterfacesTextExtensiveReth4328(t *testing.T) {
	s := rethShowGRPCStore(t)
	cfg := s.store.ActiveConfig()
	var buf strings.Builder
	if err := s.showInterfacesExtensive(cfg, "", &buf); err != nil {
		t.Fatalf("showInterfacesExtensive: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Physical interface: reth0", "ge-0/0/2", "172.16.50.8/24"} {
		if !strings.Contains(out, want) {
			t.Errorf("reth extensive missing %q\n%s", want, out)
		}
	}
}
