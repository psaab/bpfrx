package userspace

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestZZProbe6941Snapshot(t *testing.T) {
	cmds := []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key 1111111111111111111111111111111111111111111111111111111111111111",
		"set interfaces wg0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa allowed-ips 10.0.0.0/24",
		"set interfaces wg0 unit 3 family inet address 10.66.3.1/24",
		"set interfaces wg0 unit 3 tunnel mode gre",
		"set interfaces wg0 unit 3 tunnel source 10.1.1.1",
		"set interfaces wg0 unit 3 tunnel destination 10.1.1.2",
	}
	tree := &config.ConfigTree{}
	for _, c := range cmds {
		p, err := config.ParseSetCommand(c)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath: %v", err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ifs := buildInterfaceSnapshots(cfg)
	// Production has real ifindexes; this host has no wg0/wg0u3 devices, and
	// buildTunnelEndpointSnapshots skips rows with Ifindex<=0. Fill them in
	// so the production builder runs on a production-shaped input.
	for i := range ifs {
		ifs[i].Ifindex = 100 + i
	}
	fmt.Println("--- interface rows ---")
	for _, i := range ifs {
		addrs := []string{}
		for _, a := range i.Addresses {
			addrs = append(addrs, a.Address)
		}
		fmt.Printf("  Name=%-10q LinuxName=%-8q Ifindex=%d ParentLinux=%-6q addrs=%v\n",
			i.Name, i.LinuxName, i.Ifindex, i.ParentLinuxName, addrs)
	}
	fmt.Println("--- tunnel endpoints ---")
	for _, e := range buildTunnelEndpointSnapshots(cfg, ifs) {
		fmt.Printf("  Interface=%-10q LinuxName=%-8q Ifindex=%d Mode=%q\n",
			e.Interface, e.LinuxName, e.Ifindex, e.Mode)
	}
}
