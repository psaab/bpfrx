package daemon

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/bpfrx/pkg/config"
)

// testLink implements netlink.Link for testing.
type testLink struct {
	attrs netlink.LinkAttrs
}

func (l *testLink) Attrs() *netlink.LinkAttrs { return &l.attrs }
func (l *testLink) Type() string              { return "test" }

// mockLinkByName returns a function that resolves interfaces from a map.
func mockLinkByName(links map[string]*testLink) func(string) (netlink.Link, error) {
	return func(name string) (netlink.Link, error) {
		if l, ok := links[name]; ok {
			return l, nil
		}
		return nil, fmt.Errorf("link not found: %s", name)
	}
}

func newTestLink(name string, up bool) *testLink {
	var state netlink.LinkOperState = netlink.OperDown
	if up {
		state = netlink.OperUp
	}
	return &testLink{
		attrs: netlink.LinkAttrs{Name: name, OperState: state},
	}
}

func TestCheckVIPReadiness_AllUp(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 0,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	links := map[string]*testLink{
		"ge-0-0-0": newTestLink("ge-0-0-0", true),
	}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if !ready {
		t.Errorf("should be ready, got reasons: %v", reasons)
	}
}

func TestCheckVIPReadiness_InterfaceDown(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 0,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	links := map[string]*testLink{
		"ge-0-0-0": newTestLink("ge-0-0-0", false),
	}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if ready {
		t.Error("should NOT be ready with interface down")
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "down") {
		t.Errorf("unexpected reasons: %v", reasons)
	}
}

func TestCheckVIPReadiness_InterfaceNotFound(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 0,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	// Empty links map — interface not found.
	links := map[string]*testLink{}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if ready {
		t.Error("should NOT be ready when interface is missing")
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "not found") {
		t.Errorf("unexpected reasons: %v", reasons)
	}
}

func TestCheckVIPReadiness_NoVIPs(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {
					Name: "ge-0/0/0",
					// No RedundancyGroup, no RETH.
				},
			},
		},
	}

	links := map[string]*testLink{}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if !ready {
		t.Errorf("should be ready with no VIPs, got reasons: %v", reasons)
	}
}

func TestCheckVIPReadiness_WrongRG(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1, // RG 1, not 0
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	links := map[string]*testLink{}

	// Query RG 0 — reth0 is in RG 1, so no VIPs for RG 0.
	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if !ready {
		t.Errorf("should be ready for unrelated RG, got reasons: %v", reasons)
	}
}

func TestCheckVIPReadiness_InterfaceUpViaFlags(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 0,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	// Interface with OperDown but FlagUp set — should count as up.
	links := map[string]*testLink{
		"ge-0-0-0": {
			attrs: netlink.LinkAttrs{
				Name:      "ge-0-0-0",
				OperState: netlink.OperDown,
				Flags:     net.FlagUp,
			},
		},
	}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if !ready {
		t.Errorf("should be ready with FlagUp, got reasons: %v", reasons)
	}
}

func TestUserspaceRGConfigured(t *testing.T) {
	cfg := &config.Config{
		System: config.SystemConfig{
			DataplaneType: "userspace",
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
				},
				"reth1": {
					Name:            "reth1",
					RedundancyGroup: 2,
				},
			},
		},
	}

	if !userspaceRGConfigured(cfg, 1) {
		t.Fatal("userspaceRGConfigured(cfg, 1) = false, want true")
	}
	if userspaceRGConfigured(cfg, 0) {
		t.Fatal("userspaceRGConfigured(cfg, 0) = true, want false for RG0")
	}
	if userspaceRGConfigured(cfg, 3) {
		t.Fatal("userspaceRGConfigured(cfg, 3) = true, want false for missing RG")
	}

	cfg.System.DataplaneType = ""
	if userspaceRGConfigured(cfg, 1) {
		t.Fatal("userspaceRGConfigured(non-userspace, 1) = true, want false")
	}
}
