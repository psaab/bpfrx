// Package frr generates FRR configuration and queries routing state via vtysh.
package frr

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/psviderski/bpfrx/pkg/config"
)

const (
	// DefaultConfigDir is where FRR reads conf.d snippets.
	DefaultConfigDir = "/etc/frr/conf.d"
	// BPFRXConfFile is the config file bpfrx manages.
	BPFRXConfFile = "bpfrx.conf"
)

// Manager handles FRR config generation and state queries.
type Manager struct {
	configDir  string
	configPath string
}

// New creates a new FRR manager.
func New() *Manager {
	dir := DefaultConfigDir
	return &Manager{
		configDir:  dir,
		configPath: filepath.Join(dir, BPFRXConfFile),
	}
}

// Apply generates an FRR config from OSPF/BGP settings and reloads FRR.
func (m *Manager) Apply(ospf *config.OSPFConfig, bgp *config.BGPConfig) error {
	if ospf == nil && bgp == nil {
		return m.Clear()
	}

	cfg := m.generateConfig(ospf, bgp)

	if err := os.MkdirAll(m.configDir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	if err := os.WriteFile(m.configPath, []byte(cfg), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	slog.Info("FRR config written", "path", m.configPath)

	// Reload FRR
	if err := m.reload(); err != nil {
		slog.Warn("FRR reload failed", "err", err)
		return err
	}

	return nil
}

// Clear removes the bpfrx config and reloads FRR.
func (m *Manager) Clear() error {
	if err := os.Remove(m.configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove config: %w", err)
	}
	_ = m.reload()
	return nil
}

func (m *Manager) generateConfig(ospf *config.OSPFConfig, bgp *config.BGPConfig) string {
	var b strings.Builder

	b.WriteString("! bpfrx managed config - do not edit\n")
	b.WriteString("!\n")

	if ospf != nil {
		b.WriteString("router ospf\n")
		if ospf.RouterID != "" {
			fmt.Fprintf(&b, " ospf router-id %s\n", ospf.RouterID)
		}
		for _, area := range ospf.Areas {
			for _, iface := range area.Interfaces {
				fmt.Fprintf(&b, " network %s area %s\n",
					ifaceNetwork(iface.Name), area.ID)
				if iface.Passive {
					fmt.Fprintf(&b, " passive-interface %s\n", iface.Name)
				}
			}
		}
		b.WriteString("exit\n!\n")
	}

	if bgp != nil && bgp.LocalAS > 0 {
		fmt.Fprintf(&b, "router bgp %d\n", bgp.LocalAS)
		if bgp.RouterID != "" {
			fmt.Fprintf(&b, " bgp router-id %s\n", bgp.RouterID)
		}
		for _, n := range bgp.Neighbors {
			fmt.Fprintf(&b, " neighbor %s remote-as %d\n", n.Address, n.PeerAS)
			if n.Description != "" {
				fmt.Fprintf(&b, " neighbor %s description %s\n", n.Address, n.Description)
			}
			if n.MultihopTTL > 0 {
				fmt.Fprintf(&b, " neighbor %s ebgp-multihop %d\n", n.Address, n.MultihopTTL)
			}
		}
		b.WriteString("exit\n!\n")
	}

	return b.String()
}

func (m *Manager) reload() error {
	// Try systemctl reload first
	cmd := exec.Command("systemctl", "reload", "frr")
	if err := cmd.Run(); err == nil {
		slog.Info("FRR reloaded via systemctl")
		return nil
	}

	// Fallback: load config directly via vtysh
	cmd = exec.Command("vtysh", "-f", m.configPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("vtysh reload: %w: %s", err, string(output))
	}
	slog.Info("FRR config loaded via vtysh")
	return nil
}

// ifaceNetwork returns a placeholder network string for an interface.
// In real use FRR matches based on interface addresses.
func ifaceNetwork(name string) string {
	// Use 0.0.0.0/0 as a catch-all; FRR resolves per-interface
	return "0.0.0.0/0"
}

// OSPFNeighbor represents an OSPF neighbor.
type OSPFNeighbor struct {
	NeighborID string
	Priority   string
	State      string
	Address    string
	Interface  string
}

// GetOSPFNeighbors queries FRR for OSPF neighbor state.
func (m *Manager) GetOSPFNeighbors() ([]OSPFNeighbor, error) {
	output, err := vtyshCmd("show ip ospf neighbor")
	if err != nil {
		return nil, err
	}

	var neighbors []OSPFNeighbor
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Skip header lines
		if fields[0] == "Neighbor" || strings.HasPrefix(line, "-") {
			continue
		}
		n := OSPFNeighbor{
			NeighborID: fields[0],
			Priority:   fields[1],
			State:      fields[2],
		}
		if len(fields) >= 5 {
			n.Address = fields[len(fields)-2]
			n.Interface = fields[len(fields)-1]
		}
		neighbors = append(neighbors, n)
	}
	return neighbors, nil
}

// GetOSPFDatabase returns raw OSPF database output.
func (m *Manager) GetOSPFDatabase() (string, error) {
	return vtyshCmd("show ip ospf database")
}

// BGPPeerSummary represents a BGP peer in the summary.
type BGPPeerSummary struct {
	Neighbor string
	AS       string
	MsgRcvd  string
	MsgSent  string
	UpDown   string
	State    string
	PfxRcd   string
}

// GetBGPSummary queries FRR for BGP peer summary.
func (m *Manager) GetBGPSummary() ([]BGPPeerSummary, error) {
	output, err := vtyshCmd("show bgp summary")
	if err != nil {
		return nil, err
	}

	var peers []BGPPeerSummary
	lines := strings.Split(output, "\n")
	inTable := false
	for _, line := range lines {
		if strings.HasPrefix(line, "Neighbor") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		p := BGPPeerSummary{
			Neighbor: fields[0],
			AS:       fields[2],
		}
		if len(fields) >= 10 {
			p.MsgRcvd = fields[3]
			p.MsgSent = fields[4]
			p.UpDown = fields[8]
			p.State = fields[9]
		}
		peers = append(peers, p)
	}
	return peers, nil
}

// BGPRoute represents a BGP route.
type BGPRoute struct {
	Network string
	NextHop string
	Metric  string
	Path    string
}

// GetBGPRoutes queries FRR for BGP routes.
func (m *Manager) GetBGPRoutes() ([]BGPRoute, error) {
	output, err := vtyshCmd("show bgp ipv4 unicast")
	if err != nil {
		return nil, err
	}

	var routes []BGPRoute
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, "*") && !strings.HasPrefix(line, " ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		r := BGPRoute{
			Network: fields[1],
			NextHop: fields[2],
		}
		if len(fields) >= 5 {
			r.Path = strings.Join(fields[4:], " ")
		}
		routes = append(routes, r)
	}
	return routes, nil
}

func vtyshCmd(command string) (string, error) {
	cmd := exec.Command("vtysh", "-c", command)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("vtysh %q: %w: %s", command, err, stderr.String())
	}
	return stdout.String(), nil
}
