// Package dhcpserver manages Kea DHCP server configuration and lifecycle.
package dhcpserver

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/psaab/bpfrx/pkg/config"
)

const (
	kea4Config = "/etc/kea/kea-dhcp4.conf"
	kea6Config = "/etc/kea/kea-dhcp6.conf"
	kea4Svc    = "kea-dhcp4-server"
	kea6Svc    = "kea-dhcp6-server"
)

// Manager manages Kea DHCP server processes.
type Manager struct {
	running4 bool
	running6 bool
}

// New creates a new DHCP server manager.
func New() *Manager {
	return &Manager{}
}

// Apply generates Kea config from the bpfrx DHCP server config and restarts Kea.
func (m *Manager) Apply(cfg *config.DHCPServerConfig) error {
	if cfg == nil {
		m.Clear()
		return nil
	}

	// DHCPv4
	if cfg.DHCPLocalServer != nil && len(cfg.DHCPLocalServer.Groups) > 0 {
		if err := m.generateKea4Config(cfg); err != nil {
			return fmt.Errorf("generate kea4 config: %w", err)
		}
		if err := m.restartKea4(); err != nil {
			slog.Warn("failed to restart kea-dhcp4", "err", err)
		} else {
			m.running4 = true
		}
	} else if m.running4 {
		stopService(kea4Svc)
		m.running4 = false
		os.Remove(kea4Config)
	}

	// DHCPv6
	if cfg.DHCPv6LocalServer != nil && len(cfg.DHCPv6LocalServer.Groups) > 0 {
		if err := m.generateKea6Config(cfg); err != nil {
			return fmt.Errorf("generate kea6 config: %w", err)
		}
		if err := m.restartKea6(); err != nil {
			slog.Warn("failed to restart kea-dhcp6", "err", err)
		} else {
			m.running6 = true
		}
	} else if m.running6 {
		stopService(kea6Svc)
		m.running6 = false
		os.Remove(kea6Config)
	}

	return nil
}

// Clear stops Kea and removes generated configs.
func (m *Manager) Clear() {
	if m.running4 {
		stopService(kea4Svc)
		m.running4 = false
	}
	if m.running6 {
		stopService(kea6Svc)
		m.running6 = false
	}
	os.Remove(kea4Config)
	os.Remove(kea6Config)
}

// IsRunning returns true if any Kea server is running.
func (m *Manager) IsRunning() bool {
	return m.running4 || m.running6
}

// Lease represents a DHCP lease from Kea's lease database.
type Lease struct {
	Address    string
	HWAddress  string
	Hostname   string
	ValidLife  string
	ExpireTime string
	SubnetID   string
}

// GetLeases4 reads Kea DHCPv4 lease file and returns active leases.
func (m *Manager) GetLeases4() ([]Lease, error) {
	return parseLeaseCSV("/var/lib/kea/kea-leases4.csv")
}

// GetLeases6 reads Kea DHCPv6 lease file and returns active leases.
func (m *Manager) GetLeases6() ([]Lease, error) {
	return parseLeaseCSV("/var/lib/kea/kea-leases6.csv")
}

func parseLeaseCSV(path string) ([]Lease, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		return nil, nil
	}

	// Parse CSV header to find column indices
	header := strings.Split(lines[0], ",")
	cols := make(map[string]int)
	for i, h := range header {
		cols[h] = i
	}

	var leases []Lease
	for _, line := range lines[1:] {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		l := Lease{}
		if idx, ok := cols["address"]; ok && idx < len(fields) {
			l.Address = fields[idx]
		}
		if idx, ok := cols["hwaddr"]; ok && idx < len(fields) {
			l.HWAddress = fields[idx]
		}
		if idx, ok := cols["hostname"]; ok && idx < len(fields) {
			l.Hostname = fields[idx]
		}
		if idx, ok := cols["valid_lifetime"]; ok && idx < len(fields) {
			l.ValidLife = fields[idx]
		}
		if idx, ok := cols["expire"]; ok && idx < len(fields) {
			l.ExpireTime = fields[idx]
		}
		if idx, ok := cols["subnet_id"]; ok && idx < len(fields) {
			l.SubnetID = fields[idx]
		}
		if l.Address != "" {
			leases = append(leases, l)
		}
	}
	return leases, nil
}

func (m *Manager) generateKea4Config(cfg *config.DHCPServerConfig) error {
	type keaPool struct {
		Pool string `json:"pool"`
	}
	type keaOpt struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}
	type keaSubnet4 struct {
		ID            int       `json:"id"`
		Subnet        string    `json:"subnet"`
		Pools         []keaPool `json:"pools,omitempty"`
		Interface     string    `json:"interface,omitempty"`
		OptionData    []keaOpt  `json:"option-data,omitempty"`
		ValidLifetime int       `json:"valid-lifetime,omitempty"`
	}

	var subnets []keaSubnet4
	subnetID := 1
	for _, group := range cfg.DHCPLocalServer.Groups {
		for _, pool := range group.Pools {
			sub := keaSubnet4{
				ID:     subnetID,
				Subnet: pool.Subnet,
			}
			subnetID++
			if pool.RangeLow != "" && pool.RangeHigh != "" {
				sub.Pools = append(sub.Pools, keaPool{
					Pool: fmt.Sprintf("%s - %s", pool.RangeLow, pool.RangeHigh),
				})
			}
			if len(group.Interfaces) > 0 {
				sub.Interface = group.Interfaces[0]
			}
			if pool.Router != "" {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "routers", Data: pool.Router,
				})
			}
			if len(pool.DNSServers) > 0 {
				dnsStr := ""
				for i, d := range pool.DNSServers {
					if i > 0 {
						dnsStr += ", "
					}
					dnsStr += d
				}
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "domain-name-servers", Data: dnsStr,
				})
			}
			if pool.Domain != "" {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "domain-name", Data: pool.Domain,
				})
			}
			if pool.LeaseTime > 0 {
				sub.ValidLifetime = pool.LeaseTime
			}
			subnets = append(subnets, sub)
		}
	}

	// Collect interfaces
	var ifaces []string
	for _, group := range cfg.DHCPLocalServer.Groups {
		ifaces = append(ifaces, group.Interfaces...)
	}

	keaCfg := map[string]any{
		"Dhcp4": map[string]any{
			"interfaces-config": map[string]any{
				"interfaces": ifaces,
			},
			"lease-database": map[string]any{
				"type": "memfile",
				"name": "/var/lib/kea/kea-leases4.csv",
			},
			"valid-lifetime":   86400,
			"subnet4":          subnets,
		},
	}

	data, err := json.MarshalIndent(keaCfg, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll("/etc/kea", 0755); err != nil {
		return fmt.Errorf("create /etc/kea: %w", err)
	}

	return os.WriteFile(kea4Config, data, 0644)
}

func stopService(name string) {
	cmd := exec.Command("systemctl", "stop", name)
	if err := cmd.Run(); err != nil {
		slog.Debug("service stop failed", "service", name, "err", err)
	}
}

func (m *Manager) restartKea4() error {
	cmd := exec.Command("systemctl", "restart", kea4Svc)
	return cmd.Run()
}

func (m *Manager) generateKea6Config(cfg *config.DHCPServerConfig) error {
	type keaPool struct {
		Pool string `json:"pool"`
	}
	type keaOpt struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}
	type keaSubnet6 struct {
		ID            int       `json:"id"`
		Subnet        string    `json:"subnet"`
		Pools         []keaPool `json:"pools,omitempty"`
		Interface     string    `json:"interface,omitempty"`
		OptionData    []keaOpt  `json:"option-data,omitempty"`
		ValidLifetime int       `json:"valid-lifetime,omitempty"`
	}

	var subnets []keaSubnet6
	subnetID := 1
	for _, group := range cfg.DHCPv6LocalServer.Groups {
		for _, pool := range group.Pools {
			sub := keaSubnet6{
				ID:     subnetID,
				Subnet: pool.Subnet,
			}
			subnetID++
			if pool.RangeLow != "" && pool.RangeHigh != "" {
				sub.Pools = append(sub.Pools, keaPool{
					Pool: fmt.Sprintf("%s - %s", pool.RangeLow, pool.RangeHigh),
				})
			}
			if len(group.Interfaces) > 0 {
				sub.Interface = group.Interfaces[0]
			}
			if len(pool.DNSServers) > 0 {
				dnsStr := ""
				for i, d := range pool.DNSServers {
					if i > 0 {
						dnsStr += ", "
					}
					dnsStr += d
				}
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "dns-servers", Data: dnsStr,
				})
			}
			if pool.Domain != "" {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "domain-search", Data: pool.Domain,
				})
			}
			if pool.LeaseTime > 0 {
				sub.ValidLifetime = pool.LeaseTime
			}
			subnets = append(subnets, sub)
		}
	}

	var ifaces []string
	for _, group := range cfg.DHCPv6LocalServer.Groups {
		ifaces = append(ifaces, group.Interfaces...)
	}

	keaCfg := map[string]any{
		"Dhcp6": map[string]any{
			"interfaces-config": map[string]any{
				"interfaces": ifaces,
			},
			"lease-database": map[string]any{
				"type": "memfile",
				"name": "/var/lib/kea/kea-leases6.csv",
			},
			"valid-lifetime": 86400,
			"subnet6":        subnets,
		},
	}

	data, err := json.MarshalIndent(keaCfg, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll("/etc/kea", 0755); err != nil {
		return fmt.Errorf("create /etc/kea: %w", err)
	}

	return os.WriteFile(kea6Config, data, 0644)
}

func (m *Manager) restartKea6() error {
	cmd := exec.Command("systemctl", "restart", kea6Svc)
	return cmd.Run()
}
