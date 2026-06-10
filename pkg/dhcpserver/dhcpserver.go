// Package dhcpserver manages Kea DHCP server configuration and lifecycle.
package dhcpserver

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// systemctlTimeout bounds every systemctl shell-out. Apply/Clear run on
// the config-apply path under applyConfigLocked's applySem
// (daemon_apply.go d.dhcpServer.Apply), so a hung systemctl (dbus
// stall, wedged Kea stop job) would otherwise block every commit
// indefinitely. Mirrors the 15s FRR reload precedent
// (pkg/frr/manager.go reloadTimeout). #1794/#1800.
const systemctlTimeout = 15 * time.Second

// runSystemctl runs `systemctl <args...>` under systemctlTimeout. On
// failure the returned error includes the captured output, so callers
// that previously logged a bare exit status now surface the systemd
// diagnostic too.
func runSystemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), systemctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	// WaitDelay caps the post-SIGKILL pipe-drain window.
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// unitIsActive reports whether a systemd unit is active (or on its way
// up) by querying `systemctl is-active`. A non-zero exit means "not
// active" — the state string is on stdout either way, so exit status
// is not treated as a query failure. If systemctl cannot run at all
// the output is empty and the unit is reported inactive (there is
// nothing useful to stop in that case anyway).
func unitIsActive(unit string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), systemctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", unit)
	cmd.WaitDelay = 5 * time.Second
	out, _ := cmd.Output()
	switch strings.TrimSpace(string(out)) {
	case "active", "activating", "reloading":
		return true
	}
	return false
}

const (
	kea4Config = "/etc/kea/kea-dhcp4.conf"
	kea6Config = "/etc/kea/kea-dhcp6.conf"
	kea4Svc    = "kea-dhcp4-server"
	kea6Svc    = "kea-dhcp6-server"
)

// Manager manages Kea DHCP server processes.
//
// The manager is authoritative over the kea-dhcp{4,6}-server units
// (#1778): it reconciles against the ACTUAL systemd unit state
// (`systemctl is-active`) rather than process-local booleans, so a
// stale Kea left running by a previous xpfd instance is stopped when
// the current config has no matching dhcp-server stanza.
type Manager struct {
	mu        sync.Mutex
	confPath4 string
	confPath6 string

	// Seams for tests (see test_seams.go). Production instances get
	// the package-level implementations from New().
	runSystemctl func(args ...string) error
	unitActive   func(unit string) bool
}

// New creates a new DHCP server manager.
func New() *Manager {
	return &Manager{
		confPath4:    kea4Config,
		confPath6:    kea6Config,
		runSystemctl: runSystemctl,
		unitActive:   unitIsActive,
	}
}

// Apply reconciles the Kea DHCP servers with the xpf DHCP server
// config. For each address family that is configured it regenerates
// the Kea config and restarts the unit; for each family that is NOT
// configured (including cfg == nil) it stops the unit if systemd
// reports it active — regardless of whether this process started it —
// and removes the generated config file.
//
// Fail-closed (#1778): a restart failure (or a failure to stop an
// active unit that is no longer in config) is returned to the caller
// so a config commit surfaces the failure instead of reporting
// success while no DHCP service is running.
func (m *Manager) Apply(cfg *config.DHCPServerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error

	want4 := cfg != nil && cfg.DHCPLocalServer != nil && len(cfg.DHCPLocalServer.Groups) > 0
	want6 := cfg != nil && cfg.DHCPv6LocalServer != nil && len(cfg.DHCPv6LocalServer.Groups) > 0

	if want4 {
		if err := m.generateKea4Config(cfg); err != nil {
			errs = append(errs, fmt.Errorf("generate kea4 config: %w", err))
		} else if err := m.runSystemctl("restart", kea4Svc); err != nil {
			errs = append(errs, fmt.Errorf("restart %s: %w", kea4Svc, err))
		}
	} else if err := m.clearFamilyLocked(kea4Svc, m.confPath4); err != nil {
		errs = append(errs, err)
	}

	if want6 {
		if err := m.generateKea6Config(cfg); err != nil {
			errs = append(errs, fmt.Errorf("generate kea6 config: %w", err))
		} else if err := m.runSystemctl("restart", kea6Svc); err != nil {
			errs = append(errs, fmt.Errorf("restart %s: %w", kea6Svc, err))
		}
	} else if err := m.clearFamilyLocked(kea6Svc, m.confPath6); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// clearFamilyLocked stops one Kea unit if systemd reports it active
// and removes its generated config file. Caller must hold m.mu.
func (m *Manager) clearFamilyLocked(svc, confPath string) error {
	var err error
	if m.unitActive(svc) {
		if e := m.runSystemctl("stop", svc); e != nil {
			err = fmt.Errorf("stop %s: %w", svc, e)
			slog.Warn("failed to stop Kea unit", "service", svc, "err", e)
		} else {
			slog.Info("stopped Kea unit not in current config", "service", svc)
		}
	}
	os.Remove(confPath)
	return err
}

// Clear stops both Kea units (if systemd reports them active) and
// removes the generated configs. Stop failures are logged at Warn by
// clearFamilyLocked; callers on the VRRP transition path (daemon_ha)
// cannot fail a state transition, so Clear keeps a void signature.
// Commit-path callers use Apply(nil) instead, which returns errors.
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.clearFamilyLocked(kea4Svc, m.confPath4)
	_ = m.clearFamilyLocked(kea6Svc, m.confPath6)
}

// IsRunning returns true if any Kea server unit is active per systemd
// (authoritative — survives xpfd restarts, unlike the pre-#1778
// process-local booleans).
func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.unitActive(kea4Svc) || m.unitActive(kea6Svc)
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
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // memfile rows can vary across Kea versions
	r.Comment = '#'
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(records) < 2 {
		return nil, nil
	}

	// Parse CSV header to find column indices
	cols := make(map[string]int)
	for i, h := range records[0] {
		cols[h] = i
	}

	var leases []Lease
	for _, fields := range records[1:] {
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

// subnetInterface returns the per-subnet interface binding for a
// group. Kea allows at most ONE interface per subnet; for a
// single-interface group binding it explicitly is the most robust
// selection. For multi-interface groups the binding is omitted so Kea
// falls back to address-based subnet selection (matching the address
// of the receiving interface against the subnet prefix) — the
// pre-#1778 renderer silently bound only the first interface,
// breaking the others. All group interfaces are always listed in
// interfaces-config, so Kea listens on every one either way.
func subnetInterface(group *config.DHCPServerGroup) string {
	if len(group.Interfaces) == 1 {
		return group.Interfaces[0]
	}
	return ""
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
			sub.Interface = subnetInterface(group)
			if pool.Router != "" {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "routers", Data: pool.Router,
				})
			}
			if len(pool.DNSServers) > 0 {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "domain-name-servers", Data: strings.Join(pool.DNSServers, ", "),
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
			"valid-lifetime": 86400,
			"subnet4":        subnets,
		},
	}

	return m.writeKeaConfig(m.confPath4, keaCfg)
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
			sub.Interface = subnetInterface(group)
			if len(pool.DNSServers) > 0 {
				sub.OptionData = append(sub.OptionData, keaOpt{
					Name: "dns-servers", Data: strings.Join(pool.DNSServers, ", "),
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

	return m.writeKeaConfig(m.confPath6, keaCfg)
}

func (m *Manager) writeKeaConfig(path string, keaCfg map[string]any) error {
	data, err := json.MarshalIndent(keaCfg, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return os.WriteFile(path, data, 0644)
}
