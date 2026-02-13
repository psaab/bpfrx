// Package radvd generates radvd configuration and manages the radvd daemon.
package radvd

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/psaab/bpfrx/pkg/config"
)

const (
	// DefaultConfigPath is the radvd config file managed by bpfrx.
	DefaultConfigPath = "/etc/radvd.conf"
	// PidFile for radvd.
	DefaultPidFile = "/run/radvd.pid"
)

// Manager handles radvd config generation and daemon lifecycle.
type Manager struct {
	configPath string
	pidFile    string
}

// New creates a new radvd manager.
func New() *Manager {
	return &Manager{
		configPath: DefaultConfigPath,
		pidFile:    DefaultPidFile,
	}
}

// Apply generates radvd.conf from RA config and starts/reloads radvd.
func (m *Manager) Apply(raConfigs []*config.RAInterfaceConfig) error {
	if len(raConfigs) == 0 {
		return m.Clear()
	}

	cfg := m.generateConfig(raConfigs)

	if err := os.WriteFile(m.configPath, []byte(cfg), 0644); err != nil {
		return fmt.Errorf("write radvd config: %w", err)
	}

	slog.Info("radvd config written", "path", m.configPath, "interfaces", len(raConfigs))

	if err := m.reload(); err != nil {
		slog.Warn("radvd reload failed, attempting start", "err", err)
		return m.start()
	}

	return nil
}

// Clear stops radvd and removes the config.
func (m *Manager) Clear() error {
	m.stop()
	if err := os.Remove(m.configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove radvd config: %w", err)
	}
	return nil
}

func (m *Manager) generateConfig(raConfigs []*config.RAInterfaceConfig) string {
	var b strings.Builder

	b.WriteString("# bpfrx managed radvd config - do not edit\n\n")

	for _, ra := range raConfigs {
		fmt.Fprintf(&b, "interface %s\n{\n", ra.Interface)
		b.WriteString("    AdvSendAdvert on;\n")

		if ra.ManagedConfig {
			b.WriteString("    AdvManagedFlag on;\n")
		}
		if ra.OtherStateful {
			b.WriteString("    AdvOtherConfigFlag on;\n")
		}
		if ra.DefaultLifetime > 0 {
			fmt.Fprintf(&b, "    AdvDefaultLifetime %d;\n", ra.DefaultLifetime)
		}
		if ra.MaxAdvInterval > 0 {
			fmt.Fprintf(&b, "    MaxRtrAdvInterval %d;\n", ra.MaxAdvInterval)
		}
		if ra.MinAdvInterval > 0 {
			fmt.Fprintf(&b, "    MinRtrAdvInterval %d;\n", ra.MinAdvInterval)
		}
		if ra.LinkMTU > 0 {
			fmt.Fprintf(&b, "    AdvLinkMTU %d;\n", ra.LinkMTU)
		}
		if ra.Preference != "" {
			fmt.Fprintf(&b, "    AdvDefaultPreference %s;\n", ra.Preference)
		}

		b.WriteString("\n")

		for _, pfx := range ra.Prefixes {
			fmt.Fprintf(&b, "    prefix %s\n    {\n", pfx.Prefix)
			if pfx.OnLink {
				b.WriteString("        AdvOnLink on;\n")
			} else {
				b.WriteString("        AdvOnLink off;\n")
			}
			if pfx.Autonomous {
				b.WriteString("        AdvAutonomous on;\n")
			} else {
				b.WriteString("        AdvAutonomous off;\n")
			}
			if pfx.ValidLifetime > 0 {
				fmt.Fprintf(&b, "        AdvValidLifetime %d;\n", pfx.ValidLifetime)
			}
			if pfx.PreferredLife > 0 {
				fmt.Fprintf(&b, "        AdvPreferredLifetime %d;\n", pfx.PreferredLife)
			}
			b.WriteString("    };\n\n")
		}

		if len(ra.DNSServers) > 0 {
			b.WriteString("    RDNSS")
			for _, dns := range ra.DNSServers {
				fmt.Fprintf(&b, " %s", dns)
			}
			b.WriteString("\n    {\n    };\n\n")
		}

		if ra.NAT64Prefix != "" {
			fmt.Fprintf(&b, "    PREF64 %s\n    {\n", ra.NAT64Prefix)
			if ra.NAT64PrefixLife > 0 {
				fmt.Fprintf(&b, "        AdvPREF64Lifetime %d;\n", ra.NAT64PrefixLife)
			}
			b.WriteString("    };\n\n")
		}

		b.WriteString("};\n\n")
	}

	return b.String()
}

func (m *Manager) start() error {
	cmd := exec.Command("radvd", "-C", m.configPath, "-p", m.pidFile)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start radvd: %w", err)
	}
	slog.Info("radvd started")
	return nil
}

func (m *Manager) reload() error {
	// Try systemctl first
	cmd := exec.Command("systemctl", "reload", "radvd")
	if err := cmd.Run(); err == nil {
		slog.Info("radvd reloaded via systemctl")
		return nil
	}

	// Fallback: send SIGHUP via pidfile
	pidData, err := os.ReadFile(m.pidFile)
	if err != nil {
		return fmt.Errorf("radvd pidfile: %w", err)
	}
	pidStr := strings.TrimSpace(string(pidData))
	cmd = exec.Command("kill", "-HUP", pidStr)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("radvd SIGHUP: %w", err)
	}
	slog.Info("radvd reloaded via SIGHUP")
	return nil
}

func (m *Manager) stop() {
	// Try systemctl first
	cmd := exec.Command("systemctl", "stop", "radvd")
	if cmd.Run() == nil {
		slog.Info("radvd stopped via systemctl")
		return
	}

	// Fallback: kill via pidfile
	pidData, err := os.ReadFile(m.pidFile)
	if err != nil {
		return // not running
	}
	pidStr := strings.TrimSpace(string(pidData))
	exec.Command("kill", pidStr).Run()
	slog.Info("radvd stopped")
}
