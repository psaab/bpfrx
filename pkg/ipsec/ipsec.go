// Package ipsec generates strongSwan (swanctl) configuration and queries SA status.
package ipsec

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/psaab/bpfrx/pkg/config"
)

const (
	// DefaultSwanctlDir is where swanctl reads conf.d snippets.
	DefaultSwanctlDir = "/etc/swanctl/conf.d"
	// BPFRXConfFile is the config file bpfrx manages.
	BPFRXConfFile = "bpfrx.conf"
)

// Manager handles strongSwan config generation and SA queries.
type Manager struct {
	configDir  string
	configPath string
}

// New creates a new IPsec manager.
func New() *Manager {
	dir := DefaultSwanctlDir
	return &Manager{
		configDir:  dir,
		configPath: filepath.Join(dir, BPFRXConfFile),
	}
}

// Apply generates swanctl config and reloads strongSwan.
func (m *Manager) Apply(ipsecCfg *config.IPsecConfig) error {
	if ipsecCfg == nil || len(ipsecCfg.VPNs) == 0 {
		return m.Clear()
	}

	cfg := m.generateConfig(ipsecCfg)

	if err := os.MkdirAll(m.configDir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	if err := os.WriteFile(m.configPath, []byte(cfg), 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	slog.Info("swanctl config written", "path", m.configPath)

	if err := m.reload(); err != nil {
		slog.Warn("swanctl reload failed", "err", err)
		return err
	}

	return nil
}

// Clear removes the bpfrx config and reloads strongSwan.
func (m *Manager) Clear() error {
	if err := os.Remove(m.configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove config: %w", err)
	}
	_ = m.reload()
	return nil
}

func (m *Manager) generateConfig(ipsecCfg *config.IPsecConfig) string {
	var b strings.Builder

	b.WriteString("# bpfrx managed config - do not edit\n\n")

	// Connections
	b.WriteString("connections {\n")
	for name, vpn := range ipsecCfg.VPNs {
		fmt.Fprintf(&b, "  %s {\n", name)

		if vpn.LocalAddr != "" {
			fmt.Fprintf(&b, "    local_addrs = %s\n", vpn.LocalAddr)
		}
		if vpn.Gateway != "" {
			fmt.Fprintf(&b, "    remote_addrs = %s\n", vpn.Gateway)
		}

		b.WriteString("    local {\n")
		b.WriteString("      auth = psk\n")
		b.WriteString("    }\n")
		b.WriteString("    remote {\n")
		b.WriteString("      auth = psk\n")
		b.WriteString("    }\n")

		// Build ESP proposals string from referenced proposal
		espProposals := "default"
		if vpn.IPsecPolicy != "" {
			if prop, ok := ipsecCfg.Proposals[vpn.IPsecPolicy]; ok {
				espProposals = buildESPProposal(prop)
			}
		}

		fmt.Fprintf(&b, "    children {\n")
		fmt.Fprintf(&b, "      %s {\n", name)
		if vpn.LocalID != "" {
			fmt.Fprintf(&b, "        local_ts = %s\n", vpn.LocalID)
		}
		if vpn.RemoteID != "" {
			fmt.Fprintf(&b, "        remote_ts = %s\n", vpn.RemoteID)
		}
		fmt.Fprintf(&b, "        esp_proposals = %s\n", espProposals)
		fmt.Fprintf(&b, "      }\n")
		fmt.Fprintf(&b, "    }\n")

		fmt.Fprintf(&b, "  }\n")
	}
	b.WriteString("}\n\n")

	// Secrets
	b.WriteString("secrets {\n")
	for name, vpn := range ipsecCfg.VPNs {
		if vpn.PSK != "" {
			fmt.Fprintf(&b, "  ike-%s {\n", name)
			fmt.Fprintf(&b, "    secret = \"%s\"\n", vpn.PSK)
			fmt.Fprintf(&b, "  }\n")
		}
	}
	b.WriteString("}\n")

	return b.String()
}

func buildESPProposal(prop *config.IPsecProposal) string {
	var parts []string

	// Encryption algorithm
	enc := prop.EncryptionAlg
	if enc == "" {
		enc = "aes256"
	}
	// Normalize Junos names to swanctl names
	enc = strings.ReplaceAll(enc, "-cbc", "")
	enc = strings.ReplaceAll(enc, "-", "")
	parts = append(parts, enc)

	// Authentication algorithm (skip for GCM modes)
	if !strings.Contains(prop.EncryptionAlg, "gcm") && prop.AuthAlg != "" {
		auth := prop.AuthAlg
		auth = strings.ReplaceAll(auth, "hmac-", "")
		auth = strings.ReplaceAll(auth, "-", "")
		parts = append(parts, auth)
	}

	// DH group
	if prop.DHGroup > 0 {
		parts = append(parts, fmt.Sprintf("modp%d", dhGroupBits(prop.DHGroup)))
	}

	return strings.Join(parts, "-")
}

func dhGroupBits(group int) int {
	switch group {
	case 1:
		return 768
	case 2:
		return 1024
	case 5:
		return 1536
	case 14:
		return 2048
	case 15:
		return 3072
	case 16:
		return 4096
	case 19:
		return 256 // ecp256
	case 20:
		return 384 // ecp384
	default:
		return group
	}
}

func (m *Manager) reload() error {
	cmd := exec.Command("swanctl", "--load-all")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("swanctl --load-all: %w: %s", err, string(output))
	}
	slog.Info("swanctl config reloaded")
	return nil
}

// SAStatus represents an IPsec Security Association.
type SAStatus struct {
	Name      string
	LocalAddr string
	RemoteAddr string
	State     string
	LocalTS   string
	RemoteTS  string
	InBytes   string
	OutBytes  string
}

// GetSAStatus queries strongSwan for active SAs.
func (m *Manager) GetSAStatus() ([]SAStatus, error) {
	cmd := exec.Command("swanctl", "--list-sas")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("swanctl --list-sas: %w: %s", err, stderr.String())
	}

	return parseSAOutput(stdout.String()), nil
}

func parseSAOutput(output string) []SAStatus {
	var sas []SAStatus
	var current *SAStatus

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)

		// Connection name line (no leading whitespace = new SA)
		if len(line) > 0 && line[0] != ' ' && strings.Contains(line, ":") {
			if current != nil {
				sas = append(sas, *current)
			}
			name := strings.TrimSuffix(strings.Fields(trimmed)[0], ":")
			current = &SAStatus{Name: name}
			continue
		}

		if current == nil {
			continue
		}

		if strings.Contains(trimmed, "local") && strings.Contains(trimmed, "===") {
			parts := strings.Split(trimmed, "===")
			if len(parts) >= 2 {
				current.LocalAddr = strings.TrimSpace(strings.TrimPrefix(parts[0], "local:"))
				current.RemoteAddr = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(trimmed, "ESTABLISHED") || strings.Contains(trimmed, "CONNECTING") {
			for _, word := range []string{"ESTABLISHED", "CONNECTING", "INSTALLED", "REKEYING"} {
				if strings.Contains(trimmed, word) {
					current.State = word
					break
				}
			}
		}

		if strings.Contains(trimmed, "local_ts") {
			if idx := strings.Index(trimmed, "="); idx >= 0 {
				current.LocalTS = strings.TrimSpace(trimmed[idx+1:])
			}
		}
		if strings.Contains(trimmed, "remote_ts") {
			if idx := strings.Index(trimmed, "="); idx >= 0 {
				current.RemoteTS = strings.TrimSpace(trimmed[idx+1:])
			}
		}
	}

	if current != nil {
		sas = append(sas, *current)
	}

	return sas
}
