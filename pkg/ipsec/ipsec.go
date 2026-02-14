// Package ipsec generates strongSwan (swanctl) configuration and queries SA status.
package ipsec

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

		// Resolve gateway reference
		remoteAddr := vpn.Gateway
		localAddr := vpn.LocalAddr
		var gw *config.IPsecGateway
		if g, ok := ipsecCfg.Gateways[vpn.Gateway]; ok {
			gw = g
			if gw.Address != "" {
				remoteAddr = gw.Address
			} else if gw.DynamicHostname != "" {
				remoteAddr = gw.DynamicHostname
			}
			if gw.LocalAddress != "" && localAddr == "" {
				localAddr = gw.LocalAddress
			}
		}

		// IKE version
		if gw != nil && gw.Version == "v2-only" {
			b.WriteString("    version = 2\n")
		} else if gw != nil && gw.Version == "v1-only" {
			b.WriteString("    version = 1\n")
		}

		// Aggressive mode: resolve IKE policy mode through gateway -> ike-policy chain
		if gw != nil && gw.IKEPolicy != "" {
			if ikePol, ok := ipsecCfg.IKEPolicies[gw.IKEPolicy]; ok {
				if ikePol.Mode == "aggressive" {
					b.WriteString("    aggressive = yes\n")
				}
			}
		}

		if localAddr != "" {
			fmt.Fprintf(&b, "    local_addrs = %s\n", localAddr)
		}
		if remoteAddr != "" {
			fmt.Fprintf(&b, "    remote_addrs = %s\n", remoteAddr)
		}

		// NAT traversal
		if gw != nil {
			switch gw.NATTraversal {
			case "disable":
				b.WriteString("    encap = no\n")
			case "force":
				b.WriteString("    encap = yes\n")
				b.WriteString("    forceencaps = yes\n")
			default:
				// "enable" or empty = strongSwan default (auto-detect NAT)
				if gw.NoNATTraversal {
					b.WriteString("    encap = no\n")
				}
			}
		}

		// DPD
		if gw != nil && gw.DeadPeerDetect != "" {
			b.WriteString("    dpd_delay = 10s\n")
		}

		// Local auth section
		b.WriteString("    local {\n")
		b.WriteString("      auth = psk\n")
		if gw != nil && gw.LocalIDValue != "" {
			fmt.Fprintf(&b, "      id = %s\n", formatIdentity(gw.LocalIDType, gw.LocalIDValue))
		}
		b.WriteString("    }\n")

		// Remote auth section
		b.WriteString("    remote {\n")
		b.WriteString("      auth = psk\n")
		if gw != nil && gw.RemoteIDValue != "" {
			fmt.Fprintf(&b, "      id = %s\n", formatIdentity(gw.RemoteIDType, gw.RemoteIDValue))
		}
		b.WriteString("    }\n")

		// Build IKE proposals: gateway.IKEPolicy -> IKEPolicy -> IKEProposal
		if gw != nil && gw.IKEPolicy != "" {
			if ikePol, ok := ipsecCfg.IKEPolicies[gw.IKEPolicy]; ok {
				if ikeProp, ok := ipsecCfg.IKEProposals[ikePol.Proposals]; ok {
					fmt.Fprintf(&b, "    proposals = %s\n", buildIKEProposalFromIKE(ikeProp))
				}
			}
			// Fallback: try IPsec proposals directly (legacy config)
			if !hasIKEChain(ipsecCfg, gw.IKEPolicy) {
				if prop, ok := ipsecCfg.Proposals[gw.IKEPolicy]; ok {
					fmt.Fprintf(&b, "    proposals = %s\n", buildIKEProposal(prop))
				}
			}
		}

		// Build ESP proposals: vpn.IPsecPolicy -> IPsecPolicyDef -> IPsecProposal
		espProposals := "default"
		pfsGroup := 0
		if vpn.IPsecPolicy != "" {
			if ipsecPol, ok := ipsecCfg.Policies[vpn.IPsecPolicy]; ok {
				pfsGroup = ipsecPol.PFSGroup
				propRef := ipsecPol.Proposals
				if propRef == "" {
					propRef = vpn.IPsecPolicy
				}
				if prop, ok := ipsecCfg.Proposals[propRef]; ok {
					espProposals = buildESPProposal(prop)
				}
			} else if prop, ok := ipsecCfg.Proposals[vpn.IPsecPolicy]; ok {
				// Fallback: direct proposal reference (legacy)
				espProposals = buildESPProposal(prop)
			}
		}

		// Start immediately?
		if vpn.EstablishTunnels == "immediately" {
			b.WriteString("    start_action = start\n")
		}

		// Compute XFRM interface ID from bind-interface name
		ifID := xfrmiIfID(vpn.BindInterface)

		fmt.Fprintf(&b, "    children {\n")
		fmt.Fprintf(&b, "      %s {\n", name)
		if vpn.LocalID != "" {
			fmt.Fprintf(&b, "        local_ts = %s\n", vpn.LocalID)
		}
		if vpn.RemoteID != "" {
			fmt.Fprintf(&b, "        remote_ts = %s\n", vpn.RemoteID)
		}
		fmt.Fprintf(&b, "        esp_proposals = %s\n", espProposals)
		if pfsGroup > 0 {
			fmt.Fprintf(&b, "        dpd_action = restart\n")
		}
		if vpn.DFBit == "copy" {
			fmt.Fprintf(&b, "        copy_df = yes\n")
		} else if vpn.DFBit == "set" {
			fmt.Fprintf(&b, "        copy_df = no\n")
		}
		if vpn.EstablishTunnels == "immediately" {
			fmt.Fprintf(&b, "        start_action = start\n")
		}
		if ifID > 0 {
			fmt.Fprintf(&b, "        if_id_in = %d\n", ifID)
			fmt.Fprintf(&b, "        if_id_out = %d\n", ifID)
		}
		fmt.Fprintf(&b, "      }\n")
		fmt.Fprintf(&b, "    }\n")

		fmt.Fprintf(&b, "  }\n")
	}
	b.WriteString("}\n\n")

	// Secrets — resolve PSK from IKE policy chain
	b.WriteString("secrets {\n")
	for name, vpn := range ipsecCfg.VPNs {
		secret := vpn.PSK
		// Resolve PSK from IKE policy chain: VPN -> gateway -> IKE policy -> PSK
		if secret == "" {
			if gw, ok := ipsecCfg.Gateways[vpn.Gateway]; ok {
				if ikePol, ok := ipsecCfg.IKEPolicies[gw.IKEPolicy]; ok {
					secret = ikePol.PSK
				}
			}
		}
		if secret != "" {
			fmt.Fprintf(&b, "  ike-%s {\n", name)
			fmt.Fprintf(&b, "    secret = \"%s\"\n", secret)
			fmt.Fprintf(&b, "  }\n")
		}
	}
	b.WriteString("}\n")

	return b.String()
}

// hasIKEChain checks if the IKE policy -> IKE proposal chain is available.
func hasIKEChain(cfg *config.IPsecConfig, ikePolicyName string) bool {
	if cfg.IKEPolicies == nil {
		return false
	}
	pol, ok := cfg.IKEPolicies[ikePolicyName]
	if !ok {
		return false
	}
	if cfg.IKEProposals == nil {
		return false
	}
	_, ok = cfg.IKEProposals[pol.Proposals]
	return ok
}

// formatIdentity formats an IKE identity for strongSwan.
func formatIdentity(idType, idValue string) string {
	switch idType {
	case "hostname", "fqdn":
		return "@" + idValue
	default: // "inet", "ipv4", etc.
		return idValue
	}
}

// buildIKEProposalFromIKE builds a swanctl IKE proposal string from an IKE proposal.
func buildIKEProposalFromIKE(prop *config.IKEProposal) string {
	var parts []string

	enc := prop.EncryptionAlg
	if enc == "" {
		enc = "aes256"
	}
	enc = strings.ReplaceAll(enc, "-cbc", "")
	enc = strings.ReplaceAll(enc, "-", "")
	parts = append(parts, enc)

	if prop.AuthAlg != "" && !strings.Contains(prop.EncryptionAlg, "gcm") {
		auth := prop.AuthAlg
		auth = strings.ReplaceAll(auth, "hmac-", "")
		auth = strings.ReplaceAll(auth, "-", "")
		parts = append(parts, auth)
	}

	if prop.DHGroup > 0 {
		parts = append(parts, fmt.Sprintf("modp%d", dhGroupBits(prop.DHGroup)))
	}

	return strings.Join(parts, "-")
}

// buildIKEProposal builds a swanctl IKE (Phase 1) proposal string from a proposal config.
func buildIKEProposal(prop *config.IPsecProposal) string {
	var parts []string

	enc := prop.EncryptionAlg
	if enc == "" {
		enc = "aes256"
	}
	enc = strings.ReplaceAll(enc, "-cbc", "")
	enc = strings.ReplaceAll(enc, "-", "")
	parts = append(parts, enc)

	// IKE always includes integrity/PRF (even for GCM, swanctl adds PRFHMACSHA256 implicitly)
	if prop.AuthAlg != "" && !strings.Contains(prop.EncryptionAlg, "gcm") {
		auth := prop.AuthAlg
		auth = strings.ReplaceAll(auth, "hmac-", "")
		auth = strings.ReplaceAll(auth, "-", "")
		parts = append(parts, auth)
	}

	if prop.DHGroup > 0 {
		parts = append(parts, fmt.Sprintf("modp%d", dhGroupBits(prop.DHGroup)))
	}

	return strings.Join(parts, "-")
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

// xfrmiIfID derives the XFRM interface ID from a bind-interface name.
// "st0.0" -> 1, "st1.0" -> 2, "" -> 0 (disabled).
func xfrmiIfID(bindIface string) uint32 {
	if bindIface == "" {
		return 0
	}
	devName := bindIface
	if dot := strings.IndexByte(bindIface, '.'); dot >= 0 {
		devName = bindIface[:dot]
	}
	if len(devName) < 3 || devName[:2] != "st" {
		return 0
	}
	idx, err := strconv.Atoi(devName[2:])
	if err != nil {
		return 0
	}
	return uint32(idx + 1)
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

// TerminateAllSAs terminates all active IKE SAs via swanctl.
func (m *Manager) TerminateAllSAs() (int, error) {
	sas, err := m.GetSAStatus()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, sa := range sas {
		cmd := exec.Command("swanctl", "--terminate", "--ike", sa.Name)
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("swanctl terminate failed", "ike", sa.Name, "err", err, "output", string(out))
		} else {
			count++
		}
	}
	return count, nil
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
			// Extract state from the connection name line (e.g. "site-a: #1, ESTABLISHED")
			for _, word := range []string{"ESTABLISHED", "CONNECTING", "INSTALLED", "REKEYING"} {
				if strings.Contains(trimmed, word) {
					current.State = word
					break
				}
			}
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
		if strings.HasPrefix(trimmed, "bytes_in") || strings.Contains(trimmed, " bytes_in") {
			for _, field := range strings.Fields(trimmed) {
				if strings.HasPrefix(field, "bytes_in=") {
					current.InBytes = strings.TrimPrefix(field, "bytes_in=")
					current.InBytes = strings.TrimRight(current.InBytes, ",")
				}
				if strings.HasPrefix(field, "bytes_out=") {
					current.OutBytes = strings.TrimPrefix(field, "bytes_out=")
					current.OutBytes = strings.TrimRight(current.OutBytes, ",")
				}
			}
		}
	}

	if current != nil {
		sas = append(sas, *current)
	}

	return sas
}
