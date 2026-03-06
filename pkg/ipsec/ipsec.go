// Package ipsec generates strongSwan (swanctl) configuration and queries SA status.
package ipsec

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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

	cfg, err := m.renderConfig(ipsecCfg)
	if err != nil {
		return err
	}

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
	cfg, _ := m.renderConfig(ipsecCfg)
	return cfg
}

func (m *Manager) renderConfig(ipsecCfg *config.IPsecConfig) (string, error) {
	var b strings.Builder

	b.WriteString("# bpfrx managed config - do not edit\n\n")

	// Connections
	b.WriteString("connections {\n")
	for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
		vpn := ipsecCfg.VPNs[name]
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
		authMethod, ikeProposals, ikeLifetime, aggressive, err := resolveIKESettings(ipsecCfg, gw)
		if err != nil {
			return "", fmt.Errorf("vpn %s: %w", name, err)
		}
		espProposals, espLifetime := resolveESPSettings(ipsecCfg, vpn)
		dpd := deriveDPD(gw, vpn)

		// IKE version
		if gw != nil && gw.Version == "v2-only" {
			b.WriteString("    version = 2\n")
		} else if gw != nil && gw.Version == "v1-only" {
			b.WriteString("    version = 1\n")
		}

		if aggressive {
			b.WriteString("    aggressive = yes\n")
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

		if dpd.Delay > 0 {
			fmt.Fprintf(&b, "    dpd_delay = %ds\n", dpd.Delay)
		}
		if dpd.Timeout > 0 {
			fmt.Fprintf(&b, "    dpd_timeout = %ds\n", dpd.Timeout)
		}

		// Local auth section
		b.WriteString("    local {\n")
		fmt.Fprintf(&b, "      auth = %s\n", authMethod)
		if gw != nil && gw.LocalCertificate != "" {
			fmt.Fprintf(&b, "      certs = %s\n", gw.LocalCertificate)
		}
		if gw != nil && gw.LocalIDValue != "" {
			fmt.Fprintf(&b, "      id = %s\n", formatIdentity(gw.LocalIDType, gw.LocalIDValue))
		}
		b.WriteString("    }\n")

		// Remote auth section
		b.WriteString("    remote {\n")
		fmt.Fprintf(&b, "      auth = %s\n", authMethod)
		if gw != nil && gw.RemoteIDValue != "" {
			fmt.Fprintf(&b, "      id = %s\n", formatIdentity(gw.RemoteIDType, gw.RemoteIDValue))
		}
		b.WriteString("    }\n")

		if ikeProposals != "" {
			fmt.Fprintf(&b, "    proposals = %s\n", ikeProposals)
		}
		if ikeLifetime > 0 {
			fmt.Fprintf(&b, "    rekey_time = %ds\n", ikeLifetime)
			b.WriteString("    rand_time = 0s\n")
		}

		// Start immediately?
		if vpn.EstablishTunnels == "immediately" {
			b.WriteString("    start_action = start\n")
		}

		// Compute XFRM interface ID from bind-interface name
		ifID := xfrmiIfID(vpn.BindInterface)

		fmt.Fprintf(&b, "    children {\n")
		for _, child := range effectiveTrafficSelectors(name, vpn) {
			fmt.Fprintf(&b, "      %s {\n", child.Name)
			if child.LocalTS != "" {
				fmt.Fprintf(&b, "        local_ts = %s\n", child.LocalTS)
			}
			if child.RemoteTS != "" {
				fmt.Fprintf(&b, "        remote_ts = %s\n", child.RemoteTS)
			}
			fmt.Fprintf(&b, "        esp_proposals = %s\n", espProposals)
			if espLifetime > 0 {
				fmt.Fprintf(&b, "        rekey_time = %ds\n", espLifetime)
				b.WriteString("        rand_time = 0s\n")
			}
			if vpn.DFBit == "copy" {
				fmt.Fprintf(&b, "        copy_df = yes\n")
			} else if vpn.DFBit == "set" {
				fmt.Fprintf(&b, "        copy_df = no\n")
			}
			if vpn.EstablishTunnels == "immediately" {
				fmt.Fprintf(&b, "        start_action = start\n")
			}
			if dpd.Action != "" {
				fmt.Fprintf(&b, "        dpd_action = %s\n", dpd.Action)
			}
			if ifID > 0 {
				fmt.Fprintf(&b, "        if_id_in = %d\n", ifID)
				fmt.Fprintf(&b, "        if_id_out = %d\n", ifID)
			}
			fmt.Fprintf(&b, "      }\n")
		}
		fmt.Fprintf(&b, "    }\n")

		fmt.Fprintf(&b, "  }\n")
	}
	b.WriteString("}\n\n")

	// Secrets — resolve PSK from IKE policy chain
	b.WriteString("secrets {\n")
	for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
		vpn := ipsecCfg.VPNs[name]
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
			decoded, err := normalizePSK(secret)
			if err != nil {
				return "", fmt.Errorf("vpn %s: %w", name, err)
			}
			fmt.Fprintf(&b, "  ike-%s {\n", name)
			fmt.Fprintf(&b, "    secret = \"%s\"\n", decoded)
			fmt.Fprintf(&b, "  }\n")
		}
	}
	b.WriteString("}\n")

	return b.String(), nil
}

type childSelector struct {
	Name     string
	LocalTS  string
	RemoteTS string
}

type dpdSettings struct {
	Delay   int
	Timeout int
	Action  string
}

func sortedVPNNames(vpns map[string]*config.IPsecVPN) []string {
	names := make([]string, 0, len(vpns))
	for name := range vpns {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func resolveIKESettings(cfg *config.IPsecConfig, gw *config.IPsecGateway) (authMethod, proposals string, lifetime int, aggressive bool, err error) {
	authMethod = "psk"
	if gw == nil || gw.IKEPolicy == "" {
		return authMethod, "", 0, false, nil
	}

	if ikePol, ok := cfg.IKEPolicies[gw.IKEPolicy]; ok {
		aggressive = ikePol.Mode == "aggressive"
		if ikeProp, ok := cfg.IKEProposals[ikePol.Proposals]; ok {
			authMethod, err = authMethodToSwan(ikeProp.AuthMethod)
			if err != nil {
				return "", "", 0, false, err
			}
			return authMethod, buildIKEProposalFromIKE(ikeProp), ikeProp.LifetimeSeconds, aggressive, nil
		}
	}

	if !hasIKEChain(cfg, gw.IKEPolicy) {
		if prop, ok := cfg.Proposals[gw.IKEPolicy]; ok {
			return authMethod, buildIKEProposal(prop), prop.LifetimeSeconds, aggressive, nil
		}
	}

	return authMethod, "", 0, aggressive, nil
}

func resolveESPSettings(cfg *config.IPsecConfig, vpn *config.IPsecVPN) (string, int) {
	espProposals := "default"
	pfsGroup := 0
	if vpn.IPsecPolicy != "" {
		if ipsecPol, ok := cfg.Policies[vpn.IPsecPolicy]; ok {
			pfsGroup = ipsecPol.PFSGroup
			propRef := ipsecPol.Proposals
			if propRef == "" {
				propRef = vpn.IPsecPolicy
			}
			if prop, ok := cfg.Proposals[propRef]; ok {
				return buildESPProposal(prop, pfsGroup), prop.LifetimeSeconds
			}
		} else if prop, ok := cfg.Proposals[vpn.IPsecPolicy]; ok {
			return buildESPProposal(prop, 0), prop.LifetimeSeconds
		}
	}
	return espProposals, 0
}

func deriveDPD(gw *config.IPsecGateway, vpn *config.IPsecVPN) dpdSettings {
	if gw == nil || gw.DeadPeerDetect == "" {
		return dpdSettings{}
	}

	delay := gw.DPDInterval
	if delay <= 0 {
		delay = 10
	}
	threshold := gw.DPDThreshold
	if threshold <= 0 {
		threshold = 5
	}

	action := ""
	switch gw.DeadPeerDetect {
	case "always-send":
		action = "restart"
	case "optimized":
		if vpn != nil && vpn.EstablishTunnels == "immediately" {
			action = "restart"
		} else {
			action = "clear"
		}
	case "probe-idle-tunnel":
		if vpn != nil && vpn.EstablishTunnels == "immediately" {
			action = "restart"
		} else {
			action = "trap"
		}
	default:
		if vpn != nil && vpn.EstablishTunnels == "immediately" {
			action = "restart"
		}
	}

	return dpdSettings{
		Delay:   delay,
		Timeout: delay * threshold,
		Action:  action,
	}
}

func effectiveTrafficSelectors(connName string, vpn *config.IPsecVPN) []childSelector {
	if vpn == nil || len(vpn.TrafficSelectors) == 0 {
		return []childSelector{{
			Name:     connName,
			LocalTS:  vpn.LocalID,
			RemoteTS: vpn.RemoteID,
		}}
	}

	names := make([]string, 0, len(vpn.TrafficSelectors))
	for name := range vpn.TrafficSelectors {
		names = append(names, name)
	}
	sort.Strings(names)

	children := make([]childSelector, 0, len(names))
	for _, name := range names {
		ts := vpn.TrafficSelectors[name]
		localTS := vpn.LocalID
		remoteTS := vpn.RemoteID
		if ts.LocalIP != "" {
			localTS = ts.LocalIP
		}
		if ts.RemoteIP != "" {
			remoteTS = ts.RemoteIP
		}
		children = append(children, childSelector{
			Name:     connName + "-" + sanitizeChildName(name),
			LocalTS:  localTS,
			RemoteTS: remoteTS,
		})
	}
	return children
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

func buildESPProposal(prop *config.IPsecProposal, pfsGroup int) string {
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
	dhGroup := prop.DHGroup
	if pfsGroup > 0 {
		dhGroup = pfsGroup
	}
	if dhGroup > 0 {
		parts = append(parts, fmt.Sprintf("modp%d", dhGroupBits(dhGroup)))
	}

	return strings.Join(parts, "-")
}

// xfrmiIfID derives the XFRM interface ID from a bind-interface name.
func xfrmiIfID(bindIface string) uint32 {
	_, ifID := config.XFRMIfNameAndID(bindIface)
	return ifID
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
	Name           string
	ConnectionName string
	LocalAddr      string
	RemoteAddr     string
	State          string
	LocalTS        string
	RemoteTS       string
	InBytes        string
	OutBytes       string
}

// TerminateAllSAs terminates all active IKE SAs via swanctl.
func (m *Manager) TerminateAllSAs() (int, error) {
	sas, err := m.GetSAStatus()
	if err != nil {
		return 0, err
	}
	count := 0
	seen := make(map[string]bool)
	for _, sa := range sas {
		ikeName := sa.ConnectionName
		if ikeName == "" {
			ikeName = sa.Name
		}
		if ikeName == "" || seen[ikeName] {
			continue
		}
		seen[ikeName] = true
		cmd := exec.Command("swanctl", "--terminate", "--ike", ikeName)
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("swanctl terminate failed", "ike", ikeName, "err", err, "output", string(out))
		} else {
			count++
		}
	}
	return count, nil
}

// ActiveConnectionNames returns the names of all active/established IKE SAs.
func (m *Manager) ActiveConnectionNames() ([]string, error) {
	sas, err := m.GetSAStatus()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(sas))
	seen := make(map[string]bool)
	for _, sa := range sas {
		if sa.Name != "" && !seen[sa.Name] {
			seen[sa.Name] = true
			names = append(names, sa.Name)
		}
	}
	return names, nil
}

// InitiateConnection initiates a single IPsec connection by name.
func (m *Manager) InitiateConnection(name string) error {
	cmd := exec.Command("swanctl", "--initiate", "--child", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("swanctl --initiate %s: %w: %s", name, err, string(out))
	}
	return nil
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
	var currentConn *SAStatus
	var currentChild *SAStatus
	connHasChild := false

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)

		// Connection name line (no leading whitespace = new SA)
		if len(line) > 0 && line[0] != ' ' && strings.Contains(line, ":") {
			if currentChild != nil {
				sas = append(sas, *currentChild)
				currentChild = nil
			}
			if currentConn != nil && !connHasChild {
				sas = append(sas, *currentConn)
			}
			name := strings.TrimSuffix(strings.Fields(trimmed)[0], ":")
			currentConn = &SAStatus{Name: name, ConnectionName: name}
			connHasChild = false
			// Extract state from the connection name line (e.g. "site-a: #1, ESTABLISHED")
			for _, word := range []string{"ESTABLISHED", "CONNECTING", "INSTALLED", "REKEYING"} {
				if strings.Contains(trimmed, word) {
					currentConn.State = word
					break
				}
			}
			continue
		}

		if currentConn == nil {
			continue
		}

		if strings.Contains(trimmed, ", reqid ") && strings.Contains(trimmed, ":") {
			if currentChild != nil {
				sas = append(sas, *currentChild)
			}
			childName := strings.TrimSuffix(strings.Fields(trimmed)[0], ":")
			currentChild = &SAStatus{
				Name:           childName,
				ConnectionName: currentConn.Name,
				LocalAddr:      currentConn.LocalAddr,
				RemoteAddr:     currentConn.RemoteAddr,
			}
			connHasChild = true
			for _, word := range []string{"ESTABLISHED", "CONNECTING", "INSTALLED", "REKEYING"} {
				if strings.Contains(trimmed, word) {
					currentChild.State = word
					break
				}
			}
			continue
		}

		target := currentConn
		if currentChild != nil {
			target = currentChild
		}

		if strings.Contains(trimmed, "local") && strings.Contains(trimmed, "===") {
			parts := strings.Split(trimmed, "===")
			if len(parts) >= 2 {
				currentConn.LocalAddr = strings.TrimSpace(strings.TrimPrefix(parts[0], "local:"))
				currentConn.RemoteAddr = strings.TrimSpace(parts[1])
				if currentChild != nil {
					currentChild.LocalAddr = currentConn.LocalAddr
					currentChild.RemoteAddr = currentConn.RemoteAddr
				}
			}
		}

		if strings.Contains(trimmed, "ESTABLISHED") || strings.Contains(trimmed, "CONNECTING") {
			for _, word := range []string{"ESTABLISHED", "CONNECTING", "INSTALLED", "REKEYING"} {
				if strings.Contains(trimmed, word) {
					target.State = word
					break
				}
			}
		}

		if strings.Contains(trimmed, "local_ts") {
			if idx := strings.Index(trimmed, "="); idx >= 0 {
				target.LocalTS = strings.TrimSpace(trimmed[idx+1:])
			}
		}
		if strings.Contains(trimmed, "remote_ts") {
			if idx := strings.Index(trimmed, "="); idx >= 0 {
				target.RemoteTS = strings.TrimSpace(trimmed[idx+1:])
			}
		}
		if strings.HasPrefix(trimmed, "bytes_in") || strings.Contains(trimmed, " bytes_in") {
			for _, field := range strings.Fields(trimmed) {
				if strings.HasPrefix(field, "bytes_in=") {
					target.InBytes = strings.TrimPrefix(field, "bytes_in=")
					target.InBytes = strings.TrimRight(target.InBytes, ",")
				}
				if strings.HasPrefix(field, "bytes_out=") {
					target.OutBytes = strings.TrimPrefix(field, "bytes_out=")
					target.OutBytes = strings.TrimRight(target.OutBytes, ",")
				}
			}
		}
	}

	if currentChild != nil {
		sas = append(sas, *currentChild)
	} else if currentConn != nil && !connHasChild {
		sas = append(sas, *currentConn)
	}

	return sas
}
