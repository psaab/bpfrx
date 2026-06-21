package ipsec

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// dpdSettings holds the resolved dead-peer-detection parameters for a
// connection (derived from the gateway + VPN config).
type dpdSettings struct {
	Delay   int
	Timeout int
	Action  string
}

// resolveIKESettings resolves the IKE (Phase 1) auth method, proposal
// string, lifetime, and aggressive-mode flag from the gateway's IKE policy
// chain.
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

// resolveESPSettings resolves the ESP (Phase 2) proposal string and lifetime
// from the VPN's IPsec policy chain.
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
			// #2073: the IPsec policy resolves but its proposal reference
			// does not. The commit-time strict validator
			// (validateIPsecPolicyProposalReferencesStrict) hard-rejects
			// this for new operator edits, so this branch is only reached
			// on a tolerant-path boot of an already-persisted or
			// peer-synced config (where the validator downgraded to a
			// warning so the node still boots). Do NOT silently drop a
			// configured perfect-forward-secrecy group by falling through
			// to bare "default" (which has no modp term): carry the
			// configured PFS group on a conservative fallback proposal so
			// PFS is still negotiated. A non-AEAD (CBC) ESP transform
			// requires an integrity algorithm, so the fallback includes
			// both a cipher and integrity in addition to the modp term. The
			// string is built directly with swanctl's canonical keyword
			// spellings (aes256 / sha256 / modp<bits>) rather than via
			// buildESPProposal: buildESPProposal's hmac-sha-256-128
			// normalization emits the non-canonical "sha256128" token,
			// which strongSwan's proposal parser does not recognize (its
			// keyword table has only "sha256"/"sha2_256" for
			// AUTH_HMAC_SHA2_256_128) and would reject the whole proposal.
			// (The normal-path "sha256128" spelling is a separate
			// pre-existing concern tracked outside #2073.)
			//
			// dhGroupBits maps MODP groups (1/2/5/14/15/16) to their bit
			// size, so the fallback is a valid modp<bits> token for those.
			// For the elliptic-curve groups 19/20 it returns 256/384, which
			// yields modp256/modp384 — a strongSwan-invalid token. That ECP
			// mis-spelling is a pre-existing, project-wide bug shared by
			// buildESPProposal / buildIKEProposal on the normal path (they
			// emit the same modp<bits> for ECP groups); this fallback
			// inherits it rather than introducing it, and it is tracked as a
			// separate follow-up outside #2073. MODP PFS groups — the common
			// case — are preserved correctly.
			if pfsGroup > 0 {
				slog.Warn("ipsec policy references undefined proposal; "+
					"preserving configured PFS group on fallback proposal",
					"policy", vpn.IPsecPolicy, "proposal", propRef,
					"pfs_group", pfsGroup)
				return fmt.Sprintf("aes256-sha256-modp%d", dhGroupBits(pfsGroup)), 0
			}
		} else if prop, ok := cfg.Proposals[vpn.IPsecPolicy]; ok {
			return buildESPProposal(prop, 0), prop.LifetimeSeconds
		}
	}
	return espProposals, 0
}

// deriveDPD computes the dead-peer-detection settings for a connection.
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

// normalizeEncAlg maps a Junos encryption-algorithm name to its swanctl
// token. For AES-GCM it returns the ICV-suffixed token strongSwan
// requires (a bare "aes256gcm" is NOT a valid swanctl keyword — GCM
// ciphers must carry an explicit ICV length). Junos AES-GCM uses a
// 16-octet (128-bit) ICV, so aes-256-gcm -> aes256gcm16. isGCM reports
// whether the algorithm is AEAD (the caller skips the integrity
// algorithm for AEAD and, for IKE, appends an explicit PRF instead).
//
// Already-suffixed forms (e.g. aes256gcm128 fed directly by config or
// older tests) pass through the generic dash-strip unchanged so they
// keep rendering as before. Non-GCM algorithms return ("", false) and
// the caller applies the historical "-cbc"/"-" normalization.
func normalizeEncAlg(enc string) (token string, isGCM bool) {
	switch enc {
	case "aes-128-gcm", "aes128gcm":
		return "aes128gcm16", true
	case "aes-192-gcm", "aes192gcm":
		return "aes192gcm16", true
	case "aes-256-gcm", "aes256gcm":
		return "aes256gcm16", true
	}
	if strings.Contains(enc, "gcm") {
		// Already carries an ICV suffix (or some other GCM spelling);
		// strip Junos punctuation but otherwise leave it intact.
		t := strings.ReplaceAll(enc, "-cbc", "")
		t = strings.ReplaceAll(t, "-", "")
		return t, true
	}
	return "", false
}

// gcmPRF derives the swanctl PRF token for an IKE (Phase 1) AEAD
// proposal. AEAD ciphers carry no integrity algorithm for strongSwan to
// derive a PRF from, so IKEv2 GCM proposals MUST name a PRF explicitly
// (e.g. aes256gcm16-prfsha256-modp2048). When the proposal names an
// auth/integrity algorithm we mirror it as the PRF; otherwise we default
// to prfsha256.
func gcmPRF(authAlg string) string {
	switch {
	case strings.Contains(authAlg, "512"):
		return "prfsha512"
	case strings.Contains(authAlg, "384"):
		return "prfsha384"
	case strings.Contains(authAlg, "256"):
		return "prfsha256"
	case strings.Contains(authAlg, "sha1"), strings.Contains(authAlg, "sha-1"):
		return "prfsha1"
	default:
		return "prfsha256"
	}
}

// normalizeAuthAlg maps a Junos authentication-algorithm name to its
// swanctl integrity token (hmac-sha-256 -> sha256).
func normalizeAuthAlg(authAlg string) string {
	a := strings.ReplaceAll(authAlg, "hmac-", "")
	a = strings.ReplaceAll(a, "-", "")
	return a
}

// buildIKEProposalFromIKE builds a swanctl IKE proposal string from an IKE proposal.
func buildIKEProposalFromIKE(prop *config.IKEProposal) string {
	var parts []string

	enc := prop.EncryptionAlg
	if enc == "" {
		enc = "aes256"
	}
	if tok, isGCM := normalizeEncAlg(enc); isGCM {
		parts = append(parts, tok)
		// IKEv2 AEAD proposals require an explicit PRF.
		parts = append(parts, gcmPRF(prop.AuthAlg))
	} else {
		enc = strings.ReplaceAll(enc, "-cbc", "")
		enc = strings.ReplaceAll(enc, "-", "")
		parts = append(parts, enc)
		if prop.AuthAlg != "" {
			parts = append(parts, normalizeAuthAlg(prop.AuthAlg))
		}
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
	if tok, isGCM := normalizeEncAlg(enc); isGCM {
		parts = append(parts, tok)
		// IKEv2 AEAD proposals require an explicit PRF — there is no
		// integrity algorithm to derive one from.
		parts = append(parts, gcmPRF(prop.AuthAlg))
	} else {
		enc = strings.ReplaceAll(enc, "-cbc", "")
		enc = strings.ReplaceAll(enc, "-", "")
		parts = append(parts, enc)
		if prop.AuthAlg != "" {
			parts = append(parts, normalizeAuthAlg(prop.AuthAlg))
		}
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
	// Normalize Junos names to swanctl names. AEAD (GCM) ciphers carry
	// an ICV suffix and take no separate integrity algorithm and no PRF.
	if tok, isGCM := normalizeEncAlg(enc); isGCM {
		parts = append(parts, tok)
	} else {
		enc = strings.ReplaceAll(enc, "-cbc", "")
		enc = strings.ReplaceAll(enc, "-", "")
		parts = append(parts, enc)
		// Authentication algorithm (non-GCM only)
		if prop.AuthAlg != "" {
			parts = append(parts, normalizeAuthAlg(prop.AuthAlg))
		}
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
		if out, err := runSwanctl("--terminate", "--ike", ikeName); err != nil {
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
	if out, err := runSwanctl("--initiate", "--child", name); err != nil {
		return fmt.Errorf("swanctl --initiate %s: %w: %s", name, err, string(out))
	}
	return nil
}

// GetSAStatus queries strongSwan for active SAs.
func (m *Manager) GetSAStatus() ([]SAStatus, error) {
	// Inline ctx (not runSwanctl): the parser needs stdout alone, and the
	// historical error message carries stderr alone.
	ctx, cancel := context.WithTimeout(context.Background(), swanctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "swanctl", "--list-sas")
	// Buffer-backed Stdout/Stderr are pipe-fed by the runtime, so the
	// post-SIGKILL drain window applies here too.
	cmd.WaitDelay = 5 * time.Second
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
