// Package ipsec generates strongSwan (swanctl) configuration and queries SA status.
package ipsec

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// swanctlTimeout bounds every swanctl shell-out. reload() runs on the
// config-apply path under applyConfigLocked's applySem (daemon_apply.go
// d.ipsec.Apply), so a hung swanctl (wedged charon, stuck vici socket)
// would otherwise block every commit indefinitely. The operator-RPC
// sites (--terminate / --initiate / --list-sas) hang the gRPC/CLI show
// and request paths the same way. Mirrors the 15s FRR reload precedent
// (pkg/frr/manager.go reloadTimeout). #1794/#1800.
const swanctlTimeout = 15 * time.Second

// runSwanctl runs `swanctl <args...>` under swanctlTimeout and returns
// CombinedOutput, preserving the historical error-message shape at the
// call sites.
func runSwanctl(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), swanctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "swanctl", args...)
	// WaitDelay caps the post-SIGKILL pipe-drain window (a charon child
	// inheriting the pipe could otherwise hold CombinedOutput open).
	cmd.WaitDelay = 5 * time.Second
	return cmd.CombinedOutput()
}

const (
	// DefaultSwanctlDir is where swanctl reads conf.d snippets.
	DefaultSwanctlDir = "/etc/swanctl/conf.d"
	// BPFRXConfFile is the config file xpf manages.
	BPFRXConfFile = "xpf.conf"
)

// Manager handles strongSwan config generation and SA queries.
type Manager struct {
	configDir  string
	configPath string

	// mu guards prevConnNames across concurrent Apply callers (the ordered
	// commit path and the DHCP-rebind re-render both call Apply).
	mu sync.Mutex
	// prevConnNames is the set of swanctl connection names (sanitized VPN
	// names) written by the most recent Apply. Diffing it against the new
	// config's connection set yields the connections an operator DELETED, so
	// their live SAs can be torn down (#3941). nil until the first Apply.
	prevConnNames map[string]bool

	// swanctl is the exec seam for shelling out to swanctl. Nil in
	// production and directly-constructed test Managers; sc() falls back to
	// the package-level runSwanctl. Tests that must observe/intercept the
	// swanctl invocations (e.g. the removed-connection terminate in #3941)
	// set this to a recording double.
	swanctl func(args ...string) ([]byte, error)
}

// sc returns the swanctl exec function, defaulting to the package-level
// runSwanctl when the seam is unset. This keeps a zero-value / directly
// constructed Manager working while letting tests inject a double.
func (m *Manager) sc(args ...string) ([]byte, error) {
	if m.swanctl != nil {
		return m.swanctl(args...)
	}
	return runSwanctl(args...)
}

// New creates a new IPsec manager.
func New() *Manager {
	return NewWithConfigDir(DefaultSwanctlDir)
}

// NewWithConfigDir creates an IPsec manager that writes its swanctl
// snippet under dir instead of the default /etc/swanctl/conf.d. It lets
// callers (and tests that must not touch the real swanctl tree) redirect
// the generated config to an arbitrary directory; reload() still shells
// out to the system swanctl.
func NewWithConfigDir(dir string) *Manager {
	return &Manager{
		configDir:  dir,
		configPath: filepath.Join(dir, BPFRXConfFile),
	}
}

// Apply generates swanctl config and reloads strongSwan.
//
// swanctl --load-all only UNLOADS the config of a connection the operator
// deleted; it does NOT terminate that connection's already-established
// IKE/child SAs, so a removed VPN keeps forwarding until rekey/lifetime
// expiry (#3941). Apply therefore diffs the previous applied connection set
// against the new one and, after the reload has unloaded the removed
// connections, actively terminates their live SAs (terminateRemovedConns).
func (m *Manager) Apply(ipsecCfg *config.IPsecConfig) error {
	newNames := vpnConnNameSet(ipsecCfg)

	var applyErr error
	if ipsecCfg == nil || len(ipsecCfg.VPNs) == 0 {
		applyErr = m.clearConfig()
	} else {
		applyErr = m.applyConfig(ipsecCfg)
	}

	// #4898: state promotion and SA teardown are gated on reload SUCCESS. On a
	// failed reload strongSwan keeps the PREVIOUS config loaded and effective, so
	// prevConnNames must NOT advance and the removed connections' live SAs must
	// NOT be terminated — they may still be the effective policy. Leaving
	// prevConnNames unchanged lets the next successful Apply/Clear recompute the
	// diff and retry the teardown; advancing it here (the old ordering) would
	// forget which connections are still loaded and disrupt a still-effective
	// tunnel while reporting success.
	if applyErr != nil {
		return applyErr
	}

	// Reload succeeded: atomically advance prevConnNames to the applied set and
	// tear down the live SAs of the connections the operator DELETED. Their
	// config is now unloaded, so a straggler SA cannot be re-initiated from a
	// still-loaded connection while we tear it down. Terminate is idempotent:
	// a removed VPN with no active SA is a clean no-op (no --terminate is
	// issued because it never shows up in --list-sas).
	removed := m.promoteConnNames(newNames)
	m.terminateRemovedConns(removed)
	return nil
}

// Clear removes the xpf config and reloads strongSwan, terminating the live
// SAs of every previously-applied connection.
func (m *Manager) Clear() error {
	if err := m.clearConfig(); err != nil {
		// #4898: the reload failed — the old config is still the effective
		// loaded config. Preserve prevConnNames and skip termination so a later
		// Clear retries the teardown rather than reporting a false success.
		return err
	}
	removed := m.promoteConnNames(nil)
	m.terminateRemovedConns(removed)
	return nil
}

// applyConfig renders + atomically writes the swanctl snippet and reloads.
func (m *Manager) applyConfig(ipsecCfg *config.IPsecConfig) error {
	cfg, err := m.renderConfig(ipsecCfg)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(m.configDir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	// AtomicGeneratedConfig (#1894): regenerated on every apply — a
	// torn file must never reach the strongSwan parser, but fsync is
	// deliberately skipped on this hot apply path.
	if err := fsatomic.WriteFileAtomic(m.configPath, []byte(cfg), 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	slog.Info("swanctl config written", "path", m.configPath)

	if err := m.reload(); err != nil {
		slog.Warn("swanctl reload failed", "err", err)
		return err
	}

	return nil
}

// clearConfig removes the xpf snippet and reloads strongSwan.
//
// #4898: the reload error is PROPAGATED, not swallowed. The empty-clear branch
// (Apply(nil)/Clear deleting the last VPN) previously did `_ = m.reload()` and
// returned nil, reporting success even when `swanctl --load-all` failed and
// charon kept the old connection loaded — a decommissioned/compromised peer
// would stay authorized and could re-initiate. This now mirrors applyConfig,
// which already propagates reload errors (the #4433 contract).
func (m *Manager) clearConfig() error {
	if err := os.Remove(m.configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove config: %w", err)
	}
	return m.reload()
}

func (m *Manager) reload() error {
	output, err := m.sc("--load-all")
	if err != nil {
		return fmt.Errorf("swanctl --load-all: %w: %s", err, string(output))
	}
	slog.Info("swanctl config reloaded")
	return nil
}

// vpnConnNameSet returns the set of swanctl connection names (sanitized VPN
// names, matching what renderConfig writes and what swanctl reports in
// --list-sas) for every VPN in ipsecCfg. A nil config / empty VPN map yields
// an empty set.
func vpnConnNameSet(ipsecCfg *config.IPsecConfig) map[string]bool {
	if ipsecCfg == nil || len(ipsecCfg.VPNs) == 0 {
		return nil
	}
	names := make(map[string]bool, len(ipsecCfg.VPNs))
	for name := range ipsecCfg.VPNs {
		names[sanitizeSwanctlValue(name)] = true
	}
	return names
}

// promoteConnNames records newNames as the current applied connection set and
// returns the connections that were present before but are gone now — the
// ones an operator DELETED. The diff keys off the VPN name (map key), not
// renderability, so a VPN that merely became unrenderable (a broken gateway
// reference) is NOT treated as removed and keeps its SAs.
//
// #4898: this is called ONLY after a successful reload, so prevConnNames always
// reflects the last config strongSwan actually loaded — never a config whose
// reload failed. The name/removed diff and the prevConnNames advance stay
// atomic under mu.
func (m *Manager) promoteConnNames(newNames map[string]bool) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var removed []string
	for name := range m.prevConnNames {
		if !newNames[name] {
			removed = append(removed, name)
		}
	}
	m.prevConnNames = newNames
	return removed
}

// terminateRemovedConns tears down the live IKE/child SAs of the deleted
// connections. It queries live SAs and only terminates a removed connection
// that actually has an SA, so a deletion of a VPN that was never up issues no
// swanctl call. A terminate failure is logged but never fails the apply — the
// config reload already unloaded the connection, and the SA may simply have
// been down already (#3941).
func (m *Manager) terminateRemovedConns(removed []string) {
	if len(removed) == 0 {
		return
	}

	removedSet := make(map[string]bool, len(removed))
	for _, name := range removed {
		removedSet[name] = true
	}

	live, err := m.liveConnNames()
	if err != nil {
		// Could not enumerate live SAs (charon down / vici error). Fall back
		// to an unconditional, idempotent terminate of each removed name so a
		// straggler SA is not left forwarding; swanctl no-ops when nothing
		// matches.
		slog.Warn("could not list SAs before terminating removed IPsec "+
			"connections; terminating unconditionally", "err", err)
		for _, name := range removed {
			m.terminateIKE(name)
		}
		return
	}

	for name := range live {
		if removedSet[name] {
			m.terminateIKE(name)
		}
	}
}

// terminateIKE issues `swanctl --terminate --ike <name>` for a single
// connection, logging (but not propagating) any error.
func (m *Manager) terminateIKE(name string) {
	if out, err := m.sc("--terminate", "--ike", name); err != nil {
		slog.Warn("swanctl terminate for deleted IPsec VPN failed "+
			"(SA may already be down)", "ike", name, "err", err,
			"output", string(out))
		return
	}
	slog.Info("terminated live SAs for deleted IPsec VPN", "ike", name)
}

// liveConnNames returns the set of connection (IKE SA) names strongSwan
// currently reports via --list-sas. It routes through the swanctl exec seam
// (unlike GetSAStatus, which uses stdout only); parseSAOutput ignores any
// unrecognized stderr lines CombinedOutput may fold in.
func (m *Manager) liveConnNames() (map[string]bool, error) {
	out, err := m.sc("--list-sas")
	if err != nil {
		return nil, fmt.Errorf("swanctl --list-sas: %w: %s", err, string(out))
	}
	names := make(map[string]bool)
	for _, sa := range parseSAOutput(string(out)) {
		conn := sa.ConnectionName
		if conn == "" {
			conn = sa.Name
		}
		if conn != "" {
			names[conn] = true
		}
	}
	return names, nil
}
