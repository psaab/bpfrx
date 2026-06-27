// Package ipsec generates strongSwan (swanctl) configuration and queries SA status.
package ipsec

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
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

// Clear removes the xpf config and reloads strongSwan.
func (m *Manager) Clear() error {
	if err := os.Remove(m.configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove config: %w", err)
	}
	_ = m.reload()
	return nil
}

func (m *Manager) reload() error {
	output, err := runSwanctl("--load-all")
	if err != nil {
		return fmt.Errorf("swanctl --load-all: %w: %s", err, string(output))
	}
	slog.Info("swanctl config reloaded")
	return nil
}
