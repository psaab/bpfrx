package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/ipsec"
)

// TestApplyConfigLocked_IPsecApplyErrorFailsCommit is the #4433 regression: an
// IPsec swanctl render/reload failure previously only logged a slog.Warn and
// the commit succeeded, so the OLD tunnels stayed active (swanctl --load-all
// leaves the previously-loaded config in place on failure) while a NEW config
// was reported committed — the enforced IPsec runtime silently diverged from
// the committed policy. The daemon must now surface the ipsec.Apply error as
// the applyConfigLocked return so the commit reports failure (fail-closed),
// matching the networkd / Kea / host-inbound / lo0 tail-error contract.
//
// The failure is injected deterministically by pointing the IPsec manager's
// swanctl config dir at an UNWRITABLE path (a parent path component that is a
// regular file, so os.MkdirAll returns ENOTDIR inside applyConfig). The swallow
// at step 6 caught EVERY Apply error class — render, write, and reload — so a
// write-leg failure exercises the identical propagate-vs-swallow code path a
// reload-leg failure would (the reload contract itself is covered by
// pkg/ipsec's TestApplyReloadErrorPropagates).
func TestApplyConfigLocked_IPsecApplyErrorFailsCommit(t *testing.T) {
	networkDir := t.TempDir()

	d, cfg := minimalNetworkdDaemon(t, networkDir, &dataplane.ApplyResult{})

	// A regular file used as a parent path component makes the swanctl
	// configDir unwritable: os.MkdirAll(<file>/conf.d) fails with ENOTDIR,
	// so applyConfig returns a non-nil error before the reload.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	d.ipsec = ipsec.NewWithConfigDir(filepath.Join(blocker, "conf.d"))

	// A VPN in the config forces Apply down the applyConfig (render + write +
	// reload) path rather than the empty-config clear path, so the unwritable
	// configDir is exercised.
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn1": {Gateway: "gw1"},
	}

	err := d.applyConfigLocked(context.Background(), cfg)
	if err == nil {
		t.Fatal("applyConfigLocked must fail when ipsec.Apply cannot render/write/reload " +
			"the swanctl config (got nil — the render/reload error was swallowed, " +
			"leaving stale tunnels active under a new committed config)")
	}
	if !strings.Contains(err.Error(), "IPsec") {
		t.Fatalf("applyConfigLocked error should mention the IPsec failure: %v", err)
	}
}
