package ipsec

import (
	"errors"
	"strings"
	"testing"
)

// TestApplyReloadErrorPropagates documents the Manager-side half of the #4433
// contract: when `swanctl --load-all` fails, strongSwan leaves the previously
// loaded config in place (the OLD tunnels stay active), so Manager.Apply MUST
// return that reload error to its caller. The daemon then joins it into the
// commit result (see pkg/daemon TestApplyConfigLocked_IPsecApplyErrorFailsCommit)
// so the operator is not told the new IPsec policy is enforced when it is not.
func TestApplyReloadErrorPropagates(t *testing.T) {
	reloadErr := errors.New("charon vici socket refused")

	m := NewWithConfigDir(t.TempDir())
	// Render + write succeed; only the reload shell-out fails.
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			return []byte("unable to load config"), reloadErr
		}
		return nil, nil
	}

	err := m.Apply(vpnCfg("vpn1"))
	if err == nil {
		t.Fatal("Manager.Apply must return the swanctl --load-all failure " +
			"(got nil — a reload failure was swallowed, leaving stale tunnels " +
			"active under the new config)")
	}
	if !errors.Is(err, reloadErr) {
		t.Fatalf("Apply error must wrap the underlying reload error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "--load-all") {
		t.Fatalf("Apply error should name the failed swanctl --load-all call: %v", err)
	}
}
