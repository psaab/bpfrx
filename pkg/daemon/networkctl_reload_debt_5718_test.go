package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/networkd"
)

// TestNetworkctlReloadRecordsActivationDebt_5718 is the pkg/daemon half of the
// #5718 fold F2 fail-on-revert.
//
// networkctlReload is the process's OTHER `networkctl reload` owner: every
// daemon-side reload funnels through it — linksetup's post-rename reload,
// device-map's rename and teardown reloads (via networkctlReloadFn), and
// bootstrap's teardown and lifeline reloads — and they all write or remove the
// same 10-xpf-* files pkg/networkd generates.
//
// Before the fold it bypassed networkd's #4954 activation debt entirely. That
// matters most at the linksetup call site, which is warn-only: a failed reload
// there was logged and forgotten, the renamed .link files stayed on disk
// unactivated, and networkd.Apply's debt still read false — so the next Apply
// with byte-identical content skipped the reload and returned nil, which is
// exactly the #4954 false success, reached through the other owner.
//
// networkd's debt epoch advances only when a failure is RECORDED, so it is the
// observable for "the failure was carried forward".
func TestNetworkctlReloadRecordsActivationDebt_5718(t *testing.T) {
	origRun := runCommandTimeout
	t.Cleanup(func() { runCommandTimeout = origRun })

	reloadFails := true
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name == "networkctl" && len(args) > 0 && args[0] == "reload" {
			if reloadFails {
				return []byte("Failed to reload network settings"),
					errors.New("simulated networkctl reload failure")
			}
			return nil, nil
		}
		return nil, nil
	}

	// A FAILED daemon-side reload must record the activation debt.
	before := networkd.BeginReload()
	if err := networkctlReload(); err == nil {
		t.Fatal("setup: networkctlReload must surface the failing reload")
	}
	afterFailure := networkd.BeginReload()
	if afterFailure == before {
		t.Fatal("a FAILED daemon-side `networkctl reload` must record networkd's #4954 " +
			"activation debt. Without it the generated 10-xpf-* files stay on disk " +
			"unactivated while networkd.Apply's debt reads false, so the next Apply " +
			"with unchanged content skips the reload and reports a success the " +
			"kernel never performed — and the linksetup call site is warn-only, so " +
			"this record is the only thing that carries the failure forward")
	}

	// A SUCCESSFUL daemon-side reload must NOT be misrecorded as a failure:
	// the debt is an obligation, not a counter of reloads.
	reloadFails = false
	beforeSuccess := networkd.BeginReload()
	if err := networkctlReload(); err != nil {
		t.Fatalf("networkctlReload should succeed when the shell-out succeeds: %v", err)
	}
	if networkd.BeginReload() != beforeSuccess {
		t.Fatal("a SUCCESSFUL daemon-side `networkctl reload` must not record activation debt")
	}
}
