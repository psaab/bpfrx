package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
	"golang.org/x/sync/semaphore"
)

// armFailTestDP is a runtime dataplane whose Start() (the AF_XDP arm /
// LoadUserspaceShim attach) fails, to exercise the #5275 fail-closed path
// without a live dataplane. Every other method is inherited from
// runtimeOnlyApplyTestDP.
type armFailTestDP struct {
	runtimeOnlyApplyTestDP
	startErr error
}

func (d *armFailTestDP) Start(context.Context) error { return d.startErr }

// captureForwardingSysctls redirects writeForwardingSysctl into a map for the
// duration of the test so the fail-closed forwarding decision is observable
// without touching /proc.
func captureForwardingSysctls(t *testing.T) map[string]string {
	t.Helper()
	got := make(map[string]string)
	prev := writeForwardingSysctl
	writeForwardingSysctl = func(path, val string) { got[path] = val }
	t.Cleanup(func() { writeForwardingSysctl = prev })
	return got
}

// TestEnterDataplaneArmFailedFailClosed_ImmediateActions_5275 pins the immediate
// fail-closed actions the handler takes when a successful compile is followed by
// a dataplane arm failure: the sticky flag is set, transit forwarding is
// disabled (ip_forward=0), the FRR managed section is stripped, and the cluster
// is held SECONDARY.
//
// FAIL-ON-REVERT: delete any one of the four actions in
// enterDataplaneArmFailedFailClosed (bootstrap.go) and the matching assertion
// below goes RED — e.g. dropping disableForwarding() leaves ip_forward unwritten,
// dropping SetArmFailedHold() leaves ArmFailedHeld() false, dropping the
// clearFRR call leaves the managed section on disk.
func TestEnterDataplaneArmFailedFailClosed_ImmediateActions_5275(t *testing.T) {
	fwd := captureForwardingSysctls(t)
	// No pinned XDP links (cold boot) → FRR clear takes the stage-1 path.
	withFailClosedBootPinnedXDPProbe(t, func() (bool, error) { return false, nil })
	confPath, sentinel := seededFRRConf(t)
	rec := &frr.RecordingExecutor{}

	d := &Daemon{
		frr:     frr.NewForTest(confPath, rec),
		cluster: cluster.NewManager(0, 1),
		vrrpMgr: vrrp.NewManager(),
	}

	d.enterDataplaneArmFailedFailClosed()

	if !d.dataplaneArmFailed.Load() {
		t.Fatal("enterDataplaneArmFailedFailClosed must set the sticky dataplaneArmFailed flag")
	}
	if got := fwd["/proc/sys/net/ipv4/ip_forward"]; strings.TrimSpace(got) != "0" {
		t.Fatalf("transit forwarding must be DISABLED (ip_forward=0); got %q", got)
	}
	if got := fwd["/proc/sys/net/ipv6/conf/all/forwarding"]; strings.TrimSpace(got) != "0" {
		t.Fatalf("IPv6 forwarding must be DISABLED; got %q", got)
	}
	if strings.Contains(readConf(t, confPath), sentinel) {
		t.Fatalf("FRR managed section (route advertisement) must be stripped on arm failure; frr.conf still has %q", sentinel)
	}
	if !d.cluster.ArmFailedHeld() {
		t.Fatal("cluster must be held SECONDARY (ArmFailedHeld) so the healthy peer owns the RGs")
	}
}

// TestBootArmFailure_SkipsApplyConfig_5275 is the boot-arm wiring proof. When the
// boot-time arm fails, armBuiltDataplaneAndApplyBootConfig must fail closed and
// SKIP the boot applyConfig entirely — no VRF/interface/routing/FRR/VRRP/cluster
// takeover is published on a policy-free node.
//
// FAIL-ON-REVERT: change the arm-failure branch back to the pre-#5275 behavior
// (set d.dp=nil and fall through to applyConfig) and this goes RED — the
// applyBodyForTest recorder is invoked and the flag is never set.
func TestBootArmFailure_SkipsApplyConfig_5275(t *testing.T) {
	captureForwardingSysctls(t) // swallow the disableForwarding writes

	// A committed active config so the pre-#5275 fall-through WOULD reach
	// applyConfig (ActiveConfig() != nil).
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if store.ActiveConfig() == nil {
		t.Fatal("precondition: committed store must expose a non-nil ActiveConfig")
	}

	applyCalled := false
	d := &Daemon{
		dp:       &armFailTestDP{startErr: errors.New("xsk bind: operation not permitted")},
		store:    store,
		applySem: semaphore.NewWeighted(1),
	}
	d.applyBodyForTest = func(*config.Config) { applyCalled = true }

	d.armBuiltDataplaneAndApplyBootConfig()

	if applyCalled {
		t.Fatal("boot arm failure must SKIP applyConfig (no ownership publish); applyConfig was called")
	}
	if !d.dataplaneArmFailed.Load() {
		t.Fatal("boot arm failure must set the sticky dataplaneArmFailed flag")
	}
	if d.dp != nil {
		t.Fatal("boot arm failure must clear d.dp (config-only), got non-nil")
	}
}

// withForwardingEnableProbe swaps the transit-forwarding-enable seam for a
// recorder so the #5275 applyKernelTuning gate is testable without depending on
// the host's /proc/sys/net/ipv4/ip_forward (already 1 on a firewall dev box).
func withForwardingEnableProbe(t *testing.T) *bool {
	t.Helper()
	called := false
	prev := enableTransitForwardingSysctls
	enableTransitForwardingSysctls = func() { called = true }
	t.Cleanup(func() { enableTransitForwardingSysctls = prev })
	return &called
}

// TestApplyKernelTuning_ArmFailed_DoesNotReenableForwarding_5275 pins that the
// apply-tail kernel tuning does NOT re-arm ip_forward=1 while the dataplane is
// unarmed — the exact "applyKernelTuning re-writes ip_forward=1 at the apply
// tail" re-arm the issue calls out, which a bootstrap-exit or recovery-commit
// apply would otherwise hit.
//
// FAIL-ON-REVERT: delete the `if d.dataplaneArmFailed.Load() { ... return }`
// gate in applyKernelTuning (daemon_system.go) and this goes RED — the
// transit-forwarding-enable seam is invoked.
func TestApplyKernelTuning_ArmFailed_DoesNotReenableForwarding_5275(t *testing.T) {
	enabled := withForwardingEnableProbe(t)
	d := &Daemon{}
	d.dataplaneArmFailed.Store(true)

	d.applyKernelTuning(&config.Config{})

	if *enabled {
		t.Fatal("fail-closed applyKernelTuning must NOT re-enable transit forwarding")
	}
}

// TestApplyKernelTuning_Armed_ReenablesForwarding_5275 is the negative control:
// with the flag UNSET, applyKernelTuning re-enables forwarding as before, so the
// gate above is not a blanket disable.
func TestApplyKernelTuning_Armed_ReenablesForwarding_5275(t *testing.T) {
	enabled := withForwardingEnableProbe(t)
	d := &Daemon{} // dataplaneArmFailed == false

	d.applyKernelTuning(&config.Config{})

	if !*enabled {
		t.Fatal("armed applyKernelTuning must re-enable transit forwarding")
	}
}

// TestApplyTailReconciles_ArmFailed_SuppressesVRRP_5275 proves the commit/apply
// tail publishes NO VRRP instances when the dataplane failed to arm. It reuses
// the #5083 duplicate-identity config: without the fail-closed gate the tail
// collects the colliding instances and UpdateInstances REJECTS them, failing the
// commit; with the gate the desired set is empty, so there is no collision and
// no VRRP ownership.
//
// FAIL-ON-REVERT: delete the `if !d.dataplaneArmFailed.Load()` guard around the
// VRRP collection in applyTailReconciles (daemon_apply_tail.go) and this goes
// RED — the duplicate-identity collision returns a non-nil commit error.
func TestApplyTailReconciles_ArmFailed_SuppressesVRRP_5275(t *testing.T) {
	installFakeNetworkctl(t)
	captureForwardingSysctls(t)

	origApply, origDelete := nftApplyPayload, nftDeleteTable
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	nftDeleteTable = func(string, string) ([]byte, error) { return nil, nil }
	defer func() { nftApplyPayload, nftDeleteTable = origApply, origDelete }()

	d := &Daemon{
		dp:       &runtimeOnlyApplyTestDP{},
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.dataplaneArmFailed.Store(true)

	group := func(vip string) map[string]*config.VRRPGroup {
		return map[string]*config.VRRPGroup{
			vip + "_grp5": {ID: 5, VirtualAddresses: []string{vip}},
		}
	}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {
			Name: "ge-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				100: {Number: 100, VlanID: 100, VRRPGroups: group("10.0.0.1/24")},
				200: {Number: 200, VlanID: 100, VRRPGroups: group("10.0.1.1/24")},
			},
		},
	}

	err := d.applyTailReconciles(cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil && strings.Contains(err.Error(), "duplicate VRRP instance identity") {
		t.Fatalf("fail-closed tail must NOT collect/publish VRRP instances; got collision error: %v", err)
	}
	if states := d.vrrpMgr.States(); len(states) != 0 {
		t.Fatalf("fail-closed tail must install no VRRP runtime state; got %v", states)
	}
}

// TestApplyRoutingRules_ArmFailed_SkipsFRRPublish_5275 proves the apply path does
// NOT re-publish the FRR managed section (route advertisement) while the
// dataplane is unarmed — so a bootstrap-exit or recovery-commit apply cannot
// re-open the route-advertisement hole the immediate handler closed.
//
// FAIL-ON-REVERT: delete the `d.dataplaneArmFailed.Load()` branch guarding the
// applyFRRConfig publish in applyRoutingRules (daemon_apply_routing.go) and this
// goes RED — applyFRRConfig runs and the recording executor logs a reload.
func TestApplyRoutingRules_ArmFailed_SkipsFRRPublish_5275(t *testing.T) {
	confPath, _ := seededFRRConf(t)
	rec := &frr.RecordingExecutor{}
	d := &Daemon{
		frr:   frr.NewForTest(confPath, rec),
		store: newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		// d.routing left nil: the ip-rule reconciles below the FRR block
		// nil-guard, so the FRR publish decision is exercised in isolation.
	}
	d.dataplaneArmFailed.Store(true)

	if err := d.applyRoutingRules(&config.Config{}, nil); err != nil {
		t.Fatalf("applyRoutingRules returned error: %v", err)
	}

	if rec.ReloadCalls != 0 {
		t.Fatalf("fail-closed apply must NOT publish/reload FRR; got %d reloads", rec.ReloadCalls)
	}
}

// TestApplyRoutingRules_Armed_PublishesFRR_5275 is the negative control: with the
// flag UNSET the FRR managed section is published as before (the gate is not a
// blanket skip).
func TestApplyRoutingRules_Armed_PublishesFRR_5275(t *testing.T) {
	confPath, _ := seededFRRConf(t)
	rec := &frr.RecordingExecutor{}
	d := &Daemon{
		frr:   frr.NewForTest(confPath, rec),
		store: newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
	}

	if err := d.applyRoutingRules(&config.Config{}, nil); err != nil {
		t.Fatalf("applyRoutingRules returned error: %v", err)
	}

	if rec.ReloadCalls == 0 {
		t.Fatal("armed apply must publish/reload FRR; got 0 reloads")
	}
}
