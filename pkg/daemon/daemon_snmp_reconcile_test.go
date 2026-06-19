package daemon

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/snmp"
	"github.com/psaab/xpf/pkg/vrrp"
)

// snmpDowngradeConfig returns a compiled config whose only SNMP community is
// authorized read-only. Reconciling the running agent onto it must flip the
// live SET access-control gate from read-write to read-only.
func snmpDowngradeConfig() *config.Config {
	return &config.Config{
		System: config.SystemConfig{
			SNMP: &config.SNMPConfig{
				Communities: map[string]*config.SNMPCommunity{
					"private": {Name: "private", Authorization: "read-only"},
				},
			},
		},
	}
}

// TestApplyConfigLockedReconcilesSNMPAuthorization proves the daemon WIRING:
// applyConfigLocked must call snmpAgent.UpdateConfig so a committed community
// downgrade (read-write -> read-only) reaches the live agent. This drives the
// REAL applyConfigLocked body (not the applyBodyForTest seam), so it fails if
// the UpdateConfig call is removed from applyConfigLocked — the package-level
// snmp tests exercise UpdateConfig directly and would NOT catch that.
//
// Mutation check: delete the `d.snmpAgent.UpdateConfig(...)` line from
// applyConfigLocked and this test fails — the agent keeps its read-write gate
// and SETAuthorized("private") stays true after the apply.
func TestApplyConfigLockedReconcilesSNMPAuthorization(t *testing.T) {
	agent := snmp.NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"private": {Name: "private", Authorization: "read-write"},
		},
	})
	if !agent.SETAuthorized("private") {
		t.Fatal("precondition: agent should start read-write")
	}

	installFakeNetworkctl(t)
	d := &Daemon{
		applySem:  semaphore.NewWeighted(1),
		snmpAgent: agent,
		dp:        &runtimeOnlyApplyTestDP{},
		vrrpMgr:   vrrp.NewManager(),
		store:     newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:      Options{NoDataplane: true},
	}

	if err := d.applyConfigLocked(snmpDowngradeConfig()); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}

	if agent.SETAuthorized("private") {
		t.Fatal("applyConfigLocked did not reconcile SNMP authorization: " +
			"community is still read-write after a read-only commit " +
			"(missing snmpAgent.UpdateConfig wiring)")
	}
}

// TestApplyConfigLockedReconcilesSNMPBeforeDataplaneAbort is the Codex r2
// regression: the SNMP reconcile must run BEFORE the dataplane apply, which
// aborts applyConfigLocked early on ErrPolicySchedulerProtocolIncompatible
// (compileErrorMustAbortApply). Store.Commit() has already promoted/persisted
// the compiled config, so the committed authorization is live regardless of
// whether the dataplane apply later fails. If the reconcile is placed AFTER the
// abort (the original step-16b position), an early-aborting apply leaves the
// downgraded community still serving the stale read-write gate.
//
// The fake dataplane returns the aborting sentinel from ApplyConfig, so the
// call returns that error (proving the early-return fired). The assertion is
// that despite the abort the live SNMP gate reflects the downgrade.
//
// Mutation check: move the snmpAgent.UpdateConfig call back below the dataplane
// apply (step 16b) and this test fails — the early return skips it and the gate
// stays read-write.
func TestApplyConfigLockedReconcilesSNMPBeforeDataplaneAbort(t *testing.T) {
	agent := snmp.NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"private": {Name: "private", Authorization: "read-write"},
		},
	})
	if !agent.SETAuthorized("private") {
		t.Fatal("precondition: agent should start read-write")
	}

	dp := &runtimeOnlyApplyTestDP{
		applyErr: dpuserspace.ErrPolicySchedulerProtocolIncompatible,
	}
	d := &Daemon{
		applySem:  semaphore.NewWeighted(1),
		snmpAgent: agent,
		dp:        dp,
		store:     newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:      Options{NoDataplane: true},
	}

	err := d.applyConfigLocked(snmpDowngradeConfig())
	if !errors.Is(err, dpuserspace.ErrPolicySchedulerProtocolIncompatible) {
		t.Fatalf("applyConfigLocked error = %v, want early abort on "+
			"ErrPolicySchedulerProtocolIncompatible (the early-return path "+
			"this test exercises)", err)
	}
	if dp.applyCalls != 1 {
		t.Fatalf("dataplane ApplyConfig calls = %d, want 1 (abort path not reached)", dp.applyCalls)
	}

	if agent.SETAuthorized("private") {
		t.Fatal("SNMP authorization was NOT reconciled before the dataplane " +
			"abort: a committed read-write -> read-only downgrade is still " +
			"serving the stale read-write gate because applyConfigLocked " +
			"aborted early before reaching the SNMP reconcile")
	}
}
