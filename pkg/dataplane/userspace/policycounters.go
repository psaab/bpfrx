package userspace

import (
	"errors"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func buildPolicyRuleCounterIndex(status *ProcessStatus) map[string]PolicyRuleCounterStatus {
	index := make(map[string]PolicyRuleCounterStatus)
	if status == nil {
		return index
	}
	for _, counter := range status.PolicyRuleCounters {
		if counter.RuleID == "" {
			continue
		}
		index[counter.RuleID] = counter
	}
	return index
}

// policyRuleIDForCounter translates the numeric policy-counter handle used by
// the per-policy hit-count read callers into the stable rule ID that the
// userspace helper reports counters by.
//
// IMPORTANT — two distinct numeric namespaces coexist by design, and this
// resolver intentionally lives in the SLICE-INDEX one, NOT the span-accumulated
// snapshot-PolicyID one:
//
//   - The dataplane snapshot's PolicyRuleSnapshot.PolicyID (assigned by
//     walkPolicyRuleSlots / buildPolicySnapshots) is span-accumulated:
//     policySetID*MaxRulesPerPolicy + ruleIndex, where ruleIndex advances by the
//     application-set expansion count. That namespace serves the dataplane and
//     the RT_FLOW/event path.
//   - The per-policy COUNTER read path is name-keyed: the helper reports each
//     rule's packets/bytes under its stable RuleID string
//     (`from->to/name`, see PolicyRuleSnapshot.RuleID and
//     buildPolicyRuleCounterIndex). The numeric policyID passed to
//     ReadPolicyCounters is ONLY a handle the callers use to identify which
//     policy they want a name for. EVERY production caller
//     (pkg/api/metrics_counters.go, pkg/api/security.go,
//     pkg/cli/cli_show_security*.go, pkg/grpcapi/server_show_*.go) computes that
//     handle as policySetID*MaxRulesPerPolicy + sliceIndex, where sliceIndex is
//     the raw position in zpp.Policies — NOT the expanded ruleIndex.
//
// Therefore this resolver MUST decode the remainder as a direct slice index to
// agree with the callers. Decoding it as a span-accumulated index (mapping the
// handle into the preceding policy's expansion span) would mis-resolve the
// counter of every policy that follows a multi-application policy to the
// preceding policy. The counter store never indexes by the span-accumulated id
// (the helper is name-keyed; the legacy bpfShim policy_counters array is not
// incremented in userspace mode), so there is nothing to "round-trip" against —
// the only requirement is caller/resolver agreement, and both use slice index.
func policyRuleIDForCounter(cfg *config.Config, policyID uint32) string {
	// #3363: the reserved sentinel doubles as the read handle for the IMPLICIT
	// default-policy hit counter. The userspace helper reports that counter
	// under the stable rule id dataplane.DefaultPolicyName ("default-policy",
	// the same name rendered in RT_FLOW logs), so resolving the sentinel here
	// lets EVERY existing counter surface (CLI, gRPC text, REST, Prometheus)
	// read it via the unchanged ReadPolicyCounters(DefaultPolicySentinelID)
	// path — no new dataplane interface method. The sentinel can never collide
	// with a configured policy's computed id (see DefaultPolicySentinelID).
	if policyID == dataplane.DefaultPolicySentinelID {
		return dataplane.DefaultPolicyName
	}
	if cfg == nil {
		return ""
	}
	policySetID := policyID / dataplane.MaxRulesPerPolicy
	ruleIndex := policyID % dataplane.MaxRulesPerPolicy

	var currentSet uint32
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			// #3474: a nil zone-pair slot still consumes a policy-set ID. The
			// SSOT walker (walkPolicyRuleSlots) and EVERY production counter
			// caller (pkg/api/security.go, pkg/api/metrics_counters.go) do
			// `policySetID++` for a nil element of cfg.Security.Policies, so this
			// resolver advances currentSet in lockstep — it was the lone consumer
			// that skipped a nil slot WITHOUT incrementing, diverging from the
			// walker + all callers. This is DEFENSIVE SSOT-alignment, not a
			// reachable-bug fix: a nil cfg.Security.Policies slot is not produced
			// by any production config path today (strict and tolerant compile
			// share a non-nil-only builder; HA ships recompiled config text;
			// persistence round-trips the tree). Aligning it here matches the
			// #3476/#3494 defensive nil-guards so the resolver/walker/callers can
			// never drift if a nil slot ever does arise.
			currentSet++
			continue
		}
		if currentSet == policySetID {
			if int(ruleIndex) >= len(zpp.Policies) || zpp.Policies[ruleIndex] == nil {
				return ""
			}
			return stablePolicyRuleID(zpp.FromZone, zpp.ToZone, zpp.Policies[ruleIndex].Name)
		}
		currentSet++
	}
	if currentSet == policySetID {
		if int(ruleIndex) >= len(cfg.Security.GlobalPolicies) || cfg.Security.GlobalPolicies[ruleIndex] == nil {
			return ""
		}
		return stablePolicyRuleID("junos-global", "junos-global", cfg.Security.GlobalPolicies[ruleIndex].Name)
	}
	return ""
}

func (m *Manager) ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error) {
	// The public DataPlane API is still indexed by legacy policy ID, while the
	// userspace helper reports counters by stable policy identity. Keep the
	// translation config-derived so scheduled-rule counters survive delete/re-add
	// and app-term slot expansion without callers recomputing Rust map slots.
	var total dataplane.CounterValue
	var innerErr error
	if m.bpfShim != nil {
		total, innerErr = m.bpfShim.ReadPolicyCounters(policyID)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	cfg := (*config.Config)(nil)
	if m.lastSnapshot != nil {
		cfg = m.lastSnapshot.Config
	}
	ruleID := policyRuleIDForCounter(cfg, policyID)
	if ruleID == "" {
		if innerErr != nil {
			return dataplane.CounterValue{}, innerErr
		}
		return total, nil
	}
	counter, ok := buildPolicyRuleCounterIndex(&m.lastStatus)[ruleID]
	if !ok {
		if innerErr != nil {
			return dataplane.CounterValue{}, innerErr
		}
		return total, nil
	}
	total.Packets += counter.Packets
	total.Bytes += counter.Bytes
	return total, nil
}

func (m *Manager) ClearPolicyCounters() error {
	var errs []error
	if m.bpfShim != nil {
		if err := m.bpfShim.ClearPolicyCounters(); err != nil {
			errs = append(errs, err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.clearHelperPolicyCountersLocked(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *Manager) ClearAllCounters() error {
	var errs []error
	if m.bpfShim != nil {
		if err := m.bpfShim.ClearAllCounters(); err != nil {
			errs = append(errs, err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.clearHelperPolicyCountersLocked(); err != nil {
		errs = append(errs, err)
	}
	// #2218: a clear-all must also reset the helper NAT translation hit store,
	// otherwise the per-rule NAT totals snap back on the next status poll (the
	// helper reports cumulative-since-start and syncBPFCountersLocked overwrites
	// the offset absolutely). bpfShim.ClearAllCounters() already zeroed the Go
	// offset map; this sends the clear_nat_counters IPC.
	if err := m.clearHelperNATCountersLocked(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *Manager) clearHelperPolicyCountersLocked() error {
	if m.proc == nil || m.proc.Process == nil {
		for i := range m.lastStatus.PolicyRuleCounters {
			m.lastStatus.PolicyRuleCounters[i].Packets = 0
			m.lastStatus.PolicyRuleCounters[i].Bytes = 0
		}
		return nil
	}

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "clear_policy_counters"}, &status); err != nil {
		return err
	}
	m.recordHelperStatusLocked(&status)
	return nil
}
