package config

// #8447: the persistent-NAT / chassis-cluster combination, single-sourced.
//
// THE DEFECT THIS EXISTS FOR. Adding `persistent-nat` to a source-NAT pool on a
// clustered node stops the dataplane forwarding transit entirely — rx drops to
// 0. That is DELIBERATE and documented (#1449): persistent-NAT leases are
// helper-local allocator state that is not HA-synchronized, so the dataplane
// declines to forward rather than forward with semantics it cannot honour.
//
// The defect is that it happens INVISIBLY. The config commits cleanly, and the
// only surface is `Forwarding supported: false` inside a `show` nobody runs
// when the symptom is "the link went down". The issue spent five rounds of
// cluster measurement rediscovering a contract the daemon already knew.
//
// WHY THE PREDICATE MOVED HERE. It lived in
// `pkg/dataplane/userspace/capabilities.go`, which `pkg/config` cannot import
// (userspace imports config, not the reverse). The tree's existing habit for
// this shape is to MIRROR the predicate with a comment saying it mirrors — see
// `deterministicIPv4Enforced`'s "this mirrors the enforced/deferred split in
// userspace.deterministicSourceNATFields". A mirror is a drift surface: the
// advisory and the gate can disagree, and the failure mode is an advisory that
// stops firing for a config that still disarms forwarding — silence that reads
// exactly like safety.
//
// So the capability gate now CALLS this. There is one predicate, and the
// advisory cannot promise something the dataplane does not do.

// UsesPersistentSourceNATPool reports whether any source-NAT rule targets a
// pool carrying a `persistent-nat` stanza.
//
// Keyed on the RULE, not on the pool table: a pool defined but referenced by no
// rule translates nothing, so it neither disarms forwarding nor deserves an
// advisory. That is the same shape the capability gate has always had, and it
// is why the loop walks rule-sets rather than `SourcePools`.
func UsesPersistentSourceNATPool(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.Then.PoolName == "" {
				continue
			}
			pool := cfg.Security.NAT.SourcePools[rule.Then.PoolName]
			if pool != nil && pool.PersistentNAT != nil {
				return true
			}
		}
	}
	return false
}

// persistentNATClusterForwardingWarnings emits the #8447 commit-time advisory.
//
// It fires on exactly the condition the capability gate uses — a chassis
// cluster AND a rule-referenced persistent-NAT pool — so an operator learns at
// COMMIT that this config stops forwarding, rather than discovering it when
// traffic stops.
//
// It is an ADVISORY, not a rejection, and that is deliberate. The behaviour is
// the documented #1449 contract, the config is valid, and an operator may be
// committing it knowingly on a node that is not yet carrying traffic. Rejecting
// would also make the standalone case — where the same stanza is perfectly
// fine — impossible to reach through a shared config, since `chassis cluster`
// and the NAT stanza are committed independently.
func persistentNATClusterForwardingWarnings(cfg *Config) []string {
	if cfg == nil || cfg.Chassis.Cluster == nil || !UsesPersistentSourceNATPool(cfg) {
		return nil
	}
	return []string{
		"security nat source persistent-nat is configured on a pool referenced by a " +
			"rule, and this node is a chassis-cluster member: the userspace dataplane " +
			"will DISARM FORWARDING while this config is active (persistent-NAT leases " +
			"are helper-local and not HA-synchronized, #1449). Transit traffic will " +
			"stop — the interfaces stay up and the config commits cleanly, so this " +
			"appears as a connectivity failure rather than a NAT one. Check " +
			"`show chassis forwarding` for \"Forwarding supported: false\". Remove " +
			"persistent-nat from the pool, or remove the node from the cluster, to " +
			"restore forwarding.",
	}
}
