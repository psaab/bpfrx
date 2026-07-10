package routing

// test_seams.go holds exported constructors used ONLY by tests in this package
// and in dependent packages (e.g. pkg/daemon) that need to drive the routing
// Manager against a fake netlink surface. They live in a production-compiled
// file (not _test.go) so cross-package tests can reach them, mirroring
// pkg/configstore/test_seams.go. They are never called from production code.

// NewManagerWithLinkOpsForTest builds a *Manager whose link-lifecycle domains
// (vrf, tunnel, xfrm, bond, reth, monitor — every domain whose ops field is
// satisfied by the narrow linkOps surface) are backed by the supplied linkOps
// instead of a live *netlink.Handle. It exists so tests in dependent packages
// can exercise the apply/commit error-propagation wiring (#5310: a genuine
// xfrmi/bond create failure must fail the commit closed) against an in-memory
// fake — no root, no real netlink handle, no side effects on the host.
//
// Scope: the rule/route domains (routes, nextTbl, ribGroup, pbr, probePin) are
// left nil — their ops interfaces (routeLister/ruleOps/probePinOps) are NOT a
// subset of linkOps, so they cannot share this fake. Callers exercising
// interface-reconcile (ApplyTunnels/ApplyXfrmi/ApplyBonds/ClearRethInterfaces)
// do not touch those domains. nlHandle stays nil (Close nil-guards it).
//
// Callers pass any value whose method set matches linkOps (the interface's
// methods are all exported, so a fake defined in another package satisfies it
// structurally).
func NewManagerWithLinkOpsForTest(ops linkOps) *Manager {
	m := &Manager{}
	m.vrf = &vrfManager{ops: ops}
	m.tunnel = &tunnelManager{ops: ops, vrfBinder: m.vrf, keepalives: make(map[string]*keepaliveRunner)}
	m.xfrm = &xfrmManager{ops: ops}
	m.bond = &bondManager{ops: ops}
	m.reth = &rethManager{ops: ops}
	m.monitor = &monitorManager{ops: ops, monitorStatus: make(map[int][]InterfaceMonitorStatus)}
	return m
}
