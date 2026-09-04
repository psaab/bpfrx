package config

import "net"

// reth_virtual_mac_8340.go — muse-spark-review-004 K18/K105.
//
// THE SPLIT. The RETH virtual MAC `02:bf:72:CC:RR:NN` was constructed in two
// places from two copies of the same literal: `cluster.RethMAC`, which the
// daemon programs onto the interface, and an inline `net.HardwareAddr{0x02,
// 0xbf, 0x72, ...}` in `pkg/dataplane/compiler_iface.go`, which SEARCHES for
// that MAC to recover a RETH member whose `.link` rename was lost.
//
// A search key and the thing it searches for, written twice. If the format ever
// changed in one, the recovery search would find nothing and the RETH member
// would be dropped from the config silently — the failure mode the recovery
// path exists to prevent.
//
// They were not merged before because `pkg/cluster` imports `pkg/dataplane`, so
// the dataplane cannot import the cluster package back. `pkg/config` is the leaf
// both already depend on, and it is where the "this id is ONE OCTET" fact
// already lives (`MaxRethRedundancyGroupOctet`).

// RethVirtualMAC returns the per-node, per-redundancy-group virtual MAC a RETH
// interface carries: `02:bf:72:CC:RR:NN` for cluster id CC, redundancy group RR
// and node id NN.
//
// EACH ID IS ONE BYTE, and that is a contract with the commit gates rather than
// a truncation to hope about:
//
//   - cluster id — `schema_chassis.go` bounds the leaf with
//     `ValidateInteger(0, 255)`, and its own description says "one byte of the
//     RETH virtual MAC";
//   - redundancy-group id — `validateChassisClusterStrict` rejects anything
//     above `MaxHeartbeatRedundancyGroupID` (255) and again at or above
//     `MaxRedundancyGroups` (16), so a committed id is 0..15;
//   - node id — 0 or 1.
//
// So `byte(id)` is EXACT for every configuration that passed commit, and the
// aliasing K18 describes needs a tolerantly-loaded config that never did.
// `reth_virtual_mac_8340_test.go` asserts that agreement rather than restating
// it, because a widened bound with an unchanged MAC width is precisely how two
// redundancy groups would come to share an L2 identity.
//
// Deliberately NOT saturating, unlike the heartbeat's `wireRGID`. Saturation is
// right there because refusing to advertise a group reproduces the bug it
// fixes; here it would collapse two out-of-range ids onto 255 AND onto a
// legitimate id 255 — three groups sharing a MAC instead of two. A clamp would
// make the aliasing deterministic, not absent, so it would buy nothing the
// commit gates do not already provide.
func RethVirtualMAC(clusterID, rgID, nodeID int) net.HardwareAddr {
	return net.HardwareAddr{0x02, 0xbf, 0x72, byte(clusterID), byte(rgID), byte(nodeID)}
}
