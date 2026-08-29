package daemon

import (
	"net"

	"github.com/psaab/xpf/pkg/config"
)

// ingress_fold_7095.go — #7095: the daemon side of the cluster-stable ingress
// identity that rides the HA session-sync wire.
//
// pkg/cluster deliberately holds no config, so the resolver is built here and
// injected. It is rebuilt on every config apply, which is also when the ifindex
// snapshot is taken.

// buildIngressFoldFn returns the resolver SessionSync stamps outgoing sessions
// with: a session's node-local {ifindex, vlan} to the fold of the interface's
// CLUSTER-STABLE name.
//
// Returns nil when there is nothing to resolve with, and nil is a supported
// value — SessionSync stamps 0, the unknown sentinel, which is what a legacy
// peer sends anyway. The failure mode of this whole path is degradation to the
// #4792 zone approximation, never a wrong interface name.
//
// THE IFINDEX SNAPSHOT IS TAKEN ONCE PER APPLY, not per session: the send path
// walks every session in a bulk sync, and a netlink round trip each would put a
// syscall on that loop. A NIC that appears after this snapshot folds to 0 until
// the next commit — it degrades, it does not lie. (A RECYCLED ifindex is the
// one case that could name the wrong device; that is #6987, which predates this
// change and is tracked separately for the local display path as well.)
func buildIngressFoldFn(cfg *config.Config) func(ifindex uint32, vlan uint16) uint32 {
	if cfg == nil {
		return nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	nameByIndex := make(map[uint32]string, len(ifaces))
	for _, ifc := range ifaces {
		if ifc.Index > 0 {
			nameByIndex[uint32(ifc.Index)] = ifc.Name
		}
	}
	// Pre-fold the names this config can produce so the send path does no
	// hashing per session — a bulk sync walks the whole table.
	return func(ifindex uint32, vlan uint16) uint32 {
		if ifindex == 0 {
			return 0
		}
		name := nameByIndex[ifindex]
		if name == "" {
			return 0
		}
		return config.StableIfaceID(cfg.ClusterStableIfaceName(name, vlan))
	}
}
