package dhcpserver

import (
	"time"

	"github.com/psaab/xpf/pkg/ddns"
)

// ddns.go: the thin glue between pkg/dhcpserver and the pkg/ddns spine
// (#2691 P1a). The RFC 2136 backend, the ownership state store, the reconcile
// engine, the sentinels, the write-ahead durability, and the DHCID/ownership
// model were moved VERBATIM to pkg/ddns; this file keeps pkg/dhcpserver a
// CALLER of that spine without changing any external API:
//
//   - It re-exports the cross-package DDNS types (DDNSManager, DNSUpdater,
//     LeaseDNSRecord, DDNSStats, DDNSOwnedRecordView) as type aliases so
//     pkg/daemon / pkg/grpcapi / pkg/cli / pkg/api compile unchanged.
//   - It injects the Kea-memfile lease parser (which STAYS in this package —
//     ddns_leases.go, entangled with the lease-sync fallback) into the engine
//     via the ddns.LeaseParser seam, inverting the dependency (pkg/ddns owns
//     the engine + Lease type; pkg/dhcpserver supplies the parser). This
//     avoids an import cycle: pkg/ddns never imports pkg/dhcpserver.
//
// No behavior changed in P1a — this is a pure code-motion refactor.

// DDNSManager is the DHCP dynamic-DNS reconcile manager. Moved to pkg/ddns in
// #2691 P1a; aliased here so existing callers (pkg/daemon's d.ddns field, etc.)
// need no change.
type DDNSManager = ddns.Manager

// DNSUpdater is the pluggable DNS-update backend interface (moved to pkg/ddns).
type DNSUpdater = ddns.DNSUpdater

// LeaseDNSRecord is the forward+reverse record set the reconciler operates on
// (moved to pkg/ddns).
type LeaseDNSRecord = ddns.LeaseDNSRecord

// DDNSStats is the observable counter snapshot (moved to pkg/ddns).
type DDNSStats = ddns.Stats

// DDNSOwnedRecordView is the read-only owned-record projection (moved to
// pkg/ddns).
type DDNSOwnedRecordView = ddns.OwnedRecordView

// keaLeaseParser adapts the package-local Kea-memfile parser
// (parseActiveLeases, in ddns_leases.go) to the ddns.LeaseParser seam,
// converting each full memfile ddnsLease into the reconcile-relevant
// ddns.Lease view. The v6 lease-type / prefix-len fields the lease-sync
// fallback needs are NOT part of the DDNS reconcile contract, so they are
// dropped at this boundary (exactly as the engine read the ddnsLease before
// the move — it only ever used these fields).
func keaLeaseParser(path string, family int, now time.Time) ([]ddns.Lease, error) {
	leases, err := parseActiveLeases(path, family, now)
	if err != nil {
		return nil, err
	}
	out := make([]ddns.Lease, 0, len(leases))
	for _, l := range leases {
		out = append(out, ddns.Lease{
			Family:     l.Family,
			Address:    l.Address,
			Identity:   l.Identity,
			SubnetID:   l.SubnetID,
			HostName:   l.HostName,
			ClientFQDN: l.ClientFQDN,
		})
	}
	return out, nil
}

// NewDDNSManager constructs a DDNS manager with the given updater backend and
// node id, wiring the package-local Kea-memfile lease parser. The ownership
// store is loaded from the default state path; a corrupt store fails open.
func NewDDNSManager(updater DNSUpdater, nodeID string) *DDNSManager {
	return ddns.NewManager(keaLeaseParser, updater, nodeID)
}

// NewProductionDDNSManager constructs the always-on production manager
// (#1387 increment 2), wiring the package-local Kea-memfile lease parser.
func NewProductionDDNSManager(nodeID string) *DDNSManager {
	return ddns.NewProductionManager(keaLeaseParser, nodeID)
}
