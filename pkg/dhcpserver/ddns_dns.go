package dhcpserver

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// ddns_dns.go: the DNS-update backend interface (#1387 plan §4.4) plus the
// pure record-construction helpers (forward A/AAAA + reverse PTR name).
// Increment 1 ships the interface, the record model, and a fakeUpdater
// (see ddns_test.go) so the reconciler is fully unit-testable with no
// network or DNS dependency. The live rfc2136 backend is increment 2.

// LeaseDNSRecord is the forward+reverse record set the reconciler wants
// for one active lease. It is the unit both UpsertLease and DeleteLease
// operate on; a delete re-derives the SAME record from owned state so the
// backend only ever touches names this firewall created.
type LeaseDNSRecord struct {
	// FQDN is the forward name (already normalized + sanitized).
	FQDN string
	// Addr is the leased address.
	Addr netip.Addr
	// TTL is the record TTL in seconds.
	TTL int
	// ForwardType is "A" (v4) or "AAAA" (v6), derived from Addr.
	ForwardType string
	// PTRName is the reverse-zone name (in-addr.arpa / ip6.arpa).
	PTRName string
}

// DNSUpdater is the pluggable DNS-update backend (plan §4.4). The
// reconciler holds one and never assumes a concrete implementation, so
// the live rfc2136 backend (increment 2), a future Kea-D2 shim, and the
// test fakeUpdater are interchangeable.
//
// Both methods MUST be idempotent: UpsertLease is called every reconcile
// for every still-active lease, and DeleteLease may be retried.
type DNSUpdater interface {
	UpsertLease(ctx context.Context, rec LeaseDNSRecord) error
	DeleteLease(ctx context.Context, rec LeaseDNSRecord) error
}

// buildLeaseRecord constructs the forward+reverse record for an address +
// FQDN + TTL. ttl <= 0 falls back to defaultDDNSTTL. Returns an error for
// an invalid address so a malformed lease row never produces a record.
func buildLeaseRecord(fqdn, addr string, ttl int) (LeaseDNSRecord, error) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return LeaseDNSRecord{}, fmt.Errorf("ddns: invalid lease address %q: %w", addr, err)
	}
	a = a.Unmap()
	if ttl <= 0 {
		ttl = defaultDDNSTTL
	}
	rec := LeaseDNSRecord{
		FQDN:    fqdn,
		Addr:    a,
		TTL:     ttl,
		PTRName: reversePTRName(a),
	}
	if a.Is4() {
		rec.ForwardType = "A"
	} else {
		rec.ForwardType = "AAAA"
	}
	return rec, nil
}

// reversePTRName builds the reverse-DNS PTR name for an address.
//
// Byte-order note (plan §4.5): this is STRING manipulation on the textual
// address form, NOT the native-endian __be32 BPF-map convention. For IPv4
// the four decimal octets are reversed and suffixed .in-addr.arpa; for
// IPv6 the 32 nibbles (low-to-high) are reversed and suffixed .ip6.arpa.
// Deliberately independent of the dataplane byte-order habit — getting it
// "consistent with the map" would be wrong for DNS.
func reversePTRName(a netip.Addr) string {
	a = a.Unmap()
	if a.Is4() {
		o := a.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", o[3], o[2], o[1], o[0])
	}
	b := a.As16()
	// 32 nibbles, least-significant first.
	var sb strings.Builder
	sb.Grow(len(b)*4 + len("ip6.arpa"))
	for i := len(b) - 1; i >= 0; i-- {
		lo := b[i] & 0x0f
		hi := b[i] >> 4
		fmt.Fprintf(&sb, "%x.%x.", lo, hi)
	}
	sb.WriteString("ip6.arpa")
	return sb.String()
}
