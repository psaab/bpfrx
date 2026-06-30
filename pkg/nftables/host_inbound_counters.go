package nftables

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// HostInboundTableName is the kernel nftables table that enforces
// `security zones <z> host-inbound-traffic` (#3070). The Go control plane
// (pkg/daemon/daemon_nft.go) renders it via `nft -f -`; this package reads its
// named DROP counters back via netlink for the observability surface (#3361).
const HostInboundTableName = "xpf_hostinbound"

// hostInboundDenyCounterPrefix tags every named counter object attached to a
// host-inbound catch-all DROP rule so the metric scraper can pick our counters
// out of the table and ignore anything else.
const hostInboundDenyCounterPrefix = "xpfhi_"

// HostInboundDenyCounterName returns the deterministic nft named-counter object
// name attached to the catch-all host-inbound DROP rule for a given zone and
// family ("ip" or "ip6"). The kernel nft host-inbound chain drops host-bound
// traffic that no host-inbound-traffic service/protocol opened with an UNCOUNTED
// catch-all drop before #3361; attaching a named counter makes those drops
// scrapeable per zone/family.
//
// Encoding is xpfhi_<family>_<len>_<zone> where <zone> is the zone name passed
// through sanitizeNftIdentByte and <len> is its byte length. The length prefix
// makes the name unambiguously reversible by ParseHostInboundDenyCounterName
// even when the zone name itself contains '_' or '-' (both legal in a Junos zone
// name AND in a bare nft identifier), so the Prometheus collector recovers the
// zone/family labels straight from the kernel object name without re-deriving
// them from config. family is one of the two fixed tokens "ip"/"ip6" so the
// family/length boundary is never ambiguous.
//
// Sanitization (#3578): this name is emitted both as an nft counter REFERENCE
// (`counter name "<n>"`, which nft accepts quoted) AND as a counter DECLARATION
// (`counter <n> { }`, which nft v1.1.6 requires UNQUOTED — a quoted declaration
// is a hard syntax error). A bare nft identifier accepts only [A-Za-z0-9_.-];
// the Junos lexer additionally permits ':','+','*','%','=',',','<','>' (and '/',
// already rejected for zone names at commit) in a zone name, any of which would
// make the bare declaration fail to parse. sanitizeNftIdentByte maps every byte
// outside the bare-safe set to '_'. The mapping is length-preserving so the
// <len> prefix stays a valid reverse key, and it is the identity for the common
// zone-name set [A-Za-z0-9_.-] (so existing names/labels are unchanged). For a
// zone whose name needs sanitizing the recovered Prometheus label is the
// sanitized form; without sanitization that zone's ruleset would fail to apply
// entirely (no metric at all), so the sanitized label is strictly better.
func HostInboundDenyCounterName(zone, family string) string {
	z := sanitizeNftIdent(zone)
	return fmt.Sprintf("%s%s_%d_%s", hostInboundDenyCounterPrefix, family, len(z), z)
}

// sanitizeNftIdent maps a string to the byte set nft v1.1.6 accepts in a BARE
// identifier ([A-Za-z0-9_.-]), replacing every other byte with '_'. It is
// length-preserving and allocation-free when the input is already bare-safe.
// See HostInboundDenyCounterName for why declarations cannot be quoted (#3578).
func sanitizeNftIdent(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '-', c == '.':
			// safe in a bare nft identifier; leave as-is.
		default:
			if b == nil {
				b = []byte(s)
			}
			b[i] = '_'
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

// ParseHostInboundDenyCounterName reverses HostInboundDenyCounterName. It returns
// ok=false for any name that is not one of our host-inbound deny counters (wrong
// prefix, unknown family, or a length field that does not match the trailing
// zone), so the scraper silently skips foreign / malformed counter objects.
func ParseHostInboundDenyCounterName(name string) (zone, family string, ok bool) {
	rest, found := strings.CutPrefix(name, hostInboundDenyCounterPrefix)
	if !found {
		return "", "", false
	}
	fam, afterFam, found := strings.Cut(rest, "_")
	if !found || (fam != "ip" && fam != "ip6") {
		return "", "", false
	}
	lenTok, zoneTok, found := strings.Cut(afterFam, "_")
	if !found {
		return "", "", false
	}
	n, err := strconv.Atoi(lenTok)
	if err != nil || n != len(zoneTok) {
		return "", "", false
	}
	return zoneTok, fam, true
}

// HostInboundDenyCount is one zone/family host-inbound kernel-drop counter read
// from the `inet xpf_hostinbound` table.
type HostInboundDenyCount struct {
	Zone    string
	Family  string // "ip" or "ip6"
	Packets uint64
	Bytes   uint64
}

// ReadHostInboundDenyCounters reads the per-zone/family named catch-all DROP
// counters from the kernel `inet xpf_hostinbound` table via netlink (no nft
// shell-out). It returns one entry per host-inbound deny counter currently
// installed.
//
// When the table is absent (no host-inbound-traffic stanza is enforced, so the
// daemon removed it) the function returns (nil, nil): no enforcement means no
// denies, not an error. A genuine netlink failure is returned so the caller can
// surface "counter unavailable" rather than a misleading zero (the #3345
// missing-sample contract the Prometheus collector applies to dataplane
// counters).
//
// Counters reset to zero whenever the daemon rebuilds the table (every commit
// and every DHCP/DHCPv6 address change on a dataplane interface, which delete +
// recreate the table); this matches the table lifecycle and is handled by
// Prometheus rate() reset detection.
func ReadHostInboundDenyCounters() ([]HostInboundDenyCount, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables conn: %w", err)
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		return nil, fmt.Errorf("nftables list tables: %w", err)
	}
	var table *nftables.Table
	for _, t := range tables {
		if t != nil && t.Name == HostInboundTableName {
			table = t
			break
		}
	}
	if table == nil {
		// No host-inbound enforcement installed -> no denies.
		return nil, nil
	}
	objs, err := c.GetObjects(table)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		return nil, fmt.Errorf("nftables list objects %s: %w", HostInboundTableName, err)
	}
	var out []HostInboundDenyCount
	for _, o := range objs {
		co, ok := o.(*nftables.CounterObj)
		if !ok {
			continue
		}
		zone, family, ok := ParseHostInboundDenyCounterName(co.Name)
		if !ok {
			continue
		}
		out = append(out, HostInboundDenyCount{
			Zone:    zone,
			Family:  family,
			Packets: co.Packets,
			Bytes:   co.Bytes,
		})
	}
	return out, nil
}
