package appid

import (
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// CatalogEntry is one application's L3/L4 classification rule, carrying the
// numeric app_id that the dataplane stamps on a matching session. One config
// application can expand to multiple entries (e.g. an omitted protocol means
// "TCP or UDP", which yields one entry per protocol) but every expansion shares
// the same AppID and Name.
//
// Port boundaries are inclusive. A zero DstPortLow/DstPortHigh pair (the
// default for a protocol-only application such as ICMP) means "no destination
// port constraint" — the entry matches on protocol alone. SrcPortLow/High of 0
// means "no source-port constraint".
type CatalogEntry struct {
	Name        string
	AppID       uint16
	Protocol    uint8
	DstPortLow  uint16
	DstPortHigh uint16
	SrcPortLow  uint16
	SrcPortHigh uint16
}

// Catalog is the ordered application catalog plus the app_id -> name index. The
// AppNames map is the SAME map shape that pkg/dataplane's compileApplications
// builds (CompileResult.AppNames) and that pkg/appid.ResolveSessionName
// consumes when resolving a session's app_id back to a name. Both are derived
// from CatalogNames in the identical sorted order with IDs assigned from 1, so
// an app_id stamped by the dataplane resolves to the same name the show path
// reports.
type Catalog struct {
	Entries  []CatalogEntry
	AppNames map[uint16]string
}

// BuildCatalog produces the ordered application catalog for a config. The id
// assignment MUST stay in lock-step with pkg/dataplane.compileApplications:
// names come from CatalogNames(cfg, ApplicationIdentification), sorted, with
// app_id assigned sequentially from 1. The id<->name correspondence is kept
// byte-identical to pkg/dataplane/compiler.go's AppNames assignment, which is
// what ResolveSessionName consumes. That compiler records AppNames[appID]=name
// BEFORE parsing the destination port, then on a bad/unresolvable port simply
// `continue`s — SKIPPING the loop-tail appID++ — so a malformed application
// does NOT consume an id slot (the next good application overwrites the same
// id). This builder mirrors that exactly: record the name, then on a bad port
// `continue` WITHOUT bumping appID. (Bumping was the #2065-review divergence.)
func BuildCatalog(cfg *config.Config) (Catalog, error) {
	cat := Catalog{AppNames: map[uint16]string{}}
	if cfg == nil {
		return cat, nil
	}

	names, err := CatalogNames(cfg, cfg.Services.ApplicationIdentification)
	if err != nil {
		return cat, err
	}

	userApps := cfg.Applications.Applications
	appID := uint16(1)
	for _, name := range names {
		app, found := config.ResolveApplication(name, userApps)
		if !found {
			// compileApplications hard-errors here; the snapshot builder must
			// not abort the whole apply over one stray name, so skip it and do
			// NOT consume an id slot (compileApplications would have failed the
			// commit before producing AppNames at all, so there is no id to
			// keep in step with).
			continue
		}

		cat.AppNames[appID] = name

		proto := catalogProtocolNumber(app.Protocol)

		dstLow, dstHigh, derr := parsePortRange(app.DestinationPort)
		if derr != nil {
			// Mirror the compiler EXACTLY (pkg/dataplane/compiler.go): on a
			// bad destination port it slog.Warns and `continue`s, which SKIPS
			// the loop-tail appID++. The name was already recorded at this id
			// above, but the id is NOT consumed — the next good application
			// overwrites this same id. So do NOT bump appID here; emit no
			// catalog entry for the unparsable port and fall through to the
			// next name. (Bumping here is the #2065-review bug: it would shift
			// every subsequent id by one vs CompileResult.AppNames, so the
			// Rust-stamped app_id would resolve to the wrong name.)
			continue
		}

		var srcLow, srcHigh uint16
		if app.SourcePort != "" {
			// A bad source-port is non-fatal in compileApplications (it warns
			// and proceeds with zero bounds); do the same.
			srcLow, srcHigh, _ = parsePortRange(app.SourcePort)
		}

		// Omitted protocol means "any L4"; compileApplications installs both
		// TCP and UDP entries (ICMP is excluded from that fan-out).
		protos := []uint8{proto}
		if proto == 0 && app.Protocol != "icmp" {
			protos = []uint8{6, 17}
		}
		for _, p := range protos {
			cat.Entries = append(cat.Entries, CatalogEntry{
				Name:        name,
				AppID:       appID,
				Protocol:    p,
				DstPortLow:  dstLow,
				DstPortHigh: dstHigh,
				SrcPortLow:  srcLow,
				SrcPortHigh: srcHigh,
			})
		}
		appID++
	}

	return cat, nil
}

// catalogProtocolNumber mirrors pkg/dataplane.protocolNumber so the catalog's
// protocol byte matches what the legacy compiler used. Kept private to pkg/appid
// to avoid an import cycle with pkg/dataplane.
func catalogProtocolNumber(name string) uint8 {
	switch strings.ToLower(name) {
	case "tcp", "junos-tcp-any":
		return 6
	case "udp", "junos-udp-any":
		return 17
	case "icmp", "junos-icmp-all", "junos-ping":
		return 1
	case "icmpv6", "icmp6", "junos-icmp6-all", "junos-pingv6":
		return 58
	case "gre", "junos-gre":
		return 47
	case "ospf", "junos-ospf":
		return 89
	case "junos-ip-in-ip", "junos-ipip", "ipip":
		return 4
	case "egp":
		return 8
	case "igmp":
		return 2
	case "pim":
		return 103
	case "ah":
		return 51
	case "esp":
		return 50
	case "sctp":
		return 132
	case "vrrp":
		return 112
	default:
		if n, err := strconv.Atoi(name); err == nil && n > 0 && n < 256 {
			return uint8(n)
		}
		return 0
	}
}

// parsePortRange mirrors pkg/dataplane.parsePortRange. Inclusive boundaries;
// empty spec means no constraint (0,0).
func parsePortRange(spec string) (uint16, uint16, error) {
	if spec == "" {
		return 0, 0, nil
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		low, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return 0, 0, err
		}
		high, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return 0, 0, err
		}
		return uint16(low), uint16(high), nil
	}
	port, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return 0, 0, err
	}
	return uint16(port), uint16(port), nil
}
