package appid

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// maxCatalogAppID is the largest assignable application id. app_id is a uint16
// on the Rust wire (userspace-dp/src/protocol/security.rs) where 0 is the
// reserved "unknown" sentinel, so real applications take ids 1..65535 (#3438).
const maxCatalogAppID = 65535

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
	// #3438 H4: app_id is a uint16 on the Rust wire with 0 reserved as the
	// unknown sentinel, so the assignable id space is 1..65535. nextID is a
	// uint32 working counter precisely so it CANNOT silently wrap a uint16 past
	// 65535 back onto 0 (the reserved sentinel) — the boundary check below
	// rejects a config that would need a 65536th id deterministically instead.
	nextID := uint32(1)
	for _, name := range names {
		if nextID > maxCatalogAppID {
			return cat, fmt.Errorf("application catalog exceeds %d entries: assigning app_id to %q would overflow the uint16 app_id space (0 is the reserved unknown sentinel); reduce the number of referenced applications", maxCatalogAppID, name)
		}
		appID := uint16(nextID)
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
		nextID++
	}

	return cat, nil
}

// ProtocolNumber is the single source of truth (#2124) for resolving an IANA
// protocol name, a Junos predefined-protocol alias, or a numeric string to its
// IANA protocol number. It is the centralized replacement for the formerly
// duplicated tables in pkg/appid (catalogProtocolNumber) and pkg/dataplane
// (protocolNumber); both now delegate here so the userspace policy capability
// gate, the legacy compiler, and the app-identification catalog agree on
// exactly which protocols are representable.
//
// ok=false means the token is neither a known name/alias nor a valid 0..255
// numeric. Crucially, the deliberate "protocol 0" (HOPOPT) resolves to
// (0, true) — distinct from the unrepresentable (0, false) case — so callers
// that fail closed on unrepresentable protocols (#2124 Layer G) do not also
// reject a legitimate "protocol 0".
//
// pkg/appid is a leaf package (imports only pkg/config), so housing the helper
// here keeps it importable by both pkg/dataplane (which already imports
// pkg/appid) and pkg/dataplane/userspace without an import cycle.
func ProtocolNumber(name string) (uint8, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "tcp", "junos-tcp-any":
		return 6, true
	case "udp", "junos-udp-any":
		return 17, true
	case "icmp", "junos-icmp-all", "junos-ping":
		return 1, true
	case "icmpv6", "icmp6", "junos-icmp6-all", "junos-pingv6":
		return 58, true
	case "gre", "junos-gre":
		return 47, true
	case "ospf", "junos-ospf":
		return 89, true
	case "junos-ip-in-ip", "junos-ipip", "ipip":
		return 4, true
	case "ipv6":
		// IANA protocol 41 (IPv6 encapsulation). This is the reverse of
		// ProtocolName(41)=="ipv6" — added in #3393 so the canonical
		// display name round-trips through the SSOT. ProtocolName renders
		// it, so it must parse back to the same number.
		return 41, true
	case "egp":
		return 8, true
	case "igmp":
		return 2, true
	case "pim":
		return 103, true
	case "ah":
		return 51, true
	case "esp":
		return 50, true
	case "sctp":
		return 132, true
	case "vrrp":
		return 112, true
	default:
		// Numeric protocol number, including the deliberate "0" (HOPOPT).
		if n, err := strconv.Atoi(strings.TrimSpace(name)); err == nil && n >= 0 && n < 256 {
			return uint8(n), true
		}
		return 0, false
	}
}

// ProtocolNumberLenient resolves an operator protocol-FILTER token (a
// name, alias, or numeric 0-255) to its IP protocol number for the
// session-inspection surfaces. It accepts everything ProtocolNumber
// resolves PLUS any display-only name that ProtocolName renders but
// ProtocolNumber does not reverse.
//
// Since #3393 closed the strict round-trip (every name ProtocolName
// emits — including "ipv6"=41 — now reverses through ProtocolNumber), the
// ProtocolName reverse-scan below is a belt-and-suspenders backstop rather
// than a behavioral difference: for the current tables this function is
// equal to ProtocolNumber. It is retained as a stable seam for the filter
// callers (cmd/cli, gRPC session filters) so that if ProtocolName ever
// gains a render-only name ahead of its ProtocolNumber reverse, the
// read/filter side still accepts the name the system displays rather than
// rejecting it as an invalid filter.
func ProtocolNumberLenient(name string) (uint8, bool) {
	if n, ok := ProtocolNumber(name); ok {
		return n, true
	}
	t := strings.ToLower(strings.TrimSpace(name))
	if t == "" {
		return 0, false
	}
	// ProtocolName is the display SSOT; accept any token it can render.
	for p := 0; p < 256; p++ {
		if ProtocolName(uint8(p)) == t {
			return uint8(p), true
		}
	}
	return 0, false
}

// ProtocolName is the single source of truth for rendering an IP protocol
// number as a canonical lowercase protocol name. It returns "" for a
// protocol that has no display name here, letting callers fall back to the
// numeric form.
//
// This renders the named protocol set the operator surfaces have
// historically displayed (matching the prior gRPC switch); it is NOT a
// complete inverse of ProtocolNumber. ProtocolNumber resolves additional
// protocols (ospf/egp/igmp/pim/ah/sctp/vrrp/...) that have no display
// mapping here. But the converse round-trip DOES hold for the entire set
// ProtocolName renders: every name it returns parses back to the same
// number, i.e. ProtocolNumber(ProtocolName(p)) == p for every p with a
// display name. #3393 closed the last gap — ProtocolName(41)=="ipv6" now
// reverses through ProtocolNumber("ipv6")==41, so a rendered protocol name
// re-parses safely (no accepted-but-never-matches / mislabel for proto 41).
//
// This is the SSOT for the named-protocol set rendered by every operator
// surface (REST pkg/api, gRPC pkg/grpcapi). Before #2949 each surface kept its
// own switch: REST rendered only tcp/udp/icmp/icmpv6 while gRPC also rendered
// gre/esp/ipip/ipv6, so a REST `protocol=gre` NAMED filter silently failed to
// match and a GRE/ESP session displayed numeric on REST but named on gRPC.
// Housing the table here (a leaf package importing only pkg/config) keeps the
// REST and gRPC name sets identical from one definition.
//
// Casing is a per-surface concern, not part of this SSOT: REST upper-cases the
// result to preserve its historical TCP/UDP/ICMP display; gRPC uses the
// lowercase form directly. The named SET (which protocols are named at all) is
// identical across surfaces.
func ProtocolName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 4:
		return "ipip"
	case 41:
		return "ipv6"
	default:
		return ""
	}
}

// catalogProtocolNumber resolves a protocol to its byte for the app-id catalog,
// returning 0 for an unrepresentable token (the catalog's historical
// "unknown -> 0" behavior). Delegates to ProtocolNumber (#2124) so the catalog
// and the capability gate share one table.
func catalogProtocolNumber(name string) uint8 {
	n, _ := ProtocolNumber(name)
	return n
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
