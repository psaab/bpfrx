// render_validate.go holds the render-side value-sanitization and
// validation belt: it keeps a leniently-loaded / peer-synced / rolled-back
// malformed value (router-id, cluster-id, BGP origin, or a free-text
// field carrying an embedded newline) out of the generated frr.conf so a
// single bad token can neither inject commands nor fail the whole managed
// frr-reload. Commit-time validation stays strict in pkg/config; this is
// defense-in-depth for the tolerant load / no-brick paths.
//
// Split out of policy_render.go (#6424) as a pure code-motion refactor;
// the emitted frr.conf is byte-identical.
//
// Symbols:
//   - sanitizeFRRValue
//   - validRouterID, validClusterID, validBGPOrigin
package frr

import (
	"net"
	"strconv"
)

// sanitizeFRRValue strips ASCII control characters — the C0 set
// (0x00-0x1F, including newline) and DEL (0x7F), each replaced by a
// space — from a free-text config value (description, auth key,
// password, BGP community member, AS-path regex) before it is
// interpolated into a generated frr.conf line. Render-side belt for
// #1798 / #4097: a BGP neighbor description, auth key, community-list
// member, or as-path-access-list regex containing an embedded newline
// must not be able to inject extra frr.conf commands even if the
// commit-time validation layer were bypassed (a leniently-loaded /
// peer-synced / rolled-back stored value re-parses through the same
// lexer, which materializes a `\n` escape into a real newline byte).
// Collapsing the newline to a space keeps the whole value on the single
// rendered line, so no injected `router bgp` / `neighbor` command
// reaches the managed section. A single SPACE (0x20) is preserved: an
// FRR `bgp as-path access-list ... permit LINE` and an expanded
// `bgp community-list expanded ... permit LINE` take the regex as a
// rest-of-line token, so a space inside the regex is legitimate (unlike
// a whitespace-split auth secret, which frrTokenUnsafeIndex also rejects
// at commit).
func sanitizeFRRValue(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] < 0x20 || b[i] == 0x7f {
			b[i] = ' '
		}
	}
	return string(b)
}

// validRouterID reports whether a router-id is a valid 32-bit IPv4
// dotted-quad. FRR/vtysh requires an IPv4 router-id for ALL routing
// protocols (including the IPv6 protocols OSPFv3 and BGP) and rejects
// anything else, failing the whole frr-reload. This is the render-side
// defense-in-depth for #2980: commit-time validation
// (validateRouterIDStrict, pkg/config) hard-rejects a bad router-id, but
// the tolerant load / peer-sync paths only warn (#1960 no-brick), so the
// renderer must keep a leniently-loaded malformed router-id out of frr.conf
// entirely. Empty is intentionally invalid here (the caller already gates
// on != "" and an empty value is omitted so FRR auto-derives the router-id).
func validRouterID(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// validClusterID reports whether a BGP route-reflector cluster-id is one of
// the two forms FRR/vtysh's `bgp cluster-id <A.B.C.D | (1-4294967295)>` grammar
// accepts: an IPv4 dotted-quad or a 32-bit unsigned integer in 1..4294967295.
// Render-side defense-in-depth for #4919: `protocols bgp cluster-id` is stored
// verbatim, so a tolerant-load / peer-synced / rolled-back config may carry a
// malformed value (e.g. `not.an.ip`, an IPv6 literal, or an embedded-newline
// injection). FRR rejects anything else and fails the whole frr-reload, so the
// renderer must keep a leniently-loaded bad cluster-id out of frr.conf
// entirely. Commit / commit-check stay strict (config.ValidateBGPClusterID).
// Mirrors validRouterID; the accept set matches ValidateBGPClusterID exactly.
func validClusterID(s string) bool {
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() != nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	return err == nil && v >= 1
}

// validBGPOrigin reports whether a route-map `then origin` value is one of the
// three tokens FRR's `set origin <egp|igp|incomplete>` grammar accepts.
// Render-side belt for #4919: `then origin` is stored verbatim and was only
// control-char sanitized (#4498), so a non-control typo (`igpp`) or a
// leniently-loaded / peer-synced bad value reached FRR and failed the route-map
// grammar, stalling the reload. Skipping an invalid origin (fail-closed) keeps
// it out of frr.conf; commit-check stays strict (schema ValidateEnum).
func validBGPOrigin(s string) bool {
	switch s {
	case "igp", "egp", "incomplete":
		return true
	}
	return false
}
