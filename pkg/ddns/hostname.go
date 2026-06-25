package ddns

import (
	"fmt"
	"strings"
)

// hostname.go (moved verbatim from pkg/dhcpserver/ddns_hostname.go in #2691
// P1a): deterministic hostname -> DNS-label normalization for
// the #1387 DHCP DDNS feature (plan §4.3). Pure functions, no I/O — the
// reconciler feeds a lease's offered name(s) and the configured policy in
// and gets back a validated FQDN (or an error for an unpublishable name).

const (
	// maxDNSLabel is the RFC 1035 single-label limit (octets).
	maxDNSLabel = 63
	// maxDNSName is the RFC 1035 total name limit (octets, including dots
	// but excluding the trailing root). 253 is the conventional textual
	// ceiling (255 wire bytes minus the leading length + trailing root).
	maxDNSName = 253
)

// hostnameSourceFor normalizes the configured hostname-source to one of
// the three supported modes, defaulting to client-hostname when unset or
// unrecognized (the schema validator already rejects unknown values at
// commit; this is the runtime belt-and-braces default).
func hostnameSourceFor(cfg *ddnsPolicy) string {
	switch cfg.hostnameSource {
	case "fqdn", "mac-fallback", "client-hostname":
		return cfg.hostnameSource
	default:
		return "client-hostname"
	}
}

// deriveFQDN builds the fully-qualified name to publish for a lease per
// the configured hostname-source and default domain. It returns an error
// (rather than a junk name) when no publishable label can be derived, so
// the reconciler simply skips that lease instead of polluting the zone.
//
//   - fqdn:            prefer the client-supplied FQDN; if absent fall
//     back to the host-name option + domain.
//   - client-hostname: use the host-name option + domain (default).
//   - mac-fallback:    as client-hostname, but synthesize dhcp-<id> from
//     the hardware/DUID identity when no name is offered.
//
// label sanitization (lower-case, [a-z0-9-], strip illegal chars, trim
// dashes, cap length) is applied to every derived label. An empty result
// after sanitization is an error.
func deriveFQDN(hostName, clientFQDN, identity, domain, source string) (string, error) {
	domain = sanitizeDomain(domain)

	switch source {
	case "fqdn":
		if clientFQDN != "" {
			return finalizeFQDN(clientFQDN, domain)
		}
		// fall through to host-name handling
	case "mac-fallback":
		if hostName == "" && clientFQDN == "" {
			lbl := sanitizeLabel("dhcp-" + identity)
			if lbl == "" {
				return "", fmt.Errorf("ddns: cannot synthesize mac-fallback label from identity %q", identity)
			}
			return joinLabelDomain(lbl, domain)
		}
	}

	name := hostName
	if name == "" {
		name = clientFQDN
	}
	if name == "" {
		return "", fmt.Errorf("ddns: lease offers no hostname (source=%s)", source)
	}
	return finalizeFQDN(name, domain)
}

// finalizeFQDN turns an offered name into a validated FQDN that is ALWAYS
// contained in the configured zone (plan §4.3 + the never-publish-outside-
// the-zone boundary). The client supplies the name; the firewall — not the
// client — decides the zone, so a dotted name can never let a client escape
// the configured domain:
//
//   - No domain configured: only the FIRST label of the offered name is
//     kept (a dotted name has no zone to be contained in, so we refuse to
//     publish the client-supplied suffix). The result is a bare label.
//   - Domain configured, dotted name already within the zone (its sanitized
//     form ends in ".<domain>" or equals the domain's host part): keep it
//     as-is (e.g. host.sub.example.com under example.com).
//   - Domain configured, dotted name OUTSIDE the zone (foreign TLD, trailing
//     dot escapes, double-dot, etc.): take only the FIRST sanitized label of
//     the offered name and re-append the configured domain, so the published
//     name is forced back inside the zone (relabel, never reject — a usable
//     name is still derived).
func finalizeFQDN(name, domain string) (string, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")

	// No configured zone: never honor a client-supplied dotted suffix.
	// Reduce to the first non-empty sanitized label.
	if domain == "" {
		lbl := firstSanitizedLabel(name)
		if lbl == "" {
			return "", fmt.Errorf("ddns: hostname %q sanitizes to empty label", name)
		}
		return joinLabelDomain(lbl, "")
	}

	if strings.Contains(name, ".") {
		// Sanitize the full dotted name, then enforce zone containment. A
		// name that does not land inside the configured domain is relabeled
		// to <first-label>.<domain> rather than published outside the zone.
		fqdn := sanitizeFQDN(name)
		if fqdn != "" && fqdnWithinDomain(fqdn, domain) {
			return fqdn, nil
		}
		lbl := firstSanitizedLabel(name)
		if lbl == "" {
			return "", fmt.Errorf("ddns: name %q sanitizes to empty", name)
		}
		return joinLabelDomain(lbl, domain)
	}

	lbl := sanitizeLabel(name)
	if lbl == "" {
		return "", fmt.Errorf("ddns: hostname %q sanitizes to empty label", name)
	}
	return joinLabelDomain(lbl, domain)
}

// fqdnWithinDomain reports whether the already-sanitized name is contained
// in the (already-sanitized) configured domain: either it equals the domain
// exactly (the zone apex) or it is a subdomain of it (ends in ".<domain>").
// Both inputs are lower-case sanitized LDH forms, so a plain suffix compare
// on label boundaries is sufficient and safe.
func fqdnWithinDomain(name, domain string) bool {
	if name == domain {
		return true
	}
	return strings.HasSuffix(name, "."+domain)
}

// firstSanitizedLabel returns the first label of a (possibly dotted) name
// that sanitizes to a non-empty LDH label, or "" if none do. This is the
// "take only the first label" zone-containment fallback: the client picks
// the host part, the firewall picks the zone.
func firstSanitizedLabel(name string) string {
	for _, p := range strings.Split(name, ".") {
		if s := sanitizeLabel(p); s != "" {
			return s
		}
	}
	return ""
}

// joinLabelDomain appends domain to a single label (when domain is set),
// enforcing the total-name length cap.
func joinLabelDomain(label, domain string) (string, error) {
	fqdn := label
	if domain != "" {
		fqdn = label + "." + domain
	}
	if len(fqdn) > maxDNSName {
		return "", fmt.Errorf("ddns: name %q exceeds %d octets", fqdn, maxDNSName)
	}
	return fqdn, nil
}

// sanitizeFQDN sanitizes every label of a dotted name and rejoins them,
// dropping labels that sanitize to empty.
func sanitizeFQDN(name string) string {
	parts := strings.Split(name, ".")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := sanitizeLabel(p)
		if s != "" {
			out = append(out, s)
		}
	}
	joined := strings.Join(out, ".")
	if len(joined) > maxDNSName {
		return ""
	}
	return joined
}

// sanitizeDomain sanitizes a default-domain suffix (dotted), returning ""
// for an empty/invalid domain so a bare label is published un-suffixed.
func sanitizeDomain(domain string) string {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return ""
	}
	return sanitizeFQDN(domain)
}

// sanitizeLabel lower-cases a single label, keeps only [a-z0-9-], drops
// every other rune, trims leading/trailing dashes, and caps the result
// at maxDNSLabel octets. The empty string signals an unusable label.
func sanitizeLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			// drop spaces, dots, underscores, and anything non-LDH
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > maxDNSLabel {
		out = strings.Trim(out[:maxDNSLabel], "-")
	}
	return out
}
