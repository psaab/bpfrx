package dhcpserver

import (
	"fmt"
	"strings"
)

// ddns_hostname.go: deterministic hostname -> DNS-label normalization for
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

// finalizeFQDN turns an offered name into a validated FQDN: if it already
// contains a dot it is treated as fully qualified (each label sanitized);
// otherwise the configured domain is appended.
func finalizeFQDN(name, domain string) (string, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if strings.Contains(name, ".") {
		fqdn := sanitizeFQDN(name)
		if fqdn == "" {
			return "", fmt.Errorf("ddns: name %q sanitizes to empty", name)
		}
		return fqdn, nil
	}
	lbl := sanitizeLabel(name)
	if lbl == "" {
		return "", fmt.Errorf("ddns: hostname %q sanitizes to empty label", name)
	}
	return joinLabelDomain(lbl, domain)
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
