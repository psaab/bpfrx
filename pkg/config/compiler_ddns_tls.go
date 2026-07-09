package config

import "strings"

// ddnsBackendCarriesCredentials reports whether an HTTP DDNS backend attaches
// credentials to its update requests — Basic auth (dyndns2/generic), a query or
// bearer token (DuckDNS/Cloudflare), or SigV4 (Route 53). Such a backend must
// only ever talk to an https:// endpoint (#4861); an rfc2136 backend (DNS, not
// HTTP) and an unknown backend are false. For the generic templated backend the
// credential may be Basic auth or an inadyn %u/%p specifier embedded in the
// url-template.
func ddnsBackendCarriesCredentials(p *DDNSProvider) bool {
	switch p.Backend {
	case "dyndns2":
		return p.Username != "" || p.Password.Reveal() != ""
	case "duckdns", "cloudflare":
		return p.APIToken.Reveal() != ""
	case "route53":
		return p.AWSAccessKeyID != "" || p.AWSSecretAccessKey.Reveal() != ""
	case "generic":
		return p.Username != "" || p.Password.Reveal() != "" ||
			strings.Contains(p.URLTemplate, "%u") || strings.Contains(p.URLTemplate, "%p")
	}
	return false
}

// ddnsPlaintextCredentialEndpoint reports the operator-supplied endpoint field
// (server / url-template) and value when a CREDENTIALED HTTP DDNS backend is
// configured with an explicit non-https scheme (#4861). A bare host with no
// scheme is fine — every HTTP backend composes it over https — so only an
// explicit http:// (or any non-https scheme) endpoint that would carry the
// credential in cleartext is flagged. Returns bad=false for a non-credentialed
// backend or an https/empty/bare endpoint.
//
// Scheme extraction is the substring before "://" compared case-insensitively
// (RFC 3986 §3.1), string-based rather than url.Parse-based because a generic
// url-template legitimately embeds %h/%i/%u/%p specifiers (and a userinfo
// credential) that make url.Parse mangle or reject the value — the same reason
// validateGenericURLTemplate is string-based.
func ddnsPlaintextCredentialEndpoint(p *DDNSProvider) (field, value string, bad bool) {
	if !ddnsBackendCarriesCredentials(p) {
		return "", "", false
	}
	check := func(field, s string) (string, string, bool) {
		s = strings.TrimSpace(s)
		if s == "" {
			return "", "", false
		}
		i := strings.Index(s, "://")
		if i < 0 {
			// Bare host (no scheme) → composed over https by the backend.
			return "", "", false
		}
		if !strings.EqualFold(s[:i], "https") {
			return field, s, true
		}
		return "", "", false
	}
	if f, v, b := check("server", p.Server); b {
		return f, v, true
	}
	if p.Backend == "generic" {
		if f, v, b := check("url-template", p.URLTemplate); b {
			return f, v, true
		}
	}
	return "", "", false
}
