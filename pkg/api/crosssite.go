package api

import (
	"github.com/psaab/xpf/pkg/denyaudit"

	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// crosssite.go implements a Fetch-Metadata resource-isolation guard on the
// REST mutation surface (#5055).
//
// The HTTP API accepts HTTP Basic auth and advertises `WWW-Authenticate: Basic`
// (pkg/api/auth.go). Basic is an *ambient* browser credential: once a browser
// has been challenged, it reattaches the cached credentials to every request to
// that origin, including a cross-site `fetch(...,{credentials:'include'})` or a
// cross-site HTML `<form>` POST. The same-origin policy stops the attacker page
// from *reading* the response, but not from *sending* the side-effecting
// request — so a malicious page can drive a credentialed state change (config
// set/delete/commit, session clear, system reboot) with no operator intent. The
// loopback bind does not mitigate: the victim's own browser is the confused
// deputy. Header-based API-key / Bearer clients are NOT exposed — a cross-site
// page cannot set `Authorization: Bearer` or `X-API-Key` (they are not simple
// headers and are not reattached ambiently) — so this guard only ever rejects
// the browser-driven vector while leaving programmatic clients untouched.
//
// The guard runs on every non-safe (state-changing) method and rejects a
// request that shows cross-site provenance. Its signals, in order:
//
//   - Sec-Fetch-Site: a forbidden header the browser stamps and page JS cannot
//     forge. cross-site / same-site are rejected; same-origin (the management UI
//     itself) and none (a typed URL / bookmark) pass.
//   - Origin: browsers send it on cross-origin — and on same-origin POST —
//     requests. Rejected when present and its host:port differs from the target.
//   - Referer: fallback for a browser that suppresses Origin; rejected only when
//     present and cross-host (referrer-policy may strip it, so absence is no
//     signal).
//   - Content-Type: a cross-site `<form>` or a `no-cors` fetch can only produce
//     the CORS "simple" content types. A JSON API mutation is always
//     application/json (or has no body), so the three simple form types are
//     rejected — this blocks a credentialed cross-site form POST even on a
//     browser old enough to send neither Sec-Fetch-Site nor Origin.
//
// A non-browser client (curl, the CLI, a Prometheus-style scraper) sends none of
// Sec-Fetch-Site / Origin / Referer and uses Content-Type application/json (or
// an empty body), so it passes every check. Requiring application/json for the
// three simple types is exactly the "non-simple content type a cross-site form
// can't set" defense the issue calls for, without a stateful CSRF token.

// isSafeHTTPMethod reports whether method is a read-only ("safe") HTTP method
// that never changes server state and so is not cross-site guarded.
func isSafeHTTPMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// mutationCrossSiteGuard wraps next so that every state-changing request
// (non-safe HTTP method) carrying cross-site provenance is rejected with 403
// before it reaches a handler (#5055). Safe methods pass through untouched.
func mutationCrossSiteGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeHTTPMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if reason, reject := crossSiteRejectReason(r); reject {
			// #9042: unbounded per-request on the REST surface, and the
			// remote address was in the record -- so an attacker both paced
			// the line and chose part of its content. Keyed on the REASON,
			// which is a bounded set: keying on the remote address would let
			// one source spread a flood across every bucket and defeat the
			// limiter, which is the failure mode a per-key limiter invites
			// when the key is attacker-supplied.
			if emit, suppressed := denyaudit.Note(denyaudit.SurfaceRESTCrossSite, reason); emit {
				slog.Warn("api: rejected cross-site mutation request",
					"method", r.Method, "path", r.URL.Path,
					"reason", reason, "remote", r.RemoteAddr,
					"suppressed_since_last", suppressed,
					"denials_total", denyaudit.Total(denyaudit.SurfaceRESTCrossSite))
			} else {
				slog.Debug("api: rejected cross-site mutation request",
					"method", r.Method, "path", r.URL.Path,
					"reason", reason, "remote", r.RemoteAddr)
			}
			writeError(w, http.StatusForbidden, "cross-site request forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// crossSiteRejectReason reports the first cross-site signal that disqualifies a
// mutation request, or ("", false) when the request is same-origin /
// programmatic and may proceed. See the file comment for the policy.
func crossSiteRejectReason(r *http.Request) (string, bool) {
	// (a) Sec-Fetch-Site — unforgeable browser signal.
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "cross-site", "same-site":
		return "sec-fetch-site=" + strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))), true
	}

	// (b) Origin host must match the target.
	//
	// #8597 (muse-004 K89): there is no `null` carve-out, and there was one.
	// `Origin: null` is precisely what a browser sends from the contexts an
	// attacker controls — a sandboxed iframe (`sandbox` without
	// `allow-same-origin`), a `data:` or `file:` document, and a cross-origin
	// redirect — so exempting it turned this check off for exactly the
	// provenance it exists to detect. It also contradicted this file's own
	// stated policy three paragraphs up: "Origin ... Rejected when present and
	// its host:port differs from the target". `null` differs from every host.
	//
	// Failing closed costs nothing reachable: `sameHostAs("null", host)` parses
	// to an empty host and returns false, a non-browser client (curl, the CLI, a
	// scraper) sends no Origin header at all and is unaffected, and the
	// management UI is same-origin. The only requests this newly rejects are the
	// ones whose provenance is a sandboxed or opaque context.
	if origin := r.Header.Get("Origin"); origin != "" {
		if !sameHostAs(origin, r.Host) {
			return "origin-mismatch", true
		}
	}

	// (c) Referer host must match when present.
	if ref := r.Header.Get("Referer"); ref != "" {
		if !sameHostAs(ref, r.Host) {
			return "referer-mismatch", true
		}
	}

	// (d) Reject the CORS "simple" form content types. application/json and an
	// absent content type both pass, so empty-body programmatic mutations stay
	// callable. An unparseable content type is left to the browser signals above
	// rather than rejected here (a real JSON client never sends one).
	if ct := r.Header.Get("Content-Type"); ct != "" {
		if mediaType, _, err := mime.ParseMediaType(ct); err == nil {
			switch mediaType {
			case "application/x-www-form-urlencoded", "multipart/form-data", "text/plain":
				return "simple-content-type=" + mediaType, true
			}
		}
	}

	return "", false
}

// sameHostAs reports whether rawURL (an Origin or Referer value) has the same
// host:port as the request's Host header. A parse failure or an empty host is a
// mismatch (fail-closed). Scheme is ignored: the Host header carries none, and
// an http/https flip to the same host:port is not the cross-site concern this
// guard addresses.
func sameHostAs(rawURL, host string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}
