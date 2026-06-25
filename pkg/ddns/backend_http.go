package ddns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// backend_http.go: shared discipline for the HTTP-API DDNS backends (#2691 P3,
// plan §5.2/§8.1/§8.3). The dyndns2, Cloudflare, Route 53, and generic-templated
// backends all implement the SAME DNSUpdater interface the RFC 2136 backend does
// (UpsertLease / DeleteLease over a LeaseDNSRecord) so the Surface A engine
// drives them identically — change-detection, forced-refresh, per-RG HA gate,
// and flat error backoff all apply unchanged. Only the wire mechanism differs.
//
// Security / ban-avoidance discipline shared here (plan §8.1/§8.3):
//   - HTTPS with the system trust store; certificate + hostname verification
//     stays ON (no InsecureSkipVerify) — the inadyn secure-ssl default-on posture.
//   - bounded request timeout (no infinite hang) so a stuck provider can never
//     wedge the reconcile loop.
//   - the response body is read with an io.LimitReader cap so a hostile/buggy
//     provider cannot OOM the daemon.
//   - credentials come from config.Secret (Reveal() only at the transport
//     boundary); no secret is ever placed in an error string or a log line.

// httpClientTimeout bounds a single provider request. The Surface A engine's own
// per-pass timeout is 60s (daemon surfaceAReconcileTimeout); a per-request floor
// well under that lets a slow provider fail one scope without starving the pass.
const httpClientTimeout = 15 * time.Second

// httpMaxResponseBody caps how many bytes of a provider response we read. dyndns2
// replies are a few bytes ("good 203.0.113.5\n"); Cloudflare/Route53 JSON/XML
// replies are a few KB. 64 KiB is generous and OOM-safe.
const httpMaxResponseBody = 64 << 10

// errHTTPAuth is a hard, non-retryable auth/abuse failure (dyndns2
// badauth/abuse/!donator, HTTP 401/403). The engine's flat backoff treats every
// error the same (back off, never crash), but classifying it lets the backend
// log a single clear message and stops a publish from being silently retried as
// if transient. Wrapped, never bare, so callers can errors.Is it.
var errHTTPAuth = errors.New("ddns http: authentication/authorization refused")

// errHTTPRateLimited marks a provider rate-limit / throttle response (dyndns2
// 911/dnserr, HTTP 429). The engine backs off; this lets the backend log it as
// a ban-avoidance signal rather than a generic failure.
var errHTTPRateLimited = errors.New("ddns http: provider rate-limited")

// newHTTPClient builds the shared, hardened HTTP client for every HTTP backend.
// TLS verification is ON; the timeout is bounded. Exposed (not a package var) so
// each backend gets its own client with no shared mutable state, and tests can
// point Transport at an httptest server.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: httpClientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// InsecureSkipVerify deliberately left false: certificate +
				// hostname verification against the system trust store.
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}
}

// readCappedBody reads at most httpMaxResponseBody bytes of a response body and
// closes it. A provider that streams an unbounded body is truncated, never
// allowed to exhaust memory.
func readCappedBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, httpMaxResponseBody))
}

// doRequest issues one request against the backend's client with the reconcile
// context attached (so a pass timeout / shutdown cancels in-flight I/O) and
// returns the status code + the capped body. The caller classifies the verdict.
func doRequest(ctx context.Context, client *http.Client, req *http.Request) (int, []byte, error) {
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		// SECURITY: client.Do returns a *url.Error whose Error() string embeds the
		// FULL request URL — including the query, which for the generic backend
		// carries the %p-expanded password. Scrub it to the transport error class
		// + a query-stripped URL so no secret reaches a log/error string.
		return 0, nil, fmt.Errorf("ddns http: request failed: %s", scrubURLError(err))
	}
	body, rerr := readCappedBody(resp)
	if rerr != nil {
		return resp.StatusCode, nil, fmt.Errorf("ddns http: read response: %w", rerr)
	}
	return resp.StatusCode, body, nil
}

// scrubURLError renders an HTTP-client error without leaking secrets carried in
// the request URL's userinfo/query. A *url.Error embeds the full URL in its
// Error() string; we replace it with the same URL stripped of userinfo and query
// (the host+path are not sensitive). Any other error is returned verbatim (it
// never carries the URL).
func scrubURLError(err error) string {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err.Error()
	}
	safe := ue.URL
	if u, perr := url.Parse(ue.URL); perr == nil {
		u.RawQuery = ""
		u.User = nil
		safe = u.Redacted()
	}
	return fmt.Sprintf("%s %q: %v", ue.Op, safe, ue.Err)
}

// queryEscape URL-query-escapes a value for safe insertion into a generic
// template URL (%u/%p/%h/%i expansion).
func queryEscape(s string) string { return url.QueryEscape(s) }

// classifyHTTPStatus maps a transport-level HTTP status (used by the
// JSON/SigV4 backends — Cloudflare/Route53) to a typed error. 2xx is success
// (nil). It is NOT used by dyndns2/generic, which classify by BODY content (the
// dyndns2 protocol returns 200 + a status keyword in the body).
func classifyHTTPStatus(code int) error {
	switch {
	case code >= 200 && code < 300:
		return nil
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return errHTTPAuth
	case code == http.StatusTooManyRequests:
		return errHTTPRateLimited
	default:
		return fmt.Errorf("ddns http: unexpected status %d", code)
	}
}
