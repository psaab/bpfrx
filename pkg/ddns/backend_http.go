package ddns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
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

// httpDialTimeout bounds a single TCP connect on a bound HTTP client (#2846).
// Well under httpClientTimeout so a black-holed source bind fails the connect
// (and the pass) promptly rather than consuming the whole request budget.
const httpDialTimeout = 10 * time.Second

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

// newHTTPClient builds the shared, hardened HTTP client for every HTTP backend
// with NO source binding (the default route / kernel-chosen source). TLS
// verification is ON; the timeout is bounded. Exposed (not a package var) so each
// backend gets its own client with no shared mutable state, and tests can point
// Transport at an httptest server.
func newHTTPClient() *http.Client {
	return newHTTPClientBound(bindConfig{})
}

// newHTTPClientBound builds the same hardened HTTP client but applies the
// provider's transport source binding (source-address / destination-interface /
// routing-instance, #2846) to the dial — so Cloudflare/Route53/dyndns2/generic
// updates and external checkip probes egress from the operator-configured source
// IP / interface / VRF, matching the RFC 2136 backend (backend_bind.go).
//
// When the bindConfig requests no binding (the zero value) the Transport gets no
// DialContext override and behaves byte-for-byte like the unbound client — the
// default-route behaviour for an operator who never set a source-address.
//
// The bind reuses backend_bind.go's dialer(): a single Dialer.Control hook that
// does unix.Bind(source-address) + SO_BINDTODEVICE(interface/VRF). For HTTP we
// expose it via Transport.DialContext (the dialer is connection-typed "tcp" for
// HTTP, so the Control-based bind — not a network-typed LocalAddr — is what keeps
// it working across both families uniformly). httpDialTimeout bounds the connect.
func newHTTPClientBound(b bindConfig) *http.Client {
	tr := &http.Transport{
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
	}
	if d := b.dialer(httpDialTimeout); d != nil {
		tr.DialContext = d.DialContext
	}
	return &http.Client{
		Timeout:   httpClientTimeout,
		Transport: tr,
	}
}

// httpClientCache caches the hardened *http.Client (and its underlying
// *http.Transport keep-alive connection pool) per distinct source-binding so the
// Surface A reconcile loop does not throw away the pool every pass (#2904). The
// Surface A engine rebuilds the lightweight backend OBJECT every reconcile
// (resolve-per-Reconcile, #2691) — that is cheap — but each rebuild previously
// called newProviderHTTPClient, which allocated a fresh http.Transport with its
// own (empty) connection pool. Every ~30s checkip probe and DNS update then paid
// a full TCP + TLS handshake from scratch (wasted CPU, added latency, ephemeral
// port churn).
//
// The cache key is the provider's source-binding inputs ONLY (source-address /
// destination-interface / routing-instance). Two providers that egress from the
// same source share one transport (correct: a transport's pool is keyed on the
// destination host:port, so cross-provider reuse only ever connects to the host
// the request actually targets). The client carries no provider credential or
// URL — those live on the backend object and are applied per-request — so it is
// safe to share. The cache invalidates implicitly: when an operator changes a
// binding leaf on commit the next reconcile resolves a NEW key and builds (and
// caches) a fresh bound transport; the stale entry is simply no longer looked
// up. Cardinality is bounded by the number of distinct configured bindings, so
// the map does not grow without bound.
type httpClientCache struct {
	mu      sync.Mutex
	clients map[string]*http.Client
}

// newHTTPClientCache builds an empty per-binding client cache.
func newHTTPClientCache() *httpClientCache {
	return &httpClientCache{clients: map[string]*http.Client{}}
}

// bindCacheKey is the stable cache key for a provider's source binding. It is
// derived from the RAW config leaves (not the resolved bindConfig) so a commit
// that changes any binding leaf yields a different key and forces a rebuild. A
// nil provider keys to the unbound default (empty key).
func bindCacheKey(p *config.DDNSProvider) string {
	if p == nil {
		return ""
	}
	// NUL-separated so distinct field boundaries cannot collide (an interface
	// named "a" + VRF "b" must not key the same as interface "a\x00b").
	return p.SourceAddress + "\x00" + p.DestinationInterface + "\x00" + p.RoutingInstance
}

// clientFor returns the cached bound *http.Client for the provider's source
// binding, building and caching it on first use. The bind-resolution error (a
// malformed source-address) is returned alongside the UNBOUND default client
// (fail-open, matching newProviderHTTPClient); the error path is NOT cached so a
// corrected source-address on the next commit rebuilds cleanly.
func (c *httpClientCache) clientFor(p *config.DDNSProvider) (*http.Client, error) {
	b, err := resolveProviderBindConfig(p)
	if err != nil {
		return newHTTPClient(), err
	}
	key := bindCacheKey(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl, ok := c.clients[key]; ok {
		return cl, nil
	}
	cl := newHTTPClientBound(b)
	c.clients[key] = cl
	return cl, nil
}

// resolveProviderBindConfig derives the transport bindConfig (#2846) from a DDNS
// provider catalog entry's source-binding leaves. The HTTP backends carry the
// source-address / destination-interface / routing-instance on the provider
// (config.DDNSProvider, #2780); RFC 2136 reuses the same resolveBindConfig via a
// DHCPDynamicDNSConfig carrier. This adapts the provider shape onto the SAME
// resolveBindConfig discipline so an invalid source-address is a hard error
// (fail-open: the constructor degrades to the unbound default rather than
// emitting from the wrong source — see the callers).
func resolveProviderBindConfig(p *config.DDNSProvider) (bindConfig, error) {
	if p == nil {
		return bindConfig{}, nil
	}
	return resolveBindConfig(&config.DHCPDynamicDNSConfig{
		SourceAddress:        p.SourceAddress,
		DestinationInterface: p.DestinationInterface,
		RoutingInstance:      p.RoutingInstance,
	})
}

// newProviderHTTPClient builds a bound HTTP client for an HTTP backend from its
// provider's source-binding leaves (#2846). A malformed source-address fails
// open to the unbound default client (logged by the caller already has the commit
// warning) rather than wedging the backend — matching the rfc2136 fail-open
// posture. Returns the client and any bind-resolution error for the caller to
// surface; on error the returned client is the unbound default.
func newProviderHTTPClient(p *config.DDNSProvider) (*http.Client, error) {
	b, err := resolveProviderBindConfig(p)
	if err != nil {
		return newHTTPClient(), err
	}
	return newHTTPClientBound(b), nil
}

// ensureProviderHTTPClient returns the caller-supplied client when non-nil
// (the Surface A reconcile path threads a cached, reused client through here,
// #2904), otherwise it builds a fresh bound client from the provider's
// source-binding leaves (the pre-#2904 self-contained path used by direct/test
// callers). On a bind-resolution error it fails open to the unbound default
// client and returns the error for the caller to surface — matching
// newProviderHTTPClient's posture.
func ensureProviderHTTPClient(p *config.DDNSProvider, client *http.Client) (*http.Client, error) {
	if client != nil {
		return client, nil
	}
	return newProviderHTTPClient(p)
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
