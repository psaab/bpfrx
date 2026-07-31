package ddns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

// errRedirectRefused tags every refusal guardRedirect returns. It is a
// PROVENANCE marker, not decoration: an *http.Client wraps a CheckRedirect
// failure into the *url.Error it returns, so the refusal text reaches
// scrubInnerError, which renders an error verbatim only when it can prove the
// text is credential-free (see scrubInnerError). This sentinel is that proof
// for our own refusals — the sentences are built HERE, from fixed prose plus
// host/scheme tokens that have already been through safeHostText/safeScheme.
//
// Which matters because the redirect target is PROVIDER-supplied: a provider
// that answers with `Location: https://<our-own-password>.evil.example/` gets
// the hop refused (that is the point of the guard) but would, without the
// grammar, put the echoed credential into the refusal message and thence into
// the daemon log. Anything added to a refusal string here must be
// grammar-bounded the same way, or this sentinel starts vouching for text
// nobody bounded.
var errRedirectRefused = errors.New("ddns http")

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
//
// #5327: when a source-address is configured the DialContext is wrapped
// (boundDialContext) to PIN the dial to the source family, so Happy-Eyeballs
// cannot pick the other family and silently skip the source bind (an update that
// then egresses the wrong WAN / bypasses a source ACL / publishes the wrong
// address). An endpoint with no address in the source family FAILS CLOSED at the
// dial instead of egressing unbound.
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
		// #5327: pin the dial to the configured source-address family via a
		// DialContext wrapper (constrainDialNetwork) so Happy-Eyeballs cannot pick
		// the other family and skip the source bind — which would egress the update
		// from a kernel-chosen source on the wrong WAN. A device-only bind (no
		// source-address) passes the network through unchanged.
		tr.DialContext = b.boundDialContext(d)
	}
	return &http.Client{
		Timeout:       httpClientTimeout,
		Transport:     tr,
		CheckRedirect: guardRedirect,
	}
}

// maxRedirects re-implements Go's built-in redirect cap. Setting CheckRedirect
// REPLACES http.Client's default 10-hop limit, so the cap has to be restored by
// the policy itself or a redirect loop would spin forever inside one request.
const maxRedirects = 10

// guardRedirect is the shared *http.Client.CheckRedirect for every HTTP DDNS
// backend. It enforces three things on a 30x Location, and restores the hop cap
// the default policy would otherwise have provided.
//
//  1. NO SCHEME DOWNGRADE (#4861). A credentialed backend (dyndns2 Basic auth,
//     DuckDNS/Cloudflare query/bearer token, Route 53 SigV4) that started over
//     TLS must never be walked onto a plaintext connection, which would put the
//     update credential on the wire for an on-path attacker. An HTTP->HTTPS
//     upgrade is still followed.
//
//  2. NO CROSS-HOST REDIRECT (#6545). The scheme guard alone left an
//     https->https hop to a DIFFERENT host wide open, and Go discloses real
//     secrets across exactly that hop — verified firsthand against the stdlib,
//     not assumed:
//
//     - Referer carries the FULL previous URL INCLUDING the query string.
//     net/http refererForURL() strips only the userinfo and suppresses the
//     header only for https->http; on an https->https hop to any host the
//     redirect target receives e.g.
//     "https://www.duckdns.org/update?domains=h&token=<TOKEN>". That is a
//     live provider credential for DuckDNS (token is a QUERY param, not
//     Basic — see backend_duckdns.go), for the generic backend (a %p-expanded
//     password or a literal ?token= in url-template), and for a checkip-url
//     that carries an API key. It also discloses the FQDN and the public
//     address being published for every backend.
//
//     - Go forwards Authorization/Cookie to any SUBDOMAIN of the original
//     host (net/http shouldCopyHeaderOnRedirect -> isDomainOrSubdomain).
//     So a redirect to sub.<configured-host> hands the dyndns2/generic Basic
//     credential and the Cloudflare bearer token to a host the operator never
//     configured. Stripping Referer would NOT have closed that half.
//
//     Refusing outright, rather than sanitizing and following, is the choice
//     because these clients are machine-to-machine callers of an endpoint the
//     operator PINNED (a built-in provider constant, or a `server` /
//     `url-template` / `checkip-url` leaf). There is no discovery step that
//     needs to land somewhere else, and following a Location to an unconfigured
//     host is itself the trust violation: it sends the update payload (which
//     FQDN, which public address) — and on a 307/308 the whole request body,
//     e.g. a Route 53 change batch — to a host the operator never named. The
//     realistic trigger is a mistyped or hostile `server` leaf, and fail-closed
//     is this package's posture everywhere else (bind error, malformed
//     checkip-url, unrecognized response body). A provider that genuinely moves
//     to a new host is served by pointing the leaf at the final host; the error
//     names both hosts so the operator can do exactly that. SAME-host
//     redirects — the common real case, a path or API-version move — are still
//     followed.
//
//  3. NO Referer ON ANY FOLLOWED REDIRECT. Defense in depth on top of (2): the
//     hop we do allow is same-host, so the target already holds the credential
//     it is being sent, but there is no reason for a DDNS API call to echo its
//     own query string back into a header that provider access logs record
//     separately. Go sets Referer on the new request BEFORE calling
//     CheckRedirect precisely so a policy can override it (see the comment on
//     Client.do), so deleting it here is the supported seam. Deleting from a nil
//     header map is a defined no-op, so a synthetic request needs no guard.
//
// Host comparison is by HOSTNAME only — case-insensitive per RFC 4343, with one
// trailing root dot normalized away, and deliberately PORT-INDEPENDENT. The
// trust anchor is the DNS name and the TLS certificate identity bound to it,
// which is what the operator configured and what cert verification pins; a port
// move stays inside that identity, and a port-strict rule would falsely refuse
// the plain "https://prov.example:443/x" -> "https://prov.example/x" default-port
// normalization. A Unicode (non-punycode) Location host compares unequal to its
// A-label spelling and is refused; that is the conservative direction (a false
// refusal, never a false allow) and no in-tree provider uses an IDN host.
//
// The comparison is against the PREVIOUS hop, matching the scheme guard. Under
// exact equality that is equivalent to comparing against the original request:
// every hop must equal its predecessor, so by induction every hop equals hop 0.
func guardRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("%w: stopped after %d redirects", errRedirectRefused, maxRedirects)
	}
	if len(via) > 0 {
		prev := via[len(via)-1].URL
		if strings.EqualFold(prev.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
			// The scheme AND the host here come from the provider's Location
			// header, so both are rendered through the safe grammar — see
			// errRedirectRefused.
			return fmt.Errorf("%w: refusing HTTPS->%s redirect downgrade to %s "+
				"(would expose update credentials in cleartext)",
				errRedirectRefused, safeScheme(req.URL.Scheme), refusalHost(req.URL))
		}
		if !strings.EqualFold(redirectHost(prev), redirectHost(req.URL)) {
			return fmt.Errorf("%w: refusing cross-host redirect from %s to %s "+
				"(would disclose the update credentials and payload to a host that is not "+
				"the configured endpoint); point the provider endpoint at the final host instead",
				errRedirectRefused, refusalHost(prev), refusalHost(req.URL))
		}
	}
	// Followed (same-host) hop: never echo the previous URL's query string —
	// which carries the DuckDNS/generic/checkip credential — into Referer.
	req.Header.Del("Referer")
	return nil
}

// refusalHost renders a host inside a guardRedirect refusal sentence: the safe
// grammar, or a fixed placeholder when the host does not fit it. It differs from
// safeHostText only in never returning "" — an empty slot mid-sentence ("refusing
// cross-host redirect from prov.example to ") reads as a bug rather than as a
// withheld value.
//
// This is a RENDERING helper only. guardRedirect's same-host DECISION still uses
// redirectHost on the raw values; a host that fails the grammar must be refused,
// not compared loosely.
func refusalHost(u *url.URL) string {
	if h := safeHostText(u); h != "" {
		return h
	}
	return "(host withheld: not a plain host name)"
}

// redirectHost normalizes a URL's host for guardRedirect's same-host test:
// the hostname with the port dropped (URL.Hostname also unwraps an IPv6 literal
// from its brackets) and one trailing root dot removed, so "prov.example." and
// "prov.example" are the one name they actually are. Case folding is left to the
// EqualFold comparison at the call site.
func redirectHost(u *url.URL) string {
	return strings.TrimSuffix(u.Hostname(), ".")
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
// caches) a fresh bound transport.
//
// Reap on supersede (#2956): a binding-leaf change keys a FRESH entry, so the
// OLD entry is never looked up again — but it is not self-evicting. The
// SurfaceAManager lives for the whole daemon lifetime, so distinct historical
// binding tuples would otherwise accumulate forever (their *http.Transport +
// the idle-connection pool retained until process exit even though
// IdleConnTimeout reaps the sockets). Each reconcile pass therefore calls reap
// with the set of binding keys still referenced by the committed config; an
// entry whose key is gone has its idle connection pool closed and is dropped,
// bounding the map to current config under binding churn.
type httpClientCache struct {
	mu      sync.Mutex
	clients map[string]*http.Client
}

// closeIdleConns is the seam reap uses to drop a superseded client's keep-alive
// connection pool. It is a package var so a test can record that the reap
// actually fired (fail-on-revert for #2956). Production closes the transport's
// idle connections via the standard *http.Client.CloseIdleConnections.
var closeIdleConns = func(cl *http.Client) { cl.CloseIdleConnections() }

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
// malformed source-address) is returned alongside the UNBOUND default client;
// the error path is NOT cached so a corrected source-address on the next commit
// rebuilds cleanly. Returning the unbound client is a convenience for the
// no-source caller — a NON-nil error means the source could NOT be honored, and
// every caller MUST fail CLOSED on it (skip the publish / probe) rather than
// egress from that unbound client: the publish resolver (resolveSurfaceABackend,
// #4437) and the checkip observer (CheckIPBound, #3733) both do.
// resolveIf is the OPTIONAL committed-config interface-name resolver
// (cfg.ResolveKernelIfName) threaded from the daemon so a destination-interface
// binding resolves to the real kernel device (#5070). The cache KEY stays the
// raw binding leaves (bindCacheKey) so the #2956 reap stays consistent; only the
// bound client's SO_BINDTODEVICE target is resolved.
func (c *httpClientCache) clientFor(p *config.DDNSProvider, resolveIf ...func(string) string) (*http.Client, error) {
	b, err := resolveProviderBindConfig(p, firstResolver(resolveIf))
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

// reap closes the idle-connection pool of, and evicts, every cached client whose
// binding key is NOT in the live set (#2956). The caller (the Surface A
// reconcile) passes the binding keys still referenced by the committed provider
// catalog + configured scopes, so a binding-leaf change that supersedes a cache
// entry on the next pass has its stale *http.Transport / idle pool released
// instead of lingering for the daemon lifetime. A key still in live (the active
// binding for a current scope) is preserved — only an actual key change is
// superseded. Safe on a nil cache (the test/no-cache manager). Takes c.mu (the
// same lock clientFor uses); the manager's m.mu is always the OUTER lock so
// there is no lock-order inversion.
func (c *httpClientCache) reap(live map[string]struct{}) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, cl := range c.clients {
		if _, ok := live[key]; ok {
			continue
		}
		closeIdleConns(cl)
		delete(c.clients, key)
	}
}

// size returns the number of cached clients (test observability for the #2956
// bounded-map invariant).
func (c *httpClientCache) size() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.clients)
}

// resolveProviderBindConfig derives the transport bindConfig (#2846) from a DDNS
// provider catalog entry's source-binding leaves. The HTTP backends carry the
// source-address / destination-interface / routing-instance on the provider
// (config.DDNSProvider, #2780); RFC 2136 reuses the same resolveBindConfig via a
// DHCPDynamicDNSConfig carrier. This adapts the provider shape onto the SAME
// resolveBindConfig discipline so an invalid source-address is a hard error
// (fail-open: the constructor degrades to the unbound default rather than
// emitting from the wrong source — see the callers).
func resolveProviderBindConfig(p *config.DDNSProvider, resolve func(string) string) (bindConfig, error) {
	if p == nil {
		return bindConfig{}, nil
	}
	return resolveBindConfig(&config.DHCPDynamicDNSConfig{
		SourceAddress:        p.SourceAddress,
		DestinationInterface: p.DestinationInterface,
		RoutingInstance:      p.RoutingInstance,
	}, resolve)
}

// newProviderHTTPClient builds a bound HTTP client for an HTTP backend from its
// provider's source-binding leaves (#2846). A malformed source-address fails
// open to the unbound default client (logged by the caller already has the commit
// warning) rather than wedging the backend — matching the rfc2136 fail-open
// posture. Returns the client and any bind-resolution error for the caller to
// surface; on error the returned client is the unbound default.
func newProviderHTTPClient(p *config.DDNSProvider, resolveIf ...func(string) string) (*http.Client, error) {
	b, err := resolveProviderBindConfig(p, firstResolver(resolveIf))
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

// scrubURLError is the SINGLE renderer in this package for an error that may
// carry a request URL. Every DDNS site that fails while BUILDING or while
// ISSUING a request routes through it, so "no credential reaches a log" is a
// property of the package rather than of each call site remembering to redact
// (#6545 review). The one deliberate exception is the dyndns2 raw-`server`
// render in resolveDyndns2Endpoint, tracked separately as #6606 and pinned by
// an explicit, self-expiring exemption in the source gate
// (url_render_class_6545_test.go).
//
// WHAT IT RENDERS: at most SCHEME://HOST[:PORT], built by ALLOWLIST — and the
// allowlist is over the CHARACTERS, not just over the url.URL fields. Round 7
// found that field-level allowlisting was not enough: an allowlist is only as
// good as the safety of what it admits, and `Host` is NOT credential-free.
//
// Field-level allowlisting (a fresh url.URL carrying only Scheme and Host)
// closed the field-expansion class — User, Path, RawPath, RawQuery, Fragment,
// RawFragment, Opaque, OmitHost and anything net/url adds later are absent by
// construction. It did not close the credential class, because `Host` is a
// container for substituted template text, not a name. What url.Parse will
// legally leave in `Host` (verified against Go 1.26 net/url):
//
//   - AN IPv6 ZONE ID. RFC 6874 lets a zone use "basically any %-encoding it
//     likes", and net/url honours that: "https://[fe80::1%25%p]/update" is a
//     SUPPORTED generic template and parses to Host = "[fe80::1%<password>]".
//     u.Hostname() does not help — it strips the brackets and keeps the zone.
//   - A REG-NAME LABEL. "https://%p.example.com/" parses to
//     Host = "<password>.example.com" whenever the password is host-safe.
//   - RAW NON-ASCII BYTES. %-escapes above 0x7F are decoded in place, so
//     "ex%FFample.com" reaches Host as a literal 0xFF — log-injection material
//     on top of everything else.
//   - A PORT, which is digits-only (net/url's validOptionalPort) but is still
//     a place a numeric password can land.
//   - ANY OF THE ABOVE FROM THE PROVIDER. A cross-host Location echoing our own
//     credential as its hostname is refused by guardRedirect — correctly — and
//     the refusal named the host.
//
// Userinfo is NOT in this list: url.Parse splits "user:pass@host" into u.User,
// so an ordinary credentialed URL was already safe.
//
// So the host is rebuilt from a CLOSED GRAMMAR rather than copied (safeHostText):
// an IP literal is re-rendered from netip with its ZONE DROPPED, and a reg-name
// must be ASCII letters/digits/'-'/'_' in dot-separated labels or it is withheld
// entirely. The scheme is likewise reduced to the two values this package ever
// legitimately uses. What survives is exactly the network identity that is on
// the wire in the DNS query, the TCP SYN and the TLS SNI regardless; path,
// query, userinfo, fragment and zone id are all operator- or provider-supplied
// opaque bytes and are treated as secret.
//
// The residual is stated rather than papered over: an operator whose template
// puts the password in the DNS NAME ITSELF ("https://%p.example.com/") has
// already published it to their resolver and to every on-path observer, and it
// will appear in this error. That is a configuration error the logging boundary
// cannot repair, and hiding it would make the operator less likely to notice.
//
// The diagnostic cost of dropping the path is deliberate and small: the
// caller's own prefix already names the backend and the operation ("ddns
// cloudflare: build request", "ddns route53: build list request"), so what is
// lost is the API sub-path, not the ability to tell which call failed.
//
// A URL THAT DOES NOT RE-PARSE yields NO URL at all — only the sanitized
// urlParseCause reason. The old code fell back to ue.URL VERBATIM, which was
// survivable only while this helper was reachable exclusively from the
// transport path, where the URL had necessarily parsed on the way in. It is now
// also the renderer for BUILD-request failures, whose DEFINING input is a URL
// that does not parse, so that fallback would have been a direct leak of the
// whole raw string.
//
// THE INNER ERROR is rendered too, because that is the entire diagnostic value
// ("connection refused", "i/o timeout", "certificate signed by unknown
// authority") — but by CLASSIFICATION, never verbatim. See scrubInnerError.
//
// A non-*url.Error goes through the same classifier: it is not automatically
// URL-free just because it is not a *url.Error (round 7).
func scrubURLError(err error) string {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return scrubInnerError(err)
	}
	u, perr := url.Parse(ue.URL)
	if perr != nil {
		// Nothing can be recovered safely from a URL that does not parse — not
		// even the host. Report the sanitized reason and no part of the input.
		return fmt.Sprintf("url is not a valid URL: %s", urlParseCause(perr))
	}
	target, note := safeURLTarget(u)
	return fmt.Sprintf("%s %q%s: %s", ue.Op, target, note, scrubInnerError(ue.Err))
}

// safeURLTarget renders the largest part of u that the closed grammar admits,
// plus a fixed NOTE naming anything withheld (empty when nothing was). Splitting
// the note out keeps the target a well-formed URL instead of stuffing a
// parenthetical inside it.
func safeURLTarget(u *url.URL) (target, note string) {
	scheme := safeScheme(u.Scheme)
	if scheme == "" {
		// Nothing downstream of an unrecognised scheme can be trusted to be a
		// host at all, so nothing is rendered. This package only ever issues
		// http(s), so no legitimate diagnostic is lost.
		return "", " (url withheld: scheme is not http or https)"
	}
	host := safeHostText(u)
	if host == "" {
		return scheme + ":", " (host withheld: not a plain host name)"
	}
	target = scheme + "://" + host
	if zoneOf(u.Hostname()) != "" {
		note = " (link-local zone id withheld)"
	}
	return target, note
}

// safeScheme reduces a URL scheme to the two values this package legitimately
// uses, or "" for anything else. url.Parse constrains a scheme's CHARACTERS but
// not its content, so a template that expanded a credential into the scheme
// position would otherwise be rendered; the allowlist makes that impossible
// without depending on any upstream validator having run.
func safeScheme(s string) string {
	switch strings.ToLower(s) {
	case "http":
		return "http"
	case "https":
		return "https"
	}
	return ""
}

// safeHostText renders u's authority under the closed grammar, or "" if it does
// not fit. The result is one of exactly three shapes:
//
//   - an IP literal re-rendered by netip WITH ANY ZONE ID DROPPED, bracketed
//     when it is v6 ("[2001:db8::1]", "192.0.2.7");
//   - a reg-name of dot-separated labels drawn from ASCII letters, digits, '-'
//     and '_', at most 63 bytes per label and 253 total, with at most one
//     trailing root dot;
//
// each optionally followed by ":" and 1..5 decimal digits in 1..65535.
//
// Everything else — a raw non-ASCII byte, a '%', an empty label, an
// over-long name, a non-numeric or out-of-range port — yields "". The point is
// that the OUTPUT CHARACTER SET is closed, so no amount of template
// substitution or provider-supplied Location text can put arbitrary bytes into
// a log line through this path.
func safeHostText(u *url.URL) string {
	host := safeHostName(u.Hostname())
	if host == "" {
		return ""
	}
	if port := safePort(u.Port()); port != "" {
		return host + ":" + port
	}
	return host
}

// safeHostName applies the grammar to a bare hostname (no port, no brackets).
func safeHostName(h string) string {
	if h == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		// An IP literal is re-rendered from the PARSED value, which is how the
		// zone id is dropped: netip holds it as a separate field, so
		// WithZone("") removes it structurally rather than by trimming text.
		addr = addr.WithZone("")
		if addr.Is6() {
			return "[" + addr.String() + "]"
		}
		return addr.String()
	}
	return safeRegName(h)
}

// zoneOf reports the IPv6 zone id on a hostname, or "" when there is none. It is
// used only to decide whether to say a zone was withheld — the zone itself is
// never rendered.
func zoneOf(h string) string {
	addr, err := netip.ParseAddr(h)
	if err != nil {
		return ""
	}
	return addr.Zone()
}

// safeRegName returns h when it is a plain DNS-shaped name under the grammar
// documented on safeHostText, "" otherwise.
func safeRegName(h string) string {
	if len(h) > 253 {
		return ""
	}
	labels := strings.TrimSuffix(h, ".")
	if labels == "" {
		return ""
	}
	for _, label := range strings.Split(labels, ".") {
		if len(label) == 0 || len(label) > 63 {
			return ""
		}
		for i := 0; i < len(label); i++ {
			switch c := label[i]; {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return ""
			}
		}
	}
	return h
}

// safePort returns p when it is a decimal port in 1..65535, "" otherwise.
// net/url already rejects a non-numeric port, so this is a second, local proof
// rather than a first line of defence.
func safePort(p string) string {
	if p == "" || len(p) > 5 {
		return ""
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return ""
	}
	return p
}

// transportReason is a CLOSED enumeration of what scrubInnerError may report,
// following the parseReason precedent in checkip.go: because the classifier
// returns transportReason, a bare pass-through of an error's text — "return
// text" — does not COMPILE. Reintroducing the leak requires an explicit
// transportReason(...) conversion, which is a deliberate, greppable edit rather
// than a plausible-looking slip.
//
// There is exactly ONE sanctioned conversion, errnoReason, and its argument
// space is the kernel's fixed errno table.
type transportReason string

// The COMPLETE set of reasons scrubInnerError can report, errno aside.
const (
	transportNil            transportReason = "<nil>"
	transportWithheld       transportReason = "transport error withheld"
	transportTimeout        transportReason = "network timeout"
	transportDeadline       transportReason = "context deadline exceeded"
	transportCanceled       transportReason = "context canceled"
	transportEOF            transportReason = "connection closed before a complete response"
	transportDNS            transportReason = "dns lookup failed"
	transportDNSNotFound    transportReason = "dns lookup failed: no such host"
	transportDNSTimeout     transportReason = "dns lookup failed: timed out"
	transportTLSVerify      transportReason = "tls: certificate verification failed"
	transportTLSHostname    transportReason = "tls: certificate is not valid for the requested host"
	transportTLSAuthority   transportReason = "tls: certificate signed by unknown authority"
	transportTLSInvalid     transportReason = "tls: certificate is invalid"
	transportTLSHandshake   transportReason = "tls: handshake failed"
	transportSchemeMismatch transportReason = "server gave an HTTP response to an HTTPS client"
	transportLocationEcho   transportReason = "failed to parse redirect Location header " +
		"(withheld: it echoes provider-supplied URL text)"
)

// scrubInnerError renders the error nested inside a *url.Error.
//
// ROUND 7 MADE THIS TOTAL. It previously returned any non-*url.Error VERBATIM
// on the reasoning that "transport errors name a host/IP, never a URL". That
// held for the transports this package builds itself, but CheckIP takes a
// caller-supplied *http.Client, and a RoundTripper returning
//
//	fmt.Errorf("request %s failed: %w", req.URL, context.DeadlineExceeded)
//
// put the complete path credential straight through. The old special case for
// net/http's Location-parse message was an exact PREFIX match, so the same
// message wrapped one layer deep also walked past it.
//
// The rule now is provenance, not pattern-matching: an error's text is rendered
// only when we can point at what generates it.
//
//   - OUR OWN refusals (errRedirectRefused) — built from fixed prose plus
//     grammar-bounded host tokens, here in this file.
//   - A syscall.Errno — the kernel's fixed table ("connection refused", "no
//     route to host"), which is where nearly all real transport diagnosis
//     lives.
//   - Recognised stdlib SENTINELS and TYPES, each collapsed onto a constant
//     above. Structure is read (net.Error.Timeout, DNSError.IsNotFound,
//     OpError.Op/Net against an allowlist); embedded STRINGS never are —
//     DNSError.Name and OpError.Addr are the request host, and x509 errors
//     quote provider-supplied certificate fields.
//
// Anything else is withheld, naming only its Go TYPE, which is a compile-time
// symbol from this repository or the stdlib and carries no operator data. That
// costs some of net/http's internal prose; the type name still says where to
// look, and an unrecognised error is exactly the case where we cannot say what
// it contains.
func scrubInnerError(err error) string {
	if err == nil {
		return string(transportNil)
	}
	// A nested *url.Error would re-embed a full URL in its own Error(); recurse
	// through the same scrub instead of printing it.
	var nested *url.Error
	if errors.As(err, &nested) {
		return scrubURLError(nested)
	}
	// Our own refusals carry their provenance, so their text is known-safe.
	// Rendering them matters: the cross-host refusal IS the diagnostic this
	// guard exists to produce.
	if errors.Is(err, errRedirectRefused) {
		return err.Error()
	}
	return string(classifyTransportError(err))
}

// classifyTransportError maps an arbitrary transport error onto the closed
// transportReason set. Every branch reads TYPE or STRUCTURE; none reads an
// error's message text.
func classifyTransportError(err error) transportReason {
	// net/http builds fmt.Errorf("failed to parse Location header %q: %v", ...)
	// BEFORE CheckRedirect runs, so a provider that 3xx-es to a malformed
	// Location echoing our own query lands the credential here. It has no
	// distinguishing type, so it is matched on the invariant prefix — at any
	// wrapping depth, unlike the round-6 exact match. Anything the match misses
	// falls through to "withheld", so a stdlib rewording fails CLOSED.
	for e := err; e != nil; e = errors.Unwrap(e) {
		if strings.HasPrefix(e.Error(), locationHeaderPrefix) {
			return transportLocationEcho
		}
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return transportDeadline
	case errors.Is(err, context.Canceled):
		return transportCanceled
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return transportEOF
	case errors.Is(err, http.ErrSchemeMismatch):
		return transportSchemeMismatch
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return transportDNSNotFound
		case dnsErr.IsTimeout:
			return transportDNSTimeout
		}
		return transportDNS
	}

	if reason, ok := classifyTLSError(err); ok {
		return reason
	}

	// An errno is the single most useful thing in the whole chain and its text
	// comes from a fixed kernel table, so it is the ONE sanctioned conversion
	// out of free text into transportReason.
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errnoReason(errno)
	}

	// A *net.OpError with no errno underneath still says what stage failed. Its
	// Op and Net come from net's own fixed vocabulary, but a caller-supplied
	// RoundTripper can forge one, so both are checked against an allowlist and
	// the Addr/Source fields (the request host) are dropped.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if safeTransportOps[opErr.Op] && safeTransportNets[opErr.Net] {
			return transportReason(opErr.Op + " " + opErr.Net + " failed")
		}
		return transportWithheld
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return transportTimeout
	}

	return transportReason(fmt.Sprintf("%s (%T)", transportWithheld, err))
}

// classifyTLSError collapses the TLS/x509 failures worth naming. The x509 types
// all quote provider-supplied certificate fields in their Error(), so only the
// TYPE is read.
func classifyTLSError(err error) (transportReason, bool) {
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return transportTLSHostname, true
	}
	var authErr x509.UnknownAuthorityError
	if errors.As(err, &authErr) {
		return transportTLSAuthority, true
	}
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		return transportTLSInvalid, true
	}
	var verifyErr *tls.CertificateVerificationError
	if errors.As(err, &verifyErr) {
		return transportTLSVerify, true
	}
	var recErr tls.RecordHeaderError
	if errors.As(err, &recErr) {
		return transportTLSHandshake, true
	}
	return "", false
}

// errnoReason is the ONE place free text becomes a transportReason. It is sound
// because syscall.Errno.Error() is a table lookup over the kernel's fixed error
// list ("connection refused", "no route to host", "connection reset by peer") —
// a closed vocabulary that cannot contain operator or provider data.
func errnoReason(e syscall.Errno) transportReason { return transportReason(e.Error()) }

// safeTransportOps / safeTransportNets are net's own vocabularies for
// net.OpError.Op and .Net. A value outside them means the OpError did not come
// from package net, so nothing about it is known.
var safeTransportOps = map[string]bool{
	"dial": true, "read": true, "write": true, "close": true, "accept": true,
	"listen": true, "set": true, "readfrom": true, "writeto": true,
}

var safeTransportNets = map[string]bool{
	"tcp": true, "tcp4": true, "tcp6": true, "udp": true, "udp4": true, "udp6": true,
	"ip": true, "ip4": true, "ip6": true, "unix": true, "unixgram": true, "unixpacket": true,
}

// locationHeaderPrefix is the invariant head of net/http's Location-parse
// failure (net/http/client.go), which quotes the raw header value.
const locationHeaderPrefix = `failed to parse Location header `

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
