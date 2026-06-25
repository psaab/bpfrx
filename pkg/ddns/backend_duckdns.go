package ddns

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// backend_duckdns.go: the DuckDNS DDNS backend (#2960). DuckDNS is NOT
// dyndns2-protocol-compatible — it was previously wired as a dyndns2 alias
// (dyndns2Endpoints["duckdns"]), which sent the WRONG request shape
// (hostname=/myip=), the WRONG auth model (HTTP Basic user/pass), rejected
// DuckDNS's normal OK body as an unrecognized dyndns2 keyword, and used the
// WRONG withdraw verb (offline=YES). An operator who configured the built-in
// duckdns provider exactly as the schema/docs advertised got a non-operational
// provider. This backend speaks the real DuckDNS API instead.
//
// DuckDNS API (https://www.duckdns.org/spec.jsp): a single GET
//
//	https://www.duckdns.org/update?domains=<sub>&token=<tok>&ip=<v4>[&ipv6=<v6>]
//
// authenticates by TOKEN passed as a QUERY PARAM (not HTTP Basic), and returns
// a plain-text body that is literally "OK" on success or "KO" on failure
// (HTTP 200 in both cases — like dyndns2 it is a 200-with-body protocol). A
// record is CLEARED with &clear=true (DuckDNS has no per-family clear; clear=true
// removes BOTH the A and the AAAA for the domain — documented on the withdraw
// path and in the README).
//
// The `domains` value is the DuckDNS SUBDOMAIN label, not an FQDN: a record for
// myhost.duckdns.org is updated with domains=myhost. The Surface A scope carries
// the operator's hostname as an FQDN (rec.FQDN); duckdnsDomain() reduces it to
// the subdomain label DuckDNS expects (stripping a trailing dot and the
// .duckdns.org suffix when present) so the operator can configure either the
// bare label or the full duckdns.org name.
//
// The token comes from the `api-token` leaf (config.DDNSProvider.APIToken,
// config.Secret-redacted) — reused from the Cloudflare backend rather than
// adding a duckdns-specific leaf. The update endpoint is overridable via
// `server` for test/mocking; production uses the built-in duckDNSUpdateBase.
//
// Implements the SAME DNSUpdater interface as rfc2136/cloudflare/route53/dyndns2;
// the Surface A engine drives it identically (change-detection, forced-refresh,
// per-RG HA gate, flat error backoff). A non-nil client is the cached
// reconcile-path client (#2904).

// duckDNSUpdateBase is the production DuckDNS update endpoint. Overridable
// per-instance via the provider `server` leaf so httptest can point the backend
// at a mock server.
const duckDNSUpdateBase = "https://www.duckdns.org/update"

// duckdnsBackend publishes a single A/AAAA record via the DuckDNS API.
type duckdnsBackend struct {
	name     string // provider name (for logs)
	endpoint string // resolved update base URL
	token    string // revealed at construction; never logged
	client   *http.Client
}

// newDuckDNSBackend resolves a provider-catalog entry into a live DuckDNS
// backend. A missing api-token is a hard error so the manager falls back to
// no-op (logged) rather than issuing unauthenticated requests DuckDNS would
// reject with KO. A non-nil client is reused (the cached reconcile-path client,
// #2904); nil builds a fresh bound client.
func newDuckDNSBackend(p *config.DDNSProvider, client *http.Client) (*duckdnsBackend, error) {
	if p == nil {
		return nil, fmt.Errorf("ddns duckdns: nil provider")
	}
	token := p.APIToken.Reveal()
	if token == "" {
		return nil, fmt.Errorf("ddns duckdns: provider %q has no api-token", p.Name)
	}
	endpoint := duckDNSUpdateBase
	if s := strings.TrimSpace(p.Server); s != "" {
		if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
			endpoint = s
		} else {
			// Bare host → canonical DuckDNS update path over HTTPS.
			endpoint = "https://" + strings.TrimRight(s, "/") + "/update"
		}
	}
	// Bind the dial to the configured source-address/interface/VRF (#2846). A
	// malformed source-address is a hard error so we degrade to no-op rather than
	// publish from the wrong source. A cached client (#2904) is reused when the
	// reconcile path supplies one; nil builds a fresh bound client.
	client, err := ensureProviderHTTPClient(p, client)
	if err != nil {
		return nil, fmt.Errorf("ddns duckdns: provider %q: %w", p.Name, err)
	}
	return &duckdnsBackend{
		name:     p.Name,
		endpoint: endpoint,
		token:    token,
		client:   client,
	}, nil
}

// duckdnsDomain reduces an FQDN to the DuckDNS `domains` subdomain label. DuckDNS
// keys updates on the bare subdomain (myhost), not the full myhost.duckdns.org
// FQDN, so a trailing dot and a .duckdns.org suffix are stripped. An operator may
// configure either spelling; both resolve to the same label.
func duckdnsDomain(fqdn string) string {
	d := strings.TrimSuffix(strings.TrimSpace(fqdn), ".")
	d = strings.TrimSuffix(strings.ToLower(d), ".duckdns.org")
	return d
}

// UpsertLease publishes one A or AAAA via a single DuckDNS update GET. DuckDNS
// takes the v4 address in `ip` and the v6 address in `ipv6`; a Surface A record
// carries exactly one address (one family per record), so exactly one of the two
// is set per call.
//
// CAVEAT — DuckDNS per-family clobber (#2960): omitting the OTHER family's
// parameter does NOT leave that family's record untouched. The DuckDNS spec
// (duckdns.org/spec.jsp) says "If you do not specify the IP address, then it
// will be detected" — so a v6 update that sends only ipv6= makes DuckDNS
// AUTO-DETECT the source IPv4 and SET the A record (and the v4-only path's
// behaviour for the AAAA is undocumented — treat it as the same risk). DuckDNS
// has no per-family update verb, so xpf cannot update one family without DuckDNS
// touching the other. With per-family Surface A scopes (no per-FQDN coalescing)
// a dual-stack DuckDNS name would have its A and AAAA fight on every reconcile.
// The supported topology is therefore ONE family per DuckDNS name; a config that
// binds the same DuckDNS name on both inet and inet6 is flagged at commit by
// config.validateSurfaceADDNSWarnings (#2960). We deliberately do NOT synthesize
// a placeholder/last-known value for the other family here: the engine does not
// pass cross-scope knowledge to the backend, so any value we could fabricate
// would itself be a guess that clobbers.
func (b *duckdnsBackend) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
	q := url.Values{}
	addr := rec.Addr.Unmap()
	if addr.Is4() {
		q.Set("ip", addr.String())
	} else {
		q.Set("ipv6", addr.String())
	}
	return b.update(ctx, rec.FQDN, q)
}

// DeleteLease withdraws the firewall's own record via the DuckDNS clear verb
// (&clear=true). DuckDNS has no per-family clear: clear=true removes BOTH the A
// and the AAAA for the domain. This is the only portable DuckDNS withdraw, so a
// dual-stack scope's two records collapse onto one clear — acceptable because the
// Surface A engine only withdraws on scope teardown (the firewall is the sole
// owner of its own duckdns.org name; there is no third-party RR to preserve). The
// body verdict (OK/KO) is parsed exactly like an upsert, so a failed clear
// returns a non-nil error and the engine keeps ownership for retry instead of
// orphaning the public record.
func (b *duckdnsBackend) DeleteLease(ctx context.Context, rec LeaseDNSRecord) error {
	q := url.Values{}
	q.Set("clear", "true")
	return b.update(ctx, rec.FQDN, q)
}

// update issues one DuckDNS GET against the resolved endpoint with the supplied
// per-call query merged onto domains=+token=, then parses the OK/KO body verdict.
// Shared by UpsertLease and DeleteLease so both paths apply identical auth and
// response handling. The token is sent as a query param (the DuckDNS auth model),
// NEVER logged: doRequest scrubs the query from any *url.Error before it reaches
// an error string.
func (b *duckdnsBackend) update(ctx context.Context, fqdn string, q url.Values) error {
	u, err := url.Parse(b.endpoint)
	if err != nil {
		return fmt.Errorf("ddns duckdns: bad endpoint: %w", err)
	}
	// Merge the caller's parameters onto domains=+token= (and any the endpoint
	// already carries).
	base := u.Query()
	base.Set("domains", duckdnsDomain(fqdn))
	base.Set("token", b.token)
	for k, vs := range q {
		base[k] = vs
	}
	u.RawQuery = base.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("ddns duckdns: build request: %w", err)
	}
	req.Header.Set("User-Agent", "xpf-ddns/1.0")

	code, body, err := doRequest(ctx, b.client, req)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		// DuckDNS is a 200-with-body protocol; a non-200 is itself the verdict.
		if cerr := classifyHTTPStatus(code); cerr != nil {
			return fmt.Errorf("ddns duckdns: %s: %w", b.name, cerr)
		}
		return fmt.Errorf("ddns duckdns: %s: unexpected status %d", b.name, code)
	}
	return parseDuckDNSResponse(string(body), b.name)
}

// parseDuckDNSResponse maps a DuckDNS response body to a verdict. The body is the
// literal keyword "OK" (success) or "KO" (failure) — DuckDNS does not return
// dyndns2's good/nochg, so the dyndns2 parser rejected DuckDNS's normal success
// as unrecognized (#2960). The keyword is matched case-insensitively on the first
// non-empty line; some DuckDNS update responses append diagnostic lines after the
// keyword (verbose=true), so only the leading token of the first line is
// significant.
func parseDuckDNSResponse(body, name string) error {
	first := ""
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			first = line
			break
		}
	}
	keyword := first
	if fields := strings.Fields(first); len(fields) > 0 {
		keyword = fields[0]
	}
	switch strings.ToUpper(keyword) {
	case "OK":
		return nil
	case "KO":
		// DuckDNS returns KO for a bad token or unknown domain; treat it as a
		// hard auth/config failure so it is not silently retried as transient.
		return fmt.Errorf("ddns duckdns: %s: response %q (bad token or unknown domain): %w",
			name, keyword, errHTTPAuth)
	default:
		return fmt.Errorf("ddns duckdns: %s: unrecognized response %q", name, first)
	}
}
