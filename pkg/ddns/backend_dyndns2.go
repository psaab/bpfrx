package ddns

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// backend_dyndns2.go: the dyndns2 HTTP DDNS backend (#2691 P3, plan §3.1/§5.2).
// dyndns2 is the de-facto consumer-DDNS protocol: a single GET
//
//	https://user:pass@<server>/nic/update?hostname=<H>&myip=<IP>
//
// with HTTP Basic auth, whose response BODY (HTTP 200) carries a status keyword
// (good/nochg/nohost/badauth/abuse/notfqdn/911/...) the client parses into a
// verdict. The inadyn idea adopted here (idea #2, plan §3.7): ONE implementation
// behind MANY provider names — a name→endpoint table (dyndns2Endpoints) maps the
// provider backend token (or an explicit `server`) to the right host. dyn,
// no-ip, duckdns, dynu, etc. all speak this protocol; only the endpoint differs.
//
// This backend implements the SAME DNSUpdater interface as rfc2136, so the
// Surface A engine drives it identically. A router record carries no PTR and no
// ClientID (the firewall owns its own name), so Upsert sends exactly one GET and
// Delete is a best-effort offline (dyndns2 has no standard delete verb — most
// providers offman by pointing the record at 0.0.0.0 or simply letting it
// expire). We implement Delete as a documented no-op-with-warning rather than
// guessing a per-provider deletion verb.

// dyndns2Endpoints maps a known dyndns2 provider name to its update base URL.
// The provider's `backend` token selects the protocol (dyndns2); when the
// `backend` token is itself a known provider NAME we use its endpoint, else the
// operator must set `server`. Keep this table small and well-known; everything
// else uses the generic backend or an explicit `server`.
var dyndns2Endpoints = map[string]string{
	"dyn":       "https://members.dyndns.org/v3/update",
	"dyndns":    "https://members.dyndns.org/v3/update",
	"no-ip":     "https://dynupdate.no-ip.com/nic/update",
	"noip":      "https://dynupdate.no-ip.com/nic/update",
	"duckdns":   "https://www.duckdns.org/update",
	"dynu":      "https://api.dynu.com/nic/update",
	"easydns":   "https://api.cp.easydns.com/dyn/generic.php",
	"dnsomatic": "https://updates.dnsomatic.com/nic/update",
}

// dyndns2Backend publishes a single A/AAAA record via the dyndns2 protocol.
type dyndns2Backend struct {
	name     string // provider name (for logs)
	endpoint string // resolved update base URL
	username string
	password string // revealed at construction; never logged
	client   *http.Client
}

// newDyndns2Backend resolves a provider-catalog entry into a live dyndns2
// backend. The endpoint is the explicit `server` (a full URL, or a bare host we
// suffix with /nic/update) else the built-in endpoint for the named provider.
// Returns an error when no endpoint can be resolved so the manager falls back to
// no-op (logged + counted) rather than emitting to a wrong host.
func newDyndns2Backend(p *config.DDNSProvider) (*dyndns2Backend, error) {
	if p == nil {
		return nil, fmt.Errorf("ddns dyndns2: nil provider")
	}
	endpoint, err := resolveDyndns2Endpoint(p)
	if err != nil {
		return nil, err
	}
	return &dyndns2Backend{
		name:     p.Name,
		endpoint: endpoint,
		username: p.Username,
		password: p.Password.Reveal(),
		client:   newHTTPClient(),
	}, nil
}

// resolveDyndns2Endpoint picks the update base URL for a dyndns2 provider.
func resolveDyndns2Endpoint(p *config.DDNSProvider) (string, error) {
	if s := strings.TrimSpace(p.Server); s != "" {
		if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
			return s, nil
		}
		// Bare host → canonical dyndns2 path over HTTPS.
		return "https://" + s + "/nic/update", nil
	}
	// No explicit server: use the built-in endpoint for the named provider. The
	// `backend` token is "dyndns2"; the provider NAME (or an alias in the table)
	// selects the host.
	if ep, ok := dyndns2Endpoints[strings.ToLower(p.Name)]; ok {
		return ep, nil
	}
	if ep, ok := dyndns2Endpoints[strings.ToLower(p.Backend)]; ok {
		return ep, nil
	}
	return "", fmt.Errorf("ddns dyndns2: provider %q has no server and no built-in endpoint "+
		"(set `server`, or name the provider after a known dyndns2 service)", p.Name)
}

// UpsertLease publishes one A/AAAA via a single dyndns2 GET. The reverse PTR and
// ClientID fields of the record are ignored (dyndns2 is a forward-only consumer
// protocol; the firewall owns its own name).
func (b *dyndns2Backend) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
	u, err := url.Parse(b.endpoint)
	if err != nil {
		return fmt.Errorf("ddns dyndns2: bad endpoint: %w", err)
	}
	q := u.Query()
	q.Set("hostname", rec.FQDN)
	q.Set("myip", rec.Addr.Unmap().String())
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("ddns dyndns2: build request: %w", err)
	}
	// Basic auth via the header (set explicitly, NOT in the URL userinfo, so the
	// password never lands in a logged URL string).
	if b.username != "" || b.password != "" {
		req.SetBasicAuth(b.username, b.password)
	}
	req.Header.Set("User-Agent", "xpf-ddns/1.0")

	code, body, err := doRequest(ctx, b.client, req)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		// dyndns2 is a 200-with-body protocol; a non-200 is itself the verdict.
		if cerr := classifyHTTPStatus(code); cerr != nil {
			return fmt.Errorf("ddns dyndns2: %s: %w", b.name, cerr)
		}
		return fmt.Errorf("ddns dyndns2: %s: unexpected status %d", b.name, code)
	}
	return parseDyndns2Response(string(body), b.name)
}

// DeleteLease is a no-op for dyndns2: the protocol has no portable delete verb,
// and pointing the record at a bogus address (some providers' offline trick) is
// a foot-gun we will not do implicitly. The Surface A engine treats a no-op
// backend's withdraw as a non-success that keeps ownership for retry, but a
// dyndns2 binding removed from config has nothing safe to do remotely, so we log
// once and report success (no ownership orphan: the operator removed the binding
// knowingly; the record ages out via the provider's record TTL / liveness reap).
func (b *dyndns2Backend) DeleteLease(_ context.Context, rec LeaseDNSRecord) error {
	// Intentionally not isNopUpdater (that would make withdrawOwnedLocked keep
	// the ownership entry forever). dyndns2 cannot delete; report success so the
	// ownership entry is dropped and the engine stops trying.
	return nil
}

// parseDyndns2Response maps a dyndns2 response body's first status keyword to a
// verdict (plan §3.1; sources help.dyn.com / ddclient wiki):
//   - good / nochg            → success (record set / unchanged)
//   - badauth / !donator      → hard auth failure (errHTTPAuth)
//   - abuse / blocked         → hard abuse lockout (errHTTPAuth — back off hard)
//   - 911 / dnserr           → provider error / rate-limit (errHTTPRateLimited)
//   - nohost / notfqdn / numhost / nofqdn / badagent → config error (hard)
//   - anything else          → unknown (treated as a transient failure)
func parseDyndns2Response(body, name string) error {
	// The status keyword is the first whitespace-delimited token of the first
	// non-empty line ("good 203.0.113.5").
	first := ""
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			first = line
			break
		}
	}
	fields := strings.Fields(first)
	keyword := ""
	if len(fields) > 0 {
		keyword = strings.ToLower(fields[0])
	}
	switch keyword {
	case "good", "nochg":
		return nil
	case "badauth", "!donator":
		return fmt.Errorf("ddns dyndns2: %s: response %q: %w", name, keyword, errHTTPAuth)
	case "abuse", "blocked":
		return fmt.Errorf("ddns dyndns2: %s: response %q (account locked): %w", name, keyword, errHTTPAuth)
	case "911", "dnserr":
		return fmt.Errorf("ddns dyndns2: %s: response %q (provider error): %w", name, keyword, errHTTPRateLimited)
	case "nohost", "notfqdn", "numhost", "nofqdn", "badagent":
		return fmt.Errorf("ddns dyndns2: %s: response %q (hostname/request rejected)", name, keyword)
	default:
		return fmt.Errorf("ddns dyndns2: %s: unrecognized response %q", name, first)
	}
}
