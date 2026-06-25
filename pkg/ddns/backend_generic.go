package ddns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// backend_generic.go: the generic-templated HTTP DDNS backend (#2691 P3, plan
// §3.7 idea #3 — inadyn "custom"). CONFIG-ONLY: an operator supports a provider
// xpf has no coded backend for by supplying a URL template + a success-substring
// matcher, with NO new Go code per provider. This is the highest-leverage P3
// feature — it covers the long tail of niche DDNS services.
//
// The template uses inadyn's format specifiers (plan §3.1):
//
//	%h → hostname (the FQDN)        %i → IP address (the observed addr)
//	%u → username                  %p → password
//	%% → a literal percent sign
//
// Success is decided by SUBSTRING match on the (HTTP 2xx) response body against
// the operator's `ok-response` (or the default matcher set). This mirrors
// inadyn's default {"OK","good","true","updated","nochg"} list.

// defaultGenericOKSubstrings is the success-matcher set used when a generic
// provider sets no explicit ok-response (plan §3.1). Case-insensitive.
var defaultGenericOKSubstrings = []string{"good", "nochg", "ok", "true", "updated"}

// genericBackend publishes via a templated URL + substring success match.
type genericBackend struct {
	name        string
	urlTemplate string
	okSubstr    []string // success substrings (lowercased)
	username    string
	password    string // revealed at construction; never logged
	client      *http.Client
}

// newGenericBackend resolves a provider-catalog entry into a live generic
// backend. A missing url-template is a hard error (nothing to do) so the manager
// falls back to no-op rather than silently publishing nothing.
func newGenericBackend(p *config.DDNSProvider) (*genericBackend, error) {
	if p == nil {
		return nil, fmt.Errorf("ddns generic: nil provider")
	}
	tmpl := strings.TrimSpace(p.URLTemplate)
	if tmpl == "" {
		return nil, fmt.Errorf("ddns generic: provider %q has no url-template", p.Name)
	}
	if !strings.HasPrefix(tmpl, "http://") && !strings.HasPrefix(tmpl, "https://") {
		return nil, fmt.Errorf("ddns generic: provider %q url-template must be an http(s) URL", p.Name)
	}
	ok := defaultGenericOKSubstrings
	if s := strings.TrimSpace(p.OKResponse); s != "" {
		ok = []string{strings.ToLower(s)}
	}
	return &genericBackend{
		name:        p.Name,
		urlTemplate: tmpl,
		okSubstr:    ok,
		username:    p.Username,
		password:    p.Password.Reveal(),
		client:      newHTTPClient(),
	}, nil
}

// renderGenericURL expands the inadyn-style template specifiers. %u/%p are
// URL-query-escaped so a credential or hostname with reserved characters does
// not break the URL. %% is a literal percent. An unknown %x is left verbatim.
func renderGenericURL(tmpl, host, ip, user, pass string) string {
	var sb strings.Builder
	sb.Grow(len(tmpl) + 32)
	for i := 0; i < len(tmpl); i++ {
		c := tmpl[i]
		if c != '%' || i+1 >= len(tmpl) {
			sb.WriteByte(c)
			continue
		}
		i++
		switch tmpl[i] {
		case 'h':
			sb.WriteString(queryEscape(host))
		case 'i':
			sb.WriteString(queryEscape(ip))
		case 'u':
			sb.WriteString(queryEscape(user))
		case 'p':
			sb.WriteString(queryEscape(pass))
		case '%':
			sb.WriteByte('%')
		default:
			// Unknown specifier: keep both bytes verbatim.
			sb.WriteByte('%')
			sb.WriteByte(tmpl[i])
		}
	}
	return sb.String()
}

// UpsertLease publishes via the rendered template URL.
func (b *genericBackend) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
	rawURL := renderGenericURL(b.urlTemplate, rec.FQDN, rec.Addr.Unmap().String(), b.username, b.password)
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		// SECURITY: a build-request error (url.Parse) embeds the offending URL,
		// which carries the %p-expanded password in the query — do NOT propagate
		// the raw URL. Report the error class only (the operator can see the
		// template in config; the EXPANDED secret must not reach a log/error).
		return fmt.Errorf("ddns generic: %s: malformed rendered update URL (redacted)", b.name)
	}
	// If the operator also set username/password (and did NOT thread them through
	// the template), offer them via Basic auth too — harmless if the server
	// ignores it, and it keeps the secret out of a logged URL.
	if b.username != "" || b.password != "" {
		req.SetBasicAuth(b.username, b.password)
	}
	req.Header.Set("User-Agent", "xpf-ddns/1.0")

	code, body, err := doRequest(ctx, b.client, req)
	if err != nil {
		return err
	}
	if cerr := classifyHTTPStatus(code); cerr != nil {
		return fmt.Errorf("ddns generic: %s: %w", b.name, cerr)
	}
	lower := strings.ToLower(string(body))
	for _, sub := range b.okSubstr {
		if strings.Contains(lower, sub) {
			return nil
		}
	}
	return fmt.Errorf("ddns generic: %s: response did not match success substring(s) %v", b.name, b.okSubstr)
}

// errGenericDeleteUnsupported marks the generic backend's lack of a portable
// withdraw verb (#2772). A single inadyn-style update template carries no notion
// of "remove this record", and xpf exposes no per-provider delete template, so
// there is nothing safe to send. Wrapped (never bare) so a caller can errors.Is
// it and surface the abandoned record rather than treat it as a generic failure.
var errGenericDeleteUnsupported = errors.New("ddns generic: backend has no delete/withdraw operation")

// DeleteLease FAILS for the generic backend (#2772): a templated update protocol
// has no portable delete verb, and xpf has no per-provider delete template, so
// the backend cannot actually clear the record. The previous implementation was
// a no-op that returned nil — the Surface A engine then dropped local ownership
// while the public record kept resolving forever. Returning a non-nil error
// makes the engine increment deleteFail and KEEP the ownership entry, so the
// stale/abandoned record stays operator-visible (it shows up as a withdraw that
// did not complete) instead of being silently reported as withdrawn. An operator
// who needs an actual withdraw must use a backend that supports one (dyndns2's
// offline verb, cloudflare/route53 DELETE, or rfc2136) and clear the record at
// the provider out of band.
func (b *genericBackend) DeleteLease(_ context.Context, rec LeaseDNSRecord) error {
	return fmt.Errorf("ddns generic: %s: cannot withdraw %s %s: %w",
		b.name, rec.ForwardType, rec.FQDN, errGenericDeleteUnsupported)
}
