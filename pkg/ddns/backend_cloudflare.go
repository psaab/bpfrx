package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// backend_cloudflare.go: the Cloudflare API DDNS backend (#2691 P3, plan
// §5.2). Authenticates with an API TOKEN (Authorization: Bearer) and publishes a
// single A/AAAA record through the Cloudflare DNS API. The flow mirrors inadyn's
// `setup`+`request` model:
//
//  1. setup  — resolve the zone id from the configured zone name (GET /zones).
//  2. find   — GET /zones/{zid}/dns_records?type=&name= for the existing record.
//  3. update — PATCH the existing record's content, OR POST a new record.
//
// Rate-limit discipline (plan §8.3): the Surface A engine only calls Upsert on a
// CHANGE or a forced-refresh, so a steady WAN address generates at most one
// Cloudflare update per forced-refresh interval — far under the ~1200 req/5min
// limit. A 429 is classified errHTTPRateLimited and the engine backs off.
//
// Implements the SAME DNSUpdater interface as rfc2136; the Surface A engine
// drives it identically.

// cloudflareAPIBase is the production API root. Overridable per-instance (the
// apiBase field) so httptest can point the backend at a mock server.
const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// cloudflareBackend publishes a single record via the Cloudflare API.
type cloudflareBackend struct {
	name    string
	apiBase string
	token   string // revealed at construction; never logged
	zone    string // zone NAME (e.g. example.net); id resolved at update time
	client  *http.Client
}

// newCloudflareBackend resolves a provider-catalog entry into a live Cloudflare
// backend. A missing api-token or zone is a hard error so the manager falls back
// to no-op (logged) rather than issuing unauthenticated requests. A non-nil
// client is reused (the cached reconcile-path client, #2904); nil builds a
// fresh bound client.
func newCloudflareBackend(p *config.DDNSProvider, client *http.Client) (*cloudflareBackend, error) {
	if p == nil {
		return nil, fmt.Errorf("ddns cloudflare: nil provider")
	}
	token := p.APIToken.Reveal()
	if token == "" {
		return nil, fmt.Errorf("ddns cloudflare: provider %q has no api-token", p.Name)
	}
	if strings.TrimSpace(p.Zone) == "" {
		return nil, fmt.Errorf("ddns cloudflare: provider %q has no zone", p.Name)
	}
	base := cloudflareAPIBase
	if s := strings.TrimSpace(p.Server); s != "" {
		base = strings.TrimRight(s, "/")
	}
	// Bind the dial to the configured source-address/interface/VRF (#2846). A
	// malformed source-address is a hard error so we degrade to no-op rather than
	// publish from the wrong source. A cached client (#2904) is reused when the
	// reconcile path supplies one; nil builds a fresh bound client.
	client, err := ensureProviderHTTPClient(p, client)
	if err != nil {
		return nil, fmt.Errorf("ddns cloudflare: provider %q: %w", p.Name, err)
	}
	return &cloudflareBackend{
		name:    p.Name,
		apiBase: base,
		token:   token,
		zone:    strings.TrimSuffix(strings.TrimSpace(p.Zone), "."),
		client:  client,
	}, nil
}

// cfEnvelope is the common Cloudflare response envelope.
type cfEnvelope struct {
	Success bool            `json:"success"`
	Errors  []cfMessage     `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

// cfErrors formats the envelope errors WITHOUT leaking the token (which is only
// ever in the request header, never echoed by Cloudflare).
func cfErrors(env cfEnvelope) string {
	if len(env.Errors) == 0 {
		return "unknown error"
	}
	parts := make([]string, 0, len(env.Errors))
	for _, e := range env.Errors {
		parts = append(parts, fmt.Sprintf("%d:%s", e.Code, e.Message))
	}
	return strings.Join(parts, "; ")
}

// do issues an authenticated Cloudflare API request and decodes the envelope.
func (b *cloudflareBackend) do(ctx context.Context, method, path string, body any) (cfEnvelope, error) {
	var rdr *bytes.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return cfEnvelope{}, fmt.Errorf("ddns cloudflare: marshal body: %w", err)
		}
		rdr = bytes.NewReader(buf)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, b.apiBase+path, rdr)
	if err != nil {
		return cfEnvelope{}, fmt.Errorf("ddns cloudflare: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xpf-ddns/1.0")

	code, raw, err := doRequest(ctx, b.client, req)
	if err != nil {
		return cfEnvelope{}, err
	}
	if cerr := classifyHTTPStatus(code); cerr != nil {
		return cfEnvelope{}, fmt.Errorf("ddns cloudflare: %s: %w", b.name, cerr)
	}
	var env cfEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return cfEnvelope{}, fmt.Errorf("ddns cloudflare: %s: decode response: %w", b.name, err)
	}
	if !env.Success {
		return env, fmt.Errorf("ddns cloudflare: %s: API error: %s", b.name, cfErrors(env))
	}
	return env, nil
}

// resolveZoneID fetches the zone id for the configured zone name (the setup step).
func (b *cloudflareBackend) resolveZoneID(ctx context.Context) (string, error) {
	q := url.Values{}
	q.Set("name", b.zone)
	env, err := b.do(ctx, http.MethodGet, "/zones?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	var zones []cfZone
	if err := json.Unmarshal(env.Result, &zones); err != nil {
		return "", fmt.Errorf("ddns cloudflare: %s: decode zones: %w", b.name, err)
	}
	for _, z := range zones {
		if strings.EqualFold(z.Name, b.zone) {
			return z.ID, nil
		}
	}
	return "", fmt.Errorf("ddns cloudflare: %s: zone %q not found for this token", b.name, b.zone)
}

// listRecords returns ALL A/AAAA records Cloudflare holds for the FQDN+type.
// Returning the full set (rather than recs[0]) is the basis for both the
// upsert content-match and — critically — the ownership-scoped delete: a name
// can carry several records of one type, and recs[0] is an API-ordering
// artifact, not a statement of which row xpf owns (#2770).
func (b *cloudflareBackend) listRecords(ctx context.Context, zoneID, rtype, fqdn string) ([]cfRecord, error) {
	q := url.Values{}
	q.Set("type", rtype)
	q.Set("name", strings.TrimSuffix(fqdn, "."))
	env, err := b.do(ctx, http.MethodGet, "/zones/"+zoneID+"/dns_records?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var recs []cfRecord
	if err := json.Unmarshal(env.Result, &recs); err != nil {
		return nil, fmt.Errorf("ddns cloudflare: %s: decode records: %w", b.name, err)
	}
	return recs, nil
}

// findRecord returns ONE existing A/AAAA record for the FQDN+type to update, or
// (zero, false) when none exists. It prefers the row whose content already
// equals wantContent (so a re-publish is a no-op) and otherwise returns the
// first record (the row to PATCH to the new content). Used only by the upsert
// path — the delete path re-derives ownership from content and must NOT
// collapse to a single record.
func (b *cloudflareBackend) findRecord(ctx context.Context, zoneID, rtype, fqdn, wantContent string) (cfRecord, bool, error) {
	recs, err := b.listRecords(ctx, zoneID, rtype, fqdn)
	if err != nil {
		return cfRecord{}, false, err
	}
	if len(recs) == 0 {
		return cfRecord{}, false, nil
	}
	for _, rec := range recs {
		if rec.Content == wantContent {
			return rec, true, nil
		}
	}
	return recs[0], true, nil
}

// UpsertLease publishes the A/AAAA: resolve zone id, find the record, PATCH its
// content if present else POST a new one.
func (b *cloudflareBackend) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
	zoneID, err := b.resolveZoneID(ctx)
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(rec.FQDN, ".")
	content := rec.Addr.Unmap().String()
	ttl := rec.TTL
	if ttl <= 0 {
		ttl = 1 // Cloudflare TTL=1 means "automatic".
	}
	existing, found, err := b.findRecord(ctx, zoneID, rec.ForwardType, name, content)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"type":    rec.ForwardType,
		"name":    name,
		"content": content,
		"ttl":     ttl,
	}
	if found {
		if existing.Content == content {
			// Already correct — no write (extra ban-avoidance on top of the
			// engine's change-detection).
			return nil
		}
		_, err = b.do(ctx, http.MethodPatch, "/zones/"+zoneID+"/dns_records/"+existing.ID, payload)
		return err
	}
	_, err = b.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", payload)
	return err
}

// DeleteLease removes the firewall's OWN A/AAAA from Cloudflare: resolve zone
// id, list every record for the FQDN+type, and DELETE only the rows whose
// content equals the owned address (rec.Addr.Unmap().String()).
//
// This honours the Surface A sole-delete-authority boundary
// (withdrawOwnedLocked re-derives the delete from the EXACT owned tuple): xpf
// never deletes a name+value it did not record. recs[0] is an API-ordering
// artifact, so a content-blind delete of the first match would clobber a value
// a human/automation later set on the same name (#2770). Multiple owned rows
// with the same content are all removed (not just the first). A record that is
// already gone — or where no row matches the owned content (ownership conflict)
// — is a success no-op: the wire is already in (or never reached) the desired
// state, and deleting a foreign value would itself be the bug.
func (b *cloudflareBackend) DeleteLease(ctx context.Context, rec LeaseDNSRecord) error {
	zoneID, err := b.resolveZoneID(ctx)
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(rec.FQDN, ".")
	owned := rec.Addr.Unmap().String()
	recs, err := b.listRecords(ctx, zoneID, rec.ForwardType, name)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r.Content != owned {
			continue
		}
		if _, err := b.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+r.ID, nil); err != nil {
			return err
		}
	}
	return nil
}
