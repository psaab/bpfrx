package ddns

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// backend_route53.go: the AWS Route 53 DDNS backend (#2691 P3, plan §5.2). Uses
// a SigV4-signed ChangeResourceRecordSets request with action UPSERT — the
// idempotent "create or replace" Route 53 verb that exactly matches the DDNS
// publish semantic (one record, one address, replace on change). A DELETE action
// withdraws the record on binding removal / address loss.
//
// SigV4 is implemented in sigv4.go (a minimal signer — no AWS SDK dependency;
// plan §5.2 open question resolved toward the minimal signer since we sign ONE
// API shape). Rate-limit discipline (plan §8.3): Route 53 is 5 req/s/account;
// the engine's change-only + forced-refresh cadence keeps us far under that, and
// a 429/throttle classifies errHTTPRateLimited so the engine backs off.
//
// Implements the SAME DNSUpdater interface as rfc2136; the engine drives it
// identically.

// route53Endpoint is the Route 53 API host. Route 53 is a global service signed
// in us-east-1. Overridable per-instance (the endpoint field) for httptest.
const route53Endpoint = "https://route53.amazonaws.com"

// route53APIVersion is the Route 53 REST API version path prefix.
const route53APIVersion = "2013-04-01"

// route53Backend publishes a single record via Route 53 ChangeResourceRecordSets.
type route53Backend struct {
	name     string
	endpoint string
	zoneID   string
	creds    sigv4Credentials
	client   *http.Client
	now      func() time.Time
}

// newRoute53Backend resolves a provider-catalog entry into a live Route 53
// backend. Missing access key / secret / hosted-zone-id are hard errors so the
// manager falls back to no-op (logged) rather than issuing unsigned requests.
func newRoute53Backend(p *config.DDNSProvider) (*route53Backend, error) {
	if p == nil {
		return nil, fmt.Errorf("ddns route53: nil provider")
	}
	secret := p.AWSSecretAccessKey.Reveal()
	if p.AWSAccessKeyID == "" || secret == "" {
		return nil, fmt.Errorf("ddns route53: provider %q is missing aws-access-key / aws-secret-key", p.Name)
	}
	if strings.TrimSpace(p.HostedZoneID) == "" {
		return nil, fmt.Errorf("ddns route53: provider %q has no hosted-zone-id", p.Name)
	}
	region := strings.TrimSpace(p.AWSRegion)
	if region == "" {
		region = "us-east-1" // Route 53 is signed in us-east-1.
	}
	endpoint := route53Endpoint
	if s := strings.TrimSpace(p.Server); s != "" {
		endpoint = strings.TrimRight(s, "/")
	}
	return &route53Backend{
		name:     p.Name,
		endpoint: endpoint,
		zoneID:   normalizeHostedZoneID(p.HostedZoneID),
		creds: sigv4Credentials{
			accessKeyID:     p.AWSAccessKeyID,
			secretAccessKey: secret,
			region:          region,
			service:         "route53",
		},
		client: newHTTPClient(),
		now:    time.Now,
	}, nil
}

// normalizeHostedZoneID strips the "/hostedzone/" prefix Route 53 sometimes
// reports so the operator can paste either form.
func normalizeHostedZoneID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "/hostedzone/")
	return id
}

// changeBatchXML is the ChangeResourceRecordSets request body.
type changeBatchXML struct {
	XMLName     xml.Name `xml:"https://route53.amazonaws.com/doc/2013-04-01/ ChangeResourceRecordSetsRequest"`
	ChangeBatch struct {
		Changes struct {
			Change []r53Change `xml:"Change"`
		} `xml:"Changes"`
	} `xml:"ChangeBatch"`
}

type r53Change struct {
	Action            string `xml:"Action"`
	ResourceRecordSet struct {
		Name            string `xml:"Name"`
		Type            string `xml:"Type"`
		TTL             int    `xml:"TTL"`
		ResourceRecords struct {
			ResourceRecord []struct {
				Value string `xml:"Value"`
			} `xml:"ResourceRecord"`
		} `xml:"ResourceRecords"`
	} `xml:"ResourceRecordSet"`
}

// r53ErrorXML is the Route 53 error response envelope.
type r53ErrorXML struct {
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// buildChangeBatch builds the UPSERT (or DELETE) change batch for a record.
func buildChangeBatch(action string, rec LeaseDNSRecord) ([]byte, error) {
	ttl := rec.TTL
	if ttl <= 0 {
		ttl = defaultDDNSTTL
	}
	var batch changeBatchXML
	var c r53Change
	c.Action = action
	c.ResourceRecordSet.Name = strings.TrimSuffix(rec.FQDN, ".") + "."
	c.ResourceRecordSet.Type = rec.ForwardType
	c.ResourceRecordSet.TTL = ttl
	rr := struct {
		Value string `xml:"Value"`
	}{Value: rec.Addr.Unmap().String()}
	c.ResourceRecordSet.ResourceRecords.ResourceRecord = append(
		c.ResourceRecordSet.ResourceRecords.ResourceRecord, rr)
	batch.ChangeBatch.Changes.Change = []r53Change{c}
	out, err := xml.Marshal(&batch)
	if err != nil {
		return nil, fmt.Errorf("ddns route53: marshal change batch: %w", err)
	}
	return append([]byte(xml.Header), out...), nil
}

// change issues a signed ChangeResourceRecordSets with the given action. When
// the request fails, the parsed Route 53 error code/message (never the creds)
// is returned alongside the typed transport error so DELETE-path idempotency
// classification (r53DeleteAlreadyGone) can inspect the on-wire code/message.
func (b *route53Backend) change(ctx context.Context, action string, rec LeaseDNSRecord) (errCode, errMsg string, err error) {
	body, err := buildChangeBatch(action, rec)
	if err != nil {
		return "", "", err
	}
	path := "/" + route53APIVersion + "/hostedzone/" + b.zoneID + "/rrset/"
	req, err := http.NewRequest(http.MethodPost, b.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("ddns route53: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("User-Agent", "xpf-ddns/1.0")
	signRequest(req, b.creds, body, b.now())

	code, raw, err := doRequest(ctx, b.client, req)
	if err != nil {
		return "", "", err
	}
	if cerr := classifyHTTPStatus(code); cerr != nil {
		// Surface the Route 53 error code/message when present (never the creds).
		var e r53ErrorXML
		if xml.Unmarshal(raw, &e) == nil && e.Error.Code != "" {
			return e.Error.Code, e.Error.Message, fmt.Errorf("ddns route53: %s: %s: %s: %w", b.name, e.Error.Code, e.Error.Message, cerr)
		}
		return "", "", fmt.Errorf("ddns route53: %s: %w", b.name, cerr)
	}
	return "", "", nil
}

// UpsertLease publishes the A/AAAA via a Route 53 UPSERT (create-or-replace).
func (b *route53Backend) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
	_, _, err := b.change(ctx, "UPSERT", rec)
	return err
}

// DeleteLease withdraws the A/AAAA via a Route 53 DELETE. Route 53 requires the
// DELETE to match the existing record's TTL + value; we re-derive both from the
// owned record the engine passes (the sole-delete-authority boundary), so the
// delete targets exactly what we published; over-deletion is impossible (exact
// match required).
//
// IDEMPOTENT delete (#2771): if the record is already gone (manually removed,
// or a prior withdraw that did land but whose ack was lost), Route 53 rejects
// the DELETE with HTTP 400 InvalidChangeBatch "... but it was not found".
// Treat that as success (nil) so Surface A's withdrawOwnedLocked drops
// ownership instead of wedging on a withdraw that can never converge. This
// mirrors the rfc2136 backend, which treats NXRRSET/NXDOMAIN as a benign
// idempotent delete (backend_rfc2136.go sendRemove). A genuine
// transient/auth/throttle failure (SignatureDoesNotMatch, 5xx, 429, …) still
// returns non-nil so the engine retries — only the already-gone case is
// swallowed.
func (b *route53Backend) DeleteLease(ctx context.Context, rec LeaseDNSRecord) error {
	errCode, errMsg, err := b.change(ctx, "DELETE", rec)
	if err != nil && r53DeleteAlreadyGone(errCode, errMsg) {
		return nil
	}
	return err
}

// r53DeleteAlreadyGone reports whether a Route 53 DELETE failure means the
// target record set was already absent (an idempotent no-op), as opposed to a
// real failure that must be retried.
//
// Route 53 reports a delete of a non-existent record as a single envelope:
// HTTP 400, Code=InvalidChangeBatch, with a per-change message of the form
//
//	[Tried to delete resource record set [name='wan.example.net.', type='A']
//	 but it was not found]
//
// The Code alone (InvalidChangeBatch) is NOT sufficient — it also covers
// genuine batch errors (e.g. an UPSERT whose value collides). We additionally
// require the "but it was not found" / "was not found" marker, so a malformed
// or conflicting batch (which must keep retrying / surface as a conflict) is
// never mistaken for an idempotent delete.
func r53DeleteAlreadyGone(code, msg string) bool {
	if !strings.EqualFold(strings.TrimSpace(code), "InvalidChangeBatch") {
		return false
	}
	m := strings.ToLower(msg)
	return strings.Contains(m, "but it was not found") ||
		strings.Contains(m, "was not found") ||
		strings.Contains(m, "not found")
}
