package ddns

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// sigv4.go: a minimal, self-contained AWS Signature Version 4 signer for the
// Route 53 backend (#2691 P3, plan §5.2 / open Q "minimal signer vs full AWS
// SDK"). We sign ONE API shape — Route 53 ChangeResourceRecordSets (and the
// occasional ListResourceRecordSets) — so the full AWS SDK (a large dependency
// tree) is unnecessary. This implements the documented SigV4 algorithm:
//
//	https://docs.aws.amazon.com/general/latest/gr/sigv4-signing.html
//
// Correctness is the whole point of this file — a wrong canonical request or
// string-to-sign produces a SignatureDoesNotMatch and silently fails to publish.
// The signer is unit-tested against fixed inputs (sigv4_test.go) so the four
// stages (canonical request → string-to-sign → signing key → signature) are
// each pinned and fail-on-revert.

// sigv4Credentials is the access-key pair + region + service for one signature.
type sigv4Credentials struct {
	accessKeyID     string
	secretAccessKey string // revealed at construction; never logged
	region          string
	service         string // "route53"
}

// hmacSHA256 returns HMAC-SHA256(key, data).
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// sha256Hex returns the lowercase hex SHA-256 of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// signingKey derives the SigV4 signing key for a given date (yyyymmdd).
func (c sigv4Credentials) signingKey(dateStamp string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+c.secretAccessKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(c.region))
	kService := hmacSHA256(kRegion, []byte(c.service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

// canonicalURI returns the URI-encoded path, normalizing an empty path to "/".
// Route 53 paths are already simple (/2013-04-01/hostedzone/{id}/rrset), so we
// encode each segment per RFC 3986 (AWS does NOT double-encode the path for
// route53/s3-style services — but route53 paths contain only unreserved chars +
// '/', so a straightforward per-segment escape is correct and stable).
func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = awsURIEscape(s, false)
	}
	return strings.Join(segs, "/")
}

// awsURIEscape escapes per AWS rules: unreserved (A-Z a-z 0-9 - _ . ~) are
// literal; everything else is %XX. When encodeSlash is false, '/' is kept (path
// component joiner).
func awsURIEscape(s string, encodeSlash bool) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~':
			sb.WriteByte(c)
		case c == '/' && !encodeSlash:
			sb.WriteByte(c)
		default:
			sb.WriteString("%")
			const hexdigits = "0123456789ABCDEF"
			sb.WriteByte(hexdigits[c>>4])
			sb.WriteByte(hexdigits[c&0xf])
		}
	}
	return sb.String()
}

// canonicalQuery returns the sorted, encoded canonical query string.
func canonicalQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ""
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := values[k]
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, awsURIEscape(k, true)+"="+awsURIEscape(v, true))
		}
	}
	return strings.Join(parts, "&")
}

// signRequest applies a SigV4 Authorization header (and the required x-amz-date /
// x-amz-content-sha256 headers) to req for the given body and time. The body is
// passed explicitly (not re-read from req.Body) so the payload hash is exact.
func signRequest(req *http.Request, creds sigv4Credentials, body []byte, now time.Time) {
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	payloadHash := sha256Hex(body)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if req.Header.Get("Host") == "" && req.Host == "" {
		req.Host = req.URL.Host
	}

	// Canonical headers: host + every x-amz-* header, lowercased keys, sorted,
	// trimmed values. Host is taken from req.Host/URL.Host (Go does not surface
	// it in req.Header for an outbound request).
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	headers := map[string]string{"host": strings.TrimSpace(host)}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if lk == "x-amz-date" || lk == "x-amz-content-sha256" || strings.HasPrefix(lk, "x-amz-") {
			headers[lk] = strings.TrimSpace(strings.Join(v, ","))
		}
	}
	signedKeys := make([]string, 0, len(headers))
	for k := range headers {
		signedKeys = append(signedKeys, k)
	}
	sort.Strings(signedKeys)
	var canonHeaders strings.Builder
	for _, k := range signedKeys {
		canonHeaders.WriteString(k)
		canonHeaders.WriteString(":")
		canonHeaders.WriteString(headers[k])
		canonHeaders.WriteString("\n")
	}
	signedHeaders := strings.Join(signedKeys, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.Path),
		canonicalQuery(req.URL.RawQuery),
		canonHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := dateStamp + "/" + creds.region + "/" + creds.service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signature := hex.EncodeToString(hmacSHA256(creds.signingKey(dateStamp), []byte(stringToSign)))

	authz := "AWS4-HMAC-SHA256 " +
		"Credential=" + creds.accessKeyID + "/" + scope + ", " +
		"SignedHeaders=" + signedHeaders + ", " +
		"Signature=" + signature
	req.Header.Set("Authorization", authz)
}
