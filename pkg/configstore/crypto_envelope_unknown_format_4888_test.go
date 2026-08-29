package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestUnmarshalEnvelopeUnknownFormatFailsClosed_4888 pins the fail-closed
// contract of unmarshalEnvelope: an envelope-shaped body with an unknown /
// future `format` (or one carrying AES-GCM fields without our current format)
// MUST be rejected, not treated as plaintext. Only a body with no format and
// no AES-GCM fields is a genuine plaintext body.
func TestUnmarshalEnvelopeUnknownFormatFailsClosed_4888(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantOK  bool
		wantErr bool
	}{
		{
			name: "future format with encrypted fields is rejected",
			body: `{"format":"xpf-master-password-v2","prf":"sha256",` +
				`"salt":"AAAA","nonce":"AAAA","data":"AAAA"}`,
			wantErr: true,
		},
		{
			name:    "encrypted fields without a format are rejected",
			body:    `{"salt":"AAAA","nonce":"AAAA","data":"AAAA"}`,
			wantErr: true,
		},
		{
			name:    "unknown format alone is rejected",
			body:    `{"format":"totally-bogus"}`,
			wantErr: true,
		},
		{
			name:   "genuine plaintext config tree passes through",
			body:   `{"Children":[{"Keys":["system"]}]}`,
			wantOK: false,
		},
		{
			name:   "empty object passes through as plaintext",
			body:   `{}`,
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ok, err := unmarshalEnvelope([]byte(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("unmarshalEnvelope(%s): err=nil, want a fail-closed error", tc.body)
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshalEnvelope(%s): unexpected err %v", tc.body, err)
			}
			if ok != tc.wantOK {
				t.Fatalf("unmarshalEnvelope(%s): ok=%v, want %v", tc.body, ok, tc.wantOK)
			}
		})
	}
}

// TestStoreLoadUnknownInnerEnvelopeFailsClosed_4888 proves the end-to-end
// fail-closed property: an on-disk DB that passes the OUTER #xpf-config-envelope
// gate but whose INNER body is an encrypted envelope with an unknown/future
// `format` is rejected with ErrConfigDBUnreadable, NOT silently decoded to an
// empty ConfigTree (which would boot a committed-empty config and lose policy).
func TestStoreLoadUnknownInnerEnvelopeFailsClosed_4888(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	dbDir := filepath.Join(dir, ".configdb")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Inner body: a future/unknown encrypted-tree format. Pre-fix, this fell
	// through unmarshalEnvelope as "not an envelope" and got parsed as a
	// ConfigTree with all fields dropped -> empty tree, no error.
	inner := `{"format":"xpf-master-password-v2","prf":"sha256",` +
		`"salt":"AAAA","nonce":"AAAA","data":"AAAA"}`
	body := wrapEnvelope([]byte(inner), "9.9.9", true, EnvelopeMinReaderVersion)
	if err := os.WriteFile(filepath.Join(dbDir, "active.json"), body, 0644); err != nil {
		t.Fatal(err)
	}

	s := newTestStoreAt(t, path)
	err := s.Load()
	if err == nil {
		t.Fatal("Load accepted an unknown inner encrypted-envelope format; must fail closed")
	}
	if !errors.Is(err, ErrConfigDBUnreadable) {
		t.Fatalf("Load error not tagged ErrConfigDBUnreadable: %v", err)
	}
}
