package config

import (
	"strings"
	"testing"
)

// #7511: the raw-AST redaction pass leaked an archive-site URL credential and
// the inline archival password.
//
// #7510 fixed the TYPED half — a marshaller per owning type, plus a reflective
// census. Neither reaches these two: the syslog `archive-sites` URL lives only
// in the raw AST and is never promoted to a typed field, so no `MarshalJSON`
// sees it, and the generic `password` key was masked only under `api-auth` or
// `dynamic-dns`.
//
// Measured at master before the fix, both verbatim:
//
//	in : set system syslog file audit archive archive-sites "scp://user:pw@host/dir"
//	out: set system syslog file audit archive archive-sites "scp://user:pw@host/dir"
//	in : set ... archive-sites "scp://host/dir" password "s3cr3t"
//	out: set ... archive-sites scp://host/dir password s3cr3t
//
// ASSERTED ON THE RENDERED OUTPUT, not on the presence of a redaction rule —
// an existence check is what let the typed half hide, and the acceptance
// criteria say so explicitly.

func renderRedacted7511(t *testing.T, lines ...string) string {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	return tree.RedactedClone().FormatSet()
}

func TestArchiveSitesURLCredentialIsRedacted7511(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"syslog file archive", `set system syslog file audit archive archive-sites "scp://user:pw@host/dir"`},
		{"archival configuration", `set system archival configuration archive-sites "scp://user:pw@host/dir"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := renderRedacted7511(t, tc.line)
			if strings.Contains(got, "pw@") || strings.Contains(got, "user:pw") {
				t.Errorf("the archive-site URL credential is rendered verbatim:\n%s\n"+
					"This URL lives only in the raw AST and is never promoted to a typed "+
					"field, so #7510's typed pass and its census cannot see it (#7511)", got)
			}
			// NON-VACUITY: the host and path must survive. A redaction that
			// dropped the whole value would pass the assertion above and make
			// `show configuration` useless for the leaf it is redacting.
			if !strings.Contains(got, "host/dir") {
				t.Errorf("the host/path was destroyed along with the credential:\n%s", got)
			}
		})
	}
}

func TestArchivalInlinePasswordIsMasked7511(t *testing.T) {
	got := renderRedacted7511(t,
		`set system archival configuration archive-sites "scp://host/dir" password "s3cr3t"`)
	if strings.Contains(got, "s3cr3t") {
		t.Errorf("the inline archival password is rendered in full:\n%s\n"+
			"The generic `password` key was masked only under api-auth or "+
			"dynamic-dns; archive-sites matched neither (#7511)", got)
	}
	if !strings.Contains(got, SecretDataPlaceholder) {
		t.Errorf("the password was removed but not MASKED; the render must show the "+
			"placeholder so an operator can tell a redacted secret from an absent "+
			"one:\n%s", got)
	}
	// The URL beside it must still render — the two rules must not overlap.
	if !strings.Contains(got, "scp://host/dir") {
		t.Errorf("the archive-site URL was consumed by the password rule:\n%s", got)
	}
}

// NO OVER-REDACTION. The acceptance criteria call this out separately, and it
// needs its own check on the raw side because the values reaching this pass are
// LEXER TOKENS, not typed strings — #7510 measured it only for RedactURL on
// typed input.
func TestArchiveSitesWithoutCredentialIsUnchanged7511(t *testing.T) {
	for _, tc := range []struct{ name, url string }{
		{"bare scp host and dir", "scp://host/dir"},
		{"scp with explicit port-style path", "scp://host:/dir"},
		{"ftp with no userinfo", "ftp://archive.example.net/logs"},
		{"plain path", "/var/tmp/archive"},
		{"host only", "archive.example.net"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := renderRedacted7511(t,
				`set system archival configuration archive-sites "`+tc.url+`"`)
			if !strings.Contains(got, tc.url) {
				t.Errorf("a credential-free archive-site value was altered.\nwant it to "+
					"contain %q, got:\n%s\nRedactURL is a no-op on non-URL input by "+
					"measurement, so a change here means the token was mangled before "+
					"it reached RedactURL", tc.url, got)
			}
			if strings.Contains(got, "<redacted>") {
				t.Errorf("a credential-free value was redacted anyway:\n%s", got)
			}
		})
	}
}

// The `password` widening must not leak into the scopes it was deliberately
// kept out of. Without this, "mask password under archive-sites" is
// indistinguishable from "mask every password", and the context gate the
// original comment describes — keeping a future non-secret `password`
// unmasked — is silently gone.
func TestPasswordScopingIsStillContextual7511(t *testing.T) {
	got := renderRedacted7511(t,
		`set system archival configuration archive-sites "scp://host/dir" password "s3cr3t"`,
		`set system services rest-api api-auth password "apipw"`)
	if strings.Contains(got, "s3cr3t") || strings.Contains(got, "apipw") {
		t.Errorf("a scoped password leaked:\n%s", got)
	}
	if strings.Count(got, SecretDataPlaceholder) != 2 {
		t.Errorf("expected exactly two masked passwords, got %d:\n%s",
			strings.Count(got, SecretDataPlaceholder), got)
	}
}
