package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Three arms of the #5719/#6827 stale-management-cert diagnostic that the
// hostile review of #6827 found UNBOUND — the code is correct, and a 28-cell
// deletion sweep over that PR's pkg/api delta left these four green.
//
// They are one file because they are one function's terminal ladder
// (Server.WarnStaleMgmtCertForHostName -> warnCertNoSANs -> warnStaleHostName)
// and each cell has to distinguish "the ladder stopped here" from "the ladder
// ran on", which is a property of the ladder, not of any single rung.

// certNoSANs mints a self-signed leaf carrying NO subjectAltName at all — no
// DNSNames, no IPAddresses. generateSelfSignedCertAt cannot produce this
// (it always mints SANs), which is exactly why the arm that handles it had no
// fixture (#7044).
func certNoSANs(t *testing.T, commonName string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7044),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse minted certificate: %v", err)
	}
	if !certHasNoSANs(leaf) {
		t.Fatalf("fixture is wrong: the minted certificate carries SANs (dns=%v ip=%v), "+
			"so it cannot exercise the no-SANs arm", leaf.DNSNames, leaf.IPAddresses)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// #7043: an unparseable leaf must report the question ANSWERED (true), not
// unanswered.
//
// `return true` -> `return false` was a total survivor in both pkg/api and
// pkg/daemon. The contract is stated two lines above the return — "re-parsing it
// later will fail identically, so report it answered rather than making the
// caller retry forever" — and a flip turns the caller into a permanent retry
// loop against a certificate that will never parse.
func TestUnparseableCertReportsTheQuestionAnswered_7043(t *testing.T) {
	// Deliberately not a truncated real certificate: bytes that cannot begin a
	// DER SEQUENCE make the parse failure unambiguous, so the cell cannot pass
	// because some other arm returned first.
	garbage := tls.Certificate{Certificate: [][]byte{{0xff, 0xff, 0xff, 0xff}}}
	s := legServing(garbage, "127.0.0.1:8443")

	var answered bool
	out := captureWarn(t, func() { answered = s.WarnStaleMgmtCertForHostName("new-fw") })

	if !answered {
		t.Error("WarnStaleMgmtCertForHostName returned false for a leg serving an UNPARSEABLE " +
			"certificate; the question was reached and re-parsing will fail identically, so the " +
			"caller is left retrying forever (#7043)")
	}
	// The ladder must STOP here. Anything below dereferences a leaf that does
	// not exist, so a warning from a lower rung means the arm did not return.
	if strings.Contains(out, "does not cover") {
		t.Errorf("a per-identity warning was emitted for an unparseable certificate, so the "+
			"terminal arm did not return: %s", out)
	}
}

// #7044: the no-SANs arm is terminal at the RENAME call site too, not only on
// the load path.
//
// Neutralising the early return was a total survivor: the property IS bound, at
// the SIBLING call site, and the identical shape here was covered by nothing.
// The behaviour is documented as deliberate at server.go: with no SANs at all,
// the per-identity warnings would each report "does not cover X" for a
// certificate that covers no X whatsoever, burying the actual finding under a
// list of symptoms.
func TestNoSANsIsTerminalAtTheRenameCallSite_7044(t *testing.T) {
	s := legServing(certNoSANs(t, "old-fw"), "127.0.0.1:8443")

	var answered bool
	out := captureWarn(t, func() { answered = s.WarnStaleMgmtCertForHostName("new-fw") })

	if !answered {
		t.Error("WarnStaleMgmtCertForHostName returned false for a no-SANs certificate (#7044)")
	}
	// POSITIVE CONTROL. Without it a fix that emitted NOTHING would satisfy the
	// suppression assertion below, and the arm would be "bound" by a cell that
	// cannot tell silence from correctness.
	if !strings.Contains(out, "carries NO subjectAltName") {
		t.Errorf("the no-SANs finding was not reported at all: %s", out)
	}
	if strings.Contains(out, "does not cover") {
		t.Errorf("a per-identity `does not cover` warning was emitted alongside the no-SANs "+
			"finding, burying it under a list of symptoms — the arm is not terminal here (#7044): %s", out)
	}
}

// #7045: the `hostName == bindHost` conjunct in warnStaleHostName.
//
// Dropping it was green in BOTH polarities of the observable — the rename path
// goes from zero warnings to one, and no cell noticed either direction. A
// suppression conjunct going wrong is precisely how a diagnostic turns into
// duplicate noise, and duplicate noise is how the real finding gets skimmed
// past.
//
// The fixture makes hostName EQUAL bindHost and the certificate cover neither,
// so every other early return in warnStaleHostName is passed: the conjunct is
// the only thing that can suppress the warning. That is what makes the cell
// sensitive — with the certificate covering the host, `certCoversHost` would
// return first and the conjunct would be dominated.
func TestHostNameEqualToBindHostIsSuppressed_7045(t *testing.T) {
	const shared = "fw.example.net"
	// Covers something else entirely, so certCoversHost(leaf, shared) is false.
	cert := mintCert(t, "other-fw.example.net", "10.9.9.9")
	s := legServing(cert, shared+":8443")

	out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName(shared) })

	if strings.Contains(out, "does not cover the current host-name") {
		t.Errorf("the host-name warning fired for a host name EQUAL to the bind host; the same "+
			"identity is reported twice, once as bind host and once as host name (#7045): %s", out)
	}

	// The other polarity, so the suppression cannot be "warns about nothing".
	// A DIFFERENT host name, uncovered, must still warn — otherwise deleting
	// the whole warning would pass the assertion above.
	out2 := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("renamed-fw.example.net") })
	if !strings.Contains(out2, "does not cover the current host-name") {
		t.Errorf("a host name DIFFERENT from the bind host and uncovered by the certificate drew "+
			"no warning, so the suppression above is indistinguishable from the diagnostic being "+
			"dead: %s", out2)
	}
}
