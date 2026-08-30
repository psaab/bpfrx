package configstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7176 (C179-053). The envelope header — including the #1922 `committed=`
// marker that gates the bootstrap decision — is plaintext ahead of the
// ciphertext and was sealed with a nil AAD, so it was unauthenticated and
// editable in place. v2 binds the header line into the AES-GCM AAD.
//
// The read side gates on the STORED v=, which is what makes the migration safe
// against a forced downgrade rather than merely convenient.

// newEncDB builds a DB through the real constructor so the master-key path and
// directory layout are the production ones.
func newEncDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), ".configdb"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	db.SetWriterVersion("test-1.0")
	return db
}

func encryptedTree(t *testing.T) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	path, err := config.ParseSetCommand("set system master-password pseudorandom-function sha256")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	// Precondition: without this every cell below is vacuous — a plaintext body
	// "decrypts" under any AAD, so tampering would prove nothing.
	if prf := masterPasswordPRF(tree); prf == "" {
		t.Fatal("fixture broken: nothing would be encrypted, so the AAD cells prove nothing")
	}
	return tree
}

// writeRealActive drives the PRODUCTION write path (WriteActiveMarker ->
// writeTreeMarked) and returns the raw on-disk bytes.
//
// It does NOT re-implement the seal. An earlier version of this file did, and
// every cell below passed while the production path sealed with a nil AAD:
// mutating db.go changed nothing the tests could see. The defect lives in the
// write and read paths, so those are what a test has to drive.
func writeRealActive(t *testing.T, db *DB, tree *config.ConfigTree, committed bool) []byte {
	t.Helper()
	db.SetWriterVersion("test-1.0")
	if err := db.WriteActiveMarker(tree, committed); err != nil {
		t.Fatalf("WriteActiveMarker: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(db.dir, "active.json"))
	if err != nil {
		t.Fatalf("read on-disk active.json: %v", err)
	}
	if !bytes.HasPrefix(raw, []byte(envelopeMagic)) {
		t.Fatalf("fixture broken: on-disk file is not enveloped: %q", raw[:40])
	}
	return raw
}

// rewriteActive puts tampered bytes back and reads them through the PRODUCTION
// read path (ReadActiveMeta -> readTree).
func rewriteActive(t *testing.T, db *DB, raw []byte) error {
	t.Helper()
	if err := os.WriteFile(filepath.Join(db.dir, "active.json"), raw, 0o600); err != nil {
		t.Fatalf("rewrite active.json: %v", err)
	}
	_, _, err := db.ReadActiveMeta()
	return err
}

// The control: a v2 envelope round-trips. Without it every refusal below is
// satisfiable by a decryptor that refuses everything.
func TestEnvelopeAADRoundTrips_7176(t *testing.T) {
	db := newEncDB(t)
	tree := encryptedTree(t)
	raw := writeRealActive(t, db, tree, true)
	// Structural check, not a substring one: the first attempt grepped for
	// "master-password" and matched the encrypted envelope's own format label
	// ("xpf-master-password-v1"), so it fired on a correctly-encrypted body.
	// Ask whether the body IS an encrypted envelope instead.
	body, _, serr := stripEnvelope(raw)
	if serr != nil {
		t.Fatalf("fixture broken: %v", serr)
	}
	if _, ok, uerr := unmarshalEnvelope(body); uerr != nil || !ok {
		t.Fatalf("fixture broken: body is not an encrypted envelope (ok=%v err=%v), so "+
			"the AAD cells prove nothing", ok, uerr)
	}
	if err := rewriteActive(t, db, raw); err != nil {
		t.Fatalf("a freshly written v2 envelope failed to read back: %v", err)
	}
}

// THE POINT OF THE CHANGE: editing the committed= marker in place must break
// decryption. Before v2 this edit was free and flipped the #1922 bootstrap
// decision.
func TestTamperedCommittedMarkerFailsDecryption_7176(t *testing.T) {
	db := newEncDB(t)
	tree := encryptedTree(t)
	raw := writeRealActive(t, db, tree, true)

	tampered := bytes.Replace(raw, []byte("committed=1"), []byte("committed=0"), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("fixture broken: the committed= edit did not apply, so the cell " +
			"would pass without testing anything")
	}
	if err := rewriteActive(t, db, tampered); err == nil {
		t.Fatal("an in-place edit of the committed= marker still decrypted — the " +
			"#1922 bootstrap marker is unauthenticated (#7176 C179-053)")
	}
}

// A FORCED DOWNGRADE must fail closed, not succeed weakly. Rewriting a v2
// header to claim v=1 selects the nil-AAD read path against a ciphertext sealed
// WITH AAD, so the tag check fails. This is what makes the version gate a
// migration rather than a bypass.
func TestForcedVersionDowngradeFailsClosed_7176(t *testing.T) {
	db := newEncDB(t)
	tree := encryptedTree(t)
	raw := writeRealActive(t, db, tree, true)

	downgraded := bytes.Replace(raw,
		[]byte(fmt.Sprintf("v=%d", envelopeAADFormatVersion)), []byte("v=1"), 1)
	if bytes.Equal(downgraded, raw) {
		t.Fatal("fixture broken: the v= rewrite did not apply")
	}
	// It must not be readable AT ALL — neither under the weak path nor the strong one.
	if err := rewriteActive(t, db, downgraded); err == nil {
		t.Fatal("a header rewritten to claim v=1 was accepted — an attacker can force " +
			"the pre-AAD path and the authentication is bypassable (#7176 C179-053)")
	}
}

// MIGRATION: a genuine v1 envelope (body sealed with nil AAD, header stamped
// v=1) must still read, or upgrading strands every existing encrypted DB.
func TestLegacyV1EnvelopeStillReads_7176(t *testing.T) {
	db := newEncDB(t)
	tree := encryptedTree(t)

	realTree := &config.ConfigTree{}
	if path, perr := config.ParseSetCommand("set system master-password pseudorandom-function sha256"); perr != nil {
		t.Fatalf("ParseSetCommand: %v", perr)
	} else if perr := realTree.SetPath(path); perr != nil {
		t.Fatalf("SetPath: %v", perr)
	}
	plain, merr := json.MarshalIndent(realTree, "", "  ")
	if merr != nil {
		t.Fatalf("marshal: %v", merr)
	}
	body, err := db.maybeEncryptTreeJSON(plain, tree, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	v1Header := []byte("#xpf-config-envelope v=1 writer=old-1.0 ast=1 min-reader=1 rollback-fmt=1 committed=1\n")
	raw := append(append([]byte{}, v1Header...), body...)

	// Read through the PRODUCTION path. A v1 envelope must open with nil AAD.
	if err := rewriteActive(t, db, raw); err != nil {
		t.Fatalf("a legacy v1 envelope failed to read: %v — upgrading would strand "+
			"every existing encrypted config DB", err)
	}
}

// min-reader is raised ONLY for an encrypted envelope. An unencrypted v2
// envelope has no ciphertext to bind, so stamping the floor on it would refuse
// a downgrade for no reason.
func TestMinReaderRaisedOnlyWhenEncrypted_7176(t *testing.T) {
	// Drives the PRODUCTION write path for both tree shapes and reads the
	// stamped header off disk. The first version of this cell called
	// buildEnvelopeHeaderLine directly with hand-picked arguments, so making the
	// write path stamp the floor unconditionally left it green — it asserted the
	// builder does what it is told, which was never in doubt.
	encDB := newEncDB(t)
	encRaw := writeRealActive(t, encDB, encryptedTree(t), true)
	encHdr := string(encRaw[:bytes.IndexByte(encRaw, '\n')])
	if !strings.Contains(encHdr, fmt.Sprintf("min-reader=%d", envelopeAADFormatVersion)) {
		t.Errorf("encrypted envelope header %q must raise the min-reader floor to %d, or a "+
			"pre-v2 build reports an opaque decrypt failure instead of \"too new\"",
			encHdr, envelopeAADFormatVersion)
	}

	plainDB := newEncDB(t)
	plainRaw := writeRealActive(t, plainDB, &config.ConfigTree{}, true)
	plainHdr := string(plainRaw[:bytes.IndexByte(plainRaw, '\n')])
	if !strings.Contains(plainHdr, fmt.Sprintf("min-reader=%d", EnvelopeMinReaderVersion)) {
		t.Errorf("unencrypted envelope header %q must NOT raise the floor — there is no "+
			"ciphertext to bind, so refusing an older reader buys nothing", plainHdr)
	}
}

// The canonical-parse half. Atoi-then-`n != 0` accepted all of these as
// committed; only the two values this build writes are valid now. Absence is a
// separate question and is DELIBERATELY unchanged — see the parser comment.
func TestCommittedMarkerParsesCanonically_7176(t *testing.T) {
	base := "#xpf-config-envelope v=2 writer=w ast=1 min-reader=1 rollback-fmt=1 "
	for _, tc := range []struct {
		val     string
		wantErr bool
		want    bool
	}{
		{"1", false, true},
		{"0", false, false},
		{"2", true, false},
		{"-1", true, false},
		{"+1", true, false},
		{"007", true, false},
		{"true", true, false},
		{"", true, false},
	} {
		hdr, err := parseEnvelopeHeader(base + "committed=" + tc.val)
		if tc.wantErr {
			if err == nil {
				t.Errorf("committed=%q was accepted (Committed=%v); only \"0\"/\"1\" are "+
					"values this build writes, and a permissive read of the #1922 marker "+
					"is what C179-053 is about", tc.val, hdr.Committed)
			}
			continue
		}
		if err != nil {
			t.Errorf("committed=%q rejected: %v", tc.val, err)
			continue
		}
		if hdr.Committed != tc.want {
			t.Errorf("committed=%q -> %v, want %v", tc.val, hdr.Committed, tc.want)
		}
	}

	// Absence still defaults to committed (migration rule C3). Changing this
	// would alter how existing envelopes that omit the field are read and could
	// trigger bootstrap on upgrade; the AAD binding is what removes the reason
	// to want it changed, since the field can no longer be deleted undetected.
	hdr, err := parseEnvelopeHeader(strings.TrimSpace(base))
	if err != nil {
		t.Fatalf("a header omitting committed= must still parse: %v", err)
	}
	if !hdr.Committed {
		t.Error("absence of committed= must still default to TRUE (migration rule C3)")
	}
}
