package configstore

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 (muse-004 K69) — the envelope guard and the decoder it guards
// disagreed about what counts as a key.
//
// encoding/json matches an incoming object key to a struct field by preferring
// an exact match but ACCEPTING a case-insensitive one. `envelopeKeysPresent`
// used an exact lowercase lookup, so every body whose key differed only in case
// fell into the gap between them. Measured before the fix:
//
//	{"format": 123}      -> rejected (fail-closed)
//	{"Format": 123}      -> PASSED THROUGH AS PLAINTEXT
//	{"Format":"garbage"} -> PASSED THROUGH AS PLAINTEXT
//	{"Salt": 5}          -> PASSED THROUGH AS PLAINTEXT
//
// Downstream, json.Unmarshal drops the unknown fields, an EMPTY ConfigTree
// decodes, and Store.Load boots an active firewall with NO SECURITY POLICY
// reporting success — silently, because the #4579 plaintext-downgrade warning
// keys on masterPasswordPRF(tree) != "" and the tree is empty.
//
// This is the FOURTH member of that family (#4888, #7454, #8288), and the first
// three all read the body's keys with a rule the decoder does not use.

// TestEnvelopeGuardIsCaseInsensitive_8597 is the RED-on-revert core. It pairs
// each case-variant body with its lowercase twin, so the assertion is the
// AGREEMENT between the two spellings rather than a verdict pinned in
// isolation: whatever the guard decides about `{"format": 123}` it must decide
// about `{"Format": 123}`.
func TestEnvelopeGuardIsCaseInsensitive_8597(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lower string
		upper string
	}{
		{"format, wrong JSON type", `{"format": 123}`, `{"Format": 123}`},
		{"format, unsupported value", `{"format":"garbage"}`, `{"Format":"garbage"}`},
		{"format, SHOUTED", `{"format": 123}`, `{"FORMAT": 123}`},
		{"salt, wrong JSON type", `{"salt": 5}`, `{"Salt": 5}`},
		{"nonce, wrong JSON type", `{"nonce": true}`, `{"NONCE": true}`},
		{"data, wrong JSON type", `{"data": []}`, `{"Data": []}`},
		{"prf alone (the #8288 shape)", `{"prf":"sha256"}`, `{"PRF":"sha256"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, lowerErr := unmarshalEnvelope([]byte(tc.lower))
			_, _, upperErr := unmarshalEnvelope([]byte(tc.upper))

			// Non-vacuity: the lowercase twin must actually be refused, or the
			// agreement below is between two passes and proves nothing.
			if lowerErr == nil {
				t.Fatalf("the lowercase body %s was NOT refused; this cell asserts the "+
					"case-variant matches it, so without a refusal it tests nothing", tc.lower)
			}
			if upperErr == nil {
				t.Fatalf("%s passed through as PLAINTEXT while %s was refused — the guard "+
					"probes exact-lowercase keys while encoding/json matches "+
					"case-insensitively, so Store.Load decodes an EMPTY ConfigTree and "+
					"boots an active firewall with no security policy, reporting success "+
					"(#8597/K69)", tc.upper, tc.lower)
			}
		})
	}
}

// TestPlaintextStillPassesThrough_8597 is the OVER-BROAD control, and it is the
// half that decides whether a fail-closed change can ship: refusing a genuine
// plaintext config DB is a boot failure on every box that has not enabled
// encryption.
//
// The bodies below are the ones #7454's acceptance criteria require to keep
// passing: a real plaintext tree, and the non-object shapes.
func TestPlaintextStillPassesThrough_8597(t *testing.T) {
	realTree, err := json.Marshal(&config.ConfigTree{})
	if err != nil {
		t.Fatalf("marshal ConfigTree: %v", err)
	}
	for _, body := range []string{
		string(realTree),
		`{"Children": []}`,
		`null`,
		`[]`,
		`"scalar"`,
		`not json at all`,
		`{}`,
	} {
		if _, enc, err := unmarshalEnvelope([]byte(body)); err != nil || enc {
			t.Errorf("plaintext body %q was refused (enc=%v err=%v); every box without "+
				"encryption enabled boots from a body of this shape", body, enc, err)
		}
	}
}

// TestPlaintextKeySetCannotCollideWhenFolded_8597 is the measurement behind the
// over-broad control, rather than a hope.
//
// Case-folding widens the guard, so it is only safe if no key a genuine
// plaintext body carries folds onto an envelope name. config.ConfigTree has
// exactly one field; this marshals a real one and checks its folded key set,
// so a future field named `Format` or `Data` fails HERE rather than by bricking
// a boot.
func TestPlaintextKeySetCannotCollideWhenFolded_8597(t *testing.T) {
	body, err := json.Marshal(&config.ConfigTree{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	envelope := map[string]bool{"data": true, "format": true, "nonce": true, "prf": true, "salt": true}
	for k := range probe {
		if envelope[strings.ToLower(k)] {
			t.Fatalf("config.ConfigTree marshals a top-level key %q whose folded form is an "+
				"envelope field name: case-folding the guard now refuses every genuine "+
				"plaintext config DB. Rename the field or narrow the guard.", k)
		}
	}
	if len(probe) == 0 {
		t.Fatal("a marshalled ConfigTree has no top-level keys; this check is vacuous")
	}
}

// TestEnvelopeKeysReportCanonicalNames_8597: the names are embedded in the
// operator-facing diagnostics, so a shouted key in a corrupt body must not
// produce a shouted message.
func TestEnvelopeKeysReportCanonicalNames_8597(t *testing.T) {
	got := envelopeKeysPresent([]byte(`{"FORMAT":1,"Salt":2,"nonce":3}`))
	want := []string{"format", "nonce", "salt"}
	if len(got) != len(want) {
		t.Fatalf("envelopeKeysPresent = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("key %d = %q, want %q (canonical lowercase, sorted)", i, got[i], want[i])
		}
	}
}
