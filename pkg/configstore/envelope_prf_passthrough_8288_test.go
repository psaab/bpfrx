package configstore

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8288: a body naming ANY envelope key must be refused, not passed through as
// plaintext.
//
// THE DEFECT WAS A GAP BETWEEN TWO GUARDS, not a missing one, which is why the
// table below carries both halves. #7454's key-presence guard is consulted only
// inside the decode-FAILURE branch, and `{"prf":"sha256"}` is well-formed JSON
// that decodes cleanly, so it never reached it. #4888's fail-closed
// discriminator then tested Format/Salt/Nonce/Data — four of the envelope's
// FIVE fields — so a PRF-only body satisfied "no format AND no AES-GCM fields",
// which the comment above that test defines as a genuine plaintext body.
//
// Consequence, and the reason this is not a cosmetic refusal: json.Unmarshal
// drops the unknown field, an EMPTY ConfigTree decodes, and Store.Load boots an
// active firewall with NO security policy while reporting success.
//
// THE PASSTHROUGH ROWS ARE NOT PADDING. A fix that simply refused more would
// satisfy every REFUSE row and take a firewall down on upgrade by rejecting a
// genuine plaintext config. Those rows are the control, and `{"Children":...}`
// is the one that matters most — it is the shape `writeTreeMarked` actually
// writes.
func TestEnvelopePRFOnlyBodyIsRefused8288(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       string
		wantRefuse bool
		why        string
	}{
		// The defect.
		{"prf only", `{"prf":"sha256"}`, true,
			"the body this issue was filed for: decodes cleanly, so #7454's guard never ran"},
		{"prf with a plaintext-looking key", `{"prf":"sha256","Children":null}`, true,
			"a Children key alongside must not launder an envelope key into plaintext"},

		// Pre-existing refusals — these already worked, and must keep working.
		// If one of these ever passes, the guard has been weakened rather than
		// strengthened and the REFUSE rows above would still be green.
		{"salt only", `{"salt":"x"}`, true, "#4888, already refused before this fix"},
		{"nonce only", `{"nonce":"x"}`, true, "#4888"},
		{"data only", `{"data":"x"}`, true, "#4888"},
		{"unknown format", `{"format":"xpf-master-password-v2"}`, true, "#4888 too-new DB"},

		// Strictly stronger than the old field test, and deliberately so: the
		// key is present, so the body was MEANT to be an envelope.
		{"format key with empty value", `{"format":""}`, true,
			"key presence, not value emptiness, is the question"},

		// The tolerance #7454's acceptance requires, unchanged. A stricter fix
		// that broke any of these would brick a box on upgrade.
		{"genuine plaintext tree", `{"Children":[]}`, false,
			"THE shape writeTreeMarked writes — must pass through"},
		{"populated plaintext tree", `{"Children":[{"Keys":["system"]}]}`, false,
			"content does not change the top-level key set"},
		{"null", `null`, false, "#7454 deliberate tolerance"},
		{"array", `[1,2]`, false, "#7454 deliberate tolerance"},
		{"scalar", `42`, false, "#7454 deliberate tolerance"},
		{"garbage", `garbage`, false, "#7454 deliberate tolerance"},
		{"empty object", `{}`, false, "no envelope key named at all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ok, err := unmarshalEnvelope([]byte(tc.body))
			if ok {
				t.Fatalf("body %s decoded as a VALID envelope; this table is about "+
					"bodies that are not valid envelopes", tc.body)
			}
			if tc.wantRefuse && err == nil {
				t.Fatalf("body %s was passed through as PLAINTEXT (err=nil), want a refusal.\n"+
					"%s\nA plaintext passthrough here decodes an EMPTY ConfigTree, so the "+
					"daemon boots an active firewall with no security policy and reports "+
					"success.", tc.body, tc.why)
			}
			if !tc.wantRefuse && err != nil {
				t.Fatalf("body %s was REFUSED (%v), want plaintext passthrough.\n%s\n"+
					"Over-rejecting here takes a working firewall down on upgrade — this "+
					"row is the control on the fix being aimed, not merely strict.",
					tc.body, err, tc.why)
			}
		})
	}
}

// The refusal must name WHICH envelope key it saw. "unsupported format \"\"" on
// its own sends an operator looking for a `format` field the body does not have.
func TestEnvelopeRefusalNamesTheKeysPresent8288(t *testing.T) {
	_, _, err := unmarshalEnvelope([]byte(`{"prf":"sha256"}`))
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "prf") {
		t.Fatalf("the refusal must name the key that triggered it, got %q", err)
	}
}

// THE PREMISE THE FIX RESTS ON, asserted rather than trusted to a comment.
//
// `len(envKeys) > 0` is only safe because no genuine plaintext body can carry
// an envelope key. That holds because config.ConfigTree has exactly one field.
// If a field were ever added whose JSON name collided with one of the five,
// every plaintext load would start failing closed — a brick on upgrade — and
// this cell is what would say so, at the point of change rather than in the
// field.
func TestPlaintextTreeCarriesNoEnvelopeKeys8288(t *testing.T) {
	trees := map[string]config.ConfigTree{
		"empty":     {},
		"populated": {Children: []*config.Node{{Keys: []string{"system"}}}},
	}
	for name, tree := range trees {
		body, err := json.MarshalIndent(tree, "", "  ")
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		if keys := envelopeKeysPresent(body); len(keys) > 0 {
			t.Fatalf("%s: a marshalled ConfigTree carries envelope key(s) %v — "+
				"`len(envKeys) > 0` would now REFUSE every genuine plaintext config "+
				"and brick the box on upgrade. Either rename the new field or stop "+
				"using key presence as the discriminator.", name, keys)
		}
		// And the positive half: the probe must actually be looking at
		// something. An empty/garbage body would also report no envelope keys.
		var top map[string]json.RawMessage
		if err := json.Unmarshal(body, &top); err != nil {
			t.Fatalf("%s: the marshalled tree is not a JSON object: %v", name, err)
		}
		if _, ok := top["Children"]; !ok {
			t.Fatalf("%s: marshalled tree has no Children key (top-level keys %v) — "+
				"the assertion above would have been vacuous", name, top)
		}
	}
}
