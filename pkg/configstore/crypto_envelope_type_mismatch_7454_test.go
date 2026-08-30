package configstore

import (
	"strings"
	"testing"
)

// #7454: a JSON TYPE mismatch on an encrypted-envelope field bypassed the #4888
// fail-closed guard and booted an empty committed config.
//
// #4888's guard fails closed on an envelope-shaped body whose discriminator is
// unsupported, and its comment names the exact outcome it exists to prevent:
//
//	Treating it as plaintext lets json.Unmarshal drop the unknown fields and
//	decode an EMPTY ConfigTree, so Store.Load would boot a committed-empty
//	config (loss of policy) instead of failing closed.
//
// But it sits AFTER the initial unmarshal, and that unmarshal swallowed every
// error as "not the envelope shape at all". True for a SYNTAX error. Not true
// for a *json.UnmarshalTypeError: a perfectly good JSON object with the right
// keys, one carrying the wrong JSON type, took the same branch and passed
// through as plaintext — reaching the outcome the guard in front of it names.
//
// The failure is COMPLETELY SILENT. The #4579 plaintext-downgrade warning keys
// on masterPasswordPRF(tree) != "" and the tree is empty, so it does not fire
// either. Contrast the string-valued path, which is correctly fatal all the way
// to `daemon_run_bringup.go` refusing to start.
//
// The extension is the point: the existing #4888 table covers only
// STRING-valued malformation, which is why this was missed. Every row here
// carries a non-string value.

func TestEnvelopeTypeMismatchFailsClosed7454(t *testing.T) {
	const goodFmt = `"format":"xpf-master-password-v1"`

	for _, tc := range []struct {
		name      string
		body      string
		wantErr   bool
		wantIsEnv bool
		// wantMsg is the diagnosis the refusal must carry. Rows differ here on
		// purpose — an operator distinguishes a corrupt envelope from an
		// unsupported one by this wording, and the two have different remedies
		// (restore a backup vs. downgrade the reader).
		wantMsg string
		why     string
	}{
		// --- the defect: wrong TYPE on each envelope field ---
		{"salt is a number", `{` + goodFmt + `,"prf":"sha256","salt":5,"nonce":"AA","data":"AA"}`, true, false, "corrupted",
			"a numeric salt decoded as plaintext, dropped every field, and booted an EMPTY committed config"},
		{"format is an array", `{"format":[],"prf":"sha256","salt":"AA","nonce":"AA","data":"AA"}`, true, false, "corrupted",
			"an array format is corruption"},
		{"prf is an object", `{` + goodFmt + `,"prf":{},"salt":"AA","nonce":"AA","data":"AA"}`, true, false, "corrupted",
			"an object prf is corruption"},
		{"nonce is a bool", `{` + goodFmt + `,"prf":"sha256","salt":"AA","nonce":true,"data":"AA"}`, true, false, "corrupted",
			"a boolean nonce is corruption"},
		// The row that separates "was MEANT to be an envelope" from "decodes as
		// one": a single envelope key, wrong type, nothing else. A check that
		// discriminated only on the format discriminator would let it through.
		{"only a wrong-typed salt", `{"salt":5}`, true, false, "corrupted",
			"one envelope key present at all means the body was meant to be an envelope"},

		// --- MEASURED, and it corrects the issue's framing ---
		// JSON null is NOT a type error in Go: it decodes into any type as a
		// no-op, leaving the zero value. So a null-valued field reaches the
		// envelope's own required-field check and is refused THERE, with that
		// check's wording. Already fail-closed before #7454, by a different
		// guard. Kept as rows so the two paths stay distinguishable.
		{"data is null", `{` + goodFmt + `,"prf":"sha256","salt":"AA","nonce":"AA","data":null}`, true, false,
			"invalid encrypted config envelope",
			"null leaves Data empty and the required-field check refuses it"},
		{"format is null", `{"format":null,"prf":"sha256","salt":"AA","nonce":"AA","data":"AA"}`, true, false,
			"unsupported encrypted config envelope format",
			"null format leaves Format empty; #4888's discriminator check refuses it"},

		// --- acceptance: a genuine plaintext / legacy body still loads ---
		{"plaintext ConfigTree", `{"Children":[]}`, false, false, "",
			"the persisted plaintext body is a bare ConfigTree; its only top-level key is Children"},
		{"plaintext with content", `{"Children":[{"Keys":["system"]}]}`, false, false, "",
			"a populated plaintext body must load"},
		{"empty object", `{}`, false, false, "",
			"no envelope key present — genuine plaintext passthrough"},

		// --- acceptance: a malformed NON-OBJECT body keeps current behaviour ---
		{"null body", `null`, false, false, "", "not an object — unchanged passthrough"},
		{"array body", `[1,2,3]`, false, false, "", "not an object — unchanged passthrough"},
		{"scalar body", `42`, false, false, "", "not an object — unchanged passthrough"},
		{"garbage body", `not json at all`, false, false, "", "not JSON — unchanged passthrough"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, isEnv, err := unmarshalEnvelope([]byte(tc.body))
			if tc.wantErr && err == nil {
				t.Fatalf("unmarshalEnvelope returned NO error and isEncrypted=%v.\n%s\n"+
					"Store.Load then compiles an empty tree and the daemon boots with no "+
					"policy, reporting success (#7454)", isEnv, tc.why)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unmarshalEnvelope returned %v; %s", err, tc.why)
			}
			if isEnv != tc.wantIsEnv {
				t.Errorf("isEncrypted = %v, want %v", isEnv, tc.wantIsEnv)
			}
			if tc.wantErr && tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("the refusal carries the wrong diagnosis: got %v, want it to "+
					"contain %q. An operator distinguishes a corrupt envelope from an "+
					"unsupported one by this wording, and the two have different "+
					"remedies (restore a backup vs. downgrade the reader)", err, tc.wantMsg)
			}
		})
	}
}

// The error must NAME which envelope fields were present, or an operator
// staring at a refusing daemon cannot tell a corrupt envelope from an
// unsupported one — two conditions with different remedies (restore a backup
// vs. downgrade the reader).
func TestEnvelopeCorruptionErrorNamesTheFields7454(t *testing.T) {
	_, _, err := unmarshalEnvelope([]byte(
		`{"format":"xpf-master-password-v1","prf":"sha256","salt":5,"nonce":"AA","data":"AA"}`))
	if err == nil {
		t.Fatal("expected a fail-closed error")
	}
	for _, want := range []string{"data", "format", "nonce", "prf", "salt"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name the present envelope field %q: %v", want, err)
		}
	}
}

// THE STILL-WORKS CONTROL for the #4888 guard this sits in front of. A
// string-valued unsupported discriminator must keep failing closed with ITS
// message, not be absorbed into the new one — the two are different diagnoses.
func TestUnsupportedFormatStillFailsClosed7454(t *testing.T) {
	_, _, err := unmarshalEnvelope([]byte(
		`{"format":"xpf-master-password-v9","prf":"sha256","salt":"AA","nonce":"AA","data":"AA"}`))
	if err == nil {
		t.Fatal("an unsupported format must still fail closed (#4888)")
	}
	if !strings.Contains(err.Error(), "unsupported encrypted config envelope format") {
		t.Errorf("#4888's diagnosis was replaced rather than preserved: %v", err)
	}
}

// And the round-trip control: a genuinely encrypted envelope must still be
// RECOGNIZED as one. Without this, every cell above is satisfied by a function
// that fails closed on everything.
func TestWellFormedEnvelopeStillRecognized7454(t *testing.T) {
	_, isEnv, err := unmarshalEnvelope([]byte(
		`{"format":"xpf-master-password-v1","prf":"sha256","salt":"AA","nonce":"AA","data":"AA"}`))
	if err != nil {
		t.Fatalf("a well-formed envelope was rejected: %v", err)
	}
	if !isEnv {
		t.Error("a well-formed envelope was not recognized as encrypted; the cells " +
			"above would all pass for a function that fails closed on everything")
	}
}
