package config

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestSecretMarshalJSON covers the core redaction contract: a non-empty
// Secret marshals to the sentinel, an empty Secret marshals to "" (so
// absence stays distinguishable), and the real value never appears.
func TestSecretMarshalJSON(t *testing.T) {
	// json.Marshal HTML-escapes the sentinel's "<"/">"; compare against the
	// encoder's own rendering so the test tracks the real wire bytes.
	redactedJSON, _ := json.Marshal(SecretRedacted)
	tests := []struct {
		name string
		s    Secret
		want string
	}{
		{"non-empty redacts", Secret("supersecret"), string(redactedJSON)},
		{"empty stays empty", Secret(""), `""`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.s)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			if string(b) != tc.want {
				t.Errorf("Marshal() = %s, want %s", b, tc.want)
			}
			if strings.Contains(string(b), "supersecret") {
				t.Errorf("Marshal() leaked cleartext: %s", b)
			}
		})
	}
}

// TestSecretMarshalYAML mirrors MarshalJSON. The YAML marshaller is
// interface-detected, so we exercise the method directly (no yaml encoder
// dependency in this test): non-empty -> sentinel, empty -> "".
func TestSecretMarshalYAML(t *testing.T) {
	got, err := Secret("supersecret").MarshalYAML()
	if err != nil {
		t.Fatalf("MarshalYAML() error = %v", err)
	}
	if got != SecretRedacted {
		t.Errorf("MarshalYAML() non-empty = %v, want %q", got, SecretRedacted)
	}
	got, err = Secret("").MarshalYAML()
	if err != nil {
		t.Fatalf("MarshalYAML() error = %v", err)
	}
	if got != "" {
		t.Errorf("MarshalYAML() empty = %v, want \"\"", got)
	}
}

// TestSecretRedactsInContainers is the value-vs-pointer-receiver trap from
// the plan (§6.5): redaction MUST fire for a Secret used as a struct field,
// inside a []Secret slice, and as a map value. A pointer receiver would
// silently NOT redact in a non-addressable slice/map element.
func TestSecretRedactsInContainers(t *testing.T) {
	type holder struct {
		Field   Secret
		Slice   []Secret
		MapVals map[string]Secret
	}
	h := holder{
		Field:   Secret("field-secret"),
		Slice:   []Secret{Secret("slice-secret-a"), Secret("slice-secret-b")},
		MapVals: map[string]Secret{"k": Secret("map-secret")},
	}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	out := string(b)
	for _, leak := range []string{"field-secret", "slice-secret-a", "slice-secret-b", "map-secret"} {
		if strings.Contains(out, leak) {
			t.Errorf("Marshal() leaked %q in %s", leak, out)
		}
	}
	// Four secret positions present (field + 2 slice + 1 map) -> four
	// redaction sentinels. Count the JSON-encoded (HTML-escaped) form.
	rb, _ := json.Marshal(SecretRedacted)
	redacted := strings.Trim(string(rb), `"`)
	if n := strings.Count(out, redacted); n != 4 {
		t.Errorf("expected 4 redaction sentinels (field + 2 slice + 1 map), got %d in %s", n, out)
	}
}

// TestSecretString covers logging hygiene: %s/%v of a Secret redacts a
// non-empty value and renders empty as "".
func TestSecretString(t *testing.T) {
	if got := Secret("x").String(); got != SecretRedacted {
		t.Errorf("String() non-empty = %q, want %q", got, SecretRedacted)
	}
	if got := Secret("").String(); got != "" {
		t.Errorf("String() empty = %q, want \"\"", got)
	}
}

// TestSecretReveal confirms the render/reconcile escape hatch returns the
// real cleartext value (the half of the contract the in-memory consumers
// depend on).
func TestSecretReveal(t *testing.T) {
	if got := Secret("real-value").Reveal(); got != "real-value" {
		t.Errorf("Reveal() = %q, want %q", got, "real-value")
	}
	if got := Secret("").Reveal(); got != "" {
		t.Errorf("Reveal() empty = %q, want \"\"", got)
	}
}

// TestSecretUnmarshalJSON documents the fail-closed round-trip guard: a
// plain string ingests as-is, but the redaction sentinel is REFUSED so a
// marshalled-then-reloaded compiled config can never silently turn
// "<redacted>" into a live secret (the compiled-config SSOT is the AST
// tree, not JSON — see secret.go).
func TestSecretUnmarshalJSON(t *testing.T) {
	var s Secret
	if err := json.Unmarshal([]byte(`"plain"`), &s); err != nil {
		t.Fatalf("Unmarshal(plain) error = %v", err)
	}
	if s.Reveal() != "plain" {
		t.Errorf("Unmarshal(plain) = %q, want %q", s.Reveal(), "plain")
	}

	err := json.Unmarshal([]byte(`"`+SecretRedacted+`"`), &s)
	if err == nil {
		t.Fatal("Unmarshal(sentinel) succeeded; want refusal")
	}
	if !errors.Is(err, errRedactedSecretIngest) {
		t.Errorf("Unmarshal(sentinel) err = %v, want errRedactedSecretIngest", err)
	}
}

// TestSecretIsComparable confirms Secret stays usable as a map key and for
// direct == "" present/absent checks at call sites (the named-string-type
// property the design depends on).
func TestSecretIsComparable(t *testing.T) {
	m := map[Secret]int{Secret("a"): 1}
	if m[Secret("a")] != 1 {
		t.Error("Secret not usable as map key")
	}
	var unset Secret
	if unset != "" {
		t.Error("zero-value Secret should compare equal to \"\"")
	}
}

// TestSNMPCommunityMarshalRedactsName covers the targeted struct marshaller
// (#2053): SNMPCommunity keeps Name a plain string so it stays the map key
// and the text show paths are unchanged, but its JSON/YAML form redacts the
// community string (the secret) while leaving Authorization in the clear.
func TestSNMPCommunityMarshalRedactsName(t *testing.T) {
	c := SNMPCommunity{Name: "publiclikesecret", Authorization: "read-only"}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	out := string(b)
	if strings.Contains(out, "publiclikesecret") {
		t.Errorf("SNMPCommunity JSON leaked community string: %s", out)
	}
	rb, _ := json.Marshal(SecretRedacted)
	if !strings.Contains(out, strings.Trim(string(rb), `"`)) {
		t.Errorf("SNMPCommunity JSON missing redaction sentinel: %s", out)
	}
	if !strings.Contains(out, "read-only") {
		t.Errorf("SNMPCommunity JSON should keep Authorization in clear: %s", out)
	}
	// In-memory Name (the map key / render value) is untouched.
	if c.Name != "publiclikesecret" {
		t.Errorf("in-memory SNMPCommunity.Name mutated to %q", c.Name)
	}
}
