package config

import (
	"strings"
	"testing"
)

// #9027: a missing semicolon in a multi-value run injected the leaf's own
// keyword as a VALUE, and at `api-auth api-key` that value is a CREDENTIAL:
//
//	api-key AAA api-key BBB;   ->  keys = ["AAA", "api-key", "BBB"]
//
// The injected credential is a PREDICTABLE, PUBLICLY-KNOWN ENGLISH LITERAL, so
// anyone who can reach the management listener can present
// `X-API-Key: api-key`. The braced spelling of the same intent yields two keys.
//
// THE TWO READERS OF THIS SHAPE GUESSED OPPOSITE WAYS — firewallMatchValues
// skips the repeat (#8883, an EXPERIMENT, which silently drops a
// legitimately-named object per #9029) and multiLeafAuthoredValues accepts it
// (which injects). Both are guesses at an input that is genuinely ambiguous, so
// this refuses instead of choosing one.

func selfRepeatTree9027(t *testing.T, text string) *ConfigTree {
	t.Helper()
	root, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	return &ConfigTree{Children: root.Children}
}

func TestMultiLeafSelfRepeatIsRefused9027(t *testing.T) {
	const apiAuth = `system { services { web-management { api-auth { %s } } } }`
	for _, tc := range []struct {
		name       string
		text       string
		wantRefuse bool
	}{
		// THE DEFECT.
		{"api-key run repeats its keyword",
			`system { services { web-management { api-auth { api-key AAA api-key BBB; } } } }`, true},

		// CONTROLS — every legitimate spelling of the same intent must survive.
		// Without these, "refuse everything" would satisfy the row above.
		{"two separate statements",
			`system { services { web-management { api-auth { api-key AAA; api-key BBB; } } } }`, false},
		{"a bracketed list",
			`system { services { web-management { api-auth { api-key [ AAA BBB ]; } } } }`, false},
		{"a single key",
			`system { services { web-management { api-auth { api-key AAA; } } } }`, false},

		// A DIFFERENT multi leaf, to show the gate is keyed on the shape and
		// not on `api-key`.
		{"firewall match run repeats its keyword",
			`firewall { family inet { filter F { term t1 {
				from { protocol tcp protocol udp; } then { discard; } } } } }`, true},
		{"firewall match, bracketed list",
			`firewall { family inet { filter F { term t1 {
				from { protocol [ tcp udp ]; } then { discard; } } } } }`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := selfRepeatTree9027(t, tc.text)
			_, err := CompileConfig(tr)
			if (err != nil) != tc.wantRefuse {
				t.Fatalf("refused=%v, want %v (err=%v)", err != nil, tc.wantRefuse, err)
			}
			if !tc.wantRefuse {
				return
			}
			// The message must offer BOTH readings. A refusal that says only
			// "ambiguous" leaves the operator to guess which fix is meant.
			for _, want := range []string{"missing a semicolon", "named"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not offer both readings (missing %q): %v", want, err)
				}
			}
			// #1960: the tolerant path must WARN, never refuse.
			lc, lerr := CompileConfigLenient(tr)
			if lerr != nil {
				t.Fatalf("the LENIENT path rejected — a persisted config would fail to "+
					"load (#1960): %v", lerr)
			}
			var warned bool
			for _, w := range lc.Warnings {
				if strings.Contains(w, "repeats its own keyword") {
					warned = true
				}
			}
			if !warned {
				t.Error("the lenient path accepted the ambiguous run with NO warning")
			}
		})
	}
	_ = apiAuth
}

// TestApiKeyLiteralIsNotMintedAsACredential9027 is the security assertion,
// stated as the thing an attacker would use rather than as a count.
func TestApiKeyLiteralIsNotMintedAsACredential9027(t *testing.T) {
	tr := selfRepeatTree9027(t,
		`system { services { web-management { api-auth { api-key AAA api-key BBB; } } } }`)

	// STRICT refuses, so the credential is never minted on the operator path.
	if _, err := CompileConfig(tr); err == nil {
		t.Fatal("the packed api-key run was ACCEPTED at commit")
	}

	// On the TOLERANT path the config still loads — and this is the honest
	// limit of this fix, asserted rather than left to be discovered: the
	// existing reader still yields the literal, and the operator's only signal
	// is the warning. Closing that needs the reader change #9029 is about.
	lc, err := CompileConfigLenient(tr)
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	var got []string
	if a := lc.System.Services.WebManagement.APIAuth; a != nil {
		for _, k := range a.APIKeys {
			got = append(got, k.Reveal())
		}
	}
	var sawLiteral bool
	for _, g := range got {
		if g == "api-key" {
			sawLiteral = true
		}
	}
	if !sawLiteral {
		t.Skipf("the tolerant path no longer yields the literal (%v) — the reader was fixed, "+
			"so delete this arm and the note on #9027", got)
	}
	t.Logf("KNOWN RESIDUAL: the tolerant path still yields %v; the strict gate is what "+
		"stops a NEW instance, and the warning is what tells the operator about an "+
		"existing one", got)
}

// #9029: THE GATE MUST NOT REFUSE A LEGITIMATELY-NAMED OBJECT.
//
// #8883's `k == self` skip in firewallMatchValues was the same over-reach in
// the other direction — it DROPPED such an object, silently. Both mistakes come
// from treating the spelling question as unanswerable when the AST already
// answers it two different ways:
//
//   - ARITY. Keys[1..args] are the leaf's first value, or its NAME. `address
//     address 10.0.0.0/8` DEFINES an address called "address"; flagging Keys[1]
//     there refuses a definition rather than a repeat.
//   - QUOTING. `address "address"` says in the grammar itself that the token is
//     a name. KeysQuoted is exactly that bit (#6673: "the one bit about a key
//     that its TEXT cannot carry").
func TestLegitimatelyNamedObjectIsAccepted9029(t *testing.T) {
	for _, tc := range []struct {
		name       string
		text       string
		wantRefuse bool
	}{
		// The definition of an object NAMED after its own keyword. Refusing
		// this was the first version of the gate over-reaching.
		{"an address DEFINED as `address`",
			`security { address-book { global { address address 10.0.0.0/8; } } }`, false},

		// Referencing it, said unambiguously by QUOTING.
		{"a member quoted as \"address\"",
			`security { address-book { global { address address 10.0.0.0/8;
				address-set AS1 { address "address"; } } } }`, false},

		// The api-key site: a key legitimately named `api-key`, quoted.
		{"a quoted api-key name",
			`system { services { web-management { api-auth {
				api-key AAA; api-key "api-key"; } } } }`, false},

		// THE ROW THAT BINDS THE QUOTING BRANCH, and it is the only one that
		// does. The two spellings below produce the IDENTICAL Keys
		// (`[address ADDR-A address]`) and differ only in KeysQuoted, so the
		// verdict comes from that bit and nothing else.
		//
		// Without this pair the quoting branch is INERT: arity scoping already
		// covers every other case in this file, and a mutation disabling
		// KeyQuoted killed zero cells until this row existed. A branch nothing
		// can fail is a claim, not a guard.
		{"a member run whose second member is QUOTED as the keyword",
			`security { address-book { global { address ADDR-A 10.0.0.0/8; address address 10.1.0.0/16;
				address-set AS1 { address ADDR-A "address"; } } } }`, false},
		{"the same run UNQUOTED is refused",
			`security { address-book { global { address ADDR-A 10.0.0.0/8; address address 10.1.0.0/16;
				address-set AS1 { address ADDR-A address; } } } }`, true},

		// STILL REFUSED. The bare repeat is the missing-semicolon shape and the
		// security case; the quoting escape must not open it.
		{"bare api-key run is still refused",
			`system { services { web-management { api-auth { api-key AAA api-key BBB; } } } }`, true},
		{"bare address member run is still refused",
			`security { address-book { global { address ADDR-A 10.0.0.0/8; address ADDR-B 10.1.0.0/16;
				address-set AS1 { address ADDR-A address ADDR-B; } } } }`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := selfRepeatTree9027(t, tc.text)
			_, err := CompileConfig(tr)
			if (err != nil) != tc.wantRefuse {
				t.Fatalf("refused=%v, want %v (err=%v)", err != nil, tc.wantRefuse, err)
			}
			if tc.wantRefuse && !strings.Contains(err.Error(), "QUOTE it") {
				t.Errorf("the refusal does not offer quoting as the remedy: %v", err)
			}
		})
	}
}
