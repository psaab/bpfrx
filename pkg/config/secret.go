package config

import (
	"encoding/json"
	"errors"
)

// errRedactedSecretIngest is returned by Secret.UnmarshalJSON when the
// redaction sentinel is decoded — see UnmarshalJSON.
var errRedactedSecretIngest = errors.New(
	"config: refusing to ingest redacted secret sentinel \"" + SecretRedacted + "\"")

// Secret is a config string whose cleartext value is preserved in memory
// for the reconciler/render paths but is REDACTED on any JSON/YAML marshal
// so a compiled-config serializer can never leak it (#2053).
//
// Why this exists: the compiled *config.Config carries every operator
// secret verbatim (IKE/IPsec pre-shared keys, OSPF/IS-IS/RIP/VRRP/interface
// auth keys, the TSIG HMAC key, SNMPv3 auth/priv passwords, root/login
// crypt(3) hashes, the BGP TCP-MD5 password, REST basic-auth passwords +
// API keys, the WireGuard private key). A registered production REST route,
// GET /api/v1/config (pkg/api/config.go), JSON-encodes that whole struct.
// Before #2053 it returned every secret in plaintext to any authorized
// client (loopback by default, but bindable non-loopback over HTTPS via
// `web-management https interface`). The pre-existing String() redaction on
// a couple of structs only covers %v/%s/slog — encoding/json ignores
// Stringer, so it did NOT close the marshal leak. Making the field type
// itself enforce redaction means the guarantee is type-enforced, not
// per-comment: any present or future marshal of a struct that contains a
// Secret field redacts automatically, and adding a new secret field is a
// single type annotation.
//
// Round-trip is safe: nothing in the tree unmarshals a compiled
// *config.Config back from JSON/YAML (the persistence/sync SSOT is the
// *ConfigTree AST, db.go / sync_conn.go). A redacting marshaller therefore
// cannot starve any consumer of a secret. Render/reconcile sites read the
// cleartext via Reveal(). UnmarshalJSON below additionally refuses the
// redaction sentinel so that if a compiled-config JSON ingest is ever added
// it fails loudly instead of silently loading "<redacted>" as a key.
//
// Secret keeps the underlying string kind (it is a named string type, not a
// struct) so it stays comparable — usable as a map key and directly
// comparable to "" for present/absent checks at call sites.
type Secret string

// SecretRedacted is the sentinel emitted in place of a non-empty Secret on
// JSON/YAML marshal.
const SecretRedacted = "<redacted>"

// String redacts a non-empty Secret for %v/%s/slog formatting (logging
// hygiene). An empty Secret renders as "" so absence stays distinguishable.
func (s Secret) String() string {
	if s == "" {
		return ""
	}
	return SecretRedacted
}

// Reveal returns the real cleartext value. This is the ONLY way to read the
// secret; render/reconcile paths must call it explicitly. The name is
// deliberately greppable so an audit can find every cleartext access — do
// not feed the result into a log line.
func (s Secret) Reveal() string { return string(s) }

// MarshalJSON redacts the secret. An empty Secret marshals to "" so that
// unset/empty stays distinguishable from a present-but-redacted value; a
// non-empty Secret marshals to the redaction sentinel. A value receiver is
// required so redaction fires for a Secret used as a struct field, inside a
// []Secret slice, and as a map value.
func (s Secret) MarshalJSON() ([]byte, error) {
	if s == "" {
		return []byte(`""`), nil
	}
	return json.Marshal(SecretRedacted)
}

// UnmarshalJSON accepts a plain string so the type is a drop-in if a tree
// value is ever decoded into it, but REFUSES the redaction sentinel: a
// round-trip through the redacting marshaller must never silently reload
// "<redacted>" as a real secret. The compiled-config SSOT is the AST tree,
// not JSON, so this path should not be reached today; it fails closed if
// that ever changes.
func (s *Secret) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	if v == SecretRedacted {
		return errRedactedSecretIngest
	}
	*s = Secret(v)
	return nil
}

// MarshalYAML mirrors MarshalJSON for the gopkg.in/yaml.v3 marshaller. No
// config YAML marshaller exists today, but the issue title names YAML and
// the method is detected by interface so this future-proofs the YAML
// surface at no cost. A value receiver keeps redaction firing in slices and
// map values.
func (s Secret) MarshalYAML() (any, error) {
	if s == "" {
		return "", nil
	}
	return SecretRedacted, nil
}
