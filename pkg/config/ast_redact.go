package config

// ast_redact.go masks secret leaf VALUES in the raw-AST render paths.
//
// #2053 made the TYPED compiled-config render safe: the config.Secret newtype
// redacts every operator secret on JSON/YAML marshal, so GET /api/v1/config
// (which json-encodes the compiled *config.Config) no longer leaks cleartext.
// But the AST-render surface — Format / FormatSet / FormatJSON / FormatXML /
// FormatInheritance / FormatCompare in ast_format.go — walks the *ConfigTree
// AST and prints leaf key tokens VERBATIM. That surface backs the REST config
// show / export / search / rollback endpoints and the gRPC ShowConfig RPC, so
// those returned the same secrets (#2053 protects) in CLEARTEXT (#4051, fable
// F-020). Junos redacts secrets in `show configuration` (SECRET-DATA); xpf's
// raw-AST paths did not.
//
// RedactedClone masks the secret leaf values so the AST-render display paths
// mirror the #2053 guarantee. It is a DISPLAY-only transform applied at the
// REST + gRPC boundary: the cleartext Format() on the real tree still backs HA
// config sync (daemon_ha_sync.go), the DR/compliance archive (daemon_flow.go),
// on-disk persistence + rollback (configstore) and the on-box CLI, none of
// which may lose the real secret.
//
// The secret-leaf set is exactly #2053's Secret-typed field set, resolved to
// its AST leaf signatures (verified against the compiler's Secret(...) sites):
//
//	pre-shared-key            IKE policy / IPsec VPN PSK   (keeps ascii-text|hexadecimal qualifier)
//	authentication-key        OSPF/IS-IS/RIP/BGP/VRRP auth key + BGP TCP-MD5
//	simple-password           OSPF simple-password auth (same AuthKey field)
//	key (under authentication md5 <id>)   OSPF hello md5 key
//	authentication-password   SNMPv3 USM auth password
//	privacy-password          SNMPv3 USM privacy password
//	encrypted-password        root / login crypt(3) hash
//	api-key                   REST API bearer/X-API-Key token(s)
//	password (under api-auth | dynamic-dns)  REST basic-auth / DDNS HTTP password
//	tsig-secret               RFC 2136 / DDNS TSIG HMAC key
//	api-token                 Cloudflare / DuckDNS DDNS API token
//	aws-secret-key            Route 53 DDNS AWS secret access key
//	private-key               WireGuard local static private key
//	preshared-key             WireGuard per-peer PSK
//	community (under snmp)     SNMP v1/v2c community string (the identity token)

// SecretDataPlaceholder is the mask emitted in place of a secret leaf value on
// the raw-AST render/display paths. It mirrors the Junos SECRET-DATA idiom and
// is deliberately distinct from the typed-struct redaction sentinel
// (SecretRedacted, "<redacted>") so the two surfaces stay independently
// greppable. It contains non-identifier characters, so a text/set/XML render
// quotes it — the output stays structurally valid.
const SecretDataPlaceholder = "##SECRET-DATA##"

// RedactedClone returns a deep copy of the tree with every secret leaf value
// masked by SecretDataPlaceholder, for the raw-AST DISPLAY paths (REST config
// show / export / search / rollback + gRPC ShowConfig / ShowCompare /
// ShowRollback). Structure, ordering, inactive markers and all non-secret
// values are preserved, so the redacted render is byte-identical to the
// cleartext render except at the masked value tokens. Returns nil for a nil
// receiver (callers mirror the nil handling of their cleartext siblings).
//
// It operates on a clone so the live tree — the SSOT for HA sync, the DR
// archive and persistence — is never mutated.
func (t *ConfigTree) RedactedClone() *ConfigTree {
	if t == nil {
		return nil
	}
	c := t.Clone()
	redactNodes(c.Children, nil)
	return c
}

// redactNodes walks nodes maintaining the flattened key path of all ancestors
// (base). A secret token is identified on the FULL flattened path so it is
// matched identically whether the parser produced a hierarchical tree (secret
// split across nested block nodes) or a flat SetPath collapsed the whole
// branch onto one leaf's Keys (the dual AST shape, CLAUDE.md). Each secret
// index is masked in whichever node's own Keys slice owns it (idx >= len(base))
// — so a container-identity secret (an SNMP community name) is masked once, on
// the node that introduces it, and its descendants skip it.
func redactNodes(nodes []*Node, base []string) {
	for _, n := range nodes {
		full := append(append([]string(nil), base...), n.Keys...)
		for _, idx := range secretIndices(full) {
			if idx >= len(base) && idx < len(full) {
				n.Keys[idx-len(base)] = SecretDataPlaceholder
			}
		}
		if !n.IsLeaf {
			redactNodes(n.Children, full)
		}
	}
}

// secretIndices returns the indices into the flattened key path fp that carry
// a secret value and must be masked. It reuses #2053's secret-leaf set (see
// the file header) resolved to keyword signatures; generic keywords (key,
// password, community) are disambiguated by required ancestor context so a
// GRE tunnel `key`, a chassis identity `key` or a routing-policy `community`
// (all non-secret) are never masked.
func secretIndices(fp []string) []int {
	var out []int
	for i, k := range fp {
		switch k {
		case "pre-shared-key":
			// Value token(s) follow; keep a leading ascii-text|hexadecimal
			// format qualifier so the render stays structurally valid.
			j := i + 1
			if j < len(fp) && (fp[j] == "ascii-text" || fp[j] == "hexadecimal") {
				j++
			}
			for ; j < len(fp); j++ {
				out = append(out, j)
			}
		case "authentication-key", "authentication-password", "privacy-password",
			"encrypted-password", "simple-password", "api-key", "tsig-secret",
			"api-token", "aws-secret-key", "private-key", "preshared-key":
			// Distinctive secret keywords: every token after the keyword is
			// secret value (covers multi-token / bracketed list values too).
			for j := i + 1; j < len(fp); j++ {
				out = append(out, j)
			}
		case "password":
			// Generic keyword — secret only under REST api-auth or a DDNS
			// provider; other `password` uses do not exist today but the
			// context gate keeps a future non-secret `password` unmasked.
			if containsAnyOf(fp[:i], "api-auth", "dynamic-dns") {
				for j := i + 1; j < len(fp); j++ {
					out = append(out, j)
				}
			}
		case "key":
			// Generic keyword — secret only as the OSPF hello md5 key:
			// `authentication md5 <key-id> key <secret>`. A GRE tunnel `key`
			// or a chassis device-map identity `key` has no such context.
			if i >= 3 && fp[i-2] == "md5" && fp[i-3] == "authentication" && i+1 < len(fp) {
				out = append(out, i+1)
			}
		case "community":
			// SNMP v1/v2c community string is the container-identity token
			// directly under `snmp` (the whole point of the community is a
			// shared secret). A policy-options `community` is a routing object
			// under policy-options, not snmp — left unmasked.
			if i >= 1 && fp[i-1] == "snmp" && i+1 < len(fp) {
				out = append(out, i+1)
			}
		}
	}
	return out
}

// containsAnyOf reports whether seq contains any of names.
func containsAnyOf(seq []string, names ...string) bool {
	for _, s := range seq {
		for _, n := range names {
			if s == n {
				return true
			}
		}
	}
	return false
}
