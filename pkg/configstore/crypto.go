package configstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

const encryptedTreeFormat = "xpf-master-password-v1"

type encryptedTreeEnvelope struct {
	Format string `json:"format"`
	PRF    string `json:"prf"`
	Salt   string `json:"salt"`
	Nonce  string `json:"nonce"`
	Data   string `json:"data"`
}

func (db *DB) masterKeyPath() string {
	return filepath.Join(db.dir, "master.key")
}

// masterPasswordPRF resolves the master-password pseudorandom-function that
// decides whether the config DB is written encrypted (maybeEncryptTreeJSON)
// and whether the #4579 A4-06 plaintext-downgrade warning fires (db.go
// readTreeMeta). It MUST consider every surface that activates encryption at
// runtime: every top-level `system` stanza (#4705) AND any `master-password`
// anywhere under a `groups { ... }` block reachable via apply-groups (#5231).
//
// Top-level split stanzas (#4705): the Junos parser does not merge duplicate
// top-level stanzas — parseStatements appends each `system { ... }` block as
// its own child, and neither LoadOverride nor SyncApply (both raw
// NewParser().Parse()) coalesce them. The compiler already treats a split
// config as one system — compileSections loops over ALL top-level nodes and
// folds every `system` node into the same cfg.System — so a `master-password`
// living in a SECOND system stanza is semantically active. A single-first-match
// tree.FindChild("system") would then miss it and write the whole DB (secrets
// included) in PLAINTEXT despite encryption being configured.
//
// Groups / apply-groups (#5231): a `master-password` declared inside a
// `groups { ... }` body and pulled in with `apply-groups <name>` is ACTIVE at
// runtime — compileConfigWithOpts expands apply-groups (tree.ExpandGroups)
// BEFORE compileSystem reads master-password (compiler_system.go), so the
// effective config carries the PRF. But this at-rest write path runs on the
// UNEXPANDED persisted candidate tree (apply-groups expansion happens only on
// a compile clone), so the group-declared master-password is INVISIBLE to
// systemBlocksOf, the encrypt gate returns "", and active.json (IKE PSKs,
// WireGuard keys, SNMP communities, user secrets) is written PLAINTEXT despite
// encryption being configured via a group.
//
// Fail CLOSED — err toward encrypting. The group scan is a RECURSIVE walk of
// the entire `groups { ... }` subtree that treats ANY `master-password`
// descendant as encryption-configured, regardless of the intervening node
// name. It deliberately does NOT require a node literally named `system`
// between the group and the master-password, because a group's children can be
// authored under a `<*>` wildcard node whose body Junos merges into the
// top-level `system` stanza at apply-groups expansion (walkGroupToContext /
// mergeNodes, ast_groups.go). A literal `system`-only scan MISSES that
// wildcard shape and leaks plaintext end-to-end (the residual this walk
// closes). The invariant is now: any master-password anywhere under any
// `groups` block triggers encryption. This over-encrypts on a defined-but-
// unapplied group (a harmless FALSE-POSITIVE — encrypting when unnecessary is
// always safe) and can NEVER FALSE-NEGATIVE relative to runtime: apply-groups
// only COPIES existing leaves, so any PRF active after expansion physically
// exists somewhere under a group body here. Reusing the compiler's
// ExpandGroups would instead mutate the very tree we are about to persist and
// drag ${node}/undefined-group error handling into a write path that must not
// fail, for no security gain.
func masterPasswordPRF(tree *config.ConfigTree) string {
	if tree == nil {
		return ""
	}

	// Surface 1: every top-level `system { ... }` stanza (#4705).
	if prf := masterPasswordPRFInSystems(systemBlocksOf(tree)); prf != "" {
		return prf
	}

	// Surface 2: any `master-password` anywhere under any `groups { ... }`
	// block (#5231) — recursive so it catches a master-password nested under a
	// `<*>` wildcard (or any other intervening node), not only a literal
	// `system` child.
	for _, groupsRoot := range groupsBlocksOf(tree) {
		if prf := masterPasswordPRFInSubtree(groupsRoot); prf != "" {
			return prf
		}
	}
	return ""
}

// masterPasswordPRFInSystems returns the first non-empty master-password
// pseudorandom-function value across the given system-shaped nodes. Used by
// the top-level (#4705) scan in masterPasswordPRF.
func masterPasswordPRFInSystems(systems []*config.Node) string {
	for _, sys := range systems {
		if prf := masterPasswordPRFOfNode(sys); prf != "" {
			return prf
		}
	}
	return ""
}

// masterPasswordPRFOfNode returns the first non-empty pseudorandom-function
// value carried by a `master-password` child of node.
func masterPasswordPRFOfNode(node *config.Node) string {
	if node == nil {
		return ""
	}
	for _, mp := range node.FindChildren("master-password") {
		prf := mp.FindChild("pseudorandom-function")
		if prf == nil {
			continue
		}
		if v := nodeValue(prf); v != "" {
			return v
		}
	}
	return ""
}

// masterPasswordPRFInSubtree recursively searches node and all its descendants
// for any `master-password { pseudorandom-function <X> }` and returns the first
// non-empty PRF value found. It is read-only and total — nil-safe and never
// errors or panics on a malformed tree — because it runs on the config write
// path, which must not fail. See masterPasswordPRF for why the groups/
// apply-groups scan (#5231) recurses instead of keying on a literal `system`
// node name.
func masterPasswordPRFInSubtree(node *config.Node) string {
	if node == nil {
		return ""
	}
	if len(node.Keys) > 0 && node.Keys[0] == "master-password" {
		if prf := node.FindChild("pseudorandom-function"); prf != nil {
			if v := nodeValue(prf); v != "" {
				return v
			}
		}
	}
	for _, child := range node.Children {
		if v := masterPasswordPRFInSubtree(child); v != "" {
			return v
		}
	}
	return ""
}

func nodeValue(n *config.Node) string {
	if n == nil {
		return ""
	}
	if len(n.Keys) >= 2 {
		return n.Keys[1]
	}
	if len(n.Children) > 0 {
		return n.Children[0].Name()
	}
	return ""
}

func (db *DB) maybeEncryptTreeJSON(data []byte, tree *config.ConfigTree) ([]byte, error) {
	prf := masterPasswordPRF(tree)
	if prf == "" {
		return data, nil
	}

	keyMaterial, err := db.readOrCreateMasterKey()
	if err != nil {
		return nil, err
	}
	key, salt, err := deriveEncryptionKey(keyMaterial, prf)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	env := encryptedTreeEnvelope{
		Format: encryptedTreeFormat,
		PRF:    prf,
		Salt:   base64.StdEncoding.EncodeToString(salt),
		Nonce:  base64.StdEncoding.EncodeToString(nonce),
		Data:   base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, data, nil)),
	}
	return marshalEnvelope(env)
}

// maybeDecryptTreeJSON returns the plaintext body of a stored config.
// The second return value reports whether the input was an AES-GCM
// envelope that was actually decrypted (true) or was passed through as
// plaintext because it carried no envelope (false). Callers that know
// the config declares a master-password use the flag to detect an
// unexpected plaintext downgrade (#4579 A4-06).
func (db *DB) maybeDecryptTreeJSON(data []byte) ([]byte, bool, error) {
	env, ok, err := unmarshalEnvelope(data)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return data, false, nil
	}

	keyMaterial, err := db.readMasterKey()
	if err != nil {
		return nil, false, fmt.Errorf("encrypted config but master key unavailable: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return nil, false, fmt.Errorf("decode salt: %w", err)
	}
	key, err := deriveEncryptionKeyFromSalt(keyMaterial, env.PRF, salt)
	if err != nil {
		return nil, false, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, false, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, false, fmt.Errorf("decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false, fmt.Errorf("create GCM: %w", err)
	}
	// #4793: cipher.AEAD.Open panics if len(nonce) != gcm.NonceSize()
	// instead of returning an error. A corrupt or tampered on-disk
	// envelope (bad base64 length, truncated write, hand-edited JSON)
	// would otherwise crash the daemon here on every boot — a
	// config-DB-triggered boot loop. Fail closed with a plain error so
	// the caller can report it instead of the process dying.
	if len(nonce) != gcm.NonceSize() {
		return nil, false, fmt.Errorf("invalid nonce length %d (want %d)", len(nonce), gcm.NonceSize())
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, false, fmt.Errorf("decrypt config tree: %w", err)
	}
	return plaintext, true, nil
}

func marshalEnvelope(env encryptedTreeEnvelope) ([]byte, error) {
	type alias encryptedTreeEnvelope
	return json.Marshal(alias(env))
}

func unmarshalEnvelope(data []byte) (encryptedTreeEnvelope, bool, error) {
	type alias encryptedTreeEnvelope
	var env alias
	if err := json.Unmarshal(data, &env); err != nil {
		// Not JSON, or not the envelope object shape at all — a genuine
		// plaintext (pre-encryption / legacy) config body. Pass through.
		return encryptedTreeEnvelope{}, false, nil
	}
	if env.Format != encryptedTreeFormat {
		// Fail CLOSED on an envelope-shaped body whose discriminator we do not
		// support (#4888). An unknown/future `format`
		// (e.g. xpf-master-password-v2), or the AES-GCM fields
		// (salt/nonce/data) present without our current `format`, is a too-new
		// or corrupted ENCRYPTED DB — it MUST be rejected, never treated as
		// plaintext. Treating it as plaintext lets json.Unmarshal drop the
		// unknown fields and decode an EMPTY ConfigTree, so Store.Load would
		// boot a committed-empty config (loss of policy) instead of failing
		// closed with ErrConfigDBUnreadable. Only a body with NO format AND no
		// AES-GCM fields is a genuine plaintext body and passes through.
		if env.Format != "" || env.Salt != "" || env.Nonce != "" || env.Data != "" {
			return encryptedTreeEnvelope{}, false, fmt.Errorf(
				"unsupported encrypted config envelope format %q (too-new or corrupted config DB)", env.Format)
		}
		return encryptedTreeEnvelope{}, false, nil
	}
	if env.PRF == "" || env.Salt == "" || env.Nonce == "" || env.Data == "" {
		return encryptedTreeEnvelope{}, false, fmt.Errorf("invalid encrypted config envelope")
	}
	return encryptedTreeEnvelope(env), true, nil
}

func deriveEncryptionKey(keyMaterial []byte, prf string) ([]byte, []byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("generate salt: %w", err)
	}
	key, err := deriveEncryptionKeyFromSalt(keyMaterial, prf, salt)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}

func deriveEncryptionKeyFromSalt(keyMaterial []byte, prf string, salt []byte) ([]byte, error) {
	hashFn, err := prfHash(prf)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(hashFn, keyMaterial, salt, "xpf-configstore-master-password", 32)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return key, nil
}

// prfHash maps a master-password pseudorandom-function selector name to its
// hash constructor. It is the SSOT for the name->hash.Hash mapping; the
// accepted NAMES are mirrored in config.masterPasswordPRFNames, which the
// commit-time gate (config.ValidateMasterPasswordPRF, #4578) uses to reject a
// typo'd selector BEFORE it reaches this path. Adding a case here means adding
// the name there too. Matching is case-insensitive (the commit gate mirrors
// this ToLower).
func prfHash(prf string) (func() hash.Hash, error) {
	switch strings.ToLower(prf) {
	case "juniper-prf1", "hmac-sha2-256", "sha256":
		return sha256.New, nil
	case "hmac-sha2-384", "sha384":
		return sha512.New384, nil
	case "hmac-sha2-512", "sha512":
		return sha512.New, nil
	case "hmac-sha1", "sha1":
		return sha1.New, nil
	default:
		return nil, fmt.Errorf("unsupported master-password pseudorandom-function %q", prf)
	}
}

// readMasterKey reads an existing master key — never creates one.
// Used by the decrypt path to avoid overwriting a lost key.
func (db *DB) readMasterKey() ([]byte, error) {
	path := db.masterKeyPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read master key: %w", err)
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("invalid master key length in %s", path)
	}
	return data, nil
}

func (db *DB) readOrCreateMasterKey() ([]byte, error) {
	path := db.masterKeyPath()
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != 32 {
			return nil, fmt.Errorf("invalid master key length in %s", path)
		}
		return data, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read master key: %w", err)
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}

	// DurableState (#1894): a master.key lost to a power cut after the
	// first encrypted active-config write makes that config permanently
	// undecryptable — the key must hit stable storage before any tree
	// encrypted with it does (readOrCreateMasterKey runs inside the
	// encrypt step of writeTree, so this ordering is structural).
	if err := fsatomic.WriteFileDurable(path, key, 0600); err != nil {
		return nil, fmt.Errorf("persist master key: %w", err)
	}
	return key, nil
}
