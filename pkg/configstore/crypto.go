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

// defaultMasterPasswordPRF is the supported PRF used to key at-rest encryption
// when encryption is required (a master-password is configured somewhere) but
// no SUPPORTED effective PRF can be resolved from the applied config — e.g. the
// encryption belt is triggered only by a dormant (inactive / unapplied-group)
// master-password, or the effective declaration carries an unsupported selector
// that slipped past the #4578 commit gate on a tolerant HA/upgrade path. It
// MUST be a value prfHash accepts so the persistence write never fails
// deterministically. See masterPasswordPRF (#5638 / codex-review-181 M30).
const defaultMasterPasswordPRF = "sha256"

// masterPasswordPRF resolves the master-password pseudorandom-function that
// keys at-rest encryption (maybeEncryptTreeJSON) and gates the #4579 A4-06
// plaintext-downgrade warning (db.go readTreeMeta). It answers TWO separable
// questions — conflating them caused #5638 (codex-review-181 M30):
//
//  1. IS ENCRYPTION REQUIRED?  Conservative, fail-closed. ANY master-password
//     anywhere — an active top-level `system` stanza (#4705), or any
//     `master-password` under any `groups { ... }` block including an
//     UNAPPLIED or `<*>`-wildcard group (#5231) — means "encrypt, never leak
//     plaintext." Over-encrypting a dormant/unapplied master-password is a
//     harmless false-positive; under-encrypting leaks secrets to disk. This is
//     masterPasswordConfigured.
//
//  2. WHICH PRF ALGORITHM?  Must be a SUPPORTED, DETERMINISTIC selector so the
//     write path never fails and an active↔standby pair reproduces the same
//     key. Resolve it from the EFFECTIVE/APPLIED scope only — the same
//     inactive-strip + apply-groups expansion the compiler applies
//     (effectiveMasterPasswordPRF) — and accept only a selector prfHash
//     understands. A dormant or unsupported PRF must NOT reach prfHash.
//
// Why the split matters (M30): the #4578 commit gate (ValidateMasterPasswordPRF)
// validates the EFFECTIVE tree (inactive stripped, groups expanded), so an
// UNSUPPORTED PRF hidden in an inactive node or an unapplied group is never
// rejected at commit. The old resolver's fail-closed SUPERSET, however, scanned
// every group regardless of application state and returned that unsupported
// value. On HA config-sync the standby promotes the peer tree in memory
// (Option B) and then persists it: masterPasswordPRF returned the dormant
// `bogus`, prfHash rejected it, writeActive failed, and the singleton retry
// re-selected `bogus` forever — a DETERMINISTIC, non-transient persistence
// failure that keeps the node /health-503 and its authoritative generation off
// disk (non-durable across restart). The fix keeps the encryption belt broad
// (question 1) but constrains the ALGORITHM to a supported effective value,
// falling back to defaultMasterPasswordPRF rather than poisoning the write with
// an unsupported selector. Encryption still happens; only a value prfHash
// accepts ever reaches it.
//
// The effective resolution is error-tolerant (any apply-groups expansion error
// falls through to the supported default), so the "this write path must not
// fail" contract that originally motivated NOT calling ExpandGroups here still
// holds — it runs on a clone and never propagates an error.
func masterPasswordPRF(tree *config.ConfigTree) string {
	if tree == nil {
		return ""
	}

	// Question 1: is at-rest encryption required at all? Fail-closed broad
	// scan (dormant/unapplied/wildcard included). Empty means plaintext.
	if !masterPasswordConfigured(tree) {
		return ""
	}

	// Question 2: choose a SUPPORTED, DETERMINISTIC algorithm from the
	// effective/applied scope. A dormant or unsupported effective value must
	// not reach prfHash on the persistence write path.
	if prf := effectiveMasterPasswordPRF(tree); prf != "" && prfSupported(prf) {
		return prf
	}

	// Encryption is required but the applied config resolves no supported PRF
	// (belt triggered by dormant content, or an unsupported effective value):
	// fall back to a fixed supported selector so the DB is still encrypted and
	// the write stays durable and deterministic across active↔standby.
	return defaultMasterPasswordPRF
}

// masterPasswordConfigured reports whether ANY master-password is present in
// the tree — the fail-closed "must we encrypt?" decision (#4705 split stanzas +
// #5231 groups/wildcard). It intentionally does NOT strip inactive nodes or
// require apply-groups: a master-password that exists anywhere (even dormant)
// means secrets have been or may be configured, and erring toward encryption is
// always safe. Read-only and total (nil-safe, never errors) — it runs on the
// config write path, which must not fail.
func masterPasswordConfigured(tree *config.ConfigTree) bool {
	if tree == nil {
		return false
	}
	// Surface 1: every top-level `system { ... }` stanza (#4705).
	if masterPasswordPRFInSystems(systemBlocksOf(tree)) != "" {
		return true
	}
	// Surface 2: any `master-password` anywhere under any `groups { ... }`
	// block (#5231) — recursive so it catches a master-password nested under a
	// `<*>` wildcard (or any other intervening node), not only a literal
	// `system` child.
	for _, groupsRoot := range groupsBlocksOf(tree) {
		if masterPasswordPRFInSubtree(groupsRoot) != "" {
			return true
		}
	}
	return false
}

// effectiveMasterPasswordPRF resolves the master-password PRF from the
// EFFECTIVE/APPLIED config only — the value the compiler would activate — so
// the algorithm chosen for at-rest encryption matches the running config and
// never comes from a dormant (inactive / unapplied-group) subtree. It mirrors
// the compile/schema path (schemaValidateExpandedTreeForNode): strip inactive
// THEN expand applied groups, on a CLONE, then scan the resulting top-level
// `system` stanzas. Returns "" when no active master-password resolves (the
// caller then uses the supported default).
//
// This runs on the config write path, which MUST NOT fail: it operates on a
// clone (never the persisted tree) and swallows every apply-groups expansion
// error (returning ""), so a ${node}/undefined-group condition degrades to the
// default rather than failing the write.
func effectiveMasterPasswordPRF(tree *config.ConfigTree) string {
	if tree == nil {
		return ""
	}
	// Fast path: with no groups to expand and no inactive nodes to strip, the
	// effective scope is exactly the raw top-level `system` stanzas. Scan
	// directly with zero extra allocation — this covers every normal active
	// config, keeping it bit-identical to the pre-#5638 resolver.
	if len(groupsBlocksOf(tree)) == 0 && !tree.HasInactiveNodes() {
		return masterPasswordPRFInSystems(systemBlocksOf(tree))
	}
	stripped := tree.WithoutInactive()
	expanded := stripped.Clone()
	if err := expanded.ExpandGroups(); err != nil {
		// A cluster ${node} group can only be expanded with the node var; the
		// write path is node-agnostic and the envelope is self-describing
		// (decrypt reads env.PRF), so a deterministic node0 substitution is
		// enough to resolve a supported selector. Any residual error degrades
		// to "" → the caller's supported default (the write must not fail).
		if strings.Contains(err.Error(), `undefined group "${node}"`) {
			vars := map[string]string{"node": "node0"}
			if err2 := expanded.ExpandGroupsWithVars(vars); err2 != nil {
				return ""
			}
		} else {
			return ""
		}
	}
	return masterPasswordPRFInSystems(systemBlocksOf(expanded))
}

// prfSupported reports whether prf is a selector prfHash can key encryption
// with. It is the single gate that keeps an unsupported PRF — one that slipped
// past the #4578 commit gate through a tolerant HA/upgrade load — off the
// deterministic persistence-retry path (#5638).
func prfSupported(prf string) bool {
	_, err := prfHash(prf)
	return err == nil
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

// aad is the AES-GCM additional authenticated data. The envelope write path
// passes the header line so the plaintext header — including the #1922
// committed= marker — is bound to the ciphertext and cannot be edited in place
// (#7176 C179-053). Callers with no header to bind (WriteConfirm) pass nil,
// which is the pre-#7176 behaviour and is correct for them: there is no
// plaintext preamble to authenticate.
func (db *DB) maybeEncryptTreeJSON(data []byte, tree *config.ConfigTree, aad []byte) ([]byte, error) {
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
		Data:   base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, data, aad)),
	}
	return marshalEnvelope(env)
}

// maybeDecryptTreeJSON returns the plaintext body of a stored config.
// The second return value reports whether the input was an AES-GCM
// envelope that was actually decrypted (true) or was passed through as
// plaintext because it carried no envelope (false). Callers that know
// the config declares a master-password use the flag to detect an
// unexpected plaintext downgrade (#4579 A4-06).
// aad must be byte-identical to what the writer sealed with, or the tag check
// fails. The envelope read path supplies the stored header line ONLY when the
// stored v= is at or above envelopeAADFormatVersion; below that it passes nil,
// which is how pre-v2 envelopes stay readable. A tampered v2 header — including
// one rewritten to claim v=1 — therefore fails to decrypt rather than being
// read under the weaker rule (#7176 C179-053).
func (db *DB) maybeDecryptTreeJSON(data []byte, aad []byte) ([]byte, bool, error) {
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
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
