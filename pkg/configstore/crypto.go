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

	"github.com/psaab/bpfrx/pkg/config"
)

const encryptedTreeFormat = "bpfrx-master-password-v1"

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

func masterPasswordPRF(tree *config.ConfigTree) string {
	if tree == nil {
		return ""
	}
	sys := tree.FindChild("system")
	if sys == nil {
		return ""
	}
	mp := sys.FindChild("master-password")
	if mp == nil {
		return ""
	}
	prf := mp.FindChild("pseudorandom-function")
	if prf == nil {
		return ""
	}
	return nodeValue(prf)
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

func (db *DB) maybeDecryptTreeJSON(data []byte) ([]byte, error) {
	env, ok, err := unmarshalEnvelope(data)
	if err != nil {
		return nil, err
	}
	if !ok {
		return data, nil
	}

	keyMaterial, err := db.readMasterKey()
	if err != nil {
		return nil, fmt.Errorf("encrypted config but master key unavailable: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	key, err := deriveEncryptionKeyFromSalt(keyMaterial, env.PRF, salt)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt config tree: %w", err)
	}
	return plaintext, nil
}

func marshalEnvelope(env encryptedTreeEnvelope) ([]byte, error) {
	type alias encryptedTreeEnvelope
	return json.Marshal(alias(env))
}

func unmarshalEnvelope(data []byte) (encryptedTreeEnvelope, bool, error) {
	type alias encryptedTreeEnvelope
	var env alias
	if err := json.Unmarshal(data, &env); err != nil {
		return encryptedTreeEnvelope{}, false, nil
	}
	if env.Format != encryptedTreeFormat {
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
	key, err := hkdf.Key(hashFn, keyMaterial, salt, "bpfrx-configstore-master-password", 32)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return key, nil
}

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

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, key, 0600); err != nil {
		return nil, fmt.Errorf("write master key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("persist master key: %w", err)
	}
	return key, nil
}
