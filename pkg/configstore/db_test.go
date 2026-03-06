package configstore

import (
	"os"
	"strings"
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestDBWriteReadPlainTree(t *testing.T) {
	dir := t.TempDir()
	db, err := NewDB(dir)
	if err != nil {
		t.Fatalf("NewDB() error = %v", err)
	}

	tree := testConfigTree("", "fw-plain")
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive() error = %v", err)
	}

	raw, err := os.ReadFile(db.activePath())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(raw), "\"fw-plain\"") {
		t.Fatalf("plain config was not persisted as JSON: %s", string(raw))
	}

	got, err := db.ReadActive()
	if err != nil {
		t.Fatalf("ReadActive() error = %v", err)
	}
	if got.FormatJSON() != tree.FormatJSON() {
		t.Fatalf("ReadActive() mismatch\ngot:\n%s\nwant:\n%s", got.FormatJSON(), tree.FormatJSON())
	}
}

func TestDBWriteReadEncryptedTree(t *testing.T) {
	dir := t.TempDir()
	db, err := NewDB(dir)
	if err != nil {
		t.Fatalf("NewDB() error = %v", err)
	}

	tree := testConfigTree("hmac-sha2-512", "fw-encrypted")
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive() error = %v", err)
	}

	raw, err := os.ReadFile(db.activePath())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(raw), "\"fw-encrypted\"") {
		t.Fatalf("encrypted config leaked plaintext host-name: %s", string(raw))
	}
	if !strings.Contains(string(raw), encryptedTreeFormat) {
		t.Fatalf("encrypted config missing envelope marker: %s", string(raw))
	}
	if _, err := os.Stat(db.masterKeyPath()); err != nil {
		t.Fatalf("master key was not created: %v", err)
	}

	got, err := db.ReadActive()
	if err != nil {
		t.Fatalf("ReadActive() error = %v", err)
	}
	if got.FormatJSON() != tree.FormatJSON() {
		t.Fatalf("ReadActive() mismatch\ngot:\n%s\nwant:\n%s", got.FormatJSON(), tree.FormatJSON())
	}
}

func TestDBRewritePlainAfterMasterPasswordRemoved(t *testing.T) {
	dir := t.TempDir()
	db, err := NewDB(dir)
	if err != nil {
		t.Fatalf("NewDB() error = %v", err)
	}

	if err := db.WriteActive(testConfigTree("juniper-prf1", "fw-encrypted")); err != nil {
		t.Fatalf("WriteActive(encrypted) error = %v", err)
	}
	if err := db.WriteActive(testConfigTree("", "fw-plain-again")); err != nil {
		t.Fatalf("WriteActive(plain) error = %v", err)
	}

	raw, err := os.ReadFile(db.activePath())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(raw), encryptedTreeFormat) {
		t.Fatalf("plain rewrite should not keep encrypted envelope: %s", string(raw))
	}
	if !strings.Contains(string(raw), "\"fw-plain-again\"") {
		t.Fatalf("plain rewrite missing host-name: %s", string(raw))
	}
}

func testConfigTree(prf, host string) *config.ConfigTree {
	system := &config.Node{
		Keys: []string{"system"},
		Children: []*config.Node{
			{Keys: []string{"host-name", host}, IsLeaf: true},
		},
	}
	if prf != "" {
		system.Children = append(system.Children, &config.Node{
			Keys: []string{"master-password"},
			Children: []*config.Node{
				{Keys: []string{"pseudorandom-function", prf}, IsLeaf: true},
			},
		})
	}
	return &config.ConfigTree{Children: []*config.Node{system}}
}
