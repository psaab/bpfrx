package configstore

import (
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4690: a corrupt rollback file must be logged by POSITION ONLY (line/column),
// never by forwarding the config.ParseError / its text. A rollback file is the
// full active config TEXT with cleartext secret leaves (IKE PSK, auth keys,
// SNMP community), and config.ParseError.Error() embeds ParseError.Message,
// which the lexer/parser can populate with offending token/character content.
// Routing errs[0] into the log therefore risks echoing file content — the same
// invariant the #4099 rescue path enforces.
//
// RED-on-revert: restoring `slog.Warn("skipping corrupt rollback file",
// "path", path, "err", errs[0])` makes the log carry the ParseError's Error()
// text (its Message), so the "message text absent" assertion below fires RED.
func TestLoadRollbackHistoryCorruptFileLogsPositionOnly(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config"
	s := newTestStoreAt(t, path)

	// A realistic corrupt rollback file: valid config carrying a secret PSK,
	// then a stray '|' token that the parser rejects. The PSK value is
	// consumed as a leaf value (never echoed by the parser), and the parse
	// error message is a generic "unexpected '|'" — but the OLD code forwarded
	// that whole ParseError text into the log; the fix logs only line/column.
	const secret = "SUPERSECRETPSK987"
	corrupt := "security {\n" +
		"    ike {\n" +
		"        pre-shared-key ascii-text \"" + secret + "\";\n" +
		"    }\n" +
		"}\n" +
		"| stray-token\n"
	if err := os.WriteFile(s.rollbackPath(1), []byte(corrupt), 0o600); err != nil {
		t.Fatalf("seed corrupt rollback file: %v", err)
	}

	// Compute the ParseError this text produces so the assertion targets the
	// exact Message that the old code would have leaked into the log.
	_, perrs := config.NewParser(corrupt).Parse()
	if len(perrs) == 0 {
		t.Fatal("test setup: corrupt config must fail to parse")
	}

	// syncBuffer (not a raw bytes.Buffer): the slog sink is installed
	// process-globally, so a persistRetryLoop goroutine leaked from an earlier
	// test writes through the handler while this test reads via String() —
	// the -race read/write must share a lock (#6446).
	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	s.loadRollbackHistory()

	logged := buf.String()
	if !strings.Contains(logged, "skipping corrupt rollback file") {
		t.Fatalf("expected a corrupt-rollback warning, got:\n%s", logged)
	}
	// The parse-error MESSAGE must NOT appear (this is the RED-on-revert gate):
	// forwarding errs[0] renders its Error() text ("... unexpected '|'").
	if strings.Contains(logged, perrs[0].Message) {
		t.Fatalf("corrupt-rollback log leaked the ParseError message %q:\n%s", perrs[0].Message, logged)
	}
	// Defense-in-depth: the secret must never appear either.
	if strings.Contains(logged, secret) {
		t.Fatalf("corrupt-rollback log leaked secret file content:\n%s", logged)
	}
	// Position must still be logged so operators can locate the corruption.
	if !strings.Contains(logged, "line=") || !strings.Contains(logged, "column=") {
		t.Fatalf("corrupt-rollback log must carry line/column position, got:\n%s", logged)
	}
}
