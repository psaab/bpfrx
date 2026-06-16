package configstore

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrConfigDBUnreadable tags a Store.Load failure caused by a PRESENT but
// unreadable active.json — a JSON parse error, a decrypt failure, or a
// config compatibility envelope that this build cannot read (too-new
// min-reader / format). It is distinct from an absent DB (start-fresh) and
// from a compile error (handled leniently). The daemon makes this FATAL at
// startup so an unparseable or too-new DB is never silently overwritten by
// a blind bootstrap (#1917 increment B, plan §6.4 / D1 fatal-on-parse).
var ErrConfigDBUnreadable = errors.New("config DB present but unreadable")

// Config-DB compatibility envelope (#1917 increment B, plan §6.4 / D1).
//
// The envelope is EMBEDDED in active.json as a single magic header LINE
// prepended to the (possibly-encrypted) JSON body, NOT a sidecar manifest
// and NOT a wrapping JSON object. The encoding is deliberately one the
// CURRENT pre-envelope reader REJECTS rather than silently empty-loads:
//
//   - the pre-envelope reader runs json.Unmarshal(data, &ConfigTree{})
//     (db.go readTree) — a leading '#' line is NOT valid JSON, so it
//     ERRORS. Paired with fatal-on-parse (daemon_run.go), an old reader
//     fails closed on a too-new DB instead of overwriting it.
//   - a {manifest,tree} JSON OBJECT would empty-load on the old reader
//     (Go ignores unknown fields), silently wiping config. That is the
//     defect this floor closes (rev-8 codex-review-010, SMR-proven).
//
// On-disk layout of an enveloped active.json:
//
//	#xpf-config-envelope v=1 writer=<ver> ast=<n> min-reader=<n> rollback-fmt=<n>\n
//	{ ...the existing (possibly AES-GCM-encrypted) JSON body... }
//
// The header line is the OUTERMOST framing: it wraps the encrypted bytes
// for a write and is stripped BEFORE decryption on a read, so an old
// reader sees the '#' before either its decrypt-or-passthrough fallback
// or its json.Unmarshal — both reject it.
//
// A body with NO leading '#' is a pre-envelope (legacy) DB; the floor
// release still reads it (back-compat), so upgrading TO the floor release
// is non-destructive.

const (
	// envelopeMagic is the fixed token that opens the header line. The
	// leading '#' is load-bearing: it is what makes the old reader's
	// json.Unmarshal fail closed.
	envelopeMagic = "#xpf-config-envelope"

	// EnvelopeFormatVersion is the envelope grammar version (the `v=`
	// field). Bump only on an incompatible header-grammar change; a
	// reader rejects an envelope whose v= it does not understand.
	EnvelopeFormatVersion = 1

	// EnvelopeASTVersion is the current config AST/schema version the
	// writer stamps. Informational today (carried for future migrations);
	// not gated on read.
	EnvelopeASTVersion = 1

	// EnvelopeMinReaderVersion is the minimum envelope-format version a
	// reader must support to safely load a DB this build writes. A reader
	// whose EnvelopeFormatVersion < the stored min-reader fails closed.
	// It equals EnvelopeFormatVersion today (this build both writes and
	// requires v1); a future incompatible writer raises it.
	EnvelopeMinReaderVersion = 1

	// EnvelopeRollbackFormatVersion is the rollback-slot DB format version
	// (carried so a future rollback-format change is detectable). The
	// auto-rollback DB-restore path (xpf-upgrade) keys binary+DB atomic
	// rollback on this matching.
	EnvelopeRollbackFormatVersion = 1
)

// envelopeHeader is the parsed content of the magic header line.
type envelopeHeader struct {
	FormatVersion  int
	Writer         string
	ASTVersion     int
	MinReader      int
	RollbackFormat int
}

// hasEnvelope reports whether data begins with the envelope magic line.
func hasEnvelope(data []byte) bool {
	return bytes.HasPrefix(data, []byte(envelopeMagic))
}

// buildEnvelopeHeaderLine renders the magic header line (including the
// trailing newline) for the given writer version.
func buildEnvelopeHeaderLine(writer string) []byte {
	if writer == "" {
		writer = "unknown"
	}
	// writer is a build version string; strip any whitespace/newline so it
	// can never break the single-line header grammar.
	writer = sanitizeEnvelopeToken(writer)
	line := fmt.Sprintf("%s v=%d writer=%s ast=%d min-reader=%d rollback-fmt=%d\n",
		envelopeMagic, EnvelopeFormatVersion, writer,
		EnvelopeASTVersion, EnvelopeMinReaderVersion, EnvelopeRollbackFormatVersion)
	return []byte(line)
}

// sanitizeEnvelopeToken removes whitespace from a header token value so a
// malformed writer-version string cannot inject a newline or split the
// key=value grammar.
func sanitizeEnvelopeToken(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return '-'
		default:
			return r
		}
	}, s)
}

// wrapEnvelope prepends the magic header line to body. body is the
// already-(maybe-)encrypted JSON bytes.
func wrapEnvelope(body []byte, writer string) []byte {
	header := buildEnvelopeHeaderLine(writer)
	out := make([]byte, 0, len(header)+len(body))
	out = append(out, header...)
	out = append(out, body...)
	return out
}

// stripEnvelope validates the magic header line, enforces the min-reader
// gate, and returns the body bytes (everything after the first newline).
// The caller MUST have confirmed hasEnvelope(data) first.
//
// A reader that does not understand the stored envelope (v= too new, or
// min-reader > this build's EnvelopeFormatVersion) returns an error so the
// daemon FAILS CLOSED rather than misreading a too-new DB.
func stripEnvelope(data []byte) ([]byte, *envelopeHeader, error) {
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		return nil, nil, fmt.Errorf("config envelope: header line has no terminating newline")
	}
	headerLine := strings.TrimRight(string(data[:nl]), "\r")
	body := data[nl+1:]

	hdr, err := parseEnvelopeHeader(headerLine)
	if err != nil {
		return nil, nil, err
	}

	// Min-reader gate: a DB stamped min-reader=N can only be read by a
	// build whose envelope-format support is >= N. Too-new => fail closed.
	if hdr.MinReader > EnvelopeFormatVersion {
		return nil, nil, fmt.Errorf(
			"config envelope requires reader format >= %d but this build supports %d; "+
				"the config DB was written by a NEWER xpf and cannot be safely read "+
				"(upgrade xpf, or roll the binary forward); refusing to load to avoid "+
				"silently misreading or overwriting the config",
			hdr.MinReader, EnvelopeFormatVersion)
	}
	// Defense-in-depth: also reject an envelope grammar version we do not
	// understand even if min-reader were (wrongly) low.
	if hdr.FormatVersion > EnvelopeFormatVersion {
		return nil, nil, fmt.Errorf(
			"config envelope format v=%d is newer than this build supports (v=%d); refusing to load",
			hdr.FormatVersion, EnvelopeFormatVersion)
	}

	return body, hdr, nil
}

// parseEnvelopeHeader parses the magic header line into an envelopeHeader.
func parseEnvelopeHeader(line string) (*envelopeHeader, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 || fields[0] != envelopeMagic {
		return nil, fmt.Errorf("config envelope: malformed header line %q", line)
	}
	hdr := &envelopeHeader{}
	seenVersion := false
	for _, f := range fields[1:] {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			return nil, fmt.Errorf("config envelope: malformed header field %q", f)
		}
		switch k {
		case "v":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("config envelope: bad v=%q: %w", v, err)
			}
			hdr.FormatVersion = n
			seenVersion = true
		case "writer":
			hdr.Writer = v
		case "ast":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("config envelope: bad ast=%q: %w", v, err)
			}
			hdr.ASTVersion = n
		case "min-reader":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("config envelope: bad min-reader=%q: %w", v, err)
			}
			hdr.MinReader = n
		case "rollback-fmt":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("config envelope: bad rollback-fmt=%q: %w", v, err)
			}
			hdr.RollbackFormat = n
		default:
			// Unknown fields are tolerated (additive forward-compat); the
			// v=/min-reader gate is what governs readability.
		}
	}
	if !seenVersion {
		return nil, fmt.Errorf("config envelope: header missing required v= field: %q", line)
	}
	return hdr, nil
}
