package userspace

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// #8597 K80: `handleOversizedFrame` advances the ACK watermark from a seq that,
// on one of its two paths, comes from a header the reader has just concluded is
// not a header. The advance is safe — but for a reason that lives in ANOTHER
// COMPONENT AND ANOTHER LANGUAGE: the helper validates every ACK against
// [acked_seq, next_seq] and ignores one outside it (#2959,
// userspace-dp/src/event_stream/control.rs).
//
// The comment at that call site used to assert a LOCAL property instead ("its
// aligned-header seq is trustworthy") which is false on the desync path. It now
// names the remote guarantee it actually depends on. That is a better comment
// and a worse dependency: a rationale that points at code in another crate is
// hollowed the moment that code changes, and nothing would re-check it.
//
// So bind it. If the helper's out-of-window ACK rejection is removed or
// weakened, this goes RED and names the Go comment that is now false — rather
// than leaving a confident justification standing in front of a guarantee that
// no longer exists.
//
// This is the same shape as the #8597 K83 producer binding: the hazard is a
// future change on the far side, so the guard belongs at the build.

func TestHelperStillRejectsOutOfWindowAcks8597K80(t *testing.T) {
	path := filepath.Join("..", "..", "..", "userspace-dp", "src", "event_stream", "control.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v — this guard binds a Go comment to the Rust guarantee "+
			"it cites, so it must not pass when it cannot see it", path, err)
	}

	// The rejection: a sequence below the acked watermark or above the highest
	// allocated one is ignored rather than applied. Matched structurally (the
	// comparison against both bounds) rather than by a quoted sentence, so a
	// comment rewrite does not red it but a behaviour change does.
	window := regexp.MustCompile(`seq\s*<\s*acked\s*\|\|\s*seq\s*>\s*next`)
	if !window.Match(src) {
		t.Fatal("#8597 K80: userspace-dp/src/event_stream/control.rs no longer rejects " +
			"an ACK outside [acked_seq, next_seq].\n\n" +
			"That check (#2959) is the ONLY thing that makes handleOversizedFrame's " +
			"unconditional watermark advance safe on its desync path, where the seq " +
			"comes from a header the reader has already concluded is not a header. " +
			"The comment in eventstream.go now says so explicitly.\n\n" +
			"If the rejection was deliberately changed, the Go comment and the #8597 " +
			"K80 refutation both need revisiting — the residual there is currently " +
			"argued to be small BECAUSE an out-of-window ACK is ignored.")
	}

	// DEGENERATE-FAILURE CONTROL. A regex that silently matched nothing would
	// make the assertion above unfalsifiable; anchor on a second, independent
	// token from the same block so a wholesale rewrite cannot leave this
	// passing on a coincidence.
	if !regexp.MustCompile(`frames_invalid_acks`).Match(src) {
		t.Fatal("control.rs no longer counts frames_invalid_acks — the out-of-window " +
			"ACK path was restructured, so the window check above may be matching " +
			"something unrelated. Re-verify the guarantee before trusting either " +
			"this guard or the eventstream.go comment that cites it")
	}
}
