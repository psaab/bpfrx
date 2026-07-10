package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestCompleteRejectsMidRunePos guards the #4970 UTF-8 boundary. Complete
// interprets req.Pos as a BYTE offset into req.Line (it does text[:req.Pos]),
// so a Pos that lands inside a multibyte rune must be rejected with
// InvalidArgument rather than slicing a code point in half and returning
// corrupted completion text.
//
// "show zöne" byte layout: s h o w SP z (0..5) then 'ö' occupies bytes 6-7
// (0xC3 0xB6) then n e (8,9). Byte offset 7 is 'ö's continuation byte — not a
// rune boundary. Offset 6 (start of 'ö') and offset 10 (end of line) are valid.
//
// Fail-on-revert: removing the utf8.RuneStart guard makes Complete accept
// Pos=7, slice "show z\xc3" (invalid UTF-8), and return a non-nil response
// instead of InvalidArgument — failing the mid-rune subcase below.
func TestCompleteRejectsMidRunePos(t *testing.T) {
	s := &Server{}
	const line = "show zöne" // 10 bytes, 9 runes

	t.Run("mid-rune-rejected", func(t *testing.T) {
		resp, err := s.Complete(context.Background(), &pb.CompleteRequest{Line: line, Pos: 7})
		if err == nil {
			t.Fatalf("Complete(pos=7 mid-rune) error = nil, want InvalidArgument")
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("Complete(pos=7 mid-rune) code = %v, want InvalidArgument", status.Code(err))
		}
		if resp != nil {
			t.Fatalf("Complete(pos=7 mid-rune) resp = %v, want nil on error", resp)
		}
	})

	t.Run("rune-boundary-accepted", func(t *testing.T) {
		// Offset 6 is the start of 'ö' — a valid boundary; text[:6] = "show z".
		resp, err := s.Complete(context.Background(), &pb.CompleteRequest{Line: line, Pos: 6})
		if err != nil {
			t.Fatalf("Complete(pos=6 boundary) error = %v, want nil", err)
		}
		if resp == nil {
			t.Fatalf("Complete(pos=6 boundary) resp = nil, want non-nil")
		}
	})

	t.Run("cursor-at-end-accepted", func(t *testing.T) {
		// Pos == byte length (what the fixed client sends): the guard's
		// int(req.Pos) < len(text) is false, so no re-slice, no corruption.
		resp, err := s.Complete(context.Background(), &pb.CompleteRequest{Line: line, Pos: int32(len(line))})
		if err != nil {
			t.Fatalf("Complete(pos=len boundary) error = %v, want nil", err)
		}
		if resp == nil {
			t.Fatalf("Complete(pos=len boundary) resp = nil, want non-nil")
		}
	})
}
