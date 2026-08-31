package termsafe

import (
	"io"
	"sync"
)

// maxBufferedLine bounds how much a SanitizingWriter will hold waiting for a
// newline before emitting anyway.
//
// #7389: the motivating caller is `monitor traffic` (tcpdump), whose output is
// unbounded and interactive. A writer that buffered until a newline would grow
// without limit on a stream that never emits one -- a remote party choosing
// the packet bytes chooses whether a newline ever arrives, so "wait for the
// line to end" is an attacker-controlled allocation. Emitting a partial line
// is a cosmetic wrap; holding it is a memory defect.
const maxBufferedLine = 64 * 1024

// SanitizingWriter wraps an io.Writer and sanitizes everything passing through
// it with SanitizeBlockForDisplay, LINE AT A TIME.
//
// #7389: `handleMonitorTraffic` (tcpdump) and `handleTraceroute` wired
// `cmd.Stdout = os.Stdout` directly, so there was no string to sanitize and
// the #6584 sweep could not reach them. They are the two highest-taint sites
// in that class: tcpdump renders packet BYTES as ASCII, so the payload is
// chosen by whoever sends the packet, and traceroute resolves PTR records by
// default, so the displayed hostnames come from DNS an attacker may control.
// Both stream straight to the operator's terminal.
//
// Buffered capture was rejected: it is unbounded for tcpdump, and it breaks
// Ctrl-C and the incremental output that is the entire point of `monitor
// traffic`. A line-wise writer preserves the streaming UX.
//
// Line-at-a-time rather than chunk-at-a-time because a read boundary can fall
// mid-rune. Sanitizing a chunk that ends halfway through a multi-byte rune
// would escape the split bytes as invalid UTF-8 and corrupt legitimate output
// -- the sanitizer would be the thing mangling the text. Holding a partial
// line until its newline (or the bound) keeps runes intact.
type SanitizingWriter struct {
	mu  sync.Mutex
	w   io.Writer
	buf []byte
}

// NewSanitizingWriter returns a writer that sanitizes each line before passing
// it to w.
func NewSanitizingWriter(w io.Writer) *SanitizingWriter {
	return &SanitizingWriter{w: w}
}

// Write buffers p and emits every COMPLETE line, sanitized.
//
// It reports len(p) consumed on success. The sanitized form is a different
// length from the input -- escaping grows it -- so returning the underlying
// writer's count would make callers see a short write and retry, duplicating
// output. The contract this satisfies is io.Writer's: all of p was consumed.
func (s *SanitizingWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, p...)

	for {
		i := indexByte(s.buf, '\n')
		if i < 0 {
			break
		}
		line := s.buf[:i+1]
		s.buf = s.buf[i+1:]
		if err := s.emit(line); err != nil {
			return 0, err
		}
	}

	// #7389: bound the hold. See maxBufferedLine.
	if len(s.buf) >= maxBufferedLine {
		line := s.buf
		s.buf = nil
		if err := s.emit(line); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Flush emits any buffered partial line. Callers must call it once the command
// has exited, or a final line with no trailing newline is silently dropped --
// which for a diagnostic tool would mean losing the last line of output, the
// one most likely to say why it stopped.
func (s *SanitizingWriter) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buf) == 0 {
		return nil
	}
	line := s.buf
	s.buf = nil
	return s.emit(line)
}

func (s *SanitizingWriter) emit(line []byte) error {
	_, err := io.WriteString(s.w, SanitizeBlockForDisplay(string(line)))
	return err
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}
