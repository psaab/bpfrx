package journal

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// #7176 (C179-061). The journal append opened with
// os.O_APPEND|os.O_CREATE|os.O_RDWR and no O_NOFOLLOW, and its only post-open
// Stat read fi.Size() for the torn-tail check — never Mode().IsRegular(). So the
// append followed a symlink, or wrote into a FIFO/device, planted at the path.
//
// The package already refused to CHMOD through a symlinked segment
// (chmodOwnerOnly); it just did not refuse to APPEND through one. These cells
// hold both halves, because neither subsumes the other: O_NOFOLLOW does not
// reject a FIFO (it is not a symlink), and a regular-file check alone would have
// a TOCTOU window an attacker can win.

// The control. Without it, an open that refused EVERYTHING would satisfy both
// refusals below and the journal would simply be broken.
func TestJournalAppendsToARegularFile_7176(t *testing.T) {
	j := New(filepath.Join(t.TempDir(), ".config.journal"))
	if err := j.Log(&Entry{Action: "commit", Detail: "ordinary"}); err != nil {
		t.Fatalf("appending to a regular file must work: %v", err)
	}
}

func TestJournalRefusesToFollowASymlink_7176(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(target, []byte("pre-existing content\n"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	link := filepath.Join(dir, ".config.journal")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}

	j := New(link)
	err := j.Log(&Entry{Action: "commit", Detail: "should-not-land"})
	if err == nil {
		t.Fatal("the journal appended THROUGH a symlink — an attacker who can create " +
			"the journal path redirects the audit record into a file of their choosing")
	}

	// The victim must be untouched. Asserting only that Log errored would be
	// satisfied by an implementation that wrote and then failed.
	got, rerr := os.ReadFile(target)
	if rerr != nil {
		t.Fatalf("read target: %v", rerr)
	}
	if string(got) != "pre-existing content\n" {
		t.Errorf("the symlink target was modified: %q", got)
	}
}

func TestJournalRefusesAFIFO_7176(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".config.journal")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}

	// A FIFO is the case O_NOFOLLOW does NOT cover: it is not a symlink, so the
	// open succeeds, and with O_RDWR the writes land in the pipe buffer and the
	// daemon BLOCKS once it fills. The regular-file check is what catches it,
	// which is why both are present.
	j := New(path)
	err := j.Log(&Entry{Action: "commit", Detail: "should-not-block"})
	if err == nil {
		t.Fatal("the journal opened a FIFO planted at its path — writes land in the " +
			"pipe buffer and the daemon blocks once it fills")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("err = %v; want the regular-file refusal, so a case that fails for "+
			"some other reason cannot pass for the wrong one", err)
	}
}
