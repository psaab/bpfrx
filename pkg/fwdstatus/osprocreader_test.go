package fwdstatus

import (
	"os"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %q: %v", name, err)
	}
	return string(data)
}

func TestParseSelfStat_Good(t *testing.T) {
	got, err := parseSelfStat(readFixture(t, "self-stat-good"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.UtimeTicks != 1234 {
		t.Errorf("utime: got %d, want 1234", got.UtimeTicks)
	}
	if got.StimeTicks != 567 {
		t.Errorf("stime: got %d, want 567", got.StimeTicks)
	}
	if got.StartTimeTicks != 9876543 {
		t.Errorf("starttime: got %d, want 9876543", got.StartTimeTicks)
	}
}

func TestParseSelfStat_Malformed(t *testing.T) {
	_, err := parseSelfStat(readFixture(t, "self-stat-malformed-fields"))
	if err == nil {
		t.Fatal("expected parse error on malformed /proc/self/stat, got nil")
	}
}

func TestParseSelfStat_NoParen(t *testing.T) {
	_, err := parseSelfStat("no closing paren")
	if err == nil {
		t.Fatal("expected parse error when no closing paren, got nil")
	}
}

func TestParseSelfStatm_Good(t *testing.T) {
	got, err := parseSelfStatm(readFixture(t, "self-statm-good"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.ResidentPages != 6789 {
		t.Errorf("resident: got %d, want 6789", got.ResidentPages)
	}
}

func TestParseSelfStatm_Malformed(t *testing.T) {
	_, err := parseSelfStatm(readFixture(t, "self-statm-malformed"))
	if err == nil {
		t.Fatal("expected parse error on malformed /proc/self/statm, got nil")
	}
}

func TestParseProcStat_Good(t *testing.T) {
	got, err := parseProcStat(strings.NewReader(readFixture(t, "proc-stat-good")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.BootTime != 1716000000 {
		t.Errorf("btime: got %d, want 1716000000", got.BootTime)
	}
}

func TestParseProcStat_NoBtime(t *testing.T) {
	_, err := parseProcStat(strings.NewReader(readFixture(t, "proc-stat-no-btime")))
	if err == nil {
		t.Fatal("expected parse error when /proc/stat lacks btime, got nil")
	}
}

func TestParseMemInfo_Good(t *testing.T) {
	got, err := parseMemInfo(strings.NewReader(readFixture(t, "meminfo-good")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// 16384000 kB * 1024
	want := uint64(16384000) * 1024
	if got.MemTotalBytes != want {
		t.Errorf("MemTotal: got %d, want %d", got.MemTotalBytes, want)
	}
}

func TestParseMemInfo_NoMemTotal(t *testing.T) {
	_, err := parseMemInfo(strings.NewReader(readFixture(t, "meminfo-no-memtotal")))
	if err == nil {
		t.Fatal("expected parse error when /proc/meminfo lacks MemTotal, got nil")
	}
}

// Smoke test: the real OSProcReader can read live /proc/* on a Linux
// test machine.  Skipped if /proc isn't mounted (e.g. non-Linux CI).
func TestOSProcReader_Live(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc available")
	}
	rd := OSProcReader{}
	ss, err := rd.ReadSelfStat()
	if err != nil {
		t.Fatalf("ReadSelfStat live: %v", err)
	}
	if ss.StartTimeTicks == 0 {
		t.Error("live ReadSelfStat returned zero starttime")
	}
	sm, err := rd.ReadSelfStatm()
	if err != nil {
		t.Fatalf("ReadSelfStatm live: %v", err)
	}
	if sm.ResidentPages == 0 {
		t.Error("live ReadSelfStatm returned zero resident pages")
	}
	ps, err := rd.ReadStat()
	if err != nil {
		t.Fatalf("ReadStat live: %v", err)
	}
	if ps.BootTime == 0 {
		t.Error("live ReadStat returned zero btime")
	}
	mi, err := rd.ReadMemInfo()
	if err != nil {
		t.Fatalf("ReadMemInfo live: %v", err)
	}
	if mi.MemTotalBytes == 0 {
		t.Error("live ReadMemInfo returned zero MemTotal")
	}
}
