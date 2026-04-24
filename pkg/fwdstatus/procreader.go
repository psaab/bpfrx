package fwdstatus

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// ProcSelfStat holds the fields Build needs from /proc/self/stat.
type ProcSelfStat struct {
	UtimeTicks     uint64 // field 14
	StimeTicks     uint64 // field 15
	StartTimeTicks uint64 // field 22
}

// ProcSelfStatm holds the fields Build needs from /proc/self/statm.
type ProcSelfStatm struct {
	ResidentPages uint64 // field 2
}

// ProcStat holds the fields Build needs from /proc/stat.
type ProcStat struct {
	BootTime uint64 // btime line, Unix seconds
}

// ProcMemInfo holds the fields Build needs from /proc/meminfo.
type ProcMemInfo struct {
	MemTotalBytes uint64
}

// ProcReader reads the /proc files needed by Build.  Tests inject a
// fake to exercise success and failure paths deterministically.
type ProcReader interface {
	ReadSelfStat() (ProcSelfStat, error)
	ReadSelfStatm() (ProcSelfStatm, error)
	ReadStat() (ProcStat, error)
	ReadMemInfo() (ProcMemInfo, error)
	ReadCgroupMemoryMax() (uint64, error)
}

// OSProcReader is the production ProcReader: it reads real /proc/*
// files from the filesystem.  No state.
type OSProcReader struct{}

// ReadSelfStat parses /proc/self/stat.  The comm field (field 2) can
// contain spaces and parentheses, so we locate the closing paren
// before splitting on whitespace.
func (OSProcReader) ReadSelfStat() (ProcSelfStat, error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return ProcSelfStat{}, err
	}
	return parseSelfStat(string(data))
}

func parseSelfStat(s string) (ProcSelfStat, error) {
	rparen := strings.LastIndex(s, ")")
	if rparen < 0 || rparen+2 >= len(s) {
		return ProcSelfStat{}, fmt.Errorf("malformed /proc/self/stat: no closing paren")
	}
	// After ") " the first field is `state` (#3).  Subsequent fields
	// are space-separated.  Our targets: utime=#14, stime=#15,
	// starttime=#22.  After the rparen we've already consumed #1 + #2.
	rest := strings.Fields(s[rparen+2:])
	if len(rest) < 20 {
		return ProcSelfStat{}, fmt.Errorf("malformed /proc/self/stat: only %d fields after comm", len(rest))
	}
	// Field #N → index N-3 within `rest` (rest[0] is field 3).
	utime, err := strconv.ParseUint(rest[14-3], 10, 64)
	if err != nil {
		return ProcSelfStat{}, fmt.Errorf("parse utime: %w", err)
	}
	stime, err := strconv.ParseUint(rest[15-3], 10, 64)
	if err != nil {
		return ProcSelfStat{}, fmt.Errorf("parse stime: %w", err)
	}
	starttime, err := strconv.ParseUint(rest[22-3], 10, 64)
	if err != nil {
		return ProcSelfStat{}, fmt.Errorf("parse starttime: %w", err)
	}
	return ProcSelfStat{
		UtimeTicks:     utime,
		StimeTicks:     stime,
		StartTimeTicks: starttime,
	}, nil
}

// ReadSelfStatm parses /proc/self/statm (size resident shared ...).
func (OSProcReader) ReadSelfStatm() (ProcSelfStatm, error) {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return ProcSelfStatm{}, err
	}
	return parseSelfStatm(string(data))
}

func parseSelfStatm(s string) (ProcSelfStatm, error) {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return ProcSelfStatm{}, fmt.Errorf("malformed /proc/self/statm: only %d fields", len(fields))
	}
	resident, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return ProcSelfStatm{}, fmt.Errorf("parse resident: %w", err)
	}
	return ProcSelfStatm{ResidentPages: resident}, nil
}

// ReadStat parses /proc/stat looking for the `btime <seconds>` line.
func (OSProcReader) ReadStat() (ProcStat, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return ProcStat{}, err
	}
	defer f.Close()
	return parseProcStat(f)
}

func parseProcStat(r io.Reader) (ProcStat, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		btime, err := strconv.ParseUint(strings.TrimSpace(line[len("btime "):]), 10, 64)
		if err != nil {
			return ProcStat{}, fmt.Errorf("parse btime: %w", err)
		}
		return ProcStat{BootTime: btime}, nil
	}
	if err := sc.Err(); err != nil {
		return ProcStat{}, err
	}
	return ProcStat{}, fmt.Errorf("malformed /proc/stat: no btime line")
}

// ReadMemInfo parses /proc/meminfo looking for MemTotal.
func (OSProcReader) ReadMemInfo() (ProcMemInfo, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return ProcMemInfo{}, err
	}
	defer f.Close()
	return parseMemInfo(f)
}

func parseMemInfo(r io.Reader) (ProcMemInfo, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return ProcMemInfo{}, fmt.Errorf("malformed /proc/meminfo MemTotal line")
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return ProcMemInfo{}, fmt.Errorf("parse MemTotal: %w", err)
		}
		return ProcMemInfo{MemTotalBytes: kb * 1024}, nil
	}
	if err := sc.Err(); err != nil {
		return ProcMemInfo{}, err
	}
	return ProcMemInfo{}, fmt.Errorf("malformed /proc/meminfo: no MemTotal line")
}

// ReadCgroupMemoryMax returns the cgroup-v2 memory.max if the caller
// is in a memory-capped cgroup, else 0 + nil error.  A "max" literal
// (no cap) also returns 0 + nil.
func (OSProcReader) ReadCgroupMemoryMax() (uint64, error) {
	// cgroup v2 layout: /sys/fs/cgroup/<path>/memory.max.  We resolve
	// <path> from /proc/self/cgroup's `0::<path>` entry.
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		// No cgroup file → not in a cgroup or proc unreadable.  Not
		// an error the caller should treat as fatal; Build falls back
		// to MemTotal.
		return 0, nil
	}
	path := ""
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			path = strings.TrimSpace(line[3:])
			break
		}
	}
	if path == "" {
		return 0, nil
	}
	maxPath := "/sys/fs/cgroup" + path + "/memory.max"
	raw, err := os.ReadFile(maxPath)
	if err != nil {
		return 0, nil
	}
	s := strings.TrimSpace(string(raw))
	if s == "max" {
		return 0, nil
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse memory.max: %w", err)
	}
	return n, nil
}
