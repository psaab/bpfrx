package monitoriface

import (
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	EnterAltScreen = "\x1b[?1049h"
	ExitAltScreen  = "\x1b[?1049l"
	ClearAndHome   = "\x1b[2J\x1b[H"
	HideCursor     = "\x1b[?25l"
	ShowCursor     = "\x1b[?25h"
)

type TrafficUnit int

const (
	TrafficUnitBytes TrafficUnit = iota
	TrafficUnitBits
	TrafficUnitPackets
	TrafficUnitErrors
)

type TrafficType int

const (
	TrafficTypeRate TrafficType = iota
	TrafficTypeMax
	TrafficTypeSum
	TrafficTypeAverage
)

type TrafficViewState struct {
	Unit    TrafficUnit
	Type    TrafficType
	Refresh time.Duration
}

type TrafficKeyAction int

const (
	TrafficKeyNone TrafficKeyAction = iota
	TrafficKeyChanged
	TrafficKeyShowHelp
	TrafficKeyQuit
)

type trafficRateSample struct {
	Timestamp time.Time
	Interval  time.Duration

	RxBytes   uint64
	TxBytes   uint64
	RxPackets uint64
	TxPackets uint64
	RxErrors  uint64
	TxErrors  uint64
}

type TrafficTracker struct {
	StartedAt time.Time
	Baseline  map[string]Snapshot
	Prev      map[string]Snapshot
	Current   map[string]trafficRateSample
	Max       map[string]trafficRateSample
	History   map[string][]trafficRateSample
}

func SetRawMode(fd int) (*unix.Termios, error) {
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	raw := *old
	raw.Lflag &^= unix.ECHO | unix.ICANON | unix.ISIG
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return nil, err
	}
	return old, nil
}

func RestoreTermMode(fd int, old *unix.Termios) {
	_ = unix.IoctlSetTermios(fd, unix.TCSETS, old)
}

func DefaultTrafficViewState() TrafficViewState {
	return TrafficViewState{
		Unit:    TrafficUnitBytes,
		Type:    TrafficTypeRate,
		Refresh: time.Second,
	}
}

func ParseTrafficViewArgs(args []string) (TrafficViewState, error) {
	state := DefaultTrafficViewState()
	for _, arg := range args {
		if unit, ok := ParseTrafficUnit(arg); ok {
			state.Unit = unit
			continue
		}
		if typ, ok := ParseTrafficType(arg); ok {
			state.Type = typ
			continue
		}
		if mode, ok := ParseSummaryMode(arg); ok {
			switch mode {
			case SummaryModePackets:
				state.Unit = TrafficUnitPackets
				state.Type = TrafficTypeRate
			case SummaryModeBytes:
				state.Unit = TrafficUnitBytes
				state.Type = TrafficTypeRate
			case SummaryModeDelta:
				state.Unit = TrafficUnitPackets
				state.Type = TrafficTypeSum
			case SummaryModeRate:
				state.Unit = TrafficUnitBits
				state.Type = TrafficTypeRate
			default:
				state.Unit = TrafficUnitBytes
				state.Type = TrafficTypeRate
			}
			continue
		}
		return state, fmt.Errorf("unknown monitor interface traffic view: %s", arg)
	}
	return state, nil
}

func ParseTrafficUnit(value string) (TrafficUnit, bool) {
	switch strings.ToLower(value) {
	case "", "bytes", "byte":
		return TrafficUnitBytes, true
	case "bits", "bit":
		return TrafficUnitBits, true
	case "packets", "packet":
		return TrafficUnitPackets, true
	case "errors", "error":
		return TrafficUnitErrors, true
	default:
		return TrafficUnitBytes, false
	}
}

func ParseTrafficType(value string) (TrafficType, bool) {
	switch strings.ToLower(value) {
	case "", "rate", "current":
		return TrafficTypeRate, true
	case "max":
		return TrafficTypeMax, true
	case "sum", "total":
		return TrafficTypeSum, true
	case "avg", "average":
		return TrafficTypeAverage, true
	default:
		return TrafficTypeRate, false
	}
}

func (u TrafficUnit) Next() TrafficUnit {
	switch u {
	case TrafficUnitBits:
		return TrafficUnitPackets
	case TrafficUnitPackets:
		return TrafficUnitErrors
	case TrafficUnitErrors:
		return TrafficUnitBytes
	default:
		return TrafficUnitBits
	}
}

func (t TrafficType) Next() TrafficType {
	switch t {
	case TrafficTypeMax:
		return TrafficTypeSum
	case TrafficTypeSum:
		return TrafficTypeAverage
	case TrafficTypeAverage:
		return TrafficTypeRate
	default:
		return TrafficTypeMax
	}
}

func (s *TrafficViewState) HandleKey(key byte) TrafficKeyAction {
	switch key {
	case 'q', 'Q', 0x1b, 0x03:
		return TrafficKeyQuit
	case 'h', 'H':
		return TrafficKeyShowHelp
	case '+':
		s.Refresh += 100 * time.Millisecond
		return TrafficKeyChanged
	case '-':
		if s.Refresh > 100*time.Millisecond {
			s.Refresh -= 100 * time.Millisecond
		}
		return TrafficKeyChanged
	case 'u', 'U':
		s.Unit = s.Unit.Next()
		return TrafficKeyChanged
	case 't', 'T':
		s.Type = s.Type.Next()
		return TrafficKeyChanged
	default:
		return TrafficKeyNone
	}
}

func TrafficUnitLabel(unit TrafficUnit) string {
	switch unit {
	case TrafficUnitBits:
		return "bits"
	case TrafficUnitPackets:
		return "packets"
	case TrafficUnitErrors:
		return "errors"
	default:
		return "bytes"
	}
}

func TrafficTypeLabel(typ TrafficType) string {
	switch typ {
	case TrafficTypeMax:
		return "max"
	case TrafficTypeSum:
		return "sum"
	case TrafficTypeAverage:
		return "avg"
	default:
		return "rate"
	}
}

func NewTrafficTracker(start time.Time) *TrafficTracker {
	return &TrafficTracker{
		StartedAt: start,
		Baseline:  map[string]Snapshot{},
		Prev:      map[string]Snapshot{},
		Current:   map[string]trafficRateSample{},
		Max:       map[string]trafficRateSample{},
		History:   map[string][]trafficRateSample{},
	}
}

func (t *TrafficTracker) Update(snaps map[string]*Snapshot) {
	for name, snap := range snaps {
		if snap == nil {
			continue
		}
		if _, ok := t.Baseline[name]; !ok {
			t.Baseline[name] = *snap
		}
		if prev, ok := t.Prev[name]; ok {
			dt := snap.Timestamp.Sub(prev.Timestamp)
			if dt > 0 {
				rate := trafficRateSample{
					Timestamp: snap.Timestamp,
					Interval:  dt,
					RxBytes:   perSecond(deltaU64(snap.RxBytes, prev.RxBytes), dt),
					TxBytes:   perSecond(deltaU64(snap.TxBytes, prev.TxBytes), dt),
					RxPackets: perSecond(deltaU64(snap.RxPkts, prev.RxPkts), dt),
					TxPackets: perSecond(deltaU64(snap.TxPkts, prev.TxPkts), dt),
					RxErrors:  perSecond(deltaU64(snap.RxErrors, prev.RxErrors), dt),
					TxErrors:  perSecond(deltaU64(snap.TxErrors, prev.TxErrors), dt),
				}
				t.Current[name] = rate
				t.Max[name] = maxTrafficRateSample(t.Max[name], rate)
				t.History[name] = append(t.History[name], rate)
				t.pruneHistory(name, snap.Timestamp.Add(-30*time.Second))
			}
		}
		t.Prev[name] = *snap
	}
}

func (t *TrafficTracker) pruneHistory(name string, cutoff time.Time) {
	history := t.History[name]
	keep := 0
	for keep < len(history) && history[keep].Timestamp.Before(cutoff) {
		keep++
	}
	if keep > 0 {
		t.History[name] = append([]trafficRateSample(nil), history[keep:]...)
	}
}

func (t *TrafficTracker) Render(w io.Writer, hostname string, names []string, snaps map[string]*Snapshot, state TrafficViewState) {
	fmt.Fprintf(w, "  bpfrx %s monitor interface traffic (probing every %.3fs), press 'h' for help\n", hostname, state.Refresh.Seconds())
	fmt.Fprintf(w, "  input: bpfrx interface counters type: %s %s\n", TrafficTypeLabel(state.Type), TrafficUnitLabel(state.Unit))
	fmt.Fprintf(w, "  %s         iface                   Rx                   Tx                Total\n", trafficIndicator(state.Unit))
	fmt.Fprintf(w, "  =\n")

	var totalRx, totalTx uint64
	for _, name := range names {
		snap := snaps[name]
		if snap == nil {
			continue
		}
		rx, tx := t.valuesFor(name, snap, state)
		totalRx += rx
		totalTx += tx
		fmt.Fprintf(w, "  %16s %20s %20s %20s\n",
			name+":",
			formatTrafficValue(rx, state.Unit, state.Type),
			formatTrafficValue(tx, state.Unit, state.Type),
			formatTrafficValue(rx+tx, state.Unit, state.Type))
	}
	fmt.Fprintf(w, "  -\n")
	fmt.Fprintf(w, "  %16s %20s %20s %20s\n",
		"total:",
		formatTrafficValue(totalRx, state.Unit, state.Type),
		formatTrafficValue(totalTx, state.Unit, state.Type),
		formatTrafficValue(totalRx+totalTx, state.Unit, state.Type))
}

func (t *TrafficTracker) valuesFor(name string, snap *Snapshot, state TrafficViewState) (uint64, uint64) {
	switch state.Type {
	case TrafficTypeMax:
		return sampleValue(t.Max[name], state.Unit, true), sampleValue(t.Max[name], state.Unit, false)
	case TrafficTypeSum:
		base, ok := t.Baseline[name]
		if !ok {
			return 0, 0
		}
		return snapshotValueDelta(snap, &base, state.Unit, true), snapshotValueDelta(snap, &base, state.Unit, false)
	case TrafficTypeAverage:
		return averageSampleValues(t.History[name], state.Unit)
	default:
		return sampleValue(t.Current[name], state.Unit, true), sampleValue(t.Current[name], state.Unit, false)
	}
}

func RenderTrafficHelp(w io.Writer, state TrafficViewState) {
	lines := []string{
		fmt.Sprintf("bpfrx monitor interface traffic - Keybindings (refresh %.3fs)", state.Refresh.Seconds()),
		"",
		"'h'  show this help",
		"'q'  exit",
		"'+'  increase refresh interval by 100ms",
		"'-'  decrease refresh interval by 100ms",
		"'u'  cycle units: bytes, bits, packets, errors",
		"'t'  cycle type: current rate, max, sum since start, avg last 30s",
		"",
		fmt.Sprintf("Current unit: %s", TrafficUnitLabel(state.Unit)),
		fmt.Sprintf("Current type: %s", TrafficTypeLabel(state.Type)),
		"",
		"press any key to continue...",
	}

	width := 0
	for _, line := range lines {
		if len(line) > width {
			width = len(line)
		}
	}
	border := "+" + strings.Repeat("-", width+2) + "+"
	fmt.Fprintln(w, border)
	for _, line := range lines {
		fmt.Fprintf(w, "| %-*s |\n", width, line)
	}
	fmt.Fprintln(w, border)
}

func perSecond(delta uint64, dt time.Duration) uint64 {
	if dt <= 0 {
		return 0
	}
	return uint64(float64(delta) / dt.Seconds())
}

func maxTrafficRateSample(curr, next trafficRateSample) trafficRateSample {
	curr.RxBytes = maxU64(curr.RxBytes, next.RxBytes)
	curr.TxBytes = maxU64(curr.TxBytes, next.TxBytes)
	curr.RxPackets = maxU64(curr.RxPackets, next.RxPackets)
	curr.TxPackets = maxU64(curr.TxPackets, next.TxPackets)
	curr.RxErrors = maxU64(curr.RxErrors, next.RxErrors)
	curr.TxErrors = maxU64(curr.TxErrors, next.TxErrors)
	return curr
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func sampleValue(sample trafficRateSample, unit TrafficUnit, rx bool) uint64 {
	switch unit {
	case TrafficUnitBits:
		if rx {
			return sample.RxBytes * 8
		}
		return sample.TxBytes * 8
	case TrafficUnitPackets:
		if rx {
			return sample.RxPackets
		}
		return sample.TxPackets
	case TrafficUnitErrors:
		if rx {
			return sample.RxErrors
		}
		return sample.TxErrors
	default:
		if rx {
			return sample.RxBytes
		}
		return sample.TxBytes
	}
}

func snapshotValueDelta(curr, base *Snapshot, unit TrafficUnit, rx bool) uint64 {
	switch unit {
	case TrafficUnitBits:
		if rx {
			return deltaU64(curr.RxBytes, base.RxBytes) * 8
		}
		return deltaU64(curr.TxBytes, base.TxBytes) * 8
	case TrafficUnitPackets:
		if rx {
			return deltaU64(curr.RxPkts, base.RxPkts)
		}
		return deltaU64(curr.TxPkts, base.TxPkts)
	case TrafficUnitErrors:
		if rx {
			return deltaU64(curr.RxErrors, base.RxErrors)
		}
		return deltaU64(curr.TxErrors, base.TxErrors)
	default:
		if rx {
			return deltaU64(curr.RxBytes, base.RxBytes)
		}
		return deltaU64(curr.TxBytes, base.TxBytes)
	}
}

func averageSampleValues(history []trafficRateSample, unit TrafficUnit) (uint64, uint64) {
	var totalSeconds float64
	var rxWeighted, txWeighted float64
	for _, sample := range history {
		seconds := sample.Interval.Seconds()
		if seconds <= 0 {
			continue
		}
		totalSeconds += seconds
		rxWeighted += float64(sampleValue(sample, unit, true)) * seconds
		txWeighted += float64(sampleValue(sample, unit, false)) * seconds
	}
	if totalSeconds <= 0 {
		return 0, 0
	}
	return uint64(rxWeighted / totalSeconds), uint64(txWeighted / totalSeconds)
}

func formatTrafficValue(v uint64, unit TrafficUnit, typ TrafficType) string {
	perSecond := typ != TrafficTypeSum
	switch unit {
	case TrafficUnitBits:
		return formatTrafficScaled(v, []string{"b", "kb", "Mb", "Gb"}, perSecond)
	case TrafficUnitPackets:
		return formatTrafficScaled(v, []string{"P", "kP", "MP", "GP"}, perSecond)
	case TrafficUnitErrors:
		return formatTrafficScaled(v, []string{"E", "kE", "ME", "GE"}, perSecond)
	default:
		return formatTrafficScaled(v, []string{"B", "KB", "MB", "GB"}, perSecond)
	}
}

func formatTrafficScaled(v uint64, units []string, perSecond bool) string {
	value := float64(v)
	unit := units[0]
	switch {
	case v >= 1_000_000_000:
		value /= 1_000_000_000
		unit = units[3]
	case v >= 1_000_000:
		value /= 1_000_000
		unit = units[2]
	case v >= 1_000:
		value /= 1_000
		unit = units[1]
	}
	if perSecond {
		return fmt.Sprintf("%8.2f %s/s", value, unit)
	}
	return fmt.Sprintf("%8.2f %s", value, unit)
}

func trafficIndicator(unit TrafficUnit) string {
	if unit == TrafficUnitErrors {
		return "\\"
	}
	return "/"
}
