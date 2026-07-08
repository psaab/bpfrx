package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/psaab/xpf/pkg/cmdtree"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/monitoriface"
)

const (
	monitorEnterAltScreen = "\x1b[?1049h"
	monitorExitAltScreen  = "\x1b[?1049l"
	monitorClearAndHome   = "\x1b[2J\x1b[H"
	monitorHideCursor     = "\x1b[?25l"
	monitorShowCursor     = "\x1b[?25h"
)

type remoteMonitorFrame struct {
	gen   uint64
	frame string
	err   error
}

// TODO: setMonitorRawMode, restoreMonitorTermMode, monitorInputIsTTY,
// keyReader, and startKeyReader duplicate helpers in
// pkg/cli/monitor_interface.go. Extract to a shared package (e.g. pkg/termutil)
// when the remote CLI gains more terminal ops.
//
// VMIN=0/VTIME=1 selects a poll-with-timeout read (#3985, #4694): os.Stdin.Read
// returns immediately when a key is available and otherwise returns (0, nil)
// after ~100ms with no data. This lets the key-reader goroutine observe its
// stop signal between reads and return, instead of staying parked forever in a
// blocking Read after the monitor exits (VMIN=1/VTIME=0 would block
// indefinitely and steal the operator's next keystroke).
func setMonitorRawMode(fd int) (*unix.Termios, error) {
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	raw := *old
	raw.Lflag &^= unix.ECHO | unix.ICANON | unix.ISIG
	raw.Cc[unix.VMIN] = 0
	raw.Cc[unix.VTIME] = 1
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return nil, err
	}
	return old, nil
}

func restoreMonitorTermMode(fd int, old *unix.Termios) {
	_ = unix.IoctlSetTermios(fd, unix.TCSETS, old)
}

// keyReader reads single bytes from r and forwards them on keyCh until done is
// closed, then returns. r must be a poll-mode reader (a raw tty configured with
// VMIN=0/VTIME>0 via setMonitorRawMode) so Read returns periodically with n==0
// when idle, letting the loop observe done and return. Without this the
// goroutine would remain blocked in Read after the monitor exits and consume
// the operator's next keystroke (#3985 / #4694). A byte read after done is
// closed is discarded rather than forwarded, so no stale monitor input reaches
// a caller.
func keyReader(r io.Reader, keyCh chan<- byte, done <-chan struct{}) {
	buf := make([]byte, 1)
	for {
		select {
		case <-done:
			return
		default:
		}
		n, err := r.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			// VTIME poll timeout with no data — loop and re-check done.
			continue
		}
		select {
		case keyCh <- buf[0]:
		case <-done:
			return
		}
	}
}

// startKeyReader launches a keyReader goroutine reading from r and returns the
// key channel plus a stop function. The stop function closes the done channel
// and blocks until the goroutine has returned, guaranteeing no reader is left
// competing for stdin once the monitor exits (#3985 / #4694). Callers defer
// stop so it runs before the terminal is restored and control returns to the
// CLI.
func startKeyReader(r io.Reader) (<-chan byte, func()) {
	keyCh := make(chan byte, 8)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		keyReader(r, keyCh, done)
	}()
	var once sync.Once
	return keyCh, func() {
		once.Do(func() {
			close(done)
			wg.Wait()
		})
	}
}

func monitorInputIsTTY(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}

func (c *ctl) handleMonitor(args []string) error {
	if len(args) == 0 {
		cmdtree.PrintTreeHelp("monitor:", cmdtree.OperationalTree, "monitor")
		return nil
	}
	switch args[0] {
	case "traffic":
		return fmt.Errorf("monitor traffic is only available on the local CLI")
	case "interface":
		return c.handleMonitorInterface(args[1:])
	case "security":
		return c.handleMonitorSecurity(args[1:])
	default:
		return fmt.Errorf("unknown monitor target: %s", args[0])
	}
}

func (c *ctl) handleMonitorInterface(args []string) error {
	req := &pb.MonitorInterfaceRequest{}
	if len(args) > 0 {
		if args[0] == "traffic" {
			mode, err := remoteMonitorSummaryMode(args[1:])
			if err != nil {
				return err
			}
			req.SummaryMode = mode
		} else {
			req.InterfaceName = args[0]
		}
	}

	if req.InterfaceName == "" && monitorInputIsTTY(int(os.Stdin.Fd())) {
		return c.handleInteractiveMonitorInterfaceSummary(req)
	}

	ctx, cancel := context.WithCancel(c.ctx())
	defer cancel()
	stream, err := c.client.MonitorInterface(ctx, req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	fmt.Print(monitorEnterAltScreen + monitorHideCursor)
	defer fmt.Print(monitorShowCursor + monitorExitAltScreen)

	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(monitorClearAndHome)
		fmt.Print(resp.Frame)
	}
	return nil
}

func (c *ctl) handleInteractiveMonitorInterfaceSummary(req *pb.MonitorInterfaceRequest) error {
	fd := int(os.Stdin.Fd())
	old, err := setMonitorRawMode(fd)
	if err != nil {
		return fmt.Errorf("failed to set raw mode: %w", err)
	}
	defer restoreMonitorTermMode(fd, old)

	fmt.Print(monitorEnterAltScreen + monitorHideCursor)
	defer fmt.Print(monitorShowCursor + monitorExitAltScreen)

	// Stop the stdin reader before restoring the terminal so no goroutine is
	// left parked in os.Stdin.Read stealing the next command's key (#3985 /
	// #4694). The old inline goroutine used a blocking VMIN=1/VTIME=0 read and
	// returned on the first n==0, so it either blocked forever after the
	// monitor exited or, under a poll reader, died on the first idle poll.
	keyCh, stopKeys := startKeyReader(os.Stdin)
	defer stopKeys()

	frameCh := make(chan remoteMonitorFrame, 16)
	ctx, cancel := context.WithCancel(c.ctx())
	defer cancel()

	var (
		streamCancel context.CancelFunc
		streamGen    uint64
	)
	startStream := func(mode pb.MonitorInterfaceSummaryMode) error {
		if streamCancel != nil {
			streamCancel()
		}
		streamGen++
		// Deep-copy via proto.Clone rather than a shallow struct copy: the
		// generated message embeds protoimpl.MessageState (a sync.Mutex), so
		// `reqCopy := *req` is a lock copy (govet copylocks). proto.Clone
		// yields a fresh message whose per-stream SummaryMode we can set
		// without aliasing the caller's req (#4697).
		reqCopy := proto.Clone(req).(*pb.MonitorInterfaceRequest)
		reqCopy.SummaryMode = mode
		gen := streamGen
		streamCtx, cancelStream := context.WithCancel(ctx)
		stream, err := c.client.MonitorInterface(streamCtx, reqCopy)
		if err != nil {
			cancelStream()
			return err
		}
		streamCancel = cancelStream
		go func() {
			for {
				resp, err := stream.Recv()
				if err != nil {
					select {
					case frameCh <- remoteMonitorFrame{gen: gen, err: err}:
					case <-ctx.Done():
					}
					return
				}
				select {
				case frameCh <- remoteMonitorFrame{gen: gen, frame: resp.Frame}:
				case <-ctx.Done():
					return
				}
			}
		}()
		return nil
	}

	mode := req.GetSummaryMode()
	if err := startStream(mode); err != nil {
		return fmt.Errorf("%v", err)
	}
	defer func() {
		if streamCancel != nil {
			streamCancel()
		}
	}()

	for {
		select {
		case frame := <-frameCh:
			if frame.gen != streamGen {
				continue
			}
			if frame.err != nil {
				if frame.err == io.EOF {
					return nil
				}
				return fmt.Errorf("%v", frame.err)
			}
			fmt.Print(monitorClearAndHome)
			fmt.Print(frame.frame)
		case key := <-keyCh:
			if isMonitorQuitKey(key) {
				return nil
			}
			nextMode, ok := remoteMonitorSummaryModeFromKey(key)
			if !ok || nextMode == mode {
				continue
			}
			mode = nextMode
			if err := startStream(mode); err != nil {
				return fmt.Errorf("%v", err)
			}
		}
	}
}

func remoteMonitorSummaryMode(args []string) (pb.MonitorInterfaceSummaryMode, error) {
	if len(args) == 0 {
		return pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_COMBINED, nil
	}
	mode, ok := monitoriface.ParseSummaryMode(args[0])
	if !ok {
		return pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_COMBINED,
			fmt.Errorf("unknown monitor interface traffic mode: %s", args[0])
	}
	switch mode {
	case monitoriface.SummaryModePackets:
		return pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_PACKETS, nil
	case monitoriface.SummaryModeBytes:
		return pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_BYTES, nil
	case monitoriface.SummaryModeDelta:
		return pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_DELTA, nil
	case monitoriface.SummaryModeRate:
		return pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_RATE, nil
	default:
		return pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_COMBINED, nil
	}
}

func remoteMonitorSummaryModeFromKey(key byte) (pb.MonitorInterfaceSummaryMode, bool) {
	switch key {
	case 'c', 'C':
		return pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_COMBINED, true
	case 'p', 'P':
		return pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_PACKETS, true
	case 'b', 'B':
		return pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_BYTES, true
	case 'd', 'D':
		return pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_DELTA, true
	case 'r', 'R':
		return pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_RATE, true
	default:
		return pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_COMBINED, false
	}
}

func isMonitorQuitKey(key byte) bool {
	switch key {
	case 'q', 'Q', 0x1b, 0x03:
		return true
	default:
		return false
	}
}

func (c *ctl) handleMonitorSecurity(args []string) error {
	if len(args) == 0 {
		cmdtree.PrintTreeHelp("monitor security:", cmdtree.OperationalTree, "monitor", "security")
		return nil
	}
	switch args[0] {
	case "flow":
		return fmt.Errorf("monitor security flow is only available on the local CLI")
	case "packet-drop":
		return c.handleMonitorSecurityPacketDrop(args[1:])
	default:
		return fmt.Errorf("unknown monitor security target: %s", args[0])
	}
}

func (c *ctl) handleMonitorSecurityPacketDrop(args []string) error {
	req := &pb.MonitorPacketDropRequest{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "source-prefix":
			if i+1 < len(args) {
				i++
				req.SourcePrefix = args[i]
			}
		case "destination-prefix":
			if i+1 < len(args) {
				i++
				req.DestinationPrefix = args[i]
			}
		case "source-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.SourcePort = uint32(v)
				}
			}
		case "destination-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.DestinationPort = uint32(v)
				}
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				req.Protocol = args[i]
			}
		case "from-zone":
			if i+1 < len(args) {
				i++
				req.FromZone = args[i]
			}
		case "interface":
			if i+1 < len(args) {
				i++
				req.Interface = args[i]
			}
		case "count":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.Count = int32(v)
				}
			}
		case "node":
			if i+1 < len(args) {
				i++
				req.Node = args[i]
			}
		}
	}

	ctx, cancel := context.WithCancel(c.ctx())
	defer cancel()
	stream, err := c.client.MonitorPacketDrop(ctx, req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Line)
	}
	return nil
}
