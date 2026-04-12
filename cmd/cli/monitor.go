package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/psaab/bpfrx/pkg/cmdtree"
	pb "github.com/psaab/bpfrx/pkg/grpcapi/bpfrxv1"
	"github.com/psaab/bpfrx/pkg/monitoriface"
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

// TODO: setMonitorRawMode, restoreMonitorTermMode, and monitorInputIsTTY
// duplicate helpers in pkg/cli/monitor_interface.go. Extract to a shared
// package (e.g. pkg/termutil) when the remote CLI gains more terminal ops.
func setMonitorRawMode(fd int) (*unix.Termios, error) {
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

func restoreMonitorTermMode(fd int, old *unix.Termios) {
	_ = unix.IoctlSetTermios(fd, unix.TCSETS, old)
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

	keyCh := make(chan byte, 8)
	doneCh := make(chan struct{})
	defer close(doneCh)
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				return
			}
			select {
			case keyCh <- buf[0]:
			case <-doneCh:
				return
			}
		}
	}()

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
		reqCopy := *req
		reqCopy.SummaryMode = mode
		gen := streamGen
		streamCtx, cancelStream := context.WithCancel(ctx)
		stream, err := c.client.MonitorInterface(streamCtx, &reqCopy)
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
