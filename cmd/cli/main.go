// cli is the remote CLI client for xpfd.
//
// It connects to the xpfd gRPC API and provides the same Junos-style
// interactive CLI as the embedded console.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/psaab/xpf/pkg/cmdtree"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "xpfd gRPC address")
	cmdFlag := flag.String("c", "", "run a single command non-interactively and exit")
	flag.Parse()

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli: connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := pb.NewBpfrxServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	resp, err := client.GetStatus(ctx, &pb.GetStatusRequest{})
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli: cannot reach xpfd at %s: %v\n", *addr, err)
		os.Exit(1)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}
	username := os.Getenv("USER")
	if username == "" {
		username = "remote"
	}

	c := &ctl{
		client:        client,
		hostname:      hostname,
		username:      username,
		configMode:    false,
		clusterRole:   resp.ClusterRole,
		clusterNodeID: resp.ClusterNodeId,
	}

	if *cmdFlag != "" {
		c.startCmd()
		err := c.dispatch(*cmdFlag)
		c.endCmd()
		if err != nil && err != errExit {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	rc := &remoteCompleter{ctl: c}
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          c.operationalPrompt(),
		HistoryFile:     filepath.Join(os.Getenv("HOME"), ".xpf_cli_history"),
		HistoryLimit:    10000,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete:    rc,
		Stdin:           os.Stdin,
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
		Listener: readline.FuncListener(func(line []rune, pos int, key rune) ([]rune, int, bool) {
			if key != '?' || pos < 1 {
				return line, pos, false
			}
			cleanLine := make([]rune, 0, len(line)-1)
			cleanLine = append(cleanLine, line[:pos-1]...)
			cleanLine = append(cleanLine, line[pos:]...)
			text := string(cleanLine[:pos-1])
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			resp, err := c.client.Complete(ctx, &pb.CompleteRequest{
				Line:       text,
				Pos:        int32(len(text)),
				ConfigMode: c.configMode,
			})
			if err != nil || len(resp.Candidates) == 0 {
				fmt.Fprintln(c.rl.Stdout(), "  (no help available)")
				rc.helpWritten = true
				return cleanLine, pos - 1, true
			}
			candidates := make([]cmdtree.Candidate, len(resp.Candidates))
			for i, name := range resp.Candidates {
				desc := ""
				if i < len(resp.Descriptions) && resp.Descriptions[i] != "" {
					desc = resp.Descriptions[i]
				} else if strings.Contains(text, "|") {
					desc = pipeFilterDescs[name]
				} else {
					desc = remoteLookupDesc(strings.Fields(text), name, c.configMode)
				}
				candidates[i] = cmdtree.Candidate{Name: name, Desc: desc}
			}
			sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
			cmdtree.WriteHelp(c.rl.Stdout(), candidates)
			rc.helpWritten = true
			return cleanLine, pos - 1, true
		}),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli: readline: %v\n", err)
		os.Exit(1)
	}
	defer rl.Close()
	c.rl = rl

	fmt.Printf("cli — connected to xpfd (uptime: %s)\n", resp.Uptime)
	fmt.Println("Type '?' for help")
	fmt.Println()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	var lastInterrupt time.Time
	go func() {
		for range sigCh {
			if c.cancelCmd() {
				fmt.Fprintln(os.Stderr, "\n^C (command cancelled)")
				continue
			}
			now := time.Now()
			if now.Sub(lastInterrupt) < 2*time.Second {
				if c.configMode {
					_, _ = client.ExitConfigure(context.Background(), &pb.ExitConfigureRequest{})
				}
				os.Exit(0)
			}
			lastInterrupt = now
			fmt.Fprintln(os.Stderr, "\n^C (press again within 2s to exit)")
			rl.Refresh()
		}
	}()
	defer signal.Stop(sigCh)

	for {
		if c.configMode {
			st, err := client.GetConfigModeStatus(context.Background(), &pb.GetConfigModeStatusRequest{})
			if err == nil && st.ConfirmPending {
				fmt.Println("[commit confirmed pending - issue 'commit' to confirm]")
			}
		}

		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				continue
			}
			if err == io.EOF {
				if c.configMode {
					c.configMode = false
					c.editPath = nil
					_, _ = client.ExitConfigure(context.Background(), &pb.ExitConfigureRequest{})
					rl.SetPrompt(c.operationalPrompt())
					fmt.Println("\nExiting configuration mode")
					continue
				}
				break
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		c.startCmd()
		err = c.dispatch(line)
		c.endCmd()
		if err != nil {
			if err == errExit {
				break
			}
			if err == context.Canceled {
				continue
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
	}

	if c.configMode {
		_, _ = client.ExitConfigure(context.Background(), &pb.ExitConfigureRequest{})
	}
}

func (c *ctl) handleCommit(args []string) error {
	if len(args) > 0 && args[0] == "check" {
		_, err := c.client.CommitCheck(c.ctx(), &pb.CommitCheckRequest{})
		if err != nil {
			return fmt.Errorf("commit check failed: %v", err)
		}
		fmt.Println("configuration check succeeds")
		return nil
	}

	if len(args) > 0 && args[0] == "comment" {
		if len(args) < 2 {
			return fmt.Errorf("usage: commit comment \"description\"")
		}
		desc := strings.Join(args[1:], " ")
		desc = strings.Trim(desc, "\"'")
		resp, err := c.client.Commit(c.ctx(), &pb.CommitRequest{Comment: desc})
		if err != nil {
			return fmt.Errorf("commit failed: %v", err)
		}
		c.refreshPrompt()
		if resp.Summary != "" {
			fmt.Printf("commit complete: %s\n", resp.Summary)
		} else {
			fmt.Println("commit complete")
		}
		return nil
	}

	if len(args) > 0 && args[0] == "confirmed" {
		minutes := int32(10)
		if len(args) >= 2 {
			if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
				minutes = int32(v)
			}
		}
		_, err := c.client.CommitConfirmed(c.ctx(), &pb.CommitConfirmedRequest{Minutes: minutes})
		if err != nil {
			return fmt.Errorf("commit confirmed failed: %v", err)
		}
		c.refreshPrompt()
		fmt.Printf("commit confirmed will be automatically rolled back in %d minutes unless confirmed\n", minutes)
		return nil
	}

	resp, err := c.client.Commit(c.ctx(), &pb.CommitRequest{})
	if err != nil {
		return fmt.Errorf("commit failed: %v", err)
	}
	c.refreshPrompt()
	if resp.Summary != "" {
		fmt.Printf("commit complete: %s\n", resp.Summary)
	} else {
		fmt.Println("commit complete")
	}
	return nil
}

func (c *ctl) handlePing(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ping <host> [count N] [source IP] [size N] [routing-instance NAME]")
	}
	req := &pb.PingRequest{Target: args[0], Count: 5}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "count":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.Count = int32(v)
				}
			}
		case "source":
			if i+1 < len(args) {
				i++
				req.Source = args[i]
			}
		case "size":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.Size = int32(v)
				}
			}
		case "routing-instance":
			if i+1 < len(args) {
				i++
				req.RoutingInstance = args[i]
			}
		}
	}
	ctx, cancel := context.WithTimeout(c.ctx(), 60*time.Second)
	defer cancel()
	stream, err := c.client.Ping(ctx, req)
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
		fmt.Println(resp.Output)
	}
	return nil
}

func (c *ctl) handleTraceroute(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: traceroute <host> [source IP] [routing-instance NAME]")
	}
	req := &pb.TracerouteRequest{Target: args[0]}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "source":
			if i+1 < len(args) {
				i++
				req.Source = args[i]
			}
		case "routing-instance":
			if i+1 < len(args) {
				i++
				req.RoutingInstance = args[i]
			}
		}
	}
	ctx, cancel := context.WithTimeout(c.ctx(), 60*time.Second)
	defer cancel()
	stream, err := c.client.Traceroute(ctx, req)
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
		fmt.Println(resp.Output)
	}
	return nil
}

func (c *ctl) handleLoad(args []string) error {
	if len(args) < 2 {
		printConfigTreeHelp("load:", "load")
		return nil
	}

	mode := args[0]
	if mode != "override" && mode != "merge" {
		return fmt.Errorf("load: unknown mode %q (use 'override' or 'merge')", mode)
	}

	source := args[1]
	var content string

	if source == "terminal" {
		fmt.Println("[Type or paste configuration, then press Ctrl-D on an empty line]")
		var lines []string
		for {
			line, err := c.rl.Readline()
			if err != nil {
				break
			}
			lines = append(lines, line)
		}
		content = strings.Join(lines, "\n")
	} else {
		data, err := os.ReadFile(source)
		if err != nil {
			return fmt.Errorf("load: %v", err)
		}
		content = string(data)
	}

	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("load: empty input")
	}

	_, err := c.client.Load(c.ctx(), &pb.LoadRequest{
		Mode:    mode,
		Content: content,
	})
	if err != nil {
		return fmt.Errorf("load %s: %v", mode, err)
	}
	fmt.Printf("load %s complete\n", mode)
	return nil
}

func (c *ctl) handleTest(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("test: specify a test command", "test")
		return nil
	}

	switch args[0] {
	case "policy":
		return c.testPolicy(args[1:])
	case "routing":
		return c.testRouting(args[1:])
	case "security-zone":
		return c.testSecurityZone(args[1:])
	default:
		return fmt.Errorf("unknown test command: %s", args[0])
	}
}

func (c *ctl) testPolicy(args []string) error {
	var fromZone, toZone, srcIP, dstIP, proto string
	var dstPort int
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "from-zone":
			if i+1 < len(args) {
				i++
				fromZone = args[i]
			}
		case "to-zone":
			if i+1 < len(args) {
				i++
				toZone = args[i]
			}
		case "source-ip":
			if i+1 < len(args) {
				i++
				srcIP = args[i]
			}
		case "destination-ip":
			if i+1 < len(args) {
				i++
				dstIP = args[i]
			}
		case "destination-port":
			if i+1 < len(args) {
				i++
				dstPort, _ = strconv.Atoi(args[i])
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				proto = args[i]
			}
		}
	}

	if fromZone == "" || toZone == "" {
		fmt.Println("usage: test policy from-zone <zone> to-zone <zone>")
		fmt.Println("       source-ip <ip> destination-ip <ip> destination-port <port> protocol <tcp|udp>")
		return nil
	}

	topic := fmt.Sprintf("test-policy:from=%s,to=%s", fromZone, toZone)
	if srcIP != "" {
		topic += ",src=" + srcIP
	}
	if dstIP != "" {
		topic += ",dst=" + dstIP
	}
	if dstPort > 0 {
		topic += ",port=" + strconv.Itoa(dstPort)
	}
	if proto != "" {
		topic += ",proto=" + proto
	}
	return c.showText(topic)
}

func (c *ctl) testRouting(args []string) error {
	var dest, instance string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "destination":
			if i+1 < len(args) {
				i++
				dest = args[i]
			}
		case "instance":
			if i+1 < len(args) {
				i++
				instance = args[i]
			}
		}
	}

	if dest == "" {
		fmt.Println("usage: test routing destination <ip-or-prefix> [instance <name>]")
		return nil
	}

	topic := "test-routing:dest=" + dest
	if instance != "" {
		topic += ",instance=" + instance
	}
	return c.showText(topic)
}

func (c *ctl) testSecurityZone(args []string) error {
	var ifName string
	for i := 0; i < len(args); i++ {
		if args[i] == "interface" && i+1 < len(args) {
			i++
			ifName = args[i]
		}
	}

	if ifName == "" {
		fmt.Println("usage: test security-zone interface <name>")
		return nil
	}

	return c.showText("test-zone:interface=" + ifName)
}
