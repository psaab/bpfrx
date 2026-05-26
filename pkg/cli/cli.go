// Package cli implements the Junos-style interactive CLI for xpf.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chzyer/readline"
	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcprelay"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/fwdstatus"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/lldp"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/vrrp"
)

// CLI is the interactive command-line interface.
type CLI struct {
	rl              *readline.Instance
	store           *configstore.Store
	dp              cliRuntime
	eventBuf        *logging.EventBuffer
	eventReader     *logging.EventReader
	routing         *routing.Manager
	frr             *frr.Manager
	ipsec           *ipsec.Manager
	dhcp            *dhcp.Manager
	dhcpRelay       *dhcprelay.Manager
	cluster         *cluster.Manager
	rpmResultsFn    func() []*rpm.ProbeResult
	feedsFn         func() map[string]feeds.FeedInfo
	lldpNeighborsFn func() []*lldp.Neighbor
	hostname        string
	username        string
	userClass       string
	version         string
	startTime       time.Time

	vrrpMgr *vrrp.Manager

	// fwdSampler supplies 5s/1m/5m CPU windows to
	// `show chassis forwarding` (#881).  Nil when no sampler is
	// wired — Build() falls back to all-invalid windows.
	fwdSampler *fwdstatus.Sampler

	// applyConfigFn is the daemon's full reconcile callback used by
	// non-commit paths (e.g. confirm/rollback). For commits, the CLI
	// prefers commitFn / commitConfirmedFn so the commit→apply pair
	// is atomic under the daemon's apply semaphore (#846). When
	// commitFn is nil (CLI spawned outside daemon), the CLI falls
	// back to store.Commit() + applyConfigFn, and ultimately to
	// applyToDataplane when neither is wired.
	applyConfigFn func(*config.Config)
	// #846: atomic commit+apply callbacks. When set, handleCommit
	// routes through these instead of calling store.Commit directly.
	// Same callback the HTTP/gRPC handlers use, so commits from all
	// three paths serialize against each other.
	commitFn          func(ctx context.Context, comment string) (*config.Config, error)
	commitConfirmedFn func(ctx context.Context, minutes int) (*config.Config, error)

	// Fabric peer dialing for cluster-wide queries (fab0 + optional fab1).
	fabricPeerAddrFn   func() []string
	fabricVRFDevice    string
	peerSystemActionFn func(ctx context.Context, action string) (string, error)

	// Monitor security flow state (per-CLI-session).
	monitorFlow *monitorFlowState

	// Command cancellation: Ctrl-C during a running external command cancels it.
	// commitCancel is a SEPARATE slot used by handleCommit so an
	// external-command cancel and a commit cancel can never displace
	// each other (the slots are single-writer per call site).
	cmdMu        sync.Mutex
	cmdCancel    context.CancelFunc
	commitCancel context.CancelFunc
}

// New creates a new CLI.
func New(store *configstore.Store, dp cliRuntime, eventBuf *logging.EventBuffer, eventReader *logging.EventReader, rm *routing.Manager, fm *frr.Manager, im *ipsec.Manager, dm *dhcp.Manager, dr *dhcprelay.Manager, cm *cluster.Manager) *CLI {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}
	username := os.Getenv("USER")
	if username == "" {
		username = "root"
	}

	return &CLI{
		store:       store,
		dp:          dp,
		eventBuf:    eventBuf,
		eventReader: eventReader,
		routing:     rm,
		startTime:   time.Now(),
		frr:         fm,
		ipsec:       im,
		dhcp:        dm,
		dhcpRelay:   dr,
		cluster:     cm,
		hostname:    hostname,
		username:    username,
	}
}

func (c *CLI) applyResult() *dataplane.ApplyResult {
	if c == nil {
		return nil
	}
	return dataplane.LastApplyResultOf(c.dp)
}

func (c *CLI) dataplaneLoaded() bool {
	return c != nil && c.dp != nil && c.dp.IsLoaded()
}

// SetForwardingSampler wires the pkg/fwdstatus Sampler into the CLI
// so `show chassis forwarding` can read 5s/1m/5m CPU windows.
// Pass nil to disable windowed CPU display (Build falls back to
// all-invalid columns and the formatter prints `-`).
func (c *CLI) SetForwardingSampler(s *fwdstatus.Sampler) {
	c.fwdSampler = s
}

// SetRPMResultsFn sets a callback for retrieving live RPM probe results.
func (c *CLI) SetRPMResultsFn(fn func() []*rpm.ProbeResult) {
	c.rpmResultsFn = fn
}

// SetFeedsFn sets a callback for retrieving live dynamic address feed status.
func (c *CLI) SetFeedsFn(fn func() map[string]feeds.FeedInfo) {
	c.feedsFn = fn
}

// SetLLDPNeighborsFn sets a callback for retrieving live LLDP neighbor data.
func (c *CLI) SetLLDPNeighborsFn(fn func() []*lldp.Neighbor) {
	c.lldpNeighborsFn = fn
}

// SetVersion sets the software version string for show version.
func (c *CLI) SetVersion(v string) {
	c.version = v
}

// SetUserClass sets the login class for RBAC permission checks.
func (c *CLI) SetUserClass(class string) {
	c.userClass = class
}

// SetVRRPManager sets the VRRP manager for runtime state queries.
func (c *CLI) SetVRRPManager(m *vrrp.Manager) {
	c.vrrpMgr = m
}

// SetApplyConfigFn wires the daemon's full reconcile callback into the
// CLI so commits issued through the in-process CLI go through the same
// path gRPC/HTTP use. Required for D3 RSS indirection reapply on
// `set system dataplane workers N` and `rss-indirection enable|disable`
// (#797 H2). When nil, CLI commits fall back to the legacy
// applyToDataplane() path.
func (c *CLI) SetApplyConfigFn(fn func(*config.Config)) {
	c.applyConfigFn = fn
}

// SetCommitFns wires the daemon's atomic commit+apply callbacks
// (#846). When set, handleCommit routes through these instead of
// calling store.Commit directly so the commit→apply pair is atomic
// against HTTP/gRPC/event-engine commits.
func (c *CLI) SetCommitFns(
	commitFn func(ctx context.Context, comment string) (*config.Config, error),
	commitConfirmedFn func(ctx context.Context, minutes int) (*config.Config, error),
) {
	c.commitFn = commitFn
	c.commitConfirmedFn = commitConfirmedFn
}

// SetFabricPeer configures fabric peer dialing for cluster-wide queries.
func (c *CLI) SetFabricPeer(addrFn func() []string, vrfDevice string) {
	c.fabricPeerAddrFn = addrFn
	c.fabricVRFDevice = vrfDevice
}

// Run starts the interactive CLI loop.
func (c *CLI) Run() error {
	var err error
	completer := &cliCompleter{cli: c}
	c.rl, err = readline.NewEx(&readline.Config{
		Prompt:          c.operationalPrompt(),
		HistoryFile:     filepath.Join(os.Getenv("HOME"), ".xpf_history"),
		HistoryLimit:    10000,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete:    completer,
		Stdin:           os.Stdin,
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
		Listener: readline.FuncListener(func(line []rune, pos int, key rune) ([]rune, int, bool) {
			if key != '?' || pos < 1 {
				return line, pos, false
			}
			// Strip the '?' that readline already inserted.
			cleanLine := make([]rune, 0, len(line)-1)
			cleanLine = append(cleanLine, line[:pos-1]...)
			cleanLine = append(cleanLine, line[pos:]...)
			// Parse words from text before cursor.
			text := string(cleanLine[:pos-1])

			// Pipe filter help: "show ... | ?"
			if pipeCandidates, handled := completePipeFilter(text + " "); handled {
				if len(pipeCandidates) > 0 {
					writeCompletionHelp(c.rl.Stdout(), pipeCandidates)
				}
				// Suppress duplicate help if readline calls Do() for this key.
				completer.helpWritten = true
				return cleanLine, pos - 1, true
			}

			words := strings.Fields(text)
			trailingSpace := len(text) > 0 && text[len(text)-1] == ' '
			var partial string
			if !trailingSpace && len(words) > 0 {
				partial = words[len(words)-1]
				words = words[:len(words)-1]
			}
			var candidates []completionCandidate
			if c.store.InConfigMode() {
				candidates = c.completeConfigWithDesc(words, partial)
			} else {
				// "show configuration <path>" — delegate sub-path to config schema
				if subPath, ok := showConfigurationSubPath(words); ok {
					if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(subPath); resolved {
						subPath = resolvedPath
					}
					schemaCompletions := config.CompleteSetPathWithValues(subPath, c.valueProvider)
					if schemaCompletions != nil {
						for _, sc := range schemaCompletions {
							if partial == "" || strings.HasPrefix(sc.Name, partial) {
								candidates = append(candidates, completionCandidate{name: sc.Name, desc: sc.Desc})
							}
						}
					}
				}
				if len(candidates) == 0 {
					candidates = completeFromTreeWithDesc(operationalTree, words, partial, c.store.ActiveConfig())
				}
			}
			if len(candidates) > 0 {
				writeCompletionHelp(c.rl.Stdout(), candidates)
			}
			// Suppress duplicate help if readline calls Do() for this key.
			completer.helpWritten = true
			return cleanLine, pos - 1, true
		}),
	})
	if err != nil {
		return fmt.Errorf("readline init: %w", err)
	}
	defer c.rl.Close()

	// Register auto-rollback handler for commit confirmed.
	// Prefer the daemon's full reconcile (applyConfigFn) so D3,
	// cluster, VRRP, etc. all re-converge on rollback — matches the
	// gRPC/HTTP rollback path. Falls back to applyToDataplane if
	// applyConfigFn is not wired (e.g. CLI spawned outside daemon).
	c.store.SetCentralRollbackHandler(func(cfg *config.Config) {
		if c.applyConfigFn != nil {
			c.applyConfigFn(cfg)
		} else if c.dp != nil {
			if err := c.applyToDataplane(cfg); err != nil {
				fmt.Fprintf(os.Stderr, "\nwarning: auto-rollback dataplane apply failed: %v\n", err)
			}
		}
		c.reloadSyslog(cfg)
		fmt.Fprintf(os.Stderr, "\ncommit confirmed timed out, configuration has been rolled back\n")
	})

	fmt.Println("xpf stateful firewall - Junos-style CLI")
	fmt.Println("Type '?' for help")
	fmt.Println()

	// Catch SIGINT to prevent process termination.
	// readline handles ^C during input (returns ErrInterrupt).
	// During dispatch, this absorbs the signal so it doesn't kill the daemon.
	// Double Ctrl-C within 2s exits the CLI.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	exitCh := make(chan struct{})
	go func() {
		var lastInterrupt time.Time
		for range sigCh {
			// If a commit or an external command is running, cancel
			// it. commitCancel takes priority because a commit
			// hanging on the apply semaphore is the only path that
			// actually needs ctx-aware cancellation; external
			// commands fall back if no commit is in flight.
			c.cmdMu.Lock()
			commitCancel := c.commitCancel
			cmdCancel := c.cmdCancel
			c.cmdMu.Unlock()
			if commitCancel != nil {
				commitCancel()
				continue
			}
			if cmdCancel != nil {
				cmdCancel()
				continue
			}
			now := time.Now()
			if now.Sub(lastInterrupt) < 2*time.Second {
				if c.store.InConfigMode() {
					c.store.ExitConfigure()
				}
				close(exitCh)
				return
			}
			lastInterrupt = now
		}
	}()

	for {
		select {
		case <-exitCh:
			return nil
		default:
		}
		if c.store.IsConfirmPending() {
			fmt.Println("[commit confirmed pending - issue 'commit' to confirm]")
		}
		line, err := c.rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				continue
			}
			if err == io.EOF {
				// Ctrl-D: exit config mode, or exit CLI if already in operational mode.
				if c.store.InConfigMode() {
					c.store.ExitConfigure()
					c.rl.SetPrompt(c.operationalPrompt())
					fmt.Println("\nExiting configuration mode")
					continue
				}
				return nil
			}
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if err := c.dispatch(line); err != nil {
			if err == errExit {
				return nil
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		// Refresh prompt after every command so cluster role
		// changes (failover) are reflected immediately.
		c.refreshPrompt()
	}
	return nil
}

func (c *CLI) refreshPrompt() {
	if h, err := os.Hostname(); err == nil && h != "" {
		c.hostname = h
	}
	if c.rl != nil {
		if c.store.InConfigMode() {
			c.rl.SetPrompt(c.configPrompt())
		} else {
			c.rl.SetPrompt(c.operationalPrompt())
		}
	}
}

func (c *CLI) clusterPrefix() string {
	if c.cluster == nil {
		return ""
	}
	rg0 := c.cluster.GroupState(0)
	if rg0 == nil {
		return ""
	}
	role := "secondary"
	if rg0.State == cluster.StatePrimary {
		role = "primary"
	}
	return fmt.Sprintf("{%s:node%d}", role, c.cluster.NodeID())
}

func (c *CLI) operationalPrompt() string {
	return fmt.Sprintf("%s%s@%s> ", c.clusterPrefix(), c.username, c.hostname)
}

func (c *CLI) configPrompt() string {
	return fmt.Sprintf("%s%s@%s# ", c.clusterPrefix(), c.username, c.hostname)
}

