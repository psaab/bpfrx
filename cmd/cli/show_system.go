package main

import (
	"fmt"
	"strings"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func (c *ctl) handleShowSystem(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show system:", "show", "system")
		return nil
	}

	switch args[0] {
	case "commit":
		if len(args) >= 2 && args[1] == "history" {
			return c.showText("commit-history")
		}
		printRemoteTreeHelp("show system commit:", "show", "system", "commit")
		return nil

	case "rollback":
		if len(args) >= 2 {
			if args[1] == "compare" && len(args) >= 3 {
				// #5052: parse the slot into the int32 the RPC carries.
				// strconv.Atoi + int32() wrapped an out-of-range value
				// (e.g. 4294967297 -> 1) and silently compared the wrong
				// slot with a success exit. The shared parser rejects it.
				n, err := parseRollbackSelector(args[2], "usage: show system rollback compare <N>", 1)
				if err != nil {
					return err
				}
				resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{
					RollbackN: n,
				})
				if err != nil {
					return fmt.Errorf("%v", err)
				}
				if resp.Output == "" {
					fmt.Println("No differences found")
				} else {
					fmt.Print(resp.Output)
				}
				return nil
			}

			// #5052: same int32-wrap guard as the compare selector above.
			n, err := parseRollbackSelector(args[1], "usage: show system rollback <N>", 1)
			if err != nil {
				return err
			}
			format := pb.ConfigFormat_HIERARCHICAL
			rest := strings.Join(args[2:], " ")
			if strings.Contains(rest, "| display set") {
				format = pb.ConfigFormat_SET
			} else if strings.Contains(rest, "| display xml") {
				format = pb.ConfigFormat_XML
			} else if strings.Contains(rest, "compare") {
				resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{
					RollbackN: n,
				})
				if err != nil {
					return fmt.Errorf("%v", err)
				}
				if resp.Output == "" {
					fmt.Println("No differences found")
				} else {
					fmt.Print(resp.Output)
				}
				return nil
			}
			resp, err := c.client.ShowRollback(c.ctx(), &pb.ShowRollbackRequest{
				N:      n,
				Format: format,
			})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Print(resp.Output)
			return nil
		}

		resp, err := c.client.ListHistory(c.ctx(), &pb.ListHistoryRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		if len(resp.Entries) == 0 {
			fmt.Println("No rollback history available")
			return nil
		}
		for _, e := range resp.Entries {
			fmt.Printf("  rollback %d: %s\n", e.Index, e.Timestamp)
		}
		return nil

	case "uptime":
		return c.showSystemInfo("uptime")
	case "memory":
		return c.showSystemInfo("memory")
	case "storage":
		return c.showText("storage")
	case "processes":
		return c.showSystemInfo("processes")
	case "alarms":
		return c.showText("alarms")
	case "users":
		return c.showSystemInfo("users")
	case "connections":
		return c.showSystemInfo("connections")
	case "license":
		fmt.Println("License: open-source (no license required)")
		return nil
	case "services":
		return c.showText("system-services")
	case "ntp":
		return c.showText("ntp")
	case "login":
		return c.showText("login")
	case "syslog":
		return c.showText("system-syslog")
	case "internet-options":
		return c.showText("internet-options")
	case "root-authentication":
		return c.showText("root-authentication")
	case "backup-router":
		return c.showText("backup-router")
	case "buffers":
		if len(args) >= 2 && args[1] == "detail" {
			return c.showText("buffers-detail")
		}
		return c.showText("buffers")
	case "boot-messages":
		return c.showSystemInfo("boot-messages")
	case "core-dumps":
		return c.showText("core-dumps")
	case "kernel-upgrade":
		// #6495: the #1930 kernel-channel state, rendered daemon-side through
		// pkg/upgrade — the same implementation the console CLI uses.
		return c.showText("kernel-upgrade")
	default:
		return fmt.Errorf("unknown show system target: %s", args[0])
	}
}
