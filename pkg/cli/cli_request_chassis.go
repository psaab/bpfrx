package cli

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/psaab/xpf/pkg/cluster"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
)

func (c *CLI) handleRequestChassis(args []string) error {
	if len(args) == 0 || args[0] != "cluster" {
		fmt.Println("request chassis:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children))
		return nil
	}
	args = args[1:] // consume "cluster"
	if len(args) == 0 {
		fmt.Println("request chassis cluster:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children["cluster"].Children))
		return nil
	}
	switch args[0] {
	case "failover":
		return c.handleRequestChassisClusterFailover(args[1:])
	case "data-plane":
		return c.handleRequestChassisClusterDataPlane(args[1:])
	default:
		fmt.Println("request chassis cluster:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children["cluster"].Children))
		return nil
	}
}

func (c *CLI) handleRequestChassisClusterFailover(args []string) error {
	if c.cluster == nil {
		return fmt.Errorf("cluster not configured")
	}
	// "request chassis cluster failover reset redundancy-group <N>"
	if len(args) >= 1 && args[0] == "reset" {
		if len(args) < 3 || args[1] != "redundancy-group" {
			return fmt.Errorf("usage: request chassis cluster failover reset redundancy-group <N>")
		}
		rgID, err := strconv.Atoi(args[2])
		if err != nil {
			return fmt.Errorf("invalid redundancy-group ID: %s", args[2])
		}
		if err := c.cluster.ResetFailover(rgID); err != nil {
			return err
		}
		fmt.Printf("Failover reset for redundancy group %d\n", rgID)
		return nil
	}

	// "request chassis cluster failover data node <N>"
	if len(args) >= 3 && args[0] == "data" && args[1] == "node" {
		targetNode, err := strconv.Atoi(args[2])
		if err != nil {
			return fmt.Errorf("invalid node ID: %s", args[2])
		}
		if !cluster.IsSupportedClusterNodeID(targetNode) {
			return fmt.Errorf("unsupported cluster failover target node %d", targetNode)
		}
		localNode := c.cluster.NodeID()
		if targetNode != localNode {
			message, err := c.requestPeerSystemAction(
				context.Background(),
				fmt.Sprintf("cluster-failover-data:node%d", targetNode),
			)
			if err != nil {
				return err
			}
			fmt.Println(message)
			return nil
		}

		dataRGs := c.cluster.DataGroupIDs()
		if len(dataRGs) == 0 {
			return fmt.Errorf("no data redundancy groups configured")
		}
		moveRGs := make([]int, 0, len(dataRGs))
		for _, rgID := range dataRGs {
			if !c.cluster.IsLocalPrimary(rgID) {
				moveRGs = append(moveRGs, rgID)
			}
		}
		if len(moveRGs) == 0 {
			fmt.Printf("All data redundancy groups are already primary on node %d\n", targetNode)
			return nil
		}
		if len(moveRGs) == 1 {
			if err := c.cluster.RequestPeerFailover(moveRGs[0]); err != nil {
				return err
			}
		} else {
			if err := c.cluster.RequestPeerFailoverBatch(moveRGs); err != nil {
				return err
			}
		}
		fmt.Printf("Manual failover completed for data redundancy groups %v (transfer committed)\n", moveRGs)
		return nil
	}

	// "request chassis cluster failover redundancy-group <N> [node <N>]"
	if len(args) >= 2 && args[0] == "redundancy-group" {
		rgID, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid redundancy-group ID: %s", args[1])
		}

		// If "node <N>" is specified, route to the correct node.
		if len(args) >= 4 && args[2] == "node" {
			targetNode, err := strconv.Atoi(args[3])
			if err != nil {
				return fmt.Errorf("invalid node ID: %s", args[3])
			}
			localNode := c.cluster.NodeID()
			if targetNode == localNode {
				if err := c.cluster.RequestPeerFailover(rgID); err != nil {
					return err
				}
				fmt.Printf("Manual failover completed for redundancy group %d (transfer committed)\n", rgID)
				return nil
			}
			message, err := c.requestPeerSystemAction(
				context.Background(),
				fmt.Sprintf("cluster-failover:%d:node%d", rgID, targetNode),
			)
			if err != nil {
				return err
			}
			fmt.Println(message)
			return nil
		}

		if err := c.cluster.ManualFailover(rgID); err != nil {
			return err
		}
		fmt.Printf("Manual failover triggered for redundancy group %d\n", rgID)
		return nil
	}

	return fmt.Errorf("usage: request chassis cluster failover {redundancy-group <N> [node <N>] | data node <N>}")
}

func (c *CLI) handleRequestChassisClusterDataPlane(args []string) error {
	if len(args) == 0 || args[0] != "userspace" {
		fmt.Println("request chassis cluster data-plane:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children["cluster"].Children["data-plane"].Children))
		return nil
	}
	provider, err := c.userspaceDataplaneControl()
	if err != nil {
		return err
	}
	args = args[1:]

	var status dpuserspace.ProcessStatus
	switch {
	case len(args) > 0 && args[0] == "inject-packet":
		slot, mode, extra, err := dpuserspace.ParseInjectPacketCommand(args)
		if err != nil {
			return err
		}
		status, err = provider.Status()
		if err != nil {
			return err
		}
		req, err := dpuserspace.BuildInjectPacketRequest(slot, mode, extra, status)
		if err != nil {
			return err
		}
		status, err = provider.InjectPacket(req)
		if err != nil {
			return err
		}
	case len(args) > 0 && args[0] == "forwarding":
		armed, err := dpuserspace.ParseForwardingCommand(args)
		if err != nil {
			return err
		}
		status, err = provider.SetForwardingArmed(armed)
		if err != nil {
			return err
		}
	case len(args) > 0 && args[0] == "queue":
		queueID, registered, armed, err := dpuserspace.ParseQueueCommand(args)
		if err != nil {
			return err
		}
		status, err = provider.SetQueueState(queueID, registered, armed)
		if err != nil {
			return err
		}
	case len(args) > 0 && args[0] == "binding":
		slot, registered, armed, err := dpuserspace.ParseBindingCommand(args)
		if err != nil {
			return err
		}
		status, err = provider.SetBindingState(slot, registered, armed)
		if err != nil {
			return err
		}
	default:
		fmt.Println("request chassis cluster data-plane userspace:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["chassis"].Children["cluster"].Children["data-plane"].Children["userspace"].Children))
		return nil
	}
	fmt.Print(dpformat.FormatStatusSummary(status))
	fmt.Println()
	fmt.Print(dpformat.FormatBindings(status))
	return nil
}
