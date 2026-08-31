package main

import (
	"fmt"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func (c *ctl) handleShowProtocols(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show protocols:", "show", "protocols")
		return nil
	}
	switch args[0] {
	case "ospf":
		typ := "neighbor"
		if len(args) >= 2 {
			typ = args[1]
			if typ == "neighbor" && len(args) >= 3 && args[2] == "detail" {
				typ = "neighbor-detail"
			}
		}
		resp, err := c.client.GetOSPFStatus(c.ctx(), &pb.GetOSPFStatusRequest{Type: typ})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	case "bgp":
		typ := "summary"
		if len(args) >= 2 {
			typ = args[1]
			if typ == "neighbor" && len(args) >= 3 {
				ip := args[2]
				if len(args) >= 4 {
					switch args[3] {
					case "received-routes":
						typ = "received-routes:" + ip
					case "advertised-routes":
						typ = "advertised-routes:" + ip
					default:
						typ = "neighbor:" + ip
					}
				} else {
					typ = "neighbor:" + ip
				}
			}
		}
		resp, err := c.client.GetBGPStatus(c.ctx(), &pb.GetBGPStatusRequest{Type: typ})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	case "bfd":
		if len(args) >= 2 && args[1] == "peers" {
			return c.showCommand("show protocols bfd peers")
		}
		printRemoteTreeHelp("show protocols bfd:", "show", "protocols", "bfd")
		return nil
	case "rip":
		resp, err := c.client.GetRIPStatus(c.ctx(), &pb.GetRIPStatusRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	case "isis":
		typ := "adjacency"
		if len(args) >= 2 {
			typ = args[1]
			if typ == "adjacency" && len(args) >= 3 && args[2] == "detail" {
				typ = "adjacency-detail"
			}
		}
		resp, err := c.client.GetISISStatus(c.ctx(), &pb.GetISISStatusRequest{Type: typ})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	default:
		return fmt.Errorf("unknown show protocols target: %s", args[0])
	}
}
