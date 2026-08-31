package main

import (
	"fmt"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func (c *ctl) showInterfaces(args []string) error {
	if len(args) > 0 && args[0] == "queue" {
		// #4228 Gap 7: per-queue CoS statistics, optional interface filter.
		selector := ""
		if len(args) > 1 {
			selector = args[1]
		}
		return c.showTextFiltered("interfaces-queue", selector)
	}
	if len(args) > 0 && args[0] == "tunnel" {
		return c.showCommand("show interfaces tunnel")
	}
	if len(args) > 0 && args[0] == "extensive" {
		return c.showCommand("show interfaces extensive")
	}
	if len(args) > 0 && args[0] == "statistics" {
		return c.showCommand("show interfaces statistics")
	}
	if len(args) > 0 && args[0] == "detail" {
		return c.showCommand("show interfaces detail")
	}
	if len(args) >= 2 && args[len(args)-1] == "detail" {
		return c.showTextFiltered("interfaces-detail", args[0])
	}
	req := &pb.ShowInterfacesDetailRequest{}
	for _, a := range args {
		if a == "terse" {
			req.Terse = true
		} else {
			req.Filter = a
		}
	}
	resp, err := c.client.ShowInterfacesDetail(c.ctx(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}
