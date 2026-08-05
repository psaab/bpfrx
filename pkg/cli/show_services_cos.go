package cli

import (
	"fmt"

	"github.com/psaab/xpf/pkg/cmdtree"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
)

// handleShowClassOfService dispatches `show class-of-service ...`
// to the appropriate presenter.
func (c *CLI) handleShowClassOfService(args []string) error {
	if len(args) == 0 {
		cmdtree.PrintTreeHelp("show class-of-service:", operationalTree, "show", "class-of-service")
		return nil
	}
	switch args[0] {
	case "interface":
		selector := ""
		if len(args) > 1 {
			selector = args[1]
		}
		return c.showClassOfServiceInterface(selector)
	case "classifier":
		nameFilter, typeFilter := parseCoSNameTypeArgs(args[1:])
		fmt.Print(dpformat.FormatCoSClassifiers(c.store.ActiveConfig(), nameFilter, typeFilter))
		return nil
	case "rewrite-rule":
		// #6848: same `name`/`type` filter grammar as `classifier`, so the two
		// sibling commands parse identically; parseCoSNameTypeArgs is shared
		// rather than duplicated.
		nameFilter, typeFilter := parseCoSNameTypeArgs(args[1:])
		fmt.Print(dpformat.FormatCoSRewriteRules(c.store.ActiveConfig(), nameFilter, typeFilter))
		return nil
	case "scheduler-map":
		name := ""
		if len(args) > 1 {
			name = args[1]
		}
		fmt.Print(dpformat.FormatCoSSchedulerMaps(c.store.ActiveConfig(), name))
		return nil
	case "forwarding-class":
		fmt.Print(dpformat.FormatCoSForwardingClasses(c.store.ActiveConfig()))
		return nil
	default:
		cmdtree.PrintTreeHelp("show class-of-service:", operationalTree, "show", "class-of-service")
		return nil
	}
}

// parseCoSNameTypeArgs extracts the optional `name <n>` / `type <t>` filters
// shared by `show class-of-service classifier` and `show class-of-service
// rewrite-rule` (#6848 — the two commands advertise the same grammar, so they
// parse through one function rather than two that can drift).
//
// A LEADING BARE TOKEN is also accepted as the name, i.e.
// `show class-of-service rewrite-rule rw-dscp` == `... rewrite-rule name
// rw-dscp`. Both commands' cmdtree nodes carry a DynamicFn offering rule names
// directly under the command (tree.go), so an operator who tab-completes a name
// and presses enter submits exactly that bare form. Before #6848 the keyword-
// only parser silently ignored it and dumped every rule — completion promised a
// filter the parser did not implement. Accepting the bare token closes that for
// `rewrite-rule` AND for the pre-existing `classifier` command, keeping the two
// siblings identical; no test pinned the old dump-everything behavior.
func parseCoSNameTypeArgs(args []string) (nameFilter, typeFilter string) {
	if len(args) > 0 && args[0] != "name" && args[0] != "type" {
		nameFilter = args[0]
		args = args[1:]
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "name":
			if i+1 < len(args) {
				nameFilter = args[i+1]
				i++
			}
		case "type":
			if i+1 < len(args) {
				typeFilter = args[i+1]
				i++
			}
		}
	}
	return nameFilter, typeFilter
}

func (c *CLI) showClassOfServiceInterface(selector string) error {
	cfg := c.store.ActiveConfig()
	var status *dpuserspace.ProcessStatus
	if userspaceStatus, err := c.userspaceDataplaneStatus(); err == nil {
		status = &userspaceStatus
	}
	fmt.Print(dpformat.FormatCoSInterfaceSummary(cfg, status, selector))
	return nil
}

// showInterfacesQueue renders `show interfaces queue [<interface>]` (#4228
// Gap 7) from the live userspace CoS runtime snapshot.
func (c *CLI) showInterfacesQueue(selector string) error {
	var status *dpuserspace.ProcessStatus
	userspaceStatus, statusErr := c.userspaceDataplaneStatus()
	if statusErr == nil {
		status = &userspaceStatus
	}
	// Pass the fetch error through so a failed status retrieval renders as an
	// explicit error, not "No class-of-service queues active" (#5326): a nil
	// status must not conflate "unreachable" with "empty".
	fmt.Print(dpformat.FormatInterfacesQueue(status, statusErr, selector))
	return nil
}
