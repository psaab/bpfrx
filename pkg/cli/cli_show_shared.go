package cli

import (
	"fmt"
	"os"

	"github.com/psaab/bpfrx/pkg/cmdtree"
)

func (c *CLI) showOperationalHelp() {
	cmdtree.WriteHelp(os.Stdout, cmdtree.HelpCandidates(operationalTree))
	fmt.Println()
	fmt.Println("  <command> | match/grep <pattern>    Filter output by pattern")
	fmt.Println("  <command> | except <pattern>        Exclude lines matching pattern")
	fmt.Println("  <command> | find <pattern>          Show from first match to end")
	fmt.Println("  <command> | count                   Count output lines")
	fmt.Println("  <command> | last [N]                Show last N lines (default 10)")
	fmt.Println("  <command> | no-more                 Disable paging")
	fmt.Println("  Use <TAB> for command completion, ? for context help")
}

func (c *CLI) showConfigHelp() {
	cmdtree.WriteHelp(os.Stdout, cmdtree.HelpCandidates(configTopLevel))
	fmt.Println()
	fmt.Println("  Use <TAB> for command completion, ? for context help")
}
