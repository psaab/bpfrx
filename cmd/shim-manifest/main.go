// shim-manifest recomputes the userspace-xdp source→object freshness
// manifest (#4977) and writes it to
// pkg/dataplane/userspace_xdp_manifest.json.
//
// It is invoked by pkg/dataplane/build-userspace-xdp.sh immediately
// after the verifier-gated install of userspace_xdp_bpfel.o, so the
// manifest stays in lockstep with the object it describes. Running it by
// hand does NOT rebuild the shim object — use `make generate` for that;
// this tool only re-hashes whatever object and source currently sit in
// the tree.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/psaab/xpf/pkg/dataplane"
)

func main() {
	repoRoot := flag.String("repo-root", ".", "repository root the manifest paths are relative to")
	flag.Parse()

	if err := dataplane.WriteUserspaceXDPManifest(*repoRoot); err != nil {
		fmt.Fprintf(os.Stderr, "shim-manifest: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("shim-manifest: wrote %s\n", dataplane.UserspaceXDPManifestRelPath)
}
