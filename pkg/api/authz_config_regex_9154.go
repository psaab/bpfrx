package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// #9154: THE REST SURFACE PERFORMED CONFIG MUTATIONS WITH NO `*-configuration`
// REGEX CHECK AT ALL.
//
// A class's `allow-configuration` / `deny-configuration` was evaluated by the
// on-box CLI and by nothing else, so an operator who gave someone broad
// `permissions` while withholding specific configuration authority had that
// withholding enforced only at the console. `pkg/api/authz.go` and
// `pkg/api/config.go` had ZERO matches for `Regex`.
//
// Reachability is not theoretical: authorizeInputs resolves the peer UID for a
// local caller, and principalFrom's stated rule is "if the caller is on this
// host, the login model is the only authority". So a local user in a
// PermConfig class, regex-restricted on the CLI and on gRPC, could
// `curl -X POST /api/v1/config/set` with no restriction whatever.
//
// GATED HERE, NOT IN THE HANDLERS. The middleware is where the principal, the
// class and the ONE config snapshot already are, and where the body has already
// been buffered for the #5561 second adjudication — so the line being gated is
// the line the handler will act on, read from the same bytes. Adding the check
// per handler would be a rule enforced by whichever handler remembered it,
// which is the shape that produced this defect.

// restConfigMutationRoutes maps a config-mutating REST route to the verb its
// handler applies. The verb is supplied here because the request body carries
// only the PATH — `{"input": "system host-name x"}` — while the regexes are
// written against a verb-led config line, the same string the CLI evaluates.
//
// `load` is deliberately ABSENT and is a stated remaining gap, inherited from
// the CLI gate: it applies arbitrary content whose paths are not known until
// parsed, so a path regex cannot be evaluated against it without a different
// mechanism. `commit` and `rollback` act on the candidate as a whole and carry
// no path to match.
var restConfigMutationRoutes = map[string]string{
	"POST /api/v1/config/set":    "set",
	"POST /api/v1/config/delete": "delete",
}

// authorizeRESTConfigMutation adjudicates a config-mutating REST request
// against the caller's `*-configuration` regexes.
//
// It reads the ALREADY-BUFFERED body and puts it back, so the handler still
// decodes the same bytes.
func (s *Server) authorizeRESTConfigMutation(r *http.Request, cfg *config.Config, p authz.Principal) error {
	verb, gated := restConfigMutationRoutes[r.Method+" "+r.URL.Path]
	if !gated || p.Class == "" {
		return nil
	}
	// A superuser is exempt for the same reason authz.Authorize exempts one:
	// uid 0 owns the config DB and the daemon process, so a regex denial would
	// be theater. p.Class is empty for a superuser anyway.
	if p.Superuser {
		return nil
	}
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	raw, err := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil {
		// The handler will report its own decode failure, which is a better
		// message than a permission denial for a body we could not read.
		return nil
	}
	var req struct {
		Input string `json:"input"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil
	}
	input := strings.TrimSpace(req.Input)
	if input == "" {
		return nil
	}
	// The edit path is empty: REST has no cursor, so the body carries the
	// resolved path — which is exactly what the store will act on.
	return config.AuthorizeConfigMutation(cfg, p.Class, nil, verb+" "+input)
}
