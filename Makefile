CLANG ?= clang
GO ?= go
CARGO ?= $(HOME)/.cargo/bin/cargo
BINARY := xpfd
PREFIX ?= /usr/local

# Version info embedded at build time
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)

# eBPF compilation flags
.PHONY: all generate generate-userspace-xdp build-userspace-xdp build build-ctl build-userspace-dp build-userspace-dp-debug-log proto install clean test test-go test-rust test-race-dp audit-check test-connectivity test-failover test-double-failover test-active-active test-stress-failover test-ha-crash test-chained-crash test-private-rg test-restart-connectivity

all: generate build build-ctl

# Generate dataplane artifacts. After the #1476 source-removal phase of
# the #1373 eBPF retirement umbrella, the only generator step here is the
# retained Rust AF_XDP shim object embedded by userspace_xdp_rust.go.
generate:
	$(GO) generate ./pkg/dataplane/...

# Generate only the retained Rust userspace XDP shim object. The
# `generate` target above runs the same single directive; this alias
# stays for callers wired to the older name (e.g. build scripts that
# only need the shim and not full code-gen). Originally introduced as
# the #1473 source-removal canary that must not invoke legacy
# xdp_main/tc bpf2go (now permanently true post-#1476).
generate-userspace-xdp:
	$(GO) generate -run '^//go:generate bash build-userspace-xdp\.sh$$' ./pkg/dataplane

build-userspace-xdp: generate-userspace-xdp

# Build the daemon binary
build:
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/xpfd

# Build the remote CLI client
build-ctl:
	CGO_ENABLED=0 $(GO) build -o cli ./cmd/cli

# Build the userspace dataplane helper
build-userspace-dp:
	$(CARGO) build --manifest-path userspace-dp/Cargo.toml --release
	install -m 0755 userspace-dp/target/release/xpf-userspace-dp ./xpf-userspace-dp

# Manual build check for the diagnostic `debug-log` feature (#1678).
# The debug-log build is not the production target and is deliberately
# NOT wired into `all`/`build`/`test`, mirroring the opt-in
# `audit-check` precedent. There is no CI in this repo, so this is a
# developer convenience, not an automated gate: nothing runs it unless
# invoked. It exists so the feature build (which silently rotted until
# #1678 because nothing compiled it) can be revalidated with one
# command before a commit. Compile-only; does not install.
build-userspace-dp-debug-log:
	$(CARGO) build --manifest-path userspace-dp/Cargo.toml --release --features debug-log

# Generate protobuf/gRPC code
proto:
	protoc --proto_path=proto/xpf/v1 \
		--go_out=pkg/grpcapi/xpfv1 --go_opt=paths=source_relative \
		--go-grpc_out=pkg/grpcapi/xpfv1 --go-grpc_opt=paths=source_relative \
		proto/xpf/v1/xpf.proto

install: build build-ctl
	install -m 0755 $(BINARY) $(PREFIX)/sbin/$(BINARY)
	install -m 0755 cli $(PREFIX)/bin/cli

# The single pre-commit gate. `test` runs BOTH the Go suite AND the Rust
# userspace-dp cargo suite (#4006). The Rust AF_XDP dataplane is the only
# runtime forwarding path after the #1373/#1476 eBPF retirement, so a
# forwarding / CoS / NAT / session-correctness regression there must fail
# `make test`. Before #4006 this target ran only `go test ./...`, giving a
# false all-clear for the most critical code (a broken Rust dataplane test
# passed `make test` green). Each prerequisite recipe is a plain command,
# so a non-zero exit from either leg aborts the target (Make stops at the
# first failing prerequisite) — a Rust test failure now fails `make test`.
test: test-go test-rust

# Go suite. Invocation preserved exactly from the pre-#4006 `test` target.
test-go: test-race-dp
	# go vet gate scoped to pkg/flowexport (#2224): catches the
	# atomic.Uint64-copy regression class (ExportConfig embeds the live
	# 1-in-N sampleCounter and must never be copied by value). NOT
	# tree-wide yet — two pre-existing vet diagnostics live outside this
	# package (cmd/cli protobuf MessageState copy, pkg/cli unreachable
	# code); widen to ./... once those are resolved.
	$(GO) vet ./pkg/flowexport/...
	$(GO) test ./...
	# #6626: pkg/refactoraudit MUST run uncached.
	#
	# Its hard gate (TestTouchedFileCrossedModularityThreshold) measures the
	# branch's own diff against its merge base by shelling out to
	# scripts/refactoring-audit-touched.sh. Neither the working tree nor that
	# script is a `go test` cache input, so a REAL threshold crossing changes
	# nothing the cache hashes and `./...` above returns "ok (cached)" — the
	# gate passes without running. Reproduced: a new 2004-LOC production file
	# (a genuine [REFACTOR] crossing, exactly the event this gate exists to
	# catch) returned "ok (cached)" and FAILED under -count=1.
	#
	# #6623 widened the window rather than creating it: under the old
	# byte-exact artifact compare the tracked artifact churned constantly and
	# busted the cache by accident, so a stale pass survived one commit instead
	# of many.
	#
	# Scoped to this package, not the whole suite: measured at ~10.7s uncached
	# against ~0.1s cached, which is noise on a suite that already runs
	# minutes, whereas -count=1 on ./... would forfeit caching everywhere.
	# Deliberately NOT narrowed further with -run: a name predicate silently
	# stops covering the next tree-reading test added here, which is the
	# #6743 r2-N3 lesson recorded in this package's own doc.go.
	$(GO) test -count=1 ./pkg/refactoraudit/

# #2114 scoped race gate: the dataplane-cell publication races
# (bootstrap-exit clear vs sampler/watcher/confirm-timer readers) and the
# A3 armed-gate registry races are only visible under -race — a plain
# `go test ./...` has no race teeth, and a full-repo -race run stays out
# of scope. The named patterns cover the daemon cell tests (incl. the
# #2116 NAT pool-alarm regressions and the forwarding-status adapter) and
# the pkg/dataplane armed-gate legs.
#
# #6743 r2-N3: the pkg/daemon pattern used to be just
# 'DataplaneCell|NATPoolAlarm|ForwardingStatus|BootstrapExit', which matched
# 19 of 1118 tests and EXCLUDED every test that runs a loop goroutine
# against a concurrently emptied cell — the event-stream binders, the
# capability probes, the escape binders. A -run filter is a NAME predicate
# over a PROPERTY-defined set, so widening it once is not the whole fix:
# pkg/daemon's TestRaceGateCoversTheConcurrencyBinders parses THIS recipe
# and fails if any test in the declared concurrency-binder files stops
# matching. Keep the `-run '<pattern>'` single-quoted spelling — that canary
# reads it.
#
# #6550: the pkg/cluster leg. Before it, NO make target ran ./pkg/cluster
# under -race at all, so the cluster Monitor's concurrent-map fatal (poll
# goroutine vs UpdateGroups) and the #7257 heartbeat start/stop race were
# not races CI had failed to catch — they were races CI had no path to
# observe. The selection is the two packages' race PROBES only (they are
# ~2s combined at -count=2); pkg/cluster's non-race tests stay on the
# plain `go test ./...` leg. Keep the `-run '<pattern>'` single-quoted
# spelling here too: pkg/cluster's TestRaceGateCoversTheClusterProbes6550
# parses this line, and pkg/daemon's canary reads the FIRST -run line in
# this recipe, so this leg must stay BELOW the pkg/daemon one.
test-race-dp:
	$(GO) test -race ./pkg/daemon/ -run 'DataplaneCell|NATPoolAlarm|ForwardingStatus|BootstrapExit|RuntimeDataplaneNeverBareRootManager|EventStreamFallbackLoop|RunUserspaceEventStream|LiveDataPlane_|GRPCShowBuffers_|SystemAction_|GRPCServer_|RESTServer_|ManagementProbe|ConsoleCLIProbeWiring|FullResync|ReconcilePassUsesOneDataplaneSnapshot|ReconcileBlackholeWrappersStillReloadPerCall' -count=2
	$(GO) test -race ./pkg/dataplane/ -run 'ArmedGate|PreArm' -count=2
	$(GO) test -race ./pkg/cluster/ -run 'DoesNotRaceUpdateGroups6550|DoesNotHoldMuAcrossManagerCallback6550|DoesNotRaceStopHeartbeat7257|HeartbeatStartSuperseded' -count=2

# Rust userspace-dp correctness suite (#4006). userspace-dp is a
# binary-only crate (no [lib] target), so its unit tests live in the bin
# and are reached via --bins; --tests adds any tests/ integration tests.
# Run in --release, matching build-userspace-dp so compiled artifacts are
# shared rather than rebuilt.
#
#   --bins --tests         select the correctness suite. Benches are
#                          deliberately excluded: criterion's harness
#                          (harness = false) rejects libtest's
#                          --test-threads flag, so running them here would
#                          break the run. #5190: benches are NOT run by any
#                          make target or CI job, and only two of them
#                          (prefix_set_lookup, runtime_view_refresh) even
#                          emit a failing verdict — the rest print numbers
#                          for a human and always exit 0. Do not treat a
#                          `cargo bench` exit status as a perf gate.
#   -- --test-threads=1    serialize the harness. Some dataplane socket
#                          tests can wedge in __skb_wait_for_more_packets
#                          when run concurrently; single-threaded execution
#                          avoids the intermittent hang. Runtime for the
#                          full suite is a few minutes (thousands of tests)
#                          — slower than the Go suite but a real gate.
#
# A non-zero cargo exit propagates: this is a plain recipe line, so Make
# fails the target on any command that exits non-zero (no `-` prefix / no
# `|| true` swallows the failure).
#
# #6610: a `cargo check --benches` leg runs FIRST. Benches are still never
# RUN here (criterion's harness = false rejects --test-threads, and the
# numbers are for a human), but they must at least COMPILE, and compiling
# them is what evaluates their `const _: () = assert!(...)` invariants.
# That distinction is the whole point: #6610 was a runtime `attempt to add
# with overflow` in benches/snat_allocator.rs that a compile-only check
# could NOT have caught, so the fix made the invariant it violated a CONST
# assert. A compile check now catches a reintroduction of that class,
# rather than only catching a bench that stopped compiling.
#
# Cheap: cold ~2.5 min (shared with the --release artifacts below only
# partially, since this is a dev-profile check), warm ~0s.
test-rust:
	$(CARGO) check --manifest-path userspace-dp/Cargo.toml --benches
	$(CARGO) test --manifest-path userspace-dp/Cargo.toml --release \
		--bins --tests -- --test-threads=1

# Standalone convenience view of the refactoring-heatmap drift (#1661
# item 8). Regenerates scripts/refactoring-audit.sh output to a temp
# file and diffs it against the committed
# docs/refactoring-audit-current.txt, printing the exact drift and the
# one-line regenerate command.
#
# NOTHING IN `make test` FAILS ON WHAT THIS TARGET REPORTS (#7253). Global
# heatmap staleness stopped being a gate: it is a repo-GLOBAL property, so
# any file crossing 1500 or 2000 LOC anywhere flipped it for every author
# on the board, and #7235, #7252 and #7254 all regenerated it inside one
# hour — #7252 was already stale when it merged. The gate that remains is
# pkg/refactoraudit's TestTouchedFileCrossedModularityThreshold, which reds
# only the author who grew a file THEY TOUCHED past a threshold and is
# derived from that branch's own diff, so it cannot go stale. Converging
# the global artifact is `make audit-refresh`'s job, not a PR author's.
#
# This target's verdict MUST agree with the suite, or the two surfaces
# teach opposite lessons and both get ignored — which is how the artifact
# came to sit stale for 21 consecutive commits (#6617). So it exits 0 on
# every kind of staleness and reserves exit 1 for a MALFORMED artifact,
# which is a real defect the suite does still fail on:
#
#   no diff                       -> up to date, exit 0
#   LOC-only (same files+tiers)   -> ADVISORY refresh, exit 0
#   a file entered/left/retiered  -> STALE, exit 0 (run `make audit-refresh`)
#   malformed rows / dead generator -> ERROR, exit 1 (the suite fails too)
#
# For a machine-readable staleness predicate — a timer deciding whether to
# refresh — use `bash scripts/refactoring-audit-refresh.sh --check`, which
# exits 1 when the artifact is behind. That is a job's question, not a
# developer's.
#
# The full `diff -u` is printed either way, so a refresh is still one
# command away when you want the numbers current.
#
# Recipe notes: Make runs the recipe in one shell without `set -e`, so
# each step's failure is handled explicitly. `trap ... EXIT` guarantees
# the temp files are removed on every exit path. The awk projection
# drops the LOC column ($$2), leaving "tier path" — the canary's
# criterion — and sorts it so row order cannot affect the verdict.
# #6937 struct-heterogeneity drift. Standalone, like audit-check, and for
# the same reason: this is a repo-GLOBAL snapshot, so making it a gate
# would flip it for every author whenever any struct anywhere crossed a
# floor (see pkg/refactoraudit/doc.go on why global freshness stopped
# being a gate). The per-struct signal is reviewable in the artifact diff.
.PHONY: audit-structs
audit-structs:
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
	bash scripts/refactoring-audit-structs.sh > "$$tmp" || { \
		echo "ERROR: scripts/refactoring-audit-structs.sh failed."; exit 1; }; \
	if [ ! -s "$$tmp" ]; then \
		echo "ERROR: generator produced no rows; refusing to report an empty audit."; \
		exit 1; \
	fi; \
	if diff -u docs/refactoring-audit-structs.txt "$$tmp"; then \
		echo "struct audit: up to date ($$(wc -l < "$$tmp") rows)"; \
	else \
		echo ""; \
		echo "struct audit is stale. Regenerate with:"; \
		echo "  bash scripts/refactoring-audit-structs.sh > docs/refactoring-audit-structs.txt"; \
	fi

.PHONY: audit-check
audit-check:
	@tmp=$$(mktemp); com=$$(mktemp); gen=$$(mktemp); \
	trap 'rm -f "$$tmp" "$$com" "$$gen"' EXIT; \
	bash scripts/refactoring-audit.sh > "$$tmp" || { \
		echo "ERROR: scripts/refactoring-audit.sh failed."; \
		exit 1; \
	}; \
	for f in docs/refactoring-audit-current.txt "$$tmp"; do \
		if awk 'NF == 0 { next } \
			NF != 3 { print "  " FILENAME ": want 3 fields, got " NF ": " $$0; bad = 1; next } \
			$$1 != "[REFACTOR]" && $$1 != "[WATCH]" { print "  " FILENAME ": bad tier " $$1 ": " $$0; bad = 1; next } \
			$$2 !~ /^[0-9]+$$/ { print "  " FILENAME ": non-numeric LOC " $$2 ": " $$0; bad = 1 } \
			{ rows++ } \
			END { if (rows == 0) { print "  " FILENAME ": zero rows"; bad = 1 } exit bad }' "$$f"; then :; else \
			echo "ERROR: $$f is malformed."; \
			echo "  Validated BEFORE the diff, and on BOTH the committed artifact and the"; \
			echo "  freshly generated one. Doing it after the diff let an identically"; \
			echo "  malformed pair pass as 'up to date', and checking only the committed"; \
			echo "  side let a broken generator through — while the Go parser rejected"; \
			echo "  each. This target must not report green on input the suite refuses."; \
			exit 1; \
		fi; \
	done; \
	if diff -u docs/refactoring-audit-current.txt "$$tmp"; then \
		echo "audit-check: refactoring-audit-current.txt is up to date"; \
		exit 0; \
	fi; \
	if awk 'NF != 3 { print "  malformed row (want 3 fields, got " NF "): " $$0; bad = 1 } \
		END { exit bad }' docs/refactoring-audit-current.txt; then :; else \
		echo "ERROR: docs/refactoring-audit-current.txt has malformed rows."; \
		echo "  The Go parser requires exactly 3 fields; this target used to project"; \
		echo "  \$$1,\$$3 and silently ignore extra ones, so a hand edit could pass here"; \
		echo "  and fail the test suite."; \
		exit 1; \
	fi; \
	awk '{print $$1, $$3}' docs/refactoring-audit-current.txt | LC_ALL=C sort > "$$com"; \
	awk '{print $$1, $$3}' "$$tmp" | LC_ALL=C sort > "$$gen"; \
	if cmp -s "$$com" "$$gen"; then \
		echo "audit-check: ADVISORY — same files, same tiers; only the LOC snapshot drifted."; \
		echo "  This target compares the (tier, path) projection SORTED, so it is blind to"; \
		echo "  LOC values and to row order BY DESIGN — that is what makes LOC advisory."; \
		echo "  No test fails on this. It is NOT a statement about the whole suite:"; \
		echo "  TestHeatmapArtifactWellFormed still checks each row's LOC against its"; \
		echo "  tier band and checks generator sort order, and can fail while this target is"; \
		echo "  green. Run 'go test ./pkg/refactoraudit/' for the authoritative answer."; \
		echo "  Refresh when convenient:"; \
		echo "    make audit-refresh"; \
		exit 0; \
	fi; \
	echo "audit-check: STALE — a file entered the audit, left it, or changed tier."; \
	echo "  This is NOT a failure and no test reds on it (#7253): the heatmap is a"; \
	echo "  repo-global snapshot that any unrelated file can invalidate, so keeping it"; \
	echo "  current is a job's work, not yours. Converge it with:"; \
	echo "    make audit-refresh"; \
	echo "  If one of the files above is one YOU grew past a threshold, the test that"; \
	echo "  says so is pkg/refactoraudit.TestTouchedFileCrossedModularityThreshold,"; \
	echo "  and regenerating this artifact will not silence it."; \
	exit 0

# Periodic heatmap refresh job (#7253). Regenerates
# docs/refactoring-audit-current.txt and COMMITS it, so global freshness
# converges without interrupting a PR author who did nothing wrong. Run it
# by hand, or wire it as a timer on a master checkout; add --push there
# (the docs-only maintenance carve-out from docs/engineering-style.md
# first principle #6, the same one /sync-history takes). Refuses to commit
# an empty heatmap, and commits only the artifact path even on a dirty
# tree. Self-tested hermetically by pkg/refactoraudit's
# TestRefreshJobConvergesTheGlobalArtifact — no repo state involved.
.PHONY: audit-refresh
audit-refresh:
	bash scripts/refactoring-audit-refresh.sh

# Upgrade/install docs canary (#2001). Fails if either of the two
# misleading upgrade-install doc phrasings reappears: "symlinks into the
# staging path" in the install-layout doc (the live sbin links resolve
# THROUGH versions/current after the #1964 seed, not into staging) or
# the phantom symbol `manifest.Managed` (the managed-binary SSOT is the
# unexported `managed` slice + All()/Names()/LockstepNames()). Standalone
# by design — same posture as audit-check; NOT a dependency of `test`.
.PHONY: docs-check
docs-check:
	bash scripts/docs/check-upgrade-docs.sh

# Single entry point for the day-0/image/dist/deploy self-tests (#4210 H-19).
# Before this, scripts/image/test-grow-root.sh, test_bake_sign_ordering.py,
# scripts/dist/selftest.sh, and scripts/deploy/test_xpf_deploy_*.py all passed
# but were reachable from NO target — a regression re-introducing
# sign-before-validate (#4017) or breaking the grow-root stamp discipline
# (#2047) merged green because nothing ran them. `make selftest` discovers and
# runs them all in one fast (<a few seconds), hermetic pass (no root, no incus,
# no cluster, no network); a leg whose external tool is missing SKIPs rather
# than fails. Standalone by design — same posture as audit-check / docs-check /
# test-deploy-lib (this repo has no CI; every gate is developer-invoked). It is
# the one command to run before touching image/day-0/dist/deploy tooling, and
# the single hook a future CI would call. The incus/QEMU image boot matrix
# (scripts/image/validate.py) and the loss-cluster smokes are NOT included —
# they need a hypervisor and have their own entry points.
.PHONY: selftest
selftest:
	sh scripts/run-selftests.sh

# Bake the distributable appliance image (#1879 Path C): one
# offline-built bootable root disk (REVIEWED-PIN Ubuntu server cloudimg
# base — PINNED_BASE_RELEASE + PINNED_BASE_SHA256 in bake.py, not
# auto-latest; XPF_BASE_RELEASE overrides one run; linux-generic
# kernel >= 6.18, xpfd + cli + xpf-userspace-dp + day-0 config-drive
# loader), exported as a qcow2 for libvirt/KVM AND as an incus VM
# image (metadata tarball + the same qcow2). Includes the in-guest
# verify-dataplane validation gate. See docs/install-images.md.
.PHONY: image
image:
	python3 scripts/image/bake.py

# ── signed, hosted distribution (#1924) ───────────────────────────────────
# Hosting URL + signing key are CONFIG INPUTS, never hardcoded:
#   XPF_SIGN_SECKEY    path to the minisign image secret key (sign step)
#   XPF_GPG_KEY        OpenPGP key id that signs the apt Release
#   XPF_IMAGE_BASE_URL / XPF_APT_BASE_URL   publish destinations
#   XPF_PUBLISH_CMD    backend shim: $CMD <local-dir> <dest-base-url>
.PHONY: dist-sign dist-repo dist-publish dist-selftest

# Sign already-baked dist/ image artifacts (re-emit the per-version manifest
# signature). The bake also signs inline when XPF_SIGN_SECKEY is set; this is
# the standalone re-sign / rotation entry point.
dist-sign:
	@test -n "$(XPF_SIGN_SECKEY)" || { echo "set XPF_SIGN_SECKEY=<minisign seckey path>"; exit 1; }
	@for m in dist/xpf-*.SHA256SUMS; do \
	    [ -f "$$m" ] || { echo "no dist/xpf-*.SHA256SUMS (run 'make image' first)"; exit 1; }; \
	    python3 scripts/dist/sign.py sign-manifest --manifest "$$m" \
	        --seckey "$(XPF_SIGN_SECKEY)" \
	        $$(awk '{print "dist/" $$2}' "$$m"); \
	done

# Build the signed apt repo (flat default; XPF_APT_TOOL=reprepro to opt in).
dist-repo:
	XPF_GPG_KEY="$(XPF_GPG_KEY)" sh scripts/dist/build-apt-repo.sh

# Fail-closed publish: verifies every artifact is signed, then dispatches
# XPF_PUBLISH_CMD once per URL. Refuses to upload anything unsigned.
dist-publish:
	python3 scripts/dist/publish.py --channel $${XPF_CHANNEL:-stable}

# Self-contained roundtrip gate: throwaway key -> sign -> verify ->
# tamper-fails -> flat repo build -> install.sh dry-run. No real key, no host.
dist-selftest:
	sh scripts/dist/selftest.sh

clean:
	rm -f $(BINARY) cli xpf-userspace-dp
	# Narrowed glob (#1476): the retained Rust shim object lives at
	# pkg/dataplane/userspace_xdp_bpfel.o. Cleaning it would break
	# `make build` because userspace_xdp_rust.go uses //go:embed.
	# We restrict to the legacy bpf2go `xpf*` prefix even though
	# every matching file is gone after the #1476 deletion — the
	# pattern stays as defence-in-depth against accidental
	# re-introduction by a future PR.
	rm -f pkg/dataplane/xpf*_bpfel.go pkg/dataplane/xpf*_bpfeb.go
	rm -f pkg/dataplane/xpf*_bpfel.o pkg/dataplane/xpf*_bpfeb.o
	rm -rf userspace-dp/target

# Legacy standalone test environment management (single Incus VM/container).
# The standalone instance name defaults to xpf-fw; override it for an
# ad-hoc/renamed VM with `XPF_INSTANCE=<name> make test-deploy` (#2162). The
# env var flows through to setup.sh (INSTANCE_NAME=${XPF_INSTANCE:-xpf-fw}).
.PHONY: test-env-init test-vm standalone-test-vm test-ct test-deploy test-deploy-lib test-cluster-lock-lib test-cluster-env-lib test-iperf-throughput-lib test-cos-apply-lib test-ssh test-destroy test-status test-start test-stop test-restart test-logs test-journal

test-env-init:
	./test/incus/setup.sh init

test-vm:
	./test/incus/setup.sh create-vm

standalone-test-vm: test-vm

test-ct:
	./test/incus/setup.sh create-ct

test-deploy: build build-ctl
	./test/incus/setup.sh deploy

# Self-test the raw-deploy reconciliation + sha-verify helpers (#2162/#2176)
# against a mocked fake VM. No incus, no cluster, no network — pure bash logic.
test-deploy-lib:
	bash ./test/incus/deploy-lib-selftest.sh

# Self-test the #1875 shared-cluster lock cell (with-cluster.sh contention
# matrix) and the #4020 destructive-smoke lock preamble (every reboot/
# force-stop/failover smoke script routes through the lock, and the cell
# serializes/queues/re-enters correctly). Private lock path, mocked incus —
# no cluster, no network. Run this after touching the lock or smoke wiring.
test-cluster-lock-lib:
	bash ./test/incus/with-cluster-selftest.sh
	bash ./test/incus/cluster-cell-selftest.sh

# Self-test the #6440 CoS-apply CLI-transcript gate. `apply-cos-config.sh`
# drives the Junos CLI by piping a heredoc into it; that form is a REPL that
# prints "error: ..." for a failed command, continues, and still exits 0 — so
# the phase gates verify the CLI's own success markers instead of the session
# exit status. Hermetic: mocked incus, canned transcripts; no cluster, no VM.
# Run this after touching apply-cos-config.sh or cos-apply-lib.sh. The Go half
# of the marker contract lives in cmd/cli/cos_apply_markers_6440_test.go.
test-cos-apply-lib:
	bash ./test/incus/cos-apply-lib-selftest.sh
	go test -count=1 -run 6440 ./cmd/cli/

# Self-test the shared cluster-env resolver (#5024): the HA/failover
# smoke scripts read $FW0/$FW1/$CLUSTER_LAN_HOST, which cluster-env.sh
# derives from each env's VM0/VM1/LAN_HOST and remote-qualifies with
# INCUS_REMOTE (including bare caller overrides). Hermetic — sources
# cluster-env.sh in an `env -i` subshell; no incus, cluster, or network.
# Run this after touching cluster-env.sh or a cluster *.env file.
test-cluster-env-lib:
	bash ./test/incus/cluster-env-selftest.sh

# Self-test the #6897 iperf3 throughput parse + verdict used by
# test-failover.sh. The defect it guards is a MISSING CELL, not a wrong
# number: the old inline parse matched only "Gbits", so a sub-Gbit run
# matched neither the pass nor the fail branch and the gate emitted nothing
# while still summarising "0 failed". Hermetic — sources the lib and feeds it
# literal [SUM] lines; no incus, cluster, network or iperf3.
# Run this after touching test-failover.sh's throughput cell.
test-iperf-throughput-lib:
	bash ./test/incus/iperf-throughput-selftest.sh

# Self-test the #4800 new-flow-ceiling analysis layer: the function that
# turns two helper counter snapshots into "N new flows/sec, and here is
# which synchronization site saturated". Hermetic — synthetic snapshot
# pairs only; no incus, cluster, network or helper. Also builds and unit-
# tests the connection-rate generator, which lives outside the dataplane
# workspaces so `cargo test` at the root does not reach it.
# Run this after touching newflow_ceiling_analyze.py or newflow-gen.
test-newflow-ceiling-lib:
	cd test/incus && python3 -m unittest newflow_ceiling_analyze_test
	cargo test --release --manifest-path test/incus/newflow-gen/Cargo.toml
	bash -n ./test/incus/newflow-ceiling-harness.sh

test-ssh:
	./test/incus/setup.sh ssh

test-destroy:
	./test/incus/setup.sh destroy

test-status:
	./test/incus/setup.sh status

test-start:
	./test/incus/setup.sh start

test-stop:
	./test/incus/setup.sh stop

test-restart:
	./test/incus/setup.sh restart

test-logs:
	./test/incus/setup.sh logs

test-journal:
	./test/incus/setup.sh journal

# Connectivity tests (standalone + cluster, VRF-aware)
MODE ?= all
PRIVATE_RG_MODE ?= $(if $(filter all,$(MODE)),full,$(MODE))
test-connectivity:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-connectivity.sh $(MODE)

# Cluster failover test (iperf3 through reboot — requires cluster + iperf3 server)
test-failover:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-failover.sh

# Double failover test (crash fw0 → fw1 takes over → fw0 rejoins → crash fw1 → fw0 takes over)
test-double-failover:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-double-failover.sh

# Active/active per-RG failover test (iperf3 through RG split — requires cluster + iperf3 server)
test-active-active:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-active-active.sh

# Rapid failover stress test (repeated failover cycles — requires cluster + iperf3 server)
test-stress-failover:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-stress-failover.sh

# Hard-crash / hung-node HA test (force-stop + daemon stop + multi-cycle — requires cluster + iperf3 server)
test-ha-crash:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-ha-crash.sh

# Chained hard-reset failover test (fw0 crash → fw1 crash → both rejoin — requires cluster + iperf3 server)
test-chained-crash:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-chained-crash.sh

# Private RG election test (enable/disable private-rg-election, verify VRRP behavior)
test-private-rg:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-private-rg.sh $(PRIVATE_RG_MODE)

# Restart connectivity regression test (verify no transient loss during daemon restart — requires cluster + iperf3 server)
test-restart-connectivity:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-restart-connectivity.sh

# Canonical cluster HA test environment (isolated loss userspace cluster).
# Override CLUSTER_ENV= to use cluster-setup.sh local xpf-fw0/xpf-fw1 defaults.
NODE ?= all
ifeq ($(origin CLUSTER_ENV),undefined)
ifeq ($(origin BPFRX_CLUSTER_ENV),undefined)
CLUSTER_ENV := test/incus/loss-userspace-cluster.env
else
CLUSTER_ENV := $(BPFRX_CLUSTER_ENV)
endif
endif
LOSS_CLUSTER_ENV ?= test/incus/loss-cluster.env
CLUSTER_SETUP = BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/cluster-setup.sh
LOSS_CLUSTER_SETUP = BPFRX_CLUSTER_ENV=$(LOSS_CLUSTER_ENV) ./test/incus/cluster-setup.sh
.PHONY: cluster-init cluster-create cluster-deploy cluster-destroy cluster-status cluster-ssh cluster-logs cluster-start cluster-stop cluster-restart
.PHONY: userspace-cluster-init userspace-cluster-create userspace-cluster-deploy userspace-cluster-destroy userspace-cluster-status userspace-cluster-ssh userspace-cluster-logs userspace-cluster-start userspace-cluster-stop userspace-cluster-restart

cluster-init:
	$(CLUSTER_SETUP) init

cluster-create:
	$(CLUSTER_SETUP) create

cluster-deploy: build build-ctl
	$(CLUSTER_SETUP) deploy $(NODE)

cluster-destroy:
	$(CLUSTER_SETUP) destroy

cluster-status:
	$(CLUSTER_SETUP) status

cluster-ssh:
	$(CLUSTER_SETUP) ssh $(NODE)

cluster-logs:
	$(CLUSTER_SETUP) logs $(NODE)

cluster-start:
	$(CLUSTER_SETUP) start $(NODE)

cluster-stop:
	$(CLUSTER_SETUP) stop $(NODE)

cluster-restart:
	$(CLUSTER_SETUP) restart $(NODE)

userspace-cluster-init: cluster-init
userspace-cluster-create: cluster-create
userspace-cluster-deploy: cluster-deploy
userspace-cluster-destroy: cluster-destroy
userspace-cluster-status: cluster-status
userspace-cluster-ssh: cluster-ssh
userspace-cluster-logs: cluster-logs
userspace-cluster-start: cluster-start
userspace-cluster-stop: cluster-stop
userspace-cluster-restart: cluster-restart

# Legacy remote "loss" cluster using the older xpf-fw0/xpf-fw1 instance names.
.PHONY: loss-cluster-init loss-cluster-create loss-cluster-deploy loss-cluster-destroy loss-cluster-status loss-cluster-ssh loss-cluster-logs loss-cluster-start loss-cluster-stop loss-cluster-restart

loss-cluster-init:
	$(LOSS_CLUSTER_SETUP) init

loss-cluster-create:
	$(LOSS_CLUSTER_SETUP) create

loss-cluster-deploy: build build-ctl
	$(LOSS_CLUSTER_SETUP) deploy $(NODE)

loss-cluster-destroy:
	$(LOSS_CLUSTER_SETUP) destroy

loss-cluster-status:
	$(LOSS_CLUSTER_SETUP) status

loss-cluster-ssh:
	$(LOSS_CLUSTER_SETUP) ssh $(NODE)

loss-cluster-logs:
	$(LOSS_CLUSTER_SETUP) logs $(NODE)

loss-cluster-start:
	$(LOSS_CLUSTER_SETUP) start $(NODE)

loss-cluster-stop:
	$(LOSS_CLUSTER_SETUP) stop $(NODE)

loss-cluster-restart:
	$(LOSS_CLUSTER_SETUP) restart $(NODE)

# Build the xpf Debian package (#1917 increment A). Produces ../xpf_*.deb
# and ../xpf-appliance_*.deb relative to the source tree (dpkg's default
# parent-dir output), then copies them into dist-deb/ (a staging dir OUTSIDE
# the image publish root dist/ — see DEB_OUT below).
#
# The package build delegates to `make build build-ctl build-userspace-dp`
# (see debian/rules), so it picks up the embedded #1864 shim and the
# pinned cargo helper. The changelog version is rewritten from
# `git describe` here, normalized to a Debian-policy-valid native version
# (dashes -> dots; a `-` is illegal in a native package version).
# Debian native versions MUST start with a digit and exclude `-`. The
# project's git tags are non-numeric (e.g. userspace-forwarding-ok-*),
# so synthesize 0.0.<commit-count>+g<short-sha>[.dirty] — monotonic in
# commit count, carries the exact source sha, and is policy-valid.
DEB_GIT_COUNT ?= $(shell git rev-list --count HEAD 2>/dev/null || echo 0)
DEB_GIT_SHA   ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
DEB_GIT_DIRTY ?= $(shell git diff --quiet 2>/dev/null || echo .dirty)
DEB_VERSION ?= 0.0.$(DEB_GIT_COUNT)+g$(DEB_GIT_SHA)$(DEB_GIT_DIRTY)
# DEB_OUT is a build-STAGING dir and MUST live OUTSIDE the image publish root
# `dist/` (HB165 H-5): `make image` runs `make deb` and `make dist-publish`
# uploads the WHOLE `dist/` tree to the image URL, so a deb staged under
# `dist/` would ship unsigned. publish.py's default-deny sweep now REFUSES any
# stray file under `dist/`, so debs stage in the `dist-deb/` sibling instead.
DEB_OUT ?= $(CURDIR)/dist-deb

.PHONY: deb
deb:
	@echo "==> xpf .deb version: $(DEB_VERSION)"
	@# Run the whole build inside ONE shell with a trap so the changelog
	@# version is ALWAYS restored to the committed 0.0.0 and the parent-dir
	@# build byproducts are ALWAYS removed — even on SIGINT/SIGTERM or a
	@# failed dpkg-buildpackage. (A backup FILE under debian/ would be
	@# deleted by dpkg-buildpackage's own clean phase, so re-sed instead.)
	@# The build version is derived from git at build time, not committed;
	@# only the top changelog line's version token is rewritten so the rest
	@# of the entry/trailer stays dpkg-parseable. dpkg-buildpackage writes
	@# the .deb/.changes/.buildinfo to the PARENT dir (not configurable);
	@# we keep the canonical copies in dist-deb/ and scrub the parent so it
	@# never litters the tree above the source dir (a git worktree parent).
	@# Signal traps re-raise the caught signal after cleanup (trap - SIG;
	@# kill -SIG $$) so an interrupted build returns the SIGNAL exit status,
	@# not 0. A bare `trap cleanup INT TERM` with a cleanup that returns 0
	@# would mask Ctrl-C / CI-kill as success under dash (AGY r2). The EXIT
	@# trap covers normal completion + dpkg-buildpackage failure (set -e).
	set -e; \
	  cleanup() { \
	    sed -i "1s/^xpf ([^)]*)/xpf (0.0.0)/" debian/changelog; \
	    rm -f ../xpf_$(DEB_VERSION)_*.deb ../xpf-appliance_$(DEB_VERSION)_*.deb \
	          ../xpf_$(DEB_VERSION)_*.changes ../xpf_$(DEB_VERSION)_*.buildinfo; \
	  }; \
	  trap cleanup EXIT; \
	  trap 'cleanup; trap - INT; kill -INT $$$$' INT; \
	  trap 'cleanup; trap - TERM; kill -TERM $$$$' TERM; \
	  sed -i "1s/^xpf ([^)]*)/xpf ($(DEB_VERSION))/" debian/changelog; \
	  dpkg-buildpackage -us -uc -b --no-sign; \
	  mkdir -p $(DEB_OUT); \
	  cp ../xpf_$(DEB_VERSION)_*.deb ../xpf-appliance_$(DEB_VERSION)_*.deb $(DEB_OUT)/
	@echo "==> packages in $(DEB_OUT):"
	@ls -1 $(DEB_OUT)/*.deb
