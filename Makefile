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
.PHONY: all generate generate-userspace-xdp build-userspace-xdp build build-ctl build-userspace-dp build-userspace-dp-debug-log proto install clean test audit-check test-connectivity test-failover test-double-failover test-active-active test-stress-failover test-ha-crash test-chained-crash test-private-rg test-restart-connectivity

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

test:
	# go vet gate scoped to pkg/flowexport (#2224): catches the
	# atomic.Uint64-copy regression class (ExportConfig embeds the live
	# 1-in-N sampleCounter and must never be copied by value). NOT
	# tree-wide yet — two pre-existing vet diagnostics live outside this
	# package (cmd/cli protobuf MessageState copy, pkg/cli unreachable
	# code); widen to ./... once those are resolved.
	$(GO) vet ./pkg/flowexport/...
	$(GO) test ./...

# Drift guard for the committed refactoring heatmap (#1661 item 8).
# Regenerates scripts/refactoring-audit.sh output to a temp file and
# diffs it against the committed docs/refactoring-audit-current.txt.
# Fails if they differ OR if the generator itself fails. Standalone by
# design — deliberately NOT a dependency of `test`/`all`, so a PR that
# legitimately grows a large file is not blocked until someone
# regenerates the artifact (run this target, then commit the result).
#
# Recipe notes: Make runs the recipe in one shell without `set -e`, so
# the generator is `&&`-chained to `diff` to make a generator failure
# (not just a diff mismatch) take the error path. `trap ... EXIT`
# guarantees the temp file is removed on every exit path.
.PHONY: audit-check
audit-check:
	@tmp=$$(mktemp); \
	trap 'rm -f "$$tmp"' EXIT; \
	bash scripts/refactoring-audit.sh > "$$tmp" && \
	diff -u docs/refactoring-audit-current.txt "$$tmp" || { \
		echo "ERROR: docs/refactoring-audit-current.txt is stale or the audit script failed."; \
		echo "Run: bash scripts/refactoring-audit.sh > docs/refactoring-audit-current.txt"; \
		exit 1; \
	}; \
	echo "audit-check: refactoring-audit-current.txt is up to date"

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

# Bake the distributable appliance image (#1879 Path C): one
# offline-built bootable root disk (LATEST Ubuntu server cloudimg base
# discovered at bake time — XPF_BASE_RELEASE pins; linux-generic
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
.PHONY: test-env-init test-vm standalone-test-vm test-ct test-deploy test-deploy-lib test-ssh test-destroy test-status test-start test-stop test-restart test-logs test-journal

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
# parent-dir output), then copies them into dist/deb/.
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
DEB_OUT ?= $(CURDIR)/dist/deb

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
	@# we keep the canonical copies in dist/deb/ and scrub the parent so it
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
