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
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf

.PHONY: all generate build build-ctl build-userspace-dp proto install clean test test-connectivity test-failover test-double-failover test-active-active test-stress-failover test-ha-crash test-chained-crash test-private-rg build-dpdk-worker build-dpdk clean-dpdk

all: generate build build-ctl

# Generate Go bindings from eBPF C programs via bpf2go
generate:
	$(GO) generate ./pkg/dataplane/...

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
	$(GO) test ./...

clean: clean-dpdk
	rm -f $(BINARY) cli xpf-userspace-dp
	rm -f pkg/dataplane/*_bpfel.go pkg/dataplane/*_bpfeb.go
	rm -f pkg/dataplane/*_bpfel.o pkg/dataplane/*_bpfeb.o
	rm -rf userspace-dp/target

# Test environment management (Incus VM/container)
.PHONY: test-env-init test-vm test-ct test-deploy test-ssh test-destroy test-status test-start test-stop test-restart test-logs test-journal

test-env-init:
	./test/incus/setup.sh init

test-vm:
	./test/incus/setup.sh create-vm

test-ct:
	./test/incus/setup.sh create-ct

test-deploy: build build-ctl
	./test/incus/setup.sh deploy

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
test-connectivity:
	./test/incus/test-connectivity.sh $(MODE)

# Cluster failover test (iperf3 through reboot — requires cluster + iperf3 server)
test-failover:
	./test/incus/test-failover.sh

# Double failover test (crash fw0 → fw1 takes over → fw0 rejoins → crash fw1 → fw0 takes over)
test-double-failover:
	./test/incus/test-double-failover.sh

# Active/active per-RG failover test (iperf3 through RG split — requires cluster + iperf3 server)
test-active-active:
	./test/incus/test-active-active.sh

# Rapid failover stress test (repeated failover cycles — requires cluster + iperf3 server)
test-stress-failover:
	./test/incus/test-stress-failover.sh

# Hard-crash / hung-node HA test (force-stop + daemon stop + multi-cycle — requires cluster + iperf3 server)
test-ha-crash:
	./test/incus/test-ha-crash.sh

# Chained hard-reset failover test (fw0 crash → fw1 crash → both rejoin — requires cluster + iperf3 server)
test-chained-crash:
	./test/incus/test-chained-crash.sh

# Private RG election test (enable/disable private-rg-election, verify VRRP behavior)
test-private-rg:
	./test/incus/test-private-rg.sh $(MODE)

# Restart connectivity regression test (verify no transient loss during daemon restart — requires cluster + iperf3 server)
test-restart-connectivity:
	./test/incus/test-restart-connectivity.sh

# Cluster HA test environment (two-VM chassis cluster)
NODE ?= all
.PHONY: cluster-init cluster-create cluster-deploy cluster-destroy cluster-status cluster-ssh cluster-logs cluster-start cluster-stop cluster-restart

cluster-init:
	./test/incus/cluster-setup.sh init

cluster-create:
	./test/incus/cluster-setup.sh create

cluster-deploy: build build-ctl
	./test/incus/cluster-setup.sh deploy $(NODE)

cluster-destroy:
	./test/incus/cluster-setup.sh destroy

cluster-status:
	./test/incus/cluster-setup.sh status

cluster-ssh:
	./test/incus/cluster-setup.sh ssh $(NODE)

cluster-logs:
	./test/incus/cluster-setup.sh logs $(NODE)

cluster-start:
	./test/incus/cluster-setup.sh start $(NODE)

cluster-stop:
	./test/incus/cluster-setup.sh stop $(NODE)

cluster-restart:
	./test/incus/cluster-setup.sh restart $(NODE)

# Remote cluster on "loss" host (Mellanox SR-IOV VFs)
.PHONY: loss-cluster-init loss-cluster-create loss-cluster-deploy loss-cluster-destroy loss-cluster-status loss-cluster-ssh loss-cluster-logs loss-cluster-start loss-cluster-stop loss-cluster-restart

loss-cluster-init:
	BPFRX_CLUSTER_ENV=test/incus/loss-cluster.env ./test/incus/cluster-setup.sh init

loss-cluster-create:
	BPFRX_CLUSTER_ENV=test/incus/loss-cluster.env ./test/incus/cluster-setup.sh create

loss-cluster-deploy: build build-ctl
	BPFRX_CLUSTER_ENV=test/incus/loss-cluster.env ./test/incus/cluster-setup.sh deploy $(NODE)

loss-cluster-destroy:
	BPFRX_CLUSTER_ENV=test/incus/loss-cluster.env ./test/incus/cluster-setup.sh destroy

loss-cluster-status:
	BPFRX_CLUSTER_ENV=test/incus/loss-cluster.env ./test/incus/cluster-setup.sh status

loss-cluster-ssh:
	BPFRX_CLUSTER_ENV=test/incus/loss-cluster.env ./test/incus/cluster-setup.sh ssh $(NODE)

loss-cluster-logs:
	BPFRX_CLUSTER_ENV=test/incus/loss-cluster.env ./test/incus/cluster-setup.sh logs $(NODE)

loss-cluster-start:
	BPFRX_CLUSTER_ENV=test/incus/loss-cluster.env ./test/incus/cluster-setup.sh start $(NODE)

loss-cluster-stop:
	BPFRX_CLUSTER_ENV=test/incus/loss-cluster.env ./test/incus/cluster-setup.sh stop $(NODE)

loss-cluster-restart:
	BPFRX_CLUSTER_ENV=test/incus/loss-cluster.env ./test/incus/cluster-setup.sh restart $(NODE)

# --- DPDK targets (require dpdk-dev, meson, ninja) ---

build-dpdk-worker:
	@echo "==> Building DPDK worker..."
	cd dpdk_worker && meson setup build --buildtype=release 2>/dev/null || true
	cd dpdk_worker && meson compile -C build

build-dpdk: build-dpdk-worker
	@echo "==> Building xpfd with DPDK support..."
	CGO_ENABLED=1 go build -tags dpdk -ldflags "$(LDFLAGS)" -o xpfd ./cmd/xpfd

clean-dpdk:
	rm -rf dpdk_worker/build
