CLANG ?= clang
GO ?= go
BINARY := bpfrxd
PREFIX ?= /usr/local

# Version info embedded at build time
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)

# eBPF compilation flags
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf

.PHONY: all generate build build-ctl proto install clean test build-dpdk-worker build-dpdk clean-dpdk

all: generate build build-ctl

# Generate Go bindings from eBPF C programs via bpf2go
generate:
	$(GO) generate ./pkg/dataplane/...

# Build the daemon binary
build:
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/bpfrxd

# Build the remote CLI client
build-ctl:
	CGO_ENABLED=0 $(GO) build -o cli ./cmd/cli

# Generate protobuf/gRPC code
proto:
	protoc --proto_path=proto/bpfrx/v1 \
		--go_out=pkg/grpcapi/bpfrxv1 --go_opt=paths=source_relative \
		--go-grpc_out=pkg/grpcapi/bpfrxv1 --go-grpc_opt=paths=source_relative \
		proto/bpfrx/v1/bpfrx.proto

install: build build-ctl
	install -m 0755 $(BINARY) $(PREFIX)/sbin/$(BINARY)
	install -m 0755 cli $(PREFIX)/bin/cli

test:
	$(GO) test ./...

clean: clean-dpdk
	rm -f $(BINARY) cli
	rm -f pkg/dataplane/*_bpfel.go pkg/dataplane/*_bpfeb.go
	rm -f pkg/dataplane/*_bpfel.o pkg/dataplane/*_bpfeb.o

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

# --- DPDK targets (require dpdk-dev, meson, ninja) ---

build-dpdk-worker:
	@echo "==> Building DPDK worker..."
	cd dpdk_worker && meson setup build --buildtype=release 2>/dev/null || true
	cd dpdk_worker && meson compile -C build

build-dpdk: build-dpdk-worker
	@echo "==> Building bpfrxd with DPDK support..."
	CGO_ENABLED=1 go build -tags dpdk -ldflags "$(LDFLAGS)" -o bpfrxd ./cmd/bpfrxd

clean-dpdk:
	rm -rf dpdk_worker/build
