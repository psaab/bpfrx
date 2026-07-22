# Build + strict-warning gate for the AF_XDP reproducers (#4906).
#
# The C reproducers embed the XDP object (xdp_pass_redirect.o) directly via a
# generated header and load it with bpf_object__open_mem() instead of reading a
# predictable /tmp path (#4906 HC-025). Strict warnings are the compile-time
# fail-on-revert gate for the uninitialized-counter false PASS (#4906 HC-081):
# -Werror -Wjump-misses-init turns "goto cleanup" over an rx1/rx2 declaration
# back into a hard build error.
#
# Requires: cc, libbpf-dev, libxdp-dev, libelf, zlib(, zstd), and xxd.
# The Rust reproducer (main.rs) is built separately with `cargo build` — it
# embeds the same object with include_bytes! and needs no generated header.

CC      ?= cc
CLANG   ?= clang
ARCH    := $(shell uname -m)
CFLAGS  ?= -O2 -g
WARNFLAGS := -Wall -Wextra -Werror -Wjump-misses-init
LIBS_XSK    := -lbpf -lxdp -lelf -lz
LIBS_SHARED := -Wl,-Bstatic -lxdp -lbpf -lelf -lz -lzstd -Wl,-Bdynamic -lpthread

C_TOOLS := libbpf-xsk-test libbpf-xsk-shared-test
GEN_HDR := xdp_pass_redirect_obj.h

# Disable built-in implicit rules (notably %.o:%.c). Without this, make would
# "rebuild" the tracked BPF object xdp_pass_redirect.o from xdp_pass_redirect.c
# with a NATIVE cc -c whenever the .c is newer — clobbering the eBPF object with
# an x86-64 one. The BPF object is a tracked input here; rebuild it only via the
# explicit `regen-obj` target.
.SUFFIXES:
MAKEFLAGS += --no-builtin-rules

.PHONY: all check clean regen-obj
all: $(C_TOOLS)

# The tracked BPF object is an input, not something the default build rebuilds.
# The empty recipe stops any implicit rule from firing on it.
xdp_pass_redirect.o: ;

# Embed the tracked XDP object as a C array so the tools never touch a
# world-writable /tmp path.
$(GEN_HDR): xdp_pass_redirect.o
	xxd -i $< > $@

libbpf-xsk-test: libbpf_xsk_test.c $(GEN_HDR)
	$(CC) $(CFLAGS) $(WARNFLAGS) -o $@ $< $(LIBS_XSK)

libbpf-xsk-shared-test: libbpf_xsk_shared_test.c $(GEN_HDR)
	$(CC) $(CFLAGS) $(WARNFLAGS) -o $@ $< $(LIBS_SHARED)

# Fail-on-revert gate: a strict-warning build. Reverting the #4906 HC-081 fix
# (rx1/rx2 declared past the gotos) makes this fail with -Werror=jump-misses-init
# / -Werror=maybe-uninitialized.
check: all
	@echo "xsk-repro: strict-warning build OK"

# Rebuild the tracked XDP object from source with the current toolchain. Refresh
# it when a newer elfutils/libbpf rejects the committed object (the arch include
# dir supplies <asm/types.h>). Both the C tools (via the embedded header) and the
# Rust tool (include_bytes!) then pick up the fresh object.
regen-obj:
	$(CLANG) -O2 -g -target bpf -I/usr/include/$(ARCH)-linux-gnu \
		-c xdp_pass_redirect.c -o xdp_pass_redirect.o

clean:
	rm -f $(C_TOOLS) $(GEN_HDR)
