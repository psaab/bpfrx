#!/bin/sh
# selftest-rule-dscp_7796.sh — run the #7796 FBF DSCP ip-rule APPLY LEG.
#
# Why this leg exists at all: the #7796 defect was invisible to every
# compile-side test. The pre-fix code built a well-formed netlink.Rule and all
# build-side assertions passed; the failure was entirely in what the KERNEL
# accepted (FRA_TOS is masked to IPTOS_TOS_MASK, so a DSCP shifted into a TOS
# byte was rejected with EINVAL from dscp 8 up, failing the whole commit). The
# only instrument that can see that is one that talks to a real kernel.
#
# Why it is not simply part of `make test-go`: the cells need CAP_NET_ADMIN to
# create a private netns, so under a plain `go test` they SKIP — and a skipped
# cell is indistinguishable from a passing one in aggregate output. That is the
# exact shape that lets an apply-leg regression sit green forever. This leg runs
# them under `unshare -rn` where they actually execute.
#
# Exit codes follow the selftest contract: 0 = PASS, 77 = SKIP (a tool or
# capability this host does not have), anything else = FAIL.

set -u

GO=${GO:-go}

if ! command -v "$GO" >/dev/null 2>&1; then
	echo "SKIP: $GO not installed — cannot run the apply leg"
	exit 77
fi

if ! command -v unshare >/dev/null 2>&1; then
	echo "SKIP: unshare not found — cannot self-isolate a private netns"
	exit 77
fi

# Probe the capability rather than assuming it: unprivileged user namespaces are
# disabled on some hosts, and running as a non-root user without them cannot
# create a netns. A probe that cannot distinguish "denied" from "works" would
# make this leg report PASS while running nothing.
if ! unshare -rn true 2>/dev/null; then
	echo "SKIP: cannot create a private netns (needs unprivileged userns or root)"
	exit 77
fi

# -count=1 so a cached PASS can never stand in for a run that did not happen.
unshare -rn "$GO" test -count=1 -run 7796 ./pkg/routing/
