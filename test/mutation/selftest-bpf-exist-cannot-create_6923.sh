#!/bin/sh
# #6923: demonstrate that BPF_EXIST cannot CREATE a map entry.
#
# WHY THIS EXISTS AS A TEST RATHER THAN A CITATION. The #6923 chokepoint
# argument is that `publish_v6_session` is the ONLY path by which a v6 session
# key becomes visible to the shim, because the other two writers cannot mint a
# key: `delete_bpf_conntrack_entry` deletes, and `refresh_bpf_conntrack_last_seen`
# updates with BPF_EXIST.
#
# "The flag is named EXIST" and "the kernel refuses creation under this flag"
# are DIFFERENT CLAIMS, and only the second is the one the argument needs. This
# asks the kernel.
#
# The BPF_ANY leg is the positive control and it is what makes this a
# measurement rather than a null result: without it, an ENOENT from the
# BPF_EXIST leg is equally consistent with "the flag refuses creation" and "my
# fixture is broken and nothing would have worked". The third leg (BPF_EXIST on
# a key that now EXISTS) closes the remaining reading — that BPF_EXIST simply
# always fails.
#
# SKIPs (77) rather than passing when it cannot run. Creating a BPF map needs
# CAP_BPF, and on a host with kernel.unprivileged_bpf_disabled=2 an unprivileged
# BPF_MAP_CREATE returns EPERM. A test that silently passes when it could not
# run is worse than one that reports SKIP.
set -e
cd "$(dirname "$0")"

command -v cc >/dev/null 2>&1 || { echo "SKIP: no C compiler"; exit 77; }
sudo -n true >/dev/null 2>&1 || { echo "SKIP: no passwordless sudo (BPF_MAP_CREATE needs CAP_BPF)"; exit 77; }

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT INT TERM

cat >"${tmp}/probe.c" <<'EOF'
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

static int upd(int fd, unsigned *k, unsigned *v, unsigned long long flags) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_fd = fd;
    a.key = (unsigned long)k;
    a.value = (unsigned long)v;
    a.flags = flags;
    return syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &a, sizeof(a));
}

int main(void) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_type = BPF_MAP_TYPE_HASH;
    a.key_size = 4; a.value_size = 4; a.max_entries = 8;
    int fd = syscall(SYS_bpf, BPF_MAP_CREATE, &a, sizeof(a));
    if (fd < 0) { printf("SKIP_CREATE %s\n", strerror(errno)); return 77; }

    unsigned k = 1, v = 7;

    /* 1. BPF_EXIST on an ABSENT key MUST fail with ENOENT. */
    if (upd(fd, &k, &v, BPF_EXIST) == 0) {
        printf("FAIL BPF_EXIST created an absent key\n"); return 1;
    }
    if (errno != ENOENT) {
        printf("FAIL BPF_EXIST failed with %s, expected ENOENT\n", strerror(errno)); return 1;
    }

    /* 2. POSITIVE CONTROL: BPF_ANY on the SAME absent key must succeed, or the
     *    ENOENT above proves nothing about the flag. */
    if (upd(fd, &k, &v, BPF_ANY) != 0) {
        printf("FAIL control: BPF_ANY could not create (%s) — fixture broken\n", strerror(errno));
        return 1;
    }

    /* 3. SECOND CONTROL: BPF_EXIST on the key that now EXISTS must succeed, so
     *    the ENOENT was about ABSENCE and not about BPF_EXIST always failing. */
    if (upd(fd, &k, &v, BPF_EXIST) != 0) {
        printf("FAIL control: BPF_EXIST on a present key failed (%s)\n", strerror(errno));
        return 1;
    }

    printf("OK BPF_EXIST refuses creation (ENOENT); BPF_ANY creates; BPF_EXIST updates\n");
    return 0;
}
EOF

cc -O1 -Wall -Wextra -o "${tmp}/probe" "${tmp}/probe.c" 2>"${tmp}/cc.err" || {
    echo "SKIP: probe did not compile (missing linux/bpf.h?)"; sed 's/^/  /' "${tmp}/cc.err"; exit 77; }

out="$(sudo -n "${tmp}/probe" 2>&1)" && rc=0 || rc=$?
case "${out}" in
  SKIP_CREATE*) echo "SKIP: BPF_MAP_CREATE refused (${out#SKIP_CREATE })"; exit 77 ;;
esac
if [ "${rc}" -ne 0 ]; then
    echo "FAIL: ${out}"
    exit 1
fi
echo "PASS: ${out}"
exit 0
