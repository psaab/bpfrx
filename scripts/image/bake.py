#!/usr/bin/env python3
"""xpf appliance image bake (#1879 Path C — vSRX-style prebuilt image), in Python.

Builds ONE bootable root-disk image OFFLINE (libguestfs — never boots the
image to provision it) and exports it for both hypervisors:

  dist/xpf-<ver>.qcow2                  - libvirt/KVM (virt-install)
  dist/xpf-<ver>.incus-metadata.tar.gz  - incus VM image metadata
  dist/SHA256SUMS

Pipeline: build the xpf .deb (`make deb`; no `make generate` — embeds the
#1864 tracked shim) -> discover + SHA256-verify the latest Ubuntu cloud
image (XPF_BASE_RELEASE pins) -> virt-resize root into a work disk ->
virt-customize (runtime packages, linux-generic >= 6.18 with the full
driver set, purge cloud-init/snapd/stale kernels, networkd,
init_on_alloc=0, `apt-get install ./xpf.deb` which stages the binaries +
creates the /usr/local/sbin symlinks + enables the units via its postinst)
-> virt-sysprep seal -> virt-sparsify+compress export -> checksums +
manifest -> in-guest verify-dataplane validation gate (validate.py).

Requirements: make/go/cargo, libguestfs-tools, qemu-utils, curl; incus for
the validation gate. /dev/kvm makes libguestfs fast.

Usage:
  bake.py [--version V] [--out DIR] [--skip-build] [--skip-validate] [--keep-work]
"""

import argparse
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

RUNTIME_PACKAGES = [
    "frr", "strongswan", "strongswan-swanctl",
    "kea-dhcp4-server", "kea-dhcp6-server", "chrony",
    "iproute2", "nftables", "ethtool", "tcpdump", "pciutils",
    "iputils-ping", "traceroute", "openssh-server", "openssh-client",
    "systemd-resolved", "rsyslog", "curl", "ca-certificates",
]

SYSCTL_CONF = (
    "net.core.bpf_jit_enable=1\n"
    "net.ipv4.ip_forward=1\n"
    "net.ipv6.conf.all.forwarding=1\n"
    "net.ipv6.conf.all.accept_ra=0\n"
    "net.ipv6.conf.default.accept_ra=0\n"
)

# apt-get update exits 0 even when an index fetch fails; --error-on=any
# makes that fatal, one retry covers a transient blip.
APT_UPDATE = ("apt-get update -qq -o Acquire::Retries=5 --error-on=any || "
              "{ echo 'apt update failed; retrying in 10s' >&2; sleep 10; "
              "apt-get update -qq -o Acquire::Retries=5 --error-on=any; }")

GRUB_DROPIN = (
    '# xpf (#1879): init_on_alloc=0 — CONFIG_INIT_ON_ALLOC_DEFAULT_ON zeroes\n'
    '# every allocated page (~20% CPU in the virtio-net XDP path). A grub.d\n'
    '# drop-in, NOT a sed on /etc/default/grub: Ubuntu cloud images override\n'
    '# GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub.d/50-cloudimg-settings.cfg.\n'
    'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT init_on_alloc=0"'
)

SSHD_DROPIN = (
    '# xpf factory posture (#1879): root password is EMPTY (console-only\n'
    '# login, vSRX parity). Pin the OpenSSH defaults explicitly.\n'
    'PermitRootLogin prohibit-password\n'
    'PermitEmptyPasswords no'
)


def info(m):
    print(f"==> {m}")


def die(m):
    sys.exit(f"ERROR: {m}")


def require(tool, hint):
    if not shutil.which(tool):
        die(f"{tool} not found — {hint}")


def run(argv, **kw):
    return subprocess.run(argv, check=True, **kw)


def out_text(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def git_version():
    try:
        return out_text(["git", "-C", ROOT, "describe", "--tags", "--always", "--dirty"]).strip()
    except Exception:
        return "dev"


def ensure_memlock():
    """qemu io_uring needs locked memory beyond the 8 MiB default."""
    soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    if hard == resource.RLIM_INFINITY or hard >= 1048576 * 1024:
        return
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
        # The shell original died if this failed; preserve that — a silent
        # drop just relocates the failure into libguestfs/qemu later.
        if subprocess.run(["sudo", "-n", "prlimit", "--memlock=unlimited:unlimited",
                           "--pid", str(os.getpid())]).returncode != 0:
            die("could not raise RLIMIT_MEMLOCK (libguestfs/qemu io_uring needs it)")
    else:
        die("RLIMIT_MEMLOCK too low for libguestfs/qemu io_uring — raise it "
            "(sudo prlimit --memlock=unlimited:unlimited --pid $$) and re-run")


def discover_base_release():
    if os.environ.get("XPF_BASE_RELEASE"):
        return os.environ["XPF_BASE_RELEASE"]
    url = os.environ.get("XPF_UBUNTU_RELEASES_URL",
                         "https://cloud-images.ubuntu.com/releases")
    import re
    html = out_text(["curl", "-fsSL", url + "/"])
    rels = sorted(set(re.findall(r'href="(\d{2}\.\d{2})/"', html)),
                  key=lambda v: tuple(int(x) for x in v.split(".")))
    if not rels:
        die(f"could not discover the latest Ubuntu release from {url}/ "
            "(set XPF_BASE_RELEASE to pin one)")
    return rels[-1]


def sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_base(cache_dir, work_dir):
    releases_url = os.environ.get("XPF_UBUNTU_RELEASES_URL",
                                  "https://cloud-images.ubuntu.com/releases")
    rel = discover_base_release()
    base_url = os.environ.get("XPF_BASE_URL", f"{releases_url}/{rel}/release")
    img = f"ubuntu-{rel}-server-cloudimg-amd64.img"
    info(f"fetching Ubuntu {rel} server cloud image base ({base_url})")
    cached = os.path.join(cache_dir, img)
    if not os.path.isfile(cached):
        run(["curl", "-fsSL", "-o", cached + ".tmp", f"{base_url}/{img}"])
        os.replace(cached + ".tmp", cached)
    # Re-verify the cache against the upstream checksum (cache not trusted).
    sums = os.path.join(work_dir, "SHA256SUMS.upstream")
    run(["curl", "-fsSL", "-o", sums, f"{base_url}/SHA256SUMS"])
    expected = None
    with open(sums) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("*") == img:
                expected = parts[0]
                break
    if not expected:
        die(f"no SHA256 for {img} in upstream SHA256SUMS")
    actual = sha256(cached)
    if expected != actual:
        os.remove(cached)
        die("base image SHA256 mismatch (cache removed — re-run)")
    info("base image checksum verified.")
    return rel, base_url, img, cached, actual


def virt_customize(work_qcow, xpf_deb):
    pkgs = " ".join(RUNTIME_PACKAGES)
    deb_name = os.path.basename(xpf_deb)
    argv = [
        "virt-customize", "-a", work_qcow, "--smp", "4", "--memsize", "2048",
        "--hostname", "xpf",
        # #1917 increment A: install xpf via the .deb instead of copying raw
        # binaries. The package stages the binary set under
        # /usr/local/share/xpf/staged, creates the live /usr/local/sbin
        # symlinks, and enables xpfd + xpf-day0-config in its postinst — so
        # the bake no longer hand-copies binaries/units or runs `systemctl
        # enable xpfd`. The git-tracked, kernel-verified shim travels
        # embedded inside the staged xpfd binary (#1864 contract preserved).
        "--copy-in", f"{xpf_deb}:/var/tmp",
        "--copy-in", f"{HERE}/incus-agent.service:/usr/lib/systemd/system",
        "--copy-in", f"{HERE}/incus-agent-setup:/usr/lib/systemd",
        "--copy-in", f"{HERE}/99-incus-agent.rules:/usr/lib/udev/rules.d",
        "--run-command", "chmod 0755 /usr/lib/systemd/incus-agent-setup",
        "--write", f"/etc/sysctl.d/99-xpf.conf:{SYSCTL_CONF}",
        "--run-command", "mkdir -p /etc/xpf && chmod 0750 /etc/xpf",
        "--run-command", f"export DEBIAN_FRONTEND=noninteractive && {APT_UPDATE}",
        "--run-command", f"export DEBIAN_FRONTEND=noninteractive && "
                         f"apt-get install -y -qq -o Acquire::Retries=5 {pkgs}",
        "--run-command", "export DEBIAN_FRONTEND=noninteractive && "
                         "apt-get install -y -qq -o Acquire::Retries=5 linux-generic",
        "--run-command",
        'latest=$(ls /lib/modules | sort -V | tail -1) && case "$latest" in [0-9]*) ;; '
        '*) echo "FATAL: non-kernel entry $latest in /lib/modules" >&2; exit 1 ;; esac && '
        'dpkg --compare-versions "${latest%%-*}" ge 6.18 || '
        '{ echo "FATAL: newest installed kernel $latest < 6.18 (verifier floor)" >&2; exit 1; }',
        "--run-command",
        'test -d "/lib/modules/$(ls /lib/modules | sort -V | tail -1)/kernel/drivers/net/ethernet/mellanox" || '
        '{ echo "FATAL: linux-modules-extra missing (mlx5/i40e)" >&2; exit 1; }',
        "--run-command", "export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq "
                         "linux-virtual linux-image-virtual linux-headers-virtual 2>/dev/null || true",
        # Ship EXACTLY ONE kernel. Ubuntu 26.04's cloudimg already runs a
        # -generic kernel, so `apt install linux-generic` pulls a NEWER
        # point release (e.g. 7.0.0-22 over the stock 7.0.0-15) and leaves
        # the original — across packages a narrow name regex misses
        # (linux-main-modules-zfs-<ver>, linux-headers-<ver>, …) AND
        # depmod-generated files dpkg doesn't own. So for every non-newest
        # version: purge ALL its packages via an apt glob, then rm -rf the
        # leftover module dir + its /boot files. update-grub (below)
        # regenerates the menu. Then HARD-ASSERT one kernel remains — the
        # bake must catch this itself, not only the boot validation
        # (this assert caught a real 2-kernel image during #1879 live bake).
        "--run-command",
        'export DEBIAN_FRONTEND=noninteractive; newest=$(ls /lib/modules | sort -V | tail -1); '
        'for v in $(ls /lib/modules | grep -vxF "$newest"); do '
        'apt-get purge -y -qq "linux-*$v*" 2>/dev/null || true; '
        'rm -rf "/lib/modules/$v" /boot/*"$v"*; done; '
        'apt-get autoremove --purge -y -qq 2>/dev/null || true; true',
        "--run-command",
        'n=$(ls /lib/modules | wc -l); [ "$n" -eq 1 ] || '
        '{ echo "FATAL: $n kernels in /lib/modules after purge ($(ls /lib/modules | tr "\\n" " "))" >&2; exit 1; }',
        "--run-command", "export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq snapd "
                         "2>/dev/null || true; rm -rf /snap /var/snap /var/lib/snapd /var/cache/snapd",
        "--run-command", 'export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq "cloud-init*" '
                         "2>/dev/null || true; rm -rf /etc/cloud /var/lib/cloud",
        "--run-command", "rm -f /etc/network/interfaces.d/* /etc/netplan/*.yaml 2>/dev/null || true",
        "--run-command", f"export DEBIAN_FRONTEND=noninteractive && apt-get autoremove -y -qq && "
                         f"{{ {APT_UPDATE}; }}",
        "--run-command", "systemctl enable systemd-networkd systemd-resolved",
        "--run-command", "systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true",
        "--run-command", "ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf",
        "--run-command", "systemctl enable frr chrony",
        "--run-command", 'sed -i "s/^pool /#pool /; s/^server /#server /" /etc/chrony/chrony.conf '
                         "&& mkdir -p /etc/chrony/sources.d",
        # Install the xpf .deb. apt resolves the package's deps (adduser,
        # present) from the local file. The postinst stages the binaries,
        # creates the /usr/local/sbin symlinks, and enables xpfd +
        # xpf-day0-config — so there is no separate `systemctl enable xpfd`
        # here. systemd is not running under virt-customize, so the
        # postinst's deb-systemd-invoke start is a harmless no-op (the units
        # are enabled and start on the real first boot). The xpfd version
        # check below confirms the symlink resolves the staged binary.
        "--run-command", "export DEBIAN_FRONTEND=noninteractive && "
                         f"apt-get install -y -qq -o Acquire::Retries=5 /var/tmp/{deb_name} && "
                         f"rm -f /var/tmp/{deb_name}",
        "--write", f"/etc/default/grub.d/99-xpf.cfg:{GRUB_DROPIN}",
        "--run-command", "update-grub",
        "--write", f"/etc/ssh/sshd_config.d/10-xpf-factory.conf:{SSHD_DROPIN}",
        "--run-command", "passwd -d root",
        "--run-command", "/usr/local/sbin/xpfd version",
    ]
    run(argv)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", default=git_version())
    p.add_argument("--out", default=os.path.join(ROOT, "dist"))
    p.add_argument("--skip-build", action="store_true")
    p.add_argument("--skip-validate", action="store_true")
    p.add_argument("--keep-work", action="store_true")
    a = p.parse_args()

    for t, hint in [("qemu-img", "apt-get install qemu-utils"),
                    ("virt-customize", "apt-get install libguestfs-tools"),
                    ("virt-resize", "apt-get install libguestfs-tools"),
                    ("virt-sysprep", "apt-get install libguestfs-tools"),
                    ("virt-sparsify", "apt-get install libguestfs-tools"),
                    ("virt-filesystems", "apt-get install libguestfs-tools"),
                    ("curl", "apt-get install curl")]:
        require(t, hint)
    if not (os.access("/dev/kvm", os.R_OK) and os.access("/dev/kvm", os.W_OK)):
        print("WARNING: no /dev/kvm access — libguestfs will use TCG (slow).", file=sys.stderr)
    ensure_memlock()

    cache_dir = os.path.join(os.environ.get("XDG_CACHE_HOME",
                             os.path.expanduser("~/.cache")), "xpf-image-bake")
    os.makedirs(a.out, exist_ok=True)
    os.makedirs(cache_dir, exist_ok=True)
    work = tempfile.mkdtemp(prefix="xpf-bake-", dir=os.environ.get("TMPDIR", "/tmp"))

    import glob
    try:
        # 1. build the xpf .deb (#1917 increment A). `make deb` runs
        #    `make build build-ctl build-userspace-dp` via debian/rules, so
        #    it picks up the embedded #1864 shim and the pinned cargo helper,
        #    then packages the freshly-built binaries. The image consumes the
        #    .deb instead of raw --copy-in binaries.
        deb_dir = os.path.join(ROOT, "dist", "deb")
        if not a.skip_build:
            info("building xpf .deb (xpfd, cli, xpf-userspace-dp -> staged)...")
            run(["make", "-C", ROOT, "deb"])
        # The git-derived version is computed by the Makefile; glob for the
        # binary package (NOT the xpf-appliance metapackage).
        debs = sorted(g for g in glob.glob(os.path.join(deb_dir, "xpf_*.deb"))
                      if "xpf-appliance" not in os.path.basename(g))
        if not debs:
            die(f"no xpf_*.deb in {deb_dir} (run without --skip-build, or run `make deb`)")
        xpf_deb = debs[-1]
        info(f"using package: {xpf_deb}")
        # build-host pre-gate (best-effort): verify the staged shim against
        # the build-host kernel before baking it in (#1864). The staged
        # binary inside the package is byte-identical to ROOT/xpfd.
        host_xpfd = os.path.join(ROOT, "xpfd")
        if not os.access(host_xpfd, os.X_OK):
            die(f"missing {host_xpfd} (make deb should have built it)")
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
            info(f"build-host pre-gate: xpfd verify-dataplane (host kernel {os.uname().release})...")
            if subprocess.run(["sudo", "-n", "nice", "-n", "19",
                               host_xpfd, "verify-dataplane"]).returncode != 0:
                die("embedded shim REJECTED by the build-host kernel verifier (#1864)")
        else:
            print("NOTE: no passwordless sudo — skipping build-host verify pre-gate "
                  "(in-guest gate still enforces).", file=sys.stderr)

        # 2. base
        rel, base_url, base_img, cached, base_sha = fetch_base(cache_dir, work)

        # 3. resize
        disk = os.environ.get("XPF_IMAGE_DISK_SIZE", "8G")
        info(f"creating {disk} work disk + expanding root partition...")
        fs = out_text(["virt-filesystems", "-a", cached, "--filesystems", "--long", "--no-title"])
        root_part = next((ln.split()[0] for ln in fs.splitlines()
                          if len(ln.split()) >= 3 and ln.split()[2] == "ext4"), None)
        if not root_part:
            die("could not locate the ext4 root partition in the base image")
        work_qcow = os.path.join(work, "work.qcow2")
        run(["qemu-img", "create", "-f", "qcow2", "-o", "preallocation=off", work_qcow, disk],
            stdout=subprocess.DEVNULL)
        run(["virt-resize", "--quiet", "--expand", root_part, cached, work_qcow])

        # 4. customize
        info("customizing image offline (packages, kernel >= 6.18, xpf install)...")
        virt_customize(work_qcow, xpf_deb)

        # 5. seal
        info("sealing image (virt-sysprep)...")
        run(["virt-sysprep", "-a", work_qcow, "--quiet", "--enable",
             "machine-id,ssh-hostkeys,ssh-userdir,logfiles,tmp-files,bash-history,"
             "package-manager-cache,backup-files,passwd-backups,utmp",
             "--run-command", "rm -rf /etc/xpf/.configdb /etc/xpf/xpf.conf "
             "/etc/xpf/.day0-config-applied /var/lib/systemd/random-seed "
             "/var/lib/apt/lists/* 2>/dev/null || true"])

        # 6. export
        ver = a.version
        qcow_out = os.path.join(a.out, f"xpf-{ver}.qcow2")
        meta_out = os.path.join(a.out, f"xpf-{ver}.incus-metadata.tar.gz")
        info(f"exporting {qcow_out} (sparsified + compressed qcow2)...")
        run(["virt-sparsify", "--quiet", "--tmp", work, "--compress", work_qcow, qcow_out])

        info(f"exporting {meta_out} (incus VM image metadata)...")
        meta = os.path.join(work, "metadata.yaml")
        with open(meta, "w") as f:
            f.write("architecture: x86_64\n"
                    f"creation_date: {int(time.time())}\n"
                    "properties:\n"
                    f"  description: xpf appliance {ver} (Ubuntu {rel}, kernel >= 6.18, "
                    "AF_XDP userspace dataplane)\n"
                    "  os: Ubuntu\n"
                    f"  release: {rel}\n"
                    "  variant: xpf-appliance\n")
        run(["tar", "-C", work, "-czf", meta_out, "metadata.yaml"])

        sums = os.path.join(a.out, "SHA256SUMS")
        with open(sums, "w") as f:
            for path in (qcow_out, meta_out):
                f.write(f"{sha256(path)}  {os.path.basename(path)}\n")
        info("checksums:")
        print(open(sums).read(), end="")

        try:
            commit = out_text(["git", "-C", ROOT, "rev-parse", "HEAD"]).strip()
        except Exception:
            commit = "unknown"
        manifest = os.path.join(a.out, f"xpf-{ver}.manifest")
        with open(manifest, "w") as f:
            f.write(f"version: {ver}\ngit_commit: {commit}\n"
                    f"base_image: {base_url}/{base_img}\nbase_release: {rel}\n"
                    f"base_image_sha256: {base_sha}\n"
                    f"bake_date: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
                    f"bake_host_kernel: {os.uname().release}\n")
        info(f"manifest: {manifest}")

        # 7. validation gate
        if a.skip_validate:
            print("WARNING: --skip-validate — artifacts have NOT passed the in-guest "
                  "verify-dataplane gate; do not publish them.", file=sys.stderr)
        else:
            info("running validation gate (factory boot + in-guest verify-dataplane + "
                 "valid/invalid day-0 drives)...")
            if subprocess.run([sys.executable, os.path.join(HERE, "validate.py"),
                               "--qcow2", qcow_out, "--metadata", meta_out, "all"]).returncode != 0:
                die(f"validation gate FAILED — artifacts in {a.out} are NOT publishable")

        info(f"bake complete: {qcow_out}")
        info("deploy quickstarts: docs/install-images.md")
        return 0
    finally:
        if a.keep_work:
            print(f"keeping work dir: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
