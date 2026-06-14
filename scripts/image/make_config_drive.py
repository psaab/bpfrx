#!/usr/bin/env python3
"""Build an xpf day-0 config drive ISO (#1879 Path C), in Python.

The vSRX analog of "ISO with juniper.conf at the root": an ISO9660 volume
labeled `xpf-config` carrying the config as `xpf.conf` (+ an optional
`node-id` for cluster members). Attach it to the appliance VM as a CD-ROM
(libvirt) or a disk device (incus); the first-boot loader applies it.

Importable: validate.py and other tooling call build_config_drive().
CLI:
  make_config_drive.py [-n 0|1] [-o out.iso] [--no-validate] <config-file>

Validation: if an xpfd binary is available (./xpfd or $XPFD), the config
is run through the real commit-check gate and the build FAILS on reject.
--no-validate skips it (the appliance still validates at first boot).
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile


def die(msg):
    sys.exit(f"ERROR: {msg}")


def find_xpfd():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))
    for c in (os.environ.get("XPFD"), os.path.join(root, "xpfd"), shutil.which("xpfd")):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def _iso_tool():
    for t in ("xorriso", "genisoimage", "mkisofs"):
        if shutil.which(t):
            return t
    die("need xorriso/genisoimage/mkisofs (apt-get install xorriso)")


def build_config_drive(config, out=None, node_id=None, validate=True):
    """Build the day-0 ISO. Returns the output path."""
    if not os.path.isfile(config):
        die(f"config file not found: {config}")
    if node_id is not None and str(node_id) not in ("0", "1"):
        die("node-id must be 0 or 1")
    out = out or (os.path.splitext(os.path.basename(config))[0] + "-config.iso")

    if validate:
        xpfd = find_xpfd()
        if xpfd:
            print(f"==> validating {config} with check-config ({xpfd})")
            nodearg = ["-node-id", str(node_id)] if node_id is not None else []
            r = subprocess.run([xpfd, "check-config"] + nodearg + [config],
                               capture_output=True, text=True)
            if r.returncode != 0:
                die("config REJECTED by commit-check — fix it or pass "
                    f"--no-validate:\n{r.stdout}{r.stderr}")
        else:
            print("WARNING: no xpfd binary — skipping build-host validation "
                  "(the appliance still validates at first boot).", file=sys.stderr)

    tool = _iso_tool()
    stage = tempfile.mkdtemp(prefix="xpf-day0-")
    try:
        shutil.copyfile(config, os.path.join(stage, "xpf.conf"))
        os.chmod(os.path.join(stage, "xpf.conf"), 0o644)
        if node_id is not None:
            with open(os.path.join(stage, "node-id"), "w") as f:
                f.write(f"{node_id}\n")
        print(f"==> building {out} (volume label xpf-config)")
        if tool == "xorriso":
            argv = ["xorriso", "-as", "mkisofs", "-quiet", "-V", "xpf-config",
                    "-J", "-r", "-o", out, stage]
        else:
            argv = [tool, "-quiet", "-V", "xpf-config", "-J", "-r", "-o", out, stage]
        subprocess.run(argv, check=True)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-n", "--node-id", choices=["0", "1"])
    p.add_argument("-o", "--out")
    p.add_argument("--no-validate", action="store_true")
    p.add_argument("config")
    a = p.parse_args()
    out = build_config_drive(a.config, a.out, a.node_id, not a.no_validate)
    print(f"==> done: {out}")
    print(f"    libvirt: virt-install … --disk path={out},device=cdrom")
    print(f"    incus:   incus config device add <vm> day0 disk source={os.path.abspath(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
