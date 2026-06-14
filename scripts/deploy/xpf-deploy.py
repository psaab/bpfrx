#!/usr/bin/env python3
"""xpf-deploy — launch xpf appliance VMs from a YAML definition.

One YAML file fully describes an appliance: its mode, the day-0 config to
ship, and an ORDERED list of interfaces. Interface position is the whole
naming contract (matches pkg/daemon/linksetup.go assignName):

  standalone:        pos1 -> fxp0   pos2 -> ge-0/0/0   posN -> ge-0/0/(N-2)
  cluster node 0:    pos1 -> fxp0   pos2 -> em0        posN -> ge-0/0/(N-3)
  cluster node 1:    pos1 -> fxp0   pos2 -> em0        posN -> ge-7/0/(N-3)

You declare the `role` you EXPECT at each position; the tool computes the
real name from the position and refuses to launch if they disagree, so a
miswired YAML fails on your laptop, not in production. It then builds the
day-0 config drive (validated by `xpfd check-config`) and emits the incus
(or libvirt) commands to bring the VM up with the NICs attached in order.

Usage:
  xpf-deploy.py [opts] <appliance.yaml> [<appliance2.yaml> ...]

Options:
  --dry-run            print the commands instead of running them
  --hypervisor X       incus (default) | libvirt
  --no-start           create everything, don't start
  --image ALIAS        override the YAML's image
  -h, --help           this help

A cluster is just two YAML files: `xpf-deploy.py ha-fw0.yaml ha-fw1.yaml`.
See examples/deploy/*.yaml and docs/deploy-quickstart.md.
"""

import argparse
import os
import re
import shlex
import subprocess
import sys

try:
    import yaml
except ImportError:
    sys.exit("ERROR: PyYAML is required (pip install pyyaml / apt install python3-yaml)")

HERE = os.path.dirname(os.path.abspath(__file__))
MAKE_DRIVE = os.path.join(HERE, "..", "image", "make-config-drive.sh")

VALID_BACKINGS = {"net", "bridge", "macvlan", "sriov", "physical", "pci"}


def die(msg):
    sys.exit(f"ERROR: {msg}")


def expected_name(idx, mode, node_id):
    """The vSRX name the guest assigns to the NIC at position idx (0-based).

    Mirrors assignName() in pkg/daemon/linksetup.go exactly.
    """
    if idx == 0:
        return "fxp0"
    if mode == "cluster":
        if idx == 1:
            return "em0"
        fpc = 7 if node_id == 1 else 0
        return f"ge-{fpc}/0/{idx - 2}"
    return f"ge-0/0/{idx - 1}"


def norm_role(role):
    """Normalize an interface name to slash form (ge-0-0-0 -> ge-0/0/0)."""
    r = role.strip()
    m = re.fullmatch(r"ge-(\d+)[-/]0[-/](\d+)", r)
    if m:
        return f"ge-{m.group(1)}/0/{m.group(2)}"
    return r


def load_appliance(path):
    with open(path) as f:
        doc = yaml.safe_load(f)
    if not isinstance(doc, dict):
        die(f"{path}: top level must be a mapping")
    ap = doc.get("appliance") or {}
    name = ap.get("name")
    if not name:
        die(f"{path}: appliance.name is required")
    mode = ap.get("mode", "standalone")
    if mode not in ("standalone", "cluster"):
        die(f"{path}: appliance.mode must be standalone|cluster")
    node_id = ap.get("node_id")
    if mode == "cluster" and node_id not in (0, 1):
        die(f"{path}: cluster appliance needs node_id: 0|1")
    ifaces = doc.get("interfaces") or []
    if not ifaces:
        die(f"{path}: at least one interface is required (position 1 = fxp0)")

    # Validate each interface and check declared role == positional name.
    for i, ic in enumerate(ifaces):
        if not isinstance(ic, dict):
            die(f"{path}: interfaces[{i}] must be a mapping")
        backing = ic.get("backing")
        if backing not in VALID_BACKINGS:
            die(f"{path}: interfaces[{i}].backing must be one of {sorted(VALID_BACKINGS)}")
        if not ic.get("source"):
            die(f"{path}: interfaces[{i}].source is required")
        want = expected_name(i, mode, node_id)
        declared = ic.get("role")
        if declared and norm_role(declared) != want:
            die(f"{path}: interfaces[{i}] declares role '{declared}' but position {i + 1} "
                f"is '{want}' ({mode}"
                + (f" node {node_id}" if mode == "cluster" else "") + "). "
                "Reorder the list or fix the role — position is the contract.")
        ic["_name"] = want
    return {
        "name": name, "mode": mode, "node_id": node_id,
        "image": ap.get("image", "xpf-appliance"),
        "cpu": ap.get("cpu", 4), "memory": ap.get("memory", "4GiB"),
        "config": ap.get("config"), "interfaces": ifaces,
        "yaml_dir": os.path.dirname(os.path.abspath(path)),
    }


def vf_parent(addr):
    """Return (PF_netdev, vf_index) for an SR-IOV VF PCI address, or None."""
    base = "/sys/class/net"
    try:
        pfs = os.listdir(base)
    except OSError:
        return None
    for pf in pfs:
        devdir = os.path.join(base, pf, "device")
        if not os.path.isdir(devdir):
            continue
        for entry in os.listdir(devdir):
            if not entry.startswith("virtfn"):
                continue
            if os.path.basename(os.path.realpath(os.path.join(devdir, entry))) == addr:
                return pf, entry[len("virtfn"):]
    return None


class Runner:
    def __init__(self, dry):
        self.dry = dry

    def run(self, argv):
        if self.dry:
            print(" ".join(shlex.quote(a) for a in argv))
            return ""
        return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def build_config_drive(ap, runner):
    cfg = ap["config"]
    if not cfg:
        return None
    cfg_path = cfg if os.path.isabs(cfg) else os.path.join(ap["yaml_dir"], cfg)
    if not runner.dry and not os.path.isfile(cfg_path):
        die(f"config not found: {cfg_path}")
    iso = os.path.join(os.getcwd(), f"{ap['name']}-day0.iso")
    argv = ["bash", MAKE_DRIVE]
    if ap["mode"] == "cluster":
        argv += ["-n", str(ap["node_id"])]
    argv += ["-o", iso, cfg_path]
    print(f"==> building day-0 drive {iso} (validated by check-config)")
    runner.run(argv)
    return iso


def deploy_incus(ap, runner, start):
    name = ap["name"]
    print(f"==> {name}: {ap['mode']}"
          + (f" node {ap['node_id']}" if ap["mode"] == "cluster" else "")
          + f", {len(ap['interfaces'])} NICs")
    # Print the resolved position->name->role map up front.
    for i, ic in enumerate(ap["interfaces"]):
        print(f"      pos {i + 1}: {ic['_name']:<10} <- {ic['backing']}:{ic['source']}")
    iso = build_config_drive(ap, runner)
    runner.run(["incus", "init", ap["image"], name, "--vm",
                "-c", f"limits.cpu={ap['cpu']}", "-c", f"limits.memory={ap['memory']}"])
    pins = []
    for i, ic in enumerate(ap["interfaces"]):
        dev = f"dev{i:02d}"  # zero-padded => incus name order = position order
        b, src = ic["backing"], str(ic["source"])
        mac = ic.get("mac")
        if b == "net":
            args = ["nic", f"network={src}"]
        elif b == "bridge":
            args = ["nic", "nictype=bridged", f"parent={src}"]
        elif b == "macvlan":
            args = ["nic", "nictype=macvlan", f"parent={src}"]
        elif b == "sriov":
            args = ["nic", "nictype=sriov", f"parent={src}"]
        elif b == "physical":
            args = ["nic", "nictype=physical", f"parent={src}"]
        elif b == "pci":
            args = ["pci", f"address={src}"]
        if mac and b in ("net", "bridge", "macvlan", "sriov"):
            args.append(f"hwaddr={mac}")
        if mac and b == "pci":
            par = None if runner.dry else vf_parent(src)
            if par:
                pins.append(["sudo", "ip", "link", "set", "dev", par[0], "vf", par[1], "mac", mac])
            elif runner.dry:
                print(f"      (dry-run) would pin VF MAC for pci:{src}")
            else:
                die(f"pci:{src} with mac= is not an SR-IOV VF on this host (drop mac= for whole-PF)")
        runner.run(["incus", "config", "device", "add", name, dev] + args)
    if iso:
        runner.run(["incus", "config", "device", "add", name, "day0", "disk", f"source={iso}"])
    for pin in pins:
        pf = pin[5]
        runner.run(["sudo", "ip", "link", "set", "dev", pf, "up"])
        print(f"==> pinning VF MAC: {' '.join(pin)}")
        runner.run(pin)
    if start:
        runner.run(["incus", "start", name])
        print(f"\n{name} launched. Verify the NIC->name map:\n"
              f"  incus exec {name} -- cli -c \"show interfaces terse\"")
    else:
        print(f"{name} created (not started): incus start {name}")


def memory_mb(val):
    """'4GiB'/'4096MiB'/4096/'4G' -> MB integer for virt-install."""
    s = str(val).strip()
    m = re.fullmatch(r"(\d+)\s*([GMgm]i?[Bb]?)?", s)
    if not m:
        die(f"unparseable memory '{val}'")
    n = int(m.group(1))
    unit = (m.group(2) or "M").upper()
    return n * 1024 if unit.startswith("G") else n


def pci_parts(addr):
    """'0000:09:00.2' -> dict of hex domain/bus/slot/function for libvirt."""
    m = re.fullmatch(r"([0-9a-fA-F]{4}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", addr)
    if not m:
        die(f"pci address '{addr}' is not DDDD:BB:DD.F")
    return {"domain": "0x" + m.group(1), "bus": "0x" + m.group(2),
            "slot": "0x" + m.group(3), "function": "0x" + m.group(4)}


def deploy_libvirt(ap, runner, start):
    """Emit a virt-install command. NIC order on the command line becomes
    the persisted guest <address> PCI-slot order, which the guest then
    names positionally — same contract as incus."""
    name = ap["name"]
    iso = build_config_drive(ap, runner)
    disk = f"/var/lib/libvirt/images/{ap['image']}.qcow2"
    argv = ["virt-install", "--name", name,
            "--memory", str(memory_mb(ap["memory"])),
            "--vcpus", str(ap["cpu"]), "--import",
            "--disk", f"path={disk}",
            "--osinfo", "ubuntu26.04", "--noautoconsole"]
    if iso:
        argv += ["--disk", f"path={iso},device=cdrom"]
    notes = []
    for ic in ap["interfaces"]:
        b, src, mac = ic["backing"], str(ic["source"]), ic.get("mac")
        if b in ("net", "bridge"):
            # incus managed net has no libvirt analogue — both map to a
            # host bridge / libvirt network by name.
            kind = "network" if b == "net" else "bridge"
            net = f"{kind}={src},model=virtio"
            if mac:
                net += f",mac.address={mac}"
            argv += ["--network", net]
        elif b == "macvlan":
            net = f"type=direct,source={src},source_mode=bridge,model=virtio"
            if mac:
                net += f",mac.address={mac}"
            argv += ["--network", net]
        elif b == "physical":
            argv += ["--hostdev", src]   # whole card, keeps burned-in MAC
        elif b == "pci":
            if mac:
                # SR-IOV VF with a pinned MAC -> hostdev-network form so
                # libvirt programs the VF MAC on the PF before assignment.
                p = pci_parts(src)
                argv += ["--network",
                         "type=hostdev,"
                         f"source.address.type=pci,source.address.domain={p['domain']},"
                         f"source.address.bus={p['bus']},source.address.slot={p['slot']},"
                         f"source.address.function={p['function']},mac.address={mac}"]
            else:
                argv += ["--hostdev", src]   # raw VF/PF passthrough
        elif b == "sriov":
            # libvirt has no "pick a free VF on this PF" device; the
            # idiomatic equivalent is a <forward mode='hostdev'> VF pool
            # network named after the PF (one-time host setup).
            pool = f"{src}-vfpool"
            net = f"network={pool}"
            if mac:
                net += f",mac.address={mac}"
            argv += ["--network", net]
            notes.append(
                f"sriov:{src} -> libvirt VF pool '{pool}'. Define it once:\n"
                f"      <network><name>{pool}</name>"
                f"<forward mode='hostdev' managed='yes'>"
                f"<pf dev='{src}'/></forward></network>\n"
                f"      virsh net-define <file> && virsh net-start {pool} "
                f"&& virsh net-autostart {pool}")
    print("# virt-install — NIC order = guest PCI-slot order = positional names.")
    print("# For fully contractual hardware ordering, pin guest <address> slots in `virsh edit`.")
    for n in notes:
        print(f"# NOTE: {n}")
    runner.run(argv)
    if start:
        print(f"\n{name}: after boot, verify with "
              f"`virsh console {name}` then `cli -c \"show interfaces terse\"`.")


def main():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("yamls", nargs="*")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--hypervisor", default="incus", choices=["incus", "libvirt"])
    p.add_argument("--no-start", action="store_true")
    p.add_argument("--image")
    p.add_argument("-h", "--help", action="store_true")
    args = p.parse_args()
    if args.help or not args.yamls:
        print(__doc__)
        return 0 if args.help else 2
    runner = Runner(args.dry_run)
    for path in args.yamls:
        ap = load_appliance(path)
        if args.image:
            ap["image"] = args.image
        if args.hypervisor == "incus":
            deploy_incus(ap, runner, not args.no_start)
        else:
            deploy_libvirt(ap, runner, not args.no_start)
    return 0


if __name__ == "__main__":
    sys.exit(main())
