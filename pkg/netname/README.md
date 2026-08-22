# pkg/netname

Single source for the predictable network-interface name udev would assign to a
NIC (#7426).

## Why this package exists

Two re-implementations of one contract were live, and they were wrong in
**opposite directions on the same field**:

| | `deriveKernelName` (pkg/daemon) | `getOriginalKernelName` (pkg/dataplane) |
|---|---|---|
| altname selection | systemd NamePolicy order | **first match wins**, kernel listing order |
| PCI `f0` suffix | **never emitted** (`fn > 0`) | #4795's multifunction fix |

`#4795` — *"getOriginalKernelName appends f0 for single-function PCI"* — fixed
**over**-emission in the dataplane copy and never reached the daemon copy, which
**under**-emits.

**An agreement test would have frozen a bug rather than caught one.** It can only
pin one copy's behaviour to the other's, and on the `f0` field there is no
direction that is correct for both, because neither was right. That is the rule
this package encodes:

> **BIND an agreement when both copies can be right. SINGLE-SOURCE when they are
> wrong in opposite directions.**

## Measured on real hardware

The development host is an ARI box. `0000:b7:00.0` is a multifunction NIC
(`PCI_HEADER_TYPE` byte `0x80`):

```
10: ix0: ... altname eno5np0
           altname enp183s0f0np0
           altname enx3cecef6aa8bc

ID_NET_NAME_ONBOARD=eno5np0
ID_NET_NAME_PATH=enp183s0f0np0
```

Both defects are visible in that one device:

- **Ordering is a genuine coin flip** — three candidate altnames at once.
  First-match returns whichever the kernel listed first; udev resolves
  onboard-before-slot-before-path. Here they happen to agree, which is exactly
  the coincidence that makes first-match look correct.
- **`ID_NET_NAME_PATH` carries the `f0`.** The daemon's derivation produced
  `enp183s0`.

`TestDerivationMatchesRealHardware` scans the live PCI topology for multifunction
NICs and checks the derivation against udev's own answer. On the development host
it verifies **9 devices**; it SKIPS on a slot-0 / VF-only box, which is precisely
why the defect survived review elsewhere.

## Placement

A deliberate leaf with **zero xpf imports**. `pkg/daemon` imports
`pkg/dataplane` and not the reverse, so a resolver living in `pkg/daemon`
compiles fine right up until `pkg/dataplane` needs it. `pkg/devicemap` was the
other candidate, but `pkg/dataplane` does not import it today and adding that
edge is a larger commitment than a zero-import leaf.

## Entry points

- `FromAltNames(alts)` — the altname udev's NamePolicy would assign.
- `FromUdevProperties(props)` — `ID_NET_NAME_ONBOARD` → `SLOT` → `PATH`.
- `FromPCIAddr(addr, multifunction)` — best-effort derivation; blind to the port
  suffix (`np0`) and SR-IOV VF parentage, so it is the last resort.
- `FunctionSuffix(multifunction, fn)` / `Multifunction(addr)` — the `f<n>` rule
  and the `PCI_HEADER_TYPE` probe behind it.
- `Resolve(alts, pciAddr)` — the chain. Callers pass altnames because each call
  site already owns a seam for them; the dataplane compile path reads them
  through a per-compile link **cache** that collapsing into this package would
  drop.

## Gotchas

- **The function is parsed base 16.** sysfs prints it in hex and an ARI device
  can carry functions above 9 (up to 255); a base-10 parse rejects those and
  returns `""` where a name was derivable. Latent on the development host, whose
  maximum observed function is 7 — verified, not assumed.
- **`altNamePrefixOrder` in pkg/daemon is an ALIAS of `NamePolicyPrefixOrder`,
  not a copy.** A separate literal would leave `derive_kernel_name_6677_test.go`
  pinning a variable production no longer reads — a test that still passes while
  guarding nothing. The mutation matrix confirms the alias keeps that test live.
- **The #4795 regression test moved here with the code.** Left in
  `pkg/dataplane` it would have guarded a deleted copy while the surviving
  derivation went unpinned.
