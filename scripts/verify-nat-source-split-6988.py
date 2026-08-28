"""#6988 code-motion verifier.

Reconstructs nat/source.rs from the split and compares it byte-for-byte with the
pre-split file, allowing ONLY the visibility widenings enumerated below. Any other
difference — a reordered statement, a changed literal, a dropped comment — fails.
"""
import subprocess, sys

BASE = subprocess.run(['git','show','origin/master:userspace-dp/src/nat/source.rs'],
                      capture_output=True, text=True, check=True).stdout.split('\n')

# Line ranges in the CURRENT origin/master source.rs. They shift whenever master
# lands work in the residual: #7858 (`carry_renamed_pool_reservations`, #6979 F6)
# inserted 99 lines at ~717 and moved every seam below it by exactly that. When
# they shift, re-derive them by CONTENT — match each seam's first and last line
# in the new file and require the span length to be preserved — rather than by
# arithmetic. That derivation also proves master did not touch the moved text,
# which is the fact a modify/delete merge most needs and the one a
# conflict-marker sweep cannot supply (this conflict produces ZERO markers).
SEAMS=[('failure',59,215),('expand',1193,1366),('release',1679,1935),
       ('synced',1937,2451),('nat64_ports',2453,2592),('match_rules',2594,3340)]

# Two WIDENINGS (private -> pub(super)) and one RESPELLING. The respelling is
# not a visibility change at all: `pub(super)` inside `nat::source` meant
# `pub(in crate::nat)`, and one level deeper the same keyword would mean
# `pub(in crate::nat::source)` — narrower, and it broke
# nat/tests_aggregate_budget.rs with E0603 on the first build. The absolute
# form restores exactly what the pre-split file had.
ALLOWED=[('failure','    fn for_rule(','    pub(super) fn for_rule('),
         ('failure','fn source_nat_failure_reason_from_snapshot(',
                    'pub(super) fn source_nat_failure_reason_from_snapshot('),
         ('expand','pub(super) fn expand_pool_address(',
                   'pub(in crate::nat) fn expand_pool_address(')]

def submodule_body(name):
    lines=open(f'userspace-dp/src/nat/source/{name}.rs').read().split('\n')
    i=lines.index('use super::*;')          # header ends at the glob import
    body=lines[i+2:]                        # skip the blank line after it
    while body and body[-1]=='': body.pop() # trailing newline the writer added
    return body

# 1. Un-apply the allowed edits, so what remains must be IDENTICAL to base.
recon={}
for name,a,b in SEAMS:
    body='\n'.join(submodule_body(name))
    # Explanatory lines added by the split are tagged so stripping them is
    # deterministic rather than a prefix guess that can silently miss one.
    body='\n'.join(l for l in body.split('\n') if '// #6988-note:' not in l)
    for f,old,new in ALLOWED:
        if f==name:
            assert body.count(new)==1, f'{name}: expected exactly one {new!r}'
            body=body.replace(new,old)
    recon[name]=body.split('\n')

# 2. Rebuild the original line sequence.
mod_lines=open('userspace-dp/src/nat/source/mod.rs').read().split('\n')
# strip the inserted block (mod decls + re-exports + their comment banner)
start=next(i for i,l in enumerate(mod_lines) if l.startswith('// #6988: source.rs crossed'))
end=next(i for i,l in enumerate(mod_lines) if l.startswith('pub(crate) use match_rules::*;'))
residual=mod_lines[:start-1]+mod_lines[end+2:]

out=[]; ri=0; taken=set()
for n in range(1,len(BASE)+1):
    hit=[s for s in SEAMS if s[1]==n]
    if hit:
        out.extend(recon[hit[0][0]]); taken.add(hit[0][0]); continue
    if any(a<n<=b for _,a,b in SEAMS): continue
    out.append(residual[ri]); ri+=1

assert len(taken)==len(SEAMS), f'missed submodules: {set(s[0] for s in SEAMS)-taken}'
if ri!=len(residual):
    print(f'FAIL: {len(residual)-ri} residual mod.rs lines unaccounted for'); sys.exit(1)

if out==BASE:
    print(f'PASS: the split reconstructs nat/source.rs EXACTLY ({len(BASE)} lines).')
    print(f'      Allowed edits, and nothing else: {len(ALLOWED)}')
    for f,old,new in ALLOWED: print(f'        {f}.rs: {old.strip()}  ->  {new.strip()}')
    sys.exit(0)

import difflib
print('FAIL: reconstruction differs from the pre-split file:')
for d in list(difflib.unified_diff(BASE,out,'pre-split','reconstructed',lineterm='',n=1))[:60]:
    print(d)
sys.exit(1)
