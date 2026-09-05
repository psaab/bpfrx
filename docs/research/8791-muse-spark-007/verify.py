import re, os, sys
REPO="/var/tmp/GE"
txt=open("/tmp/muse-spark-review-007.md").read()

# split into findings
parts=re.split(r'^### Finding\s+(\d+)', txt, flags=re.M)
results=[]
for i in range(1,len(parts),2):
    num=parts[i]; body=parts[i+1]
    # find (path:line) followed by a fenced block
    for m in re.finditer(r'`([A-Za-z0-9_/.\-]+\.(?:go|rs|py|c|h|md)):(\d+)(?:-(\d+))?`\s*\n+```[a-z]*\n(.*?)```', body, re.S):
        path,a,b,quote=m.group(1),int(m.group(2)),m.group(3),m.group(4)
        b=int(b) if b else a
        full=os.path.join(REPO,path)
        if not os.path.exists(full):
            results.append((num,path,f"{a}-{b}","FILE MISSING",0,0)); continue
        lines=open(full,encoding='utf-8',errors='replace').read().split('\n')
        actual=[l.strip() for l in lines[a-1:b] if l.strip()]
        claimed=[l.strip() for l in quote.split('\n') if l.strip()]
        if not claimed:
            results.append((num,path,f"{a}-{b}","EMPTY QUOTE",0,0)); continue
        hits=sum(1 for c in claimed if c in actual)
        pct=100*hits//len(claimed)
        verdict = "MATCH" if pct>=80 else ("PARTIAL" if pct>=30 else "NO MATCH")
        results.append((num,path,f"{a}-{b}",verdict,hits,len(claimed)))
print(f"{'F':>3} {'verdict':<12} {'hit/claimed':>12}  path:lines")
bad=0
for num,path,rng,v,h,t in results:
    if v!="MATCH": bad+=1
    print(f"{num:>3} {v:<12} {h:>5}/{t:<6}  {path}:{rng}")
print()
print(f"TOTAL evidence blocks checked: {len(results)}")
print(f"  MATCH   : {sum(1 for r in results if r[3]=='MATCH')}")
print(f"  PARTIAL : {sum(1 for r in results if r[3]=='PARTIAL')}")
print(f"  NO MATCH: {sum(1 for r in results if r[3]=='NO MATCH')}")
print(f"  MISSING : {sum(1 for r in results if r[3] in ('FILE MISSING','EMPTY QUOTE'))}")
