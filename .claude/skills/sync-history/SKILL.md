---
name: sync-history
description: Regenerate docs/issues/issue-history.md and docs/issues/pr-history.md from GitHub
user_invocable: true
---

# Sync GitHub Issue and PR History

Regenerate the offline history documents from GitHub data. Run this after significant issue/PR activity to keep the local docs current.

## Steps

1. Generate `docs/issues/issue-history.md` with all issues (open and closed), full bodies, categorized by status.
2. Generate `docs/issues/pr-history.md` with all PRs (merged, closed, open), full bodies.
3. Commit and push both files.

## Implementation

Run this Python script to generate both files:

```bash
python3 << 'PYEOF'
import subprocess, json, os

os.makedirs("docs/issues", exist_ok=True)

# === ISSUES ===
result = subprocess.run(
    ["gh", "issue", "list", "--state", "all", "--limit", "5000", "--json",
     "number,title,state,closedAt,body"],
    capture_output=True, text=True
)
issues = json.loads(result.stdout)
issues.sort(key=lambda x: x["number"])

with open("docs/issues/issue-history.md", "w") as f:
    f.write("# bpfrx Issue History\n\n")
    f.write("Complete record of all issues filed and resolved.\n")
    f.write(f"Total: {len(issues)} issues ({sum(1 for i in issues if i['state']=='CLOSED')} closed, {sum(1 for i in issues if i['state']=='OPEN')} open)\n\n---\n\n")
    for i in issues:
        status = "OPEN" if i["state"] == "OPEN" else "CLOSED"
        closed = f" (closed {i['closedAt'][:10]})" if i.get("closedAt") else ""
        f.write(f"## #{i['number']} — {i['title']} [{status}]{closed}\n\n")
        body = i.get("body") or "(no description)"
        lines = body.split("\n")
        if len(lines) > 40:
            f.write("\n".join(lines[:40]))
            f.write(f"\n\n*(truncated — {len(lines)} lines total)*\n")
        else:
            f.write(body)
        f.write("\n\n---\n\n")
print(f"Issues: {len(issues)}")

# === PRs ===
all_prs = []
for state in ["merged", "closed", "open"]:
    result = subprocess.run(
        ["gh", "pr", "list", "--state", state, "--limit", "5000",
         "--json", "number,title,state,mergedAt,closedAt,body,headRefName"],
        capture_output=True, text=True
    )
    if result.stdout.strip():
        for pr in json.loads(result.stdout):
            if pr["number"] not in {p["number"] for p in all_prs}:
                all_prs.append(pr)
all_prs.sort(key=lambda x: x["number"])

with open("docs/issues/pr-history.md", "w") as f:
    f.write("# bpfrx Pull Request History\n\n")
    f.write("Complete record of all pull requests.\n")
    merged = sum(1 for p in all_prs if p.get("mergedAt"))
    f.write(f"Total: {len(all_prs)} PRs ({merged} merged)\n\n---\n\n")
    for pr in all_prs:
        status = "MERGED" if pr.get("mergedAt") else pr.get("state", "UNKNOWN").upper()
        date = ""
        if pr.get("mergedAt"):
            date = f" (merged {pr['mergedAt'][:10]})"
        elif pr.get("closedAt"):
            date = f" (closed {pr['closedAt'][:10]})"
        branch = pr.get("headRefName", "")
        f.write(f"## PR #{pr['number']} — {pr['title']} [{status}]{date}\n\n")
        if branch:
            f.write(f"Branch: `{branch}`\n\n")
        body = pr.get("body") or "(no description)"
        lines = body.split("\n")
        if len(lines) > 50:
            f.write("\n".join(lines[:50]))
            f.write(f"\n\n*(truncated — {len(lines)} lines total)*\n")
        else:
            f.write(body)
        f.write("\n\n---\n\n")
print(f"PRs: {len(all_prs)}")
PYEOF
```

Then commit:

```bash
git add docs/issues/issue-history.md docs/issues/pr-history.md
git commit -m "docs: sync issue and PR history from GitHub

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
git push origin master
```
