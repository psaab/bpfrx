#!/usr/bin/env python3
"""
Fast dedup check for new findings against prior reviews + issues.
Handles dynamic model naming: claude-spark-1.1 -> claude-spark, muse- -> claude-, version stripping.

Usage: python3 scripts/review-dedup-check.py "NAT pool overflow" --check-issues
"""

import json, re, sys, glob, os
from collections import defaultdict

def normalize_whoami(raw):
    if not raw:
        return "unknown"
    raw = raw.lower()
    raw = re.sub(r'^muse-', 'claude-', raw)
    if raw.startswith('claude-'):
        parts = raw.split('-')
        who = f"{parts[0]}-{parts[1]}" if len(parts) >= 2 else parts[0]
    else:
        who = raw.split('-')[0]
    who = re.sub(r'-[0-9]+(\.[0-9]+)*$', '', who)
    who = re.sub(r'-[0-9]{8,}$', '', who)
    return who or "unknown"

def is_result_report(path):
    """Research/triage derivatives are status evidence, not fresh discoveries."""
    return os.path.basename(path).startswith(('report-', 'result-'))

def load_review_titles():
    cached_titles = []
    # Current and legacy indexes are leads, not an exhaustive report inventory.
    for index in ('/var/tmp/deep-review-work/review-index.json', '/tmp/review-index.json'):
        try:
            data = json.loads(open(index).read())
            for entry in data:
                if is_result_report(entry['filename']):
                    continue
                for t in entry.get('titles', []):
                    cached_titles.append((entry['filename'], t))
        except:
            pass
    # Always scan active, finished and legacy history: an older cached index may
    # miss a newly published or archived report. Do not create discovery aliases.
    paths = (glob.glob('/var/tmp/deep-review-reports/*-review*.md')
             + glob.glob('/var/tmp/deep-review-finished/*-review*.md')
             + glob.glob('/tmp/*-review*.md'))
    titles = []
    paths_by_basename = defaultdict(set)
    derivatives = set()
    for path in paths:
        paths_by_basename[os.path.basename(path)].add(os.path.abspath(path))
        if is_result_report(path):
            continue
        try:
            content = open(path, 'r', errors='ignore').read()
            if re.search(r'^Artifact kind:\s*research-result\s*$', content, re.MULTILINE | re.IGNORECASE):
                derivatives.add(os.path.abspath(path))
                continue
            for m in re.finditer(r'^Title\s*[:\-]\s*([^\n]+)', content, re.MULTILINE | re.IGNORECASE):
                titles.append((os.path.basename(path), m.group(1).strip()))
        except:
            pass
    retained_cache = []
    for filename, title in cached_titles:
        candidates = ({os.path.abspath(filename)} if os.path.dirname(filename)
                      else paths_by_basename.get(filename, set()))
        # A basename-only cache cannot distinguish equal names across roots.
        # If one is a known derivative, rely on fresh original-source rows;
        # do not guess that the cached title belongs to the other root.
        if candidates & derivatives:
            continue
        retained_cache.append((filename, title))
    return list(dict.fromkeys(retained_cache + titles))

def load_issue_titles():
    titles = []
    for index in ('/var/tmp/deep-review-work/issue-pr-index.json', '/tmp/issue-pr-index.json'):
        try:
            data = json.loads(open(index).read())
            titles.extend((f"ISSUE #{i['number']}", i['title']) for i in data.get('issues', []))
        except:
            pass
    return list(dict.fromkeys(titles))

def check_finding(new_title, threshold=0.5):
    """Check if new_title is similar to prior review or issue"""
    new_words = set(re.findall(r'\b\w{3,}\b', new_title.lower()))
    matches = []
    for fname, title in load_review_titles():
        existing_words = set(re.findall(r'\b\w{3,}\b', title.lower()))
        if not existing_words or not new_words:
            continue
        overlap = new_words & existing_words
        jaccard = len(overlap) / len(new_words | existing_words) if (new_words | existing_words) else 0
        if jaccard > threshold or (len(overlap) >= 3 and len(overlap)/len(new_words) > 0.6):
            matches.append((fname, title, jaccard, overlap))
    for fname, title in load_issue_titles():
        existing_words = set(re.findall(r'\b\w{3,}\b', title.lower()))
        overlap = new_words & existing_words
        jaccard = len(overlap) / len(new_words | existing_words) if (new_words | existing_words) else 0
        if jaccard > threshold:
            matches.append((fname, title, jaccard, overlap))
    matches = sorted(matches, key=lambda x: x[2], reverse=True)
    return matches[:10]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/review-dedup-check.py \"Finding title to check\"")
        sys.exit(1)
    new_title = sys.argv[1]
    print(f"Checking dedup for: {new_title}")
    print(f"Normalized whoami detection for current model:")
    import os
    raw = os.environ.get('ANTHROPIC_MODEL','') or os.environ.get('CLAUDE_CODE_SUBAGENT_MODEL','')
    print(f"  ANTHROPIC_MODEL={raw} -> normalized whoami={normalize_whoami(raw)}")
    matches = check_finding(new_title)
    if not matches:
        print("No close matches found — likely NEW finding")
    else:
        print(f"Found {len(matches)} potential duplicates:")
        for fname, title, jaccard, overlap in matches:
            print(f"  - {fname}: {title[:80]} (jaccard={jaccard:.2f}, overlap={overlap})")
