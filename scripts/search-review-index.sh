#!/bin/bash
# Fast searchable index for prior reviews + issue/PR history
# Dynamic model handling: normalizes muse->claude, strips versions
# Usage: ./scripts/search-review-index.sh <keyword> [--type review|issue|pr]
# Examples:
#   ./scripts/search-review-index.sh "zone policy"
#   ./scripts/search-review-index.sh "NAT pool" --type review
#   ./scripts/search-review-index.sh "VRRP" --type issue
set -e
KEYWORD="${1:-}"
TYPE="${2:-}"
if [ -z "$KEYWORD" ]; then
  echo "Usage: $0 <keyword> [--type review|issue|pr]"
  echo "Examples:"
  echo "  $0 'zone policy'"
  echo "  $0 'NAT pool' --type review"
  echo "  $0 'VRRP' --type issue"
  exit 1
fi

# Handle --type flag in either position
if [[ "$1" == --type ]]; then
  TYPE="$2"
  KEYWORD="$3"
elif [[ "$2" == --type ]]; then
  TYPE="$3"
fi

echo "=== Searching for: $KEYWORD ==="
echo ""

# Normalize keyword for inverted index lookup
KW_LC=$(echo "$KEYWORD" | tr '[:upper:]' '[:lower:]' | cut -d' ' -f1)

if [ "$TYPE" = "review" ] || [ -z "$TYPE" ]; then
  echo "--- Review findings (from review-index.md) ---"
  rg -i --no-heading "$KEYWORD" /tmp/review-index.md 2>/dev/null | head -30 || grep -i "$KEYWORD" /tmp/review-index.md 2>/dev/null | head -30 || echo "No matches in review-index.md"
  echo ""
  echo "--- Review titles (searchable-index.txt) ---"
  rg -i --no-heading "$KEYWORD" /tmp/searchable-index.txt 2>/dev/null | grep -i "REVIEW" | head -30 || true
  echo ""
fi

if [ "$TYPE" = "issue" ] || [ -z "$TYPE" ]; then
  echo "--- Issues (from issue-history) ---"
  rg -i --no-heading "$KEYWORD" /tmp/issue-pr-index.md 2>/dev/null | head -30 || true
  rg -i --no-heading "$KEYWORD" /tmp/all-titles-searchable.txt 2>/dev/null | grep "^ISSUE" | head -20 || true
  echo ""
fi

if [ "$TYPE" = "pr" ] || [ -z "$TYPE" ]; then
  echo "--- PRs ---"
  rg -i --no-heading "$KEYWORD" /tmp/issue-pr-index.md 2>/dev/null | tail -30 | head -20 || true
  echo ""
fi

echo "--- Inverted index lookup (keyword: $KW_LC) ---"
python3 -c "
import json, sys
kw=sys.argv[1].lower()
try:
    idx=json.load(open('/tmp/review-inverted-index.json'))
    matches=idx.get(kw, [])
    print(f\"Keyword '{kw}' has {len(matches)} matches in inverted index:\")
    for m in matches[:15]:
        print(m)
except Exception as e:
    print(f\"No inverted index match or error: {e}\")
" "$KW_LC" 2>/dev/null || echo "No inverted index match"

echo ""
echo "Full files: /tmp/review-index.md (95KB table + titles), /tmp/review-index.json (structured), /tmp/issue-pr-index.md, /tmp/all-titles-searchable.txt (516KB all titles), /tmp/searchable-index.txt (compact whoami|NNN|TYPE|file|title), /tmp/review-inverted-index.json (8011 keywords)"
echo "Persistent copies: docs/issues/review-index.json, docs/issues/review-index.md, docs/issues/issue-pr-index.json"
