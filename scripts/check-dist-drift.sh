#!/usr/bin/env bash
set -euo pipefail

npm ci
npm run build

# `git status --porcelain` reports BOTH modified tracked files AND untracked
# generated assets — `git diff --quiet` misses the untracked case and would
# pass a build that emitted brand-new files nobody committed.
drift="$(git status --porcelain -- dist/)"
if [ -n "$drift" ]; then
    echo "Committed dist/ is stale — rebuild with 'npm ci && npm run build' and commit the result." >&2
    echo "$drift" >&2
    exit 1
fi
