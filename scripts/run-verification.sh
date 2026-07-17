#!/usr/bin/env bash
set -euo pipefail
export npm_config_cache="${npm_config_cache:-/Users/max/Library/Caches/grok-worker/npm}"
mkdir -p .grok-output/verification

npm run typecheck > .grok-output/verification/typecheck.log 2>&1
echo "typecheck_exit:$?"

npm run build > .grok-output/verification/build.log 2>&1
echo "build_exit:$?"

npm test > .grok-output/verification/npm-test.log 2>&1
echo "test_exit:$?"

node scripts/cli-hash-proof.mjs > .grok-output/verification/cli-hash-proof.log 2>&1
echo "proof_exit:$?"

{
  echo "=== git status ==="
  git status --short
  echo ""
  echo "=== git diff --stat ==="
  git diff --stat
} > .grok-output/verification/git-status-review.log 2>&1
echo "git_review_done"
