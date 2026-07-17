#!/usr/bin/env bash
set -uo pipefail
export npm_config_cache="${npm_config_cache:-/Users/max/Library/Caches/grok-worker/npm}"
mkdir -p .grok-output/verification

run_step() {
  local name="$1"
  shift
  set +e
  "$@" > ".grok-output/verification/${name}.log" 2>&1
  local ec=$?
  set -e
  echo "${name}_exit:${ec}"
  return 0
}

run_step typecheck npm run typecheck
run_step build npm run build
run_step npm-test npm test
run_step boundary npm run check:boundary
run_step package npm run package
run_step package-smoke npm run package:smoke
run_step cli-hash-proof node scripts/cli-hash-proof.mjs
run_step git-diff-check git diff --check

{
  echo "=== git status ==="
  git status --short
  echo ""
  echo "=== git diff --stat ==="
  git diff --stat
} > .grok-output/verification/git-status-review.log 2>&1
echo "git_review_done"
