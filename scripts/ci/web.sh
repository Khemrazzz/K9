#!/usr/bin/env bash
# CI stage "web": clean install from the lockfile, strict typecheck, lint with zero
# warnings, unit tests and the production build. Needs Node 22. No secrets are required:
# configuration is read at request time, not at build time.
set -euo pipefail

cd "$(dirname "$0")/../../apps/web"

echo "::group::Install (npm ci)"
npm ci --no-audit --no-fund
echo "::endgroup::"

echo "::group::Typecheck"
npm run typecheck
echo "::endgroup::"

echo "::group::Lint"
npm run lint
echo "::endgroup::"

echo "::group::Unit tests"
npm test
echo "::endgroup::"

echo "::group::Production build"
npm run build
echo "::endgroup::"
