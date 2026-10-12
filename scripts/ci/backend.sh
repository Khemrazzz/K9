#!/usr/bin/env bash
# CI stage "backend": locked restore, Release build (warnings and vulnerable packages are
# errors), all unit and integration tests against real Postgres (Testcontainers), and the
# security regression gate. Needs the .NET 10 SDK and Docker.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
results="artifacts/backend-tests"
rm -rf "$results"

echo "::group::Restore (locked)"
dotnet restore apps/api/K9.slnx --locked-mode
echo "::endgroup::"

echo "::group::Build (Release)"
dotnet build apps/api/K9.slnx --configuration Release --no-restore
echo "::endgroup::"

echo "::group::Tests"
dotnet test apps/api/K9.slnx --configuration Release --no-build \
  --logger "trx;LogFileName=backend.trx" --logger "console;verbosity=normal" \
  --results-directory "$results"
echo "::endgroup::"

node scripts/ci/verify-test-results.mjs backend "$results/backend.trx"
