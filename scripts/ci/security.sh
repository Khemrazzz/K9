#!/usr/bin/env bash
# CI stage "security": secret scanning and dependency vulnerability gates.
# Needs Docker, Node 22 and the .NET 10 SDK. Reports go to artifacts/security/.
# Every check exits non-zero on a finding *or* on a scanner error, so a broken scanner
# can never turn into a passing run.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
out="$root/artifacts/security"
rm -rf "$out"
mkdir -p "$out/tree"

# Pinned by digest: a moved tag cannot change what runs.
gitleaks_image="ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

# Docker Desktop on Windows (Git Bash) needs Windows paths and no MSYS path rewriting.
export MSYS_NO_PATHCONV=1
host_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

group() { echo "::group::$1"; }
endgroup() { echo "::endgroup::"; }

group "Secrets: full git history"
# Needs the full history (CI checks out with fetch-depth: 0).
docker run --rm \
  -v "$(host_path "$root"):/repo:ro" \
  -v "$(host_path "$out"):/out" \
  "$gitleaks_image" git /repo \
  --gitleaks-ignore-path /repo/.gitleaksignore \
  --redact --no-banner --verbose --exit-code 1 \
  --report-format json --report-path /out/gitleaks-history.json
endgroup

group "Secrets: files in this change (tracked and untracked, minus .gitignore)"
# Scans exactly what would be committed: catches uncommitted secrets locally, and never
# reads node_modules, build output or local .env files.
git ls-files -co --exclude-standard -z | xargs -0 cp --parents -t "$out/tree"
docker run --rm \
  -v "$(host_path "$out"):/scan" \
  "$gitleaks_image" dir /scan/tree \
  --gitleaks-ignore-path /scan/tree/.gitleaksignore \
  --redact --no-banner --verbose --exit-code 1 \
  --report-format json --report-path /scan/gitleaks-tree.json
rm -rf "$out/tree"
endgroup

# Node gets relative paths below: Git Bash and Windows node disagree on absolute ones.
group "NuGet: known vulnerabilities (direct and transitive)"
dotnet restore apps/api/K9.slnx --locked-mode
dotnet list apps/api/K9.slnx package --vulnerable --include-transitive --format json > artifacts/security/nuget-vulnerable.json
node scripts/ci/check-nuget-audit.mjs artifacts/security/nuget-vulnerable.json
endgroup

group "npm: production dependencies (no exceptions)"
(cd apps/web && npm audit --omit=dev --audit-level=low)
endgroup

group "npm: development dependencies (documented exceptions only)"
node scripts/ci/check-npm-audit.mjs apps/web security/dependency-exceptions.json artifacts/security/npm-audit.json
endgroup

echo "Security gates passed."
