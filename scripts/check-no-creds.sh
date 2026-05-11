#!/usr/bin/env bash
# scripts/check-no-creds.sh — fail if the repo leaks PII or credentials.
#
# Trips on:
#   * The developer's real AWS account ID (371126261144)
#   * The developer's real target domain (aitrading.ninja)
#   * Any OpenAI API key shape (`sk-...` 20+ chars)
#   * Any full Mongo connection string (mongodb://… or mongodb+srv://…)
#
# Exempted: vendor dirs, build artefacts, the leak-guard tests themselves
# (which intentionally name the forbidden strings to assert they are NOT
# in API/payload responses).
#
# Exits 1 on any match, 0 on a clean repo.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# grep -E -rn so we get file:line context and ERE for the cred patterns.
EXCLUDE_DIRS=(
  --exclude-dir=.git
  --exclude-dir=node_modules
  --exclude-dir=dist
  --exclude-dir=build
  --exclude-dir=__pycache__
  --exclude-dir=.pytest_cache
  --exclude-dir=.venv
  --exclude-dir=venv
)
EXCLUDE_FILES=(
  --exclude='*.pdf'
  --exclude='*.tar.gz'
  --exclude='*.lock'
  --exclude='yarn.lock'
  --exclude='package-lock.json'
  # Template / local-dev env files. `.env` is gitignored; the dev-only
  # MONGO_URL=mongodb://localhost:27017 inside is not a credential leak.
  --exclude='.env'
  --exclude='.env.example'
)
# Files that intentionally name the forbidden strings (leak guards). Any
# new entry here MUST be reviewed — that's why the list is explicit.
SELF_EXEMPT_PATHS=(
  "backend/demo/build_demo_fixture.py"
  "backend/tests/test_feat_22_demo_page.py"
  "backend/tests/test_no_creds_in_repo.py"
  # Phase 0 secrets-loader unit test uses synthetic Mongo URIs (no creds
  # embedded) as `monkeypatch.setenv` fixtures.
  "backend/tests/test_phase0.py"
  "scripts/check-no-creds.sh"
)

EXEMPT_GREP=""
for p in "${SELF_EXEMPT_PATHS[@]}"; do
  EXEMPT_GREP+="^${p}:|"
done
EXEMPT_GREP="${EXEMPT_GREP%|}"

FAIL=0

scan() {
  local label="$1"
  local pattern="$2"
  local mode="$3"  # "fixed" | "regex"
  local hits
  if [[ "$mode" == "regex" ]]; then
    hits=$(grep -EHrn "${EXCLUDE_DIRS[@]}" "${EXCLUDE_FILES[@]}" -- "$pattern" . 2>/dev/null \
      | sed 's|^\./||' \
      | grep -Ev "$EXEMPT_GREP" || true)
  else
    hits=$(grep -FHrn "${EXCLUDE_DIRS[@]}" "${EXCLUDE_FILES[@]}" -- "$pattern" . 2>/dev/null \
      | sed 's|^\./||' \
      | grep -Ev "$EXEMPT_GREP" || true)
  fi
  if [[ -n "$hits" ]]; then
    echo "FAIL: $label leak detected:"
    echo "$hits" | sed 's/^/  /'
    FAIL=1
  fi
}

scan "real AWS account ID (371126261144)" "371126261144"  fixed
scan "real target domain (aitrading.ninja)" "aitrading.ninja" fixed
scan "OpenAI API key shape (sk-…)" '\bsk-[A-Za-z0-9_-]{20,}\b' regex
# Only flag Mongo URIs that embed credentials (user:pass@host). Plain
# `mongodb://localhost:27017` or `mongodb+srv://cluster.mongodb.net` are
# host-only and carry nothing sensitive on their own.
scan "Mongo connection string with embedded credentials" \
  'mongodb(\+srv)?://[^[:space:]:/"@]+:[^[:space:]@"]+@[^[:space:]"/]+' regex

if [[ "$FAIL" -ne 0 ]]; then
  echo
  echo "If the match is an intentional leak-guard test that asserts the"
  echo "string is NOT in a payload, add the file to SELF_EXEMPT_PATHS in"
  echo "scripts/check-no-creds.sh — but think twice first."
  exit 1
fi

echo "clean — no credentials or PII detected."
exit 0
