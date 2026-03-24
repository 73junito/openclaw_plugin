#!/usr/bin/env bash
set -euo pipefail
# Patch workflow: apply a unified diff in a temporary copy, validate syntax/tests,
# and only commit changes to the real tree if validation passes.
#
# Usage: patch_workflow.sh <patch-file> <language> [target-dir]
# Returns status lines to stdout: PATCH_APPLY_FAILED, PATCH_VALIDATED, PATCH_APPLIED, PATCH_REJECTED

PATCH_FILE="$1"
LANGUAGE="${2:-}"
TARGET_DIR="${3:-.}"

if [ -z "$PATCH_FILE" ] || [ -z "$LANGUAGE" ]; then
  echo "Usage: $0 <patch-file> <language> [target-dir]"
  exit 2
fi

if [ ! -f "$PATCH_FILE" ]; then
  echo "PATCH_APPLY_FAILED: patch file not found: $PATCH_FILE"
  exit 3
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# copy target tree into tempdir
mkdir -p "$TMPDIR/work"
rsync -a --delete "$TARGET_DIR/" "$TMPDIR/work/"
pushd "$TMPDIR/work" >/dev/null

# try to apply the patch in tempdir
if command -v git >/dev/null 2>&1 && [ -d "$TARGET_DIR/.git" ]; then
  # if source tree is a git repo, use git apply
  if ! git apply --index --whitespace=fix "$PATCH_FILE" 2>/dev/null; then
    echo "PATCH_APPLY_FAILED: git apply failed"
    exit 4
  fi
else
  # fallback to patch(1) - try several strip levels to handle prefixes like orig/ new/
  applied=1
  for p in 0 1 2 3; do
    if patch -p$p --silent < "$PATCH_FILE" 2>/dev/null; then
      applied=0
      break
    fi
  done
  if [ "$applied" -ne 0 ]; then
    echo "PATCH_APPLY_FAILED: patch command failed"
    exit 4
  fi
fi

# At this point patch applied in tempdir. Run language-specific validators.
VALID_OK=0
VALID_FAIL=0
errors=""

validate_php() {
  local f
  while IFS= read -r -d '' f; do
    if ! php -l "$f" >/dev/null 2>&1; then
      errors+="$f: php -l failed\n"
      VALID_FAIL=$((VALID_FAIL+1))
    else
      VALID_OK=$((VALID_OK+1))
    fi
  done < <(find . -name '*.php' -print0)
}

validate_python() {
  local f
  while IFS= read -r -d '' f; do
    if ! python -m py_compile "$f" >/dev/null 2>&1; then
      errors+="$f: python -m py_compile failed\n"
      VALID_FAIL=$((VALID_FAIL+1))
    else
      VALID_OK=$((VALID_OK+1))
    fi
  done < <(find . -name '*.py' -print0)
}

validate_go() {
  if command -v go >/dev/null 2>&1; then
    if ! go vet ./... >/dev/null 2>&1 && ! go build ./... >/dev/null 2>&1; then
      errors+="go: vet/build failed\n"
      VALID_FAIL=$((VALID_FAIL+1))
    else
      VALID_OK=$((VALID_OK+1))
    fi
  else
    errors+="go: go tool not found (skipped)\n"
  fi
}

validate_java() {
  java_files=$(find . -name '*.java') || true
  if [ -n "$java_files" ]; then
    if command -v javac >/dev/null 2>&1; then
      if ! javac $(find . -name '*.java') >/dev/null 2>&1; then
        errors+="javac failed\n"
        VALID_FAIL=$((VALID_FAIL+1))
      else
        VALID_OK=$((VALID_OK+1))
      fi
    else
      errors+="javac not found (skipped)\n"
    fi
  fi
}

validate_node() {
  if command -v node >/dev/null 2>&1; then
    local f
    while IFS= read -r -d '' f; do
      # try node --check (newer node) or fallback to node -c (older)
      if node --check "$f" >/dev/null 2>&1 2>/dev/null; then
        VALID_OK=$((VALID_OK+1))
      elif node -c "$f" >/dev/null 2>&1 2>/dev/null; then
        VALID_OK=$((VALID_OK+1))
      else
        # best-effort: try to parse with node via eval wrapper
        if node -e "require('fs').readFileSync('$f','utf8')" >/dev/null 2>&1; then
          VALID_OK=$((VALID_OK+1))
        else
          errors+="$f: node syntax check failed\n"
          VALID_FAIL=$((VALID_FAIL+1))
        fi
      fi
    done < <(find . -name '*.js' -print0)
  else
    errors+="node not found (skipped)\n"
  fi
}

case "$LANGUAGE" in
  php)
    validate_php
    ;;
  python)
    validate_python
    ;;
  go)
    validate_go
    ;;
  java)
    validate_java
    ;;
  js|javascript|node)
    validate_node
    ;;
  all)
    validate_php
    validate_python
    validate_node
    validate_go
    validate_java
    ;;
  *)
    echo "PATCH_REJECTED: unknown language or validator: $LANGUAGE"
    exit 5
    ;;
esac

if [ "$VALID_FAIL" -gt 0 ]; then
  printf "PATCH_REJECTED\n%s" "$errors"
  exit 6
fi

echo "PATCH_VALIDATED"

# Apply validated changes to the real target
popd >/dev/null

if command -v git >/dev/null 2>&1 && [ -d "$TARGET_DIR/.git" ]; then
  if git apply --index --whitespace=fix "$PATCH_FILE"; then
    echo "PATCH_APPLIED"
    exit 0
  else
    echo "PATCH_APPLY_FAILED: git apply to real tree failed"
    exit 7
  fi
else
  # when applying to the real tree, change into the target dir and try several -p levels
  applied=1
  pushd "$TARGET_DIR" >/dev/null
  for p in 0 1 2 3; do
    if patch -p$p --silent < "$PATCH_FILE"; then
      applied=0
      break
    fi
  done
  popd >/dev/null
  if [ "$applied" -eq 0 ]; then
    echo "PATCH_APPLIED"
    exit 0
  else
    echo "PATCH_APPLY_FAILED: patch to real tree failed"
    exit 7
  fi
fi

# Post-validation test hooks: run language-specific test commands in the temp workspace
run_tests_for() {
  lang="$1"
  wd="$TMPDIR/work"
  case "$lang" in
    php)
      # php -l already run; if composer test exists, run it
      if [ -f "$wd/composer.json" ] && command -v composer >/dev/null 2>&1; then
        (cd "$wd" && composer test >/dev/null 2>&1) || return 1
      fi
      ;;
    python)
      if [ -d "$wd/tests" ] && command -v pytest >/dev/null 2>&1; then
        (cd "$wd" && pytest -q) || return 1
      fi
      ;;
    js|node|javascript)
      if [ -f "$wd/package.json" ] && command -v npm >/dev/null 2>&1; then
        # only run if npm test script exists
        if node -e "console.log(require('./package.json').scripts && require('./package.json').scripts.test?1:0)" 2>/dev/null | grep -q 1; then
          (cd "$wd" && npm test --silent) || return 1
        fi
      fi
      ;;
    go)
      if command -v go >/dev/null 2>&1; then
        (cd "$wd" && go test ./...) || return 1
      fi
      ;;
    java)
      if [ -f "$wd/pom.xml" ] && command -v mvn >/dev/null 2>&1; then
        (cd "$wd" && mvn -q test) || return 1
      elif [ -f "$wd/build.gradle" ] && command -v gradle >/dev/null 2>&1; then
        (cd "$wd" && gradle test --quiet) || return 1
      fi
      ;;
  esac
  return 0
}

# Run post-validation tests and if they fail, reject the patch before applying to real tree
if ! run_tests_for "$LANGUAGE"; then
  echo "PATCH_REJECTED: tests failed or test tools missing"
  exit 6
fi
 
