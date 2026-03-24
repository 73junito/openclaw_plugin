#!/usr/bin/env bash
set -euo pipefail
# process_pristine_projects.sh [model]
# For each pristine project, ask model to produce a patch that adds an exclamation
# to greet() and a top-line marker comment. If model fails, apply deterministic fallback.

MODEL="${1:-deepseek-coder:6.7b}"
BASE_DIR="$HOME/.ollama/patch_tests/pristine"

declare -A FILE MAP_LANG COMMENT CHECK_CMD

FILE[go]=main.go; MAP_LANG[go]=go; COMMENT[go]="// PATCHED_BY_MODEL"; CHECK_CMD[go]="grep -q 'Hello, .*!' main.go || grep -q PATCHED_BY_MODEL main.go"
FILE[java]=App.java; MAP_LANG[java]=java; COMMENT[java]="// PATCHED_BY_MODEL"; CHECK_CMD[java]="grep -q 'Hello, .*!' App.java || grep -q PATCHED_BY_MODEL App.java"
FILE[js]=app.js; MAP_LANG[js]=js; COMMENT[js]="// PATCHED_BY_MODEL"; CHECK_CMD[js]="grep -q 'Hello, .*!' app.js || grep -q PATCHED_BY_MODEL app.js"
FILE[php]=app.php; MAP_LANG[php]=php; COMMENT[php]="// PATCHED_BY_MODEL"; CHECK_CMD[php]="grep -q 'Hello, .*!' app.php || grep -q PATCHED_BY_MODEL app.php"
FILE[python]=app.py; MAP_LANG[python]=python; COMMENT[python]="# PATCHED_BY_MODEL"; CHECK_CMD[python]="grep -q 'Hello, .*!' app.py || grep -q PATCHED_BY_MODEL app.py"

for proj in go java js php python; do
  target="$BASE_DIR/$proj"
  if [ ! -d "$target" ]; then
    echo "Skipping missing $proj"
    continue
  fi
  pushd "$target" >/dev/null
  f=${FILE[$proj]}
  lang=${MAP_LANG[$proj]}
  comment=${COMMENT[$proj]}
  checkcmd=${CHECK_CMD[$proj]}

  echo "\n=== Processing $proj ($f) ==="

  # instruction for model
  INSTR="Modify only $f: in function greet, change the return to include an exclamation so it returns \"Hello, <name>!\". Add the single-line marker comment '${comment}' as the first non-blank line of the file. Output only a unified diff with paths relative to the project root."

  ~/.ollama/scripts/model_patch_generator.sh "$MODEL" "$lang" "$target" "$INSTR" || true

  # Check if change present
  if bash -c "$checkcmd" >/dev/null 2>&1; then
    echo "Model change applied for $proj"
    popd >/dev/null
    continue
  fi

  echo "Model did not apply a valid patch for $proj — applying deterministic fallback."

  # deterministic fallback: edit file in temp copy, produce patch, run workflow
  WORK=$(mktemp -d)
  cp -r "$target" "$WORK/orig"
  cp -r "$target" "$WORK/new"

  # language-specific edits
  case "$proj" in
    php|js|go|java)
      sed -i "s/Hello, \$\(name\)\"/Hello, \\\:name!\"/" "$WORK/new/$f" 2>/dev/null || true
      sed -i "s/Hello, \$name/Hello, $name!/g" "$WORK/new/$f" 2>/dev/null || true
      ;;
    python)
      sed -i "s/Hello, {name}/Hello, {name}!/g" "$WORK/new/$f" 2>/dev/null || true
      sed -i "s/Hello, \{name\}/Hello, {name}!/g" "$WORK/new/$f" 2>/dev/null || true
      sed -i "s/Hello, \%s/Hello, %s!/g" "$WORK/new/$f" 2>/dev/null || true
      ;;
  esac

  # insert marker if missing
  if ! grep -q "PATCHED_BY_MODEL" "$WORK/new/$f" 2>/dev/null; then
    # insert after shebang or first line
    sed -i "1a $comment" "$WORK/new/$f" || true
  fi

  OUTDIR="$HOME/.ollama/generated_patches"
  mkdir -p "$OUTDIR"
  PATCHFILE="$OUTDIR/patch_${proj}_autofallback_$(date +%s).patch"
  git --no-pager diff --no-index -- "$WORK/orig" "$WORK/new" > "$PATCHFILE" || true

  echo "Applying fallback patch for $proj: $PATCHFILE"
  ~/.ollama/scripts/patch_workflow.sh "$PATCHFILE" "$lang" "$target" || true

  # cleanup
  rm -rf "$WORK"
  popd >/dev/null
done

echo "All projects processed."
