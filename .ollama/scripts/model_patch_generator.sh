#!/usr/bin/env bash
set -euo pipefail
# model_patch_generator.sh <model> <language> <target-dir> <instruction>
# Calls the tuned wrapper to ask the model for a unified diff patch, saves it,
# and runs the patch workflow.

MODEL="$1"
LANG="$2"
TARGET_DIR="${3:-.}"
shift 3
INSTR="$*"

if [ -z "$MODEL" ] || [ -z "$LANG" ] || [ -z "$INSTR" ]; then
  echo "Usage: $0 <model> <language> <target-dir> <instruction>"
  exit 2
fi

OUTDIR="$HOME/.ollama/generated_patches"
mkdir -p "$OUTDIR"
PATCH_FILE="$OUTDIR/patch_${LANG}_$(date +%s).patch"
LOG_FILE="$OUTDIR/patch_${LANG}_$(date +%s).log"

# Ask the model to produce a unified diff. Keep prompt minimal and explicit.
PROMPT="Produce a unified diff (patch) that updates files in the target project.\nTarget files are relative to the project root.\nOnly output the patch (no commentary).\nProject path: $TARGET_DIR\nInstruction: $INSTR\n"

if ! printf "%s\n" "$PROMPT" | ~/.ollama/scripts/run_tuned.sh "$MODEL" - > "$PATCH_FILE" 2>"$LOG_FILE"; then
  echo "MODEL_PATCH_GENERATION_FAILED: ollama run failed (see $LOG_FILE)"
fi

if [ ! -s "$PATCH_FILE" ]; then
  echo "MODEL_PATCH_GENERATION_FAILED: no patch produced"
  if [ -s "$LOG_FILE" ]; then
    echo "--- model stderr (first 200 lines) ---"
    sed -n '1,200p' "$LOG_FILE"
  fi
  exit 3
fi

echo "Generated patch: $PATCH_FILE"

# Sanitize common wrapper output from models (strip markdown fences and keep from 'diff --git' or '--- ')
# Replace the original file with the cleaned version so the workflow receives a proper unified diff.
CLEAN_FILE="$PATCH_FILE.clean"
awk 'BEGIN{p=0} /^diff --git/ {p=1} p{print}' "$PATCH_FILE" > "$CLEAN_FILE"
if [ ! -s "$CLEAN_FILE" ]; then
  sed -n '/^--- /,$p' "$PATCH_FILE" > "$CLEAN_FILE"
fi
sed -i '/^```/d' "$CLEAN_FILE" || true
sed -i '1{/^$/d}' "$CLEAN_FILE" || true
if [ -s "$CLEAN_FILE" ]; then
  mv "$CLEAN_FILE" "$PATCH_FILE"
fi

# As a fallback, remove any lines that begin with triple-backtick markers
# which some models include like ``` or ```diff
grep -v '^```' "$PATCH_FILE" > "$PATCH_FILE.tmp" || true
mv "$PATCH_FILE.tmp" "$PATCH_FILE" || true
sed -i '1{/^$/d}' "$PATCH_FILE" || true

# Attempt to map any file paths in the patch to the target project's relative paths.
# This helps when models emit full or temp paths (e.g. a/tmp/.../orig/file.php).
if [ -d "$TARGET_DIR" ]; then
  # collect project files (relative paths)
  mapfile -t _proj_files < <(cd "$TARGET_DIR" && find . -type f | sed 's|^./||')
  for _f in "${_proj_files[@]}"; do
    _base=$(basename "$_f")
    # rewrite header lines that mention the basename to use the repo relative path
    awk -v base="${_base}" -v path="${_f}" '
      /^diff --git/ && $0 ~ base { print "diff --git a/" path " b/" path; next }
      /^--- / && $0 ~ base { print "--- a/" path; next }
      /^\+\+\+ / && $0 ~ base { print "+++ b/" path; next }
      { print }
    ' "$PATCH_FILE" > "$PATCH_FILE.tmp" && mv "$PATCH_FILE.tmp" "$PATCH_FILE" || true
  done
  # clean up double slashes that can occur after replacements
  sed -i 's|a//|a/|g; s|b//|b/|g' "$PATCH_FILE" || true
fi

# Finally run the workflow on the sanitized, path-mapped patch
~/.ollama/scripts/patch_workflow.sh "$PATCH_FILE" "$LANG" "$TARGET_DIR"
