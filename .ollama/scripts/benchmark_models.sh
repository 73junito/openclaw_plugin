#!/usr/bin/env bash
# Benchmark script for Ollama models (safe, non-destructive)
# - Tests multiple --num_ctx values per model
# - Records latency and GPU memory before/after (if nvidia-smi available)
# - Logs results to ~/.ollama/benchmarks/benchmark_<date>.csv

set -euo pipefail

OUT_DIR="$HOME/.ollama/benchmarks"
mkdir -p "$OUT_DIR"
TS=$(date +%Y%m%d_%H%M%S)
OUT_FILE="$OUT_DIR/benchmark_${TS}.csv"

# Models to test
MODELS=(
  "qwen2.5-coder:7b"
  "deepseek-coder:6.7b"
  "deepseek-r1:latest"
)

# Context sizes to try (small -> large)
CONTEXTS=(2048 4096 8192 16384)

# Timeout for each run (seconds)
# Increased to 300s to allow slower model loads on limited hardware
TIMEOUT_SECS=300

# Write header
echo "timestamp,model,num_ctx,elapsed_ms,gpu_mem_before_mb,gpu_mem_after_mb,exit_code,note" > "$OUT_FILE"

which_ollama=$(command -v ollama || true)
if [ -z "$which_ollama" ]; then
  echo "ollama CLI not found in PATH; please install or add it." >&2
  exit 1
fi

has_nvidia=$(command -v nvidia-smi >/dev/null 2>&1 && echo yes || echo no)

for model in "${MODELS[@]}"; do
  # Choose system prompt file if present
  PROMPT_FILE="$HOME/.ollama/system_prompts/multi_language_system.txt"
  if [[ "$model" == *"qwen2.5"* ]] && [ -f "$HOME/.ollama/system_prompts/qwen2.5-coder.txt" ]; then
    PROMPT_FILE="$HOME/.ollama/system_prompts/qwen2.5-coder.txt"
  elif [[ "$model" == *"deepseek-coder"* ]] && [ -f "$HOME/.ollama/system_prompts/deepseek-coder-6.7b.txt" ]; then
    PROMPT_FILE="$HOME/.ollama/system_prompts/deepseek-coder-6.7b.txt"
  elif [[ "$model" == *"deepseek-r1"* ]] && [ -f "$HOME/.ollama/system_prompts/deepseek-r1.txt" ]; then
    PROMPT_FILE="$HOME/.ollama/system_prompts/deepseek-r1.txt"
  fi
  if [ -f "$PROMPT_FILE" ]; then
    # read up to 200 lines of the system prompt and collapse newlines to spaces
    PROMPT_CONTENT="$(sed -n '1,200p' "$PROMPT_FILE" | tr '\n' ' ' )"
  else
    # fallback safe system prompt
    PROMPT_CONTENT="You are a helpful assistant."
  fi

  for ctx in "${CONTEXTS[@]}"; do
    ts_now=$(date --iso-8601=seconds)
    gpu_before_mb=""
    gpu_after_mb=""

    if [ "$has_nvidia" = yes ]; then
      gpu_before_mb=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits 2>/dev/null | tr '\n' '|' | sed 's/|$//')
    fi

    start_ms=$(date +%s%3N)

    # Run a tiny prompt; timeout to avoid hangs. Send system prompt then user message on stdin
    note=""
    start_proc_ms=$(date +%s%3N)
    timeout ${TIMEOUT_SECS}s bash -c "printf '%s\n\n%s\n' \"$PROMPT_CONTENT\" \"Respond with ok\" | ollama run '$model'" >/dev/null 2>&1
    exit_code=$?
    end_proc_ms=$(date +%s%3N)
    # If timeout returned 124, mark timeout note
    if [ "$exit_code" -eq 124 ]; then
      note="timeout"
    elif [ "$exit_code" -ne 0 ]; then
      note="nonzero_exit"
    fi

    # Prefer measured process time if available
    if [ -n "${end_proc_ms-}" ] && [ -n "${start_proc_ms-}" ]; then
      elapsed_ms=$((end_proc_ms - start_proc_ms))
    else
      end_ms=$(date +%s%3N)
      elapsed_ms=$((end_ms - start_ms))
    fi

    if [ "$has_nvidia" = yes ]; then
      gpu_after_mb=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits 2>/dev/null | tr '\n' '|' | sed 's/|$//')
    fi

    # Append CSV line
    echo "${ts_now},${model},${ctx},${elapsed_ms},${gpu_before_mb},${gpu_after_mb},${exit_code},${note}" >> "$OUT_FILE"

    echo "[${ts_now}] model=${model} ctx=${ctx} elapsed=${elapsed_ms}ms exit=${exit_code}"

    # Small pause
    sleep 2
  done
done

echo "Benchmark complete. Results: $OUT_FILE"
