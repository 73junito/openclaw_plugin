#!/usr/bin/env bash
# Shell aliases/functions for quick Ollama model runs
# Source this file from your shell (~/.bashrc or ~/.zshrc):
#   source ~/.ollama/scripts/aliases.sh
# Examples:
#   qwen "Write a Python function to..."
#   dsc "Fix this bug in my JS code"
#   r1 "Suggest architecture for microservice"

# Run Qwen2.5-Coder
qwen() {
  local msg
  if [ "$#" -gt 0 ]; then
    msg="$*"
  else
    msg="Respond with ok"
  fi
  ~/.ollama/scripts/run_tuned.sh qwen2.5-coder:7b "$msg"
}

# Run DeepSeek-Coder (6.7B)
dsc() {
  local msg
  if [ "$#" -gt 0 ]; then
    msg="$*"
  else
    msg="Respond with ok"
  fi
  ~/.ollama/scripts/run_tuned.sh deepseek-coder:6.7b "$msg"
}

# Run DeepSeek-R1
r1() {
  local msg
  if [ "$#" -gt 0 ]; then
    msg="$*"
  else
    msg="Respond with ok"
  fi
  ~/.ollama/scripts/run_tuned.sh deepseek-r1:latest "$msg"
}

# Convenience: run raw model without system prompt wrapper
run_raw() {
  if [ "$#" -lt 1 ]; then
    echo "Usage: run_raw <model> [message]"
    return 1
  fi
  local model="$1"
  shift || true
  local msg
  if [ "$#" -gt 0 ]; then
    msg="$*"
  else
    msg="Respond with ok"
  fi
  printf "%s\n\n%s\n" "You are a helpful assistant." "$msg" | ollama run "$model"
}

# --- Short aliases (small, ergonomic helpers) ---
# qc -> Qwen coder; ds -> DeepSeek coder (short forms)
qc() { qwen "$@"; }
ds() { dsc "$@"; }

# Quick GPU memory read (MB): `gpu` or `gpu <nvidia-smi args>`
gpu() {
  if command -v nvidia-smi >/dev/null 2>&1; then
    nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits "$@"
  else
    echo "nvidia-smi not found"
    return 1
  fi
}

# `chat <model> [message]` - keeps the model warm when possible
# Uses `--keepalive` if the installed `ollama` supports it.
chat() {
  if [ "$#" -lt 1 ]; then
    echo "Usage: chat <model> [message]"
    return 1
  fi
  local model="$1"; shift || true
  local msg
  if [ "$#" -gt 0 ]; then
    msg="$*"
  else
    msg="Respond with ok"
  fi
  if ollama run --help 2>&1 | grep -qi keepalive; then
    printf "%s\n\n%s\n" "You are a helpful assistant." "$msg" | ollama run "$model" --keepalive 5m
  else
    printf "%s\n\n%s\n" "You are a helpful assistant." "$msg" | ollama run "$model"
  fi
}
