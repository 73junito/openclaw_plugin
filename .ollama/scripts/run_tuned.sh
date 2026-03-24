#!/usr/bin/env bash
# Wrapper to run an Ollama model by piping the saved system prompt
# Usage: ./run_tuned.sh <model-name> ["user message"]

MODEL="$1"
USER_MSG="${2-Respond with ok}"

if [ -z "$MODEL" ]; then
  echo "Usage: $0 <model-name> [\"user message\"]"
  exit 1
fi

# If caller passes '-' as the user message, read the message from stdin.
if [ "${USER_MSG:-}" = "-" ]; then
  USER_MSG="$(cat -)"
fi

PROMPT_FILE="$(dirname "$0")/../system_prompts/multi_language_system.txt"
if [ -f "$PROMPT_FILE" ]; then
  PROMPT=$(sed -n '1,200p' "$PROMPT_FILE" | tr '\n' '\n')
else
  PROMPT="You are a helpful assistant."
fi

# Combine system prompt and user message and pipe to ollama run (no unsupported flags)
printf "%s\n\n%s\n" "$PROMPT" "$USER_MSG" | ollama run "$MODEL"
