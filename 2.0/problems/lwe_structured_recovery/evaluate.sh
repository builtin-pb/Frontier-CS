#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SOLUTION="${1:-/work/execution_env/solution_env/solution.json}"

if [[ -n "${FCS_PYTHON:-}" ]]; then
  PYTHON_CANDIDATES=("$FCS_PYTHON")
else
  PYTHON_CANDIDATES=(python3.12 python3.11 python3)
fi

PYTHON_BIN=""
for CANDIDATE in "${PYTHON_CANDIDATES[@]}"; do
  if command -v "$CANDIDATE" >/dev/null 2>&1 \
    && "$CANDIDATE" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' \
      >/dev/null 2>&1; then
    PYTHON_BIN="$CANDIDATE"
    break
  fi
done

if [[ -z "$PYTHON_BIN" ]]; then
  echo "Error: Python 3.11 or newer is required" >&2
  exit 1
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/evaluator.py" "$SOLUTION"
