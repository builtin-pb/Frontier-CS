#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SOLUTION="/work/execution_env/solution_env/solution.json"

exec python3 "$SCRIPT_DIR/evaluator.py" "$SOLUTION"
