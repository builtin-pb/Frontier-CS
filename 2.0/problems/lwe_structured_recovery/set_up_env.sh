#!/usr/bin/env bash
set -euo pipefail

if command -v python3 >/dev/null 2>&1; then
  exit 0
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "Error: python3 is required and apt-get is unavailable" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends python3
