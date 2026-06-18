#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../deploy/local"
docker compose up --build
