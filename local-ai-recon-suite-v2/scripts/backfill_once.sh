#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
python recon/migrate_state.py
python recon/backfill.py
python recon/index_chroma.py
