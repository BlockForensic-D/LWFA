#!/usr/bin/env bash
# v0.5.1 entry point; retained name for callers of the previous release.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$ROOT/scripts/run-update.sh" "$@"
