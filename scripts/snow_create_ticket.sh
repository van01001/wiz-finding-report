#!/usr/bin/env bash
# ServiceNow incident auto-fill — macOS / Linux counterpart of snow_create_ticket.bat
# Reads Output/snow_ticket_pending.json, written by the report workflow.
set -u
# Run from the SKILL ROOT (the parent of scripts/) so Output/ resolves to the same
# place the report workflow wrote the pending JSON.
cd "$(dirname "$0")/.."

PY=python3
command -v python3 >/dev/null 2>&1 || PY=python

exec "$PY" scripts/snow_ticket_creator.py "$@"
