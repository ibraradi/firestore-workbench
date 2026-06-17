#!/usr/bin/env bash
# Launch Firestore Workbench (opens the GUI in your browser).
# Linux / macOS counterpart of run.bat.  Usage:  ./run.sh [--port 8799] [--proxy http://127.0.0.1:8080] ...
cd "$(dirname "$0")" || exit 1
if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi
exec "$PY" firestore_workbench.py "$@"
