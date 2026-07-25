#!/usr/bin/env bash
# Wiz API login (IdP / SSO) — macOS / Linux counterpart of login.bat
set -u
cd "$(dirname "$0")"

cat <<'BANNER'
============================================================
 Wiz API Login (IdP / SSO)
============================================================

 1. Your installed Edge/Chrome will open at the Wiz login page.
 2. Sign in via your organization's IdP / SSO (+ MFA if prompted).
 3. Wait for the Wiz DASHBOARD to fully load.
 4. Come back here and press ENTER.

BANNER

# python3 on most systems; fall back to python if that is what is on PATH.
PY=python3
command -v python3 >/dev/null 2>&1 || PY=python

if "$PY" wiz_fetch.py login "$@"; then
    echo
    echo " Login successful."
else
    echo
    echo " Login failed. Check the error above and try again."
    echo " If the browser never opened, try: $PY wiz_fetch.py login --channel chrome"
    exit 1
fi
