#!/bin/bash
# deploy.sh — stiahne najnovší kód a reštartuje službu
set -e

APP_DIR="/opt/portscanner"
SERVICE="scanner"
BRANCH="claude/networking-security-project-JEH1I"

echo "[deploy] $(date) — spúšťam nasadenie..."

cd "$APP_DIR"

# Stiahnuť zmeny
git fetch origin
git reset --hard "origin/$BRANCH"

# Aktualizovať závislosti (len ak sa zmenil requirements.txt)
if git diff HEAD@{1} HEAD --name-only 2>/dev/null | grep -q "requirements.txt"; then
    echo "[deploy] Aktualizujem závislosti..."
    ./venv/bin/pip install -r requirements.txt -q
fi

# Reštartovať službu
echo "[deploy] Reštartujem službu..."
systemctl restart "$SERVICE"

echo "[deploy] Hotovo ✓"
