#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/picokey-web}"
REPO="${REPO:-github.com-picokey-webflasher:joyanes97/picokey-webflasher.git}"

if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" -c safe.directory="$APP_DIR" pull --ff-only
else
  rm -rf "$APP_DIR"
  git clone "$REPO" "$APP_DIR"
fi

cd "$APP_DIR"
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq pcscd libpcsclite-dev swig >/dev/null
fi
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
mkdir -p data images build
chown -R picokey:picokey "$APP_DIR"
cp picokey-web.service /etc/systemd/system/picokey-web.service
systemctl daemon-reload
systemctl enable picokey-web
systemctl restart picokey-web
systemctl is-active picokey-web
