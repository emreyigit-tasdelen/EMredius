#!/bin/sh
# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
# Entry point of emredius-backup-verify.service: restore-tests the newest DB backup (see backup_verify.py).
DIR=$(cd "$(dirname "$0")/.." && pwd)
PY="$DIR/.venv/bin/python"
[ -x "$PY" ] || PY=python3.12
exec "$PY" "$DIR/scripts/backup_verify.py" "$@"
