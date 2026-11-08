#!/bin/sh
# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
# Compatibility entry point for radius-backup.service / cron: `backup.sh [--full|--sql]` (default --full).
# The DB password is never on a command line: mysqldump reads MYSQL_DEFAULTS_FILE.
DIR=$(cd "$(dirname "$0")/.." && pwd)
PY="$DIR/.venv/bin/python"
[ -x "$PY" ] || PY=python3.12
exec "$PY" "$DIR/scripts/maintenance.py" backup "$@"
