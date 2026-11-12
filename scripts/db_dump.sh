#!/bin/bash
# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
# Verified DB dump for deploy backups: db_dump.sh <out.sql.gz> [db]   (default db: radius)
# Uses the same defaults file as the panel (no password on the command line), fails loudly and checks the result:
# mysqldump exit status (pipefail), gzip integrity and mysqldump's "Dump completed" trailer.
set -o pipefail
OUT=${1:?usage: db_dump.sh <out.sql.gz> [db]}
DB=${2:-radius}
CNF=${MYSQL_DEFAULTS_FILE:-/etc/emredius/my.cnf}
[ -r "$CNF" ] || { echo "DB_DUMP_FAILED: $CNF not readable (run as root)" >&2; exit 1; }
umask 077
if ! mysqldump --defaults-extra-file="$CNF" --single-transaction --routines --triggers --events "$DB" | gzip > "$OUT.part"; then
  rm -f "$OUT.part"; echo "DB_DUMP_FAILED: mysqldump/gzip error for $DB" >&2; exit 1
fi
if ! gzip -t "$OUT.part" || ! zcat "$OUT.part" | tail -n 3 | grep -q "Dump completed"; then
  rm -f "$OUT.part"; echo "DB_DUMP_FAILED: dump of $DB incomplete" >&2; exit 1
fi
mv "$OUT.part" "$OUT"
echo "DB_DUMP_OK:$OUT ($(stat -c %s "$OUT") bytes)"
