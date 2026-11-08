#!/usr/bin/env python3
# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Refreshes emredius/data/oui.tsv from the IEEE OUI registry (run monthly by emredius-oui.timer).

  update_oui.py [--url URL] [--file local.csv] [--out PATH]

The new table replaces the old one atomically and only if it passes sanity checks;
on any failure the existing file stays untouched and the exit code is non-zero.
"""
import argparse
import csv
import io
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from emredius.core import oui  # noqa: E402

DEFAULT_URL = "https://standards-oui.ieee.org/oui/oui.csv"
MIN_ENTRIES = 10000
MAX_BYTES = 30 * 1024 * 1024


def parse_ieee_csv(text):
    """IEEE csv (Registry,Assignment,Organization Name,Address) -> {PREFIX: vendor}."""
    table = {}
    for row in csv.DictReader(io.StringIO(text)):
        prefix = (row.get("Assignment") or "").strip().upper()
        name = " ".join((row.get("Organization Name") or "").split())
        if len(prefix) == 6 and name and all(c in "0123456789ABCDEF" for c in prefix):
            table[prefix] = name
    return table


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "emredius-oui-updater"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("response too large")
    return data.decode("utf-8-sig")


def write_atomic(table, out):
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        for prefix in sorted(table):
            f.write(f"{prefix}\t{table[prefix]}\n")
    os.replace(tmp, out)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=os.environ.get("EMREDIUS_OUI_URL", DEFAULT_URL))
    ap.add_argument("--file", help="read a local oui.csv instead of downloading")
    ap.add_argument("--out", default=oui.oui_path())
    args = ap.parse_args(argv)
    try:
        if args.file:
            with open(args.file, encoding="utf-8-sig") as f:
                text = f.read()
        else:
            text = fetch(args.url)
        table = parse_ieee_csv(text)
    except Exception as e:  # noqa: BLE001 - any failure must leave the old file alone
        print(f"OUI_UPDATE_FAILED:{e}", file=sys.stderr)
        return 1
    if len(table) < MIN_ENTRIES:
        print(f"OUI_UPDATE_FAILED:only {len(table)} entries (min {MIN_ENTRIES}), keeping old file", file=sys.stderr)
        return 1
    write_atomic(table, args.out)
    print(f"OUI_UPDATED:{len(table)} entries -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
