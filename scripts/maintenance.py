#!/usr/bin/env python3
# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Scheduled maintenance jobs (run by systemd timers, see deploy/systemd/).

  maintenance.py backup [--sql|--full]   backup into BACKUP_DIR + rotation by the panel's policy (default: full)
  maintenance.py archive5651 [--date D] [--ignore-clock]
                                         signed daily 5651 archive of radacct (default: yesterday + missed days;
                                         deferred while the clock is not NTP-synced)
"""
import argparse
import logging
import os
import sys
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from emredius.config import build_config  # noqa: E402
from emredius.core import db, system  # noqa: E402
from emredius.services import audit5651, backups, chrony, timesync  # noqa: E402
from emredius.services.radius_users import ServiceError  # noqa: E402

log = logging.getLogger("emredius.maintenance")
# archive5651 postponed because the clock is not NTP-synced: not a failure (emredius-5651.service lists it in
# SuccessExitStatus=), so the unit stays healthy and the deferral is only logged. Real errors exit 1.
EXIT_DEFERRED = 75  # EX_TEMPFAIL


def run_backup(cfg, kind):
    path = backups.create_backup(cfg, kind)
    _, max_count = backups.get_policy()
    removed = backups.prune(cfg["BACKUP_DIR"], max_count)
    print(("FULL" if kind == "full" else "SQL") + "_BACKUP_CREATED:" + path)
    if removed:
        print(f"ROTATED_OLD_BACKUPS:{removed}")


def run_archive(cfg, day, catch_up=True, ignore_clock=False):
    """Archives `day`, plus every earlier day missed since the last archived one (catch_up). Deferred (EXIT_DEFERRED)
    while the clock is not NTP-synced: 'yesterday' and the radacct timestamps would not be trustworthy."""
    tracking = chrony.tracking_info()
    st = timesync.evaluate(tracking)
    if st["level"] == "crit" and not ignore_clock:
        print("ARCHIVE_DEFERRED:" + st["message"], file=sys.stderr)
        return EXIT_DEFERRED
    archive_dir = cfg["ARCHIVE_5651_DIR"]
    for d in (audit5651.pending_days(archive_dir, day) if catch_up else [day]):
        # clock trust record of this archiving run, hashed into clock_chain.log (5651_<day>.clock.json)
        clock = audit5651.clock_record(tracking, st, ignore_clock)
        path = audit5651.write_daily_archive(archive_dir, d, audit5651.day_rows(d), clock)
        print(("ARCHIVE_CREATED:" + path) if path else f"ARCHIVE_EXISTS:{d}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="job", required=True)
    b = sub.add_parser("backup")
    b.add_argument("--sql", dest="kind", action="store_const", const="sql", default="full")
    b.add_argument("--full", dest="kind", action="store_const", const="full")
    a = sub.add_parser("archive5651")
    a.add_argument("--date", help="only this day (no catch-up); default: yesterday + missed days")
    a.add_argument("--ignore-clock", action="store_true", help="archive even when the clock is not NTP-synced")
    args = p.parse_args(argv)

    cfg = build_config()
    logging.basicConfig(level=cfg["LOG_LEVEL"], format="%(levelname)s %(name)s: %(message)s")
    db.configure(cfg)
    system.set_dry_run(cfg["SYSTEM_DRY_RUN"])
    try:
        if args.job == "backup":
            run_backup(cfg, args.kind)
        else:
            day = args.date or (date.today() - timedelta(days=1)).isoformat()
            return run_archive(cfg, day, catch_up=not args.date, ignore_clock=args.ignore_clock)
    except (ServiceError, ValueError, OSError) as e:
        print(f"ERROR:{e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
