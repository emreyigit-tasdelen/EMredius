# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""gunicorn settings. One worker process with threads: the login brute-force counters, settings cache and
background jobs are per process, so a single process keeps them consistent. Admin-panel traffic is low and
I/O bound (MariaDB, systemctl, SNMP), which threads handle well."""
import os

bind = os.environ.get("EMREDIUS_BIND", "127.0.0.1:5000")
workers = 1
worker_class = "gthread"
threads = int(os.environ.get("EMREDIUS_THREADS", "16"))
timeout = 120          # backups / radtest / CLI commands may take a while
graceful_timeout = 8 
keepalive = 5
max_requests = 5000    # recycle the worker periodically (guards against slow leaks)
max_requests_jitter = 500
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info").lower()
forwarded_allow_ips = "127.0.0.1"
proc_name = os.environ.get("EMREDIUS_PROC_NAME", "emredius")
