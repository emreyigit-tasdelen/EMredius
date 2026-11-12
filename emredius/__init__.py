# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""EMredius — FreeRADIUS / TACACS+ / SNMP management panel (Flask application factory)."""
import importlib
import logging
import sys
import threading

from flask import Flask


def _asset_version(app):
    """ASSET_VERSION + static dosyaların en son değişme zamanı: her yayında tarayıcı önbelleği yenilenir."""
    import os
    latest = 0
    for root, _dirs, files in os.walk(app.static_folder or ""):
        for f in files:
            if f.endswith((".js", ".css")):
                try:
                    latest = max(latest, int(os.path.getmtime(os.path.join(root, f))))
                except OSError:
                    pass
    return "%s-%x" % (app.config["ASSET_VERSION"], latest)

from .blueprints import BLUEPRINTS
from .config import build_config

__version__ = "4.0.0"

log = logging.getLogger("emredius")


def _configure_logging(level):
    root = logging.getLogger("emredius")
    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)  # journald adds timestamps
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        root.addHandler(handler)
    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    root.propagate = False


def _register_template_helpers(app):
    from markupsafe import Markup

    from .core import (can_access_page, csrf_input, csrf_token, esc, esc_js, format_bytes, format_seconds,
                       get_radiusd_status, lookup_mac_vendor, url_for, url_seg)

    app.jinja_env.globals.update(
        esc=esc,
        can_access=can_access_page,
        csrf_token=csrf_token,
        csrf_input=csrf_input,
        url_for=url_for,
        asset_version=_asset_version(app),
    )
    app.jinja_env.filters["format_bytes"] = format_bytes
    app.jinja_env.filters["format_seconds"] = format_seconds
    app.jinja_env.filters["mac_vendor"] = lambda v: lookup_mac_vendor(v) if v else ""
    app.jinja_env.filters["url_seg"] = url_seg  # one URL path segment (percent-encoded)
    app.jinja_env.filters["js"] = lambda v: Markup(esc_js(v))  # inside a quoted JS string in an HTML attribute

    @app.context_processor
    def _inject_globals():
        from flask import session
        from .services import timesync
        return {"radius_status": get_radiusd_status(), "timesync": timesync.status(), "tenant_label": _tenant_label(),
                "support_popup": bool(session.pop("support_popup", False))}


def _tenant_label():
    """Birden fazla kiracı varsa üst çubukta gösterilecek geçerli kiracı adı; tek kiracıda boş."""
    try:
        from flask import session
        from .core import tenant as tn
        if not session.get("logged_in"):
            return ""
        ts = tn.list_tenants()
        return tn.current_tenant_name() if len(ts) > 1 else ""
    except Exception:  # noqa: BLE001
        return ""


def _register_blueprints(app):
    for name in BLUEPRINTS:
        module = importlib.import_module(f"{__name__}.blueprints.{name}")
        app.register_blueprint(module.bp)
    # TACACS+ / SNMP REST APIs (/api/tacacs/*, /api/snmp/*); auth + RBAC come from the security gate
    from nms.web.routes_snmp import snmp_bp
    from nms.web.routes_tacacs import tacacs_bp

    app.register_blueprint(tacacs_bp)
    app.register_blueprint(snmp_bp)


def _start_background_jobs(app):
    from .core.settings import nms_initial_settings_sync
    from .services.telemetry import start_history_collector

    if app.config["NMS_SETTINGS_SYNC_ON_START"]:
        threading.Thread(target=nms_initial_settings_sync, daemon=True, name="NmsSettingsSync").start()
    from .services import inventory
    inventory.start_scheduler(app.config.get("IPSCAN_HISTORY_PATH", ""))
    from .services import topology
    topology.start_scheduler()
    from .services import equipment
    equipment.start_scheduler()
    from .services import macscan
    macscan.start_scheduler()
    from .services import machist, macalarm, reports
    machist.start_scheduler()
    macalarm.start_scheduler()
    reports.start_scheduler()
    from .services import radiolink
    radiolink.start_scheduler()
    from .services import watch
    watch.start_scheduler()
    from .services import svchealth
    svchealth.start_scheduler()
    from .services import flows
    flows.start_collector(app.config.get("FLOW_PORT", 2055), sflow_port=app.config.get("SFLOW_PORT", 6343))
    from .services import alarms
    alarms.start_scheduler()
    alarms.start_ssh_scheduler(app.config["SECRET_KEY"])
    from .services import configs
    configs.start_scheduler(app.config["SECRET_KEY"])
    alarms.start_trap_listener(app.config.get("ALARM_TRAP_PORT", 0))  # 0 = kapalı
    start_history_collector()  # gunicorn runs 1 worker, so there is exactly one collector
    if not app.config["SYSTEM_DRY_RUN"]:
        from .services.timesync import start_watcher
        start_watcher()


def create_app(overrides=None):
    cfg = build_config(overrides)
    _configure_logging(cfg["LOG_LEVEL"])

    app = Flask(__name__, static_folder="static", static_url_path="/static", template_folder="templates")
    app.config.update(cfg)

    from .core import db, security, system, web

    db.configure(app.config)
    system.set_dry_run(app.config["SYSTEM_DRY_RUN"])
    security.init_app(app)
    _register_template_helpers(app)
    _register_blueprints(app)
    duplicates = web.build_endpoint_map(app)
    if duplicates and app.config.get("TESTING"):
        raise RuntimeError(f"ambiguous short endpoint names: {sorted(duplicates)}")

    if app.config["START_BACKGROUND_JOBS"] and not app.config.get("TESTING"):
        _start_background_jobs(app)
    log.info("EMredius %s started (%d blueprints)", __version__, len(app.blueprints))
    return app
