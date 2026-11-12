# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""REST API v1 (X-API-Key) and its Swagger / OpenAPI documentation (panel login)."""
import logging

from flask import jsonify, render_template, request

from ...core import api_auth_required, get_client_ip, get_radiusd_status, log_admin_action, login_required
from ...services import api_v1 as svc
from ...services.radius_users import ServiceError
from . import bp

log = logging.getLogger(__name__)


def _error(message, code):
    return jsonify({"status": "error", "message": message}), code


def _db_error(e):
    log.error("api v1: %s", e)
    return _error("Veritabanı hatası.", 503)


@bp.route("/api/openapi.json")
@login_required
def openapi_spec():
    return jsonify(svc.OPENAPI_SPEC)


@bp.route("/api/docs")
@login_required
def swagger_ui():
    return render_template("api/docs.html")


@bp.route("/api/v1/users", methods=["GET", "POST"])
@api_auth_required
def api_users():
    if request.method == "GET":
        try:
            users = svc.list_users()
        except Exception as e:
            return _db_error(e)
        return jsonify({"status": "success", "count": len(users), "users": users})

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error("Geçerli bir JSON gövdesi gereklidir.", 400)
    try:
        u = svc.create_user(data)
    except ServiceError as e:
        msg = str(e)
        return _error(msg, 409 if "zaten mevcut" in msg else 503 if "veritabanı" in msg else 400)
    except Exception as e:
        return _db_error(e)
    log_admin_action("api", "API_KULLANICI_EKLE", u, "REST API v1", get_client_ip())
    return jsonify({"status": "success", "message": f"'{u}' başarıyla oluşturuldu."}), 201


@bp.route("/api/v1/users/<path:username>", methods=["DELETE"])
@api_auth_required
def api_delete_user(username):
    try:
        u = svc.delete_user(username)
    except ServiceError as e:
        msg = str(e)
        return _error(msg, 404 if "bulunamadı" in msg else 503)
    except Exception as e:
        return _db_error(e)
    log_admin_action("api", "API_KULLANICI_SİL", u, "REST API v1", get_client_ip())
    return jsonify({"status": "success", "message": f"'{u}' silindi."})


@bp.route("/api/v1/sessions", methods=["GET"])
@api_auth_required
def api_sessions():
    try:
        active = svc.active_sessions()
    except Exception as e:
        return _db_error(e)
    return jsonify({"status": "success", "count": len(active), "sessions": active})


@bp.route("/api/v1/stats", methods=["GET"])
@api_auth_required
def api_stats():
    try:
        s = svc.stats()
    except Exception as e:
        return _db_error(e)
    return jsonify(dict(status="success", radiusd_status=get_radiusd_status(), **s))


@bp.route("/api/v1/topology", methods=["GET"])
@api_auth_required
def api_topology():
    from ...services import topology
    g = topology.graph(q=(request.args.get("q") or "")[:64])
    return jsonify({"status": "success", "nodes": g["nodes"], "edges": g["edges"], "stats": g["stats"]})


@bp.route("/api/v1/inventory/devices", methods=["GET"])
@api_auth_required
def api_inventory_devices():
    from ...services import inventory
    devs = inventory.list_devices(q=(request.args.get("q") or "")[:64], vendor=(request.args.get("vendor") or "")[:64],
                                  dtype=(request.args.get("type") or "")[:32])
    return jsonify({"status": "success", "count": len(devs),
                    "devices": [{k: d[k] for k in inventory.CSV_COLS} for d in devs]})


@bp.route("/api/v1/equipment/<kind>", methods=["GET"])
@api_auth_required
def api_equipment(kind):
    from ...services import equipment
    a = request.args
    dev = (a.get("device") or "")[:45]
    if kind == "ports":
        rows = equipment.list_ports(device_ip=dev, q=(a.get("q") or "")[:64], state=a.get("state", ""))
    elif kind == "macs":
        rows = equipment.list_macs(device_ip=dev, port=(a.get("port") or "")[:64], q=(a.get("q") or "")[:64], vlan=a.get("vlan", ""))
    elif kind == "chassis":
        rows = equipment.list_chassis(device_ip=dev)
    else:
        return _error("Tür ports, macs veya chassis olmalı.", 404)
    cols = equipment.KINDS[kind]
    return jsonify({"status": "success", "count": len(rows), kind: [{c: r.get(c, "") for c in cols} for r in rows]})


@bp.route("/api/v1/macscan", methods=["GET"])
@api_auth_required
def api_macscan():
    from ...services import macscan
    a = request.args
    rows = macscan.list_rows(device_ip=(a.get("device") or "")[:45], q=(a.get("q") or "")[:64], vlan=a.get("vlan", ""),
                             access_only=a.get("access") == "1", poe_only=a.get("poe") == "1")
    return jsonify({"status": "success", "count": len(rows), "rows": [{c: r.get(c, "") for c in macscan.COLS} for r in rows],
                    "poe": macscan.list_poe(device_ip=(a.get("device") or "")[:45])})


@bp.route("/api/v1/health/radiolink", methods=["GET"])
@api_auth_required
def api_radiolink():
    from ...services import radiolink
    rows = radiolink.list_links(q=(request.args.get("q") or "")[:64])
    return jsonify({"status": "success", "count": len(rows),
                    "links": [{c: r.get(c, "") for c in radiolink.KINDS["links"]} for r in rows]})


@bp.route("/api/v1/boards", methods=["GET"])
@bp.route("/api/v1/boards/<int:board_id>", methods=["GET"])
@api_auth_required
def api_boards(board_id=None):
    from ...services import boards
    if board_id is None:
        return jsonify({"status": "success", "boards": boards.list_boards()})
    b = boards.get_board(board_id)
    if not b:
        return _error("Pano bulunamadı.", 404)
    return jsonify({"status": "success", "name": b["name"], "widgets": boards.render(b)})


@bp.route("/api/v1/configs/compliance", methods=["GET"])
@api_auth_required
def api_configs_compliance():
    from ...services import configs
    rows = configs.compliance()
    return jsonify({"status": "success", "count": len(rows), "devices": rows})


@bp.route("/api/v1/apn", methods=["GET"])
@api_auth_required
def api_apn():
    from ...services import apn
    d = apn.overview()
    return jsonify({"status": "success", "lines": d["lines"], "providers": d["providers"], "locations": d["locations"]})


@bp.route("/api/v1/ippools", methods=["GET"])
@api_auth_required
def api_ippools():
    from ...services import ippools
    rows = ippools.list_pools()
    keys = ("name", "start_ip", "end_ip", "total", "used", "free", "users", "groups")
    return jsonify({"status": "success", "count": len(rows), "pools": [{k: r[k] for k in keys} for r in rows]})


@bp.route("/api/v1/ipam/subnets", methods=["GET"])
@api_auth_required
def api_ipam_subnets():
    from ...services import ipam
    rows = ipam.list_subnets(q=(request.args.get("q") or "")[:64])
    return jsonify({"status": "success", "count": len(rows), "subnets": [{c: r[c] for c in ipam.CSV_COLS} for r in rows]})



def _api_tenant():
    from ...core.tenant import current_tenant
    return current_tenant()


@bp.route("/api/v1/health", methods=["GET"])
@api_auth_required
def api_health():
    from ...services import health
    rows = health.health_rows(q=(request.args.get("q") or "")[:64])
    return jsonify({"status": "success", "count": len(rows), "devices": [{c: r.get(c) for c in health.KINDS["health"]} for r in rows]})


@bp.route("/api/v1/watch", methods=["GET"])
@api_auth_required
def api_watch():
    from ...services import watch
    rows = watch.list_targets(q=(request.args.get("q") or "")[:64])
    return jsonify({"status": "success", "count": len(rows), "targets": [{c: r.get(c) for c in watch.CSV_COLS} for r in rows]})


@bp.route("/api/v1/alarms", methods=["GET"])
@api_auth_required
def api_alarms():
    from ...services import alarms
    a = request.args
    rows = alarms.list_events(status=a.get("status") if a.get("status") in alarms.STATUSES else "",
                              severity=a.get("severity") if a.get("severity") in alarms.SEVERITIES else "", q=(a.get("q") or "")[:64], limit=1000)
    return jsonify({"status": "success", "count": len(rows), "alarms": [{c: r.get(c, "") for c in alarms.CSV_COLS} for r in rows]})


@bp.route("/api/v1/loops", methods=["GET"])
@api_auth_required
def api_loops():
    from ...services import loops
    return jsonify({"status": "success", "rings": loops.ring_rows(), "macs": loops.mac_rows()})


@bp.route("/api/v1/flows/top", methods=["GET"])
@api_auth_required
def api_flows_top():
    from ...services import flows
    g = request.args.get("group", "src")
    rng = request.args.get("range", "1h")
    rows = flows.top(g if g in flows.GROUPS else "src", rng if rng in flows.RANGES else "1h")
    return jsonify({"status": "success", "count": len(rows), "top": rows})
