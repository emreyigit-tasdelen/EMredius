# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""REST API v1 data access (users, sessions, stats) and the OpenAPI document."""
from ..core import get_db
from . import radius_users

OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "EMredius REST API",
        "version": "3.0.0",
        "description": "Kullanıcı oluşturma, kupon üretme, oturum sonlandırma ve istatistik API uç noktaları.",
    },
    "servers": [{"url": "/api/v1"}],
    "components": {"securitySchemes": {"ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}},
    "security": [{"ApiKeyAuth": []}],
    "paths": {
        "/users": {
            "get": {"summary": "Tüm kullanıcıları listele", "responses": {"200": {"description": "Başarılı"}}},
            "post": {
                "summary": "Yeni kullanıcı oluştur",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {"username": {"type": "string"}, "password": {"type": "string"},
                                   "vlan_id": {"type": "integer"}, "rate_limit": {"type": "string"},
                                   "description": {"type": "string"}},
                    "required": ["username", "password"],
                }}}},
                "responses": {"201": {"description": "Kullanıcı oluşturuldu"}, "400": {"description": "Geçersiz veri"},
                              "409": {"description": "Kullanıcı zaten mevcut"}},
            },
        },
        "/users/{username}": {
            "delete": {"summary": "Kullanıcıyı sil",
                       "parameters": [{"name": "username", "in": "path", "required": True, "schema": {"type": "string"}}],
                       "responses": {"200": {"description": "Silindi"}, "404": {"description": "Bulunamadı"}}},
        },
        "/sessions": {"get": {"summary": "Canlı bağlı oturumları listele", "responses": {"200": {"description": "Başarılı"}}}},
        "/stats": {"get": {"summary": "Özet istatistikler", "responses": {"200": {"description": "Başarılı"}}}},
    },
}


def list_users():
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT c.username,
                       (SELECT r.value FROM radreply r WHERE r.username = c.username AND r.attribute = 'Tunnel-Private-Group-Id' ORDER BY r.id DESC LIMIT 1) AS vlan_id,
                       (SELECT r.value FROM radreply r WHERE r.username = c.username AND r.attribute = 'Mikrotik-Rate-Limit' ORDER BY r.id DESC LIMIT 1) AS rate_limit,
                       m.description
                FROM (SELECT username, MAX(id) AS id FROM radcheck WHERE attribute = 'Cleartext-Password' GROUP BY username) c
                LEFT JOIN radius_meta m ON m.username = c.username
                ORDER BY c.id DESC
            """)
            return cur.fetchall()
    finally:
        conn.close()


def create_user(data):
    """JSON body -> radius_users.add_user (same validation as the panel). Returns the username."""
    def _s(key, default=""):
        v = data.get(key, default)
        return "" if v is None else str(v).strip()
    fields = {"username": _s("username"), "password": _s("password"), "vlan": _s("vlan_id"), "static_ip": "",
              "rate": _s("rate_limit"), "group": "", "desc": _s("description") or "API Oluşturdu"}
    if not fields["username"] or not fields["password"]:
        raise radius_users.ServiceError("username ve password alanları zorunludur.")
    return radius_users.add_user(fields, False, False)["username"]


def delete_user(username):
    return radius_users.change_user_state(username, "delete")


def active_sessions():
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT radacctid, username, framedipaddress, callingstationid, nasipaddress, acctstarttime,
                       acctsessiontime, acctinputoctets, acctoutputoctets
                FROM radacct WHERE acctstoptime IS NULL ORDER BY radacctid DESC
            """)
            return cur.fetchall()
    finally:
        conn.close()


def stats():
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(DISTINCT username) AS n FROM radcheck "
                        "WHERE username NOT LIKE '%:%' AND username NOT LIKE '%-%'")
            users = cur.fetchone()["n"]
            cur.execute("SELECT COUNT(*) AS n FROM radacct WHERE acctstoptime IS NULL")
            sessions = cur.fetchone()["n"]
            cur.execute("SELECT COUNT(*) AS n FROM nas")
            nas = cur.fetchone()["n"]
    finally:
        conn.close()
    return {"total_users": users, "active_sessions": sessions, "nas_count": nas}



def _get(summary, params=None):
    return {"get": {"summary": summary, "parameters": params or [], "responses": {"200": {"description": "Başarılı"}}}}


_TENANT = {"name": "tenant", "in": "query", "required": False, "schema": {"type": "integer"}, "description": "Kiracı kimliği (varsayılan 1)"}
_Q = {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}}
OPENAPI_SPEC["paths"].update({
    "/topology": _get("LLDP/CDP topoloji grafiği (düğümler, kenarlar)", [_Q, _TENANT]),
    "/inventory/devices": _get("Aktif cihaz envanteri", [_Q, _TENANT]),
    "/equipment/{kind}": _get("Port (ports), MAC tablosu (macs) veya şasi (chassis) envanteri",
                              [{"name": "kind", "in": "path", "required": True, "schema": {"type": "string", "enum": ["ports", "macs", "chassis"]}},
                               {"name": "device", "in": "query", "schema": {"type": "string"}}, _Q, _TENANT]),
    "/macscan": _get("MAC Tarama: cihaz-port-MAC-üretici-IP-kullanıcı-PoE (access=1 uplink'siz, poe=1 yalnız PoE verenler)",
                     [{"name": "device", "in": "query", "schema": {"type": "string"}}, {"name": "vlan", "in": "query", "schema": {"type": "integer"}},
                      {"name": "access", "in": "query", "schema": {"type": "string", "enum": ["0", "1"]}},
                      {"name": "poe", "in": "query", "schema": {"type": "string", "enum": ["0", "1"]}}, _Q, _TENANT]),
    "/health/radiolink": _get("Radyolink hat kalitesi", [_Q, _TENANT]),
    "/health": _get("Ekipman sağlığı (CPU, bellek, sıcaklık)", [_Q, _TENANT]),
    "/watch": _get("İzlenen IP'ler (durum, gecikme, kayıp)", [_Q, _TENANT]),
    "/alarms": _get("Alarmlar (aktif/onaylı/çözülen)", [{"name": "status", "in": "query", "schema": {"type": "string", "enum": ["active", "ack", "resolved"]}},
                                                          {"name": "severity", "in": "query", "schema": {"type": "string"}}, _Q, _TENANT]),
    "/loops": _get("Döngü tespiti (topoloji halkaları, MAC taşınması)", [_TENANT]),
    "/flows/top": _get("En çok konuşanlar (src/dst/app/exporter, aralık)",
                       [{"name": "group", "in": "query", "schema": {"type": "string", "enum": ["src", "dst", "app", "exporter"]}},
                        {"name": "range", "in": "query", "schema": {"type": "string", "enum": ["15m", "1h", "6h", "24h", "7d"]}}, _TENANT]),
    "/boards": _get("Özel panolar", [_TENANT]),
    "/boards/{board_id}": _get("Pano bileşenleri (canlı veri)", [{"name": "board_id", "in": "path", "required": True, "schema": {"type": "integer"}}, _TENANT]),
    "/configs/compliance": _get("Konfig uyumluluk durumu (içerik dönmez)", [_TENANT]),
    "/ipam/subnets": _get("IPAM alt ağları (doluluk)", [_Q, _TENANT]),
    "/apn": _get("APN envanteri: hatlar, sağlayıcılar, konumlar", [_TENANT]),
    "/ippools": _get("RADIUS IP havuzları (doluluk, atama sayıları)", [_TENANT]),
})
