# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Radyolink / mikrodalga hat kalitesi: Ubiquiti, Cambium, MikroTik, Siklu cihazlarından sinyal, gürültü, CCQ ve hız okur.
Üretici OID'leri OIDS tablosundadır; ayar `radiolink_oids` (JSON) ile üretici bazında değiştirilebilir. Zamanlayıcı
varsayılan KAPALI (`radiolink_enabled=0`); elle "Şimdi yokla" her zaman çalışır. Geçmiş RETAIN_DAYS gün tutulur."""
import asyncio
import csv
import io
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import inventory
from ..core import get_nms_db, get_setting
from ..core.tenant import all_tenant_ids, resolve_tenant

log = logging.getLogger(__name__)

DEFAULT_TENANT = inventory.DEFAULT_TENANT
RETAIN_DAYS = 7
POLL_INTERVAL_S = 300
WARN = {"rssi": -75, "snr": 15, "ccq": 80}
METRICS = ("rssi", "noise", "snr", "ccq", "tx_rate", "rx_rate")
# Metrik başına tam (örnekli) OID. "verified": gerçek cihazda doğrulandı mı (şu an hiçbiri değil; ayardan düzeltilebilir).
OIDS = {
    "ubiquiti": {"enterprise": "41112", "verified": False, "rssi": "1.3.6.1.4.1.41112.1.4.5.1.5.1",
                 "noise": "1.3.6.1.4.1.41112.1.4.5.1.8.1", "ccq": "1.3.6.1.4.1.41112.1.4.5.1.7.1",
                 "tx_rate": "1.3.6.1.4.1.41112.1.4.5.1.9.1", "rx_rate": "1.3.6.1.4.1.41112.1.4.5.1.10.1"},
    "mikrotik": {"enterprise": "14988", "verified": False, "rssi": "1.3.6.1.4.1.14988.1.1.1.2.1.3",
                 "noise": "1.3.6.1.4.1.14988.1.1.1.3.1.9", "snr": "1.3.6.1.4.1.14988.1.1.1.2.1.12",
                 "ccq": "1.3.6.1.4.1.14988.1.1.1.3.1.10", "tx_rate": "1.3.6.1.4.1.14988.1.1.1.3.1.2",
                 "rx_rate": "1.3.6.1.4.1.14988.1.1.1.3.1.3"},
    "cambium": {"enterprise": "161", "verified": False, "rssi": "1.3.6.1.4.1.161.19.3.2.2.8.0",
                "snr": "1.3.6.1.4.1.161.19.3.2.2.9.0"},
    "siklu": {"enterprise": "31926", "verified": False, "rssi": "1.3.6.1.4.1.31926.2.1.1.6.1",
              "snr": "1.3.6.1.4.1.31926.2.1.1.7.1"},
}
SCHEMA = """
CREATE TABLE IF NOT EXISTS rl_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, ip TEXT NOT NULL, vendor TEXT DEFAULT '',
  rssi REAL, noise REAL, snr REAL, ccq REAL, tx_rate REAL, rx_rate REAL, state TEXT DEFAULT 'nodata', ts TEXT DEFAULT '',
  UNIQUE(tenant_id, ip));
CREATE TABLE IF NOT EXISTS rl_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT, link_id INTEGER NOT NULL, ts TEXT NOT NULL, rssi REAL, snr REAL, ccq REAL);
CREATE INDEX IF NOT EXISTS rl_hist_l ON rl_history(link_id, id);
"""
KINDS = {"links": ["ip", "name", "vendor", "rssi", "noise", "snr", "ccq", "tx_rate", "rx_rate", "ts", "state"]}
_schema_ok = set()
_running = threading.Event()


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _db():
    conn = get_nms_db()
    key = conn.execute("PRAGMA database_list").fetchone()[2]
    if key not in _schema_ok:
        conn.executescript(SCHEMA)
        conn.commit()
        _schema_ok.add(key)
    return conn


def oid_table():
    """Varsayılan OID'ler + ayardaki JSON üzerine yazmalar ({"mikrotik": {"rssi": "1.3..."}})."""
    tab = {k: dict(v) for k, v in OIDS.items()}
    try:
        over = json.loads(get_setting("radiolink_oids", "") or "{}")
        for ven, d in over.items():
            if ven in tab and isinstance(d, dict):
                tab[ven].update({k: str(v) for k, v in d.items() if k in METRICS and v})
    except Exception:  # noqa: BLE001
        pass
    return tab


def detect_vendor(dev):
    """sysObjectID (enterprise numarası) ya da üretici adı ile 4 aileden birini bulur."""
    soid = (dev.get("sys_object_id") or "").lstrip(".")
    for ven, d in OIDS.items():
        if soid.startswith("1.3.6.1.4.1." + d["enterprise"] + "."):
            return ven
    text = f"{dev.get('vendor', '')} {dev.get('mac_vendor', '')} {dev.get('sys_descr', '')}".lower()
    for ven, alias in (("ubiquiti", ("ubiquiti", "ubnt", "airmax")), ("mikrotik", ("mikrotik", "routeros")),
                       ("cambium", ("cambium", "canopy", "epmp")), ("siklu", ("siklu", "etherhaul"))):
        if any(a in text for a in alias):
            return ven
    return ""


def _num(v):
    try:
        if isinstance(v, (bytes, bytearray)):
            v = v.decode(errors="ignore")
        return float(str(v).strip())
    except Exception:  # noqa: BLE001
        return None


def parse_values(vendor, raw):
    """raw: {metrik: ham değer}. İşaretsiz dBm'i eksiye çevirir, SNR'ı hesaplar, bps hızı Mb/s yapar."""
    m = {k: _num(raw.get(k)) for k in METRICS}
    if m["rssi"] is not None and m["rssi"] > 30:
        m["rssi"] = -m["rssi"]
    if m["noise"] is not None and m["noise"] > 0:
        m["noise"] = -m["noise"]
    if m["snr"] is None and m["rssi"] is not None and m["noise"] is not None:
        m["snr"] = round(m["rssi"] - m["noise"], 1)
    for k in ("tx_rate", "rx_rate"):
        if m[k] is not None and m[k] > 100000:  # bps -> Mb/s
            m[k] = round(m[k] / 1e6, 1)
    return m


def state_of(m):
    if all(m.get(k) is None for k in ("rssi", "snr", "ccq")):
        return "nodata"
    if (m.get("rssi") is not None and m["rssi"] <= WARN["rssi"]) or (m.get("snr") is not None and m["snr"] < WARN["snr"]) \
            or (m.get("ccq") is not None and m["ccq"] < WARN["ccq"]):
        return "warn"
    return "ok"


async def _fetch(ip, community, oids):
    from nms.snmp.engine import SnmpClient
    c = SnmpClient()
    out = {}
    for k, oid in oids.items():
        try:
            r = await asyncio.wait_for(c.get(target=ip, oids=[oid], community=community, version="v2c", timeout=2, retries=1), 8)
            vbs = getattr(r, "varbinds", None) or []
            if vbs and vbs[0].value is not None and "No Such" not in str(vbs[0].value):
                out[k] = vbs[0].value
        except Exception as e:  # noqa: BLE001
            log.debug("radiolink %s %s: %s", ip, k, e)
    return out


def poll_device(ip, community, vendor):
    oids = {k: v for k, v in oid_table().get(vendor, {}).items() if k in METRICS and v}
    try:
        raw = asyncio.run(_fetch(ip, community, oids))
    except Exception as e:  # noqa: BLE001
        log.debug("radiolink %s: %s", ip, e)
        raw = {}
    return parse_values(vendor, raw)


def save(conn, tenant_id, ip, vendor, m):
    now, st = _now(), state_of(m)
    conn.execute(
        "INSERT INTO rl_links (tenant_id,ip,vendor,rssi,noise,snr,ccq,tx_rate,rx_rate,state,ts) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(tenant_id,ip) DO UPDATE SET vendor=excluded.vendor, rssi=excluded.rssi, noise=excluded.noise, snr=excluded.snr, "
        "ccq=excluded.ccq, tx_rate=excluded.tx_rate, rx_rate=excluded.rx_rate, state=excluded.state, ts=excluded.ts",
        (tenant_id, ip, vendor, m["rssi"], m["noise"], m["snr"], m["ccq"], m["tx_rate"], m["rx_rate"], st, now))
    if st != "nodata":
        lid = conn.execute("SELECT id FROM rl_links WHERE tenant_id=? AND ip=?", (tenant_id, ip)).fetchone()["id"]
        conn.execute("INSERT INTO rl_history (link_id,ts,rssi,snr,ccq) VALUES (?,?,?,?,?)", (lid, now, m["rssi"], m["snr"], m["ccq"]))


def poll_all(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    if _running.is_set():
        return {"error": "Radyolink yoklaması zaten çalışıyor."}
    _running.set()
    try:
        devs = []
        for d in inventory.list_devices(tenant_id, status="ONLINE"):
            ven = detect_vendor(d)
            if ven and d["snmp_ok"] and d["snmp_community"]:
                devs.append((d["ip"], d["snmp_community"], ven))
        with ThreadPoolExecutor(4) as ex:
            res = list(ex.map(lambda x: poll_device(*x), devs))
        conn = _db()
        try:
            for (ip, _c, ven), m in zip(devs, res):
                save(conn, tenant_id, ip, ven, m)
            cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - RETAIN_DAYS * 86400))
            conn.execute("DELETE FROM rl_history WHERE ts<?", (cutoff,))
            conn.commit()
        finally:
            conn.close()
        return {"devices": len(devs)}
    finally:
        _running.clear()


def poll_async(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    if _running.is_set():
        return False
    threading.Thread(target=poll_all, args=(tenant_id,), daemon=True, name="radiolink-poll").start()
    return True


def start_scheduler():
    def loop():
        while True:
            time.sleep(POLL_INTERVAL_S)
            try:
                if str(get_setting("radiolink_enabled", "0")) == "1":
                    for t in all_tenant_ids():
                        poll_all(t)
            except Exception as e:  # noqa: BLE001
                log.warning("radiolink scheduler: %s", e)
    threading.Thread(target=loop, daemon=True, name="radiolink-scheduler").start()


def list_links(tenant_id=None, q=""):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        rows = [dict(r) for r in conn.execute("SELECT * FROM rl_links WHERE tenant_id=?", (tenant_id,))]
    finally:
        conn.close()
    names = {d["ip"]: (d["sys_name"] or d["hostname"] or d["ip"]) for d in inventory.list_devices(tenant_id)}
    ql, out = (q or "").lower(), []
    for r in rows:
        if r["ip"] not in names:
            continue
        r["name"] = names[r["ip"]]
        if ql and ql not in f"{r['ip']} {r['name']} {r['vendor']}".lower():
            continue
        out.append(r)
    out.sort(key=lambda x: (x["state"] != "warn", x["rssi"] if x["rssi"] is not None else 0))
    return out


def history(link_id, hours=24):
    since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - max(1, min(int(hours), 168)) * 3600))
    conn = _db()
    try:
        return [dict(r) for r in conn.execute(
            "SELECT ts, rssi, snr, ccq FROM rl_history WHERE link_id=? AND ts>=? ORDER BY id LIMIT 2000", (int(link_id), since))]
    finally:
        conn.close()


def overview(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    r = list_links(tenant_id)
    return {"links": len(r), "warn": sum(x["state"] == "warn" for x in r),
            "enabled": str(get_setting("radiolink_enabled", "0")) == "1"}


def to_csv(rows):
    cols = KINDS["links"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([("'" + str(r.get(c, "")) if c in ("ip", "name", "vendor") and str(r.get(c, ""))[:1] in ("=", "+", "-", "@")
                     else ("" if r.get(c) is None else r.get(c))) for c in cols])
    return buf.getvalue()
