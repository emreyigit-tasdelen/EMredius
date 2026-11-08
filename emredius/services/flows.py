# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Akış analizi: NetFlow v5 / v9 ve IPFIX toplayıcı (UDP), dakikalık özetleme ve en çok konuşanlar sorguları.
Toplayıcı panel sürecinde bir iş parçacığıdır; ham akış saklanmaz, (dakika, ihracatçı, kaynak, hedef, protokol, hedef port)
anahtarında bayt/paket/akış toplamı tutulur. Tablo flow_rollup NMS veritabanında, tenant_id'li. sFlow henüz yok."""
import csv
import io
import logging
import os
import socket
import struct
import threading
import time

from . import inventory
from . import flow_acl as flow_allow
from ..core import get_nms_db
from ..core.tenant import resolve_tenant

log = logging.getLogger(__name__)

DEFAULT_TENANT = inventory.DEFAULT_TENANT
KEEP_DAYS = 7
FLUSH_S = 30
MAX_BUF = 200000
_schema_ok = set()
_lock = threading.Lock()
_buf = {}
_templates = {}      # (exporter, domain, template_id) -> [(field_id, length), ...]
_stats = {"packets": 0, "flows": 0, "errors": 0, "last": "", "sflow_packets": 0}

SCHEMA = """
CREATE TABLE IF NOT EXISTS flow_rollup (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, minute TEXT NOT NULL, exporter TEXT NOT NULL,
  src TEXT NOT NULL, dst TEXT NOT NULL, proto INTEGER NOT NULL DEFAULT 0, dport INTEGER NOT NULL DEFAULT 0,
  bytes INTEGER NOT NULL DEFAULT 0, packets INTEGER NOT NULL DEFAULT 0, flows INTEGER NOT NULL DEFAULT 0,
  UNIQUE(tenant_id, minute, exporter, src, dst, proto, dport));
CREATE INDEX IF NOT EXISTS flow_rollup_min ON flow_rollup(tenant_id, minute);
"""
PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 89: "OSPF"}
PORTS = {22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP", 123: "NTP", 161: "SNMP", 443: "HTTPS",
         445: "SMB", 1812: "RADIUS", 1813: "RADIUS-Acct", 3306: "MySQL", 3389: "RDP", 49: "TACACS+"}
# NetFlow v9 / IPFIX alan numaraları
F_BYTES, F_PKTS, F_PROTO, F_SPORT, F_SRC, F_DPORT, F_DST, F_OBYTES, F_OPKTS = 1, 2, 4, 7, 8, 11, 12, 85, 86


def _ip(b):
    return socket.inet_ntoa(b) if len(b) == 4 else ""


def _uint(b):
    return int.from_bytes(b, "big")


def _add(exporter, src, dst, proto, dport, nbytes, pkts, ts=None):
    if not src or not dst:
        return
    minute = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts or time.time()))
    key = (minute, exporter, src, dst, proto, dport)
    with _lock:
        if key not in _buf and len(_buf) >= MAX_BUF:
            return
        c = _buf.setdefault(key, [0, 0, 0])
        c[0] += nbytes
        c[1] += pkts
        c[2] += 1
        _stats["flows"] += 1


def parse_v5(data, exporter):
    if len(data) < 24:
        return 0
    _, count, _, secs = struct.unpack("!HHII", data[:12])
    n = 0
    for i in range(min(count, 30)):
        o = 24 + i * 48
        if o + 48 > len(data):
            break
        src, dst = _ip(data[o:o + 4]), _ip(data[o + 4:o + 8])
        pkts, octets = struct.unpack("!II", data[o + 16:o + 24])
        dport = struct.unpack("!H", data[o + 34:o + 36])[0]
        proto = data[o + 38]
        _add(exporter, src, dst, proto, dport, octets, pkts, secs)
        n += 1
    return n


def _parse_template_set(body, exporter, domain, ipfix):
    o = 0
    while o + 4 <= len(body):
        tid, cnt = struct.unpack("!HH", body[o:o + 4])
        o += 4
        fields = []
        for _ in range(cnt):
            if o + 4 > len(body):
                return
            fid, flen = struct.unpack("!HH", body[o:o + 4])
            o += 4
            if ipfix and fid & 0x8000:  # kurumsal alan: 4 bayt daha
                o += 4
                fid &= 0x7FFF
            fields.append((fid, flen))
        if tid >= 256:
            _templates[(exporter, domain, tid)] = fields


def _parse_data_set(body, tid, exporter, domain):
    fields = _templates.get((exporter, domain, tid))
    if not fields:
        return 0
    rec_len = sum(l for _, l in fields)
    if rec_len <= 0:
        return 0
    n = 0
    for o in range(0, len(body) - rec_len + 1, rec_len):
        r, p = {}, o
        for fid, flen in fields:
            r[fid] = body[p:p + flen]
            p += flen
        nb = _uint(r.get(F_BYTES) or r.get(F_OBYTES) or b"\0")
        np_ = _uint(r.get(F_PKTS) or r.get(F_OPKTS) or b"\0")
        _add(exporter, _ip(r.get(F_SRC, b"")), _ip(r.get(F_DST, b"")), _uint(r.get(F_PROTO, b"\0")),
             _uint(r.get(F_DPORT, b"\0\0")), nb, np_)
        n += 1
    return n


def parse_v9_ipfix(data, exporter, ipfix):
    n = 0
    if ipfix:
        if len(data) < 16:
            return 0
        length = struct.unpack("!H", data[2:4])[0]
        domain, o, data = struct.unpack("!I", data[12:16])[0], 16, data[:length]
    else:
        if len(data) < 20:
            return 0
        domain, o = struct.unpack("!I", data[16:20])[0], 20
    while o + 4 <= len(data):
        sid, slen = struct.unpack("!HH", data[o:o + 4])
        if slen < 4:
            break
        body = data[o + 4:o + slen]
        if (ipfix and sid == 2) or (not ipfix and sid == 0):
            _parse_template_set(body, exporter, domain, ipfix)
        elif sid >= 256:
            n += _parse_data_set(body, sid, exporter, domain)
        o += slen
    return n


def _parse_sflow_header(hdr, frame_len, rate, exporter):
    """Örneklenmiş Ethernet başlığından IPv4 akışı çıkarır; bayt/paket örnekleme oranıyla çarpılır."""
    if len(hdr) < 34:
        return 0
    et, o = struct.unpack("!H", hdr[12:14])[0], 14
    while et in (0x8100, 0x88A8) and len(hdr) >= o + 4:
        et, o = struct.unpack("!H", hdr[o + 2:o + 4])[0], o + 4
    if et != 0x0800 or len(hdr) < o + 20:
        return 0
    ihl, proto = (hdr[o] & 0x0F) * 4, hdr[o + 9]
    src, dst = _ip(hdr[o + 12:o + 16]), _ip(hdr[o + 16:o + 20])
    dport = struct.unpack("!H", hdr[o + ihl + 2:o + ihl + 4])[0] if proto in (6, 17) and len(hdr) >= o + ihl + 4 else 0
    _add(exporter, src, dst, proto, dport, frame_len * max(rate, 1), max(rate, 1))
    return 1


def parse_sflow(data, exporter):
    """sFlow v5 datagramı: akış örnekleri (tip 1) ve genişletilmiş akış örnekleri (tip 3) içindeki ham paket başlıkları."""
    if len(data) < 28 or struct.unpack("!I", data[:4])[0] != 5:
        return 0
    atype = struct.unpack("!I", data[4:8])[0]
    o = 8 + (4 if atype == 1 else 16) + 12          # ajan adresi, alt ajan no, sıra no, çalışma süresi
    if len(data) < o + 4:
        return 0
    nsamples, o, n = struct.unpack("!I", data[o:o + 4])[0], o + 4, 0
    for _ in range(min(nsamples, 64)):
        if o + 8 > len(data):
            break
        stype, slen = struct.unpack("!II", data[o:o + 8])
        body, o = data[o + 8:o + 8 + slen], o + 8 + slen
        fmt = stype & 0xFFF
        if fmt not in (1, 3):
            continue
        skip = 28 if fmt == 1 else 40               # kayıt sayısına kadar olan alanlar
        if len(body) < skip + 4:
            continue
        rate = struct.unpack("!I", body[8:12])[0] if fmt == 1 else struct.unpack("!I", body[12:16])[0]
        nrec, p = struct.unpack("!I", body[skip:skip + 4])[0], skip + 4
        for _ in range(min(nrec, 16)):
            if p + 8 > len(body):
                break
            tag, rlen = struct.unpack("!II", body[p:p + 8])
            rec, p = body[p + 8:p + 8 + rlen], p + 8 + rlen
            if tag == 1 and len(rec) >= 16:          # ham paket başlığı
                _, frame_len, _, hsize = struct.unpack("!IIII", rec[:16])
                n += _parse_sflow_header(rec[16:16 + hsize], frame_len, rate, exporter)
    return n


def _load_acl():
    conn = get_nms_db()
    try:
        conn.execute(flow_allow.TABLE)
        return flow_allow.load(conn)
    finally:
        conn.close()

_acl = flow_allow.Acl(_load_acl)


def handle_packet(data, exporter):
    """Bir UDP datagramını çözer; işlenen akış sayısını döndürür. Hatalı paket sayacı artırır, istisna fırlatmaz."""
    if not _acl.allows(exporter):  # Sertleştirme: kaynak IP izin listesi
        _stats['dropped'] = _stats.get('dropped', 0) + 1
        return 0
    try:
        _stats["packets"] += 1
        _stats["last"] = time.strftime("%Y-%m-%d %H:%M:%S")
        ver = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else 0
        if ver == 0 and len(data) >= 4 and struct.unpack("!I", data[:4])[0] == 5:  # sFlow v5 (32 bit sürüm alanı)
            _stats["sflow_packets"] += 1
            return parse_sflow(data, exporter)
        if ver == 5:
            return parse_v5(data, exporter)
        if ver == 9:
            return parse_v9_ipfix(data, exporter, False)
        if ver == 10:
            return parse_v9_ipfix(data, exporter, True)
    except Exception:  # noqa: BLE001
        pass
    _stats["errors"] += 1
    return 0


def _db():
    conn = get_nms_db()
    key = conn.execute("PRAGMA database_list").fetchone()[2]
    if key not in _schema_ok:
        conn.executescript(SCHEMA)
        conn.commit()
        _schema_ok.add(key)
    return conn


def flush(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    with _lock:
        items = list(_buf.items())
        _buf.clear()
    if not items:
        return 0
    conn = _db()
    try:
        for (minute, exp, src, dst, proto, dport), (b, p, f) in items:
            conn.execute(
                "INSERT INTO flow_rollup (tenant_id,minute,exporter,src,dst,proto,dport,bytes,packets,flows) VALUES (?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(tenant_id,minute,exporter,src,dst,proto,dport) DO UPDATE SET bytes=bytes+excluded.bytes,"
                "packets=packets+excluded.packets,flows=flows+excluded.flows", (tenant_id, minute, exp, src, dst, proto, dport, b, p, f))
        cutoff = time.strftime("%Y-%m-%d %H:%M", time.localtime(time.time() - KEEP_DAYS * 86400))
        conn.execute("DELETE FROM flow_rollup WHERE minute<?", (cutoff,))
        conn.commit()
    finally:
        conn.close()
    return len(items)


def start_collector(port=2055, bind="0.0.0.0", sflow_port=6343, extra_ports=None):
    """UDP toplayıcı + periyodik yazma iş parçacıkları (panel sürecinde)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((bind, int(port)))
    except OSError as e:
        log.warning("flow collector %s:%s açılamadı: %s", bind, port, e)
        return False

    def rx():
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                handle_packet(data, addr[0])
            except Exception as e:  # noqa: BLE001
                log.debug("flow rx: %s", e)

    def wr():
        while True:
            time.sleep(FLUSH_S)
            try:
                flush()
            except Exception as e:  # noqa: BLE001
                log.warning("flow flush: %s", e)

    threading.Thread(target=rx, daemon=True, name="flow-rx").start()
    threading.Thread(target=wr, daemon=True, name="flow-flush").start()
    if sflow_port:  # sFlow UDP 6343 (0 = kapalı)
        try:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s2.bind((bind, int(sflow_port)))

            def rx2():
                while True:
                    try:
                        data, addr = s2.recvfrom(65535)
                        handle_packet(data, addr[0])
                    except Exception as e:  # noqa: BLE001
                        log.debug("sflow rx: %s", e)
            threading.Thread(target=rx2, daemon=True, name="sflow-rx").start()
        except OSError as e:
            log.warning("sflow collector %s açılamadı: %s", sflow_port, e)
    if extra_ports is None:  # IPFIX için standart UDP 4739; boş değer (FLOW_EXTRA_PORTS=) kapatır
        extra_ports = os.environ.get("FLOW_EXTRA_PORTS", "4739")
    for p in str(extra_ports).replace(";", ",").split(","):
        if p.strip().isdigit() and int(p) != int(port):
            _listen_extra(bind, int(p))
    return True


def _listen_extra(bind, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((bind, port))
    except OSError as e:
        log.warning("flow collector %s:%s açılamadı: %s", bind, port, e)
        return

    def rx():
        while True:
            try:
                data, addr = s.recvfrom(65535)
                handle_packet(data, addr[0])
            except Exception as e:  # noqa: BLE001
                log.debug("flow rx %s: %s", port, e)
    threading.Thread(target=rx, daemon=True, name=f"flow-rx-{port}").start()


RANGES = {"15m": 15, "1h": 60, "6h": 360, "24h": 1440, "7d": 10080}
WINDOWS = RANGES  # raporlar için zaman aralığı adları
GROUPS = {"src": "src", "dst": "dst", "exporter": "exporter", "app": "proto, dport"}


def _since(rng):
    m = RANGES.get(rng, 60)
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(time.time() - m * 60))


def app_name(proto, dport):
    return PORTS.get(dport) or (f"{PROTO.get(proto, proto)}/{dport}" if dport else str(PROTO.get(proto, proto)))


def top(group="src", rng="1h", tenant_id=None, q="", limit=20):
    tenant_id = resolve_tenant(tenant_id)
    col = GROUPS.get(group, "src")
    sql = (f"SELECT {col}, SUM(bytes) b, SUM(packets) p, SUM(flows) f FROM flow_rollup WHERE tenant_id=? AND minute>=? "
           + ("AND (src LIKE ? OR dst LIKE ? OR exporter LIKE ?) " if q else "") + f"GROUP BY {col} ORDER BY b DESC LIMIT ?")
    args = [tenant_id, _since(rng)] + ([f"%{q}%"] * 3 if q else []) + [max(1, min(int(limit), 200))]
    conn = _db()
    try:
        rows = conn.execute(sql, args).fetchall()
    finally:
        conn.close()
    names = {d["ip"]: (d.get("sys_name") or d.get("hostname") or "") for d in inventory.list_devices(tenant_id)}
    out = []
    for r in rows:
        if group == "app":
            key, label = f"{r[0]}/{r[1]}", app_name(r[0], r[1])
            vals = r[2:]
        else:
            key, label, vals = r[0], names.get(r[0], "") if group != "exporter" else names.get(r[0], ""), r[1:]
        out.append({"key": key, "name": label, "bytes": vals[0] or 0, "packets": vals[1] or 0, "flows": vals[2] or 0})
    return out


def timeline(rng="1h", tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        return [{"minute": r[0], "bytes": r[1] or 0, "packets": r[2] or 0} for r in conn.execute(
            "SELECT minute, SUM(bytes), SUM(packets) FROM flow_rollup WHERE tenant_id=? AND minute>=? GROUP BY minute ORDER BY minute",
            (tenant_id, _since(rng)))]
    finally:
        conn.close()


def overview(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        r = conn.execute("SELECT COUNT(*), COALESCE(SUM(bytes),0), COALESCE(SUM(flows),0), COUNT(DISTINCT exporter) FROM flow_rollup "
                         "WHERE tenant_id=? AND minute>=?", (tenant_id, _since("24h"))).fetchone()
    finally:
        conn.close()
    return {"rows": r[0], "bytes_24h": r[1], "flows_24h": r[2], "exporters": r[3], "packets_rx": _stats["packets"],
            "errors": _stats["errors"], "sflow_packets": _stats["sflow_packets"], "last_packet": _stats["last"], "buffered": len(_buf)}


def to_csv(rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["key", "name", "bytes", "packets", "flows"])
    for r in rows:
        w.writerow([("'" + str(r[c]) if str(r[c])[:1] in ("=", "+", "-", "@") else r[c]) for c in ("key", "name", "bytes", "packets", "flows")])
    return buf.getvalue()


def report_overview(window="24h", exporter="", limit=20, tenant_id=None):
    """Raporlar için flow_rollup özeti -> (veri, hata). Hata durumunda istisna fırlatmaz."""
    window = window if window in RANGES else "24h"
    limit = max(1, min(int(limit), 100))
    tenant_id = resolve_tenant(tenant_id)
    where, args = "tenant_id=? AND minute>=?", [tenant_id, _since(window)]
    if exporter:
        where += " AND exporter=?"
        args.append(exporter)
    try:
        conn = _db()
        try:
            def q(cols, group):
                sql = f"SELECT {cols}, SUM(bytes), SUM(packets), SUM(flows) FROM flow_rollup WHERE {where} "
                if group:
                    sql += f"GROUP BY {group} ORDER BY SUM(bytes) DESC LIMIT ?"
                    return conn.execute(sql, args + [limit]).fetchall()
                return conn.execute(sql, args).fetchone()
            tot = q("1", "")
            src, dst = q("src", "src"), q("dst", "dst")
            convs, apps = q("src, dst", "src, dst"), q("proto, dport", "proto, dport")
        finally:
            conn.close()
    except Exception as e:  # noqa: BLE001
        return None, "Akış verisi okunamadı: " + str(e)
    return {"window": window, "exporter": exporter, "total_bytes": tot[1] or 0, "total_pkts": tot[2] or 0, "total_flows": tot[3] or 0,
            "talkers_src": [{"ip": r[0], "bytes": r[1] or 0, "pkts": r[2] or 0, "flows": r[3] or 0} for r in src],
            "talkers_dst": [{"ip": r[0], "bytes": r[1] or 0, "pkts": r[2] or 0, "flows": r[3] or 0} for r in dst],
            "conversations": [{"src": r[0], "dst": r[1], "bytes": r[2] or 0, "pkts": r[3] or 0, "flows": r[4] or 0} for r in convs],
            "applications": [{"proto_name": str(PROTO.get(r[0], r[0])), "service": app_name(r[0], r[1]), "bytes": r[2] or 0,
                              "pkts": r[3] or 0, "flows": r[4] or 0} for r in apps]}, None
