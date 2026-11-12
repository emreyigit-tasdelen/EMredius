# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Döngü (loop) tespiti: (1) topolojideki L2 halkaları (LLDP/CDP grafiğinde döngü = STP'siz ise yayın fırtınası riski),
(2) MAC taşınması: aynı MAC'in birden çok cihaz/porta uplink dışı görülmesi. Salt okunur; mevcut topo_links ve eq_macs verisini kullanır."""
import csv
import io

from . import equipment, inventory, topology
from ..core.tenant import resolve_tenant

DEFAULT_TENANT = inventory.DEFAULT_TENANT
MAX_CYCLES = 50
MAX_LEN = 12
KINDS = {"rings": ["ring", "length", "nodes", "severity"], "macs": ["mac", "vendor", "count", "locations", "severity"]}


def find_rings(edges):
    """Yönsüz grafikte temel halkalar (spanning tree dışı her kenar için tek halka). edges: [{source,target,...}]
    -> [[düğüm,...], ...] (her biri kapalı yolun düğüm listesi). Aynı çift arası paralel bağlantı 2'li halka sayılır."""
    adj, parent, depth, rings, seen = {}, {}, {}, [], set()
    for i, e in enumerate(edges):
        a, b = e["source"], e["target"]
        if a == b:
            continue
        adj.setdefault(a, []).append((b, i))
        adj.setdefault(b, []).append((a, i))
    tree = set()
    for root in sorted(adj):
        if root in depth:
            continue
        depth[root], parent[root] = 0, (None, None)
        stack = [root]
        while stack:
            u = stack.pop()
            for v, i in adj[u]:
                if v not in depth:
                    depth[v], parent[v] = depth[u] + 1, (u, i)
                    tree.add(i)
                    stack.append(v)
    for i, e in enumerate(edges):
        a, b = e["source"], e["target"]
        if i in tree or i in seen or a == b or a not in depth or b not in depth:
            continue
        seen.add(i)
        pa, pb, x, y = [a], [b], a, b
        while depth[x] > depth[y]:
            x = parent[x][0]
            pa.append(x)
        while depth[y] > depth[x]:
            y = parent[y][0]
            pb.append(y)
        while x != y:
            x, y = parent[x][0], parent[y][0]
            pa.append(x)
            pb.append(y)
        ring = pa + pb[::-1][1:]
        ring = ring[:-1] if len(ring) > 1 and ring[0] == ring[-1] else ring
        if len(ring) >= 2:
            rings.append(ring)
        if len(rings) >= MAX_CYCLES:
            break
    return rings


def ring_rows(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    g = topology.graph(tenant_id)
    label = {n["id"]: n["label"] for n in g["nodes"]}
    out = []
    for i, r in enumerate(sorted(find_rings(g["edges"]), key=len), 1):
        sev = "high" if len(r) <= 3 else "medium" if len(r) <= MAX_LEN else "low"
        out.append({"ring": i, "length": len(r), "nodes": [{"id": n, "label": label.get(n, n)} for n in r], "severity": sev})
    return out


def mac_rows(tenant_id=None):
    """Uplink olmayan en az 2 farklı (cihaz, port) konumunda görülen MAC'ler."""
    tenant_id = resolve_tenant(tenant_id)
    rows = [r for r in equipment.list_macs(tenant_id, limit=50000, enrich=True) if not r.get("uplink")]
    by = {}
    for r in rows:
        by.setdefault(r["mac"], []).append(r)
    out = []
    for mac, rs in by.items():
        locs = sorted({(r["device_ip"], r["port"]) for r in rs})
        if len(locs) < 2:
            continue
        out.append({"mac": mac, "vendor": rs[0].get("vendor", ""), "count": len(locs),
                    "locations": [{"device_ip": d, "port": p} for d, p in locs],
                    "severity": "high" if len(locs) >= 3 else "medium", "radius_user": rs[0].get("radius_user", "")})
    out.sort(key=lambda x: -x["count"])
    return out[:500]


def overview(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    r, m = ring_rows(tenant_id), mac_rows(tenant_id)
    return {"rings": len(r), "macs": len(m), "high": sum(x["severity"] == "high" for x in r + m)}


def to_csv(kind, rows):
    cols = KINDS[kind]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        vals = []
        for c in cols:
            v = r.get(c, "")
            if isinstance(v, list):
                v = " > ".join(x.get("label") or f"{x.get('device_ip')}:{x.get('port')}" for x in v)
            v = str(v)
            vals.append("'" + v if v[:1] in ("=", "+", "-", "@") else v)
        w.writerow(vals)
    return buf.getvalue()
