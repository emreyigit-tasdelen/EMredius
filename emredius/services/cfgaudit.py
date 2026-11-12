# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Konfig denetimi: sürümler arası yan yana fark, son değişiklik akışı ve kural tabanlı uyum raporu.
Yalnızca okur (cfg_backups, cfg_rules); cihaza hiçbir şey yazmaz. Kural yönetimi services/configs.py'de."""
import csv
import difflib
import io
import re

from . import configs, inventory

MAX_LINES = 4000


def _norm(text, ignore_ws, ignore_comments):
    out = []
    for l in (text or "").split("\n"):
        if ignore_comments and l.lstrip().startswith(("!", "#")):
            continue
        out.append(re.sub(r"\s+", " ", l).strip() if ignore_ws else l.rstrip())
    return out


def _eq(A, B, i1, j1, k):
    return {"op": "eq", "ln": i1 + k + 1, "l": A[i1 + k], "rn": j1 + k + 1, "r": B[j1 + k]}


def side_by_side(ip, a, b, ignore_ws=False, ignore_comments=False, tenant_id=None):
    """-> {'rows': [{'op','ln','l','rn','r'}], 'added','removed','changed'} ya da None (sürüm yok).
    op: eq | add | del | chg. Uzun eşit bölümler katlanır ('skip')."""
    tid = configs.resolve_tenant(tenant_id)
    va, vb = configs.get_version(ip, a, tid), configs.get_version(ip, b, tid)
    if not va or not vb:
        return None
    A, B = _norm(va["content"], ignore_ws, ignore_comments), _norm(vb["content"], ignore_ws, ignore_comments)
    rows, add, rem, chg = [], 0, 0, 0
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, A, B, autojunk=False).get_opcodes():
        if tag == "equal":
            n = i2 - i1
            if n > 6:
                rows += [_eq(A, B, i1, j1, k) for k in range(3)]
                rows.append({"op": "skip", "n": n - 6})
                rows += [_eq(A, B, i1, j1, k) for k in range(n - 3, n)]
            else:
                rows += [_eq(A, B, i1, j1, k) for k in range(n)]
            continue
        for k in range(max(i2 - i1, j2 - j1)):
            l_ok, r_ok = i1 + k < i2, j1 + k < j2
            op = "chg" if l_ok and r_ok else ("del" if l_ok else "add")
            rem += l_ok and not r_ok
            add += r_ok and not l_ok
            chg += l_ok and r_ok
            rows.append({"op": op, "ln": i1 + k + 1 if l_ok else "", "l": A[i1 + k] if l_ok else "",
                         "rn": j1 + k + 1 if r_ok else "", "r": B[j1 + k] if r_ok else ""})
        if len(rows) > MAX_LINES:
            break
    return {"a": a, "b": b, "rows": rows[:MAX_LINES], "added": add, "removed": rem, "changed": chg,
            "same": not (add or rem or chg), "created_a": va["created"], "created_b": vb["created"]}


def recent_changes(limit=50, tenant_id=None):
    """Her sürüm için bir önceki sürüme göre eklenen/silinen satır sayısı (en yeni önce)."""
    tid = configs.resolve_tenant(tenant_id)
    conn = configs._db()
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT device_ip, version, source, note, created, created_by, content FROM cfg_backups WHERE tenant_id=? "
            "ORDER BY created DESC, version DESC LIMIT ?", (tid, max(1, min(limit, 200))))]
        names = {d["ip"]: d.get("sys_name") or d.get("hostname") or d["ip"] for d in inventory.list_devices(tid)}
        out = []
        for r in rows:
            prev = conn.execute("SELECT content FROM cfg_backups WHERE tenant_id=? AND device_ip=? AND version=?",
                                (tid, r["device_ip"], r["version"] - 1)).fetchone()
            add = rem = 0
            if prev:
                for l in difflib.unified_diff(prev["content"].split("\n"), r["content"].split("\n"), lineterm="", n=0):
                    if l.startswith("+") and not l.startswith("+++"):
                        add += 1
                    elif l.startswith("-") and not l.startswith("---"):
                        rem += 1
            out.append({"ip": r["device_ip"], "name": names.get(r["device_ip"], r["device_ip"]), "version": r["version"],
                        "prev": r["version"] - 1 if prev else 0, "source": r["source"], "note": r["note"], "created": r["created"],
                        "by": r["created_by"], "added": add, "removed": rem, "first": not prev})
        return out
    finally:
        conn.close()


def report(tenant_id=None):
    """Uyum raporu: özet + kural bazında + cihaz bazında sonuç."""
    tid = configs.resolve_tenant(tenant_id)
    rules = [r for r in configs.list_rules(tid) if r["enabled"]]
    conn = configs._db()
    try:
        latest = {r["device_ip"]: dict(r) for r in conn.execute(
            "SELECT b.device_ip, b.version, b.content, b.created FROM cfg_backups b WHERE b.tenant_id=? AND b.version="
            "(SELECT MAX(version) FROM cfg_backups WHERE tenant_id=b.tenant_id AND device_ip=b.device_ip)", (tid,))}
    finally:
        conn.close()
    per_rule = {r["id"]: {"id": r["id"], "name": r["name"], "kind": r["kind_label"], "pattern": r["pattern"], "vendor": r["vendor"],
                          "checked": 0, "failed": [], "pct": 100} for r in rules}
    devices = []
    for d in inventory.list_devices(tid):
        lb = latest.get(d["ip"])
        item = {"ip": d["ip"], "name": d.get("sys_name") or d.get("hostname") or d["ip"], "vendor": d.get("vendor", ""),
                "version": lb["version"] if lb else 0, "last_backup": lb["created"] if lb else "", "results": [], "score": None}
        if lb:
            for r in rules:
                if r["vendor"] and r["vendor"].lower() != (d.get("vendor") or "").lower():
                    continue
                try:
                    ok = configs.check_content(lb["content"], [r], d.get("vendor", ""))[0]["ok"]
                except re.error:
                    continue
                pr = per_rule[r["id"]]
                pr["checked"] += 1
                if not ok:
                    pr["failed"].append(d["ip"])
                item["results"].append({"rule": r["name"], "ok": ok})
            if item["results"]:
                item["score"] = round(100 * sum(x["ok"] for x in item["results"]) / len(item["results"]))
        devices.append(item)
    for pr in per_rule.values():
        if pr["checked"]:
            pr["pct"] = round(100 * (pr["checked"] - len(pr["failed"])) / pr["checked"])
    scored = [d["score"] for d in devices if d["score"] is not None]
    summary = {"devices": len(devices), "no_backup": sum(1 for d in devices if not d["version"]), "rules": len(rules),
               "scored": len(scored), "avg": round(sum(scored) / len(scored)) if scored else None,
               "full": sum(1 for s in scored if s == 100), "failing": sum(1 for s in scored if s < 100)}
    devices.sort(key=lambda d: (d["score"] is None, d["score"] if d["score"] is not None else 0, d["ip"]))
    return {"summary": summary, "rules": list(per_rule.values()), "devices": devices}


def report_csv(rep):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "name", "vendor", "version", "score", "failed_rules"])
    for d in rep["devices"]:
        vals = [d["ip"], d["name"], d["vendor"], d["version"], "" if d["score"] is None else d["score"],
                "; ".join(x["rule"] for x in d["results"] if not x["ok"])]
        w.writerow([("'" + str(v) if str(v)[:1] in ("=", "+", "-", "@") else v) for v in vals])
    return buf.getvalue()
