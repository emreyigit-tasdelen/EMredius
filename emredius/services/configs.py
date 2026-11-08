# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Konfig yönetimi: sürümlü yapılandırma yedeği (SSH ile çekme ya da elle yükleme), sürümler arası fark, şablonlar,
uyumluluk kuralları ve tek/filo gönderim. Gönderim varsayılan KAPALI (ayar cfg_push_enabled=1) ve her gönderimden önce otomatik yedek alınır.
SSH için paramiko gerekir; kurulu değilse çekme/gönderim kullanılamaz, diğer her şey çalışır. Kimlik bilgileri Fernet ile şifreli saklanır
(anahtar SECRET_KEY'den türetilir). Tablolar NMS veritabanında, tenant_id'li. Sayfa yalnızca süper yönetici."""
import base64
import difflib
import hashlib
import io
import csv
import logging
import re
import threading
import time

from . import inventory, vendors
from ..core import get_nms_db, get_setting
from ..core.tenant import all_tenant_ids, resolve_tenant

log = logging.getLogger(__name__)

DEFAULT_TENANT = inventory.DEFAULT_TENANT
MAX_CONFIG = 2 * 1024 * 1024
MAX_VERSIONS = 50          # cihaz başına saklanan sürüm
_schema_ok = set()
_push_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS cfg_creds (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL, username TEXT NOT NULL,
  secret_enc TEXT NOT NULL, enable_enc TEXT DEFAULT '', port INTEGER NOT NULL DEFAULT 22);
CREATE TABLE IF NOT EXISTS cfg_backups (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, device_ip TEXT NOT NULL, version INTEGER NOT NULL,
  sha256 TEXT NOT NULL, content TEXT NOT NULL, source TEXT DEFAULT 'manual', note TEXT DEFAULT '', created TEXT NOT NULL,
  created_by TEXT DEFAULT '', UNIQUE(tenant_id, device_ip, version));
CREATE TABLE IF NOT EXISTS cfg_templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL, vendor TEXT DEFAULT '',
  body TEXT NOT NULL, created TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS cfg_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL, vendor TEXT DEFAULT '',
  kind TEXT NOT NULL, pattern TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1);
"""
VENDOR_CMDS = {"cisco": ["terminal length 0", "show running-config"], "arista": ["terminal length 0", "show running-config"],
               "huawei": ["screen-length 0 temporary", "display current-configuration"],
               "juniper": ["set cli screen-length 0", "show configuration | display set"], "mikrotik": ["/export"],
               "ruijie": ["terminal length 0", "show running-config"], "nokia": ["environment no more", "admin display-config"]}
DEFAULT_CMDS = ["terminal length 0", "show running-config"]
RULE_KINDS = {"must_contain": "Bulunmalı", "must_not_contain": "Bulunmamalı"}


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


# ------------------------------------------------------------------ şifreleme
def _fernet(secret):
    from cryptography.fernet import Fernet
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(("cfg|" + secret).encode()).digest()))


def encrypt(secret_key, text):
    return _fernet(secret_key).encrypt((text or "").encode()).decode()


def decrypt(secret_key, token):
    try:
        return _fernet(secret_key).decrypt((token or "").encode()).decode() if token else ""
    except Exception:  # noqa: BLE001
        return ""


# ------------------------------------------------------------------ kimlik bilgileri
def add_cred(secret_key, name, username, password, enable="", port=22, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    name, username = (name or "").strip()[:64], (username or "").strip()[:64]
    if not name or not username or not password:
        return "Ad, kullanıcı ve parola gerekli."
    try:
        port = int(port)
        assert 1 <= port <= 65535
    except (TypeError, ValueError, AssertionError):
        return "Port 1-65535 olmalı."
    conn = _db()
    try:
        conn.execute("INSERT INTO cfg_creds (tenant_id,name,username,secret_enc,enable_enc,port) VALUES (?,?,?,?,?,?)",
                     (tenant_id, name, username, encrypt(secret_key, password), encrypt(secret_key, enable) if enable else "", port))
        conn.commit()
    finally:
        conn.close()
    return ""


def list_creds(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        return [dict(r) for r in conn.execute("SELECT id,name,username,port FROM cfg_creds WHERE tenant_id=? ORDER BY id", (tenant_id,))]
    finally:
        conn.close()


def _cred(secret_key, cred_id, tenant_id):
    conn = _db()
    try:
        r = conn.execute("SELECT * FROM cfg_creds WHERE id=? AND tenant_id=?", (cred_id, tenant_id)).fetchone()
    finally:
        conn.close()
    if not r:
        return None
    return {"username": r["username"], "password": decrypt(secret_key, r["secret_enc"]), "enable": decrypt(secret_key, r["enable_enc"]), "port": r["port"]}


def delete_cred(cred_id, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        n = conn.execute("DELETE FROM cfg_creds WHERE id=? AND tenant_id=?", (cred_id, tenant_id)).rowcount
        conn.commit()
        return n > 0
    finally:
        conn.close()


# ------------------------------------------------------------------ SSH (paramiko isteğe bağlı)
def ssh_available():
    try:
        import paramiko  # noqa: F401
        return True
    except ImportError:
        return False


def _ssh_run(ip, cred, commands, timeout=20):
    """Komutları sırayla çalıştırır, birleşik çıktıyı döndürür. Testlerde taklit edilir."""
    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, port=cred["port"], username=cred["username"], password=cred["password"], timeout=timeout,
              look_for_keys=False, allow_agent=False)
    try:
        sh = c.invoke_shell(width=250, height=50)
        sh.settimeout(timeout)
        time.sleep(0.8)
        out = []
        if cred.get("enable"):
            sh.send("enable\n" + cred["enable"] + "\n")
            time.sleep(0.6)
        for cmd in commands:
            sh.send(cmd + "\n")
            time.sleep(1.2)
        end = time.time() + timeout
        buf = b""
        while time.time() < end:
            if sh.recv_ready():
                buf += sh.recv(65535)
                end = time.time() + 2
            else:
                time.sleep(0.3)
                if buf and not sh.recv_ready():
                    break
        out.append(buf.decode("utf-8", "replace"))
        return "\n".join(out)
    finally:
        c.close()


def _clean_output(text):
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text or "").replace("\r", "")
    return text.strip()[:MAX_CONFIG]


# ------------------------------------------------------------------ yedek / sürüm
def save_backup(conn, ip, content, source="manual", note="", user="", tenant_id=None):
    """Aynı içerik (sha256) son sürümle özdeşse yeni sürüm açılmaz. -> (version, yeni_mi)."""
    tenant_id = resolve_tenant(tenant_id)
    content = (content or "").replace("\r\n", "\n").strip()[:MAX_CONFIG]
    if not content:
        raise ValueError("Boş yapılandırma kaydedilmez.")
    sha = hashlib.sha256(content.encode()).hexdigest()
    last = conn.execute("SELECT version, sha256 FROM cfg_backups WHERE tenant_id=? AND device_ip=? ORDER BY version DESC LIMIT 1",
                        (tenant_id, ip)).fetchone()
    if last and last["sha256"] == sha:
        return last["version"], False
    ver = (last["version"] if last else 0) + 1
    conn.execute("INSERT INTO cfg_backups (tenant_id,device_ip,version,sha256,content,source,note,created,created_by) VALUES (?,?,?,?,?,?,?,?,?)",
                 (tenant_id, ip, ver, sha, content, source, (note or "")[:200], _now(), (user or "")[:64]))
    conn.execute("DELETE FROM cfg_backups WHERE tenant_id=? AND device_ip=? AND version<=?", (tenant_id, ip, ver - MAX_VERSIONS))
    return ver, True


def manual_backup(ip, content, user="", note="", tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    if ip not in {d["ip"] for d in inventory.list_devices(tenant_id)}:
        return None, "Cihaz envanterde yok."
    conn = _db()
    try:
        ver, new = save_backup(conn, ip, content, "manual", note, user, tenant_id)
        conn.commit()
        return ver, ""
    except ValueError as e:
        return None, str(e)
    finally:
        conn.close()


def collect(ip, secret_key, cred_id, user="", source="ssh", tenant_id=None):
    """Cihazdan SSH ile yapılandırmayı çekip yeni sürüm olarak kaydeder. -> (version, hata)."""
    tenant_id = resolve_tenant(tenant_id)
    devs = {d["ip"]: d for d in inventory.list_devices(tenant_id)}
    if ip not in devs:
        return None, "Cihaz envanterde yok."
    if not ssh_available():
        return None, "paramiko kurulu değil; SSH ile yedek alınamaz (elle yükleme kullanılabilir)."
    cred = _cred(secret_key, cred_id, tenant_id)
    if not cred:
        return None, "Kimlik bilgisi yok."
    cmds = vendors.backup_commands(devs[ip].get("vendor"))
    try:
        out = _clean_output(_ssh_run(ip, cred, cmds))
    except Exception as e:  # noqa: BLE001
        return None, f"SSH hatası: {str(e)[:120]}"
    conn = _db()
    try:
        ver, _ = save_backup(conn, ip, out, source, "", user, tenant_id)
        conn.commit()
        return ver, ""
    except ValueError as e:
        return None, str(e)
    finally:
        conn.close()


def list_versions(ip, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        return [dict(r) for r in conn.execute(
            "SELECT version, sha256, source, note, created, created_by, LENGTH(content) AS size FROM cfg_backups WHERE tenant_id=? AND device_ip=? "
            "ORDER BY version DESC", (tenant_id, ip))]
    finally:
        conn.close()


def get_version(ip, version, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        r = conn.execute("SELECT * FROM cfg_backups WHERE tenant_id=? AND device_ip=? AND version=?", (tenant_id, ip, version)).fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


def diff(ip, a, b, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    va, vb = get_version(ip, a, tenant_id), get_version(ip, b, tenant_id)
    if not va or not vb:
        return None
    lines = list(difflib.unified_diff(va["content"].split("\n"), vb["content"].split("\n"), f"v{a}", f"v{b}", lineterm="", n=2))
    return {"a": a, "b": b, "lines": lines[:3000], "added": sum(1 for l in lines if l.startswith("+") and not l.startswith("+++")),
            "removed": sum(1 for l in lines if l.startswith("-") and not l.startswith("---"))}


# ------------------------------------------------------------------ şablonlar
def add_template(name, body, vendor="", tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    name, body = (name or "").strip()[:64], (body or "").replace("\r\n", "\n").strip()
    if not name or not body or len(body) > 20000:
        return "Ad ve gövde gerekli (en çok 20000 karakter)."
    conn = _db()
    try:
        conn.execute("INSERT INTO cfg_templates (tenant_id,name,vendor,body,created) VALUES (?,?,?,?,?)",
                     (tenant_id, name, (vendor or "").strip()[:32], body, _now()))
        conn.commit()
    finally:
        conn.close()
    return ""


def list_templates(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM cfg_templates WHERE tenant_id=? ORDER BY id", (tenant_id,))]
    finally:
        conn.close()


def delete_template(tid, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        n = conn.execute("DELETE FROM cfg_templates WHERE id=? AND tenant_id=?", (tid, tenant_id)).rowcount
        conn.commit()
        return n > 0
    finally:
        conn.close()


def render_template(body, variables, device=None):
    """{{degisken}} yerlerini doldurur; yerleşikler: ip, hostname. Eksik değişken hata verir. -> (komutlar, hata)."""
    values = {"ip": (device or {}).get("ip", ""), "hostname": (device or {}).get("sys_name") or (device or {}).get("hostname") or ""}
    values.update({k: str(v) for k, v in (variables or {}).items() if re.fullmatch(r"[A-Za-z0-9_]{1,32}", str(k))})
    missing = sorted({m for m in re.findall(r"{{\s*([A-Za-z0-9_]+)\s*}}", body) if m not in values or values[m] == ""})
    if missing:
        return None, "Eksik değişken: " + ", ".join(missing)
    out = re.sub(r"{{\s*([A-Za-z0-9_]+)\s*}}", lambda m: re.sub(r"[\r\n]", " ", values[m.group(1)]), body)
    return [l for l in out.split("\n") if l.strip()], ""


# ------------------------------------------------------------------ uyumluluk
def add_rule(name, kind, pattern, vendor="", tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    name, pattern = (name or "").strip()[:64], (pattern or "").strip()
    if not name or not pattern or len(pattern) > 200 or kind not in RULE_KINDS:
        return "Ad, tür ve desen (en çok 200 karakter) gerekli."
    try:
        re.compile(pattern, re.M)
    except re.error:
        return "Desen geçerli bir düzenli ifade değil."
    conn = _db()
    try:
        conn.execute("INSERT INTO cfg_rules (tenant_id,name,vendor,kind,pattern) VALUES (?,?,?,?,?)",
                     (tenant_id, name, (vendor or "").strip()[:32], kind, pattern))
        conn.commit()
    finally:
        conn.close()
    return ""


def list_rules(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        return [dict(r, kind_label=RULE_KINDS.get(r["kind"], r["kind"])) for r in
                conn.execute("SELECT * FROM cfg_rules WHERE tenant_id=? ORDER BY id", (tenant_id,))]
    finally:
        conn.close()


def delete_rule(rid, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        n = conn.execute("DELETE FROM cfg_rules WHERE id=? AND tenant_id=?", (rid, tenant_id)).rowcount
        conn.commit()
        return n > 0
    finally:
        conn.close()


def check_content(content, rules, vendor=""):
    """-> [{'rule','kind','ok'}] (cihaz üreticisine uymayan kurallar atlanır)."""
    res = []
    for r in rules:
        if not r["enabled"] or (r["vendor"] and r["vendor"].lower() != (vendor or "").lower()):
            continue
        found = re.search(r["pattern"], content or "", re.M) is not None
        res.append({"rule": r["name"], "kind": r["kind"], "ok": found if r["kind"] == "must_contain" else not found})
    return res


def compliance(tenant_id=None):
    """Her cihazın son sürümü için kural sonuçları."""
    tenant_id = resolve_tenant(tenant_id)
    rules = list_rules(tenant_id)
    conn = _db()
    try:
        latest = {r["device_ip"]: r for r in conn.execute(
            "SELECT b.device_ip, b.version, b.content, b.created FROM cfg_backups b WHERE b.tenant_id=? AND b.version="
            "(SELECT MAX(version) FROM cfg_backups WHERE tenant_id=b.tenant_id AND device_ip=b.device_ip)", (tenant_id,))}
    finally:
        conn.close()
    out = []
    for d in inventory.list_devices(tenant_id):
        lb = latest.get(d["ip"])
        res = check_content(lb["content"], rules, d.get("vendor", "")) if lb else []
        bad = [x["rule"] for x in res if not x["ok"]]
        out.append({"ip": d["ip"], "name": d.get("sys_name") or d.get("hostname") or d["ip"], "vendor": d.get("vendor", ""),
                    "version": lb["version"] if lb else 0, "last_backup": lb["created"] if lb else "",
                    "rules": len(res), "violations": bad, "state": "nobackup" if not lb else ("bad" if bad else "ok")})
    return out


# ------------------------------------------------------------------ gönderim
def push_enabled():
    return str(get_setting("cfg_push_enabled", "0")) == "1"


def push(ips, template_id, variables, secret_key, cred_id, user="", dry_run=True, tenant_id=None):
    """Şablonu bir ya da çok cihaza gönderir (filo). dry_run=True: yalnızca üretilen komutları döndürür, hiçbir şey göndermez.
    Gerçek gönderim: ayar açık + SSH var + önce otomatik yedek; yedek alınamazsa o cihaza gönderilmez."""
    tenant_id = resolve_tenant(tenant_id)
    tpl = next((t for t in list_templates(tenant_id) if t["id"] == template_id), None)
    if not tpl:
        return [{"ip": "-", "ok": False, "error": "Şablon yok."}]
    devs = {d["ip"]: d for d in inventory.list_devices(tenant_id)}
    results = []
    if not dry_run:
        if not push_enabled():
            return [{"ip": "-", "ok": False, "error": "Gönderim kapalı (ayar cfg_push_enabled=1 gerekir)."}]
        if not ssh_available():
            return [{"ip": "-", "ok": False, "error": "paramiko kurulu değil."}]
        if not _push_lock.acquire(blocking=False):
            return [{"ip": "-", "ok": False, "error": "Başka bir gönderim sürüyor."}]
    try:
        for ip in list(dict.fromkeys(ips))[:100]:
            d = devs.get(ip)
            if not d:
                results.append({"ip": ip, "ok": False, "error": "Cihaz envanterde yok."})
                continue
            if tpl["vendor"] and not vendors.same_family(tpl["vendor"], d.get("vendor")):
                results.append({"ip": ip, "ok": False, "error": f"Şablon {tpl['vendor']} içindir."})
                continue
            cmds, err = render_template(tpl["body"], variables, d)
            if err:
                results.append({"ip": ip, "ok": False, "error": err})
                continue
            if dry_run:
                results.append({"ip": ip, "ok": True, "commands": cmds, "dry_run": True})
                continue
            ver, err = collect(ip, secret_key, cred_id, user, "pre-push", tenant_id)
            if err:
                results.append({"ip": ip, "ok": False, "error": "Yedek alınamadı, gönderilmedi: " + err})
                continue
            cred = _cred(secret_key, cred_id, tenant_id)
            try:
                _ssh_run(ip, cred, cmds)
            except Exception as e:  # noqa: BLE001
                results.append({"ip": ip, "ok": False, "backup": ver, "error": f"SSH hatası: {str(e)[:120]}"})
                continue
            post, _ = collect(ip, secret_key, cred_id, user, "post-push", tenant_id)
            results.append({"ip": ip, "ok": True, "backup": ver, "after": post, "commands": len(cmds)})
        return results
    finally:
        if not dry_run and _push_lock.locked():
            _push_lock.release()


def overview(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    comp = compliance(tenant_id)
    conn = _db()
    try:
        nb = conn.execute("SELECT COUNT(*) FROM cfg_backups WHERE tenant_id=?", (tenant_id,)).fetchone()[0]
    finally:
        conn.close()
    return {"devices": len(comp), "backed_up": sum(1 for c in comp if c["version"]), "violations": sum(1 for c in comp if c["state"] == "bad"),
            "versions": nb, "ssh": ssh_available(), "push": push_enabled()}


def compliance_csv(rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["ip", "name", "vendor", "version", "last_backup", "state", "violations"]
    w.writerow(cols)
    for r in rows:
        w.writerow([("'" + str(v) if str(v)[:1] in ("=", "+", "-", "@") else v) for v in
                    [r["ip"], r["name"], r["vendor"], r["version"], r["last_backup"], r["state"], "; ".join(r["violations"])]])
    return buf.getvalue()


# ------------------------------------------------------------------ zamanlanmış yedek (varsayılan kapalı)
_sched = {"last": "", "result": ""}


def schedule_settings():
    try:
        hours = max(1, min(int(get_setting("cfg_backup_hours", "24") or 24), 168))
    except ValueError:
        hours = 24
    return {"enabled": str(get_setting("cfg_backup_enabled", "0")) == "1",
            "cred_id": int(get_setting("cfg_backup_cred_id", "0") or 0) if str(get_setting("cfg_backup_cred_id", "0") or "0").isdigit() else 0,
            "hours": hours, "last": _sched["last"], "result": _sched["result"]}


def backup_all(secret_key, cred_id, tenant_id=None):
    """Envanterdeki SSH'li ONLINE cihazların hepsinden yedek alır (tek tek; hata diğerlerini durdurmaz)."""
    tenant_id = resolve_tenant(tenant_id)
    ok = fail = new = 0
    for d in inventory.list_devices(tenant_id, status="ONLINE"):
        if not d.get("ssh_ok"):
            continue
        before = (list_versions(d["ip"], tenant_id) or [{"version": 0}])[0]["version"]
        ver, err = collect(d["ip"], secret_key, cred_id, "zamanlanmış", "scheduled", tenant_id)
        if err:
            fail += 1
        else:
            ok += 1
            new += 1 if ver != before else 0
    _sched.update(last=_now(), result=f"{ok} başarılı ({new} yeni sürüm), {fail} hata")
    return ok, fail


def start_scheduler(secret_key, check_s=600):
    def loop():
        due = 0.0
        while True:
            time.sleep(check_s)
            try:
                st = schedule_settings()
                if not st["enabled"] or not st["cred_id"] or time.time() < due:
                    continue
                due = time.time() + st["hours"] * 3600
                for t in all_tenant_ids():
                    backup_all(secret_key, st["cred_id"], t)
            except Exception as e:  # noqa: BLE001
                log.warning("config backup scheduler: %s", e)
    threading.Thread(target=loop, daemon=True, name="config-backup-scheduler").start()
