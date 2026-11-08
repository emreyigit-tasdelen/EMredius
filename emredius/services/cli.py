# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Web terminal: runs one shell command (superadmin only) and path/command autocomplete.
Commands run through a shell on purpose (pipes, redirects); obviously destructive or TTY-bound commands are refused."""
import os
import re
import subprocess
import time

from ..core import is_dry_run

TIMEOUT = 30
MAX_OUTPUT = 200_000

# Katalog: (kategori, ikon, renk, [(komut, açıklama)]). Hepsi salt okunur; help ve emr-* komutları kabuk kullanmaz.
CATALOG = [
    ("FreeRADIUS & AAA", "fa-shield-halved", "#2563eb", [
        ("radtest test test 127.0.0.1 0 testing123", "radtest deneme"),
        ("systemctl status radiusd --no-pager -l", "radiusd durumu"),
        ("journalctl -u radiusd -n 25 --no-pager", "radiusd günlüğü"),
        ("tail -n 25 /var/log/radius/radius.log", "RADIUS log"),
        ("emr-users", "RADIUS kullanıcı sayısı"),
        ("emr-lastauth", "son 10 kimlik doğrulama"),
        ("emr-sessions", "aktif oturum sayısı"),
    ]),
    ("Servis Durumları", "fa-server", "#0ea5e9", [
        ("systemctl is-active radiusd emredius-nms emredius-panel emredius-netflow mariadb chronyd", "özet"),
        ("systemctl status emredius-nms --no-pager -l", "TACACS+/SNMP NMS"),
        ("systemctl status emredius-panel --no-pager -l", "panel"),
        ("systemctl status emredius-netflow --no-pager -l", "flows"),
        ("systemctl status rsyslog --no-pager -l", "syslog"),
        ("systemctl status chronyd --no-pager -l", "chronyd"),
        ("systemctl status mariadb --no-pager -l", "MariaDB"),
    ]),
    ("Ağ Tanılama", "fa-network-wired", "#059669", [
        ("ss -tulpn", "açık portlar"),
        ("ip -br a", "arayüz IP listesi"),
        ("ip route", "yönlendirme tablosu"),
        ("ip neigh", "ARP/komşu tablosu"),
        ("ping -c 4 8.8.8.8", "ping"),
        ("traceroute -m 15 8.8.8.8", "traceroute"),
        ("nslookup example.com", "DNS sorgusu"),
        ("dig +short example.com", "dig"),
    ]),
    ("Zaman & Güvenlik", "fa-clock", "#d97706", [
        ("chronyc tracking", "stratum durumu"),
        ("chronyc sources -v", "NTP kaynakları"),
        ("firewall-cmd --list-all", "güvenlik duvarı"),
        ("emr-certs", "sertifika son kullanma tarihleri"),
    ]),
    ("Sistem & Donanım", "fa-microchip", "#7c3aed", [
        ("uptime", "yük ve çalışma süresi"),
        ("free -h", "RAM & swap"),
        ("df -h", "disk kullanımı"),
        ("ps aux --sort=-%cpu | head -n 15", "CPU'ya göre ilk 15 süreç"),
        ("top", "anlık özet"),
        ("journalctl -n 50 --no-pager", "son sistem günlüğü"),
        ("dmesg | tail -n 30", "çekirdek mesajları"),
        ("uname -a", "çekirdek bilgisi"),
    ]),
]

DANGEROUS_PATTERNS = [
    r"\brm\s+-[rfR]*\s+/",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\binit\s+0\b",
    r"\binit\s+6\b",
    r"\bpoweroff\b",
    r">\s*/dev/sd[a-z]",
    r">\s*/dev/nvme",
]
INTERACTIVE = {"nano", "vi", "vim", "top", "htop", "less", "more"}

KNOWN_BINS = [
    "systemctl", "journalctl", "radtest", "radclient", "radiusd", "radwho", "radmin", "radlast",
    "chronyc", "chronyd", "ss", "ip", "ping", "traceroute", "curl", "wget", "firewall-cmd",
    "iptables", "nftables", "tcpdump", "cat", "tail", "head", "grep", "less", "more",
    "free", "df", "uptime", "uname", "ps", "top", "htop", "chmod", "chown", "mkdir", "cp",
    "mv", "rm", "ls", "clear", "echo", "date", "whoami", "id", "history", "mysql", "mysqldump",
    "netstat", "find", "which", "whereis", "diff", "sed", "awk", "touch",
]
BIN_DIRS = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
MAX_MATCHES = 30


def check_command(cmd):
    """Returns (command_to_run, error). top is rewritten to a batch snapshot."""
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            return None, ("GÜVENLİK ENGELİ: Bu komut sunucu bütünlüğünü tehdit ettiği için Web CLI üzerinden "
                          "çalıştırılması engellenmiştir. Yeniden başlatma için 'Yeniden Başlat' menüsünü kullanınız.")
    tokens = cmd.split()
    first = os.path.basename(tokens[0]) if tokens else ""
    if first in INTERACTIVE:
        if first == "top":
            return "top -b -n 1 | head -n 35", None
        return None, (f"ETKİLEŞİMLİ KOMUT ENGELİ: '{first}' komutu TTY gerektirdiği için Web CLI'da doğrudan "
                      "çalıştırılamaz. Çıktı almak için komuta -n / --no-pager ekleyin veya 'cat', 'tail', 'head' kullanın.")
    return cmd, None


def help_text(topic=""):
    topic = topic.strip().lower()
    out = []
    for name, _icon, _color, cmds in CATALOG:
        if topic and topic not in name.lower():
            continue
        out.append(f"== {name} ==")
        out += [f"  {c:<70} # {d}" for c, d in cmds]
        out.append("")
    if not out:
        return "Kategori bulunamadı. Kategoriler: " + ", ".join(c[0] for c in CATALOG)
    out.append("Yerleşik komutlar: help [kategori], emr-users, emr-lastauth, emr-sessions, emr-certs (salt okunur, kabuk yok).")
    return "\n".join(out)


def _db_rows(sql):
    from ..core.db import get_db
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall()
    finally:
        conn.close()


def _cert_lines():
    import glob
    lines = []
    for path in sorted(glob.glob("/etc/raddb/certs/*.pem") + glob.glob("/etc/pki/tls/certs/emredius*.crt"))[:20]:
        try:
            p = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-in", path], capture_output=True,
                               text=True, timeout=5, shell=False)
            if p.returncode == 0:
                lines.append(f"{path}: {p.stdout.strip()}")
        except (OSError, subprocess.SubprocessError):
            pass
    return lines


def _is_builtin(cmd):
    first = cmd.split()[0] if cmd.split() else ""
    return first == "help" or first.startswith("emr-")


def _builtin(cmd):
    """Salt okunur yerleşik komutlar (kabuk yok). Returns dict like execute()."""
    tokens = cmd.split()
    name = tokens[0]
    start = time.time()
    try:
        if name == "help":
            out = help_text(" ".join(tokens[1:]))
        elif name == "emr-users":
            out = "RADIUS kullanıcı sayısı: %s" % _db_rows(
                "SELECT COUNT(DISTINCT username) AS n FROM radcheck WHERE attribute = 'Cleartext-Password'")[0]["n"]
        elif name == "emr-sessions":
            out = "Aktif oturum: %s" % _db_rows("SELECT COUNT(*) AS n FROM radacct WHERE acctstoptime IS NULL")[0]["n"]
        elif name == "emr-lastauth":
            rows = _db_rows("SELECT authdate, username, reply FROM radpostauth ORDER BY id DESC LIMIT 10")
            out = "\n".join(f"{r['authdate']}  {r['username']:<24} {r['reply']}" for r in rows) or "Kayıt yok."
        elif name == "emr-certs":
            out = "\n".join(_cert_lines()) or "Sertifika bulunamadı."
        else:
            return {"returncode": 127, "stdout": "", "stderr": f"{name}: yerleşik komut yok (help yazın)", "duration_ms": 0}
    except Exception as e:  # DB unavailable etc.: report instead of crashing
        return {"returncode": 1, "stdout": "", "stderr": f"Komut çalıştırılamadı: {e}", "duration_ms": 0}
    return {"returncode": 0, "stdout": out, "stderr": "", "duration_ms": int((time.time() - start) * 1000)}


def _cap(text):
    if len(text) > MAX_OUTPUT:
        return text[:MAX_OUTPUT] + f"\n[ÇIKTI KESİLDİ: {MAX_OUTPUT} karakter sınırı]"
    return text


def _cwd():
    if os.path.isdir("/root") and os.access("/root", os.R_OK):
        return "/root"
    return None


def execute(cmd):
    """Runs the (already checked) command. Returns dict(returncode, stdout, stderr, duration_ms)."""
    if _is_builtin(cmd):
        return _builtin(cmd)
    if is_dry_run():
        return {"returncode": -1, "stdout": "", "stderr": "SYSTEM_DRY_RUN: Web CLI bu ortamda komut çalıştırmaz.",
                "duration_ms": 0}
    start = time.time()
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                cwd=_cwd(), env=dict(os.environ, LANG="en_US.UTF-8", LC_ALL="en_US.UTF-8", PAGER="cat"))
        try:
            stdout, stderr = proc.communicate(timeout=TIMEOUT)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            rc = -1
            stderr = (stderr or "") + f"\n[ZAMAN AŞIMI]: Komut {TIMEOUT} saniye içinde tamamlanamadı ve sonlandırıldı."
    except OSError as e:
        rc, stdout, stderr = -1, "", str(e)
    return {"returncode": rc, "stdout": _cap(stdout or ""), "stderr": _cap(stderr or ""),
            "duration_ms": int((time.time() - start) * 1000)}


def _path_matches(prefix):
    matches = []
    expanded = os.path.expanduser(prefix)
    dirname = os.path.dirname(expanded) or "/"
    basename = os.path.basename(expanded)
    try:
        if not (os.path.isdir(dirname) and os.access(dirname, os.R_OK)):
            return matches
        for item in sorted(os.listdir(dirname)):
            if item.startswith(basename):
                full = os.path.join(dirname, item)
                matches.append(full + "/" if os.path.isdir(full) else full)
                if len(matches) >= 35:
                    break
    except OSError:
        pass
    return matches


def autocomplete(prefix):
    prefix = (prefix or "").strip()
    if not prefix:
        return []
    if prefix.startswith(("/", "./", "../")):
        return _path_matches(prefix)[:MAX_MATCHES]
    matches = [b for b in KNOWN_BINS if b.startswith(prefix)]
    for d in BIN_DIRS:
        if len(matches) >= MAX_MATCHES:
            break
        try:
            for f in sorted(os.listdir(d)):
                if f.startswith(prefix) and f not in matches:
                    matches.append(f)
                    if len(matches) >= MAX_MATCHES:
                        break
        except OSError:
            pass
    return matches[:MAX_MATCHES]
