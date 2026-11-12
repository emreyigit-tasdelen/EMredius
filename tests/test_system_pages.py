# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Sistem sayfaları: sertifikalar, SIEM, entegrasyonlar, erişilebilirlik."""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from conftest import login_as
from emredius.core import audit
from emredius.services import availability, certs, integrations, siem

def _store(monkeypatch):
    """Ayar deposu bellekte (testlerde veritabanı yok)."""
    d = {}
    for m in (certs, siem, integrations):
        monkeypatch.setattr(m, "get_setting", lambda k, default="": d.get(k, default))
        monkeypatch.setattr(m, "set_setting", lambda k, v: d.__setitem__(k, v))
    return d


SUPER_ONLY = ["/certs", "/siem", "/integrations"]


def _make_cert(path, days):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1234).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=days))
            .sign(key, hashes.SHA256()))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def test_pages_open_for_superadmin(client):
    login_as(client, "superadmin")
    for url in SUPER_ONLY + ["/availability"]:
        assert client.get(url).status_code == 200, url


def test_super_only_pages_denied_to_others(client):
    login_as(client, "network_admin")
    for url in SUPER_ONLY:
        assert client.get(url).status_code in (302, 403), url


def test_post_requires_csrf_and_role(client):
    login_as(client, "network_admin")
    assert client.post("/siem/settings", data={"siem_host": "x"}).status_code in (302, 400, 403)


def test_cert_inspect_states(tmp_path):
    ok, soon = tmp_path / "ok.pem", tmp_path / "soon.pem"
    _make_cert(ok, 400)
    _make_cert(soon, 5)
    assert certs.inspect(str(ok))["status"] == "ok"
    r = certs.inspect(str(soon), warn=30)
    assert r["status"] == "warn" and r["days_left"] in (4, 5)
    assert certs.inspect(str(soon), now=datetime.now(timezone.utc) + timedelta(days=10))["status"] == "expired"
    assert certs.inspect(str(tmp_path / "none.pem"))["status"] == "missing"
    bad = tmp_path / "bad.pem"
    bad.write_text("not a cert")
    assert certs.inspect(str(bad))["status"] == "error"


def test_cert_settings_validation(app, monkeypatch):
    _store(monkeypatch)
    with app.app_context():
        assert certs.save_settings({"cert_warn_days": "0"})
        assert certs.save_settings({"cert_warn_days": "x"})
        assert certs.save_settings({"cert_warn_days": "45", "cert_alert_enabled": "1"}) is None
        assert certs.warn_days() == 45
        certs.save_settings({"cert_warn_days": "30"})
        assert certs.get_settings()["cert_alert_enabled"] == "0"


def test_cert_alert_off_by_default(app, monkeypatch):
    _store(monkeypatch)
    sent = []
    monkeypatch.setattr(certs, "send_alert", sent.append)
    with app.app_context():
        assert certs.notify_expiring([{"status": "expired", "name": "x", "days_left": -1}]) == 0
    assert not sent


def test_siem_formats():
    e = siem.format_event("cef", "adm|in", "LOGIN", "t=1", "d\nx", "1.2.3.4")
    assert e.startswith("CEF:0|EMREDIUS|Panel|1.0|LOGIN|") and "\n" not in e and "suser=adm|in" in e and "dst=t\\=1" in e
    s = siem.format_event("syslog", 'a"b', "SIEM TEST", "t", "d", "1.2.3.4")
    assert s.startswith("<14>1 ") and "SIEM_TEST" in s and 'user="a\\"b"' in s


def test_siem_defaults_off_and_validation(app, monkeypatch):
    _store(monkeypatch)
    with app.app_context():
        assert siem.get_settings()["siem_enabled"] == "0"
        assert siem.save_settings({"siem_enabled": "1", "siem_host": "", "siem_port": "514", "siem_proto": "udp", "siem_format": "cef"})
        assert siem.save_settings({"siem_host": "bad host!", "siem_port": "514", "siem_proto": "udp", "siem_format": "cef"})
        assert siem.save_settings({"siem_host": "h", "siem_port": "70000", "siem_proto": "udp", "siem_format": "cef"})
        assert siem.save_settings({"siem_host": "h", "siem_port": "514", "siem_proto": "icmp", "siem_format": "cef"})
        assert siem.save_settings({"siem_host": "siem.local", "siem_port": "6514", "siem_proto": "tcp", "siem_format": "cef"}) is None
        assert siem.get_settings()["siem_port"] == "6514" and siem.get_settings()["siem_enabled"] == "0"
        siem.save_settings({"siem_host": "", "siem_port": "514", "siem_proto": "udp", "siem_format": "syslog"})


def test_siem_listener_off_does_not_send(app, monkeypatch):
    sent = []
    monkeypatch.setattr(siem, "send", lambda m, c=None: sent.append(m) or (True, "ok"))
    siem._cache["cfg"] = None
    with app.app_context():
        siem.on_audit("u", "A", "t", "d", "1.1.1.1")
    assert not sent


def test_siem_udp_delivery():
    import socket
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(3)
    ok, _ = siem.send("hello", {"siem_host": "127.0.0.1", "siem_port": str(srv.getsockname()[1]), "siem_proto": "udp"})
    assert ok and srv.recv(100) == b"hello"
    srv.close()
    assert not siem.send("x", {"siem_host": "", "siem_port": "1", "siem_proto": "udp"})[0]


def test_audit_listener_called():
    got = []
    audit.add_listener(lambda *a: got.append(a))
    audit.add_listener(audit._listeners[-1])  # tekrar eklenmez
    n = len(audit._listeners)
    audit.log_admin_action("u", "X", "t", "d", "9.9.9.9")  # DB yoksa bile dinleyiciler çalışır
    assert got and got[-1][:2] == ("u", "X") and len(audit._listeners) == n
    audit._listeners.pop()


def test_webhook_validation_and_off_by_default(app, monkeypatch):
    _store(monkeypatch)
    with app.app_context():
        assert integrations.get_settings()["int_webhook_enabled"] == "0"
        assert integrations.save_settings({"int_webhook_enabled": "1", "int_webhook_url": ""})
        assert integrations.save_settings({"int_webhook_url": "ftp://x/y"})
        assert integrations.post_webhook("m") == (False, "Webhook kapalı.")
        assert integrations.save_settings({"int_webhook_url": "https://hooks.example.com/x"}) is None
        integrations.save_settings({"int_webhook_url": "", "int_webhook_secret_clear": "1"})


def test_availability_compute_and_report(app):
    ev = [("up", 0), ("down", 100), ("up", 160)]
    up, down, outs = availability.compute(ev, 0, 400)
    assert (up, down, outs) == (100 + 240, 60, [(100, 160)])
    up, down, _ = availability.compute(ev, 120, 400)  # pencere ortada başlar
    assert (up, down) == (240, 40)
    with app.app_context():
        availability._last.clear()
        assert availability.record([{"key": "panel", "status": "up"}, {"key": "x", "status": "unknown"}], now=1000.0) == 1
        assert availability.record([{"key": "panel", "status": "up"}], now=1010.0) == 0
        assert availability.record([{"key": "panel", "status": "down"}], now=1100.0) == 1
        rep = availability.report(now=1200.0)
        panel = next(r for r in rep if r["key"] == "panel")
        assert panel["windows"][0]["pct"] == 50.0 and panel["outages"]
        availability.purge_old(days=0, now=10 ** 9)
