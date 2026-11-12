# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
import ipaddress

from conftest import login_as
from emredius.core import auth
from emredius.services import hardening as svc
from emredius.services import flow_acl as allow


def test_page_superadmin_only(client):
    login_as(client, "superadmin")
    assert client.get("/hardening").status_code == 200
    login_as(client, "helpdesk")
    assert client.get("/hardening").status_code in (302, 403)


def test_allow_parse_and_permits():
    nets = allow.parse("10.0.0.0/24, 192.168.1.5\n2001:db8::/32")
    assert allow.permits(nets, "10.0.0.77") and allow.permits(nets, "192.168.1.5") and allow.permits(nets, "2001:db8::1")
    assert not allow.permits(nets, "10.0.1.1") and not allow.permits(nets, "bogus")
    assert allow.permits([], "8.8.8.8")  # boş liste = kısıt yok
    for bad in ("300.1.1.1", "10.0.0.0/99", "abc"):
        try:
            allow.parse(bad)
            assert False, bad
        except ValueError:
            pass


def test_acl_cache_reloads():
    calls = []
    acl = allow.Acl(lambda: calls.append(1) or [ipaddress.ip_network("10.0.0.0/8")], ttl=10)
    assert acl.allows("10.1.1.1", now=100) and not acl.allows("11.1.1.1", now=101)
    assert len(calls) == 1
    acl.allows("10.1.1.1", now=200)
    assert len(calls) == 2


def test_flow_sources_roundtrip(app):
    with app.app_context():
        assert svc.get_flow_sources() == ""
        assert svc.save_flow_sources("10.0.0.5, 10.1.0.0/16") == "10.0.0.5/32, 10.1.0.0/16"
        assert svc.get_flow_sources() == "10.0.0.5/32, 10.1.0.0/16"
        try:
            svc.save_flow_sources("nope")
            assert False
        except svc.ValidationError:
            pass
        assert svc.save_flow_sources("") == ""


def test_collector_drops_unlisted_sources(app):
    from emredius.services import flows
    with app.app_context():
        svc.save_flow_sources("10.0.0.5")
        flows._acl._at = 0  # önbelleği zorla yenile
        assert flows.handle_packet(b"\x00\x05garbage", "9.9.9.9") == 0
        assert flows._stats.get("dropped", 0) >= 1
        svc.save_flow_sources("")
        flows._acl._at = 0


def test_lock_policy_defaults_and_clamp(monkeypatch):
    monkeypatch.setattr(auth, "get_setting", lambda k, d="": d)
    assert auth.lock_policy() == (5, 900)
    vals = {"login_lock_threshold": "1", "login_lock_minutes": "99999"}
    monkeypatch.setattr(auth, "get_setting", lambda k, d="": vals.get(k, d))
    assert auth.lock_policy() == (3, 1440 * 60)
    vals["login_lock_threshold"] = "abc"
    assert auth.lock_policy()[0] == 5


def test_policy_validation():
    for form in ({"login_lock_threshold": "2", "login_lock_minutes": "15"},
                 {"login_lock_threshold": "5", "login_lock_minutes": "x"}):
        try:
            svc.save_policy(form)
            assert False
        except svc.ValidationError:
            pass


def test_must_2fa_redirects_until_enrolled(client, monkeypatch):
    from emredius.core import security
    login_as(client, "superadmin")
    with client.session_transaction() as s:
        s["must_2fa"] = True
    monkeypatch.setattr(security, "_totp_enabled", lambda u: False)
    monkeypatch.setattr(security, "_revalidate_session", lambda: True)
    r = client.get("/hardening")
    assert r.status_code == 302 and r.headers["Location"].endswith("/profile/2fa/setup")
    monkeypatch.setattr(security, "_totp_enabled", lambda u: True)
    assert client.get("/hardening").status_code == 200