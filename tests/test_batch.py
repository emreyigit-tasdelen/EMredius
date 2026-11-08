# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from datetime import datetime

from conftest import login_as
from emredius.services import vouchers as svc


def test_expiration_roundtrip():
    dt = datetime(2026, 10, 9, 15, 30, 0)
    assert svc.radius_expiration_str(dt) == "09 Oct 2026 15:30:00"
    assert svc.parse_radius_expiration("09 Oct 2026 15:30:00") == dt
    assert svc.parse_radius_expiration("Eki 9 2026 15:30:00") == dt
    assert svc.parse_radius_expiration("garbage") is None


def test_quota_and_qr_escape():
    assert svc.quota_label(86400) == "1 Gün" and svc.quota_label(14400) == "4 Saat" and svc.quota_label(1800) == "30 Dk"
    assert svc.wifi_qr_escape('a;b"c') == 'a\;b\\"c'


def test_batch_page(client, monkeypatch):
    now = datetime(2030, 1, 1)
    rows = [svc._batch_row({"code": "GUEST-AB<1", "password": "123456", "expires_at": "01 Jan 2020 00:00:00",
                            "account_type": "voucher", "is_online": 0, "used_time": 0}, now),
            svc._batch_row({"code": "w1", "password": "p", "account_type": "wireless", "is_online": 1,
                            "used_time": 0, "max_all_session": "3600"}, now)]
    assert rows[0]["status"] == "expired" and rows[1]["source_cat"] == "wireless"
    monkeypatch.setattr(svc, "list_batch_accounts", lambda: {
        "accounts": rows, "group_count": 2, "online_count": 1, "expired_count": 1})
    login_as(client, "superadmin")
    body = client.get("/batch-users").get_data(as_text=True)
    assert "GUEST-AB&lt;1" in body and "/voucher/delete/GUEST-AB%3C1" in body and "(1)" in body
    assert "/vouchers/print?code=GUEST-AB%3C1" in body and "/static/js/batch.js" in body


def test_generate_validation(client, monkeypatch):
    called = []
    monkeypatch.setattr(svc, "generate_vouchers", lambda p: called.append(p))
    tok = login_as(client, "superadmin")
    client.post("/voucher/generate", data={"_csrf_token": tok, "count": "9999"})
    assert not called
    with client.session_transaction() as s:
        assert "1 ile 500" in str(s.get("_flashes"))


def test_print_page(client, monkeypatch):
    monkeypatch.setattr(svc, "printable_vouchers", lambda code, limit, ssid: [
        {"code": "GUEST-1", "password": "</script>", "timing": "x", "qr_id": "qrcode-1", "qr_payload": "WIFI:</script>"}])
    login_as(client, "superadmin")
    body = client.get("/vouchers/print").get_data(as_text=True)
    assert body.count("</script>") == 4  # only the four real closing tags
    assert "&lt;/script&gt;" in body
