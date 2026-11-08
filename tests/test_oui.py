# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
import importlib.util
import os

from emredius.core import oui
from emredius.core.validators import lookup_mac_vendor

_spec = importlib.util.spec_from_file_location(
    "update_oui", os.path.join(os.path.dirname(__file__), "..", "scripts", "update_oui.py"))
upd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(upd)


def test_lookup_formats_and_fallbacks(tmp_path, monkeypatch):
    f = tmp_path / "oui.tsv"
    f.write_text("001122\tAcme Corp\nbad line\n", encoding="utf-8")
    monkeypatch.setenv("EMREDIUS_OUI_FILE", str(f))
    for m in ("00:11:22:aa:bb:cc", "00-11-22-AA-BB-CC", "0011.22aa.bbcc", "001122AABBCC"):
        assert lookup_mac_vendor(m) == "Acme Corp"
    assert oui.lookup("04:00:00:00:00:01") == oui.UNKNOWN
    assert oui.lookup("02:00:00:00:00:01") == oui.RANDOM
    assert oui.lookup("") == oui.UNKNOWN


def test_override_wins_and_reload_on_change(tmp_path, monkeypatch):
    f = tmp_path / "oui.tsv"
    f.write_text("B827EB\tRaspberry Pi Foundation\n", encoding="utf-8")
    monkeypatch.setenv("EMREDIUS_OUI_FILE", str(f))
    assert lookup_mac_vendor("b8:27:eb:00:00:01") == "Raspberry Pi"  # curated override
    f.write_text("001122\tNew Vendor\n", encoding="utf-8")
    os.utime(f, (1, 1))
    assert lookup_mac_vendor("00:11:22:00:00:01") == "New Vendor"


def test_bundled_table_is_large():
    assert oui.file_info()["entries"] > 10000


def test_updater_rejects_small_and_keeps_old(tmp_path):
    out = tmp_path / "oui.tsv"
    out.write_text("AAAAAA\tOld\n", encoding="utf-8")
    src = tmp_path / "oui.csv"
    src.write_text("Registry,Assignment,Organization Name,Organization Address\nMA-L,001122,Acme,x\n", encoding="utf-8")
    assert upd.main(["--file", str(src), "--out", str(out)]) == 1
    assert out.read_text(encoding="utf-8") == "AAAAAA\tOld\n"


def test_updater_writes_valid_table(tmp_path, monkeypatch):
    monkeypatch.setattr(upd, "MIN_ENTRIES", 2)
    src = tmp_path / "oui.csv"
    src.write_text('Registry,Assignment,Organization Name,Organization Address\n'
                   'MA-L,001122,"Acme, Inc.",x\nMA-L,0A0B0C,Beta  Ltd,y\nMA-M,12345,bad,z\n', encoding="utf-8")
    out = tmp_path / "oui.tsv"
    assert upd.main(["--file", str(src), "--out", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == "001122\tAcme, Inc.\n0A0B0C\tBeta Ltd\n"


def test_mac_vendor_filter_registered(client):
    f = client.application.jinja_env.filters["mac_vendor"]
    assert f("") == "" and f("b8:27:eb:00:00:01") == "Raspberry Pi"
