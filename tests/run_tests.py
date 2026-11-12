# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Minimal test runner for hosts without pytest (supports the fixtures used here: app, client, tmp_path,
monkeypatch). With pytest installed simply run `python -m pytest tests`.
usage: python tests/run_tests.py [test_module ...]"""
import importlib
import inspect
import os
import sys
import tempfile
import traceback
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(1, os.path.dirname(HERE))

import conftest  # noqa: E402


class MonkeyPatch:
    def __init__(self):
        self._undo = []

    def setattr(self, target, name, value):
        self._undo.append((target, name, getattr(target, name)))
        setattr(target, name, value)

    def setenv(self, name, value):
        self._undo.append((os.environ, name, os.environ.get(name)))
        os.environ[name] = str(value)

    def undo(self):
        for target, name, old in reversed(self._undo):
            if target is os.environ:
                if old is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = old
            else:
                setattr(target, name, old)


def run_test(fn):
    params = inspect.signature(fn).parameters
    mp = MonkeyPatch()
    with tempfile.TemporaryDirectory() as td:
        kwargs = {}
        if "tmp_path" in params or "app" in params or "client" in params:
            kwargs["tmp_path"] = Path(td)
        if "monkeypatch" in params:
            kwargs["monkeypatch"] = mp
        if "app" in params or "client" in params:
            app = conftest.make_app(Path(td))
            if "app" in params:
                kwargs["app"] = app
            if "client" in params:
                kwargs["client"] = app.test_client()
        kwargs = {k: v for k, v in kwargs.items() if k in params}
        try:
            fn(**kwargs)
        finally:
            mp.undo()


def main(modules):
    failed = passed = 0
    for mod_name in modules:
        mod = importlib.import_module(mod_name)
        for name, fn in inspect.getmembers(mod, inspect.isfunction):
            if not name.startswith("test_") or fn.__module__ != mod.__name__:
                continue
            try:
                run_test(fn)
                passed += 1
            except Exception:
                failed += 1
                print(f"FAIL {mod_name}::{name}")
                traceback.print_exc(limit=6)
    print(f"{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    mods = sys.argv[1:] or sorted(p[:-3] for p in os.listdir(HERE) if p.startswith("test_") and p.endswith(".py"))
    sys.exit(main(mods))
