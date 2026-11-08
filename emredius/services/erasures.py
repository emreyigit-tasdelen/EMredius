# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Misafir Silme (Erasures): süresi dolan kupon / misafir hesaplarının önizlemesi; silme yalnızca elle, mevcut purge mantığıyla."""
from .vouchers import list_batch_accounts, purge_expired_vouchers

FIELDS = ("code", "description", "group", "expires_at", "quota", "source_cat")


def pending(limit=500):
    """Silinmeye uygun (süresi/kotası dolmuş, çevrimdışı) hesaplar. Silme yapmaz."""
    accounts = list_batch_accounts()["accounts"]
    rows = [a for a in accounts if a["status"] == "expired"]
    return {"total": len(rows), "rows": [{k: a.get(k) for k in FIELDS} for a in rows[:limit]]}


def erase():
    return purge_expired_vouchers()
