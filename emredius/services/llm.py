# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Yerel LLM (Ollama) istemcisi: tek HTTP noktası. Varsayılan KAPALI; kapalıyken veya hata olunca sessizce None döner.
Dış API yok: URL yalnızca ayardan gelir ve loopback olmalıdır. Alarm yorumu (NMS (g)) bu iskeleti kullanacak."""
import json
import logging
import urllib.request

from ..core import get_setting

log = logging.getLogger(__name__)

DEFAULT_URL = "http://127.0.0.1:11434"
TIMEOUT_S = 30


def is_enabled():
    return get_setting("llm_enabled", "0") == "1"


def generate(prompt, system=""):
    """Metin üretir; özellik kapalı/ulaşılamazsa None (çağıran bir şey göstermez)."""
    if not is_enabled() or not prompt:
        return None
    base = (get_setting("llm_url", DEFAULT_URL) or DEFAULT_URL).rstrip("/")
    model = get_setting("llm_model", "")
    if not model or not base.startswith(("http://127.0.0.1", "http://localhost")):
        return None
    body = json.dumps({"model": model, "prompt": prompt, "system": system, "stream": False}).encode()
    try:
        req = urllib.request.Request(base + "/api/generate", data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:  # noqa: S310 (loopback only)
            return (json.loads(r.read().decode()).get("response") or "").strip() or None
    except Exception as e:  # noqa: BLE001
        log.debug("llm: %s", e)
        return None


def explain_alarm(alarm):
    """Alarm için kısa yorum / kök neden özeti. Boş bağlantı noktası: kapalıyken hep None."""
    return generate(f"Ağ alarmı: {alarm.get('message', '')}. Olası kök nedeni kısaca açıkla.")
