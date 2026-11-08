# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""16 üretici CLI ailesi: yapılandırma yedeği için sayfalama kapatma ve yapılandırma gösterme komutları, eşleştirme takma adları.
Konfig Yönetimi (services/configs.py) komutları buradan alır; yeni üretici = tek satır ekleme."""

# key, etiket, takma adlar (küçük harf, envanterdeki 'vendor' alanında geçen), yedek komutları, açıklama
FAMILIES = [
    {"key": "cisco", "label": "Cisco IOS / IOS-XE", "aliases": ["cisco"], "cmds": ["terminal length 0", "show running-config"]},
    {"key": "nxos", "label": "Cisco NX-OS", "aliases": ["nx-os", "nexus"], "cmds": ["terminal length 0", "show running-config"]},
    {"key": "arista", "label": "Arista EOS", "aliases": ["arista"], "cmds": ["terminal length 0", "show running-config"]},
    {"key": "juniper", "label": "Juniper JunOS", "aliases": ["juniper", "junos"], "cmds": ["set cli screen-length 0", "show configuration | display set"]},
    {"key": "huawei", "label": "Huawei VRP", "aliases": ["huawei", "vrp"], "cmds": ["screen-length 0 temporary", "display current-configuration"]},
    {"key": "hpe", "label": "HPE Comware", "aliases": ["h3c", "comware", "hpe comware"], "cmds": ["screen-length disable", "display current-configuration"]},
    {"key": "aruba", "label": "Aruba / HPE ProCurve", "aliases": ["aruba", "procurve", "hewlett", "hp "], "cmds": ["no page", "show running-config"]},
    {"key": "ruijie", "label": "Ruijie RGOS", "aliases": ["ruijie", "rgos"], "cmds": ["terminal length 0", "show running-config"]},
    {"key": "nokia", "label": "Nokia SR OS", "aliases": ["nokia", "alcatel", "sr os"], "cmds": ["environment no more", "admin display-config"]},
    {"key": "mikrotik", "label": "MikroTik RouterOS", "aliases": ["mikrotik", "routeros"], "cmds": ["/export"]},
    {"key": "fortinet", "label": "Fortinet FortiOS", "aliases": ["fortinet", "fortigate", "fortiswitch"], "cmds": ["show full-configuration"]},
    {"key": "paloalto", "label": "Palo Alto PAN-OS", "aliases": ["palo alto", "pan-os", "paloalto"], "cmds": ["set cli pager off", "show config running"]},
    {"key": "dell", "label": "Dell OS10 / PowerConnect", "aliases": ["dell", "powerconnect", "force10"], "cmds": ["terminal length 0", "show running-configuration"]},
    {"key": "extreme", "label": "Extreme EXOS", "aliases": ["extreme", "exos"], "cmds": ["disable clipaging", "show configuration"]},
    {"key": "zyxel", "label": "Zyxel", "aliases": ["zyxel"], "cmds": ["terminal length 0", "show running-config"]},
    {"key": "ubiquiti", "label": "Ubiquiti EdgeOS / UniFi", "aliases": ["ubiquiti", "edgeos", "unifi"], "cmds": ["show configuration"]},
]
DEFAULT_CMDS = ["terminal length 0", "show running-config"]


def resolve(vendor):
    """Envanterdeki üretici metninden ailesini bulur (takma ad içerme, uzun takma ad önce); bulunamazsa None."""
    v = (vendor or "").strip().lower()
    if not v:
        return None
    hits = [(len(a), f) for f in FAMILIES for a in f["aliases"] if a.strip() in v or (len(v) >= 4 and v in a)]
    return max(hits, key=lambda x: x[0])[1] if hits else None


def backup_commands(vendor):
    f = resolve(vendor)
    return list(f["cmds"]) if f else list(DEFAULT_CMDS)


def same_family(a, b):
    """İki üretici metni aynı aileye mi ait (şablon üretici filtresi için)? Aile bulunamazsa düz metin karşılaştırması."""
    fa, fb = resolve(a), resolve(b)
    if fa and fb:
        return fa["key"] == fb["key"]
    return (a or "").strip().lower() == (b or "").strip().lower()


# SSH cihaz alarmı için günlük (log) okuma komutları; listede olmayan aile DEFAULT_LOG_CMDS kullanır
LOG_CMDS = {"cisco": ["terminal length 0", "show logging"], "nxos": ["terminal length 0", "show logging last 200"],
            "arista": ["terminal length 0", "show logging last 200"], "juniper": ["set cli screen-length 0", "show log messages | last 200"],
            "huawei": ["screen-length 0 temporary", "display logbuffer"], "hpe": ["screen-length disable", "display logbuffer"],
            "mikrotik": ["/log print"], "fortinet": ["execute log display"], "ruijie": ["terminal length 0", "show logging"],
            "aruba": ["no page", "show logging -r"], "nokia": ["environment no more", "show log log-id 99"]}
DEFAULT_LOG_CMDS = ["terminal length 0", "show logging"]


def log_commands(vendor):
    f = resolve(vendor)
    return list(LOG_CMDS.get(f["key"], DEFAULT_LOG_CMDS)) if f else list(DEFAULT_LOG_CMDS)
