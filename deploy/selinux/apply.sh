#!/bin/bash
# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
# SELinux tip düzeltmesi: yedek -> restorecon (-F yok) -> kontrol -> başarısızsa geri yükle.
#   apply.sh <yedek_dizini> stage|live
set -uo pipefail
B="$1"; PHASE="$2"; H="$(dirname "$0")/labels_backup_restore.sh"
case "$PHASE" in
stage) PATHS="/opt/emredius_stage" ;;
live)  PATHS="/opt/emredius /etc/nginx/nginx.conf /etc/nginx/conf.d" ;;
*) echo "faz: stage|live" >&2; exit 2 ;;
esac
mkdir -p "$B"
bash "$H" save "$B/labels_$PHASE.bin" $PATHS || exit 1
since=$(date '+%H:%M:%S')
restorecon -Rv $PATHS > "$B/restorecon_$PHASE.log"
echo "relabel: $(grep -c . "$B/restorecon_$PHASE.log")"
echo "kalan fark: $(restorecon -Rn $PATHS -v | grep -c .)"

check() {
    local ok=0
    if [ "$PHASE" = stage ]; then
        systemctl is-active -q emredius-staging || ok=1
        c=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5100/login); echo "staging /login $c"; [ "$c" = 200 ] || ok=1
        (cd /opt/emredius_stage && EMREDIUS_ENV_FILE=/etc/emredius/staging.env .venv/bin/python scripts/smoke.py 2>&1 | tail -1) | tee /dev/stderr | grep -qE '(^|; )0 problem' || ok=1
    else
        for s in emredius-panel emredius-nms nginx radiusd; do systemctl is-active -q $s || { echo "$s DEĞİL active"; ok=1; }; done
        nginx -t 2>&1 | tail -1
        nginx -t >/dev/null 2>&1 || ok=1
        c=$(curl -sk -o /dev/null -w '%{http_code}' http://127.0.0.1:5000/login); echo "panel /login $c"; [ "$c" = 200 ] || ok=1
        (cd /opt/emredius && /opt/emredius/.venv/bin/python scripts/healthcheck.py 2>&1) | tee /dev/stderr | grep -q FAIL && ok=1
        (cd /opt/emredius && EMREDIUS_ENV_FILE=/etc/emredius/emredius.env .venv/bin/python scripts/smoke.py 2>&1 | tail -1) | tee /dev/stderr | grep -qE '(^|; )0 problem' || ok=1
        # yeni dosya/süreç bağlamında exec testi (venv python bin_t oldu)
        /opt/emredius/.venv/bin/python -c 'import flask' || ok=1
    fi
    n=$(ausearch -m AVC,USER_AVC -ts "$since" --input-logs </dev/null 2>/dev/null | grep '^type=AVC' | grep -v chronyc_t | grep -vc 'unix_dgram_socket')
    echo "yeni AVC (chrony hariç): $n"; [ "$n" = 0 ] || ok=1
    return $ok
}

if check; then
    echo "SONUÇ $PHASE: OK"
else
    echo "SONUÇ $PHASE: FAIL -> geri yükleniyor"
    bash "$H" restore "$B/labels_$PHASE.bin"
    check && echo "geri dönüş sonrası OK" || echo "GERİ DÖNÜŞ SONRASI DA FAIL"
    exit 1
fi
