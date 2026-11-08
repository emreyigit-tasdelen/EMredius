#!/bin/bash
# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
# Yayın yedek temizliği: /root/emredius_deploy_<YYYYMMDD_HHMMSS> klasörlerini siler.
# Kullanım: deploy_cleanup.sh [-n] [KORUNACAK_YEDEK_DİZİNİ]
#   -n : kuru çalıştırma (sadece listeler)
# Sağlık kontrolü + smoke geçtikten sonra çağrılır; başarısız yayında ÇAĞRILMAZ.
# Özel adlı klasörlere (modal, ntpjs, ...), DB yedeklerine ve /root/backups'a dokunmaz.
set -u
DRY=0; [ "${1:-}" = "-n" ] && { DRY=1; shift; }
KEEP="${1:-}"; KEEP="${KEEP%/}"
cnt=0; before=$(df -k / | awk 'NR==2{print $4}')
for d in /root/emredius_deploy_[0-9]*_[0-9]*; do
  [ -d "$d" ] || continue
  [ -n "$KEEP" ] && [ "$d" = "$KEEP" ] && { echo "korunuyor: $d"; continue; }
  if [ $DRY = 1 ]; then echo "silinecek: $d"; else rm -rf -- "$d"; fi
  cnt=$((cnt+1))
done
after=$(df -k / | awk 'NR==2{print $4}')
echo "islenen=$cnt bosalan_kb=$((after-before)) dry=$DRY"
