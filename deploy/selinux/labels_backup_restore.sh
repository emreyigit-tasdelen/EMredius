#!/bin/bash
# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
# SELinux etiket yedeği / geri yükleme (restorecon öncesi alınır).
#   Yedek : labels_backup_restore.sh save    <yedek_dosyası> <yol>...
#   Geri  : labels_backup_restore.sh restore <yedek_dosyası>
#   Kontrol (değişiklik yok): labels_backup_restore.sh diff <yedek_dosyası>
# Biçim: NUL ayrılmış "bağlam\0yol\0" çiftleri (boşluk/yeni satırlı yollar güvenli).
set -euo pipefail
cmd="${1:-}"; f="${2:-}"
[ -n "$cmd" ] && [ -n "$f" ] || { echo "kullanım: $0 save|restore|diff <dosya> [yol...]" >&2; exit 2; }

case "$cmd" in
save)
    shift 2
    [ $# -gt 0 ] || { echo "en az bir yol ver" >&2; exit 2; }
    [ -e "$f" ] && { echo "$f zaten var, üzerine yazılmaz" >&2; exit 1; }
    find "$@" -xdev -printf '%Z\0%p\0' > "$f"
    chmod 600 "$f"
    echo "kaydedildi: $(tr -cd '\0' < "$f" | wc -c | awk '{print $1/2}') yol -> $f"
    ;;
restore|diff)
    n=0; fail=0
    while IFS= read -r -d '' ctx && IFS= read -r -d '' p; do
        [ -e "$p" ] || [ -L "$p" ] || continue
        cur=$(stat -c %C "$p" 2>/dev/null || echo "?")
        [ "$cur" = "$ctx" ] && continue
        n=$((n+1))
        if [ "$cmd" = diff ]; then
            printf '%s: %s -> %s\n' "$p" "$cur" "$ctx"
        else
            chcon -h "$ctx" "$p" || fail=$((fail+1))
        fi
    done < "$f"
    echo "$cmd: $n yol farklı, $fail hata"
    [ "$fail" -eq 0 ]
    ;;
*) echo "bilinmeyen komut: $cmd" >&2; exit 2 ;;
esac
