# SELinux etiket düzeltmesi (henüz UYGULANMADI)

Denetim: 2026-10-12, canlı `/root/selinux_audit_20261012_093519/` (salt okunur, `restorecon -n`).

## Önerilen uygulama (canlı, onaydan sonra)
```bash
TS=$(date +%Y%m%d_%H%M%S); B=/root/emredius_selinux_$TS; mkdir -p $B
# 1) yedek
deploy/selinux/labels_backup_restore.sh save $B/labels.bin \
    /opt/emredius /opt/emredius_stage /etc/nginx/nginx.conf /etc/nginx/conf.d
# 2) yalnızca tip düzeltmesi (-F YOK: user/role alanı kozmetik, dokunulmaz)
restorecon -Rv /opt/emredius /opt/emredius_stage /etc/nginx/nginx.conf /etc/nginx/conf.d > $B/restorecon.log
# 3) kontrol: panel/nms/staging active, /login 200, healthcheck, smoke, nginx -t, ausearch -ts recent
# Geri dönüş:
deploy/selinux/labels_backup_restore.sh restore $B/labels.bin
```
Servis yeniden başlatma gerekmez (etiket açık dosyada anında geçerli; tüm süreçler `unconfined_service_t`).
Kalıcılık: tar/scp ile kopyalanan dosyalar üst dizinin tipini alır (`usr_t`); deploy adımının sonuna
`restorecon -R <hedef>` eklenmeli, yoksa fark yeniden oluşur.
